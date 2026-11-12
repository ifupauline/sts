// SPDX-License-Identifier: Apache-2.0
/*
 * MQTT client against a real broker: starts mosquitto with a plain and a TLS
 * listener (certificates made with openssl), then checks QoS 1 delivery,
 * persistent sessions, wills, graceful shutdown, TLS verification and the
 * room protocol end to end, with an eavesdropper on the topic.
 *
 * usage: test_mqtt MOSQUITTO OPENSSL
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "crypto.h"
#include "log.h"
#include "mqtt.h"
#include "room.h"
#include "test.h"
#include "util.h"

#define TOPIC "sts-test/transport"
#define MAX_MSGS 512
#define MSG_LEN STS_WIRE_MAX
#define SKIP 77

struct client {
	struct sts_mqtt m;
	int ready;
	int session_present;
	int lost;
	char reason[512];
	int n;
	size_t len[MAX_MSGS];
	uint8_t msg[MAX_MSGS][MSG_LEN];
};

static int port;
static int tls_port;
static pid_t broker;
static char dir[STS_PATH_MAX];
static char ca_file[STS_PATH_MAX + 32];
static char wrong_ca_file[STS_PATH_MAX + 32];

/* --- broker -------------------------------------------------------------- */

static int free_port(void)
{
	struct sockaddr_in sa;
	socklen_t len = sizeof(sa);
	int fd;
	int p;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(fd >= 0);
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	REQUIRE(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
	REQUIRE(getsockname(fd, (struct sockaddr *)&sa, &len) == 0);
	p = ntohs(sa.sin_port);
	close(fd);
	return p;
}

static int port_open(int p)
{
	struct sockaddr_in sa;
	int fd;
	int ok;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return 0;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)p);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ok = connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
	close(fd);
	return ok;
}

static void run_cmd(const char *fmt, ...) STS_PRINTF(1, 2);

static void run_cmd(const char *fmt, ...)
{
	char cmd[4096];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, ap);
	va_end(ap);
	REQUIRE(system(cmd) == 0);
}

static void make_certs(const char *openssl)
{
	const char *ec = "-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes";

	run_cmd("cd '%s' && '%s' req -x509 %s -keyout ca.key -out ca.crt "
		"-days 2 -subj /CN=sts-test-ca 2>/dev/null",
		dir, openssl, ec);
	run_cmd("cd '%s' && '%s' req -x509 %s -keyout wrong.key "
		"-out wrong.crt -days 2 -subj /CN=sts-other-ca 2>/dev/null",
		dir, openssl, ec);
	run_cmd("cd '%s' && printf 'subjectAltName=DNS:localhost\\n"
		"basicConstraints=CA:FALSE\\n' > ext.cnf && "
		"'%s' req %s -keyout server.key -out server.csr "
		"-subj /CN=localhost 2>/dev/null && "
		"'%s' x509 -req -in server.csr -CA ca.crt -CAkey ca.key "
		"-CAcreateserial -out server.crt -days 2 -extfile ext.cnf "
		"2>/dev/null",
		dir, openssl, ec, openssl);
	snprintf(ca_file, sizeof(ca_file), "%s/ca.crt", dir);
	snprintf(wrong_ca_file, sizeof(wrong_ca_file), "%s/wrong.crt", dir);
}

static void start_broker(const char *exe)
{
	char conf[STS_PATH_MAX + 32];
	char log[STS_PATH_MAX + 32];
	struct passwd *pw;
	FILE *fp;
	int i;

	port = free_port();
	tls_port = free_port();
	snprintf(conf, sizeof(conf), "%s/mosquitto.conf", dir);
	fp = fopen(conf, "w");
	REQUIRE(fp != NULL);
	/* as root mosquitto would switch to a user who can't read @dir */
	pw = getpwuid(getuid());
	if (pw != NULL)
		fprintf(fp, "user %s\n", pw->pw_name);
	fprintf(fp,
		"persistence false\n"
		"allow_anonymous true\n"
		"listener %d 127.0.0.1\n"
		"listener %d 127.0.0.1\n"
		"cafile %s/ca.crt\n"
		"certfile %s/server.crt\n"
		"keyfile %s/server.key\n",
		port, tls_port, dir, dir, dir);
	fclose(fp);

	snprintf(log, sizeof(log), "%s/mosquitto.log", dir);
	broker = fork();
	REQUIRE(broker >= 0);
	if (broker == 0) {
		if (freopen("/dev/null", "w", stdout) == NULL ||
		    freopen(log, "w", stderr) == NULL)
			_exit(127);
		execl(exe, exe, "-c", conf, (char *)NULL);
		_exit(127);
	}

	for (i = 0; i < 100 && !(port_open(port) && port_open(tls_port)); i++)
		usleep(50000);
	if (!port_open(port) || !port_open(tls_port)) {
		fprintf(stderr, "mosquitto didn't start, its output:\n");
		run_cmd("cat '%s' >&2", log);
	}
	REQUIRE(port_open(port) && port_open(tls_port));
}

static void stop_broker(void)
{
	kill(broker, SIGTERM);
	waitpid(broker, NULL, 0);
}

/* --- clients ------------------------------------------------------------- */

static void on_ready(void *ud, int session_present)
{
	struct client *c = ud;

	c->ready++;
	c->session_present = session_present;
}

static void on_message(void *ud, const uint8_t *data, size_t len)
{
	struct client *c = ud;

	if (c->n < MAX_MSGS && len <= MSG_LEN) {
		memcpy(c->msg[c->n], data, len);
		c->len[c->n] = len;
		c->n++;
	}
}

static void on_lost(void *ud, const char *reason)
{
	struct client *c = ud;

	c->lost++;
	snprintf(c->reason, sizeof(c->reason), "%s", reason);
}

static const struct sts_mqtt_cb client_cb = {
	.ready = on_ready,
	.message = on_message,
	.lost = on_lost,
};

static struct client *client_new(void)
{
	struct client *c = calloc(1, sizeof(*c));

	REQUIRE(c != NULL);
	sts_mqtt_init(&c->m, &client_cb, c);
	return c;
}

static void poll_remove(struct client *c);

static void client_free(struct client *c)
{
	poll_remove(c);
	sts_mqtt_free(&c->m);
	free(c);
}

static struct sts_mqtt_opts opts(const char *id, int clean)
{
	struct sts_mqtt_opts o;

	memset(&o, 0, sizeof(o));
	o.host = "127.0.0.1";
	o.port = port;
	o.client_id = id;
	o.topic = TOPIC;
	o.keepalive_s = 30;
	o.clean_session = clean;
	o.tls_verify = 1;
	return o;
}

#define MAX_POLL 8

static struct sts_mqtt *polled[MAX_POLL];

static void poll_add(struct client *c)
{
	size_t i;

	for (i = 0; i < MAX_POLL; i++)
		if (polled[i] == NULL || polled[i] == &c->m) {
			polled[i] = &c->m;
			return;
		}
	REQUIRE(0);
}

static void poll_remove(struct client *c)
{
	size_t i;

	for (i = 0; i < MAX_POLL; i++)
		if (polled[i] == &c->m)
			polled[i] = NULL;
}

static void poll_clear(void)
{
	memset(polled, 0, sizeof(polled));
}

/* service every registered client once (waiting up to 20 ms) */
static void poll_once(void)
{
	struct sts_wait w[MAX_POLL];
	struct sts_mqtt *who[MAX_POLL];
	size_t n = 0;
	size_t i;
	int input;

	for (i = 0; i < MAX_POLL; i++) {
		intptr_t sock;
		int want_write;

		if (polled[i] == NULL)
			continue;
		sts_mqtt_wait_spec(polled[i], &sock, &want_write);
		if (sock == STS_SOCK_INVALID)
			continue;
		memset(&w[n], 0, sizeof(w[n]));
		w[n].sock = sock;
		w[n].want_write = want_write;
		who[n++] = polled[i];
	}
	if (n == 0)
		usleep(20000);
	else
		REQUIRE(sts_wait(w, n, 0, 20, &input) == 0);
	(void)who;
	for (i = 0; i < MAX_POLL; i++)
		if (polled[i] != NULL)
			sts_mqtt_process(polled[i]);
}

static void poll_for(int ms)
{
	uint64_t end = sts_monotonic_ms() + (uint64_t)ms;

	while (sts_monotonic_ms() < end)
		poll_once();
}

/* poll until @cond holds or @ms elapse, @return whether it holds */
#define POLL_UNTIL(cond, ms)                                 \
	({                                                   \
		uint64_t end_ = sts_monotonic_ms() + (ms);   \
		while (!(cond) && sts_monotonic_ms() < end_) \
			poll_once();                         \
		(cond);                                      \
	})

static void connect_ok(struct client *c, const struct sts_mqtt_opts *o)
{
	int before = c->ready;

	poll_add(c);
	REQUIRE(sts_mqtt_connect(&c->m, o) == 0);
	CHECK(POLL_UNTIL(c->ready > before || c->lost, 5000));
	if (c->lost)
		fprintf(stderr, "  connection failed: %s\n", c->reason);
	REQUIRE(sts_mqtt_is_ready(&c->m));
}

static void publish_str(struct client *c, const char *s)
{
	REQUIRE(sts_mqtt_publish(&c->m, (const uint8_t *)s, strlen(s)) == 0);
}

static int has_msg(const struct client *c, int i, const char *s)
{
	return i < c->n && c->len[i] == strlen(s) &&
	       memcmp(c->msg[i], s, c->len[i]) == 0;
}

static int count_msg(const struct client *c, const char *s)
{
	int count = 0;
	int i;

	for (i = 0; i < c->n; i++)
		count += has_msg(c, i, s);
	return count;
}

/* --- transport tests ----------------------------------------------------- */

static void test_roundtrip(void)
{
	struct client *a = client_new();
	struct client *b = client_new();
	struct sts_mqtt_opts oa = opts("rt-a", 1);
	struct sts_mqtt_opts ob = opts("rt-b", 1);
	char s[32];
	int ok = 1;
	int i;

	connect_ok(a, &oa);
	connect_ok(b, &ob);
	for (i = 0; i < 300; i++) {
		snprintf(s, sizeof(s), "m%d", i);
		publish_str(a, s);
	}
	CHECK(POLL_UNTIL(b->n == 300 && sts_mqtt_unacked(&a->m) == 0, 5000));
	for (i = 0; i < 300; i++) {
		snprintf(s, sizeof(s), "m%d", i);
		ok &= has_msg(b, i, s);
	}
	CHECK(ok); /* all of them, in order */
	CHECK(a->n == 300); /* we hear our own messages */
	CHECK(a->lost == 0 && b->lost == 0);

	/* a full-size frame */
	{
		static uint8_t big[STS_WIRE_MAX];

		memset(big, 0xa5, sizeof(big));
		REQUIRE(sts_mqtt_publish(&a->m, big, sizeof(big)) == 0);
		CHECK(POLL_UNTIL(b->n == 301, 3000));
		CHECK(b->len[300] == sizeof(big) &&
		      memcmp(b->msg[300], big, sizeof(big)) == 0);
	}
	poll_clear();
	client_free(a);
	client_free(b);
}

static void test_offline_queue(void)
{
	struct client *a = client_new();
	struct client *b = client_new();
	struct sts_mqtt_opts oa = opts("oq-a", 1);
	struct sts_mqtt_opts ob = opts("oq-b", 1);

	connect_ok(b, &ob);
	/* written before a has a connection */
	publish_str(a, "early-1");
	publish_str(a, "early-2");
	CHECK(sts_mqtt_unacked(&a->m) == 2);
	connect_ok(a, &oa);
	CHECK(POLL_UNTIL(b->n == 2, 3000));
	CHECK(has_msg(b, 0, "early-1") && has_msg(b, 1, "early-2"));
	CHECK(POLL_UNTIL(sts_mqtt_unacked(&a->m) == 0, 3000));
	poll_clear();
	client_free(a);
	client_free(b);
}

static void test_persistent_session(void)
{
	struct client *a = client_new();
	struct client *b = client_new();
	struct sts_mqtt_opts oa = opts("ps-a", 1);
	struct sts_mqtt_opts ob = opts("ps-b", 0);
	char s[32];
	int ok = 1;
	int i;

	connect_ok(a, &oa);
	connect_ok(b, &ob);
	CHECK(!b->session_present);

	/* b's connection dies; the broker keeps its messages */
	sts_mqtt_abort(&b->m);
	poll_for(200);
	for (i = 0; i < 20; i++) {
		snprintf(s, sizeof(s), "while-away-%d", i);
		publish_str(a, s);
	}
	CHECK(POLL_UNTIL(sts_mqtt_unacked(&a->m) == 0, 3000));
	CHECK(b->n == 0);

	connect_ok(b, &ob);
	CHECK(b->session_present);
	CHECK(POLL_UNTIL(b->n >= 20, 3000));
	for (i = 0; i < 20; i++) {
		snprintf(s, sizeof(s), "while-away-%d", i);
		ok &= has_msg(b, i, s);
	}
	CHECK(ok);

	/* a graceful shutdown unsubscribes: nothing queued any more */
	sts_mqtt_shutdown(&b->m);
	CHECK(POLL_UNTIL(sts_mqtt_is_closed(&b->m), 5000));
	CHECK(b->lost == 0);
	publish_str(a, "after-quit");
	CHECK(POLL_UNTIL(sts_mqtt_unacked(&a->m) == 0, 3000));
	b->n = 0;
	connect_ok(b, &ob);
	poll_for(300);
	CHECK(b->n == 0);
	publish_str(a, "resubscribed");
	CHECK(POLL_UNTIL(b->n == 1, 3000));
	CHECK(has_msg(b, 0, "resubscribed"));

	poll_clear();
	client_free(a);
	client_free(b);
}

static void test_unacked_resent(void)
{
	struct client *a = client_new();
	struct client *b = client_new();
	struct sts_mqtt_opts oa = opts("ur-a", 0);
	struct sts_mqtt_opts ob = opts("ur-b", 1);

	connect_ok(a, &oa);
	connect_ok(b, &ob);
	/* queued and maybe written, but the connection drops before PUBACK */
	publish_str(a, "fragile");
	sts_mqtt_abort(&a->m);
	CHECK(sts_mqtt_unacked(&a->m) == 1);
	connect_ok(a, &oa);
	CHECK(POLL_UNTIL(sts_mqtt_unacked(&a->m) == 0 && b->n >= 1, 3000));
	/* at least once: maybe twice */
	CHECK(count_msg(b, "fragile") >= 1);
	poll_clear();
	client_free(a);
	client_free(b);
}

static void test_will(void)
{
	struct client *a = client_new();
	struct client *b = client_new();
	struct client *c = client_new();
	struct sts_mqtt_opts oa = opts("w-a", 1);
	struct sts_mqtt_opts ob = opts("w-b", 1);
	struct sts_mqtt_opts oc = opts("w-c", 1);

	oa.will = (const uint8_t *)"a-vanished";
	oa.will_len = strlen("a-vanished");
	oc.will = (const uint8_t *)"c-vanished";
	oc.will_len = strlen("c-vanished");
	connect_ok(a, &oa);
	connect_ok(b, &ob);
	connect_ok(c, &oc);

	sts_mqtt_abort(&a->m); /* socket closed without DISCONNECT */
	CHECK(POLL_UNTIL(count_msg(b, "a-vanished") == 1, 3000));

	sts_mqtt_shutdown(&c->m);
	CHECK(POLL_UNTIL(sts_mqtt_is_closed(&c->m), 5000));
	poll_for(500);
	CHECK(count_msg(b, "c-vanished") == 0);
	poll_clear();
	client_free(a);
	client_free(b);
	client_free(c);
}

static void test_keepalive(void)
{
	struct client *a = client_new();
	struct sts_mqtt_opts oa = opts("ka-a", 1);

	oa.keepalive_s = 1;
	connect_ok(a, &oa);
	poll_for(3500); /* the broker drops us after 1.5 s silence */
	CHECK(sts_mqtt_is_ready(&a->m));
	CHECK(a->lost == 0);
	poll_clear();
	client_free(a);
}

static void test_unreachable(void)
{
	struct client *a = client_new();
	struct sts_mqtt_opts oa = opts("un-a", 1);

	oa.port = free_port();
	poll_add(a);
	if (sts_mqtt_connect(&a->m, &oa) == 0)
		CHECK(POLL_UNTIL(a->lost == 1, 5000));
	CHECK(sts_mqtt_is_closed(&a->m));
	CHECK(strstr(a->reason, "cannot reach") != NULL);
	poll_clear();
	client_free(a);
}

static void tls_attempt(struct client *c, const char *host, const char *ca,
			int verify)
{
	struct sts_mqtt_opts o = opts("tls", 1);

	o.host = host;
	o.port = tls_port;
	o.tls = 1;
	o.tls_ca_file = ca;
	o.tls_verify = verify;
	poll_add(c);
	if (sts_mqtt_connect(&c->m, &o) == 0)
		POLL_UNTIL(c->ready || c->lost, 5000);
}

static void test_tls(void)
{
	struct client *plain = client_new();
	struct client *c = client_new();
	struct sts_mqtt_opts op = opts("tls-plain", 1);

	connect_ok(plain, &op);

	/* "localhost" may resolve to ::1 first, where nobody listens */
	tls_attempt(c, "localhost", ca_file, 1);
	CHECK(c->ready == 1 && c->lost == 0);
	if (c->lost)
		fprintf(stderr, "  TLS failed: %s\n", c->reason);
	publish_str(c, "over-tls");
	CHECK(POLL_UNTIL(count_msg(plain, "over-tls") == 1, 3000));
	CHECK(POLL_UNTIL(count_msg(c, "over-tls") == 1, 3000));
	sts_mqtt_shutdown(&c->m);
	CHECK(POLL_UNTIL(sts_mqtt_is_closed(&c->m), 5000));
	CHECK(c->lost == 0);
	client_free(c);

	/* signed by somebody else */
	c = client_new();
	tls_attempt(c, "localhost", wrong_ca_file, 1);
	CHECK(c->ready == 0 && c->lost == 1);
	CHECK(strstr(c->reason, "certificate") != NULL);
	client_free(c);

	/* right authority, wrong name */
	c = client_new();
	tls_attempt(c, "127.0.0.1", ca_file, 1);
	CHECK(c->ready == 0 && c->lost == 1);
	CHECK(strstr(c->reason, "certificate") != NULL);
	client_free(c);

	/* not checking at all */
	c = client_new();
	tls_attempt(c, "127.0.0.1", wrong_ca_file, 0);
	CHECK(c->ready == 1 && c->lost == 0);
	client_free(c);

	/* plain MQTT on the TLS port fails cleanly */
	c = client_new();
	{
		struct sts_mqtt_opts o = opts("tls-mismatch", 1);

		o.port = tls_port;
		poll_add(c);
		REQUIRE(sts_mqtt_connect(&c->m, &o) == 0);
		CHECK(POLL_UNTIL(c->lost == 1, 25000));
	}
	client_free(c);

	poll_clear();
	client_free(plain);
}

/* --- room protocol over the broker ---------------------------------------- */

struct node {
	struct sts_identity id;
	struct sts_room room;
	struct client *c;
	int joins;
	int aways;
	int backs;
	int messages;
	char last[STS_TEXT_MAX + 1];
};

static int node_send(void *ud, const uint8_t *frame, size_t len)
{
	struct node *n = ud;

	return sts_mqtt_publish(&n->c->m, frame, len);
}

static void node_event(void *ud, const struct sts_event *ev)
{
	struct node *n = ud;

	switch (ev->type) {
	case STS_EV_JOIN:
		n->joins++;
		break;
	case STS_EV_AWAY:
		n->aways++;
		break;
	case STS_EV_BACK:
		n->backs++;
		break;
	case STS_EV_MESSAGE:
		n->messages++;
		memcpy(n->last, ev->text, ev->text_len);
		n->last[ev->text_len] = '\0';
		break;
	default:
		break;
	}
}

static const struct sts_room_ops node_ops = {
	.send = node_send,
	.event = node_event,
};

static void node_ready(void *ud, int session_present)
{
	struct node *n = ud;

	(void)session_present;
	n->c->ready++;
	sts_room_connected(&n->room);
}

static void node_message(void *ud, const uint8_t *data, size_t len)
{
	struct node *n = ud;

	on_message(n->c, data, len);
	sts_room_handle(&n->room, data, len);
}

static void node_lost(void *ud, const char *reason)
{
	struct node *n = ud;

	on_lost(n->c, reason);
	sts_room_disconnected(&n->room);
}

static const struct sts_mqtt_cb node_cb = {
	.ready = node_ready,
	.message = node_message,
	.lost = node_lost,
};

static char room_topic[STS_MQTT_TOPIC_MAX];

static void node_connect(struct node *n, const char *client_id)
{
	static uint8_t will[STS_MQTT_WILL_MAX];
	struct sts_mqtt_opts o = opts(client_id, 0);
	int before = n->c->ready;
	size_t will_len;

	REQUIRE(sts_room_prepare_connect(&n->room, will, sizeof(will),
					 &will_len) == 0);
	o.topic = room_topic;
	o.will = will;
	o.will_len = will_len;
	poll_add(n->c);
	REQUIRE(sts_mqtt_connect(&n->c->m, &o) == 0);
	REQUIRE(POLL_UNTIL(n->c->ready > before, 5000));
}

static void node_start(struct node *n, const char *nick, const char *key)
{
	char path[STS_PATH_MAX + 32];
	int created;

	memset(n, 0, sizeof(*n));
	snprintf(path, sizeof(path), "%s/%s", dir, key);
	REQUIRE(sts_identity_load_or_create(&n->id, path, &created) == 0);
	REQUIRE(sts_room_init(&n->room, &n->id, "e2e", "hunter2", nick, 0,
			      &node_ops, n) == 0);
	n->c = client_new();
	sts_mqtt_init(&n->c->m, &node_cb, n);
}

static void room_poll_for(struct node **nodes, size_t count, int ms)
{
	uint64_t end = sts_monotonic_ms() + (uint64_t)ms;
	size_t i;

	while (sts_monotonic_ms() < end) {
		poll_once();
		for (i = 0; i < count; i++)
			sts_room_tick(&nodes[i]->room);
	}
}

static int contains(const uint8_t *hay, size_t len, const char *needle)
{
	size_t n = strlen(needle);
	size_t i;

	for (i = 0; i + n <= len; i++)
		if (memcmp(hay + i, needle, n) == 0)
			return 1;
	return 0;
}

static void test_room_e2e(void)
{
	static struct node alice;
	static struct node bob;
	struct node *nodes[] = { &alice, &bob };
	struct client *spy = client_new();
	struct sts_mqtt_opts os = opts("spy", 1);
	const char *secret = "the eagle lands at midnight";
	int leaked = 0;
	int i;

	node_start(&alice, "alice", "alice.key");
	node_start(&bob, "bob", "bob.key");
	snprintf(room_topic, sizeof(room_topic), "sts-test/%s",
		 alice.room.keys.topic_hex);
	os.topic = room_topic;
	connect_ok(spy, &os);

	node_connect(&alice, "alice-1");
	node_connect(&bob, "bob-1");
	room_poll_for(nodes, 2, 2500);
	CHECK(alice.joins == 1 && bob.joins == 1);

	REQUIRE(sts_room_send(&alice.room, STS_KIND_TEXT, secret,
			      strlen(secret)) == 0);
	room_poll_for(nodes, 2, 500);
	CHECK(bob.messages == 1 && strcmp(bob.last, secret) == 0);

	/* nothing readable on the wire: not the text, not the nicks */
	for (i = 0; i < spy->n; i++)
		leaked |= contains(spy->msg[i], spy->len[i], "eagle") ||
			  contains(spy->msg[i], spy->len[i], "alice") ||
			  contains(spy->msg[i], spy->len[i], "e2e");
	CHECK(spy->n > 0 && !leaked);

	/* bob's link dies: the will tells alice; messages wait at the broker */
	sts_mqtt_abort(&bob.c->m);
	sts_room_disconnected(&bob.room);
	room_poll_for(nodes, 2, 500);
	CHECK(alice.aways == 1);
	REQUIRE(sts_room_send(&alice.room, STS_KIND_TEXT, "while you were out",
			      18) == 0);
	room_poll_for(nodes, 2, 300);
	node_connect(&bob, "bob-1");
	room_poll_for(nodes, 2, 1500);
	CHECK(bob.messages == 2 && strcmp(bob.last, "while you were out") == 0);
	CHECK(alice.backs == 1);

	sts_room_leave(&alice.room);
	sts_mqtt_shutdown(&alice.c->m);
	sts_mqtt_shutdown(&bob.c->m);
	room_poll_for(nodes, 2, 200);
	CHECK(POLL_UNTIL(sts_mqtt_is_closed(&alice.c->m) &&
				 sts_mqtt_is_closed(&bob.c->m),
			 5000));

	poll_clear();
	sts_room_free(&alice.room);
	sts_room_free(&bob.room);
	sts_identity_free(&alice.id);
	sts_identity_free(&bob.id);
	client_free(alice.c);
	client_free(bob.c);
	client_free(spy);
}

int main(int argc, char **argv)
{
	if (argc != 3 || access(argv[1], X_OK) != 0 ||
	    access(argv[2], X_OK) != 0) {
		fprintf(stderr, "usage: %s MOSQUITTO OPENSSL (skipped)\n",
			argv[0]);
		return SKIP;
	}
	signal(SIGPIPE, SIG_IGN);
	sts_log_set_level(getenv("STS_DEBUG") ? STS_LOG_DEBUG : STS_LOG_ERROR);
	REQUIRE(sts_crypto_init() == 0);
	test_tmpdir(dir, sizeof(dir));
	make_certs(argv[2]);
	start_broker(argv[1]);

	RUN(test_roundtrip);
	RUN(test_offline_queue);
	RUN(test_persistent_session);
	RUN(test_unacked_resent);
	RUN(test_will);
	RUN(test_keepalive);
	RUN(test_unreachable);
	RUN(test_tls);
	RUN(test_room_e2e);

	stop_broker();
	run_cmd("rm -rf '%s'", dir);
	return test_summary();
}
