// SPDX-License-Identifier: Apache-2.0
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "MQTTPacket.h"

#include "log.h"
#include "mqtt.h"
#include "crypto.h"
#include "util.h"

#define ATTEMPT_TIMEOUT_MS 10000 /* per address */
#define CONNECT_TIMEOUT_MS 20000 /* until subscribed */
#define DRAIN_TIMEOUT_MS 3000
#define CLOSE_TIMEOUT_MS 1000
#define PACKET_MAX (1024 * 1024)
#define OUT_MAX (8 * 1024 * 1024)
#define READ_CHUNK 4096

struct sts_mqtt_msg {
	struct sts_mqtt_msg *next;
	uint16_t pid; /* 0 until first sent */
	int sent; /* on the current connection */
	size_t len;
	uint8_t data[];
};

static const char *const state_names[] = {
	"disconnected", "connecting", "TLS handshake", "logging in",
	"subscribing",	"connected",  "leaving",       "leaving",
};

const char *sts_mqtt_state_name(enum sts_mqtt_state st)
{
	if ((size_t)st >= STS_ARRAY_SIZE(state_names))
		return "?";
	return state_names[st];
}

void sts_mqtt_init(struct sts_mqtt *m, const struct sts_mqtt_cb *cb, void *ud)
{
	memset(m, 0, sizeof(*m));
	m->sock = STS_SOCK_INVALID;
	m->cb = *cb;
	m->ud = ud;
	m->next_pid = 1;
}

/* --- low level ----------------------------------------------------------- */

static void close_transport(struct sts_mqtt *m)
{
	if (m->use_tls && m->state > STS_MQTT_CONNECTING)
		sts_tls_free(&m->tls);
	if (m->sock != STS_SOCK_INVALID)
		sts_sock_close(m->sock);
	m->sock = STS_SOCK_INVALID;
	m->out_len = 0;
	m->out_off = 0;
	m->in_len = 0;
	m->tls_retry = 0;
	m->tls_want_write = 0;
	m->ping_sent_ms = 0;
	m->state = STS_MQTT_CLOSED;
}

static void fail(struct sts_mqtt *m, const char *fmt, ...) STS_PRINTF(2, 3);

static void fail(struct sts_mqtt *m, const char *fmt, ...)
{
	va_list ap;

	if (m->state == STS_MQTT_CLOSED)
		return;
	va_start(ap, fmt);
	vsnprintf(m->error, sizeof(m->error), fmt, ap);
	va_end(ap);
	close_transport(m);
	if (m->cb.lost != NULL)
		m->cb.lost(m->ud, m->error);
}

static int out_reserve(struct sts_mqtt *m, size_t n)
{
	uint8_t *p;
	size_t cap;

	/* forget what was already written */
	if (m->out_off > 0 && m->tls_retry == 0) {
		memmove(m->out, m->out + m->out_off, m->out_len - m->out_off);
		m->out_len -= m->out_off;
		m->out_off = 0;
	}
	if (m->out_len + n <= m->out_cap)
		return 0;

	cap = m->out_cap ? m->out_cap : 16384;
	while (cap < m->out_len + n)
		cap *= 2;
	if (cap > OUT_MAX)
		return -1;
	p = realloc(m->out, cap);
	if (p == NULL)
		return -1;
	m->out = p;
	m->out_cap = cap;
	return 0;
}

static long raw_write(struct sts_mqtt *m, const uint8_t *buf, size_t len)
{
	return m->use_tls ? sts_tls_write(&m->tls, buf, len) :
			    sts_sock_send(m->sock, buf, len);
}

static long raw_read(struct sts_mqtt *m, uint8_t *buf, size_t len)
{
	return m->use_tls ? sts_tls_read(&m->tls, buf, len) :
			    sts_sock_recv(m->sock, buf, len);
}

static void flush(struct sts_mqtt *m)
{
	size_t len;
	long n;

	while (m->state != STS_MQTT_CLOSED && m->out_off < m->out_len) {
		/* TLS wants the very same write repeated */
		len = m->tls_retry ? m->tls_retry : m->out_len - m->out_off;
		n = raw_write(m, m->out + m->out_off, len);
		if (n == STS_IO_AGAIN) {
			if (m->use_tls)
				m->tls_retry = len;
			return;
		}
		if (n <= 0) {
			fail(m, "cannot send to the broker: %s",
			     m->use_tls ? m->tls.error : sts_sock_error());
			return;
		}
		m->tls_retry = 0;
		m->out_off += (size_t)n;
		m->last_tx_ms = sts_monotonic_ms();
	}
	if (m->out_off == m->out_len && m->tls_retry == 0) {
		m->out_off = 0;
		m->out_len = 0;
	}
}

/* room for a packet of at most @max bytes at the end of the output */
static unsigned char *out_space(struct sts_mqtt *m, size_t max)
{
	if (out_reserve(m, max) != 0)
		return NULL;
	return m->out + m->out_len;
}

/* @len: what the serializer returned */
static int out_commit(struct sts_mqtt *m, int len)
{
	if (len <= 0)
		return -1;
	m->out_len += (size_t)len;
	return 0;
}

static uint16_t take_pid(struct sts_mqtt *m)
{
	uint16_t pid = m->next_pid++;

	if (m->next_pid == 0)
		m->next_pid = 1;
	return pid;
}

static int send_connect(struct sts_mqtt *m)
{
	MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
	unsigned char *buf;
	size_t max = 64 + strlen(m->client_id) + strlen(m->topic) +
		     m->will_len + strlen(m->username) + strlen(m->password);

	data.MQTTVersion = 4; /* 3.1.1 */
	data.clientID.cstring = m->client_id;
	data.keepAliveInterval = (unsigned short)(m->keepalive_ms / 1000);
	data.cleansession = (unsigned char)m->clean_session;
	if (m->username[0] != '\0')
		data.username.cstring = m->username;
	if (m->password[0] != '\0')
		data.password.cstring = m->password;
	if (m->will_len > 0) {
		data.willFlag = 1;
		data.will.topicName.cstring = m->topic;
		data.will.message.lenstring.data = (char *)m->will;
		data.will.message.lenstring.len = (int)m->will_len;
		data.will.qos = 1;
		data.will.retained = 0;
	}
	buf = out_space(m, max);
	if (buf == NULL)
		return -1;
	return out_commit(m, MQTTSerialize_connect(buf, (int)max, &data));
}

static int send_subscribe(struct sts_mqtt *m)
{
	MQTTString topic = MQTTString_initializer;
	size_t max = 16 + strlen(m->topic);
	unsigned char *buf;
	int qos = 1;

	topic.cstring = m->topic;
	m->sub_pid = take_pid(m);
	buf = out_space(m, max);
	if (buf == NULL)
		return -1;
	return out_commit(m,
			  MQTTSerialize_subscribe(buf, (int)max, 0, m->sub_pid,
						  1, &topic, &qos));
}

static int send_publish(struct sts_mqtt *m, struct sts_mqtt_msg *msg, int dup)
{
	MQTTString topic = MQTTString_initializer;
	size_t max = 16 + strlen(m->topic) + msg->len;
	unsigned char *buf;

	topic.cstring = m->topic;
	buf = out_space(m, max);
	if (buf == NULL)
		return -1;
	return out_commit(m, MQTTSerialize_publish(buf, (int)max,
						   (unsigned char)dup, 1, 0,
						   msg->pid, topic, msg->data,
						   (int)msg->len));
}

/* send queued messages, at most STS_MQTT_INFLIGHT unacknowledged */
static void pump(struct sts_mqtt *m)
{
	struct sts_mqtt_msg *msg;

	if (m->state != STS_MQTT_READY && m->state != STS_MQTT_DRAINING)
		return;

	for (msg = m->queue; msg != NULL && m->inflight < STS_MQTT_INFLIGHT;
	     msg = msg->next) {
		int dup;

		if (msg->sent)
			continue;
		/* resent under the same id when the session survived */
		dup = msg->pid != 0 && m->session_present;
		if (!dup)
			msg->pid = take_pid(m);
		if (send_publish(m, msg, dup) != 0) {
			fail(m, "%s", "output buffer full");
			return;
		}
		msg->sent = 1;
		m->inflight++;
	}
}

static void acked(struct sts_mqtt *m, uint16_t pid)
{
	struct sts_mqtt_msg *prev = NULL;
	struct sts_mqtt_msg *msg;

	for (msg = m->queue; msg != NULL; prev = msg, msg = msg->next) {
		if (!msg->sent || msg->pid != pid)
			continue;
		if (prev != NULL)
			prev->next = msg->next;
		else
			m->queue = msg->next;
		if (m->queue_tail == msg)
			m->queue_tail = prev;
		m->queued--;
		m->inflight--;
		free(msg);
		return;
	}
}

/* --- packets in ---------------------------------------------------------- */

static void on_publish(struct sts_mqtt *m, unsigned char *buf, int len)
{
	MQTTString topic = MQTTString_initializer;
	unsigned char *payload;
	unsigned char *out;
	unsigned char retained;
	unsigned char dup;
	unsigned short pid;
	int payload_len;
	int qos;

	if (MQTTDeserialize_publish(&dup, &qos, &retained, &pid, &topic,
				    &payload, &payload_len, buf, len) != 1 ||
	    qos > 1) {
		fail(m, "%s", "malformed message from the broker");
		return;
	}

	out = qos == 1 ? out_space(m, 4) : NULL;
	if (qos == 1 &&
	    (out == NULL ||
	     out_commit(m, MQTTSerialize_puback(out, 4, pid)) != 0)) {
		fail(m, "%s", "output buffer full");
		return;
	}

	if (topic.lenstring.len != (int)strlen(m->topic) ||
	    memcmp(topic.lenstring.data, m->topic,
		   (size_t)topic.lenstring.len) != 0)
		return;
	if (m->cb.message != NULL && payload_len >= 0)
		m->cb.message(m->ud, payload, (size_t)payload_len);
}

static const char *connack_reason(unsigned char rc)
{
	switch (rc) {
	case 1:
		return "protocol version refused";
	case 2:
		return "client id refused";
	case 3:
		return "server unavailable";
	case 4:
		return "bad user name or password";
	case 5:
		return "not authorized";
	default:
		return "refused";
	}
}

static void on_packet(struct sts_mqtt *m, unsigned char *buf, int len)
{
	unsigned char type = buf[0] >> 4;
	unsigned char session;
	unsigned char rc;
	unsigned char dup;
	unsigned short pid;
	int granted[1];
	int count;

	switch (type) {
	case CONNACK:
		if (m->state != STS_MQTT_CONNACK ||
		    MQTTDeserialize_connack(&session, &rc, buf, len) != 1) {
			fail(m, "%s", "unexpected CONNACK");
			return;
		}
		if (rc != 0) {
			fail(m, "broker refused the connection: %s",
			     connack_reason(rc));
			return;
		}
		m->session_present = session != 0;
		if (send_subscribe(m) != 0) {
			fail(m, "%s", "output buffer full");
			return;
		}
		m->state = STS_MQTT_SUBACK;
		break;

	case SUBACK:
		if (m->state != STS_MQTT_SUBACK ||
		    MQTTDeserialize_suback(&pid, 1, &count, granted, buf,
					   len) != 1 ||
		    pid != m->sub_pid) {
			fail(m, "%s", "unexpected SUBACK");
			return;
		}
		if (count != 1 || granted[0] == 0x80) {
			fail(m, "%s", "broker refused the subscription");
			return;
		}
		m->state = STS_MQTT_READY;
		if (m->cb.ready != NULL)
			m->cb.ready(m->ud, m->session_present);
		pump(m);
		break;

	case PUBLISH:
		if (m->state < STS_MQTT_SUBACK) {
			fail(m, "%s", "unexpected PUBLISH");
			return;
		}
		on_publish(m, buf, len);
		break;

	case PUBACK:
		if (MQTTDeserialize_ack(&type, &dup, &pid, buf, len) == 1)
			acked(m, pid);
		pump(m);
		break;

	case UNSUBACK:
	case PINGRESP:
		break;

	default:
		fail(m, "%s", "unexpected packet from the broker");
		break;
	}
}

/* @return the packet length once complete, 0 if more bytes are needed */
static size_t packet_len(struct sts_mqtt *m, size_t *need)
{
	size_t rem = 0;
	size_t mult = 1;
	size_t i;

	for (i = 1; i < m->in_len && i <= 4; i++) {
		rem += (m->in[i] & 127) * mult;
		if ((m->in[i] & 128) == 0) {
			*need = 1 + i + rem;
			return m->in_len >= *need ? *need : 0;
		}
		mult *= 128;
	}
	*need = i > 4 ? (size_t)-1 : 0;
	return 0;
}

static void read_packets(struct sts_mqtt *m)
{
	size_t need = 0;
	size_t total;
	uint8_t *p;
	long n;

	for (;;) {
		if (m->in_cap - m->in_len < READ_CHUNK) {
			size_t cap = m->in_cap ? m->in_cap * 2 : 16384;

			if (cap > PACKET_MAX + 16) {
				fail(m, "%s", "packet too large");
				return;
			}
			p = realloc(m->in, cap);
			if (p == NULL) {
				fail(m, "%s", "out of memory");
				return;
			}
			m->in = p;
			m->in_cap = cap;
		}

		n = raw_read(m, m->in + m->in_len, m->in_cap - m->in_len);
		if (n == STS_IO_AGAIN)
			break;
		if (n == 0) {
			fail(m, "%s", "closed by the broker");
			return;
		}
		if (n < 0) {
			fail(m, "read error: %s",
			     m->use_tls ? m->tls.error : sts_sock_error());
			return;
		}
		m->in_len += (size_t)n;
		m->last_rx_ms = sts_monotonic_ms();

		while (m->state != STS_MQTT_CLOSED &&
		       (total = packet_len(m, &need)) > 0) {
			on_packet(m, m->in, (int)total);
			if (m->state == STS_MQTT_CLOSED)
				return;
			memmove(m->in, m->in + total, m->in_len - total);
			m->in_len -= total;
		}
		if (need == (size_t)-1 || need > PACKET_MAX) {
			fail(m, "%s", "malformed or oversized packet");
			return;
		}
	}
}

/* --- connection ---------------------------------------------------------- */

static int start_session(struct sts_mqtt *m)
{
	if (send_connect(m) != 0) {
		fail(m, "%s", "cannot build CONNECT");
		return -1;
	}
	m->state = STS_MQTT_CONNACK;
	m->last_rx_ms = sts_monotonic_ms();
	flush(m);
	return 0;
}

static void next_address(struct sts_mqtt *m, const char *why)
{
	int rc;

	if (m->sock != STS_SOCK_INVALID)
		sts_sock_close(m->sock);
	m->sock = STS_SOCK_INVALID;

	while (m->addr_next < m->addrs.count) {
		rc = sts_sock_connect(&m->addrs.addr[m->addr_next++], &m->sock);
		if (rc < 0)
			continue;
		m->attempt_deadline_ms =
			sts_monotonic_ms() + ATTEMPT_TIMEOUT_MS;
		m->state = STS_MQTT_CONNECTING;
		if (rc == 0)
			sts_mqtt_process(m);
		return;
	}

	fail(m, "cannot reach %s:%d: %s", m->host, m->port, why);
}

static void connected_tcp(struct sts_mqtt *m)
{
	if (!m->use_tls) {
		start_session(m);
		return;
	}
	if (sts_tls_init(&m->tls, m->sock, m->host, m->tls_ca_file,
			 m->tls_verify) != 0) {
		char err[sizeof(m->tls.error)];

		memcpy(err, m->tls.error, sizeof(err));
		sts_tls_free(&m->tls);
		m->state = STS_MQTT_CONNECTING; /* nothing to free twice */
		fail(m, "%s", err);
		return;
	}
	m->state = STS_MQTT_TLS;
}

int sts_mqtt_connect(struct sts_mqtt *m, const struct sts_mqtt_opts *o)
{
	char err[128];
	struct sts_mqtt_msg *msg;

	if (m->state != STS_MQTT_CLOSED)
		close_transport(m);

	if (sts_strlcpy(m->host, o->host, sizeof(m->host)) != 0 ||
	    sts_strlcpy(m->topic, o->topic, sizeof(m->topic)) != 0 ||
	    sts_strlcpy(m->client_id, o->client_id, sizeof(m->client_id)) !=
		    0 ||
	    sts_strlcpy(m->username, o->username ? o->username : "",
			sizeof(m->username)) != 0 ||
	    sts_strlcpy(m->password, o->password ? o->password : "",
			sizeof(m->password)) != 0 ||
	    sts_strlcpy(m->tls_ca_file, o->tls_ca_file ? o->tls_ca_file : "",
			sizeof(m->tls_ca_file)) != 0 ||
	    o->will_len > sizeof(m->will)) {
		snprintf(m->error, sizeof(m->error), "invalid options");
		return -1;
	}
	m->port = o->port;
	m->use_tls = o->tls;
	m->tls_verify = o->tls_verify;
	m->keepalive_ms = (uint64_t)o->keepalive_s * 1000;
	m->clean_session = o->clean_session;
	m->will_len = o->will_len;
	if (o->will_len > 0)
		memcpy(m->will, o->will, o->will_len);

	/* whatever wasn't acknowledged goes out again */
	for (msg = m->queue; msg != NULL; msg = msg->next)
		msg->sent = 0;
	m->inflight = 0;

	if (sts_resolve(m->host, m->port, &m->addrs, err, sizeof(err)) != 0) {
		snprintf(m->error, sizeof(m->error), "cannot resolve %s: %s",
			 m->host, err);
		return -1;
	}
	m->addr_next = 0;
	m->connect_deadline_ms = sts_monotonic_ms() + CONNECT_TIMEOUT_MS;
	m->error[0] = '\0';
	m->state = STS_MQTT_CONNECTING;
	next_address(m, "no address");
	return m->state == STS_MQTT_CLOSED ? -1 : 0;
}

void sts_mqtt_wait_spec(const struct sts_mqtt *m, intptr_t *sock,
			int *want_write)
{
	*sock = m->sock;
	*want_write = 0;
	if (m->state == STS_MQTT_CLOSED) {
		*sock = STS_SOCK_INVALID;
		return;
	}
	if (m->state == STS_MQTT_CONNECTING)
		*want_write = 1;
	else if (m->state == STS_MQTT_TLS)
		*want_write = m->tls_want_write;
	else
		*want_write = m->out_off < m->out_len;
}

static void keepalive(struct sts_mqtt *m, uint64_t now)
{
	unsigned char *buf;

	if (m->keepalive_ms == 0)
		return;

	if (m->ping_sent_ms != 0) {
		if (m->last_rx_ms >= m->ping_sent_ms)
			m->ping_sent_ms = 0;
		else if (now - m->ping_sent_ms >= m->keepalive_ms)
			fail(m, "%s", "no answer from the broker");
		return;
	}

	/* the broker drops clients silent for 1.5 keep-alive periods */
	if (now - m->last_tx_ms < m->keepalive_ms / 2)
		return;
	buf = out_space(m, 2);
	if (buf == NULL || out_commit(m, MQTTSerialize_pingreq(buf, 2)) != 0) {
		fail(m, "%s", "output buffer full");
		return;
	}
	m->ping_sent_ms = now;
}

static void finish_close(struct sts_mqtt *m)
{
	MQTTString topic = MQTTString_initializer;
	size_t max = 16 + strlen(m->topic);
	unsigned char *buf;

	topic.cstring = m->topic;
	/* without subscription the broker stops queueing for us */
	if (!m->clean_session) {
		buf = out_space(m, max);
		if (buf != NULL)
			out_commit(m, MQTTSerialize_unsubscribe(buf, (int)max,
								0, take_pid(m),
								1, &topic));
	}
	buf = out_space(m, 2);
	if (buf != NULL)
		out_commit(m, MQTTSerialize_disconnect(buf, 2));
	m->state = STS_MQTT_CLOSING;
	m->drain_deadline_ms = sts_monotonic_ms() + CLOSE_TIMEOUT_MS;
	flush(m);
}

void sts_mqtt_process(struct sts_mqtt *m)
{
	uint64_t now = sts_monotonic_ms();
	int rc;

	switch (m->state) {
	case STS_MQTT_CLOSED:
		return;

	case STS_MQTT_CONNECTING:
		if (now >= m->connect_deadline_ms) {
			fail(m, "%s", "connection timed out");
			return;
		}
		if (now >= m->attempt_deadline_ms) {
			next_address(m, "timed out");
			return;
		}
		/* done once writable (or failed): check without blocking */
		{
			struct sts_wait w = { .sock = m->sock,
					      .want_write = 1 };
			int input;

			if (sts_wait(&w, 1, 0, 0, &input) != 0 || !w.writable)
				return;
		}
		if (sts_sock_connect_finish(m->sock) != 0) {
			next_address(m, sts_sock_error());
			return;
		}
		connected_tcp(m);
		return;

	case STS_MQTT_TLS:
		if (now >= m->connect_deadline_ms) {
			fail(m, "%s", "TLS handshake timed out");
			return;
		}
		rc = sts_tls_handshake(&m->tls);
		if (rc < 0) {
			char err[sizeof(m->tls.error)];

			memcpy(err, m->tls.error, sizeof(err));
			fail(m, "%s", err);
			return;
		}
		m->tls_want_write = rc == STS_TLS_WANT_WRITE;
		if (rc == 0)
			start_session(m);
		return;

	case STS_MQTT_CONNACK:
	case STS_MQTT_SUBACK:
		if (now >= m->connect_deadline_ms) {
			fail(m, "%s", "the broker didn't answer in time");
			return;
		}
		break;

	case STS_MQTT_DRAINING:
		if (m->queued == 0 || now >= m->drain_deadline_ms) {
			finish_close(m);
			return;
		}
		break;

	case STS_MQTT_CLOSING:
		flush(m);
		if (m->out_len == 0 || now >= m->drain_deadline_ms)
			close_transport(m);
		return;

	case STS_MQTT_READY:
		break;
	}

	read_packets(m);
	if (m->state == STS_MQTT_CLOSED)
		return;
	if (m->state == STS_MQTT_READY || m->state == STS_MQTT_DRAINING) {
		pump(m);
		keepalive(m, now);
	}
	flush(m);

	if (m->state == STS_MQTT_DRAINING && m->queued == 0)
		finish_close(m);
}

int sts_mqtt_publish(struct sts_mqtt *m, const uint8_t *data, size_t len)
{
	struct sts_mqtt_msg *msg;

	if (m->queued >= STS_MQTT_QUEUE_MAX || len > PACKET_MAX)
		return -1;
	msg = malloc(sizeof(*msg) + len);
	if (msg == NULL)
		return -1;
	msg->next = NULL;
	msg->pid = 0;
	msg->sent = 0;
	msg->len = len;
	memcpy(msg->data, data, len);

	if (m->queue_tail != NULL)
		m->queue_tail->next = msg;
	else
		m->queue = msg;
	m->queue_tail = msg;
	m->queued++;

	if (m->state == STS_MQTT_READY || m->state == STS_MQTT_DRAINING) {
		pump(m);
		flush(m);
	}
	return 0;
}

int sts_mqtt_is_ready(const struct sts_mqtt *m)
{
	return m->state == STS_MQTT_READY;
}

int sts_mqtt_is_closed(const struct sts_mqtt *m)
{
	return m->state == STS_MQTT_CLOSED;
}

size_t sts_mqtt_unacked(const struct sts_mqtt *m)
{
	return m->queued;
}

void sts_mqtt_shutdown(struct sts_mqtt *m)
{
	if (m->state == STS_MQTT_READY) {
		m->state = STS_MQTT_DRAINING;
		m->drain_deadline_ms = sts_monotonic_ms() + DRAIN_TIMEOUT_MS;
		sts_mqtt_process(m);
		return;
	}
	if (m->state != STS_MQTT_DRAINING && m->state != STS_MQTT_CLOSING)
		close_transport(m);
}

void sts_mqtt_abort(struct sts_mqtt *m)
{
	close_transport(m);
}

void sts_mqtt_free(struct sts_mqtt *m)
{
	struct sts_mqtt_msg *msg;

	close_transport(m);
	while (m->queue != NULL) {
		msg = m->queue;
		m->queue = msg->next;
		free(msg);
	}
	free(m->out);
	free(m->in);
	sts_memzero(m->password, sizeof(m->password));
	memset(m, 0, sizeof(*m));
	m->sock = STS_SOCK_INVALID;
}
