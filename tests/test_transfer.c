// SPDX-License-Identifier: Apache-2.0
/*
 * File transfers over the in-memory broker: accepting, refusing, losses,
 * duplicates, corrupt data, hostile names, never replacing files.
 */
#include <stdio.h>
#include <string.h>

#include "bus.h"
#include "test.h"
#include "transfer.h"
#include "wire.h"

static struct bus bus;
static char dir[STS_PATH_MAX];
static unsigned int counter;

struct peer {
	struct client *c;
	struct sts_xfers xs;
	int events[STS_XFER_EV_TOO_BIG + 1];
	unsigned int offer; /* number of the last offer */
	char path[STS_PATH_MAX];
	char detail[256];
};

static struct peer peers[2];

static uint64_t mono(void *ud)
{
	(void)ud;
	return bus_mono;
}

static void on_xfer(void *ud, const struct sts_xfer_event *ev)
{
	struct peer *p = ud;

	p->events[ev->type]++;
	if (ev->type == STS_XFER_EV_OFFER)
		p->offer = ev->xfer->num;
	if (ev->type == STS_XFER_EV_DONE && ev->detail != NULL)
		snprintf(p->path, sizeof(p->path), "%s", ev->detail);
	if (ev->type == STS_XFER_EV_FAILED)
		snprintf(p->detail, sizeof(p->detail), "%s", ev->detail);
}

static const struct sts_xfer_ops ops = {
	.event = on_xfer,
	.monotonic_ms = mono,
};

static void hook(struct client *c, const struct sts_event *ev)
{
	struct peer *p = c->hook_ud;

	if (ev->type == STS_EV_FILE)
		sts_xfers_handle(&p->xs, ev->member, ev->text, ev->text_len);
	if (ev->type == STS_EV_LEAVE)
		sts_xfers_gone(&p->xs, ev->member->sid);
}

static void setup(void)
{
	int i;

	bus_init(&bus);
	memset(peers, 0, sizeof(peers));
	for (i = 0; i < 2; i++) {
		peers[i].c = bus_client(&bus);
		peers[i].c->hook = hook;
		peers[i].c->hook_ud = &peers[i];
	}
	REQUIRE(bus_join(peers[0].c, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(peers[1].c, "neotokyo", "bob") == 0);
	for (i = 0; i < 2; i++)
		sts_xfers_init(&peers[i].xs, &peers[i].c->room, &counter, &ops,
			       &peers[i]);
}

static void teardown(void)
{
	sts_xfers_free(&peers[0].xs);
	sts_xfers_free(&peers[1].xs);
	bus_free(&bus);
}

static void run(uint64_t ms)
{
	while (ms > 0) {
		uint64_t step = ms < 50 ? ms : 50;

		bus_mono += step;
		bus_wall += step;
		ms -= step;
		sts_xfers_tick(&peers[0].xs);
		sts_xfers_tick(&peers[1].xs);
		bus_tick(&bus);
	}
}

static void write_file(const char *path, const uint8_t *data, size_t len)
{
	FILE *fp = fopen(path, "wb");

	REQUIRE(fp != NULL);
	REQUIRE(fwrite(data, 1, len, fp) == len);
	fclose(fp);
}

static int same_content(const char *path, const uint8_t *data, size_t len)
{
	static uint8_t buf[2 * 1024 * 1024];
	FILE *fp = fopen(path, "rb");
	size_t n;

	if (fp == NULL)
		return 0;
	n = fread(buf, 1, sizeof(buf), fp);
	fclose(fp);
	return n == len && memcmp(buf, data, len) == 0;
}

static const uint8_t *bob_sid(void)
{
	return peers[1].c->room.sid;
}

/* a file of @len random bytes in the test directory */
static uint8_t *make_file(const char *name, size_t len, char *path, size_t cap)
{
	uint8_t *data = malloc(len ? len : 1);

	REQUIRE(data != NULL);
	REQUIRE(sts_random(data, len ? len : 1) == 0);
	snprintf(path, cap, "%s/%s", dir, name);
	write_file(path, data, len);
	return data;
}

static int out_dir(char *out, size_t cap, const char *name)
{
	snprintf(out, cap, "%s/%s", dir, name);
	return sts_mkdirs(out);
}

static void send_and_accept(const char *src, const char *into)
{
	int before = peers[1].events[STS_XFER_EV_OFFER];
	char err[256];
	int num;

	num = sts_xfer_send(&peers[0].xs, bob_sid(), src, err, sizeof(err));
	REQUIRE(num > 0);
	run(200);
	REQUIRE(peers[1].events[STS_XFER_EV_OFFER] == before + 1);
	CHECK(sts_xfer_accept(&peers[1].xs, peers[1].offer, into, err,
			      sizeof(err)) == 0);
}

static void test_send(void)
{
	char src[STS_PATH_MAX + 32];
	char into[STS_PATH_MAX + 32];
	const size_t len = 300 * 1000 + 7;
	const struct sts_xfer *x;
	uint8_t *data;

	setup();
	data = make_file("photo.jpg", len, src, sizeof(src));
	REQUIRE(out_dir(into, sizeof(into), "in1") == 0);

	REQUIRE(sts_xfer_send(&peers[0].xs, bob_sid(), src, NULL, 0) > 0);
	run(200);
	CHECK(peers[1].events[STS_XFER_EV_OFFER] == 1);
	x = sts_xfer_find(&peers[1].xs, peers[1].offer);
	REQUIRE(x != NULL);
	CHECK(strcmp(x->name, "photo.jpg") == 0 && x->size == len);
	CHECK(strcmp(x->nick, "alice") == 0);

	/* nothing is sent before the answer */
	run(3000);
	CHECK(peers[1].events[STS_XFER_EV_PROGRESS] == 0);

	CHECK(sts_xfer_accept(&peers[1].xs, peers[1].offer, into, NULL, 0) ==
	      0);
	run(10000);
	CHECK(peers[0].events[STS_XFER_EV_ACCEPTED] == 1);
	CHECK(peers[0].events[STS_XFER_EV_DONE] == 1);
	CHECK(peers[1].events[STS_XFER_EV_DONE] == 1);
	CHECK(peers[1].events[STS_XFER_EV_PROGRESS] == 3); /* 25, 50, 75 % */
	CHECK(peers[0].events[STS_XFER_EV_FAILED] == 0);
	CHECK(strstr(peers[1].path, "/in1/photo.jpg") != NULL);
	CHECK(same_content(peers[1].path, data, len));

	/* the same name again: a new file next to it */
	send_and_accept(src, into);
	run(10000);
	CHECK(peers[1].events[STS_XFER_EV_DONE] == 2);
	CHECK(strstr(peers[1].path, "/in1/photo (2).jpg") != NULL);
	CHECK(same_content(peers[1].path, data, len));
	free(data);
	teardown();
}

static void test_refuse_and_cancel(void)
{
	char src[STS_PATH_MAX + 32];
	char into[STS_PATH_MAX + 32];
	uint8_t *data;
	int num;

	setup();
	data = make_file("notes.txt", 5000, src, sizeof(src));
	REQUIRE(out_dir(into, sizeof(into), "in2") == 0);

	REQUIRE(sts_xfer_send(&peers[0].xs, bob_sid(), src, NULL, 0) > 0);
	run(200);
	CHECK(sts_xfer_refuse(&peers[1].xs, peers[1].offer) == 0);
	run(200);
	CHECK(peers[0].events[STS_XFER_EV_REFUSED] == 1);
	CHECK(peers[1].events[STS_XFER_EV_DONE] == 0);

	/* the sender stops while bob decides */
	num = sts_xfer_send(&peers[0].xs, bob_sid(), src, NULL, 0);
	run(200);
	CHECK(sts_xfer_cancel(&peers[0].xs, (unsigned int)num) == 0);
	run(200);
	CHECK(peers[1].events[STS_XFER_EV_FAILED] == 1);
	CHECK(strstr(peers[1].detail, "cancelled") != NULL);
	CHECK(sts_xfer_accept(&peers[1].xs, peers[1].offer, into, NULL, 0) !=
	      0);

	/* nobody answers */
	REQUIRE(sts_xfer_send(&peers[0].xs, bob_sid(), src, NULL, 0) > 0);
	run(STS_XFER_ANSWER_MS + 1000);
	CHECK(peers[0].events[STS_XFER_EV_FAILED] == 1);
	CHECK(strcmp(peers[0].detail, "no answer") == 0);
	free(data);
	teardown();
}

static unsigned int drop_seed = 12345;

/* lose about one frame in 8, both ways */
static int lossy(const struct frame *f, int to, void *ud)
{
	(void)f;
	(void)to;
	(void)ud;
	drop_seed = drop_seed * 1103515245 + 12345;
	return (drop_seed >> 16) % 8 == 0;
}

static void test_losses_and_duplicates(void)
{
	char src[STS_PATH_MAX + 32];
	char into[STS_PATH_MAX + 32];
	const size_t len = 120 * 1000;
	uint8_t *data;

	setup();
	data = make_file("lossy.bin", len, src, sizeof(src));
	REQUIRE(out_dir(into, sizeof(into), "in3") == 0);

	bus.filter = lossy;
	send_and_accept(src, into);
	{
		run(120000);
		CHECK(peers[1].events[STS_XFER_EV_DONE] == 1);
		CHECK(peers[0].events[STS_XFER_EV_DONE] == 1);
		CHECK(same_content(peers[1].path, data, len));
	}
	bus.filter = NULL;

	bus.duplicate = 1;
	send_and_accept(src, into);
	run(20000);
	CHECK(peers[1].events[STS_XFER_EV_DONE] == 2);
	CHECK(same_content(peers[1].path, data, len));
	bus.duplicate = 0;
	free(data);
	teardown();
}

static void test_corrupt_and_empty(void)
{
	char src[STS_PATH_MAX + 32];
	char into[STS_PATH_MAX + 32];
	char part[STS_PATH_MAX + 64];
	struct sts_xfer *x;
	uint8_t *data;
	int num;

	setup();
	data = make_file("doc.pdf", 50000, src, sizeof(src));
	REQUIRE(out_dir(into, sizeof(into), "in4") == 0);

	/* what arrives doesn't match the announced SHA-256 */
	num = sts_xfer_send(&peers[0].xs, bob_sid(), src, NULL, 0);
	REQUIRE(num > 0);
	/* the file changes on disk after the offer */
	{
		FILE *fp = fopen(src, "rb+");

		REQUIRE(fp != NULL);
		fseek(fp, 1000, SEEK_SET);
		fputc(data[1000] ^ 1, fp);
		fclose(fp);
	}
	run(200);
	CHECK(sts_xfer_accept(&peers[1].xs, peers[1].offer, into, NULL, 0) ==
	      0);
	x = sts_xfer_find(&peers[1].xs, peers[1].offer);
	REQUIRE(x != NULL);
	snprintf(part, sizeof(part), "%s", x->part);
	run(10000);
	CHECK(peers[1].events[STS_XFER_EV_FAILED] == 1);
	CHECK(strstr(peers[1].detail, "corrupt") != NULL);
	CHECK(peers[0].events[STS_XFER_EV_FAILED] == 1);
	CHECK(!sts_file_exists(part));
	snprintf(part, sizeof(part), "%s/doc.pdf", into);
	CHECK(!sts_file_exists(part));
	free(data);

	/* an empty file */
	data = make_file("empty", 0, src, sizeof(src));
	send_and_accept(src, into);
	run(2000);
	CHECK(peers[1].events[STS_XFER_EV_DONE] == 1);
	CHECK(peers[0].events[STS_XFER_EV_DONE] == 1);
	CHECK(same_content(peers[1].path, data, 0));
	free(data);
	teardown();
}

/* an offer written by hand, as a hostile sender could */
static void raw_offer(const char *name, uint64_t size)
{
	uint8_t buf[512];
	uint8_t hash[STS_HASH_LEN] = { 0 };
	struct sts_wbuf w;
	uint64_t id;

	REQUIRE(sts_random(&id, sizeof(id)) == 0);
	sts_wbuf_init(&w, buf, sizeof(buf));
	sts_w_u8(&w, 1);
	sts_w_u64(&w, id);
	sts_w_u64(&w, size);
	sts_w_bytes(&w, hash, sizeof(hash));
	sts_w_u8(&w, (uint8_t)strlen(name));
	sts_w_bytes(&w, name, strlen(name));
	REQUIRE(sts_room_send_file(&peers[0].c->room, bob_sid(), buf, w.len) ==
		0);
	run(200);
}

static void test_hostile_offers(void)
{
	static const char *const names[] = {
		"../../.bashrc", "/etc/passwd",	    "a/../../b", "..",
		".hidden",	 "evil\033[2Jname", "  ",
	};
	const struct sts_xfer *x;
	size_t i;

	setup();
	for (i = 0; i < STS_ARRAY_SIZE(names); i++) {
		raw_offer(names[i], 10);
		x = sts_xfer_find(&peers[1].xs, peers[1].offer);
		REQUIRE(x != NULL);
		CHECK(strchr(x->name, '/') == NULL);
		CHECK(x->name[0] != '.' && x->name[0] != ' ' &&
		      x->name[0] != '\0');
		CHECK(strchr(x->name, '\033') == NULL);
		sts_xfer_refuse(&peers[1].xs, peers[1].offer);
	}

	/* too big: refused without asking */
	peers[1].xs.max_size = 1000;
	raw_offer("huge.iso", 1001);
	CHECK(peers[1].events[STS_XFER_EV_OFFER] == (int)STS_ARRAY_SIZE(names));
	CHECK(peers[1].events[STS_XFER_EV_TOO_BIG] == 1);

	/* a flood of offers: one sender takes a few slots, not all */
	peers[1].xs.max_size = STS_XFER_SIZE_DEFAULT;
	for (i = 0; i < STS_XFER_SLOTS; i++)
		raw_offer("flood.txt", 10);
	CHECK(peers[1].events[STS_XFER_EV_OFFER] ==
	      (int)STS_ARRAY_SIZE(names) + STS_XFER_PER_PEER);
	teardown();
}

static void test_size_limits(void)
{
	char src[STS_PATH_MAX + 32];
	char err[256];
	uint8_t *data;

	setup();
	data = make_file("big.iso", 5000, src, sizeof(src));

	/* ours */
	peers[0].xs.max_size = 4999;
	CHECK(sts_xfer_send(&peers[0].xs, bob_sid(), src, err, sizeof(err)) <
	      0);
	CHECK(strstr(err, "max_file_size") != NULL);

	/* theirs: refused without asking, and the sender is told why */
	peers[0].xs.max_size = 5000;
	peers[1].xs.max_size = 4000;
	REQUIRE(sts_xfer_send(&peers[0].xs, bob_sid(), src, err, sizeof(err)) >
		0);
	run(300);
	CHECK(peers[1].events[STS_XFER_EV_OFFER] == 0);
	CHECK(peers[1].events[STS_XFER_EV_TOO_BIG] == 1);
	CHECK(peers[0].events[STS_XFER_EV_FAILED] == 1);
	CHECK(strstr(peers[0].detail, "bigger") != NULL);
	free(data);
	teardown();
}

static void test_peer_leaves(void)
{
	char src[STS_PATH_MAX + 32];
	char into[STS_PATH_MAX + 32];
	uint8_t *data;

	setup();
	data = make_file("big.bin", 400000, src, sizeof(src));
	REQUIRE(out_dir(into, sizeof(into), "in5") == 0);
	send_and_accept(src, into);
	/* gone before the data comes */
	sts_room_leave(&peers[0].c->room);
	run(500);
	CHECK(peers[1].events[STS_XFER_EV_FAILED] == 1);
	CHECK(strstr(peers[1].detail, "left") != NULL);
	CHECK(peers[1].events[STS_XFER_EV_DONE] == 0);
	free(data);
	teardown();
}

int main(void)
{
	REQUIRE(sts_crypto_init() == 0);
	test_tmpdir(dir, sizeof(dir));
	RUN(test_send);
	RUN(test_refuse_and_cancel);
	RUN(test_losses_and_duplicates);
	RUN(test_corrupt_and_empty);
	RUN(test_hostile_offers);
	RUN(test_size_limits);
	RUN(test_peer_leaves);
	return test_summary();
}
