// SPDX-License-Identifier: Apache-2.0
/*
 * Robustness: mutated and random frames fed to the protocol engine, both
 * on the wire and re-wrapped with the room key as a member of the room
 * could. Nothing may crash (CI runs this under ASan and UBSan) and no
 * mutated frame may have any effect: every byte is authenticated.
 */
#include <string.h>

#include "bus.h"
#include "crypto.h"
#include "room.h"
#include "test.h"

#define ITERATIONS 4000

static struct bus bus;
static uint64_t rng = 0x9E3779B97F4A7C15ULL;

/* xorshift64*, deterministic so failures can be reproduced */
static uint64_t rnd(void)
{
	rng ^= rng >> 12;
	rng ^= rng << 25;
	rng ^= rng >> 27;
	return rng * 0x2545F4914F6CDD1DULL;
}

struct sample {
	size_t len;
	uint8_t data[STS_FRAME_MAX];
};

static int unwrap(const struct client *c, const struct frame *f,
		  struct sample *out)
{
	uint8_t padded[STS_FRAME_MAX + STS_PAD_BLOCK];
	size_t plen = f->len - 2 - STS_NONCE_LEN - STS_TAG_LEN;

	if (sts_aead_open(c->room.keys.outer_key, &f->data[2], f->data, 2,
			  &f->data[2 + STS_NONCE_LEN], plen + STS_TAG_LEN,
			  padded) != 0)
		return -1;
	out->len = (size_t)padded[0] << 8 | padded[1];
	memcpy(out->data, &padded[2], out->len);
	return 0;
}

/* the outer layer, as any member of the room can build it */
static size_t wrap(const struct client *c, const uint8_t *inner, size_t len,
		   uint8_t *wire)
{
	uint8_t padded[STS_FRAME_MAX + STS_PAD_BLOCK];
	size_t plen =
		(2 + len + STS_PAD_BLOCK - 1) / STS_PAD_BLOCK * STS_PAD_BLOCK;

	memset(padded, 0, sizeof(padded));
	padded[0] = (uint8_t)(len >> 8);
	padded[1] = (uint8_t)len;
	memcpy(&padded[2], inner, len);
	wire[0] = STS_PROTO_MAGIC;
	wire[1] = STS_PROTO_VERSION;
	sts_random(&wire[2], STS_NONCE_LEN);
	sts_aead_seal(c->room.keys.outer_key, &wire[2], wire, 2, padded, plen,
		      &wire[2 + STS_NONCE_LEN]);
	return 2 + STS_NONCE_LEN + plen + STS_TAG_LEN;
}

static void mutate(uint8_t *p, size_t *len, size_t max)
{
	size_t n;
	size_t i;

	switch (rnd() % 5) {
	case 0:
		n = 1 + rnd() % 3;
		for (i = 0; i < n; i++)
			p[rnd() % *len] ^= (uint8_t)(1u << (rnd() % 8));
		break;
	case 1:
		i = rnd() % *len;
		p[i] = (uint8_t)(p[i] + 1 + rnd() % 255);
		break;
	case 2:
		*len = 1 + rnd() % *len;
		p[rnd() % *len] ^= 0x10;
		break;
	case 3:
		n = 1 + rnd() % 32;
		if (*len + n > max)
			n = max - *len;
		for (i = 0; i < n; i++)
			p[*len + i] = (uint8_t)rnd();
		*len += n;
		if (n == 0)
			p[0] ^= 1;
		break;
	default:
		i = rnd() % *len;
		for (n = 1 + rnd() % 8; n > 0 && i < *len; n--, i++)
			p[i] = (uint8_t)~p[i];
		break;
	}
}

/* events a forged frame could cause */
static int effects(const struct client *c, int from)
{
	int i;
	int n = 0;

	for (i = from; i < c->nevents; i++) {
		switch (c->events[i].type) {
		case STS_EV_MESSAGE:
		case STS_EV_LEAVE:
		case STS_EV_AWAY:
		case STS_EV_BACK:
		case STS_EV_NICK:
		case STS_EV_JOIN:
			n++;
			break;
		default:
			break;
		}
	}
	return n;
}

static void test_mutated_frames(void)
{
	static struct sample samples[64];
	uint8_t wire[STS_WIRE_MAX];
	struct client *a, *b, *c;
	struct sample s;
	size_t nsamples = 0;
	size_t len;
	size_t i;
	int b_before;
	int c_before;
	int it;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	c = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);
	REQUIRE(sts_room_send(&a->room, STS_KIND_TEXT, "hello", 5) == 0);
	REQUIRE(sts_room_send_private(&a->room, b->id.fpr, STS_KIND_TEXT,
				      "psst", 4) == 1);
	sts_room_rekey(&a->room);
	bus_pump(&bus);

	/* every kind of frame alice sent */
	for (i = 0; i < bus.nlog && nsamples < STS_ARRAY_SIZE(samples); i++)
		if (bus.log[i].from == 0 &&
		    unwrap(a, &bus.log[i], &samples[nsamples]) == 0)
			nsamples++;
	/* and the AWAY frame it registers as its will */
	{
		static struct frame will;

		REQUIRE(sts_room_prepare_connect(&a->room, will.data,
						 sizeof(will.data),
						 &will.len) == 0);
		REQUIRE(unwrap(a, &will, &samples[nsamples++]) == 0);
	}
	REQUIRE(nsamples >= 6);

	REQUIRE(bus_join(c, "neotokyo", "carol") == 0);
	b->connected = 0;
	c->connected = 0;
	b_before = b->nevents;
	c_before = c->nevents;

	for (it = 0; it < ITERATIONS; it++) {
		s = samples[rnd() % nsamples];
		mutate(s.data, &s.len, sizeof(s.data));
		len = wrap(a, s.data, s.len, wire);
		sts_room_handle(&b->room, wire, len);
		sts_room_handle(&c->room, wire, len);

		/* and on the wire */
		len = wrap(a, samples[rnd() % nsamples].data,
			   samples[rnd() % nsamples].len, wire);
		mutate(wire, &len, sizeof(wire));
		sts_room_handle(&b->room, wire, len);
		bus.qhead = bus.qtail = 0;
	}

	CHECK(effects(b, b_before) == 0);
	CHECK(effects(c, c_before) == 0);
	CHECK(sts_room_member_count(&b->room) == 2);

	/* everyone still works */
	b->connected = 1;
	c->connected = 1;
	REQUIRE(sts_room_send(&a->room, STS_KIND_TEXT, "still ok", 8) == 0);
	bus_pump(&bus);
	bus_run(&bus, 3000);
	CHECK(has_message(b, "still ok") == 1);
	CHECK(has_message(c, "still ok") == 1);
	bus_free(&bus);
}

static void test_random_frames(void)
{
	uint8_t inner[STS_FRAME_MAX + 16];
	uint8_t wire[STS_WIRE_MAX];
	struct client *a, *b;
	size_t len;
	size_t i;
	int it;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);

	for (it = 0; it < ITERATIONS; it++) {
		len = STS_HDR_LEN + rnd() % (STS_FRAME_MAX - STS_HDR_LEN);
		for (i = 0; i < len; i++)
			inner[i] = (uint8_t)rnd();
		inner[0] = (uint8_t)(1 + rnd() % 8); /* a real type */
		if (rnd() % 2)
			memcpy(&inner[2], a->room.sid, STS_SID_LEN);
		if (rnd() % 2)
			memcpy(&inner[STS_HDR_LEN], b->room.sid, STS_SID_LEN);
		len = wrap(a, inner, len, wire);
		CHECK(sts_room_handle(&b->room, wire, len) != 0);
		bus.qhead = bus.qtail = 0;
	}
	CHECK(effects(b, 0) == 1); /* alice joining */
	CHECK(count_events(b, STS_EV_JOIN) == 1);
	CHECK(sts_room_member_count(&b->room) == 1);
	bus_free(&bus);
}

int main(void)
{
	REQUIRE(sts_crypto_init() == 0);
	RUN(test_mutated_frames);
	RUN(test_random_frames);
	return test_summary();
}
