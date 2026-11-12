// SPDX-License-Identifier: Apache-2.0
/*
 * Protocol tests: several clients on an in-memory broker, an attacker that
 * controls the broker, lost, duplicated and reordered frames, reconnects,
 * several devices per identity.
 */
#include <string.h>

#include "bus.h"
#include "crypto.h"
#include "log.h"
#include "room.h"
#include "test.h"

static struct bus bus;

static void say(struct client *c, const char *text)
{
	REQUIRE(sts_room_send(&c->room, STS_KIND_TEXT, text, strlen(text)) ==
		0);
	bus_pump(&bus);
}

/* deliver a recorded or crafted frame to one client only */
static int inject(struct client *c, const uint8_t *data, size_t len)
{
	int ret = sts_room_handle(&c->room, data, len);

	bus_pump(&bus);
	return ret;
}

static int contains(const uint8_t *hay, size_t len, const char *needle)
{
	size_t n = strlen(needle);
	size_t i;

	for (i = 0; i + n <= len; i++)
		if (memcmp(&hay[i], needle, n) == 0)
			return 1;
	return 0;
}

static void setup3(struct client **a, struct client **b, struct client **c)
{
	bus_init(&bus);
	*a = bus_client(&bus);
	*b = bus_client(&bus);
	*c = bus_client(&bus);
	REQUIRE(bus_join(*a, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(*b, "neotokyo", "bob") == 0);
	REQUIRE(bus_join(*c, "neotokyo", "carol") == 0);
}

static void test_room_keys(void)
{
	struct sts_room_keys k1, k2, k3;

	REQUIRE(sts_room_keys_derive("neotokyo", NULL, &k1) == 0);
	REQUIRE(sts_room_keys_derive("neotokyo", "", &k2) == 0);
	REQUIRE(sts_room_keys_derive("neotokyo", "secret", &k3) == 0);

	CHECK(memcmp(&k1, &k2, sizeof(k1)) == 0);
	CHECK(memcmp(k1.topic_id, k3.topic_id, STS_TOPIC_ID_LEN) != 0);
	CHECK(memcmp(k1.outer_key, k3.outer_key, STS_KEY_LEN) != 0);
	CHECK(strlen(k1.topic_hex) == STS_TOPIC_HEX_LEN);
	/* the room name does not appear in the topic */
	CHECK(strstr(k1.topic_hex, "neotokyo") == NULL);
	CHECK(sts_room_keys_derive("bad/room", NULL, &k1) != 0);

	/* the case of the name doesn't matter, the password's does */
	REQUIRE(sts_room_keys_derive("NeoTokyo", NULL, &k2) == 0);
	REQUIRE(sts_room_keys_derive("neotokyo", NULL, &k1) == 0);
	CHECK(memcmp(&k1, &k2, sizeof(k1)) == 0);
	REQUIRE(sts_room_keys_derive("neotokyo", "Secret", &k2) == 0);
	CHECK(memcmp(&k2, &k3, sizeof(k2)) != 0);
}

static void test_join_and_keys(void)
{
	struct client *a, *b, *c;
	const struct sts_member *ab, *ba;

	setup3(&a, &b, &c);

	CHECK(sts_room_member_count(&a->room) == 2);
	CHECK(sts_room_member_count(&b->room) == 2);
	CHECK(sts_room_member_count(&c->room) == 2);
	CHECK(member_state(a, b) == STS_MEMBER_ACTIVE);
	CHECK(member_state(c, a) == STS_MEMBER_ACTIVE);
	CHECK(count_events(a, STS_EV_JOIN) == 2);
	CHECK(count_events(c, STS_EV_JOIN) == 2);

	ab = member_of(a, b);
	ba = member_of(b, a);
	REQUIRE(ab != NULL && ba != NULL);
	CHECK(ab->have_sk && ab->sk_epoch == b->room.sk_epoch);
	CHECK(memcmp(ab->sk, b->room.sk, STS_KEY_LEN) == 0);
	CHECK(strcmp(ab->nick, "bob") == 0);
	CHECK(memcmp(ab->fpr, b->id.fpr, STS_HASH_LEN) == 0);

	/* pairwise keys agree in both directions and differ per direction */
	CHECK(memcmp(ab->keys[0].send, ba->keys[0].recv, STS_KEY_LEN) == 0);
	CHECK(memcmp(ab->keys[0].recv, ba->keys[0].send, STS_KEY_LEN) == 0);
	CHECK(memcmp(ab->keys[0].send, ab->keys[0].recv, STS_KEY_LEN) != 0);
	bus_free(&bus);
}

static void test_room_message(void)
{
	struct client *a, *b, *c;
	const struct recorded_event *e;
	size_t i;
	int leaks = 0;

	setup3(&a, &b, &c);
	say(a, "hello everyone");

	e = last_event(b, STS_EV_MESSAGE);
	CHECK(e != NULL && strcmp(e->text, "hello everyone") == 0);
	CHECK(e != NULL && strcmp(e->nick, "alice") == 0 && !e->is_private);
	CHECK(has_message(c, "hello everyone") == 1);
	CHECK(has_message(a, "hello everyone") == 0); /* own echo */

	REQUIRE(sts_room_send(&b->room, STS_KIND_ACTION, "waves", 5) == 0);
	bus_pump(&bus);
	e = last_event(a, STS_EV_MESSAGE);
	CHECK(e != NULL && e->kind == STS_KIND_ACTION);

	/* the broker sees neither texts, nicks nor the room name */
	for (i = 0; i < bus.nlog; i++) {
		leaks += contains(bus.log[i].data, bus.log[i].len, "hello");
		leaks += contains(bus.log[i].data, bus.log[i].len, "alice");
		leaks += contains(bus.log[i].data, bus.log[i].len, "neotokyo");
		/* and every frame is padded */
		CHECK((bus.log[i].len - 2 - STS_NONCE_LEN - STS_TAG_LEN) %
			      STS_PAD_BLOCK ==
		      0);
	}
	CHECK(leaks == 0);
	bus_free(&bus);
}

static void test_private_message(void)
{
	struct client *a, *b, *c;
	const struct recorded_event *e;

	setup3(&a, &b, &c);
	CHECK(sts_room_send_private(&a->room, b->id.fpr, STS_KIND_TEXT,
				    "only for bob", 12) == 1);
	bus_pump(&bus);

	e = last_event(b, STS_EV_MESSAGE);
	CHECK(e != NULL && e->is_private &&
	      strcmp(e->text, "only for bob") == 0);
	CHECK(count_events(c, STS_EV_MESSAGE) == 0);
	CHECK(sts_room_send_private(&a->room, a->id.fpr, STS_KIND_TEXT, "x",
				    1) == 0);
	bus_free(&bus);
}

static void test_replay_and_duplicates(void)
{
	struct client *a, *b, *c;
	struct frame msg, dm, hello;

	setup3(&a, &b, &c);
	say(a, "pay bob 10 euros");
	msg = *last_frame(&bus, 0, STS_T_MSG);
	sts_room_send_private(&a->room, b->id.fpr, STS_KIND_TEXT, "dm", 2);
	bus_pump(&bus);
	dm = *last_frame(&bus, 0, STS_T_DM);
	hello = *last_frame(&bus, 0, STS_T_HELLO);
	CHECK(count_events(b, STS_EV_MESSAGE) == 2);

	CHECK(inject(b, msg.data, msg.len) == 1);
	CHECK(inject(b, dm.data, dm.len) == 1);
	CHECK(inject(b, hello.data, hello.len) == 1);
	CHECK(count_events(b, STS_EV_MESSAGE) == 2);
	CHECK(count_events(b, STS_EV_JOIN) == 2);

	/* QoS 1 can deliver twice */
	bus.duplicate = 1;
	say(a, "once");
	bus.duplicate = 0;
	CHECK(has_message(b, "once") == 1);
	CHECK(has_message(c, "once") == 1);
	bus_free(&bus);
}

static void test_tampering_rejected(void)
{
	struct client *a, *b, *c;
	struct frame f;
	size_t i;
	int accepted = 0;

	setup3(&a, &b, &c);
	b->connected = 0;
	say(a, "integrity matters");
	f = *last_frame(&bus, 0, STS_T_MSG);

	for (i = 0; i < f.len * 8; i += 3) {
		f.data[i / 8] ^= (uint8_t)(1u << (i % 8));
		if (sts_room_handle(&b->room, f.data, f.len) == 0)
			accepted++;
		f.data[i / 8] ^= (uint8_t)(1u << (i % 8));
	}
	CHECK(accepted == 0);
	CHECK(count_events(b, STS_EV_MESSAGE) == 0);
	CHECK(sts_room_handle(&b->room, f.data, f.len) == 0);
	CHECK(has_message(b, "integrity matters") == 1);
	bus_free(&bus);
}

static void test_password_rooms_are_separate(void)
{
	struct client *a, *b, *o;
	size_t i;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	o = bus_client(&bus);
	REQUIRE(bus_join_opts(a, "neotokyo", "pw", "alice") == 0);
	REQUIRE(bus_join_opts(b, "neotokyo", "pw", "bob") == 0);
	REQUIRE(bus_join(o, "neotokyo", "outsider") == 0);

	CHECK(sts_room_member_count(&a->room) == 1);
	CHECK(sts_room_member_count(&o->room) == 0);
	CHECK(strcmp(a->topic, o->topic) != 0);

	say(a, "secret plans");
	/* even pushed onto the outsider's topic, nothing decrypts */
	for (i = 0; i < bus.nlog; i++)
		if (bus.log[i].from == 0)
			CHECK(sts_room_handle(&o->room, bus.log[i].data,
					      bus.log[i].len) == -1);
	CHECK(has_message(b, "secret plans") == 1);
	CHECK(count_events(o, STS_EV_MESSAGE) == 0);
	bus_free(&bus);
}

/* signs frames as itself but puts alice's session id in them */
static void test_impersonation_rejected(void)
{
	struct client *a, *b, *m;
	uint8_t padded[STS_FRAME_MAX + STS_PAD_BLOCK];
	uint8_t wire[STS_WIRE_MAX];
	struct frame f;
	size_t plen;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	m = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);
	REQUIRE(bus_join(m, "neotokyo", "mallory") == 0);

	/* mallory is a member: she can open and rebuild the outer layer */
	say(m, "I am alice");
	f = *last_frame(&bus, 2, STS_T_MSG);
	plen = f.len - 2 - STS_NONCE_LEN - STS_TAG_LEN;
	REQUIRE(sts_aead_open(m->room.keys.outer_key, &f.data[2], f.data, 2,
			      &f.data[2 + STS_NONCE_LEN], plen + STS_TAG_LEN,
			      padded) == 0);
	memcpy(&padded[2 + 2], a->room.sid, STS_SID_LEN);
	memcpy(wire, f.data, 2 + STS_NONCE_LEN);
	REQUIRE(sts_aead_seal(m->room.keys.outer_key, &wire[2], wire, 2, padded,
			      plen, &wire[2 + STS_NONCE_LEN]) == 0);
	CHECK(inject(b, wire, f.len) == -1);
	CHECK(has_message(b, "I am alice") == 1); /* only her own */

	/* a LEAVE for alice's session signed by mallory */
	REQUIRE(sts_room_leave(&m->room) == 0);
	f = *last_frame(&bus, 2, STS_T_LEAVE);
	bus.qhead = bus.qtail = 0;
	plen = f.len - 2 - STS_NONCE_LEN - STS_TAG_LEN;
	REQUIRE(sts_aead_open(m->room.keys.outer_key, &f.data[2], f.data, 2,
			      &f.data[2 + STS_NONCE_LEN], plen + STS_TAG_LEN,
			      padded) == 0);
	memcpy(&padded[2 + 2], a->room.sid, STS_SID_LEN);
	memcpy(wire, f.data, 2 + STS_NONCE_LEN);
	REQUIRE(sts_aead_seal(m->room.keys.outer_key, &wire[2], wire, 2, padded,
			      plen, &wire[2 + STS_NONCE_LEN]) == 0);
	CHECK(inject(b, wire, f.len) == -1);
	CHECK(member_state(b, a) == STS_MEMBER_ACTIVE);
	bus_free(&bus);
}

/* a replayed HELLO of an ended session never becomes a member */
static void test_ghost_never_confirmed(void)
{
	struct client *a, *b, *c;
	struct frame hello, keydist;
	size_t i;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);
	hello = *last_frame(&bus, 0, STS_T_HELLO);
	keydist = *last_frame(&bus, 0, STS_T_KEYDIST);
	bus_quit(a);
	CHECK(member_state(b, a) == STS_MEMBER_GONE);

	/* bob remembers the session: the old HELLO is ignored */
	CHECK(inject(b, hello.data, hello.len) == 1);

	/*
	 * bob forgot it (restart, eviction): the replay starts a handshake
	 * that can't complete, alice's old KEYDIST doesn't answer it
	 */
	for (i = 0; i < STS_MEMBER_SLOTS; i++)
		if (b->room.members[i] != NULL &&
		    b->room.members[i]->state == STS_MEMBER_GONE) {
			free(b->room.members[i]);
			b->room.members[i] = NULL;
		}
	CHECK(inject(b, hello.data, hello.len) == 0);
	CHECK(member_state(b, a) == STS_MEMBER_PENDING);
	inject(b, keydist.data, keydist.len);
	CHECK(member_state(b, a) == STS_MEMBER_PENDING);

	/* a newcomer is fooled neither */
	c = bus_client(&bus);
	REQUIRE(bus_join(c, "neotokyo", "carol") == 0);
	inject(c, hello.data, hello.len);
	bus_run(&bus, STS_PENDING_TIMEOUT_MS + 1000);
	CHECK(member_state(b, a) == 0);
	CHECK(member_state(c, a) == 0);
	CHECK(sts_room_member_count(&c->room) == 1);
	CHECK(count_events(b, STS_EV_JOIN) == 1 + 1); /* alice, carol */
	bus_free(&bus);
}

static void test_nick_change(void)
{
	struct client *a, *b, *c;
	struct frame old_hello;
	const struct recorded_event *e;

	setup3(&a, &b, &c);
	old_hello = *last_frame(&bus, 0, STS_T_HELLO);

	REQUIRE(sts_room_set_nick(&a->room, "alicia") == 0);
	bus_pump(&bus);
	e = last_event(b, STS_EV_NICK);
	CHECK(e != NULL && strcmp(e->nick, "alicia") == 0);
	CHECK(strcmp(member_of(c, a)->nick, "alicia") == 0);

	CHECK(inject(b, old_hello.data, old_hello.len) == 1);
	CHECK(strcmp(member_of(b, a)->nick, "alicia") == 0);
	CHECK(count_events(b, STS_EV_NICK) == 1);
	bus_free(&bus);
}

static void test_leave_rotates_keys(void)
{
	struct client *a, *b, *c;
	struct frame after;
	uint32_t epoch;

	setup3(&a, &b, &c);
	epoch = a->room.sk_epoch;

	bus_quit(c);
	CHECK(count_events(a, STS_EV_LEAVE) == 1);
	CHECK(last_event(a, STS_EV_LEAVE)->reason == STS_LEAVE_QUIT);
	CHECK(sts_room_member_count(&a->room) == 1);
	CHECK(a->room.sk_epoch == epoch + 1);
	CHECK(member_of(b, a)->sk_epoch == a->room.sk_epoch);

	say(a, "carol is gone");
	CHECK(has_message(b, "carol is gone") == 1);

	/* carol kept every key she had: still nothing */
	after = *last_frame(&bus, 0, STS_T_MSG);
	inject(c, after.data, after.len);
	CHECK(has_message(c, "carol is gone") == 0);
	bus_free(&bus);
}

/*
 * Carol knows the room password and records the traffic before joining:
 * what was said before she arrived stays unreadable to her.
 */
static void test_join_rotates_used_keys(void)
{
	uint8_t old_key[STS_KEY_LEN];
	struct client *a, *b, *c, *d;
	struct frame before;
	uint32_t epoch;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	c = bus_client(&bus);
	d = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);
	/* past their first seconds, when who shows up was already there */
	bus_run(&bus, STS_DISCOVERY_MS);

	say(a, "before carol");
	CHECK(has_message(b, "before carol") == 1);
	before = *last_frame(&bus, 0, STS_T_MSG);
	memcpy(old_key, a->room.sk, STS_KEY_LEN);
	epoch = a->room.sk_epoch;

	REQUIRE(bus_join(c, "neotokyo", "carol") == 0);
	CHECK(a->room.sk_epoch == epoch + 1);
	CHECK(member_of(c, a) != NULL && member_of(c, a)->have_sk);
	CHECK(member_of(c, a)->sk_epoch == a->room.sk_epoch);
	CHECK(memcmp(member_of(c, a)->sk, old_key, STS_KEY_LEN) != 0);
	CHECK(!member_of(c, a)->have_prev_sk);
	inject(c, before.data, before.len);
	CHECK(has_message(c, "before carol") == 0);

	/* nothing was said since: dave's arrival changes no key */
	epoch = a->room.sk_epoch;
	REQUIRE(bus_join(d, "neotokyo", "dave") == 0);
	CHECK(a->room.sk_epoch == epoch);

	/* and everyone reads what comes next */
	say(a, "hello all");
	bus_run(&bus, 3000);
	CHECK(has_message(b, "hello all") == 1);
	CHECK(has_message(c, "hello all") == 1);
	CHECK(has_message(d, "hello all") == 1);
	say(c, "hi from carol");
	bus_run(&bus, 3000);
	CHECK(has_message(a, "hi from carol") == 1);
	CHECK(has_message(d, "hi from carol") == 1);
	bus_free(&bus);
}

static int frame_type(const struct client *owner, const struct frame *f)
{
	uint8_t padded[STS_FRAME_MAX + STS_PAD_BLOCK];
	size_t plen = f->len - 2 - STS_NONCE_LEN - STS_TAG_LEN;

	if (sts_aead_open(owner->room.keys.outer_key, &f->data[2], f->data, 2,
			  &f->data[2 + STS_NONCE_LEN], plen + STS_TAG_LEN,
			  padded) != 0)
		return -1;
	return padded[2];
}

/* eve's frames, except her HELLOs */
static int drop_eve(const struct frame *f, int to, void *ud)
{
	const struct client *e = ud;

	(void)to;
	return f->from == e->index && frame_type(e, f) != STS_T_HELLO;
}

/*
 * Eve knows the room password, announces herself and never answers the
 * handshake, so she never shows up in the list. Her client is modified to
 * take any key it is sent: she must still get none.
 */
static void test_silent_session_gets_no_key(void)
{
	struct client *a, *b, *e;
	struct sts_member *seen;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	e = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);
	bus_run(&bus, STS_DISCOVERY_MS);
	say(a, "before eve");
	bus_run(&bus, 1000);

	bus.filter = drop_eve;
	bus.filter_ud = e;
	REQUIRE(bus_join(e, "neotokyo", "eve") == 0);
	REQUIRE(member_of(a, e) != NULL);
	CHECK(member_of(a, e)->state == STS_MEMBER_PENDING);
	CHECK(count_events(a, STS_EV_JOIN) == 1); /* bob only */

	/* alice never got eve's challenge: her frames echo zeros */
	seen = (struct sts_member *)member_of(e, a);
	REQUIRE(seen != NULL);
	memset(seen->my_chal, 0, STS_CHAL_LEN);
	say(a, "while eve hides");
	bus_run(&bus, 5000);

	CHECK(!seen->have_sk || memcmp(seen->sk, a->room.sk, STS_KEY_LEN) != 0);
	CHECK(has_message(e, "before eve") == 0);
	CHECK(has_message(e, "while eve hides") == 0);
	CHECK(has_message(b, "while eve hides") == 1);
	bus.filter = NULL;
	bus_free(&bus);
}

/*
 * Alice forgets bob and they shake hands again. The broker then replays
 * alice's KEYDIST of the first handshake: bob doesn't start over for it.
 */
static void test_old_handshake_replay(void)
{
	struct client *a, *b;
	struct frame first, hello;
	uint32_t epoch;
	size_t i;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);
	first = *last_frame(&bus, 0, STS_T_KEYDIST);
	hello = *last_frame(&bus, 1, STS_T_HELLO);

	for (i = 0; i < STS_MEMBER_SLOTS; i++)
		if (a->room.members[i] != NULL) {
			struct sts_member *m = a->room.members[i];
			size_t j;

			for (j = 0; j < STS_PW_HISTORY; j++)
				free(m->pw_hist[j].data);
			for (j = 0; j < m->n_stash; j++)
				free(m->stash[j].data);
			free(m);
			a->room.members[i] = NULL;
		}
	inject(a, hello.data, hello.len);
	bus_run(&bus, 3000);
	REQUIRE(member_state(a, b) == STS_MEMBER_ACTIVE);
	REQUIRE(member_state(b, a) == STS_MEMBER_ACTIVE);

	epoch = b->room.sk_epoch;
	inject(b, first.data, first.len);
	bus_run(&bus, 3000);
	CHECK(b->room.sk_epoch == epoch);
	CHECK(member_state(b, a) == STS_MEMBER_ACTIVE);
	say(b, "still talking");
	bus_run(&bus, 2000);
	CHECK(has_message(a, "still talking") == 1);
	bus_free(&bus);
}

/* a member says it sent the last possible message: no endless loop */
static void test_huge_sequence(void)
{
	struct client *a, *b;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);
	say(b, "one");
	bus_run(&bus, 1000);

	b->room.sk_seq = UINT64_MAX;
	bus_crash(b);
	bus_connect(b);
	bus_run(&bus, 3000);
	CHECK(member_of(a, b) != NULL);
	b->room.sk_seq = 2;
	say(a, "still alive");
	bus_run(&bus, 3000);
	CHECK(has_message(b, "still alive") == 1);
	bus_free(&bus);
}

/* the connection drops, the broker keeps the session: nothing is lost */
static void test_away_and_back_without_loss(void)
{
	struct client *a, *b, *c;

	setup3(&a, &b, &c);
	b->persistent = 1;
	bus_crash(b);
	CHECK(member_state(a, b) == STS_MEMBER_AWAY);
	CHECK(count_events(a, STS_EV_AWAY) == 1);

	say(a, "while you were away");
	say(c, "me too");
	sts_room_send_private(&a->room, b->id.fpr, STS_KIND_TEXT, "psst", 4);
	bus_run(&bus, 20000);
	CHECK(has_message(b, "while you were away") == 0);

	bus_connect(b);
	bus_run(&bus, 1000);
	CHECK(has_message(b, "while you were away") == 1);
	CHECK(has_message(b, "me too") == 1);
	CHECK(has_message(b, "psst") == 1);
	CHECK(member_state(a, b) == STS_MEMBER_ACTIVE);
	CHECK(count_events(a, STS_EV_BACK) == 1);
	CHECK(count_events(a, STS_EV_LEAVE) == 0);

	say(b, "I'm back");
	CHECK(has_message(a, "I'm back") == 1);
	bus_free(&bus);
}

static void test_away_timeout(void)
{
	struct client *a, *b, *c;
	uint32_t epoch;

	setup3(&a, &b, &c);
	epoch = a->room.sk_epoch;
	bus_crash(c);
	bus_run(&bus, STS_AWAY_GRACE_MS - 5000);
	CHECK(member_state(a, c) == STS_MEMBER_AWAY);
	bus_run(&bus, 6000);
	CHECK(member_state(a, c) == STS_MEMBER_GONE);
	CHECK(last_event(a, STS_EV_LEAVE)->reason == STS_LEAVE_TIMEOUT);
	CHECK(a->room.sk_epoch == epoch + 1);
	bus_free(&bus);
}

/* someone leaves while we are offline without a broker session */
static void test_stale_members_after_reconnect(void)
{
	struct client *a, *b, *c;
	struct frame old_dm, old_msg;

	setup3(&a, &b, &c);
	sts_room_send_private(&a->room, b->id.fpr, STS_KIND_TEXT, "old dm", 6);
	say(a, "old message");
	bus_pump(&bus);
	old_dm = *last_frame(&bus, 0, STS_T_DM);
	old_msg = *last_frame(&bus, 0, STS_T_MSG);
	bus_crash(a);
	bus_quit(c);
	bus_run(&bus, STS_AWAY_GRACE_MS + 1000); /* bob drops alice */
	CHECK(member_state(b, a) == STS_MEMBER_GONE);
	CHECK(member_state(a, c) == STS_MEMBER_ACTIVE); /* alice missed it */

	bus_connect(a);
	bus_run(&bus, 2000);
	CHECK(member_state(a, b) == STS_MEMBER_ACTIVE);
	CHECK(member_state(b, a) == STS_MEMBER_ACTIVE); /* handshake again */
	bus_run(&bus, STS_STALE_TIMEOUT_MS);
	CHECK(member_state(a, c) == STS_MEMBER_GONE);
	CHECK(last_event(a, STS_EV_LEAVE)->reason == STS_LEAVE_LOST);

	say(a, "hi again");
	CHECK(has_message(b, "hi again") == 1);
	say(b, "welcome back");
	CHECK(has_message(a, "welcome back") == 1);

	/* bob met alice's session anew: what she sent before stays old */
	CHECK(inject(b, old_dm.data, old_dm.len) == -1);
	inject(b, old_msg.data, old_msg.len);
	bus_run(&bus, 1000);
	CHECK(has_message(b, "old dm") == 1);
	CHECK(has_message(b, "old message") == 1);
	bus_free(&bus);
}

/* type of the inner frame of @f, sent by @owner, -1 if it doesn't open */
static int drop_count;

/* drop the next @drop_count MSG frames from alice to bob */
static int drop_msgs(const struct frame *f, int to, void *ud)
{
	const struct client *a = ud;

	if (f->from != 0 || to != 1 || drop_count == 0 ||
	    frame_type(a, f) != STS_T_MSG)
		return 0;
	drop_count--;
	return 1;
}

static void test_lost_messages_recovered(void)
{
	struct client *a, *b, *c;
	const struct recorded_event *e;

	setup3(&a, &b, &c);
	bus.filter = drop_msgs;
	bus.filter_ud = a;

	drop_count = 2;
	say(a, "lost one");
	say(a, "lost two");
	say(a, "arrives");
	CHECK(has_message(b, "arrives") == 1);
	CHECK(has_message(b, "lost one") == 0);

	bus_run(&bus, 1000);
	CHECK(has_message(b, "lost one") == 1);
	CHECK(has_message(b, "lost two") == 1);
	e = last_event(b, STS_EV_MESSAGE);
	CHECK(e != NULL && e->late);
	CHECK(has_message(c, "lost one") == 1); /* not twice */

	/* the last message is lost: noticed with the next HELLO */
	drop_count = 1;
	say(a, "tail");
	CHECK(has_message(b, "tail") == 0);
	REQUIRE(sts_room_rekey(&a->room) == 0);
	bus_pump(&bus);
	bus_run(&bus, 1000);
	CHECK(has_message(b, "tail") == 1);
	CHECK(a->room.stats.resent >= 3);
	bus.filter = NULL;
	bus_free(&bus);
}

static int drop_all_keydist;

static int drop_keydist(const struct frame *f, int to, void *ud)
{
	const struct client *a = ud;

	return f->from == 0 && to == 1 && drop_all_keydist &&
	       frame_type(a, f) == STS_T_KEYDIST;
}

static void test_lost_handshake_recovered(void)
{
	struct client *a, *b;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);

	bus.filter = drop_keydist;
	bus.filter_ud = a;
	drop_all_keydist = 1;
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);
	CHECK(member_state(b, a) == STS_MEMBER_PENDING);
	say(a, "early");

	drop_all_keydist = 0;
	bus_run(&bus, STS_PENDING_RETRY_MS + 500);
	CHECK(member_state(b, a) == STS_MEMBER_ACTIVE);
	CHECK(member_state(a, b) == STS_MEMBER_ACTIVE);
	CHECK(has_message(b, "early") == 1); /* kept until confirmed */
	bus.filter = NULL;
	bus_free(&bus);
}

static void test_message_right_after_join(void)
{
	struct client *a, *b;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);

	/* bob talks before any handshake had a chance to complete */
	REQUIRE(sts_room_init(&b->room, &b->id, "neotokyo", NULL, "bob", 0,
			      &bus_ops, b) == 0);
	memcpy(b->topic, b->room.keys.topic_hex, sizeof(b->topic));
	b->joined = 1;
	REQUIRE(sts_room_prepare_connect(&b->room, b->will, sizeof(b->will),
					 &b->will_len) == 0);
	b->connected = 1;
	sts_room_connected(&b->room);
	REQUIRE(sts_room_send(&b->room, STS_KIND_TEXT, "hi!", 3) == 0);
	bus_pump(&bus);
	bus_run(&bus, 500);
	CHECK(has_message(a, "hi!") == 1);
	bus_free(&bus);
}

static void test_reordering(void)
{
	struct client *a, *b, *c;
	struct frame m1, m2;

	setup3(&a, &b, &c);
	c->connected = 0;
	say(a, "first");
	m1 = *last_frame(&bus, 0, STS_T_MSG);
	say(a, "second");
	m2 = *last_frame(&bus, 0, STS_T_MSG);
	c->connected = 1;

	CHECK(inject(c, m2.data, m2.len) == 0);
	CHECK(inject(c, m1.data, m1.len) == 0);
	CHECK(has_message(c, "first") == 1 && has_message(c, "second") == 1);
	CHECK(inject(c, m1.data, m1.len) == 1);
	bus_free(&bus);
}

static void test_several_devices(void)
{
	struct client *x1, *x2, *b;
	const struct recorded_event *e;
	char name[64];

	bus_init(&bus);
	x1 = bus_client(&bus);
	x2 = bus_client_twin(&bus, x1);
	b = bus_client(&bus);
	REQUIRE(bus_join(x1, "neotokyo", "ifupauline") == 0);
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);
	REQUIRE(bus_join(x2, "neotokyo", "ifupauline") == 0);

	/* same person, two sessions */
	CHECK(sts_room_member_count(&b->room) == 2);
	CHECK(member_state(x1, x2) == STS_MEMBER_ACTIVE);
	e = last_event(b, STS_EV_JOIN);
	CHECK(e != NULL && e->other_devices == 1);
	sts_room_display_name(&b->room, member_of(b, x1), name, sizeof(name));
	CHECK(strcmp(name, "ifupauline") == 0);

	/* a private message reaches every device */
	CHECK(sts_room_send_private(&b->room, x1->id.fpr, STS_KIND_TEXT,
				    "both of you", 11) == 2);
	bus_pump(&bus);
	CHECK(has_message(x1, "both of you") == 1);
	CHECK(has_message(x2, "both of you") == 1);

	say(x2, "from my laptop");
	CHECK(has_message(x1, "from my laptop") == 1);
	CHECK(has_message(b, "from my laptop") == 1);
	bus_free(&bus);
}

static void test_rekey(void)
{
	struct client *a, *b;
	uint8_t old_send[STS_KEY_LEN];
	uint32_t gen;
	size_t i;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);
	a->room.rekey_interval_ms = 60000;
	gen = a->room.eph_gen;
	memcpy(old_send, member_of(a, b)->keys[0].send, STS_KEY_LEN);

	bus_run(&bus, 61000);
	a->room.rekey_interval_ms = 0;
	CHECK(a->room.eph_gen == gen + 1);
	CHECK(member_of(b, a)->eph_gen == gen + 1);
	CHECK(member_of(b, a)->sk_epoch == a->room.sk_epoch);

	say(a, "after rekey");
	CHECK(has_message(b, "after rekey") == 1);
	CHECK(sts_room_send_private(&a->room, b->id.fpr, STS_KIND_TEXT,
				    "dm after", 8) == 1);
	bus_pump(&bus);
	CHECK(has_message(b, "dm after") == 1);

	/* the old ephemeral key is destroyed after a while */
	bus_run(&bus, STS_OLD_KEY_MS + 1000);
	CHECK(a->room.has_prev_eph == 0);
	for (i = 0; i < STS_ARRAY_SIZE(member_of(a, b)->keys); i++)
		CHECK(memcmp(old_send, member_of(a, b)->keys[i].send,
			     STS_KEY_LEN) != 0);
	bus_free(&bus);
}

static void test_both_rekey_at_once(void)
{
	struct client *a, *b;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);

	sts_room_rekey(&a->room);
	sts_room_rekey(&b->room);
	bus_pump(&bus);
	bus_run(&bus, 3000);
	say(a, "a->b");
	say(b, "b->a");
	CHECK(has_message(b, "a->b") == 1);
	CHECK(has_message(a, "b->a") == 1);
	bus_free(&bus);
}

static void test_cross_room_replay(void)
{
	struct client *a1, *b1, *b2;
	size_t i;

	bus_init(&bus);
	a1 = bus_client(&bus);
	b1 = bus_client(&bus);
	b2 = bus_client_twin(&bus, b1);
	REQUIRE(bus_join(a1, "public", "alice") == 0);
	REQUIRE(bus_join(b1, "public", "bob") == 0);
	REQUIRE(bus_join(b2, "private", "bob") == 0);
	say(a1, "public message");

	for (i = 0; i < bus.nlog; i++)
		if (bus.log[i].from == 0)
			CHECK(sts_room_handle(&b2->room, bus.log[i].data,
					      bus.log[i].len) == -1);
	CHECK(count_events(b2, STS_EV_MESSAGE) == 0);
	CHECK(sts_room_member_count(&b2->room) == 0);
	bus_free(&bus);
}

static void test_duplicate_nicks(void)
{
	struct client *a, *b, *c;
	const struct sts_member *found;
	char name[64];
	char want[64];
	int ambiguous;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	c = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);
	REQUIRE(bus_join(c, "neotokyo", "bob") == 0);

	found = sts_room_find(&a->room, "bob", &ambiguous);
	CHECK(found == NULL && ambiguous);

	sts_room_display_name(&a->room, member_of(a, b), name, sizeof(name));
	snprintf(want, sizeof(want), "bob#%02x%02x", b->id.fpr[0],
		 b->id.fpr[1]);
	CHECK(strcmp(name, want) == 0);
	found = sts_room_find(&a->room, want, &ambiguous);
	CHECK(found != NULL &&
	      memcmp(found->fpr, b->id.fpr, STS_HASH_LEN) == 0);
	CHECK(sts_room_find(&b->room, "Alice", &ambiguous) != NULL);
	bus_free(&bus);
}

static void test_limits(void)
{
	struct client *a, *b;
	char big[STS_TEXT_MAX + 1];
	size_t i;

	bus_init(&bus);
	a = bus_client(&bus);
	b = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);
	REQUIRE(bus_join(b, "neotokyo", "bob") == 0);

	memset(big, 'x', sizeof(big));
	CHECK(sts_room_send(&a->room, STS_KIND_TEXT, big, 0) != 0);
	CHECK(sts_room_send(&a->room, STS_KIND_TEXT, big, sizeof(big)) != 0);
	CHECK(sts_room_send(&a->room, STS_KIND_TEXT, big, STS_TEXT_MAX) == 0);
	bus_pump(&bus);
	CHECK(strlen(last_event(b, STS_EV_MESSAGE)->text) == STS_TEXT_MAX);
	for (i = 0; i < bus.nlog; i++)
		CHECK(bus.log[i].len <= STS_WIRE_MAX);
	bus_free(&bus);
}

static void test_many_members(void)
{
	static struct sts_identity ids[40];
	struct client *a;
	struct sts_room r;
	size_t i;

	bus_init(&bus);
	a = bus_client(&bus);
	REQUIRE(bus_join(a, "neotokyo", "alice") == 0);

	/* more announcements than pending slots: memory stays bounded */
	for (i = 0; i < STS_ARRAY_SIZE(ids); i++) {
		REQUIRE(sts_identity_generate(&ids[i]) == 0);
		REQUIRE(sts_room_init(&r, &ids[i], "neotokyo", NULL, "x", 0,
				      &bus_ops, &bus.clients[0]) == 0);
		bus.qhead = bus.qtail = 0;
		sts_room_connected(&r); /* sends its HELLO */
		inject(a, bus.log[bus.nlog - 1].data,
		       bus.log[bus.nlog - 1].len);
		bus.qhead = bus.qtail = 0;
		sts_room_free(&r);
		sts_identity_free(&ids[i]);
	}
	CHECK(sts_room_member_count(&a->room) == 0);
	bus_run(&bus, STS_PENDING_TIMEOUT_MS + 1000);
	for (i = 0; i < STS_MEMBER_SLOTS; i++)
		CHECK(a->room.members[i] == NULL);
	bus_free(&bus);
}

int main(void)
{
	REQUIRE(sts_crypto_init() == 0);
	if (getenv("STS_DEBUG") != NULL)
		sts_log_set_level(STS_LOG_DEBUG);

	RUN(test_room_keys);
	RUN(test_join_and_keys);
	RUN(test_room_message);
	RUN(test_private_message);
	RUN(test_replay_and_duplicates);
	RUN(test_tampering_rejected);
	RUN(test_password_rooms_are_separate);
	RUN(test_impersonation_rejected);
	RUN(test_ghost_never_confirmed);
	RUN(test_nick_change);
	RUN(test_leave_rotates_keys);
	RUN(test_join_rotates_used_keys);
	RUN(test_silent_session_gets_no_key);
	RUN(test_old_handshake_replay);
	RUN(test_huge_sequence);
	RUN(test_away_and_back_without_loss);
	RUN(test_away_timeout);
	RUN(test_stale_members_after_reconnect);
	RUN(test_lost_messages_recovered);
	RUN(test_lost_handshake_recovered);
	RUN(test_message_right_after_join);
	RUN(test_reordering);
	RUN(test_several_devices);
	RUN(test_rekey);
	RUN(test_both_rekey_at_once);
	RUN(test_cross_room_replay);
	RUN(test_duplicate_nicks);
	RUN(test_limits);
	RUN(test_many_members);
	return test_summary();
}
