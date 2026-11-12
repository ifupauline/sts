/* SPDX-License-Identifier: Apache-2.0 */
/*
 * In-memory stand-in for an MQTT broker. Every frame published by a client
 * is delivered in order to every connected client on the same topic (the
 * sender included, like a real broker). Clients that are disconnected but
 * have a persistent session get their frames queued, like MQTT QoS 1 with
 * clean session off. Frames are recorded so tests can replay, drop or
 * tamper with them, as an attacker controlling the broker could.
 */
#ifndef STS_TEST_BUS_H
#define STS_TEST_BUS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "room.h"

#define BUS_CLIENTS 12
#define BUS_FRAMES 8192
#define BUS_EVENTS 512
#define BUS_QUEUE 1024

struct bus;

struct recorded_event {
	enum sts_event_type type;
	uint8_t sid[STS_SID_LEN];
	uint8_t fpr[STS_HASH_LEN];
	char nick[STS_NICK_MAX + 1];
	char text[STS_TEXT_MAX + 1];
	enum sts_msg_kind kind;
	enum sts_leave_reason reason;
	int is_private;
	int late;
	int other_devices;
	int has_member;
};

struct frame {
	int from;
	char topic[STS_TOPIC_HEX_LEN + 1];
	size_t len;
	uint8_t data[STS_WIRE_MAX];
};

struct client {
	struct bus *bus;
	int index;
	struct sts_identity id;
	struct sts_room room;
	int joined;
	int connected;
	int persistent; /* broker keeps a session while offline */
	char topic[STS_TOPIC_HEX_LEN + 1];
	uint8_t will[STS_WIRE_MAX];
	size_t will_len;
	struct frame *offline; /* queued while disconnected */
	size_t n_offline;
	struct recorded_event events[BUS_EVENTS];
	int nevents;
	/* optional, called for every event */
	void (*hook)(struct client *c, const struct sts_event *ev);
	void *hook_ud;
};

/* return 1 to drop @f for client @to */
typedef int (*bus_filter_fn)(const struct frame *f, int to, void *ud);

struct bus {
	struct client clients[BUS_CLIENTS];
	int nclients;
	struct frame *queue;
	size_t qhead;
	size_t qtail;
	struct frame *log;
	size_t nlog;
	bus_filter_fn filter;
	void *filter_ud;
	int duplicate; /* deliver everything twice (QoS 1 resends) */
};

static uint64_t bus_mono = 1000000;
static uint64_t bus_wall = 1700000000000ULL;

static uint64_t bus_mono_ms(void *ud)
{
	(void)ud;
	return bus_mono;
}

static uint64_t bus_wall_ms(void *ud)
{
	(void)ud;
	return bus_wall;
}

static int bus_send(void *ud, const uint8_t *data, size_t len)
{
	struct client *c = ud;
	struct bus *b = c->bus;
	struct frame *f;

	if (len > STS_WIRE_MAX || b->qtail >= BUS_FRAMES ||
	    b->nlog >= BUS_FRAMES)
		return -1;
	f = &b->queue[b->qtail++];
	f->from = c->index;
	memcpy(f->topic, c->topic, sizeof(f->topic));
	f->len = len;
	memcpy(f->data, data, len);
	b->log[b->nlog++] = *f;
	return 0;
}

static void bus_event(void *ud, const struct sts_event *ev)
{
	struct client *c = ud;
	struct recorded_event *r;

	if (c->hook != NULL)
		c->hook(c, ev);
	if (ev->type == STS_EV_FILE || c->nevents >= BUS_EVENTS)
		return;
	r = &c->events[c->nevents++];
	memset(r, 0, sizeof(*r));
	r->type = ev->type;
	if (ev->member != NULL) {
		r->has_member = 1;
		memcpy(r->sid, ev->member->sid, STS_SID_LEN);
		memcpy(r->fpr, ev->member->fpr, STS_HASH_LEN);
		sts_strlcpy(r->nick, ev->member->nick, sizeof(r->nick));
	}
	if (ev->text != NULL) {
		memcpy(r->text, ev->text, ev->text_len);
		r->text[ev->text_len] = '\0';
	}
	r->kind = ev->kind;
	r->reason = ev->reason;
	r->is_private = ev->is_private;
	r->late = ev->late;
	r->other_devices = ev->other_devices;
}

static const struct sts_room_ops bus_ops = {
	.send = bus_send,
	.event = bus_event,
	.monotonic_ms = bus_mono_ms,
	.wallclock_ms = bus_wall_ms,
};

static inline void bus_init(struct bus *b)
{
	memset(b, 0, sizeof(*b));
	b->queue = calloc(BUS_FRAMES, sizeof(struct frame));
	b->log = calloc(BUS_FRAMES, sizeof(struct frame));
	if (b->queue == NULL || b->log == NULL)
		abort();
}

static inline void bus_free(struct bus *b)
{
	int i;

	for (i = 0; i < b->nclients; i++) {
		if (b->clients[i].joined)
			sts_room_free(&b->clients[i].room);
		sts_identity_free(&b->clients[i].id);
		free(b->clients[i].offline);
	}
	free(b->queue);
	free(b->log);
}

static inline void deliver(struct bus *b, struct client *c,
			   const struct frame *f)
{
	int n = b->duplicate ? 2 : 1;

	if (!c->joined || strcmp(c->topic, f->topic) != 0)
		return;
	if (b->filter && b->filter(f, c->index, b->filter_ud))
		return;
	if (!c->connected) {
		if (c->persistent && c->n_offline < BUS_QUEUE)
			c->offline[c->n_offline++] = *f;
		return;
	}
	while (n-- > 0)
		sts_room_handle(&c->room, f->data, f->len);
}

/* deliver everything queued, including what is sent meanwhile */
static inline void bus_pump(struct bus *b)
{
	struct frame f;
	int i;

	while (b->qhead < b->qtail) {
		f = b->queue[b->qhead++];
		for (i = 0; i < b->nclients; i++)
			deliver(b, &b->clients[i], &f);
		if (b->qhead == b->qtail)
			b->qhead = b->qtail = 0;
	}
}

static inline void bus_tick(struct bus *b)
{
	int i;

	for (i = 0; i < b->nclients; i++)
		if (b->clients[i].joined)
			sts_room_tick(&b->clients[i].room);
	bus_pump(b);
}

/* let @ms of time pass, running timers and deliveries */
static inline void bus_run(struct bus *b, uint64_t ms)
{
	uint64_t step;

	while (ms > 0) {
		step = ms < 100 ? ms : 100;
		bus_mono += step;
		bus_wall += step;
		ms -= step;
		bus_tick(b);
	}
}

static inline struct client *bus_client(struct bus *b)
{
	struct client *c = &b->clients[b->nclients];

	memset(c, 0, sizeof(*c));
	c->bus = b;
	c->index = b->nclients++;
	c->offline = calloc(BUS_QUEUE, sizeof(struct frame));
	if (c->offline == NULL || sts_identity_generate(&c->id) != 0)
		abort();
	return c;
}

/* a second device of @of: same identity key */
static inline struct client *bus_client_twin(struct bus *b, struct client *of)
{
	struct client *c = bus_client(b);
	uint8_t priv[STS_PRIVKEY_LEN];
	size_t len;

	sts_identity_free(&c->id);
	if (psa_export_key(of->id.key, priv, sizeof(priv), &len) != 0 ||
	    sts_identity_import(&c->id, priv) != 0)
		abort();
	return c;
}

static inline void bus_connect(struct client *c)
{
	size_t i;

	if (sts_room_prepare_connect(&c->room, c->will, sizeof(c->will),
				     &c->will_len) != 0)
		abort();
	c->connected = 1;
	/* what the broker kept for our session comes first */
	for (i = 0; i < c->n_offline; i++)
		sts_room_handle(&c->room, c->offline[i].data,
				c->offline[i].len);
	c->n_offline = 0;
	sts_room_connected(&c->room);
	bus_pump(c->bus);
}

static inline int bus_join_opts(struct client *c, const char *room,
				const char *password, const char *nick)
{
	if (sts_room_init(&c->room, &c->id, room, password, nick, 0, &bus_ops,
			  c) != 0)
		return -1;
	memcpy(c->topic, c->room.keys.topic_hex, sizeof(c->topic));
	c->joined = 1;
	bus_connect(c);
	/* let the handshakes complete (replies are paced at one per s) */
	bus_run(c->bus, 1500);
	return 0;
}

static inline int bus_join(struct client *c, const char *room, const char *nick)
{
	return bus_join_opts(c, room, NULL, nick);
}

/* the connection drops: the broker publishes the will */
static inline void bus_crash(struct client *c)
{
	struct bus *b = c->bus;
	struct frame *f;

	c->connected = 0;
	sts_room_disconnected(&c->room);
	f = &b->queue[b->qtail++];
	f->from = c->index;
	memcpy(f->topic, c->topic, sizeof(f->topic));
	f->len = c->will_len;
	memcpy(f->data, c->will, c->will_len);
	b->log[b->nlog++] = *f;
	bus_pump(b);
}

/* clean exit: LEAVE, then gone */
static inline void bus_quit(struct client *c)
{
	sts_room_leave(&c->room);
	bus_pump(c->bus);
	c->connected = 0;
	c->persistent = 0;
	c->n_offline = 0;
}

static inline int count_events(const struct client *c, enum sts_event_type t)
{
	int i;
	int n = 0;

	for (i = 0; i < c->nevents; i++)
		n += c->events[i].type == t;
	return n;
}

static inline const struct recorded_event *last_event(const struct client *c,
						      enum sts_event_type t)
{
	int i;

	for (i = c->nevents - 1; i >= 0; i--)
		if (c->events[i].type == t)
			return &c->events[i];
	return NULL;
}

static inline int has_message(const struct client *c, const char *text)
{
	int i;
	int n = 0;

	for (i = 0; i < c->nevents; i++)
		n += c->events[i].type == STS_EV_MESSAGE &&
		     strcmp(c->events[i].text, text) == 0;
	return n;
}

/* last frame of @type sent by client @from, decrypted for inspection */
static inline const struct frame *last_frame(const struct bus *b, int from,
					     uint8_t type)
{
	uint8_t padded[STS_FRAME_MAX + STS_PAD_BLOCK];
	const struct client *c = &b->clients[from];
	size_t i;

	for (i = b->nlog; i > 0; i--) {
		const struct frame *f = &b->log[i - 1];
		size_t plen;

		if (f->from != from || f->len < 2 + STS_NONCE_LEN + STS_TAG_LEN)
			continue;
		plen = f->len - 2 - STS_NONCE_LEN - STS_TAG_LEN;
		if (sts_aead_open(c->room.keys.outer_key, &f->data[2], f->data,
				  2, &f->data[2 + STS_NONCE_LEN],
				  plen + STS_TAG_LEN, padded) == 0 &&
		    padded[2] == type)
			return f;
	}
	return NULL;
}

static inline const struct sts_member *member_of(const struct client *c,
						 const struct client *other)
{
	size_t i;

	for (i = 0; i < STS_MEMBER_SLOTS; i++) {
		const struct sts_member *m = c->room.members[i];

		if (m != NULL &&
		    memcmp(m->sid, other->room.sid, STS_SID_LEN) == 0)
			return m;
	}
	return NULL;
}

static inline int member_state(const struct client *c,
			       const struct client *other)
{
	const struct sts_member *m = member_of(c, other);

	return m ? (int)m->state : 0;
}

#endif /* STS_TEST_BUS_H */
