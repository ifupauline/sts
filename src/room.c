// SPDX-License-Identifier: Apache-2.0
/*
 * STS v3 group protocol, see doc/PROTOCOL.md.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "platform.h"
#include "room.h"
#include "wire.h"

/* domain separation labels, used with their terminating NUL */
#define LABEL_ROOM "STS3/room"
#define LABEL_ROOM_SALT "STS3/room-salt"
#define LABEL_TOPIC "STS3/topic"
#define LABEL_OUTER "STS3/outer"
#define LABEL_SID "STS3/sid"
#define LABEL_HELLO "STS3/HELLO"
#define LABEL_MSG "STS3/MSG"
#define LABEL_AWAY "STS3/AWAY"
#define LABEL_LEAVE "STS3/LEAVE"
#define LABEL_PAIRWISE "STS3/pairwise"

#define KEYDIST_LEN (STS_CHAL_LEN + 4 + STS_KEY_LEN + 8)
#define RESEND_MAX 32
#define STASH_MS 30000

/* internal results of the frame handlers */
#define DONE 0
#define IGNORED 1
#define REJECT (-1)
#define WAIT (-2)

/* --- replay window ------------------------------------------------------- */

int sts_replay_check(const struct sts_replay *r, uint64_t seq)
{
	uint64_t diff;

	/* sequence numbers start at 1 */
	if (seq == 0)
		return -1;
	if (!r->init || seq > r->top)
		return 0;

	diff = r->top - seq;
	if (diff >= STS_REPLAY_WINDOW)
		return -1;
	return ((r->bitmap >> diff) & 1) ? -1 : 0;
}

void sts_replay_commit(struct sts_replay *r, uint64_t seq)
{
	uint64_t shift;

	if (!r->init) {
		r->init = 1;
		r->top = seq;
		r->bitmap = 1;
		return;
	}

	if (seq > r->top) {
		shift = seq - r->top;
		r->bitmap = shift >= STS_REPLAY_WINDOW ? 0 : r->bitmap << shift;
		r->bitmap |= 1;
		r->top = seq;
	} else {
		r->bitmap |= (uint64_t)1 << (r->top - seq);
	}
}

/* --- room keys ----------------------------------------------------------- */

int sts_room_keys_derive(const char *room, const char *password,
			 struct sts_room_keys *keys)
{
	uint8_t secret[sizeof(LABEL_ROOM) + 2 + STS_ROOM_MAX + STS_PASSWORD_MAX];
	uint8_t master[STS_KEY_LEN];
	char lower[STS_ROOM_MAX + 1];
	size_t room_len;
	size_t pw_len;
	struct sts_wbuf w;
	size_t i;
	int ret;

	if (password == NULL)
		password = "";
	room_len = strlen(room);
	pw_len = strlen(password);
	if (!sts_room_valid(room) || pw_len > STS_PASSWORD_MAX)
		return -1;
	/* "Neotokyo" is "neotokyo" (names are ASCII) */
	for (i = 0; i <= room_len; i++)
		lower[i] = (char)(room[i] >= 'A' && room[i] <= 'Z' ?
					  room[i] - 'A' + 'a' :
					  room[i]);
	room = lower;

	sts_wbuf_init(&w, secret, sizeof(secret));
	sts_w_bytes(&w, LABEL_ROOM, sizeof(LABEL_ROOM));
	sts_w_u8(&w, (uint8_t)room_len);
	sts_w_bytes(&w, room, room_len);
	sts_w_u8(&w, (uint8_t)pw_len);
	sts_w_bytes(&w, password, pw_len);
	if (w.err)
		return -1;

	ret = sts_pbkdf2(secret, w.len, (const uint8_t *)LABEL_ROOM_SALT,
			 sizeof(LABEL_ROOM_SALT), STS_PBKDF2_ITERATIONS, master,
			 sizeof(master));
	if (ret == 0)
		ret = sts_hkdf(NULL, 0, master, sizeof(master),
			       (const uint8_t *)LABEL_TOPIC,
			       sizeof(LABEL_TOPIC), keys->topic_id,
			       sizeof(keys->topic_id));
	if (ret == 0)
		ret = sts_hkdf(NULL, 0, master, sizeof(master),
			       (const uint8_t *)LABEL_OUTER,
			       sizeof(LABEL_OUTER), keys->outer_key,
			       sizeof(keys->outer_key));
	if (ret == 0)
		sts_hex(keys->topic_id, sizeof(keys->topic_id),
			keys->topic_hex);

	sts_memzero(secret, sizeof(secret));
	sts_memzero(master, sizeof(master));
	return ret;
}

/* --- helpers ------------------------------------------------------------- */

static uint64_t now_ms(const struct sts_room *r)
{
	return r->ops.monotonic_ms ? r->ops.monotonic_ms(r->ud) :
				     sts_monotonic_ms();
}

static uint64_t wall_ms(const struct sts_room *r)
{
	return r->ops.wallclock_ms ? r->ops.wallclock_ms(r->ud) :
				     sts_wallclock_ms();
}

static int elapsed(uint64_t now, uint64_t since, uint64_t interval)
{
	return since == 0 || now - since >= interval;
}

static int all_zero(const uint8_t *p, size_t len)
{
	uint8_t acc = 0;
	size_t i;

	for (i = 0; i < len; i++)
		acc |= p[i];
	return acc == 0;
}

static void emit(struct sts_room *r, struct sts_event *ev)
{
	if (r->ops.event != NULL)
		r->ops.event(r->ud, ev);
}

static void notice(struct sts_room *r, const struct sts_member *m,
		   const char *text)
{
	struct sts_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = STS_EV_NOTICE;
	ev.member = m;
	ev.notice = text;
	emit(r, &ev);
}

static int confirmed(const struct sts_member *m)
{
	return m->state == STS_MEMBER_ACTIVE || m->state == STS_MEMBER_AWAY;
}

static void stored_free(struct sts_stored *s)
{
	if (s->data != NULL) {
		sts_memzero(s->data, s->len);
		free(s->data);
	}
	memset(s, 0, sizeof(*s));
}

static int stored_set(struct sts_stored *s, uint32_t epoch, uint64_t seq,
		      const uint8_t *data, size_t len)
{
	uint8_t *copy = malloc(len);

	if (copy == NULL)
		return -1;
	memcpy(copy, data, len);
	stored_free(s);
	s->epoch = epoch;
	s->seq = seq;
	s->len = len;
	s->data = copy;
	return 0;
}

static void stash_free(struct sts_stash *s)
{
	if (s->data != NULL) {
		sts_memzero(s->data, s->len);
		free(s->data);
	}
	memset(s, 0, sizeof(*s));
}

static void stash_remove(struct sts_member *m, size_t i)
{
	stash_free(&m->stash[i]);
	memmove(&m->stash[i], &m->stash[i + 1],
		(m->n_stash - i - 1) * sizeof(m->stash[0]));
	m->n_stash--;
	memset(&m->stash[m->n_stash], 0, sizeof(m->stash[0]));
}

/* @return the slot, the oldest entry is dropped when full */
static struct sts_stash *stash_add(struct sts_room *r, struct sts_member *m)
{
	struct sts_stash *s;

	if (m->n_stash == STS_STASH_MAX)
		stash_remove(m, 0);
	s = &m->stash[m->n_stash++];
	memset(s, 0, sizeof(*s));
	s->since_ms = now_ms(r);
	return s;
}

static void member_wipe(struct sts_member *m)
{
	size_t i;

	sts_memzero(m->keys, sizeof(m->keys));
	sts_memzero(m->sk, sizeof(m->sk));
	sts_memzero(m->prev_sk, sizeof(m->prev_sk));
	for (i = 0; i < STS_STASH_MAX; i++)
		stash_free(&m->stash[i]);
	for (i = 0; i < STS_PW_HISTORY; i++)
		stored_free(&m->pw_hist[i]);
	m->n_stash = 0;
	m->have_sk = 0;
	m->have_prev_sk = 0;
	m->n_missing = 0;
}

static void slot_free(struct sts_room *r, size_t i)
{
	if (r->members[i] == NULL)
		return;
	member_wipe(r->members[i]);
	sts_memzero(r->members[i], sizeof(*r->members[i]));
	free(r->members[i]);
	r->members[i] = NULL;
}

static struct sts_member *find_sid(struct sts_room *r, const uint8_t *sid)
{
	size_t i;

	for (i = 0; i < STS_MEMBER_SLOTS; i++)
		if (r->members[i] != NULL &&
		    memcmp(r->members[i]->sid, sid, STS_SID_LEN) == 0)
			return r->members[i];
	return NULL;
}

static size_t count_state(const struct sts_room *r, enum sts_member_state st)
{
	size_t i;
	size_t n = 0;

	for (i = 0; i < STS_MEMBER_SLOTS; i++)
		n += r->members[i] != NULL && r->members[i]->state == st;
	return n;
}

/* free the oldest member in state @st */
static void evict_oldest(struct sts_room *r, enum sts_member_state st)
{
	size_t oldest = STS_MEMBER_SLOTS;
	size_t i;

	for (i = 0; i < STS_MEMBER_SLOTS; i++) {
		if (r->members[i] == NULL || r->members[i]->state != st)
			continue;
		if (oldest == STS_MEMBER_SLOTS ||
		    r->members[i]->created_ms < r->members[oldest]->created_ms)
			oldest = i;
	}
	if (oldest != STS_MEMBER_SLOTS)
		slot_free(r, oldest);
}

static struct sts_member *member_alloc(struct sts_room *r)
{
	size_t i;

	if (count_state(r, STS_MEMBER_ACTIVE) +
		    count_state(r, STS_MEMBER_AWAY) >=
	    STS_MAX_MEMBERS) {
		if (!r->full_reported)
			notice(r, NULL, "room is full, ignoring newcomers");
		r->full_reported = 1;
		return NULL;
	}
	if (count_state(r, STS_MEMBER_PENDING) >= STS_MAX_PENDING)
		evict_oldest(r, STS_MEMBER_PENDING);

	for (i = 0; i < STS_MEMBER_SLOTS; i++) {
		if (r->members[i] == NULL) {
			r->members[i] = calloc(1, sizeof(struct sts_member));
			return r->members[i];
		}
	}
	/* only GONE entries left to reuse */
	evict_oldest(r, STS_MEMBER_GONE);
	for (i = 0; i < STS_MEMBER_SLOTS; i++) {
		if (r->members[i] == NULL) {
			r->members[i] = calloc(1, sizeof(struct sts_member));
			return r->members[i];
		}
	}
	return NULL;
}

/* --- framing ------------------------------------------------------------- */

static void write_header(struct sts_wbuf *w, const struct sts_room *r,
			 enum sts_frame_type type)
{
	sts_w_u8(w, (uint8_t)type);
	sts_w_u8(w, 0); /* reserved */
	sts_w_bytes(w, r->sid, STS_SID_LEN);
}

/*
 * Outer layer: the inner frame is padded and encrypted with the room key,
 * so the broker sees neither who sends nor what kind of frame it is.
 */
static int wrap(const struct sts_room *r, const uint8_t *inner, size_t len,
		uint8_t wire[STS_WIRE_MAX], size_t *wire_len)
{
	uint8_t padded[STS_FRAME_MAX + STS_PAD_BLOCK];
	size_t plen;
	int ret;

	if (len < STS_HDR_LEN || len > STS_FRAME_MAX)
		return -1;

	plen = (2 + len + STS_PAD_BLOCK - 1) / STS_PAD_BLOCK * STS_PAD_BLOCK;
	padded[0] = (uint8_t)(len >> 8);
	padded[1] = (uint8_t)len;
	memcpy(&padded[2], inner, len);
	memset(&padded[2 + len], 0, plen - 2 - len);

	wire[0] = STS_PROTO_MAGIC;
	wire[1] = STS_PROTO_VERSION;
	if (sts_random(&wire[2], STS_NONCE_LEN) != 0)
		return -1;

	ret = sts_aead_seal(r->keys.outer_key, &wire[2], wire, 2, padded, plen,
			    &wire[2 + STS_NONCE_LEN]);
	sts_memzero(padded, sizeof(padded));
	*wire_len = 2 + STS_NONCE_LEN + plen + STS_TAG_LEN;
	return ret;
}

static int send_inner(struct sts_room *r, const uint8_t *inner, size_t len)
{
	uint8_t wire[STS_WIRE_MAX];
	size_t wire_len;

	if (wrap(r, inner, len, wire, &wire_len) != 0 ||
	    r->ops.send(r->ud, wire, wire_len) != 0)
		return -1;
	r->stats.sent++;
	return 0;
}

/* SHA-256(label || NUL || topic id || data) */
static void signed_hash(const struct sts_room *r, const char *label,
			const uint8_t *data, size_t len,
			uint8_t out[STS_HASH_LEN])
{
	struct sts_sha256 h;

	sts_sha256_init(&h);
	sts_sha256_update(&h, label, strlen(label) + 1);
	sts_sha256_update(&h, r->keys.topic_id, STS_TOPIC_ID_LEN);
	sts_sha256_update(&h, data, len);
	sts_sha256_final(&h, out);
}

static int sign_append(struct sts_room *r, struct sts_wbuf *w,
		       const char *label)
{
	uint8_t hash[STS_HASH_LEN];
	uint8_t *sig;

	if (w->err)
		return -1;
	signed_hash(r, label, w->p, w->len, hash);
	sig = sts_w_reserve(w, STS_SIG_LEN);
	if (sig == NULL)
		return -1;
	return sts_sign(r->self, hash, sig);
}

/* @frame is data || signature */
static int verify_sig(const struct sts_room *r, const char *label,
		      const uint8_t *frame, size_t len,
		      const uint8_t pub[STS_PUBKEY_LEN])
{
	uint8_t hash[STS_HASH_LEN];

	if (len < STS_SIG_LEN)
		return -1;
	signed_hash(r, label, frame, len - STS_SIG_LEN, hash);
	return sts_verify(pub, hash, frame + len - STS_SIG_LEN);
}

static void derive_sid(const uint8_t id_pub[STS_PUBKEY_LEN],
		       const uint8_t nonce[STS_SID_NONCE_LEN],
		       uint8_t sid[STS_SID_LEN])
{
	uint8_t h[STS_HASH_LEN];
	struct sts_sha256 ctx;

	sts_sha256_init(&ctx);
	sts_sha256_update(&ctx, LABEL_SID, sizeof(LABEL_SID));
	sts_sha256_update(&ctx, id_pub, STS_PUBKEY_LEN);
	sts_sha256_update(&ctx, nonce, STS_SID_NONCE_LEN);
	sts_sha256_final(&ctx, h);
	memcpy(sid, h, STS_SID_LEN);
}

/* --- pairwise keys ------------------------------------------------------- */

static const struct sts_ephemeral *own_eph(const struct sts_room *r,
					   uint32_t gen)
{
	if (gen == r->eph_gen)
		return &r->eph;
	if (r->has_prev_eph && gen == r->prev_eph_gen)
		return &r->prev_eph;
	return NULL;
}

static const uint8_t *peer_eph(const struct sts_member *m, uint32_t gen)
{
	if (gen == m->eph_gen)
		return m->eph_pub;
	if (m->has_prev_eph && gen == m->prev_eph_gen)
		return m->prev_eph_pub;
	return NULL;
}

/*
 * Pairwise keys from ECDH over both ephemeral keys, bound to the room, both
 * identities and both sessions, one key per direction.
 */
static struct sts_pw_keys *pw_keys(struct sts_room *r, struct sts_member *m,
				   uint32_t own_gen, uint32_t peer_gen)
{
	uint8_t info[sizeof(LABEL_PAIRWISE) + STS_TOPIC_ID_LEN +
		     4 * STS_PUBKEY_LEN + 2 * STS_SID_LEN];
	const uint8_t *id_lo, *id_hi, *sid_lo, *sid_hi, *eph_lo, *eph_hi;
	const struct sts_ephemeral *own;
	const uint8_t *peer;
	uint8_t shared[STS_KEY_LEN];
	uint8_t okm[2 * STS_KEY_LEN];
	uint8_t salt[STS_HASH_LEN];
	struct sts_pw_keys *k = NULL;
	struct sts_sha256 h;
	struct sts_wbuf w;
	int self_lo;
	size_t i;
	int ret;

	for (i = 0; i < STS_ARRAY_SIZE(m->keys); i++)
		if (m->keys[i].valid && m->keys[i].own_gen == own_gen &&
		    m->keys[i].peer_gen == peer_gen)
			return &m->keys[i];

	own = own_eph(r, own_gen);
	peer = peer_eph(m, peer_gen);
	if (own == NULL || peer == NULL)
		return NULL;

	/* reuse a free slot, else one that isn't for the current keys */
	for (i = 0; i < STS_ARRAY_SIZE(m->keys) && k == NULL; i++)
		if (!m->keys[i].valid)
			k = &m->keys[i];
	for (i = 0; i < STS_ARRAY_SIZE(m->keys) && k == NULL; i++)
		if (m->keys[i].own_gen != r->eph_gen ||
		    m->keys[i].peer_gen != m->eph_gen)
			k = &m->keys[i];
	if (k == NULL)
		k = &m->keys[0];

	if (sts_ecdh(own, peer, shared) != 0)
		return NULL;

	self_lo = memcmp(r->sid, m->sid, STS_SID_LEN) < 0;
	id_lo = self_lo ? r->self->pub : m->id_pub;
	id_hi = self_lo ? m->id_pub : r->self->pub;
	sid_lo = self_lo ? r->sid : m->sid;
	sid_hi = self_lo ? m->sid : r->sid;
	eph_lo = self_lo ? own->pub : peer;
	eph_hi = self_lo ? peer : own->pub;

	sts_sha256_init(&h);
	sts_sha256_update(&h, eph_lo, STS_PUBKEY_LEN);
	sts_sha256_update(&h, eph_hi, STS_PUBKEY_LEN);
	sts_sha256_final(&h, salt);

	sts_wbuf_init(&w, info, sizeof(info));
	sts_w_bytes(&w, LABEL_PAIRWISE, sizeof(LABEL_PAIRWISE));
	sts_w_bytes(&w, r->keys.topic_id, STS_TOPIC_ID_LEN);
	sts_w_bytes(&w, id_lo, STS_PUBKEY_LEN);
	sts_w_bytes(&w, id_hi, STS_PUBKEY_LEN);
	sts_w_bytes(&w, sid_lo, STS_SID_LEN);
	sts_w_bytes(&w, sid_hi, STS_SID_LEN);
	sts_w_bytes(&w, eph_lo, STS_PUBKEY_LEN);
	sts_w_bytes(&w, eph_hi, STS_PUBKEY_LEN);

	ret = w.err ? -1 :
		      sts_hkdf(salt, sizeof(salt), shared, sizeof(shared), info,
			       w.len, okm, sizeof(okm));
	sts_memzero(shared, sizeof(shared));
	if (ret != 0) {
		sts_memzero(okm, sizeof(okm));
		return NULL;
	}

	memcpy(k->send, self_lo ? okm : okm + STS_KEY_LEN, STS_KEY_LEN);
	memcpy(k->recv, self_lo ? okm + STS_KEY_LEN : okm, STS_KEY_LEN);
	k->own_gen = own_gen;
	k->peer_gen = peer_gen;
	k->valid = 1;
	sts_memzero(okm, sizeof(okm));
	return k;
}

/* forget keys whose ephemeral keys are gone */
static void pw_keys_prune(struct sts_room *r, struct sts_member *m)
{
	size_t i;

	for (i = 0; i < STS_ARRAY_SIZE(m->keys); i++)
		if (m->keys[i].valid &&
		    (own_eph(r, m->keys[i].own_gen) == NULL ||
		     peer_eph(m, m->keys[i].peer_gen) == NULL))
			sts_memzero(&m->keys[i], sizeof(m->keys[i]));
}

static void nonce_make(uint8_t nonce[STS_NONCE_LEN], uint32_t prefix,
		       uint64_t seq)
{
	struct sts_wbuf w;

	sts_wbuf_init(&w, nonce, STS_NONCE_LEN);
	sts_w_u32(&w, prefix);
	sts_w_u64(&w, seq);
}

/* --- sending ------------------------------------------------------------- */

static int send_hello(struct sts_room *r, uint8_t flags)
{
	uint8_t buf[STS_FRAME_MAX];
	uint64_t now = now_ms(r);
	size_t nlen = strlen(r->nick);
	struct sts_wbuf w;

	if (!r->connected)
		return 0;

	r->counter++;
	sts_wbuf_init(&w, buf, sizeof(buf));
	write_header(&w, r, STS_T_HELLO);
	sts_w_u8(&w, flags);
	sts_w_u64(&w, r->counter);
	sts_w_u32(&w, r->conn);
	sts_w_bytes(&w, r->sid_nonce, STS_SID_NONCE_LEN);
	sts_w_bytes(&w, r->self->pub, STS_PUBKEY_LEN);
	sts_w_u32(&w, r->eph_gen);
	sts_w_bytes(&w, r->eph.pub, STS_PUBKEY_LEN);
	sts_w_u8(&w, (uint8_t)nlen);
	sts_w_bytes(&w, r->nick, nlen);
	sts_w_u32(&w, r->sk_epoch);
	sts_w_u64(&w, r->sk_seq);

	if (sign_append(r, &w, LABEL_HELLO) != 0)
		return -1;

	r->last_hello_ms = now;
	r->reply_due_ms = 0;
	return send_inner(r, buf, w.len);
}

static void send_reply(struct sts_room *r)
{
	r->last_reply_ms = now_ms(r);
	send_hello(r, 0);
}

/*
 * Answer a request for HELLOs. One reply serves everyone who asked, so a
 * burst of joins costs at most one HELLO per STS_REPLY_INTERVAL_MS.
 */
static void schedule_reply(struct sts_room *r)
{
	uint64_t now = now_ms(r);

	if (elapsed(now, r->last_reply_ms, STS_REPLY_INTERVAL_MS))
		send_reply(r);
	else if (r->reply_due_ms == 0)
		r->reply_due_ms = r->last_reply_ms + STS_REPLY_INTERVAL_MS;
}

/* someone unknown talks to us: ask everyone to announce themselves */
static void maybe_announce(struct sts_room *r)
{
	uint64_t now = now_ms(r);

	if (!elapsed(now, r->last_announce_ms, STS_ANNOUNCE_MS))
		return;
	r->last_announce_ms = now;
	send_hello(r, STS_HELLO_WANT_REPLY);
}

/*
 * Pairwise frame:
 *   hdr | recipient | sender gen | recipient gen | seq | echo | nonce | AEAD
 * The echo is the recipient's challenge: frames of an earlier handshake
 * don't carry the current one. Nonces are random because the sequence
 * restarts when a member is forgotten and met again under the same keys.
 */
static int send_pairwise(struct sts_room *r, struct sts_member *m,
			 enum sts_frame_type type, const uint8_t *pt,
			 size_t pt_len)
{
	uint8_t buf[STS_FRAME_MAX];
	struct sts_pw_keys *k;
	struct sts_wbuf w;
	uint8_t *nonce;
	size_t aad_len;
	uint8_t *ct;
	uint64_t seq;

	k = pw_keys(r, m, r->eph_gen, m->eph_gen);
	if (k == NULL)
		return -1;

	seq = ++m->pw_send_seq;
	sts_wbuf_init(&w, buf, sizeof(buf));
	write_header(&w, r, type);
	sts_w_bytes(&w, m->sid, STS_SID_LEN);
	sts_w_u32(&w, r->eph_gen);
	sts_w_u32(&w, m->eph_gen);
	sts_w_u64(&w, seq);
	sts_w_bytes(&w, m->their_chal, STS_CHAL_LEN);
	nonce = sts_w_reserve(&w, STS_NONCE_LEN);
	aad_len = w.len;

	ct = sts_w_reserve(&w, pt_len + STS_TAG_LEN);
	if (nonce == NULL || ct == NULL ||
	    sts_random(nonce, STS_NONCE_LEN) != 0)
		return -1;

	if (sts_aead_seal(k->send, nonce, buf, aad_len, pt, pt_len, ct) != 0)
		return -1;

	/* kept for resend requests */
	stored_set(&m->pw_hist[m->pw_hist_next], 0, seq, buf, w.len);
	m->pw_hist_next = (m->pw_hist_next + 1) % STS_PW_HISTORY;

	return send_inner(r, buf, w.len);
}

/*
 * Our challenge, and our sender key once the session is confirmed: one that
 * never answers the handshake never shows up in the list, so it must not
 * read the room either. Until then epoch 0 and no key.
 */
static int send_keydist(struct sts_room *r, struct sts_member *m)
{
	static const uint8_t no_key[STS_KEY_LEN];
	uint8_t pt[KEYDIST_LEN];
	struct sts_wbuf w;
	int has_key = confirmed(m);
	int ret;

	sts_wbuf_init(&w, pt, sizeof(pt));
	sts_w_bytes(&w, m->my_chal, STS_CHAL_LEN);
	sts_w_u32(&w, has_key ? r->sk_epoch : 0);
	sts_w_bytes(&w, has_key ? r->sk : no_key, STS_KEY_LEN);
	sts_w_u64(&w, has_key ? r->sk_seq : 0);

	m->last_keydist_ms = now_ms(r);
	m->need_echo = 0;
	ret = send_pairwise(r, m, STS_T_KEYDIST, pt, sizeof(pt));
	sts_memzero(pt, sizeof(pt));
	return ret;
}

static void rotate_sender_key(struct sts_room *r)
{
	uint8_t key[STS_KEY_LEN];
	size_t i;

	if (sts_random(key, sizeof(key)) != 0) {
		/* keep writing with the old key, try again at the next tick */
		ERROR("room: no random numbers, the sender key isn't renewed");
		r->need_rotate = 1;
		return;
	}
	memcpy(r->sk, key, STS_KEY_LEN);
	sts_memzero(key, sizeof(key));
	r->sk_epoch++;
	if (r->sk_epoch == 0) /* 0 means "no key yet" */
		r->sk_epoch = 1;
	r->sk_seq = 0;

	for (i = 0; i < STS_MEMBER_SLOTS; i++)
		if (r->members[i] != NULL && confirmed(r->members[i]))
			send_keydist(r, r->members[i]);
}

/* --- member life cycle --------------------------------------------------- */

static int handle_msg(struct sts_room *r, struct sts_member *m,
		      const uint8_t *frame, size_t len, int from_stash);

static void stash_retry(struct sts_room *r, struct sts_member *m)
{
	size_t i = 0;
	int ret;

	while (i < m->n_stash && confirmed(m)) {
		struct sts_stash *s = &m->stash[i];

		ret = handle_msg(r, m, s->data, s->len, 1);
		if (ret == WAIT)
			i++;
		else
			stash_remove(m, i);
	}
}

static void activate(struct sts_room *r, struct sts_member *m)
{
	struct sts_event ev;
	size_t i;
	int others = 0;

	m->state = STS_MEMBER_ACTIVE;

	/*
	 * Only now does it get our sender key, and never one that already
	 * encrypted messages: it may have recorded them before joining. An
	 * unused key reveals nothing, so joins in a quiet room cost nothing.
	 * In our first seconds in the room, the sessions we meet were there
	 * before us: they get the key of what we wrote meanwhile.
	 */
	if (r->sk_seq > 0 && now_ms(r) >= r->discovery_until_ms)
		rotate_sender_key(r); /* sends it to everyone, m included */
	else
		send_keydist(r, m);
	for (i = 0; i < STS_MEMBER_SLOTS; i++) {
		const struct sts_member *o = r->members[i];

		if (o != NULL && o != m && confirmed(o) &&
		    memcmp(o->fpr, m->fpr, STS_HASH_LEN) == 0)
			others++;
	}

	memset(&ev, 0, sizeof(ev));
	ev.type = STS_EV_JOIN;
	ev.member = m;
	ev.other_devices = others;
	emit(r, &ev);

	stash_retry(r, m);
}

static void member_gone(struct sts_room *r, struct sts_member *m,
			enum sts_leave_reason reason)
{
	struct sts_event ev;
	int was = confirmed(m);

	if (was) {
		memset(&ev, 0, sizeof(ev));
		ev.type = STS_EV_LEAVE;
		ev.member = m;
		ev.reason = reason;
		emit(r, &ev);
	}

	member_wipe(m);
	m->state = STS_MEMBER_GONE;
	m->stale = 0;
	m->created_ms = now_ms(r);

	if (count_state(r, STS_MEMBER_GONE) > STS_MAX_GONE)
		evict_oldest(r, STS_MEMBER_GONE);

	if (was) {
		/* who left must not read what comes next */
		rotate_sender_key(r);
	}
}

/* --- missing frames ------------------------------------------------------ */

static int missing_find(const struct sts_member *m, uint8_t channel,
			uint32_t epoch, uint64_t seq)
{
	size_t i;

	for (i = 0; i < m->n_missing; i++)
		if (m->missing[i].channel == channel &&
		    m->missing[i].epoch == epoch && m->missing[i].seq == seq)
			return (int)i;
	return -1;
}

static void missing_drop(struct sts_member *m, size_t i)
{
	memmove(&m->missing[i], &m->missing[i + 1],
		(m->n_missing - i - 1) * sizeof(m->missing[0]));
	m->n_missing--;
}

/* @return 1 if (@channel, @epoch, @seq) was missing */
static int missing_resolve(struct sts_member *m, uint8_t channel,
			   uint32_t epoch, uint64_t seq)
{
	int i = missing_find(m, channel, epoch, seq);

	if (i < 0)
		return 0;
	missing_drop(m, (size_t)i);
	return 1;
}

/* frames @from to @to (included) never arrived, the most recent count */
static void missing_add(struct sts_room *r, struct sts_member *m,
			uint8_t channel, uint32_t epoch, uint64_t from,
			uint64_t to)
{
	uint64_t now = now_ms(r);
	uint64_t seq;
	uint64_t i;

	if (to < from)
		return;
	if (to - from >= STS_MISSING_MAX)
		from = to - STS_MISSING_MAX + 1;

	/* counted, not "seq <= to": @to may be UINT64_MAX */
	for (i = 0; i <= to - from; i++) {
		struct sts_missing *e;

		seq = from + i;
		if (missing_find(m, channel, epoch, seq) >= 0)
			continue;
		if (m->n_missing == STS_MISSING_MAX)
			missing_drop(m, 0);
		e = &m->missing[m->n_missing++];
		e->channel = channel;
		e->epoch = epoch;
		e->seq = seq;
		e->due_ms = now + STS_RESEND_DELAY_MS;
		e->tries = 0;
	}
}

/* the member says it sent up to @seq in @epoch: anything we lack is missing */
static void tail_check(struct sts_room *r, struct sts_member *m, uint32_t epoch,
		       uint64_t seq)
{
	uint64_t top;

	if (!m->have_sk || epoch != m->sk_epoch || seq == 0)
		return;
	top = m->sk_recv.init ? m->sk_recv.top : m->sk_base;
	if (seq > top)
		missing_add(r, m, 0, epoch, top + 1, seq);
}

static void send_resends(struct sts_room *r, struct sts_member *m, uint64_t now)
{
	uint8_t pt[1 + 4 + 1 + 8 * RESEND_MAX];
	unsigned int lost = 0;
	uint8_t channel = 0;
	uint32_t epoch = 0;
	struct sts_wbuf w;
	uint8_t count = 0;
	uint8_t *countp = NULL;
	size_t i = 0;

	sts_wbuf_init(&w, pt, sizeof(pt));

	while (i < m->n_missing) {
		struct sts_missing *e = &m->missing[i];

		if (e->due_ms > now) {
			i++;
			continue;
		}
		if (e->tries >= STS_RESEND_TRIES) {
			lost += e->channel == 0;
			missing_drop(m, i);
			continue;
		}
		/* one request per channel and epoch at a time */
		if (count == 0) {
			channel = e->channel;
			epoch = e->epoch;
			sts_wbuf_init(&w, pt, sizeof(pt));
			sts_w_u8(&w, channel);
			sts_w_u32(&w, epoch);
			countp = sts_w_reserve(&w, 1);
		} else if (e->channel != channel || e->epoch != epoch ||
			   count == RESEND_MAX) {
			i++;
			continue;
		}
		sts_w_u64(&w, e->seq);
		count++;
		e->tries++;
		e->due_ms = now + STS_RESEND_RETRY_MS;
		i++;
	}

	if (count > 0 && countp != NULL && !w.err) {
		*countp = count;
		send_pairwise(r, m, STS_T_RESEND, pt, w.len);
	}

	if (lost > 0) {
		char text[96];

		m->lost += lost;
		snprintf(text, sizeof(text),
			 "%u message%s could not be recovered", lost,
			 lost > 1 ? "s" : "");
		notice(r, m, text);
	}
}

/* --- receiving ----------------------------------------------------------- */

static void member_set_sk(struct sts_room *r, struct sts_member *m,
			  uint32_t epoch, const uint8_t *key, uint64_t base)
{
	if (m->have_sk && epoch <= m->sk_epoch)
		return; /* resend of the current key, or older */

	if (m->have_sk) {
		memcpy(m->prev_sk, m->sk, STS_KEY_LEN);
		m->prev_sk_epoch = m->sk_epoch;
		m->prev_sk_recv = m->sk_recv;
		m->have_prev_sk = 1;
		m->prev_sk_until_ms = now_ms(r) + STS_OLD_KEY_MS;
	}
	memcpy(m->sk, key, STS_KEY_LEN);
	m->sk_epoch = epoch;
	m->sk_base = base;
	m->have_sk = 1;
	memset(&m->sk_recv, 0, sizeof(m->sk_recv));
}

static int handle_hello(struct sts_room *r, const uint8_t *frame, size_t len,
			struct sts_rbuf *rd, const uint8_t *sender)
{
	const uint8_t *nonce, *id_pub, *eph_pub, *nick;
	uint8_t sid[STS_SID_LEN];
	uint8_t fpr[STS_HASH_LEN];
	char old_nick[STS_NICK_MAX + 1];
	struct sts_member *m;
	struct sts_event ev;
	uint64_t now = now_ms(r);
	uint64_t counter, sk_seq;
	uint32_t conn, eph_gen, sk_epoch;
	uint8_t flags, nlen;

	flags = sts_r_u8(rd);
	counter = sts_r_u64(rd);
	conn = sts_r_u32(rd);
	nonce = sts_r_bytes(rd, STS_SID_NONCE_LEN);
	id_pub = sts_r_bytes(rd, STS_PUBKEY_LEN);
	eph_gen = sts_r_u32(rd);
	eph_pub = sts_r_bytes(rd, STS_PUBKEY_LEN);
	nlen = sts_r_u8(rd);
	nick = sts_r_bytes(rd, nlen);
	sk_epoch = sts_r_u32(rd);
	sk_seq = sts_r_u64(rd);
	sts_r_bytes(rd, STS_SIG_LEN);

	if (rd->err || sts_r_left(rd) != 0 || counter == 0 ||
	    !sts_nick_valid((const char *)nick, nlen)) {
		DEBUG("room: malformed HELLO");
		return REJECT;
	}

	/* the session id is bound to the identity */
	derive_sid(id_pub, nonce, sid);
	if (memcmp(sid, sender, STS_SID_LEN) != 0) {
		DEBUG("room: HELLO session id doesn't match its identity");
		return REJECT;
	}

	m = find_sid(r, sender);
	if (m != NULL && m->state != STS_MEMBER_GONE && counter <= m->counter)
		return IGNORED; /* duplicate or replay */
	if (m != NULL && m->state == STS_MEMBER_GONE && counter <= m->counter)
		return IGNORED;

	/* also rejects an identity key that isn't a valid point */
	if (verify_sig(r, LABEL_HELLO, frame, len, id_pub) != 0) {
		DEBUG("room: HELLO with a bad signature");
		return REJECT;
	}
	if (sts_pubkey_check(eph_pub) != 0) {
		DEBUG("room: HELLO with an invalid ephemeral key");
		return REJECT;
	}
	sts_sha256(id_pub, STS_PUBKEY_LEN, fpr);

	if (m == NULL || m->state == STS_MEMBER_GONE) {
		/* new session (or one coming back after timing out) */
		if (m == NULL) {
			m = member_alloc(r);
			if (m == NULL)
				return REJECT;
		} else {
			member_wipe(m);
			memset(m, 0, sizeof(*m));
		}

		m->state = STS_MEMBER_PENDING;
		memcpy(m->sid, sender, STS_SID_LEN);
		memcpy(m->id_pub, id_pub, STS_PUBKEY_LEN);
		memcpy(m->fpr, fpr, STS_HASH_LEN);
		memcpy(m->nick, nick, nlen);
		m->nick[nlen] = '\0';
		m->counter = counter;
		m->conn = conn;
		m->eph_gen = eph_gen;
		memcpy(m->eph_pub, eph_pub, STS_PUBKEY_LEN);
		m->created_ms = now;
		if (sts_random(m->my_chal, sizeof(m->my_chal)) != 0)
			return REJECT;

		/* our HELLO must arrive before our KEYDIST */
		if (flags & STS_HELLO_WANT_REPLY)
			schedule_reply(r);
		send_keydist(r, m);
		return DONE;
	}

	/* the identity is fixed for the whole session */
	if (memcmp(m->id_pub, id_pub, STS_PUBKEY_LEN) != 0)
		return REJECT;

	m->counter = counter;
	m->stale = 0;

	/* new ephemeral key: post-compromise security */
	if (eph_gen != m->eph_gen) {
		if (eph_gen < m->eph_gen)
			return REJECT;
		memcpy(m->prev_eph_pub, m->eph_pub, STS_PUBKEY_LEN);
		m->prev_eph_gen = m->eph_gen;
		m->has_prev_eph = 1;
		m->prev_eph_until_ms = now + STS_OLD_KEY_MS;
		memcpy(m->eph_pub, eph_pub, STS_PUBKEY_LEN);
		m->eph_gen = eph_gen;
		pw_keys_prune(r, m);
	} else if (memcmp(m->eph_pub, eph_pub, STS_PUBKEY_LEN) != 0) {
		return REJECT;
	}

	if (strlen(m->nick) != nlen || memcmp(m->nick, nick, nlen) != 0) {
		sts_strlcpy(old_nick, m->nick, sizeof(old_nick));
		memcpy(m->nick, nick, nlen);
		m->nick[nlen] = '\0';
		if (confirmed(m)) {
			memset(&ev, 0, sizeof(ev));
			ev.type = STS_EV_NICK;
			ev.member = m;
			ev.old_nick = old_nick;
			emit(r, &ev);
		}
	}

	if (conn > m->conn) {
		m->conn = conn;
		if (m->state == STS_MEMBER_AWAY) {
			m->state = STS_MEMBER_ACTIVE;
			memset(&ev, 0, sizeof(ev));
			ev.type = STS_EV_BACK;
			ev.member = m;
			emit(r, &ev);
		}
	}

	if (confirmed(m))
		tail_check(r, m, sk_epoch, sk_seq);
	if (flags & STS_HELLO_WANT_REPLY)
		schedule_reply(r);
	return DONE;
}

/*
 * @valid: the frame echoed our current challenge. A KEYDIST that doesn't is
 * the peer's side of a handshake: we only learn its challenge from it.
 */
static int handle_keydist(struct sts_room *r, struct sts_member *m,
			  const uint8_t *pt, size_t len, int valid)
{
	const uint8_t *chal, *key;
	struct sts_rbuf rd;
	uint32_t epoch;
	uint64_t seq;

	sts_rbuf_init(&rd, pt, len);
	chal = sts_r_bytes(&rd, STS_CHAL_LEN);
	epoch = sts_r_u32(&rd);
	key = sts_r_bytes(&rd, STS_KEY_LEN);
	seq = sts_r_u64(&rd);
	if (rd.err || sts_r_left(&rd) != 0 || all_zero(chal, STS_CHAL_LEN))
		return REJECT;

	if (memcmp(chal, m->their_chal, STS_CHAL_LEN) != 0) {
		memcpy(m->their_chal, chal, STS_CHAL_LEN);
		m->need_echo = 1;
	}

	/* sender keys only from frames proven fresh; epoch 0: none yet */
	if (valid && epoch != 0)
		member_set_sk(r, m, epoch, key, seq);

	if (m->need_echo || !valid)
		send_keydist(r, m);

	if (valid && confirmed(m) && epoch != 0) {
		stash_retry(r, m);
		tail_check(r, m, epoch, seq);
	}
	return DONE;
}

static int handle_resend(struct sts_room *r, struct sts_member *m,
			 const uint8_t *pt, size_t len)
{
	uint64_t now = now_ms(r);
	struct sts_rbuf rd;
	uint8_t channel;
	uint32_t epoch;
	uint8_t count;
	uint64_t seq;
	size_t i;
	size_t j;

	sts_rbuf_init(&rd, pt, len);
	channel = sts_r_u8(&rd);
	epoch = sts_r_u32(&rd);
	count = sts_r_u8(&rd);
	if (rd.err || count == 0 || count > RESEND_MAX || channel > 1 ||
	    sts_r_left(&rd) != (size_t)count * 8)
		return REJECT;

	/* bounded work for whoever asks */
	if (!elapsed(now, m->last_resend_ms, STS_RESEND_DELAY_MS))
		return IGNORED;
	m->last_resend_ms = now;

	for (i = 0; i < count; i++) {
		seq = sts_r_u64(&rd);

		if (channel == 0) {
			for (j = 0; j < STS_HISTORY; j++) {
				struct sts_stored *s = &r->history[j];

				if (s->data != NULL && s->epoch == epoch &&
				    s->seq == seq) {
					send_inner(r, s->data, s->len);
					r->stats.resent++;
					break;
				}
			}
			continue;
		}

		for (j = 0; j < STS_PW_HISTORY; j++) {
			struct sts_stored *s = &m->pw_hist[j];

			if (s->data != NULL && s->seq == seq) {
				send_inner(r, s->data, s->len);
				r->stats.resent++;
				break;
			}
		}
	}
	return DONE;
}

static int handle_dm(struct sts_room *r, struct sts_member *m,
		     const uint8_t *pt, size_t len, int late)
{
	struct sts_event ev;
	struct sts_rbuf rd;
	uint64_t ts;
	uint8_t kind;

	sts_rbuf_init(&rd, pt, len);
	ts = sts_r_u64(&rd);
	kind = sts_r_u8(&rd);
	if (rd.err || kind > STS_KIND_ACTION || sts_r_left(&rd) == 0 ||
	    sts_r_left(&rd) > STS_TEXT_MAX)
		return REJECT;

	memset(&ev, 0, sizeof(ev));
	ev.type = STS_EV_MESSAGE;
	ev.member = m;
	ev.kind = (enum sts_msg_kind)kind;
	ev.is_private = 1;
	ev.late = late;
	ev.ts_ms = ts;
	ev.text = &pt[rd.off];
	ev.text_len = sts_r_left(&rd);
	emit(r, &ev);
	return DONE;
}

/* @chal started one of the member's earlier handshakes with us */
static int old_chal_seen(const struct sts_member *m, const uint8_t *chal)
{
	size_t i;

	for (i = 0; i < STS_OLD_CHALS; i++)
		if (!all_zero(m->old_chal[i], STS_CHAL_LEN) &&
		    memcmp(m->old_chal[i], chal, STS_CHAL_LEN) == 0)
			return 1;
	return 0;
}

static int handle_pairwise(struct sts_room *r, enum sts_frame_type type,
			   const uint8_t *frame, struct sts_rbuf *rd,
			   const uint8_t *sender)
{
	uint8_t pt[STS_FRAME_MAX];
	const uint8_t *recipient;
	const uint8_t *echo;
	const uint8_t *nonce;
	const uint8_t *ct;
	struct sts_pw_keys *k;
	struct sts_member *m;
	uint32_t sender_gen;
	uint32_t own_gen;
	size_t aad_len;
	size_t ct_len;
	size_t pt_len;
	uint64_t seq;
	int valid;
	int late;
	int ret;

	recipient = sts_r_bytes(rd, STS_SID_LEN);
	sender_gen = sts_r_u32(rd);
	own_gen = sts_r_u32(rd);
	seq = sts_r_u64(rd);
	echo = sts_r_bytes(rd, STS_CHAL_LEN);
	nonce = sts_r_bytes(rd, STS_NONCE_LEN);
	aad_len = rd->off;
	ct_len = sts_r_left(rd);
	ct = sts_r_bytes(rd, ct_len);

	if (rd->err || ct_len < STS_TAG_LEN || seq == 0)
		return REJECT;
	if (memcmp(recipient, r->sid, STS_SID_LEN) != 0)
		return IGNORED; /* for someone else */

	m = find_sid(r, sender);
	if (m == NULL || m->state == STS_MEMBER_GONE) {
		maybe_announce(r);
		return REJECT;
	}

	k = pw_keys(r, m, own_gen, sender_gen);
	if (k == NULL) {
		/* keys we never saw announced, or long gone */
		if (sender_gen > m->eph_gen)
			maybe_announce(r);
		return REJECT;
	}

	pt_len = ct_len - STS_TAG_LEN;
	if (sts_aead_open(k->recv, nonce, frame, aad_len, ct, ct_len, pt) !=
	    0) {
		DEBUG("room: pairwise frame failed authentication");
		return REJECT;
	}

	valid = sts_memcmp_ct(echo, m->my_chal, STS_CHAL_LEN) == 0;
	if (!valid) {
		/* only a KEYDIST may start (or restart) a handshake */
		if (type != STS_T_KEYDIST || pt_len < STS_CHAL_LEN) {
			sts_memzero(pt, pt_len);
			return REJECT;
		}
		/*
		 * A new challenge from someone we know: they forgot us and
		 * start over. Their sequence restarts and old frames must
		 * not come back, so new challenge, new window, new sender
		 * key for them to receive.
		 */
		if (!all_zero(m->their_chal, STS_CHAL_LEN) &&
		    memcmp(pt, m->their_chal, STS_CHAL_LEN) != 0) {
			/* the broker replays a handshake that ended */
			if (old_chal_seen(m, pt)) {
				sts_memzero(pt, pt_len);
				return IGNORED;
			}
			if (sts_random(m->my_chal, STS_CHAL_LEN) != 0) {
				sts_memzero(pt, pt_len);
				return REJECT;
			}
			memcpy(m->old_chal[m->old_chal_next], m->their_chal,
			       STS_CHAL_LEN);
			m->old_chal_next =
				(m->old_chal_next + 1) % STS_OLD_CHALS;
			memset(&m->pw_recv, 0, sizeof(m->pw_recv));
			m->n_missing = 0;
			if (confirmed(m))
				r->need_rotate = 1;
		}
	}

	if (sts_replay_check(&m->pw_recv, seq) != 0) {
		sts_memzero(pt, pt_len);
		return IGNORED;
	}
	if (valid && m->pw_recv.init && seq > m->pw_recv.top + 1)
		missing_add(r, m, 1, 0, m->pw_recv.top + 1, seq - 1);
	late = missing_resolve(m, 1, 0, seq);
	sts_replay_commit(&m->pw_recv, seq);

	/* it decrypted our fresh challenge: the session is live */
	if (valid && m->state == STS_MEMBER_PENDING && type != STS_T_KEYDIST)
		activate(r, m);

	switch (type) {
	case STS_T_KEYDIST:
		ret = handle_keydist(r, m, pt, pt_len, valid);
		if (ret == DONE && valid && m->state == STS_MEMBER_PENDING)
			activate(r, m);
		break;
	case STS_T_KEYREQ:
		ret = pt_len == 0 ? DONE : REJECT;
		if (ret == DONE && elapsed(now_ms(r), m->last_keydist_ms,
					   STS_REPLY_INTERVAL_MS))
			send_keydist(r, m);
		break;
	case STS_T_DM:
		ret = handle_dm(r, m, pt, pt_len, late);
		break;
	case STS_T_RESEND:
		ret = handle_resend(r, m, pt, pt_len);
		break;
	case STS_T_FILE:
		ret = IGNORED;
		if (confirmed(m) && pt_len > 0) {
			struct sts_event ev;

			memset(&ev, 0, sizeof(ev));
			ev.type = STS_EV_FILE;
			ev.member = m;
			ev.text = pt;
			ev.text_len = pt_len;
			emit(r, &ev);
			ret = DONE;
		}
		break;
	default:
		ret = REJECT;
		break;
	}

	if (late && ret == DONE)
		r->stats.recovered++;
	sts_memzero(pt, pt_len);
	return ret;
}

/*
 * Room message: hdr | epoch | seq | AES-GCM(sender key) | signature.
 * @from_stash: the frame was kept earlier, don't keep it again.
 */
static int handle_msg(struct sts_room *r, struct sts_member *m,
		      const uint8_t *frame, size_t len, int from_stash)
{
	uint8_t pt[STS_FRAME_MAX];
	uint8_t nonce[STS_NONCE_LEN];
	const uint8_t *key = NULL;
	struct sts_replay *win = NULL;
	struct sts_event ev;
	struct sts_stash *s;
	struct sts_rbuf rd;
	uint64_t now = now_ms(r);
	const uint8_t *ct;
	size_t aad_len;
	size_t ct_len;
	uint32_t epoch;
	uint64_t seq;
	int late;

	sts_rbuf_init(&rd, frame, len);
	sts_r_bytes(&rd, STS_HDR_LEN);
	epoch = sts_r_u32(&rd);
	seq = sts_r_u64(&rd);
	aad_len = rd.off;

	if (rd.err || sts_r_left(&rd) < 8 + 1 + 1 + STS_TAG_LEN + STS_SIG_LEN ||
	    sts_r_left(&rd) > 8 + 1 + STS_TEXT_MAX + STS_TAG_LEN + STS_SIG_LEN)
		return REJECT;
	ct_len = sts_r_left(&rd) - STS_SIG_LEN;
	ct = sts_r_bytes(&rd, ct_len);

	/* the signature binds the message to the author's identity */
	if (verify_sig(r, LABEL_MSG, frame, len, m->id_pub) != 0) {
		DEBUG("room: MSG with a bad signature from %s", m->nick);
		return REJECT;
	}

	if (m->have_sk && epoch == m->sk_epoch) {
		key = m->sk;
		win = &m->sk_recv;
	} else if (m->have_prev_sk && epoch == m->prev_sk_epoch) {
		key = m->prev_sk;
		win = &m->prev_sk_recv;
	}

	/* the key of an older epoch was already dropped */
	if (key == NULL && m->have_sk && epoch < m->sk_epoch)
		return REJECT;

	if (m->state == STS_MEMBER_PENDING || key == NULL) {
		if (key == NULL && confirmed(m) &&
		    (!m->have_sk || epoch > m->sk_epoch) &&
		    elapsed(now, m->last_keyreq_ms, STS_KEYREQ_MS)) {
			m->last_keyreq_ms = now;
			send_pairwise(r, m, STS_T_KEYREQ, NULL, 0);
		}
		if (from_stash)
			return WAIT;
		s = stash_add(r, m);
		s->data = malloc(len);
		if (s->data == NULL) {
			m->n_stash--;
			return REJECT;
		}
		memcpy(s->data, frame, len);
		s->len = len;
		return DONE;
	}

	if (sts_replay_check(win, seq) != 0)
		return IGNORED;

	nonce_make(nonce, epoch, seq);
	if (sts_aead_open(key, nonce, frame, aad_len, ct, ct_len, pt) != 0) {
		DEBUG("room: MSG failed authentication");
		return REJECT;
	}
	if (pt[8] > STS_KIND_ACTION) {
		sts_memzero(pt, sizeof(pt));
		return REJECT;
	}

	if (win->init && seq > win->top + 1)
		missing_add(r, m, 0, epoch, win->top + 1, seq - 1);
	else if (!win->init && win == &m->sk_recv && seq > m->sk_base + 1)
		missing_add(r, m, 0, epoch, m->sk_base + 1, seq - 1);
	late = missing_resolve(m, 0, epoch, seq) ||
	       (win->init && seq < win->top);
	sts_replay_commit(win, seq);
	if (late)
		r->stats.recovered++;

	memset(&ev, 0, sizeof(ev));
	ev.type = STS_EV_MESSAGE;
	ev.member = m;
	ev.kind = (enum sts_msg_kind)pt[8];
	ev.late = late;
	ev.ts_ms = (uint64_t)pt[0] << 56 | (uint64_t)pt[1] << 48 |
		   (uint64_t)pt[2] << 40 | (uint64_t)pt[3] << 32 |
		   (uint64_t)pt[4] << 24 | (uint64_t)pt[5] << 16 |
		   (uint64_t)pt[6] << 8 | (uint64_t)pt[7];
	ev.text = &pt[9];
	ev.text_len = ct_len - STS_TAG_LEN - 9;
	emit(r, &ev);

	sts_memzero(pt, sizeof(pt));
	return DONE;
}

/* AWAY and LEAVE: hdr | conn | signature */
static int handle_bye(struct sts_room *r, enum sts_frame_type type,
		      const uint8_t *frame, size_t len, struct sts_rbuf *rd,
		      const uint8_t *sender)
{
	struct sts_member *m;
	struct sts_event ev;
	uint32_t conn;

	conn = sts_r_u32(rd);
	sts_r_bytes(rd, STS_SIG_LEN);
	if (rd->err || sts_r_left(rd) != 0)
		return REJECT;

	m = find_sid(r, sender);
	if (m == NULL || m->state == STS_MEMBER_GONE)
		return IGNORED;

	/* a will of an older connection doesn't count anymore */
	if (conn < m->conn)
		return IGNORED;

	if (verify_sig(r, type == STS_T_AWAY ? LABEL_AWAY : LABEL_LEAVE, frame,
		       len, m->id_pub) != 0) {
		DEBUG("room: %s with a bad signature",
		      type == STS_T_AWAY ? "AWAY" : "LEAVE");
		return REJECT;
	}

	if (type == STS_T_LEAVE || m->state == STS_MEMBER_PENDING) {
		member_gone(r, m, STS_LEAVE_QUIT);
		return DONE;
	}

	if (m->state == STS_MEMBER_AWAY)
		return IGNORED;
	m->conn = conn;
	m->away_conn = conn;
	m->state = STS_MEMBER_AWAY;
	m->away_since_ms = now_ms(r);

	memset(&ev, 0, sizeof(ev));
	ev.type = STS_EV_AWAY;
	ev.member = m;
	emit(r, &ev);
	return DONE;
}

static int dispatch(struct sts_room *r, const uint8_t *frame, size_t len)
{
	const uint8_t *sender;
	struct sts_member *m;
	struct sts_rbuf rd;
	uint8_t type;

	sts_rbuf_init(&rd, frame, len);
	type = sts_r_u8(&rd);
	sts_r_u8(&rd); /* reserved */
	sender = sts_r_bytes(&rd, STS_SID_LEN);
	if (rd.err)
		return REJECT;

	/* the broker sends our own frames back to us */
	if (memcmp(sender, r->sid, STS_SID_LEN) == 0)
		return IGNORED;

	r->stats.received++;

	switch (type) {
	case STS_T_HELLO:
		return handle_hello(r, frame, len, &rd, sender);
	case STS_T_KEYDIST:
	case STS_T_KEYREQ:
	case STS_T_DM:
	case STS_T_RESEND:
	case STS_T_FILE:
		return handle_pairwise(r, (enum sts_frame_type)type, frame, &rd,
				       sender);
	case STS_T_MSG:
		m = find_sid(r, sender);
		if (m == NULL || m->state == STS_MEMBER_GONE) {
			maybe_announce(r);
			return REJECT;
		}
		return handle_msg(r, m, frame, len, 0);
	case STS_T_AWAY:
	case STS_T_LEAVE:
		return handle_bye(r, (enum sts_frame_type)type, frame, len, &rd,
				  sender);
	default:
		DEBUG("room: unknown frame type %u", type);
		return REJECT;
	}
}

int sts_room_handle(struct sts_room *r, const uint8_t *wire, size_t len)
{
	uint8_t padded[STS_FRAME_MAX + STS_PAD_BLOCK];
	size_t plen;
	size_t ilen;
	int ret;

	if (len < 2 + STS_NONCE_LEN + STS_PAD_BLOCK + STS_TAG_LEN ||
	    len > STS_WIRE_MAX)
		goto reject;
	plen = len - 2 - STS_NONCE_LEN - STS_TAG_LEN;
	if (plen % STS_PAD_BLOCK != 0 || wire[0] != STS_PROTO_MAGIC ||
	    wire[1] != STS_PROTO_VERSION)
		goto reject;

	/* only room members know the outer key */
	if (sts_aead_open(r->keys.outer_key, &wire[2], wire, 2,
			  &wire[2 + STS_NONCE_LEN], plen + STS_TAG_LEN,
			  padded) != 0)
		goto reject;

	ilen = (size_t)padded[0] << 8 | padded[1];
	if (ilen < STS_HDR_LEN || ilen > STS_FRAME_MAX || 2 + ilen > plen) {
		sts_memzero(padded, plen);
		goto reject;
	}

	ret = dispatch(r, &padded[2], ilen);
	sts_memzero(padded, plen);
	if (r->need_rotate) {
		r->need_rotate = 0;
		rotate_sender_key(r);
	}
	if (ret == WAIT)
		ret = DONE;
	if (ret == REJECT)
		r->stats.rejected++;
	return ret;
reject:
	r->stats.rejected++;
	return REJECT;
}

/* --- public API ---------------------------------------------------------- */

int sts_room_init(struct sts_room *r, const struct sts_identity *self,
		  const char *room, const char *password, const char *nick,
		  unsigned int rekey_s, const struct sts_room_ops *ops,
		  void *ud)
{
	memset(r, 0, sizeof(*r));

	if (!sts_room_valid(room) || !sts_nick_valid(nick, strlen(nick)) ||
	    ops == NULL || ops->send == NULL)
		return -1;

	sts_strlcpy(r->name, room, sizeof(r->name));
	sts_strlcpy(r->nick, nick, sizeof(r->nick));
	r->has_password = password != NULL && password[0] != '\0';
	r->self = self;
	r->ops = *ops;
	r->ud = ud;
	r->start_ms = now_ms(r);
	r->last_rekey_ms = r->start_ms;
	r->rekey_interval_ms = (uint64_t)rekey_s * 1000;

	if (sts_room_keys_derive(room, password, &r->keys) != 0)
		goto fail;
	if (sts_random(r->sid_nonce, sizeof(r->sid_nonce)) != 0)
		goto fail;
	derive_sid(self->pub, r->sid_nonce, r->sid);

	if (sts_ephemeral_generate(&r->eph) != 0)
		goto fail;
	r->eph_gen = 1;

	/* random first epoch keeps the epochs of sessions apart */
	if (sts_random(&r->sk_epoch, sizeof(r->sk_epoch)) != 0 ||
	    sts_random(r->sk, sizeof(r->sk)) != 0)
		goto fail;
	r->sk_epoch = (r->sk_epoch & 0x3FFFFFFF) | 1; /* 0: no key */
	return 0;
fail:
	sts_room_free(r);
	return -1;
}

void sts_room_free(struct sts_room *r)
{
	size_t i;

	for (i = 0; i < STS_MEMBER_SLOTS; i++)
		slot_free(r, i);
	for (i = 0; i < STS_HISTORY; i++)
		stored_free(&r->history[i]);
	sts_ephemeral_free(&r->eph);
	if (r->has_prev_eph)
		sts_ephemeral_free(&r->prev_eph);
	sts_memzero(r, sizeof(*r));
}

static int build_bye(struct sts_room *r, enum sts_frame_type type, uint8_t *out,
		     size_t cap, size_t *len)
{
	uint8_t buf[STS_HDR_LEN + 4 + STS_SIG_LEN];
	uint8_t wire[STS_WIRE_MAX];
	struct sts_wbuf w;

	sts_wbuf_init(&w, buf, sizeof(buf));
	write_header(&w, r, type);
	sts_w_u32(&w, r->conn);
	if (sign_append(r, &w, type == STS_T_AWAY ? LABEL_AWAY : LABEL_LEAVE) !=
		    0 ||
	    wrap(r, buf, w.len, wire, len) != 0 || *len > cap)
		return -1;
	memcpy(out, wire, *len);
	return 0;
}

int sts_room_prepare_connect(struct sts_room *r, uint8_t *will, size_t cap,
			     size_t *len)
{
	r->conn++;
	return build_bye(r, STS_T_AWAY, will, cap, len);
}

void sts_room_connected(struct sts_room *r)
{
	uint64_t now = now_ms(r);
	size_t i;

	r->connected = 1;

	/* after a reconnect, whoever doesn't answer is gone */
	if (r->ever_connected) {
		for (i = 0; i < STS_MEMBER_SLOTS; i++) {
			struct sts_member *m = r->members[i];

			if (m != NULL && confirmed(m)) {
				m->stale = 1;
				m->stale_until_ms = now + STS_STALE_TIMEOUT_MS;
			}
		}
	}
	if (!r->ever_connected)
		r->discovery_until_ms = now + STS_DISCOVERY_MS;
	r->ever_connected = 1;
	r->last_hello_ms = 0;
	send_hello(r, STS_HELLO_WANT_REPLY);
}

void sts_room_disconnected(struct sts_room *r)
{
	r->connected = 0;
}

int sts_room_send(struct sts_room *r, enum sts_msg_kind kind, const char *text,
		  size_t len)
{
	uint8_t buf[STS_FRAME_MAX];
	uint8_t pt[9 + STS_TEXT_MAX];
	uint8_t nonce[STS_NONCE_LEN];
	struct sts_wbuf w;
	struct sts_wbuf pw;
	size_t aad_len;
	uint8_t *ct;
	int ret;

	if (len == 0 || len > STS_TEXT_MAX)
		return -1;

	if (r->sk_seq >= STS_SENDER_KEY_MAX_MSG)
		rotate_sender_key(r);
	r->sk_seq++;

	sts_wbuf_init(&pw, pt, sizeof(pt));
	sts_w_u64(&pw, wall_ms(r));
	sts_w_u8(&pw, (uint8_t)kind);
	sts_w_bytes(&pw, text, len);

	sts_wbuf_init(&w, buf, sizeof(buf));
	write_header(&w, r, STS_T_MSG);
	sts_w_u32(&w, r->sk_epoch);
	sts_w_u64(&w, r->sk_seq);
	aad_len = w.len;
	ct = sts_w_reserve(&w, pw.len + STS_TAG_LEN);
	if (ct == NULL || pw.err)
		return -1;

	nonce_make(nonce, r->sk_epoch, r->sk_seq);
	ret = sts_aead_seal(r->sk, nonce, buf, aad_len, pt, pw.len, ct);
	sts_memzero(pt, sizeof(pt));
	if (ret != 0 || sign_append(r, &w, LABEL_MSG) != 0)
		return -1;

	stored_set(&r->history[r->history_next], r->sk_epoch, r->sk_seq, buf,
		   w.len);
	r->history_next = (r->history_next + 1) % STS_HISTORY;
	return send_inner(r, buf, w.len);
}

int sts_room_send_file(struct sts_room *r, const uint8_t sid[STS_SID_LEN],
		       const uint8_t *data, size_t len)
{
	struct sts_member *m = find_sid(r, sid);

	if (m == NULL || !confirmed(m) || len == 0 || len > STS_FILE_FRAME_MAX)
		return -1;
	return send_pairwise(r, m, STS_T_FILE, data, len);
}

const struct sts_member *sts_room_member(const struct sts_room *r,
					 const uint8_t sid[STS_SID_LEN])
{
	size_t i;

	for (i = 0; i < STS_MEMBER_SLOTS; i++) {
		const struct sts_member *m = r->members[i];

		if (m != NULL && confirmed(m) &&
		    memcmp(m->sid, sid, STS_SID_LEN) == 0)
			return m;
	}
	return NULL;
}

int sts_room_send_private(struct sts_room *r, const uint8_t fpr[STS_HASH_LEN],
			  enum sts_msg_kind kind, const char *text, size_t len)
{
	uint8_t pt[9 + STS_TEXT_MAX];
	struct sts_wbuf w;
	int sent = 0;
	size_t i;

	if (len == 0 || len > STS_TEXT_MAX)
		return -1;

	sts_wbuf_init(&w, pt, sizeof(pt));
	sts_w_u64(&w, wall_ms(r));
	sts_w_u8(&w, (uint8_t)kind);
	sts_w_bytes(&w, text, len);

	for (i = 0; i < STS_MEMBER_SLOTS; i++) {
		struct sts_member *m = r->members[i];

		if (m != NULL && confirmed(m) &&
		    memcmp(m->fpr, fpr, STS_HASH_LEN) == 0 &&
		    send_pairwise(r, m, STS_T_DM, pt, w.len) == 0)
			sent++;
	}
	sts_memzero(pt, sizeof(pt));
	return sent;
}

int sts_room_set_nick(struct sts_room *r, const char *nick)
{
	if (!sts_nick_valid(nick, strlen(nick)))
		return -1;
	sts_strlcpy(r->nick, nick, sizeof(r->nick));
	return send_hello(r, 0);
}

int sts_room_leave(struct sts_room *r)
{
	uint8_t wire[STS_WIRE_MAX];
	size_t len;

	if (build_bye(r, STS_T_LEAVE, wire, sizeof(wire), &len) != 0 ||
	    r->ops.send(r->ud, wire, len) != 0)
		return -1;
	r->stats.sent++;
	return 0;
}

int sts_room_rekey(struct sts_room *r)
{
	struct sts_ephemeral fresh;
	size_t i;

	if (sts_ephemeral_generate(&fresh) != 0)
		return -1;

	if (r->has_prev_eph)
		sts_ephemeral_free(&r->prev_eph);
	r->prev_eph = r->eph;
	r->prev_eph_gen = r->eph_gen;
	r->has_prev_eph = 1;
	r->prev_eph_until_ms = now_ms(r) + STS_OLD_KEY_MS;

	r->eph = fresh;
	r->eph_gen++;
	r->last_rekey_ms = now_ms(r);

	for (i = 0; i < STS_MEMBER_SLOTS; i++)
		if (r->members[i] != NULL)
			pw_keys_prune(r, r->members[i]);

	/* announce the new key first, then send sender keys under it */
	send_hello(r, 0);
	rotate_sender_key(r);
	return 0;
}

void sts_room_tick(struct sts_room *r)
{
	uint64_t now = now_ms(r);
	unsigned int dropped;
	size_t i;
	size_t j;

	/* a renewal that failed for want of random numbers */
	if (r->need_rotate) {
		r->need_rotate = 0;
		rotate_sender_key(r);
	}

	if (r->has_prev_eph && now >= r->prev_eph_until_ms) {
		sts_ephemeral_free(&r->prev_eph);
		r->has_prev_eph = 0;
		for (i = 0; i < STS_MEMBER_SLOTS; i++)
			if (r->members[i] != NULL)
				pw_keys_prune(r, r->members[i]);
	}

	if (r->connected && r->reply_due_ms != 0 && now >= r->reply_due_ms)
		send_reply(r);

	if (r->connected && r->rekey_interval_ms != 0 &&
	    now - r->last_rekey_ms >= r->rekey_interval_ms)
		sts_room_rekey(r);

	for (i = 0; i < STS_MEMBER_SLOTS; i++) {
		struct sts_member *m = r->members[i];

		if (m == NULL)
			continue;

		if (m->state == STS_MEMBER_GONE)
			continue;

		if (m->state == STS_MEMBER_PENDING) {
			if (now - m->created_ms >= STS_PENDING_TIMEOUT_MS) {
				slot_free(r, i);
				continue;
			}
			if (r->connected && elapsed(now, m->last_keydist_ms,
						    STS_PENDING_RETRY_MS))
				send_keydist(r, m);
			continue;
		}

		if (m->state == STS_MEMBER_AWAY &&
		    now - m->away_since_ms >= STS_AWAY_GRACE_MS) {
			member_gone(r, m, STS_LEAVE_TIMEOUT);
			continue;
		}
		if (m->stale && r->connected && now >= m->stale_until_ms) {
			member_gone(r, m, STS_LEAVE_LOST);
			continue;
		}

		if (m->has_prev_eph && now >= m->prev_eph_until_ms) {
			m->has_prev_eph = 0;
			pw_keys_prune(r, m);
		}
		if (m->have_prev_sk && now >= m->prev_sk_until_ms) {
			sts_memzero(m->prev_sk, sizeof(m->prev_sk));
			m->have_prev_sk = 0;
		}

		if (r->connected && m->n_missing > 0)
			send_resends(r, m, now);

		dropped = 0;
		j = 0;
		while (j < m->n_stash) {
			if (now - m->stash[j].since_ms >= STASH_MS) {
				stash_remove(m, j);
				dropped++;
			} else {
				j++;
			}
		}
		if (dropped > 0)
			notice(r, m,
			       "messages could not be decrypted, their key never arrived");
	}
}

size_t sts_room_member_count(const struct sts_room *r)
{
	return count_state(r, STS_MEMBER_ACTIVE) +
	       count_state(r, STS_MEMBER_AWAY);
}

/* someone with another identity uses the same nick? */
static int nick_shared(const struct sts_room *r, const struct sts_member *m)
{
	size_t i;

	if (sts_strcasecmp(r->nick, m->nick) == 0 &&
	    memcmp(r->self->fpr, m->fpr, STS_HASH_LEN) != 0)
		return 1;

	for (i = 0; i < STS_MEMBER_SLOTS; i++) {
		const struct sts_member *o = r->members[i];

		if (o != NULL && o != m && confirmed(o) &&
		    memcmp(o->fpr, m->fpr, STS_HASH_LEN) != 0 &&
		    sts_strcasecmp(o->nick, m->nick) == 0)
			return 1;
	}
	return 0;
}

void sts_room_display_name(const struct sts_room *r, const struct sts_member *m,
			   char *out, size_t cap)
{
	if (nick_shared(r, m))
		snprintf(out, cap, "%s#%02x%02x", m->nick, m->fpr[0],
			 m->fpr[1]);
	else
		snprintf(out, cap, "%s", m->nick);
}

const struct sts_member *sts_room_find(const struct sts_room *r,
				       const char *name, int *ambiguous)
{
	const struct sts_member *found = NULL;
	char nick[STS_NICK_MAX + 1];
	char want[5] = "";
	char fpr[5];
	const char *hash;
	size_t nlen;
	size_t i;

	*ambiguous = 0;

	hash = strchr(name, '#');
	nlen = hash ? (size_t)(hash - name) : strlen(name);
	if (nlen == 0 || nlen > STS_NICK_MAX)
		return NULL;
	memcpy(nick, name, nlen);
	nick[nlen] = '\0';

	if (hash != NULL) {
		if (strlen(hash + 1) != 4)
			return NULL;
		for (i = 0; i < 4; i++)
			want[i] = (char)(hash[1 + i] | 0x20);
		want[4] = '\0';
	}

	for (i = 0; i < STS_MEMBER_SLOTS; i++) {
		const struct sts_member *m = r->members[i];

		if (m == NULL || !confirmed(m) ||
		    sts_strcasecmp(m->nick, nick) != 0)
			continue;

		if (hash != NULL) {
			snprintf(fpr, sizeof(fpr), "%02x%02x", m->fpr[0],
				 m->fpr[1]);
			if (strcmp(fpr, want) != 0)
				continue;
		}

		/* several sessions of one identity are one person */
		if (found != NULL &&
		    memcmp(found->fpr, m->fpr, STS_HASH_LEN) != 0) {
			*ambiguous = 1;
			return NULL;
		}
		if (found == NULL || m->state == STS_MEMBER_ACTIVE)
			found = m;
	}
	return found;
}
