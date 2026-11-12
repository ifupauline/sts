/* SPDX-License-Identifier: Apache-2.0 */
/*
 * STS v3 group protocol engine, one instance per room.
 *
 * Transport agnostic: frames to publish leave through ops.send(), frames
 * received on the room topic come in through sts_room_handle(), timers run
 * from sts_room_tick(). See doc/PROTOCOL.md for the format and rationale.
 */
#ifndef STS_ROOM_H
#define STS_ROOM_H

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "util.h"

#define STS_PROTO_MAGIC 0x53 /* 'S' */
#define STS_PROTO_VERSION 0x03

#define STS_SID_LEN 8 /* session id */
#define STS_SID_NONCE_LEN 16
#define STS_CHAL_LEN 16
#define STS_OLD_CHALS 4
#define STS_TOPIC_ID_LEN 16
#define STS_TOPIC_HEX_LEN (2 * STS_TOPIC_ID_LEN)

#define STS_TEXT_MAX 1024 /* message bytes */
#define STS_FRAME_MAX 2048 /* inner frame */
#define STS_PAD_BLOCK 256 /* inner frames are padded to this */
#define STS_WIRE_MAX \
	(2 + STS_NONCE_LEN + STS_FRAME_MAX + STS_PAD_BLOCK + STS_TAG_LEN)
#define STS_HDR_LEN (2 + STS_SID_LEN)
/* pairwise frame header, nonce and tag */
#define STS_PW_OVERHEAD                                         \
	(STS_HDR_LEN + STS_SID_LEN + 4 + 4 + 8 + STS_CHAL_LEN + \
	 STS_NONCE_LEN + STS_TAG_LEN)
#define STS_FILE_FRAME_MAX (STS_FRAME_MAX - STS_PW_OVERHEAD)

#define STS_MAX_MEMBERS 256 /* other sessions in a room */
#define STS_MAX_PENDING 32 /* sessions not confirmed yet */
#define STS_MAX_GONE 64 /* ended sessions remembered */
#define STS_MEMBER_SLOTS (STS_MAX_MEMBERS + STS_MAX_PENDING + STS_MAX_GONE)

#define STS_HISTORY 256 /* own room messages kept for resends */
#define STS_PW_HISTORY 8 /* pairwise frames kept per member */
#define STS_MISSING_MAX 32 /* missing frames tracked per member */
#define STS_STASH_MAX 16 /* frames waiting for a key or a confirmation */

#define STS_PBKDF2_ITERATIONS 100000

/* timers (ms) */
#define STS_PENDING_RETRY_MS 2000
#define STS_PENDING_TIMEOUT_MS 30000
#define STS_AWAY_GRACE_MS 120000
#define STS_STALE_TIMEOUT_MS 15000
#define STS_OLD_KEY_MS 60000
#define STS_RESEND_DELAY_MS 500
#define STS_RESEND_RETRY_MS 2000
#define STS_RESEND_TRIES 3
#define STS_REPLY_INTERVAL_MS 1000
#define STS_ANNOUNCE_MS 5000
#define STS_KEYREQ_MS 3000
#define STS_SENDER_KEY_MAX_MSG 1000
/* after joining, who shows up was already there: see handle_hello() */
#define STS_DISCOVERY_MS 10000

enum sts_frame_type {
	STS_T_HELLO = 1, /* signed: session announce */
	STS_T_KEYDIST = 2, /* pairwise: challenge + sender key */
	STS_T_KEYREQ = 3, /* pairwise: please resend your sender key */
	STS_T_DM = 4, /* pairwise: private message */
	STS_T_MSG = 5, /* sender key + signed: room message */
	STS_T_RESEND = 6, /* pairwise: please resend these frames */
	STS_T_AWAY = 7, /* signed: connection lost (MQTT will) */
	STS_T_LEAVE = 8, /* signed: session ended */
	STS_T_FILE = 9, /* pairwise: file transfer, see transfer.h */
};

#define STS_HELLO_WANT_REPLY 0x01

enum sts_msg_kind {
	STS_KIND_TEXT = 0,
	STS_KIND_ACTION = 1, /* /me */
};

/* sliding window replay protection over 64-bit sequence numbers */
#define STS_REPLAY_WINDOW 64
struct sts_replay {
	uint64_t top; /* highest sequence number accepted */
	uint64_t bitmap; /* bit i set: top - i was accepted */
	int init;
};

/* 0 if @seq is fresh, -1 if replayed or too old */
int sts_replay_check(const struct sts_replay *r, uint64_t seq);
void sts_replay_commit(struct sts_replay *r, uint64_t seq);

/* keys derived from the room name and password */
struct sts_room_keys {
	uint8_t topic_id[STS_TOPIC_ID_LEN];
	uint8_t outer_key[STS_KEY_LEN];
	char topic_hex[STS_TOPIC_HEX_LEN + 1];
};

int sts_room_keys_derive(const char *room, const char *password,
			 struct sts_room_keys *keys);

enum sts_member_state {
	STS_MEMBER_PENDING = 1, /* announced, liveness not proven yet */
	STS_MEMBER_ACTIVE,
	STS_MEMBER_AWAY, /* connection lost, may come back */
	STS_MEMBER_GONE, /* session ended, kept to reject replays */
};

/* pairwise keys for one pair of ephemeral key generations */
struct sts_pw_keys {
	int valid;
	uint32_t own_gen;
	uint32_t peer_gen;
	uint8_t send[STS_KEY_LEN];
	uint8_t recv[STS_KEY_LEN];
};

struct sts_stored {
	uint32_t epoch; /* MSG only */
	uint64_t seq;
	size_t len;
	uint8_t *data; /* inner frame */
};

struct sts_missing {
	uint8_t channel; /* 0 room messages, 1 pairwise */
	uint32_t epoch;
	uint64_t seq;
	uint64_t due_ms;
	unsigned int tries;
};

/* room message waiting for its sender key or the sender's confirmation */
struct sts_stash {
	uint64_t since_ms;
	size_t len;
	uint8_t *data; /* inner frame */
};

struct sts_member {
	enum sts_member_state state;
	uint8_t sid[STS_SID_LEN];
	uint8_t id_pub[STS_PUBKEY_LEN];
	uint8_t fpr[STS_HASH_LEN];
	char nick[STS_NICK_MAX + 1];

	uint64_t counter; /* last HELLO counter seen */
	uint32_t conn; /* connection number of the session */
	uint64_t created_ms;

	uint32_t eph_gen;
	uint8_t eph_pub[STS_PUBKEY_LEN];
	int has_prev_eph;
	uint32_t prev_eph_gen;
	uint8_t prev_eph_pub[STS_PUBKEY_LEN];
	uint64_t prev_eph_until_ms;

	struct sts_pw_keys keys[4];
	uint64_t pw_send_seq;
	struct sts_replay pw_recv;

	/*
	 * Challenges, see doc/PROTOCOL.md: every pairwise frame from the
	 * member must echo my_chal, ours echo their_chal.
	 */
	uint8_t my_chal[STS_CHAL_LEN];
	uint8_t their_chal[STS_CHAL_LEN];
	/* their earlier challenges: a replayed old handshake is ignored */
	uint8_t old_chal[STS_OLD_CHALS][STS_CHAL_LEN];
	unsigned int old_chal_next;
	int need_echo;
	uint64_t last_keydist_ms;

	/* the member's sender key */
	int have_sk;
	uint32_t sk_epoch;
	uint8_t sk[STS_KEY_LEN];
	struct sts_replay sk_recv;
	uint64_t sk_base; /* sent before we got the key */
	int have_prev_sk;
	uint32_t prev_sk_epoch;
	uint8_t prev_sk[STS_KEY_LEN];
	struct sts_replay prev_sk_recv;
	uint64_t prev_sk_until_ms;

	struct sts_missing missing[STS_MISSING_MAX];
	size_t n_missing;
	unsigned int lost; /* frames given up on, reported once */

	struct sts_stash stash[STS_STASH_MAX];
	size_t n_stash;

	struct sts_stored pw_hist[STS_PW_HISTORY];
	size_t pw_hist_next;

	uint32_t away_conn;
	uint64_t away_since_ms;
	int stale; /* must answer our HELLO after a reconnect */
	uint64_t stale_until_ms;

	uint64_t last_keyreq_ms;
	uint64_t last_resend_ms;
	uint64_t last_unknown_ms;
};

enum sts_event_type {
	STS_EV_JOIN, /* member confirmed */
	STS_EV_LEAVE, /* member left, see sts_leave_reason */
	STS_EV_AWAY, /* member lost its connection */
	STS_EV_BACK, /* member reconnected */
	STS_EV_NICK, /* member changed nick, old_nick is set */
	STS_EV_MESSAGE, /* kind, is_private, late, ts_ms, text */
	STS_EV_NOTICE, /* notice, member may be set */
	STS_EV_FILE, /* file transfer frame: member, text */
};

enum sts_leave_reason {
	STS_LEAVE_QUIT, /* signed LEAVE */
	STS_LEAVE_TIMEOUT, /* away for too long */
	STS_LEAVE_LOST, /* didn't answer after our reconnect */
};

struct sts_event {
	enum sts_event_type type;
	const struct sts_member *member;
	const char *old_nick;
	enum sts_leave_reason reason;
	int other_devices; /* JOIN: other sessions of the identity */
	enum sts_msg_kind kind;
	int is_private;
	int late; /* delivered out of order (resent) */
	uint64_t ts_ms; /* sender's clock, for display only */
	const uint8_t *text; /* untrusted, NOT NUL terminated */
	size_t text_len;
	const char *notice;
};

struct sts_room_ops {
	/* publish @frame on the room topic, return 0 on success */
	int (*send)(void *ud, const uint8_t *frame, size_t len);
	/* protocol events for the user interface */
	void (*event)(void *ud, const struct sts_event *ev);
	/* optional clocks for tests, NULL uses the system clocks */
	uint64_t (*monotonic_ms)(void *ud);
	uint64_t (*wallclock_ms)(void *ud);
};

struct sts_room_stats {
	unsigned long sent;
	unsigned long received;
	unsigned long rejected; /* bad signature or tag, replay, malformed */
	unsigned long resent;
	unsigned long recovered;
};

struct sts_room {
	char name[STS_ROOM_MAX + 1];
	int has_password;
	struct sts_room_keys keys;
	const struct sts_identity *self;

	/* own session */
	uint8_t sid[STS_SID_LEN];
	uint8_t sid_nonce[STS_SID_NONCE_LEN];
	uint64_t counter;
	uint32_t conn;
	int connected;
	int ever_connected;
	uint64_t start_ms;

	char nick[STS_NICK_MAX + 1];

	struct sts_ephemeral eph;
	uint32_t eph_gen;
	int has_prev_eph;
	struct sts_ephemeral prev_eph;
	uint32_t prev_eph_gen;
	uint64_t prev_eph_until_ms;
	uint64_t rekey_interval_ms;
	uint64_t last_rekey_ms;

	uint32_t sk_epoch;
	uint8_t sk[STS_KEY_LEN];
	uint64_t sk_seq;
	uint64_t discovery_until_ms; /* end of the first seconds in the room */

	struct sts_stored history[STS_HISTORY];
	size_t history_next;

	struct sts_member *members[STS_MEMBER_SLOTS];

	int need_rotate; /* rotate the sender key after this frame */
	uint64_t last_hello_ms;
	uint64_t last_reply_ms;
	uint64_t reply_due_ms;
	uint64_t last_announce_ms;
	int full_reported;

	struct sts_room_ops ops;
	void *ud;
	struct sts_room_stats stats;
};

/*
 * @brief       create a session for @room (fresh session id, ephemeral key
 *              and sender key). Nothing is sent before sts_room_connected().
 * @password    room password, NULL or "" for none.
 * @rekey_s     seconds between ephemeral key renewals, 0 to disable.
 */
int sts_room_init(struct sts_room *r, const struct sts_identity *self,
		  const char *room, const char *password, const char *nick,
		  unsigned int rekey_s, const struct sts_room_ops *ops,
		  void *ud);

void sts_room_free(struct sts_room *r);

/*
 * @brief       start the next connection: build the signed AWAY frame the
 *              broker publishes as our last will if we vanish.
 */
int sts_room_prepare_connect(struct sts_room *r, uint8_t *will, size_t cap,
			     size_t *len);

/* @brief the transport is up: announce the session (again) */
void sts_room_connected(struct sts_room *r);

/* @brief the transport went down, the session is kept */
void sts_room_disconnected(struct sts_room *r);

/*
 * @brief       process one frame received on the room topic.
 * @return      0 if processed, 1 if ignored (own echo, not for us, old
 *              duplicate), -1 if rejected.
 */
int sts_room_handle(struct sts_room *r, const uint8_t *frame, size_t len);

/* @brief run timers, call at least every 250 ms */
void sts_room_tick(struct sts_room *r);

int sts_room_send(struct sts_room *r, enum sts_msg_kind kind, const char *text,
		  size_t len);

/*
 * @brief       private message to every session of the identity @fpr.
 * @return      number of sessions it was sent to, -1 on failure.
 */
int sts_room_send_private(struct sts_room *r, const uint8_t fpr[STS_HASH_LEN],
			  enum sts_msg_kind kind, const char *text, size_t len);

/*
 * @brief       file transfer frame (at most STS_FILE_FRAME_MAX bytes) to
 *              the session @sid, encrypted with the pairwise keys.
 * @return      0, or -1 if the session isn't confirmed or on failure.
 */
int sts_room_send_file(struct sts_room *r, const uint8_t sid[STS_SID_LEN],
		       const uint8_t *data, size_t len);

/* @return the confirmed member with session id @sid, or NULL */
const struct sts_member *sts_room_member(const struct sts_room *r,
					 const uint8_t sid[STS_SID_LEN]);

int sts_room_set_nick(struct sts_room *r, const char *nick);

/* @brief publish LEAVE: the session ends */
int sts_room_leave(struct sts_room *r);

/* @brief new ephemeral key and sender key now */
int sts_room_rekey(struct sts_room *r);

/* @brief number of confirmed sessions (active or away) */
size_t sts_room_member_count(const struct sts_room *r);

/*
 * @brief       find a confirmed member by nick, "nick#ab12" (fingerprint
 *              prefix) to choose between people sharing a nick.
 * @ambiguous   set to 1 if different identities match.
 */
const struct sts_member *sts_room_find(const struct sts_room *r,
				       const char *name, int *ambiguous);

/*
 * @brief       name to show for @m: "nick", or "nick#ab12" when someone
 *              else in the room uses the same nick.
 */
void sts_room_display_name(const struct sts_room *r, const struct sts_member *m,
			   char *out, size_t cap);

#endif /* STS_ROOM_H */
