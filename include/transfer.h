/* SPDX-License-Identifier: Apache-2.0 */
/*
 * File transfers between two sessions of a room, over the pairwise FILE
 * frames of the protocol (end-to-end encrypted, see doc/PROTOCOL.md).
 *
 * The sender offers a file (name, size, SHA-256), the receiver accepts or
 * refuses. Data then goes in chunks with a window: the receiver
 * acknowledges what it wrote, the sender goes back to the last
 * acknowledged offset when nothing progresses. The receiver writes to a
 * temporary file, checks the SHA-256 at the end and only then gives the
 * file its name, never replacing an existing file.
 */
#ifndef STS_TRANSFER_H
#define STS_TRANSFER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "crypto.h"
#include "room.h"

#define STS_XFER_SIZE_DEFAULT (16ULL * 1024 * 1024)
#define STS_XFER_SIZE_LIMIT (64ULL * 1024 * 1024 * 1024)
#define STS_XFER_NAME_MAX 200
#define STS_XFER_CHUNK 1920
#define STS_XFER_WINDOW 32 /* chunks sent ahead of the last ack */
#define STS_XFER_ACK_EVERY 8 /* chunks between acks */
#define STS_XFER_SLOTS 16
#define STS_XFER_PER_PEER 4 /* incoming at once from one session */
#define STS_XFER_OFFER_RESEND_MS 10000
#define STS_XFER_ANSWER_MS 300000 /* to accept or refuse */
#define STS_XFER_RETRY_MS 3000 /* go back if no ack for so long */
#define STS_XFER_IDLE_MS 180000 /* give up without any progress */
#define STS_XFER_LINGER_MS 60000 /* finished receiver answers resends */

enum sts_xfer_state {
	STS_XFER_FREE = 0,
	STS_XFER_OFFERED, /* waiting for the receiver's answer */
	STS_XFER_ACTIVE, /* data flowing */
	STS_XFER_FINISHED, /* receiver: done, kept to answer resends */
};

enum sts_xfer_event_type {
	STS_XFER_EV_OFFER, /* incoming offer: /accept or /refuse */
	STS_XFER_EV_ACCEPTED, /* the receiver accepted ours */
	STS_XFER_EV_REFUSED, /* the receiver refused ours */
	STS_XFER_EV_PROGRESS, /* percent */
	STS_XFER_EV_DONE, /* complete (path set when receiving) */
	STS_XFER_EV_FAILED, /* detail says why */
	STS_XFER_EV_TOO_BIG, /* an offer above max_size, refused */
};

struct sts_xfer {
	enum sts_xfer_state state;
	int outgoing;
	uint64_t id;
	unsigned int num; /* shown to the user */
	uint8_t sid[STS_SID_LEN]; /* the other session */
	char nick[STS_NICK_MAX + 1];
	char name[STS_XFER_NAME_MAX + 1];
	uint64_t size;
	uint8_t hash[STS_HASH_LEN];
	uint64_t done; /* bytes acknowledged (sender) or written */
	uint64_t next; /* sender: next offset to send */
	int percent;
	uint64_t created_ms;
	uint64_t progress_ms; /* last progress */
	uint64_t sent_ms; /* last offer or ack sent */
	uint64_t started_ms;

	FILE *src; /* sender: the file, read as it goes */

	FILE *fp; /* receiver */
	struct sts_sha256 sha;
	char part[STS_PATH_MAX];
	char path[STS_PATH_MAX];
};

struct sts_xfer_event {
	enum sts_xfer_event_type type;
	const struct sts_xfer *xfer;
	int percent;
	const char *detail;
};

struct sts_xfer_ops {
	void (*event)(void *ud, const struct sts_xfer_event *ev);
	/* 0 when the transport has enough queued already */
	int (*can_send)(void *ud);
	uint64_t (*monotonic_ms)(void *ud); /* NULL: the system clock */
};

struct sts_xfers {
	struct sts_room *room;
	struct sts_xfer x[STS_XFER_SLOTS];
	unsigned int *counter; /* numbers shared by every room */
	uint64_t max_size; /* largest file sent or accepted */
	struct sts_xfer_ops ops;
	void *ud;
};

void sts_xfers_init(struct sts_xfers *xs, struct sts_room *room,
		    unsigned int *counter, const struct sts_xfer_ops *ops,
		    void *ud);
void sts_xfers_free(struct sts_xfers *xs);

/*
 * @brief       offer the file @path to the session @sid.
 * @return      the transfer's number, or -1 with a message in @err.
 */
int sts_xfer_send(struct sts_xfers *xs, const uint8_t sid[STS_SID_LEN],
		  const char *path, char *err, size_t errlen);

/* @brief accept offer @num, saving into the directory @dir */
int sts_xfer_accept(struct sts_xfers *xs, unsigned int num, const char *dir,
		    char *err, size_t errlen);
int sts_xfer_refuse(struct sts_xfers *xs, unsigned int num);
int sts_xfer_cancel(struct sts_xfers *xs, unsigned int num);

struct sts_xfer *sts_xfer_find(struct sts_xfers *xs, unsigned int num);

/* @brief a FILE frame from @m (STS_EV_FILE) */
void sts_xfers_handle(struct sts_xfers *xs, const struct sts_member *m,
		      const uint8_t *data, size_t len);

/* @brief the session @sid left: its transfers fail */
void sts_xfers_gone(struct sts_xfers *xs, const uint8_t sid[STS_SID_LEN]);

/* @brief send data, timers; call often */
void sts_xfers_tick(struct sts_xfers *xs);

/* @brief "1.5 MB" */
void sts_xfer_size_str(uint64_t size, char *out, size_t cap);

#endif /* STS_TRANSFER_H */
