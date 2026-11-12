// SPDX-License-Identifier: Apache-2.0
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "platform.h"
#include "transfer.h"
#include "util.h"
#include "wire.h"

enum op {
	OP_OFFER = 1, /* id | size u64 | sha256 | name_len u8 | name */
	OP_ACCEPT = 2, /* id */
	OP_REFUSE = 3, /* id */
	OP_DATA = 4, /* id | offset u64 | bytes */
	OP_ACK = 5, /* id | bytes written so far u64 */
	OP_DONE = 6, /* id: received and checked */
	OP_CANCEL = 7, /* id | reason u8 */
};

enum reason {
	REASON_CANCELLED = 0,
	REASON_CORRUPT = 1, /* SHA-256 mismatch */
	REASON_ERROR = 2, /* could not write, gave up... */
	REASON_TOO_BIG = 3, /* larger than the receiver accepts */
};

#define FRAME_HDR (1 + 8)

static uint64_t now(const struct sts_xfers *xs)
{
	return xs->ops.monotonic_ms ? xs->ops.monotonic_ms(xs->ud) :
				      sts_monotonic_ms();
}

static void emit(struct sts_xfers *xs, struct sts_xfer *x,
		 enum sts_xfer_event_type type, const char *detail)
{
	struct sts_xfer_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = type;
	ev.xfer = x;
	ev.percent = x->percent;
	ev.detail = detail;
	if (xs->ops.event != NULL)
		xs->ops.event(xs->ud, &ev);
}

void sts_xfer_size_str(uint64_t size, char *out, size_t cap)
{
	if (size < 1024)
		snprintf(out, cap, "%u bytes", (unsigned int)size);
	else if (size < 1024 * 1024)
		snprintf(out, cap, "%.1f KB", (double)size / 1024);
	else
		snprintf(out, cap, "%.1f MB", (double)size / (1024 * 1024));
}

void sts_xfers_init(struct sts_xfers *xs, struct sts_room *room,
		    unsigned int *counter, const struct sts_xfer_ops *ops,
		    void *ud)
{
	memset(xs, 0, sizeof(*xs));
	xs->room = room;
	xs->counter = counter;
	xs->max_size = STS_XFER_SIZE_DEFAULT;
	xs->ops = *ops;
	xs->ud = ud;
}

static void slot_free(struct sts_xfer *x)
{
	if (x->src != NULL)
		fclose(x->src);
	if (x->fp != NULL) {
		fclose(x->fp);
		remove(x->part);
	}
	sts_memzero(x, sizeof(*x));
}

void sts_xfers_free(struct sts_xfers *xs)
{
	size_t i;

	for (i = 0; i < STS_XFER_SLOTS; i++)
		if (xs->x[i].state != STS_XFER_FREE)
			slot_free(&xs->x[i]);
}

static struct sts_xfer *slot_new(struct sts_xfers *xs)
{
	size_t i;

	for (i = 0; i < STS_XFER_SLOTS; i++)
		if (xs->x[i].state == STS_XFER_FREE)
			return &xs->x[i];
	/* a finished one only lingers to answer resends */
	for (i = 0; i < STS_XFER_SLOTS; i++)
		if (xs->x[i].state == STS_XFER_FINISHED) {
			slot_free(&xs->x[i]);
			return &xs->x[i];
		}
	return NULL;
}

static struct sts_xfer *find_id(struct sts_xfers *xs, const uint8_t *sid,
				uint64_t id, int outgoing)
{
	size_t i;

	for (i = 0; i < STS_XFER_SLOTS; i++) {
		struct sts_xfer *x = &xs->x[i];

		if (x->state != STS_XFER_FREE && x->id == id &&
		    x->outgoing == outgoing &&
		    memcmp(x->sid, sid, STS_SID_LEN) == 0)
			return x;
	}
	return NULL;
}

struct sts_xfer *sts_xfer_find(struct sts_xfers *xs, unsigned int num)
{
	size_t i;

	for (i = 0; i < STS_XFER_SLOTS; i++)
		if (xs->x[i].state != STS_XFER_FREE &&
		    xs->x[i].state != STS_XFER_FINISHED && xs->x[i].num == num)
			return &xs->x[i];
	return NULL;
}

/* --- frames out ---------------------------------------------------------- */

static int send_frame(struct sts_xfers *xs, const struct sts_xfer *x,
		      const uint8_t *buf, size_t len)
{
	return sts_room_send_file(xs->room, x->sid, buf, len);
}

static int send_simple(struct sts_xfers *xs, const struct sts_xfer *x,
		       enum op op)
{
	uint8_t buf[FRAME_HDR];
	struct sts_wbuf w;

	sts_wbuf_init(&w, buf, sizeof(buf));
	sts_w_u8(&w, op);
	sts_w_u64(&w, x->id);
	return send_frame(xs, x, buf, w.len);
}

static void send_u64(struct sts_xfers *xs, const struct sts_xfer *x, enum op op,
		     uint64_t v)
{
	uint8_t buf[FRAME_HDR + 8];
	struct sts_wbuf w;

	sts_wbuf_init(&w, buf, sizeof(buf));
	sts_w_u8(&w, op);
	sts_w_u64(&w, x->id);
	sts_w_u64(&w, v);
	send_frame(xs, x, buf, w.len);
}

static void send_cancel(struct sts_xfers *xs, const struct sts_xfer *x,
			enum reason reason)
{
	uint8_t buf[FRAME_HDR + 1];
	struct sts_wbuf w;

	sts_wbuf_init(&w, buf, sizeof(buf));
	sts_w_u8(&w, OP_CANCEL);
	sts_w_u64(&w, x->id);
	sts_w_u8(&w, reason);
	send_frame(xs, x, buf, w.len);
}

static void send_offer(struct sts_xfers *xs, struct sts_xfer *x)
{
	uint8_t buf[FRAME_HDR + 8 + STS_HASH_LEN + 1 + STS_XFER_NAME_MAX];
	size_t nlen = strlen(x->name);
	struct sts_wbuf w;

	sts_wbuf_init(&w, buf, sizeof(buf));
	sts_w_u8(&w, OP_OFFER);
	sts_w_u64(&w, x->id);
	sts_w_u64(&w, x->size);
	sts_w_bytes(&w, x->hash, STS_HASH_LEN);
	sts_w_u8(&w, (uint8_t)nlen);
	sts_w_bytes(&w, x->name, nlen);
	if (!w.err)
		send_frame(xs, x, buf, w.len);
	x->sent_ms = now(xs);
}

static void fail(struct sts_xfers *xs, struct sts_xfer *x, enum reason tell,
		 int tell_peer, const char *why)
{
	if (tell_peer)
		send_cancel(xs, x, tell);
	emit(xs, x, STS_XFER_EV_FAILED, why);
	slot_free(x);
}

static void progress(struct sts_xfers *xs, struct sts_xfer *x)
{
	int percent = x->size ? (int)(x->done * 100 / x->size) : 100;

	x->progress_ms = now(xs);
	/* every 25 % */
	if (percent / 25 > x->percent / 25 && percent < 100) {
		x->percent = percent;
		emit(xs, x, STS_XFER_EV_PROGRESS, NULL);
	}
	x->percent = percent;
}

/* send the window: chunks from x->next, at most WINDOW ahead of x->done */
static void pump(struct sts_xfers *xs, struct sts_xfer *x)
{
	uint8_t buf[FRAME_HDR + 8 + STS_XFER_CHUNK];
	uint64_t limit = x->done + (uint64_t)STS_XFER_WINDOW * STS_XFER_CHUNK;
	struct sts_wbuf w;
	size_t n;

	while (x->next < x->size && x->next < limit) {
		if (xs->ops.can_send != NULL && !xs->ops.can_send(xs->ud))
			return;
		n = x->size - x->next < STS_XFER_CHUNK ?
			    (size_t)(x->size - x->next) :
			    STS_XFER_CHUNK;
		sts_wbuf_init(&w, buf, sizeof(buf));
		sts_w_u8(&w, OP_DATA);
		sts_w_u64(&w, x->id);
		sts_w_u64(&w, x->next);
		if (fseeko(x->src, (off_t)x->next, SEEK_SET) != 0 ||
		    fread(buf + w.len, 1, n, x->src) != n) {
			fail(xs, x, REASON_ERROR, 1,
			     "cannot read the file anymore");
			return;
		}
		w.len += n;
		if (send_frame(xs, x, buf, w.len) != 0)
			return;
		x->next += n;
	}
}

/* --- sending ------------------------------------------------------------- */

static void basename_of(const char *path, char *out, size_t cap)
{
	const char *slash = strrchr(path, '/');

	sts_strlcpy(out, slash != NULL ? slash + 1 : path, cap);
}

/* SHA-256 of the whole file, @return 0 or -1 */
static int hash_file(FILE *fp, uint8_t out[STS_HASH_LEN])
{
	static uint8_t buf[65536];
	struct sts_sha256 h;
	size_t n;

	if (fseeko(fp, 0, SEEK_SET) != 0)
		return -1;
	sts_sha256_init(&h);
	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
		sts_sha256_update(&h, buf, n);
	sts_sha256_final(&h, out);
	return ferror(fp) ? -1 : 0;
}

int sts_xfer_send(struct sts_xfers *xs, const uint8_t sid[STS_SID_LEN],
		  const char *path, char *err, size_t errlen)
{
	const struct sts_member *m = sts_room_member(xs->room, sid);
	char name[STS_PATH_MAX];
	char max[32];
	struct sts_xfer *x;
	off_t size;
	FILE *fp;

	if (m == NULL) {
		snprintf(err, errlen, "they are not in the room anymore");
		return -1;
	}
	if (sts_is_dir(path)) {
		snprintf(err, errlen, "%s is a directory", path);
		return -1;
	}
	fp = sts_fopen(path, "rb");
	if (fp == NULL) {
		snprintf(err, errlen, "cannot open %s: %s", path,
			 strerror(errno));
		return -1;
	}
	size = fseeko(fp, 0, SEEK_END) == 0 ? ftello(fp) : -1;
	if (size < 0) {
		snprintf(err, errlen, "cannot read %s", path);
		fclose(fp);
		return -1;
	}
	if ((uint64_t)size > xs->max_size) {
		sts_xfer_size_str(xs->max_size, max, sizeof(max));
		snprintf(
			err, errlen,
			"%s is bigger than max_file_size (%s), see the configuration",
			path, max);
		fclose(fp);
		return -1;
	}

	x = slot_new(xs);
	if (x == NULL || sts_random(&x->id, sizeof(x->id)) != 0) {
		snprintf(err, errlen, "too many transfers at once");
		fclose(fp);
		return -1;
	}
	if (hash_file(fp, x->hash) != 0) {
		snprintf(err, errlen, "cannot read %s", path);
		fclose(fp);
		sts_memzero(x, sizeof(*x));
		return -1;
	}
	x->state = STS_XFER_OFFERED;
	x->outgoing = 1;
	x->num = ++*xs->counter;
	memcpy(x->sid, sid, STS_SID_LEN);
	sts_strlcpy(x->nick, m->nick, sizeof(x->nick));
	basename_of(path, name, sizeof(name));
	sts_sanitize((const uint8_t *)name, strlen(name), x->name,
		     sizeof(x->name));
	if (x->name[0] == '\0')
		sts_strlcpy(x->name, "file", sizeof(x->name));
	x->size = (uint64_t)size;
	x->src = fp;
	x->created_ms = now(xs);
	x->progress_ms = x->created_ms;
	send_offer(xs, x);
	return (int)x->num;
}

/* --- receiving ----------------------------------------------------------- */

/* a name that can't escape the directory or hide */
static void safe_name(const uint8_t *raw, size_t len, char *out, size_t cap)
{
	char *p;

	sts_sanitize(raw, len, out, cap);
	for (p = out; *p != '\0'; p++)
		if (*p == '/' || *p == '\\')
			*p = '_';
	p = out;
	while (*p == '.' || *p == ' ')
		p++;
	memmove(out, p, strlen(p) + 1);
	if (out[0] == '\0')
		sts_strlcpy(out, "file", cap);
}

/* "dir/name", then "dir/name (2).ext"... */
static int candidate(const char *dir, const char *name, int n, char *out,
		     size_t cap)
{
	const char *dot = strrchr(name, '.');
	int len;

	if (n == 1)
		len = snprintf(out, cap, "%s/%s", dir, name);
	else if (dot != NULL && dot != name)
		len = snprintf(out, cap, "%s/%.*s (%d)%s", dir,
			       (int)(dot - name), name, n, dot);
	else
		len = snprintf(out, cap, "%s/%s (%d)", dir, name, n);
	return len < 0 || (size_t)len >= cap ? -1 : 0;
}

static void finish_incoming(struct sts_xfers *xs, struct sts_xfer *x)
{
	uint8_t hash[STS_HASH_LEN];
	int rc = -1;
	int n;

	sts_sha256_final(&x->sha, hash);
	if (fclose(x->fp) != 0) {
		x->fp = NULL;
		remove(x->part);
		fail(xs, x, REASON_ERROR, 1, "could not write the file");
		return;
	}
	x->fp = NULL;
	if (sts_memcmp_ct(hash, x->hash, STS_HASH_LEN) != 0) {
		remove(x->part);
		fail(xs, x, REASON_CORRUPT, 1,
		     "the file is corrupt (wrong SHA-256), deleted");
		return;
	}

	/* never replace an existing file */
	for (n = 1; n <= 1000; n++) {
		char dir[STS_PATH_MAX];
		char path[STS_PATH_MAX];

		sts_path_dirname(x->part, dir, sizeof(dir));
		if (candidate(dir, x->name, n, path, sizeof(path)) != 0)
			break;
		rc = sts_file_link_new(x->part, path);
		sts_strlcpy(x->path, path, sizeof(x->path));
		if (rc != 1)
			break;
	}
	remove(x->part);
	if (rc != 0) {
		fail(xs, x, REASON_ERROR, 1, "could not save the file");
		return;
	}

	send_simple(xs, x, OP_DONE);
	x->state = STS_XFER_FINISHED;
	x->percent = 100;
	x->progress_ms = now(xs);
	emit(xs, x, STS_XFER_EV_DONE, x->path);
}

int sts_xfer_accept(struct sts_xfers *xs, unsigned int num, const char *dir,
		    char *err, size_t errlen)
{
	struct sts_xfer *x = sts_xfer_find(xs, num);
	char part[STS_PATH_MAX];
	int len;

	if (x == NULL || x->outgoing || x->state != STS_XFER_OFFERED) {
		snprintf(err, errlen, "no file offer %u", num);
		return -1;
	}
	if (!sts_is_dir(dir)) {
		snprintf(err, errlen, "%s is not a directory", dir);
		return -1;
	}
	len = snprintf(part, sizeof(part), "%s/.%s.%016llx.part", dir, x->name,
		       (unsigned long long)x->id);
	if (len < 0 || (size_t)len >= sizeof(part) ||
	    sts_strlcpy(x->part, part, sizeof(x->part)) != 0) {
		snprintf(err, errlen, "path too long");
		return -1;
	}
	x->fp = sts_file_create(x->part);
	if (x->fp == NULL) {
		snprintf(err, errlen, "cannot create %s: %s", x->part,
			 strerror(errno));
		return -1;
	}
	sts_sha256_init(&x->sha);
	x->state = STS_XFER_ACTIVE;
	x->started_ms = now(xs);
	x->progress_ms = x->started_ms;
	send_simple(xs, x, OP_ACCEPT);
	if (x->size == 0)
		finish_incoming(xs, x);
	return 0;
}

int sts_xfer_refuse(struct sts_xfers *xs, unsigned int num)
{
	struct sts_xfer *x = sts_xfer_find(xs, num);

	if (x == NULL || x->outgoing || x->state != STS_XFER_OFFERED)
		return -1;
	send_simple(xs, x, OP_REFUSE);
	slot_free(x);
	return 0;
}

int sts_xfer_cancel(struct sts_xfers *xs, unsigned int num)
{
	struct sts_xfer *x = sts_xfer_find(xs, num);

	if (x == NULL)
		return -1;
	if (!x->outgoing && x->state == STS_XFER_OFFERED)
		return sts_xfer_refuse(xs, num);
	send_cancel(xs, x, REASON_CANCELLED);
	slot_free(x);
	return 0;
}

/* transfers from @sid that we receive, or are asked to */
static unsigned int incoming_from(const struct sts_xfers *xs,
				  const uint8_t *sid)
{
	unsigned int n = 0;
	size_t i;

	for (i = 0; i < STS_XFER_SLOTS; i++)
		if (xs->x[i].state != STS_XFER_FREE && !xs->x[i].outgoing &&
		    memcmp(xs->x[i].sid, sid, STS_SID_LEN) == 0)
			n++;
	return n;
}

static void on_offer(struct sts_xfers *xs, const struct sts_member *m,
		     uint64_t id, struct sts_rbuf *rd)
{
	const uint8_t *hash;
	const uint8_t *name;
	struct sts_xfer *x;
	uint64_t size;
	uint8_t nlen;

	size = sts_r_u64(rd);
	hash = sts_r_bytes(rd, STS_HASH_LEN);
	nlen = sts_r_u8(rd);
	name = sts_r_bytes(rd, nlen);
	if (rd->err || sts_r_left(rd) != 0 || nlen == 0)
		return;

	/* the offer again: our answer may have been lost */
	x = find_id(xs, m->sid, id, 0);
	if (x != NULL) {
		if (x->state == STS_XFER_ACTIVE)
			send_simple(xs, x, OP_ACCEPT);
		else if (x->state == STS_XFER_FINISHED)
			send_simple(xs, x, OP_DONE);
		return;
	}

	if (size > xs->max_size) {
		static struct sts_xfer tmp;

		memset(&tmp, 0, sizeof(tmp));
		tmp.id = id;
		tmp.size = size;
		memcpy(tmp.sid, m->sid, STS_SID_LEN);
		sts_strlcpy(tmp.nick, m->nick, sizeof(tmp.nick));
		safe_name(name, nlen, tmp.name, sizeof(tmp.name));
		send_cancel(xs, &tmp, REASON_TOO_BIG);
		emit(xs, &tmp, STS_XFER_EV_TOO_BIG, NULL);
		return;
	}
	/* one sender can't take every slot */
	x = incoming_from(xs, m->sid) < STS_XFER_PER_PEER ? slot_new(xs) : NULL;
	if (x == NULL) {
		struct sts_xfer tmp;

		memset(&tmp, 0, sizeof(tmp));
		tmp.id = id;
		memcpy(tmp.sid, m->sid, STS_SID_LEN);
		send_simple(xs, &tmp, OP_REFUSE);
		return;
	}
	x->state = STS_XFER_OFFERED;
	x->id = id;
	x->num = ++*xs->counter;
	memcpy(x->sid, m->sid, STS_SID_LEN);
	sts_strlcpy(x->nick, m->nick, sizeof(x->nick));
	safe_name(name, nlen, x->name, sizeof(x->name));
	x->size = size;
	memcpy(x->hash, hash, STS_HASH_LEN);
	x->created_ms = now(xs);
	x->progress_ms = x->created_ms;
	emit(xs, x, STS_XFER_EV_OFFER, NULL);
}

static void on_data(struct sts_xfers *xs, struct sts_xfer *x,
		    struct sts_rbuf *rd)
{
	uint64_t offset = sts_r_u64(rd);
	size_t n = sts_r_left(rd);
	const uint8_t *bytes = sts_r_bytes(rd, n);
	uint64_t t = now(xs);

	if (rd->err)
		return;
	if (x->state == STS_XFER_FINISHED) {
		send_simple(xs, x, OP_DONE); /* our DONE was lost */
		return;
	}
	if (x->state != STS_XFER_ACTIVE)
		return;

	/* out of order or again: say where we are, now and then */
	if (offset != x->done || n == 0 || n > x->size - x->done) {
		if (t - x->sent_ms >= STS_XFER_RETRY_MS / 3) {
			send_u64(xs, x, OP_ACK, x->done);
			x->sent_ms = t;
		}
		return;
	}

	if (fwrite(bytes, 1, n, x->fp) != n) {
		fail(xs, x, REASON_ERROR, 1, "could not write the file");
		return;
	}
	sts_sha256_update(&x->sha, bytes, n);
	x->done += n;
	progress(xs, x);

	if (x->done == x->size) {
		finish_incoming(xs, x);
		return;
	}
	if ((x->done / STS_XFER_CHUNK) % STS_XFER_ACK_EVERY == 0) {
		send_u64(xs, x, OP_ACK, x->done);
		x->sent_ms = t;
	}
}

static void on_ack(struct sts_xfers *xs, struct sts_xfer *x,
		   struct sts_rbuf *rd)
{
	uint64_t done = sts_r_u64(rd);

	if (rd->err || x->state != STS_XFER_ACTIVE || done > x->size)
		return;
	if (done > x->done) {
		x->done = done;
		if (x->next < done)
			x->next = done;
		progress(xs, x);
	} else if (done == x->done && x->next > done) {
		/* the receiver lacks what follows: go back */
		x->next = done;
	}
	pump(xs, x);
}

void sts_xfers_handle(struct sts_xfers *xs, const struct sts_member *m,
		      const uint8_t *data, size_t len)
{
	struct sts_xfer *x;
	struct sts_rbuf rd;
	uint64_t id;
	uint8_t op;

	sts_rbuf_init(&rd, data, len);
	op = sts_r_u8(&rd);
	id = sts_r_u64(&rd);
	if (rd.err)
		return;

	if (op == OP_OFFER) {
		on_offer(xs, m, id, &rd);
		return;
	}

	/* answers about our files, or data of theirs */
	x = find_id(xs, m->sid, id,
		    op == OP_ACCEPT || op == OP_REFUSE || op == OP_ACK ||
			    op == OP_DONE);
	if (op == OP_CANCEL && x == NULL)
		x = find_id(xs, m->sid, id, 1);
	if (x == NULL)
		return;

	switch (op) {
	case OP_ACCEPT:
		if (x->state != STS_XFER_OFFERED)
			break;
		x->state = STS_XFER_ACTIVE;
		x->started_ms = now(xs);
		x->progress_ms = x->started_ms;
		emit(xs, x, STS_XFER_EV_ACCEPTED, NULL);
		pump(xs, x);
		break;
	case OP_REFUSE:
		if (x->state != STS_XFER_OFFERED)
			break;
		emit(xs, x, STS_XFER_EV_REFUSED, NULL);
		slot_free(x);
		break;
	case OP_DATA:
		on_data(xs, x, &rd);
		break;
	case OP_ACK:
		on_ack(xs, x, &rd);
		break;
	case OP_DONE:
		if (x->state != STS_XFER_ACTIVE)
			break;
		x->done = x->size;
		x->percent = 100;
		emit(xs, x, STS_XFER_EV_DONE, NULL);
		slot_free(x);
		break;
	case OP_CANCEL: {
		uint8_t reason = sts_r_u8(&rd);

		if (x->state == STS_XFER_FINISHED)
			break;
		fail(xs, x, REASON_CANCELLED, 0,
		     reason == REASON_CORRUPT ?
			     "the file arrived corrupt" :
		     reason == REASON_ERROR ?
			     "the other side had an error" :
		     reason == REASON_TOO_BIG ?
			     "it is bigger than what they accept (their max_file_size)" :
			     "cancelled by the other side");
		break;
	}
	default:
		break;
	}
}

void sts_xfers_gone(struct sts_xfers *xs, const uint8_t sid[STS_SID_LEN])
{
	size_t i;

	for (i = 0; i < STS_XFER_SLOTS; i++) {
		struct sts_xfer *x = &xs->x[i];

		if (x->state == STS_XFER_FREE ||
		    memcmp(x->sid, sid, STS_SID_LEN) != 0)
			continue;
		if (x->state == STS_XFER_FINISHED)
			slot_free(x);
		else
			fail(xs, x, REASON_CANCELLED, 0, "they left the room");
	}
}

void sts_xfers_tick(struct sts_xfers *xs)
{
	uint64_t t = now(xs);
	size_t i;

	for (i = 0; i < STS_XFER_SLOTS; i++) {
		struct sts_xfer *x = &xs->x[i];

		switch (x->state) {
		case STS_XFER_FREE:
			break;
		case STS_XFER_FINISHED:
			if (t - x->progress_ms >= STS_XFER_LINGER_MS)
				slot_free(x);
			break;
		case STS_XFER_OFFERED:
			if (t - x->created_ms >= STS_XFER_ANSWER_MS) {
				if (x->outgoing)
					fail(xs, x, REASON_CANCELLED, 1,
					     "no answer");
				else
					fail(xs, x, REASON_CANCELLED, 0,
					     "the offer expired");
			} else if (x->outgoing &&
				   t - x->sent_ms >= STS_XFER_OFFER_RESEND_MS) {
				send_offer(xs, x);
			}
			break;
		case STS_XFER_ACTIVE:
			if (t - x->progress_ms >= STS_XFER_IDLE_MS) {
				fail(xs, x, REASON_ERROR, 1,
				     "no progress for 3 minutes");
				break;
			}
			if (!x->outgoing)
				break;
			/* nothing acknowledged lately: go back */
			if (x->next > x->done &&
			    t - x->progress_ms >= STS_XFER_RETRY_MS &&
			    t - x->sent_ms >= STS_XFER_RETRY_MS) {
				x->next = x->done;
				x->sent_ms = t;
			}
			/* an empty file has no data to resend: offer again */
			if (x->size == 0 && t - x->sent_ms >= STS_XFER_RETRY_MS)
				send_offer(xs, x);
			pump(xs, x);
			break;
		}
	}
}
