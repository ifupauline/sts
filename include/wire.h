/* SPDX-License-Identifier: Apache-2.0 */
#ifndef STS_WIRE_H
#define STS_WIRE_H

/*
 * Bounds-checked big-endian reader/writer. Every operation checks the
 * remaining space and sets a sticky error flag instead of overflowing, so a
 * whole frame can be parsed and checked once at the end.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct sts_wbuf {
	uint8_t *p;
	size_t cap;
	size_t len;
	int err;
};

struct sts_rbuf {
	const uint8_t *p;
	size_t len;
	size_t off;
	int err;
};

static inline void sts_wbuf_init(struct sts_wbuf *w, uint8_t *p, size_t cap)
{
	w->p = p;
	w->cap = cap;
	w->len = 0;
	w->err = 0;
}

static inline uint8_t *sts_w_reserve(struct sts_wbuf *w, size_t n)
{
	uint8_t *ptr;

	if (w->err || n > w->cap - w->len) {
		w->err = 1;
		return NULL;
	}
	ptr = &w->p[w->len];
	w->len += n;
	return ptr;
}

static inline void sts_w_bytes(struct sts_wbuf *w, const void *src, size_t n)
{
	uint8_t *ptr = sts_w_reserve(w, n);

	if (ptr != NULL && n > 0)
		memcpy(ptr, src, n);
}

static inline void sts_w_u8(struct sts_wbuf *w, uint8_t v)
{
	sts_w_bytes(w, &v, 1);
}

static inline void sts_w_u16(struct sts_wbuf *w, uint16_t v)
{
	uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v };

	sts_w_bytes(w, b, sizeof(b));
}

static inline void sts_w_u32(struct sts_wbuf *w, uint32_t v)
{
	uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16),
			 (uint8_t)(v >> 8), (uint8_t)v };
	sts_w_bytes(w, b, sizeof(b));
}

static inline void sts_w_u64(struct sts_wbuf *w, uint64_t v)
{
	sts_w_u32(w, (uint32_t)(v >> 32));
	sts_w_u32(w, (uint32_t)v);
}

static inline void sts_rbuf_init(struct sts_rbuf *r, const uint8_t *p,
				 size_t len)
{
	r->p = p;
	r->len = len;
	r->off = 0;
	r->err = 0;
}

static inline size_t sts_r_left(const struct sts_rbuf *r)
{
	return r->err ? 0 : r->len - r->off;
}

/* @return pointer into the buffer, or NULL (and sets err) if too short */
static inline const uint8_t *sts_r_bytes(struct sts_rbuf *r, size_t n)
{
	const uint8_t *ptr;

	if (r->err || n > r->len - r->off) {
		r->err = 1;
		return NULL;
	}
	ptr = &r->p[r->off];
	r->off += n;
	return ptr;
}

static inline uint8_t sts_r_u8(struct sts_rbuf *r)
{
	const uint8_t *b = sts_r_bytes(r, 1);

	return b ? b[0] : 0;
}

static inline uint16_t sts_r_u16(struct sts_rbuf *r)
{
	const uint8_t *b = sts_r_bytes(r, 2);

	if (b == NULL)
		return 0;
	return (uint16_t)(b[0] << 8 | b[1]);
}

static inline uint32_t sts_r_u32(struct sts_rbuf *r)
{
	const uint8_t *b = sts_r_bytes(r, 4);

	if (b == NULL)
		return 0;
	return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 |
	       (uint32_t)b[2] << 8 | (uint32_t)b[3];
}

static inline uint64_t sts_r_u64(struct sts_rbuf *r)
{
	uint64_t hi = sts_r_u32(r);
	uint64_t lo = sts_r_u32(r);

	return hi << 32 | lo;
}

#endif /* STS_WIRE_H */
