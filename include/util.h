/* SPDX-License-Identifier: Apache-2.0 */
#ifndef STS_UTIL_H
#define STS_UTIL_H

#include <stddef.h>
#include <stdint.h>

#define STS_NICK_MAX 24
#define STS_ROOM_MAX 64
#define STS_PASSWORD_MAX 128
#define STS_PATH_MAX 1024

#define STS_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/*
 * @brief       1 if @nick is a valid nickname: 1 to STS_NICK_MAX ASCII
 *              letters, digits or one of _-.[]^`{}|
 */
int sts_nick_valid(const char *nick, size_t len);

/*
 * @brief       1 if @room is a valid room name: 1 to STS_ROOM_MAX ASCII
 *              letters, digits or one of _.-
 */
int sts_room_valid(const char *room);

/*
 * @brief       decode one UTF-8 sequence.
 * @return      its length, or 0 if invalid (overlong, surrogate, truncated).
 */
size_t sts_utf8_decode(const uint8_t *s, size_t len, uint32_t *cp);

/* @brief encode @cp as UTF-8 into @out (4 bytes), return its length */
size_t sts_utf8_encode(uint32_t cp, char *out);

/* @brief terminal columns used by @cp: 0 (combining), 1 or 2 (wide) */
int sts_cp_width(uint32_t cp);

/* @brief terminal columns used by a valid UTF-8 string */
size_t sts_str_width(const char *s);

/*
 * @brief       make untrusted text safe to print on a terminal: control
 *              characters (C0, DEL, C1) and bidirectional overrides are
 *              dropped, tabs become spaces, invalid UTF-8 becomes '?'.
 *              This stops peers from injecting terminal escape sequences.
 * @return      length of the NUL terminated string written to @out.
 */
size_t sts_sanitize(const uint8_t *in, size_t len, char *out, size_t cap);

/* @brief lowercase hex, @out must hold 2 * len + 1 bytes */
void sts_hex(const uint8_t *in, size_t len, char *out);

/* @brief decode exactly @len bytes of hex, return 0 on success */
int sts_unhex(const char *hex, uint8_t *out, size_t len);

/*
 * @brief       bounded string copy, always NUL terminated.
 * @return      0 if it fit, -1 if truncated.
 */
int sts_strlcpy(char *dst, const char *src, size_t cap);

/* @brief ASCII case-insensitive comparison, like strcasecmp() */
int sts_strcasecmp(const char *a, const char *b);
int sts_strncasecmp(const char *a, const char *b, size_t n);

/*
 * @brief       expand a path from the configuration: "~/" is the home
 *              directory, a relative path is relative to @base_dir.
 * @return      0 on success, -1 if it doesn't fit or $HOME is unknown.
 */
int sts_path_expand(const char *path, const char *base_dir, char *out,
		    size_t cap);

/* @brief directory part of @path ("." if none) */
void sts_path_dirname(const char *path, char *out, size_t cap);

#endif /* STS_UTIL_H */
