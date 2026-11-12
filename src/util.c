// SPDX-License-Identifier: Apache-2.0
#include <stdio.h>
#include <string.h>

#include "platform.h"
#include "util.h"

static int is_alnum(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9');
}

static unsigned char to_lower(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}

int sts_nick_valid(const char *nick, size_t len)
{
	size_t i;

	if (nick == NULL || len == 0 || len > STS_NICK_MAX)
		return 0;

	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)nick[i];

		if (!is_alnum(c) && (c == '\0' || !strchr("_-.[]^`{}|", c)))
			return 0;
	}
	return 1;
}

int sts_room_valid(const char *room)
{
	size_t len;
	size_t i;

	if (room == NULL)
		return 0;

	len = strlen(room);
	if (len == 0 || len > STS_ROOM_MAX)
		return 0;

	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)room[i];

		if (!is_alnum(c) && c != '_' && c != '-' && c != '.')
			return 0;
	}
	return 1;
}

size_t sts_utf8_decode(const uint8_t *s, size_t len, uint32_t *cp)
{
	uint32_t c;
	uint32_t min;
	size_t n;
	size_t i;

	if (len == 0)
		return 0;

	if (s[0] < 0x80) {
		*cp = s[0];
		return 1;
	} else if ((s[0] & 0xE0) == 0xC0) {
		n = 2;
		c = s[0] & 0x1F;
		min = 0x80;
	} else if ((s[0] & 0xF0) == 0xE0) {
		n = 3;
		c = s[0] & 0x0F;
		min = 0x800;
	} else if ((s[0] & 0xF8) == 0xF0) {
		n = 4;
		c = s[0] & 0x07;
		min = 0x10000;
	} else {
		return 0;
	}

	if (n > len)
		return 0;

	for (i = 1; i < n; i++) {
		if ((s[i] & 0xC0) != 0x80)
			return 0;
		c = (c << 6) | (s[i] & 0x3F);
	}

	/* overlong, surrogate or out of range */
	if (c < min || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF))
		return 0;

	*cp = c;
	return n;
}

size_t sts_utf8_encode(uint32_t cp, char *out)
{
	if (cp < 0x80) {
		out[0] = (char)cp;
		return 1;
	}
	if (cp < 0x800) {
		out[0] = (char)(0xC0 | (cp >> 6));
		out[1] = (char)(0x80 | (cp & 0x3F));
		return 2;
	}
	if (cp < 0x10000) {
		out[0] = (char)(0xE0 | (cp >> 12));
		out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
		out[2] = (char)(0x80 | (cp & 0x3F));
		return 3;
	}
	out[0] = (char)(0xF0 | (cp >> 18));
	out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
	out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
	out[3] = (char)(0x80 | (cp & 0x3F));
	return 4;
}

struct cp_range {
	uint32_t first;
	uint32_t last;
};

/* combining marks and zero width characters (main blocks) */
static const struct cp_range zero_width[] = {
	{ 0x0300, 0x036F }, { 0x0483, 0x0489 },	  { 0x0591, 0x05BD },
	{ 0x0610, 0x061A }, { 0x064B, 0x065F },	  { 0x0670, 0x0670 },
	{ 0x06D6, 0x06DC }, { 0x0900, 0x0903 },	  { 0x093A, 0x094F },
	{ 0x0E31, 0x0E31 }, { 0x0E34, 0x0E3A },	  { 0x0E47, 0x0E4E },
	{ 0x1AB0, 0x1AFF }, { 0x1DC0, 0x1DFF },	  { 0x200B, 0x200F },
	{ 0x20D0, 0x20FF }, { 0xFE00, 0xFE0F },	  { 0xFE20, 0xFE2F },
	{ 0xFEFF, 0xFEFF }, { 0xE0100, 0xE01EF },
};

/* East Asian wide and fullwidth characters, emoji */
static const struct cp_range double_width[] = {
	{ 0x1100, 0x115F },   { 0x231A, 0x231B },   { 0x2329, 0x232A },
	{ 0x23E9, 0x23EC },   { 0x23F0, 0x23F0 },   { 0x23F3, 0x23F3 },
	{ 0x25FD, 0x25FE },   { 0x2614, 0x2615 },   { 0x2648, 0x2653 },
	{ 0x267F, 0x267F },   { 0x2693, 0x2693 },   { 0x26A1, 0x26A1 },
	{ 0x26AA, 0x26AB },   { 0x26BD, 0x26BE },   { 0x26C4, 0x26C5 },
	{ 0x26CE, 0x26CE },   { 0x26D4, 0x26D4 },   { 0x26EA, 0x26EA },
	{ 0x26F2, 0x26F3 },   { 0x26F5, 0x26F5 },   { 0x26FA, 0x26FA },
	{ 0x26FD, 0x26FD },   { 0x2705, 0x2705 },   { 0x270A, 0x270B },
	{ 0x2728, 0x2728 },   { 0x274C, 0x274C },   { 0x274E, 0x274E },
	{ 0x2753, 0x2755 },   { 0x2757, 0x2757 },   { 0x2795, 0x2797 },
	{ 0x27B0, 0x27B0 },   { 0x27BF, 0x27BF },   { 0x2B1B, 0x2B1C },
	{ 0x2B50, 0x2B50 },   { 0x2B55, 0x2B55 },   { 0x2E80, 0x303E },
	{ 0x3041, 0x33FF },   { 0x3400, 0x4DBF },   { 0x4E00, 0x9FFF },
	{ 0xA000, 0xA4CF },   { 0xA960, 0xA97F },   { 0xAC00, 0xD7A3 },
	{ 0xF900, 0xFAFF },   { 0xFE10, 0xFE19 },   { 0xFE30, 0xFE6F },
	{ 0xFF00, 0xFF60 },   { 0xFFE0, 0xFFE6 },   { 0x1F004, 0x1F004 },
	{ 0x1F0CF, 0x1F0CF }, { 0x1F18E, 0x1F18E }, { 0x1F191, 0x1F19A },
	{ 0x1F200, 0x1F2FF }, { 0x1F300, 0x1F64F }, { 0x1F680, 0x1F6FF },
	{ 0x1F7E0, 0x1F7EB }, { 0x1F90C, 0x1F9FF }, { 0x1FA70, 0x1FAFF },
	{ 0x20000, 0x2FFFD }, { 0x30000, 0x3FFFD },
};

static int in_ranges(uint32_t cp, const struct cp_range *r, size_t n)
{
	size_t lo = 0;
	size_t hi = n;

	while (lo < hi) {
		size_t mid = (lo + hi) / 2;

		if (cp < r[mid].first)
			hi = mid;
		else if (cp > r[mid].last)
			lo = mid + 1;
		else
			return 1;
	}
	return 0;
}

int sts_cp_width(uint32_t cp)
{
	if (cp < 0x300)
		return 1;
	if (in_ranges(cp, zero_width, STS_ARRAY_SIZE(zero_width)))
		return 0;
	if (in_ranges(cp, double_width, STS_ARRAY_SIZE(double_width)))
		return 2;
	return 1;
}

size_t sts_str_width(const char *s)
{
	const uint8_t *p = (const uint8_t *)s;
	size_t len = strlen(s);
	size_t width = 0;
	uint32_t cp;
	size_t n;

	while (len > 0) {
		n = sts_utf8_decode(p, len, &cp);
		if (n == 0) {
			n = 1;
			cp = '?';
		}
		width += (size_t)sts_cp_width(cp);
		p += n;
		len -= n;
	}
	return width;
}

static int cp_printable(uint32_t cp)
{
	if (cp < 0x20 || cp == 0x7F)
		return 0;
	/* C1 control characters */
	if (cp >= 0x80 && cp <= 0x9F)
		return 0;
	/* bidi embeddings, overrides and isolates can disguise text */
	if ((cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069))
		return 0;
	/* line and paragraph separators */
	if (cp == 0x2028 || cp == 0x2029)
		return 0;
	return 1;
}

size_t sts_sanitize(const uint8_t *in, size_t len, char *out, size_t cap)
{
	uint32_t cp;
	size_t i = 0;
	size_t o = 0;
	size_t n;

	if (cap == 0)
		return 0;

	while (i < len) {
		n = sts_utf8_decode(&in[i], len - i, &cp);

		if (n == 0) {
			if (o + 1 >= cap)
				break;
			out[o++] = '?';
			i++;
			continue;
		}

		if (cp == '\t') {
			if (o + 1 >= cap)
				break;
			out[o++] = ' ';
		} else if (cp_printable(cp)) {
			if (o + n >= cap)
				break;
			memcpy(&out[o], &in[i], n);
			o += n;
		}
		i += n;
	}
	out[o] = '\0';
	return o;
}

void sts_hex(const uint8_t *in, size_t len, char *out)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[2 * i] = digits[in[i] >> 4];
		out[2 * i + 1] = digits[in[i] & 0x0F];
	}
	out[2 * len] = '\0';
}

static int hex_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int sts_unhex(const char *hex, uint8_t *out, size_t len)
{
	size_t i;
	int hi;
	int lo;

	for (i = 0; i < len; i++) {
		hi = hex_value(hex[2 * i]);
		if (hi < 0)
			return -1;
		lo = hex_value(hex[2 * i + 1]);
		if (lo < 0)
			return -1;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

int sts_strlcpy(char *dst, const char *src, size_t cap)
{
	size_t len;

	if (cap == 0)
		return -1;

	len = strlen(src);
	if (len >= cap) {
		memcpy(dst, src, cap - 1);
		dst[cap - 1] = '\0';
		return -1;
	}
	memcpy(dst, src, len + 1);
	return 0;
}

int sts_strcasecmp(const char *a, const char *b)
{
	const unsigned char *p = (const unsigned char *)a;
	const unsigned char *q = (const unsigned char *)b;

	while (*p != '\0' && to_lower(*p) == to_lower(*q)) {
		p++;
		q++;
	}
	return (int)to_lower(*p) - (int)to_lower(*q);
}

int sts_strncasecmp(const char *a, const char *b, size_t n)
{
	const unsigned char *p = (const unsigned char *)a;
	const unsigned char *q = (const unsigned char *)b;

	for (; n > 0; n--, p++, q++) {
		if (to_lower(*p) != to_lower(*q))
			return (int)to_lower(*p) - (int)to_lower(*q);
		if (*p == '\0')
			break;
	}
	return 0;
}

int sts_path_expand(const char *path, const char *base_dir, char *out,
		    size_t cap)
{
	char home[STS_PATH_MAX];
	int n;

	if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
		if (sts_home_dir(home, sizeof(home)) != 0)
			return -1;
		n = snprintf(out, cap, "%s%s", home, path + 1);
	} else if (sts_path_is_absolute(path) || base_dir == NULL ||
		   base_dir[0] == '\0') {
		n = snprintf(out, cap, "%s", path);
	} else {
		n = snprintf(out, cap, "%s/%s", base_dir, path);
	}
	return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

void sts_path_dirname(const char *path, char *out, size_t cap)
{
	const char *slash = strrchr(path, '/');
	size_t len;

	if (slash == NULL) {
		sts_strlcpy(out, ".", cap);
		return;
	}

	len = (size_t)(slash - path);
	if (len == 0)
		len = 1; /* "/file" */
	if (len >= cap)
		len = cap - 1;
	memcpy(out, path, len);
	out[len] = '\0';
}
