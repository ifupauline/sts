// SPDX-License-Identifier: Apache-2.0
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "platform.h"
#include "room.h"
#include "tui.h"

#define ESC_TIMEOUT_MS 50
#define SGR_STATE_MAX 48
#define TIME_WIDTH 6 /* "12:34 " */
#define WRAP_MAX 512 /* rows of one line */

/* --- growing string ------------------------------------------------------ */

struct sbuf {
	char *p;
	size_t len;
	size_t cap;
	int failed;
};

static void sb_add(struct sbuf *b, const char *s, size_t n)
{
	char *p;
	size_t cap;

	if (b->failed)
		return;
	if (b->len + n + 1 > b->cap) {
		cap = b->cap ? b->cap : 16384;
		while (cap < b->len + n + 1)
			cap *= 2;
		p = realloc(b->p, cap);
		if (p == NULL) {
			b->failed = 1;
			return;
		}
		b->p = p;
		b->cap = cap;
	}
	memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = '\0';
}

static void sb_str(struct sbuf *b, const char *s)
{
	sb_add(b, s, strlen(s));
}

static void sb_printf(struct sbuf *b, const char *fmt, ...) STS_PRINTF(2, 3);

static void sb_printf(struct sbuf *b, const char *fmt, ...)
{
	char tmp[512];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (n > 0)
		sb_add(b, tmp,
		       (size_t)n < sizeof(tmp) ? (size_t)n : sizeof(tmp) - 1);
}

static void sb_spaces(struct sbuf *b, int n)
{
	static const char spaces[] = "                                ";

	while (n > 0) {
		int k = n < 32 ? n : 32;

		sb_add(b, spaces, (size_t)k);
		n -= k;
	}
}

/* --- text measuring ------------------------------------------------------ */

/* @return length of the SGR sequence at @s, 0 if none */
static size_t sgr_len(const char *s)
{
	size_t i;

	if (s[0] != '\033' || s[1] != '[')
		return 0;
	for (i = 2; s[i] != '\0'; i++) {
		if (s[i] == 'm')
			return i + 1;
		if (!((s[i] >= '0' && s[i] <= '9') || s[i] == ';'))
			return 0;
	}
	return 0;
}

/* @return bytes of the character at @s and its width in *w */
static size_t next_char(const char *s, int *w)
{
	uint32_t cp;
	size_t n;

	n = sts_utf8_decode((const uint8_t *)s, strnlen(s, 4), &cp);
	if (n == 0) {
		*w = 1;
		return 1;
	}
	*w = sts_cp_width(cp);
	return n;
}

size_t tui_text_width(const char *s)
{
	size_t width = 0;
	size_t n;
	int w;

	while (*s != '\0') {
		n = sgr_len(s);
		if (n > 0) {
			s += n;
			continue;
		}
		s += next_char(s, &w);
		width += (size_t)w;
	}
	return width;
}

/*
 * @brief       append @s cut to @width columns, padded with spaces, to @b.
 *              Escape sequences are kept only with colors, and stay in
 *              effect.
 */
static void sb_fit(struct sbuf *b, const char *s, int width, int colors)
{
	int used = 0;
	size_t n;
	int w;

	while (*s != '\0') {
		n = sgr_len(s);
		if (n > 0) {
			if (colors)
				sb_add(b, s, n);
			s += n;
			continue;
		}
		n = next_char(s, &w);
		if (used + w > width)
			break;
		if (n == 1 && (unsigned char)s[0] >= 0x80)
			sb_add(b, "?", 1);
		else
			sb_add(b, s, n);
		used += w;
		s += n;
	}
	sb_spaces(b, width - used);
}

/* --- colors -------------------------------------------------------------- */

/* index 0 is the terminal's default, then the nick colors */
static const char *const color_sgr[] = {
	"\033[39m", "\033[31m", "\033[32m", "\033[33m", "\033[35m", "\033[36m",
	"\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m",
};

_Static_assert(STS_ARRAY_SIZE(color_sgr) == TUI_NICK_COLORS + 1,
	       "one SGR sequence per nick color");

int tui_nick_color(const uint8_t *fpr, const char *nick)
{
	uint32_t h = 2166136261u; /* FNV-1a */
	size_t i;

	for (i = 0; i < STS_HASH_LEN; i++)
		h = (h ^ fpr[i]) * 16777619u;
	for (; *nick != '\0'; nick++)
		h = (h ^ (uint8_t)*nick) * 16777619u;
	return 1 + (int)(h % TUI_NICK_COLORS);
}

const char *tui_color(const struct tui *t, int color)
{
	if (!t->colors || color < 0 ||
	    (size_t)color >= STS_ARRAY_SIZE(color_sgr))
		return "";
	return color_sgr[color];
}

const char *tui_sgr(const struct tui *t, const char *seq)
{
	return t->colors ? seq : "";
}

/* --- setup --------------------------------------------------------------- */

static void term_puts(const char *s)
{
	sts_term_write(s, strlen(s));
}

int tui_init(struct tui *t, int fullscreen, int colors,
	     const char *const *commands, const struct tui_ops *ops, void *ud)
{
	memset(t, 0, sizeof(*t));
	t->fullscreen = fullscreen;
	t->colors = colors;
	t->commands = commands;
	t->ops = *ops;
	t->ud = ud;
	t->history_pos = -1;
	t->cur = -1;

	if (!fullscreen)
		return 0;
	if (sts_term_raw() != 0 || sts_term_size(&t->rows, &t->cols) != 0)
		return -1;
	/* alternate screen, cursor keys in normal mode */
	term_puts("\033[?1049h\033[?1l\033[H\033[2J");
	t->dirty = 1;
	return 0;
}

void tui_end(struct tui *t)
{
	int i;

	if (t->fullscreen) {
		term_puts("\033[0m\033[?25h\033[?1049l");
		sts_term_restore();
		t->fullscreen = 0;
	}
	for (i = t->win_count - 1; i >= 0; i--)
		tui_window_remove(t, i);
	for (i = 0; i < t->history_count; i++)
		free(t->history[i]);
	t->history_count = 0;
	sts_memzero(t->input, sizeof(t->input));
	sts_memzero(t->saved, sizeof(t->saved));
	sts_memzero(t->pending, sizeof(t->pending));
}

/* --- windows ------------------------------------------------------------- */

int tui_window_add(struct tui *t, const char *name)
{
	struct tui_window *w;

	if (t->win_count >= TUI_WINDOWS_MAX)
		return -1;
	w = calloc(1, sizeof(*w));
	if (w == NULL)
		return -1;
	sts_strlcpy(w->name, name, sizeof(w->name));
	t->win[t->win_count] = w;
	if (t->cur < 0)
		t->cur = t->win_count;
	t->dirty = 1;
	return t->win_count++;
}

void tui_window_remove(struct tui *t, int win)
{
	struct tui_window *w;
	size_t i;

	if (win < 0 || win >= t->win_count)
		return;
	w = t->win[win];
	for (i = 0; i < w->count; i++)
		free(w->lines[(w->first + i) % TUI_LINES_MAX]);
	free(w->nicks);
	free(w);

	memmove(&t->win[win], &t->win[win + 1],
		(size_t)(t->win_count - win - 1) * sizeof(t->win[0]));
	t->win_count--;
	if (t->cur > win || t->cur >= t->win_count)
		t->cur--;
	if (t->cur < 0 && t->win_count > 0)
		t->cur = 0;
	t->dirty = 1;
}

void tui_window_select(struct tui *t, int win)
{
	if (win < 0 || win >= t->win_count)
		return;
	/* leaving a window: what it showed has been read */
	if (t->cur >= 0 && t->cur < t->win_count && t->cur != win)
		t->win[t->cur]->marker = 0;
	t->cur = win;
	t->win[win]->unread = 0;
	t->win[win]->highlight = 0;
	t->dirty = 1;
}

int tui_window_find(const struct tui *t, const char *name)
{
	int i;

	for (i = 0; i < t->win_count; i++)
		if (sts_strcasecmp(t->win[i]->name, name) == 0)
			return i;
	return -1;
}

static struct tui_window *window(const struct tui *t, int win)
{
	if (win < 0 || win >= t->win_count)
		return NULL;
	return t->win[win];
}

/* plain mode: print without escape sequences unless colors are on */
static void plain_line(struct tui *t, const char *line)
{
	struct sbuf b = { 0 };
	size_t n;

	while (*line != '\0') {
		n = sgr_len(line);
		if (n > 0) {
			if (t->colors)
				sb_add(&b, line, n);
			line += n;
			continue;
		}
		sb_add(&b, line, 1);
		line++;
	}
	if (t->colors)
		sb_str(&b, TUI_RESET);
	sb_add(&b, "\n", 1);
	if (!b.failed)
		sts_term_write(b.p, b.len);
	free(b.p);
}

void tui_print(struct tui *t, int win, enum tui_line_kind kind, const char *fmt,
	       ...)
{
	struct tui_window *w = window(t, win);
	char text[4096];
	char stamp[16];
	char *line;
	struct tm tm;
	size_t len;
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(text, sizeof(text), fmt, ap);
	va_end(ap);

	if (t->ops.line != NULL) {
		char plain[sizeof(text)];
		size_t i = 0;
		size_t k = 0;
		size_t n;

		while (text[i] != '\0' && k < sizeof(plain) - 1) {
			n = sgr_len(text + i);
			if (n > 0)
				i += n;
			else
				plain[k++] = text[i++];
		}
		plain[k] = '\0';
		t->ops.line(t->ud, win, plain);
	}

	sts_localtime((time_t)(sts_wallclock_ms() / 1000), &tm);
	snprintf(stamp, sizeof(stamp), "%02d:%02d ", tm.tm_hour, tm.tm_min);

	if (!t->fullscreen) {
		char out[4096 + 128];

		/* the room only matters with several of them */
		if (w != NULL && t->win_count > 1)
			snprintf(out, sizeof(out), "%s%s%s%s %s", stamp,
				 tui_sgr(t, TUI_DIM), w->name,
				 tui_sgr(t, TUI_RESET), text);
		else
			snprintf(out, sizeof(out), "%s%s", stamp, text);
		plain_line(t, out);
		return;
	}
	if (w == NULL)
		return;

	len = strlen(stamp) + strlen(text) + 1 + strlen(TUI_DIM) +
	      strlen(TUI_RESET);
	line = malloc(len);
	if (line == NULL)
		return;
	snprintf(line, len, "%s%s%s%s", tui_sgr(t, TUI_DIM), stamp,
		 tui_sgr(t, TUI_RESET), text);

	if (w->count == TUI_LINES_MAX) {
		free(w->lines[w->first]);
		w->first = (w->first + 1) % TUI_LINES_MAX;
		w->count--;
		w->dropped++;
	}
	w->lines[(w->first + w->count) % TUI_LINES_MAX] = line;
	w->count++;
	/* keep the view still while reading back */
	if (w->scroll > 0)
		w->scroll++;

	if (win != t->cur && kind != TUI_LINE_NOTICE) {
		/* "new messages" goes above the first one not read */
		if (w->unread == 0 && w->marker == 0)
			w->marker = w->dropped + w->count;
		w->unread++;
		if (kind == TUI_LINE_HIGHLIGHT)
			w->highlight = 1;
	}
	t->dirty = 1;
}

void tui_set_title(struct tui *t, int win, const char *title)
{
	struct tui_window *w = window(t, win);

	if (w != NULL && strcmp(w->title, title) != 0) {
		sts_strlcpy(w->title, title, sizeof(w->title));
		t->dirty = 1;
	}
}

void tui_set_state(struct tui *t, int win, const char *state)
{
	struct tui_window *w = window(t, win);

	if (w != NULL && strcmp(w->state, state) != 0) {
		sts_strlcpy(w->state, state, sizeof(w->state));
		t->dirty = 1;
	}
}

static int nick_order(const void *a, const void *b)
{
	const struct tui_nick *x = a;
	const struct tui_nick *y = b;

	if (x->away != y->away)
		return x->away - y->away;
	return sts_strcasecmp(x->name, y->name);
}

void tui_set_nicks(struct tui *t, int win, const struct tui_nick *nicks,
		   size_t count)
{
	struct tui_window *w = window(t, win);
	struct tui_nick *copy = NULL;

	if (w == NULL)
		return;
	if (count > 0) {
		copy = malloc(count * sizeof(*copy));
		if (copy == NULL)
			return;
		memcpy(copy, nicks, count * sizeof(*copy));
		qsort(copy, count, sizeof(*copy), nick_order);
	}
	free(w->nicks);
	w->nicks = copy;
	w->nick_count = count;
	t->dirty = 1;
}

void tui_set_extra(struct tui *t, const char *text)
{
	if (strcmp(t->extra, text) != 0) {
		sts_strlcpy(t->extra, text, sizeof(t->extra));
		t->dirty = 1;
	}
}

void tui_set_self(struct tui *t, const char *nick, int color)
{
	sts_strlcpy(t->nick, nick, sizeof(t->nick));
	t->nick_color = color;
	t->dirty = 1;
}

void tui_clear(struct tui *t, int win)
{
	struct tui_window *w = window(t, win);
	size_t i;

	if (w == NULL)
		return;
	for (i = 0; i < w->count; i++)
		free(w->lines[(w->first + i) % TUI_LINES_MAX]);
	w->first = 0;
	w->count = 0;
	w->scroll = 0;
	w->marker = 0;
	t->dirty = 1;
}

/* --- wrapping ------------------------------------------------------------ */

struct row {
	const char *start;
	const char *end;
	int indent;
};

/*
 * @brief       split @line into rows of @width columns, breaking after
 *              spaces when possible. Continuation rows are indented past
 *              the time stamp.
 * @return      number of rows stored (at most @max), all counted in *total
 */
static int wrap(const char *line, int width, struct row *rows, int max,
		int *total)
{
	const char *s = line;
	const char *row_start = line;
	const char *last_space = NULL;
	int indent = 0;
	int used = 0;
	int n = 0;
	size_t len;
	int w;

	*total = 0;
	if (width <= TIME_WIDTH + 4)
		width = TIME_WIDTH + 5;

	while (*s != '\0') {
		len = sgr_len(s);
		if (len > 0) {
			s += len;
			continue;
		}
		len = next_char(s, &w);
		if (used + w > width) {
			const char *cut = last_space != NULL ? last_space : s;

			if (n < max) {
				rows[n].start = row_start;
				rows[n].end = cut;
				rows[n].indent = indent;
				n++;
			}
			(*total)++;
			row_start = cut;
			while (*row_start == ' ')
				row_start++;
			s = row_start;
			last_space = NULL;
			indent = TIME_WIDTH;
			used = indent;
			continue;
		}
		if (*s == ' ')
			last_space = s + 1;
		used += w;
		s += len;
	}
	if (n < max) {
		rows[n].start = row_start;
		rows[n].end = s;
		rows[n].indent = indent;
		n++;
	}
	(*total)++;
	return n;
}

/*
 * @brief       the SGR state in effect at @pos of @line (escape sequences
 *              since the last reset), to repeat on continuation rows.
 */
static void sgr_state(const char *line, const char *pos, char *out, size_t cap)
{
	size_t used = 0;
	size_t n;

	out[0] = '\0';
	while (line < pos && *line != '\0') {
		n = sgr_len(line);
		if (n == 0) {
			line++;
			continue;
		}
		if (n == 4 && memcmp(line, TUI_RESET, 4) == 0) {
			used = 0;
		} else if (used + n < cap) {
			memcpy(out + used, line, n);
			used += n;
		}
		out[used] = '\0';
		line += n;
	}
}

/* --- drawing ------------------------------------------------------------- */

static int nick_width(const struct tui *t)
{
	int w;

	if (t->cols < 60)
		return 0;
	w = t->cols / 5;
	if (w < 14)
		w = 14;
	if (w > 22)
		w = 22;
	return w;
}

static void move_to(struct sbuf *b, int row, int col)
{
	sb_printf(b, "\033[%d;%dH", row + 1, col + 1);
}

static void draw_title(struct tui *t, struct sbuf *b)
{
	struct tui_window *w = window(t, t->cur);
	char text[TUI_TEXT_MAX + 8];

	snprintf(text, sizeof(text), " %s",
		 w != NULL ? w->title : "sts - type /join ROOM");
	move_to(b, 0, 0);
	sb_str(b, tui_sgr(t, "\033[7m"));
	sb_fit(b, text, t->cols, 0);
	sb_str(b, tui_sgr(t, TUI_RESET));
}

static void draw_marker(struct tui *t, struct sbuf *b, int width)
{
	static const char label[] = " new messages ";
	int left = (width - (int)sizeof(label) + 1) / 2;
	int i;

	sb_str(b, tui_sgr(t, "\033[33m"));
	for (i = 0; i < width; i++) {
		if (i == left && left >= 0) {
			sb_str(b, label);
			i += (int)sizeof(label) - 2;
		} else {
			sb_str(b, t->colors ? "\xe2\x94\x80" : "-"); /* ─ */
		}
	}
	sb_str(b, tui_sgr(t, TUI_RESET));
}

/* rows of the chat area, newest at the bottom */
static void draw_chat(struct tui *t, struct sbuf *b, int top, int height,
		      int width)
{
	struct tui_window *w = window(t, t->cur);
	static struct row rows[WRAP_MAX];
	char sgr[SGR_STATE_MAX];
	int skip;
	int row = top + height - 1;
	size_t i;

	if (w == NULL) {
		for (row = top; row < top + height; row++) {
			move_to(b, row, 0);
			sb_spaces(b, width);
		}
		return;
	}

	skip = w->scroll;
	for (i = w->count; i > 0 && row >= top; i--) {
		const char *line = w->lines[(w->first + i - 1) % TUI_LINES_MAX];
		int total;
		int n = wrap(line, width, rows, (int)STS_ARRAY_SIZE(rows),
			     &total);
		int k;

		for (k = n - 1; k >= 0 && row >= top; k--) {
			char text[TUI_INPUT_MAX * 2];
			size_t len = (size_t)(rows[k].end - rows[k].start);

			if (skip > 0) {
				skip--;
				continue;
			}
			if (len >= sizeof(text))
				len = sizeof(text) - 1;
			memcpy(text, rows[k].start, len);
			text[len] = '\0';

			move_to(b, row, 0);
			if (t->colors && k > 0) {
				sgr_state(line, rows[k].start, sgr,
					  sizeof(sgr));
				sb_str(b, sgr);
			}
			sb_spaces(b, rows[k].indent);
			sb_fit(b, text, width - rows[k].indent, t->colors);
			sb_str(b, tui_sgr(t, TUI_RESET));
			row--;
		}
		/* the line of the first unread message: marker above it */
		if (w->marker != 0 && w->marker == w->dropped + i &&
		    row >= top) {
			if (skip > 0) {
				skip--;
			} else {
				move_to(b, row, 0);
				draw_marker(t, b, width);
				row--;
			}
		}
	}
	/* scrolled back past the oldest line: stop at the top */
	if (w->scroll > 0 && (skip > 0 || row >= top)) {
		w->scroll -= skip + (row - top + 1);
		if (w->scroll < 0)
			w->scroll = 0;
		t->dirty = 1;
	}
	for (; row >= top; row--) {
		move_to(b, row, 0);
		sb_spaces(b, width);
	}
}

static void draw_nicks(struct tui *t, struct sbuf *b, int top, int height,
		       int col, int width)
{
	struct tui_window *w = window(t, t->cur);
	char text[TUI_NICK_NAME_MAX + 32];
	size_t count = w != NULL ? w->nick_count : 0;
	size_t shown;
	size_t i;
	int row;

	for (row = top; row < top + height; row++) {
		move_to(b, row, col);
		sb_str(b, tui_sgr(t, TUI_DIM));
		sb_str(b, t->colors ? "\xe2\x94\x82" : "|"); /* │ */
		sb_str(b, tui_sgr(t, TUI_RESET));
	}

	move_to(b, top, col + 1);
	snprintf(text, sizeof(text), " %zu %s", count,
		 count == 1 ? "person" : "people");
	sb_str(b, tui_sgr(t, TUI_BOLD));
	sb_fit(b, text, width, t->colors);
	sb_str(b, tui_sgr(t, TUI_RESET));

	shown = (size_t)(height - 1);
	if (count > shown && shown > 0)
		shown--; /* room for "+N more" */
	for (i = 0, row = top + 1; i < count && i < shown; i++, row++) {
		const struct tui_nick *n = &w->nicks[i];
		char devices[16] = "";

		if (n->devices > 1)
			snprintf(devices, sizeof(devices), " (%d)", n->devices);
		snprintf(text, sizeof(text), "%s%s%s%s%s%s%s",
			 n->verified ? "+" : " ",
			 n->away ? tui_sgr(t, TUI_DIM) : "",
			 n->self ? tui_sgr(t, TUI_BOLD) : "",
			 n->away ? "" : tui_color(t, n->color), n->name,
			 tui_sgr(t, TUI_RESET), devices);
		move_to(b, row, col + 1);
		sb_fit(b, text, width, t->colors);
		sb_str(b, tui_sgr(t, TUI_RESET));
	}
	if (i < count) {
		snprintf(text, sizeof(text), " +%zu more", count - i);
		move_to(b, row++, col + 1);
		sb_str(b, tui_sgr(t, TUI_DIM));
		sb_fit(b, text, width, t->colors);
		sb_str(b, tui_sgr(t, TUI_RESET));
	}
	for (; row < top + height; row++) {
		move_to(b, row, col + 1);
		sb_spaces(b, width);
	}
}

static void draw_status(struct tui *t, struct sbuf *b, int row)
{
	struct tui_window *w = window(t, t->cur);
	char text[2048];
	size_t used;
	struct tm tm;
	int i;

	sts_localtime((time_t)(sts_wallclock_ms() / 1000), &tm);
	used = (size_t)snprintf(text, sizeof(text), " %02d:%02d [%s%s%s]",
				tm.tm_hour, tm.tm_min,
				tui_color(t, t->nick_color), t->nick,
				tui_sgr(t, "\033[39m"));

	for (i = 0; i < t->win_count && used < sizeof(text) - 128; i++) {
		struct tui_window *x = t->win[i];
		const char *mark = "";
		char unread[16] = "";

		if (i == t->cur)
			mark = TUI_BOLD;
		else if (x->highlight)
			mark = "\033[1;93m";
		else if (x->unread > 0)
			mark = "\033[93m";
		if (i != t->cur && x->unread > 0)
			snprintf(unread, sizeof(unread), "(%d)", x->unread);
		used += (size_t)snprintf(text + used, sizeof(text) - used,
					 " %s%d:%s%s%s%s", tui_sgr(t, mark),
					 i + 1, x->name, unread,
					 tui_sgr(t, "\033[22;39m"),
					 tui_sgr(t, "\033[7m"));
	}
	if (w != NULL && w->state[0] != '\0' && used < sizeof(text) - 80)
		used += (size_t)snprintf(text + used, sizeof(text) - used,
					 "  | %s", w->state);
	if (w != NULL && w->scroll > 0 && used < sizeof(text) - 32)
		used += (size_t)snprintf(text + used, sizeof(text) - used,
					 "  | -- more below (PgDn) --");
	if (t->extra[0] != '\0' && used < sizeof(text) - sizeof(t->extra) - 8)
		snprintf(text + used, sizeof(text) - used, "  | %s", t->extra);

	move_to(b, row, 0);
	sb_str(b, tui_sgr(t, "\033[7m"));
	sb_fit(b, text, t->cols, t->colors);
	sb_str(b, tui_sgr(t, TUI_RESET));
}

/* @return the cursor column */
static int draw_input(struct tui *t, struct sbuf *b, int row)
{
	struct tui_window *w = window(t, t->cur);
	char prompt[TUI_NAME_MAX + 8];
	size_t start = 0;
	int prompt_w;
	int avail;
	int before;
	size_t i;
	int cw;

	snprintf(prompt, sizeof(prompt), "[%s] ", w != NULL ? w->name : "sts");
	prompt_w = (int)tui_text_width(prompt);
	if (prompt_w > t->cols / 3) {
		prompt[0] = '\0';
		prompt_w = 0;
	}
	avail = t->cols - prompt_w - 1;

	/* scroll horizontally to keep the cursor visible */
	for (;;) {
		before = 0;
		for (i = start; i < t->cursor;) {
			i += next_char(t->input + i, &cw);
			before += cw;
		}
		if (before <= avail - 1 || start >= t->cursor)
			break;
		start += next_char(t->input + start, &cw);
		while (start < t->input_len &&
		       ((unsigned char)t->input[start] & 0xc0) == 0x80)
			start++;
	}

	move_to(b, row, 0);
	sb_str(b, prompt);
	{
		char text[TUI_INPUT_MAX];
		size_t len = t->input_len - start;

		memcpy(text, t->input + start, len);
		text[len] = '\0';
		sb_fit(b, text, avail + 1, 0);
	}
	return prompt_w + before;
}

void tui_render(struct tui *t)
{
	struct sbuf b = { 0 };
	int chat_h;
	int nick_w;
	int chat_w;
	int col;

	if (!t->fullscreen || !t->dirty)
		return;
	t->dirty = 0;

	sb_str(&b, "\033[?25l");
	if (t->rows < 6 || t->cols < 24) {
		sb_str(&b, "\033[H\033[2J");
		sb_str(&b, "terminal too small");
		goto out;
	}

	nick_w = nick_width(t);
	chat_w = nick_w > 0 ? t->cols - nick_w - 1 : t->cols;
	chat_h = t->rows - 3;

	draw_title(t, &b);
	draw_chat(t, &b, 1, chat_h, chat_w);
	if (nick_w > 0)
		draw_nicks(t, &b, 1, chat_h, chat_w, nick_w);
	draw_status(t, &b, t->rows - 2);
	col = draw_input(t, &b, t->rows - 1);
	move_to(&b, t->rows - 1, col);
	sb_str(&b, "\033[?25h");
out:
	if (!b.failed)
		sts_term_write(b.p, b.len);
	free(b.p);
}

/* --- line editing -------------------------------------------------------- */

static size_t char_before(const struct tui *t, size_t pos)
{
	if (pos == 0)
		return 0;
	pos--;
	while (pos > 0 && ((unsigned char)t->input[pos] & 0xc0) == 0x80)
		pos--;
	return pos;
}

static size_t char_after(const struct tui *t, size_t pos)
{
	if (pos >= t->input_len)
		return t->input_len;
	pos++;
	while (pos < t->input_len &&
	       ((unsigned char)t->input[pos] & 0xc0) == 0x80)
		pos++;
	return pos;
}

static void input_delete(struct tui *t, size_t from, size_t to)
{
	if (to <= from)
		return;
	memmove(t->input + from, t->input + to, t->input_len - to);
	t->input_len -= to - from;
	t->input[t->input_len] = '\0';
	if (t->cursor > to)
		t->cursor -= to - from;
	else if (t->cursor > from)
		t->cursor = from;
}

static void input_insert(struct tui *t, const char *s, size_t n)
{
	if (t->input_len + n >= sizeof(t->input))
		return;
	memmove(t->input + t->cursor + n, t->input + t->cursor,
		t->input_len - t->cursor);
	memcpy(t->input + t->cursor, s, n);
	t->input_len += n;
	t->cursor += n;
	t->input[t->input_len] = '\0';
}

static void input_set(struct tui *t, const char *s)
{
	sts_strlcpy(t->input, s, sizeof(t->input));
	t->input_len = strlen(t->input);
	t->cursor = t->input_len;
}

static void history_add(struct tui *t, const char *line)
{
	char *copy;

	if (line[0] == '\0' ||
	    (t->history_count > 0 &&
	     strcmp(t->history[t->history_count - 1], line) == 0))
		return;
	/* don't keep passwords around */
	if (sts_strcasecmp(line, "/join") == 0 ||
	    strncmp(line, "/join ", 6) == 0) {
		const char *sp = strchr(line + 6, ' ');

		if (sp != NULL && sp[1] != '\0')
			return;
	}
	copy = strdup(line);
	if (copy == NULL)
		return;
	if (t->history_count == TUI_HISTORY_MAX) {
		free(t->history[0]);
		memmove(&t->history[0], &t->history[1],
			(TUI_HISTORY_MAX - 1) * sizeof(t->history[0]));
		t->history_count--;
	}
	t->history[t->history_count++] = copy;
}

static void history_move(struct tui *t, int dir)
{
	int pos = t->history_pos;

	if (t->history_count == 0)
		return;
	if (pos < 0) {
		if (dir > 0)
			return;
		sts_strlcpy(t->saved, t->input, sizeof(t->saved));
		pos = t->history_count;
	}
	pos += dir;
	if (pos < 0)
		pos = 0;
	if (pos >= t->history_count) {
		t->history_pos = -1;
		input_set(t, t->saved);
		return;
	}
	t->history_pos = pos;
	input_set(t, t->history[pos]);
}

static void submit(struct tui *t)
{
	char line[TUI_INPUT_MAX];

	memcpy(line, t->input, t->input_len + 1);
	history_add(t, line);
	t->input_len = 0;
	t->cursor = 0;
	t->input[0] = '\0';
	t->history_pos = -1;
	if (t->ops.submit != NULL)
		t->ops.submit(t->ud, line);
	sts_memzero(line, sizeof(line));
}

/* the n-th name starting with @prefix, among commands or nicks */
static const char *completion(const struct tui *t, int commands,
			      const char *prefix, int index, int *count)
{
	struct tui_window *w = window(t, t->cur);
	size_t len = strlen(prefix);
	const char *found = NULL;
	size_t i;

	*count = 0;
	if (commands) {
		for (i = 0; t->commands != NULL && t->commands[i] != NULL; i++)
			if (strncmp(t->commands[i], prefix, len) == 0 &&
			    (*count)++ == index)
				found = t->commands[i];
		return found;
	}
	for (i = 0; w != NULL && i < w->nick_count; i++) {
		const char *name = w->nicks[i].name;

		if (strlen(name) >= len &&
		    sts_strncasecmp(name, prefix, len) == 0 &&
		    (*count)++ == index)
			found = name;
	}
	return found;
}

static void complete(struct tui *t)
{
	const char *match;
	char word[TUI_NICK_NAME_MAX + 4];
	int commands;
	int count;
	size_t start;

	if (!t->completing) {
		start = t->cursor;
		while (start > 0 && t->input[start - 1] != ' ')
			start--;
		if (t->cursor - start >= sizeof(t->comp_prefix))
			return;
		memcpy(t->comp_prefix, t->input + start, t->cursor - start);
		t->comp_prefix[t->cursor - start] = '\0';
		t->comp_start = start;
		t->comp_index = 0;
		t->completing = 1;
	} else {
		t->comp_index++;
	}

	commands = t->comp_start == 0 && t->comp_prefix[0] == '/';
	match = completion(t, commands, t->comp_prefix, t->comp_index, &count);
	if (match == NULL && count > 0) {
		t->comp_index = 0; /* cycle */
		match = completion(t, commands, t->comp_prefix, 0, &count);
	}
	if (match == NULL)
		return;

	if (commands)
		snprintf(word, sizeof(word), "%s ", match);
	else if (t->comp_start == 0)
		snprintf(word, sizeof(word), "%s: ", match);
	else
		snprintf(word, sizeof(word), "%s ", match);

	/* replace from the start of the word to the cursor */
	input_delete(t, t->comp_start, t->cursor);
	t->cursor = t->comp_start;
	input_insert(t, word, strlen(word));
}

static void scroll(struct tui *t, int pages)
{
	struct tui_window *w = window(t, t->cur);
	int step = (t->rows - 3) / 2;

	if (w == NULL)
		return;
	if (step < 1)
		step = 1;
	w->scroll += pages * step;
	if (w->scroll < 0)
		w->scroll = 0;
}

static void word_left(struct tui *t)
{
	while (t->cursor > 0 && t->input[t->cursor - 1] == ' ')
		t->cursor--;
	while (t->cursor > 0 && t->input[t->cursor - 1] != ' ')
		t->cursor--;
}

static void word_right(struct tui *t)
{
	while (t->cursor < t->input_len && t->input[t->cursor] == ' ')
		t->cursor++;
	while (t->cursor < t->input_len && t->input[t->cursor] != ' ')
		t->cursor++;
}

static void switch_window(struct tui *t, int win)
{
	if (t->win_count == 0)
		return;
	win %= t->win_count;
	if (win < 0)
		win += t->win_count;
	tui_window_select(t, win);
}

enum key {
	KEY_NONE,
	KEY_UP,
	KEY_DOWN,
	KEY_LEFT,
	KEY_RIGHT,
	KEY_HOME,
	KEY_END,
	KEY_DELETE,
	KEY_PGUP,
	KEY_PGDN,
	KEY_WORD_LEFT,
	KEY_WORD_RIGHT,
	KEY_ALT_DIGIT,
};

static void key(struct tui *t, enum key k, int arg)
{
	switch (k) {
	case KEY_UP:
		history_move(t, -1);
		break;
	case KEY_DOWN:
		history_move(t, 1);
		break;
	case KEY_LEFT:
		t->cursor = char_before(t, t->cursor);
		break;
	case KEY_RIGHT:
		t->cursor = char_after(t, t->cursor);
		break;
	case KEY_HOME:
		t->cursor = 0;
		break;
	case KEY_END:
		t->cursor = t->input_len;
		break;
	case KEY_DELETE:
		input_delete(t, t->cursor, char_after(t, t->cursor));
		break;
	case KEY_PGUP:
		scroll(t, 1);
		break;
	case KEY_PGDN:
		scroll(t, -1);
		break;
	case KEY_WORD_LEFT:
		word_left(t);
		break;
	case KEY_WORD_RIGHT:
		word_right(t);
		break;
	case KEY_ALT_DIGIT:
		switch_window(t, arg == 0 ? 9 : arg - 1);
		break;
	case KEY_NONE:
		break;
	}
}

static void control(struct tui *t, unsigned char c)
{
	size_t from;

	switch (c) {
	case '\r':
	case '\n':
		submit(t);
		break;
	case 0x7f:
	case 0x08: /* backspace */
		input_delete(t, char_before(t, t->cursor), t->cursor);
		break;
	case '\t':
		complete(t);
		return; /* keep completing */
	case 0x01: /* ^A */
		t->cursor = 0;
		break;
	case 0x05: /* ^E */
		t->cursor = t->input_len;
		break;
	case 0x02: /* ^B */
		t->cursor = char_before(t, t->cursor);
		break;
	case 0x06: /* ^F */
		t->cursor = char_after(t, t->cursor);
		break;
	case 0x0b: /* ^K */
		input_delete(t, t->cursor, t->input_len);
		break;
	case 0x15: /* ^U */
		input_delete(t, 0, t->cursor);
		break;
	case 0x17: /* ^W */
		from = t->cursor;
		while (from > 0 && t->input[from - 1] == ' ')
			from--;
		while (from > 0 && t->input[from - 1] != ' ')
			from--;
		input_delete(t, from, t->cursor);
		break;
	case 0x0c: /* ^L */
		break;
	case 0x0e: /* ^N */
		switch_window(t, t->cur + 1);
		break;
	case 0x10: /* ^P */
		switch_window(t, t->cur - 1);
		break;
	case 0x03: /* ^C */
		if (t->ops.quit != NULL)
			t->ops.quit(t->ud);
		break;
	case 0x04: /* ^D */
		if (t->input_len == 0 && t->ops.quit != NULL)
			t->ops.quit(t->ud);
		else
			input_delete(t, t->cursor, char_after(t, t->cursor));
		break;
	default:
		break;
	}
	t->completing = 0;
}

/* @return bytes used by the CSI/SS3 sequence at @s, 0 if incomplete */
static size_t escape(struct tui *t, const char *s, size_t len)
{
	char params[16];
	size_t n = 0;
	size_t i;
	char fin;

	if (len < 2)
		return 0;
	if (s[1] == 'O') { /* SS3: ESC O x */
		if (len < 3)
			return 0;
		switch (s[2]) {
		case 'A':
			key(t, KEY_UP, 0);
			break;
		case 'B':
			key(t, KEY_DOWN, 0);
			break;
		case 'C':
			key(t, KEY_RIGHT, 0);
			break;
		case 'D':
			key(t, KEY_LEFT, 0);
			break;
		case 'H':
			key(t, KEY_HOME, 0);
			break;
		case 'F':
			key(t, KEY_END, 0);
			break;
		default:
			break;
		}
		return 3;
	}
	if (s[1] != '[') { /* Alt + key */
		if (s[1] >= '0' && s[1] <= '9')
			key(t, KEY_ALT_DIGIT, s[1] - '0');
		return 2;
	}

	for (i = 2; i < len; i++) {
		if ((unsigned char)s[i] >= 0x40 && (unsigned char)s[i] <= 0x7e)
			break;
		if (n < sizeof(params) - 1)
			params[n++] = s[i];
	}
	if (i >= len)
		return len > 32 ? len : 0; /* garbage: drop it */
	params[n] = '\0';
	fin = s[i];

	switch (fin) {
	case 'A':
		key(t, KEY_UP, 0);
		break;
	case 'B':
		key(t, KEY_DOWN, 0);
		break;
	case 'C':
		key(t,
		    strstr(params, ";5") || strstr(params, ";3") ?
			    KEY_WORD_RIGHT :
			    KEY_RIGHT,
		    0);
		break;
	case 'D':
		key(t,
		    strstr(params, ";5") || strstr(params, ";3") ?
			    KEY_WORD_LEFT :
			    KEY_LEFT,
		    0);
		break;
	case 'H':
		key(t, KEY_HOME, 0);
		break;
	case 'F':
		key(t, KEY_END, 0);
		break;
	case '~':
		if (strcmp(params, "1") == 0 || strcmp(params, "7") == 0)
			key(t, KEY_HOME, 0);
		else if (strcmp(params, "4") == 0 || strcmp(params, "8") == 0)
			key(t, KEY_END, 0);
		else if (strcmp(params, "3") == 0)
			key(t, KEY_DELETE, 0);
		else if (strcmp(params, "5") == 0)
			key(t, KEY_PGUP, 0);
		else if (strcmp(params, "6") == 0)
			key(t, KEY_PGDN, 0);
		break;
	default:
		break;
	}
	return i + 1;
}

static void feed_fullscreen(struct tui *t)
{
	size_t i = 0;
	size_t n;

	while (i < t->pending_len) {
		unsigned char c = (unsigned char)t->pending[i];

		if (c == 0x1b) {
			n = escape(t, t->pending + i, t->pending_len - i);
			if (n == 0)
				break; /* wait for the rest */
			i += n;
			t->completing = 0;
			continue;
		}
		if (c < 0x20 || c == 0x7f) {
			control(t, c);
			i++;
			continue;
		}
		/* printable, maybe the first byte of a UTF-8 sequence */
		n = c >= 0xf0 ? 4 : c >= 0xe0 ? 3 : c >= 0xc0 ? 2 : 1;
		if (i + n > t->pending_len)
			break; /* wait for the rest */
		input_insert(t, t->pending + i, n);
		i += n;
		t->completing = 0;
	}
	memmove(t->pending, t->pending + i, t->pending_len - i);
	t->pending_len -= i;
	t->pending_ms = sts_monotonic_ms();
	t->dirty = 1;
}

static void feed_plain(struct tui *t)
{
	char line[TUI_INPUT_MAX];
	char *nl;
	size_t len;

	while ((nl = memchr(t->pending, '\n', t->pending_len)) != NULL) {
		len = (size_t)(nl - t->pending);
		memcpy(line, t->pending, len);
		line[len] = '\0';
		if (len > 0 && line[len - 1] == '\r')
			line[len - 1] = '\0';
		memmove(t->pending, nl + 1, t->pending_len - len - 1);
		t->pending_len -= len + 1;
		if (t->ops.submit != NULL)
			t->ops.submit(t->ud, line);
	}
	/* a line longer than the buffer: cut it */
	if (t->pending_len == sizeof(t->pending) - 1) {
		t->pending[t->pending_len] = '\0';
		if (t->ops.submit != NULL)
			t->ops.submit(t->ud, t->pending);
		t->pending_len = 0;
	}
	sts_memzero(line, sizeof(line));
}

void tui_feed(struct tui *t, const char *buf, size_t len)
{
	size_t n;

	while (len > 0) {
		n = sizeof(t->pending) - 1 - t->pending_len;
		if (n > len)
			n = len;
		memcpy(t->pending + t->pending_len, buf, n);
		t->pending_len += n;
		buf += n;
		len -= n;
		if (t->fullscreen)
			feed_fullscreen(t);
		else
			feed_plain(t);
		if (n == 0)
			t->pending_len = 0; /* stuck: drop */
	}
}

void tui_eof(struct tui *t)
{
	if (!t->fullscreen && t->pending_len > 0) {
		t->pending[t->pending_len] = '\0';
		if (t->ops.submit != NULL)
			t->ops.submit(t->ud, t->pending);
		t->pending_len = 0;
	}
	if (t->ops.quit != NULL)
		t->ops.quit(t->ud);
}

void tui_tick(struct tui *t)
{
	static int last_minute = -1;
	struct tm tm;

	if (!t->fullscreen)
		return;
	/* a lone ESC key press */
	if (t->pending_len > 0 &&
	    sts_monotonic_ms() - t->pending_ms > ESC_TIMEOUT_MS) {
		t->pending_len = 0;
		t->dirty = 1;
	}
	if (sts_term_resized()) {
		sts_term_size(&t->rows, &t->cols);
		term_puts("\033[2J");
		t->dirty = 1;
	}
	sts_localtime((time_t)(sts_wallclock_ms() / 1000), &tm);
	if (tm.tm_min != last_minute) {
		last_minute = tm.tm_min;
		t->dirty = 1; /* clock in the status bar */
	}
}
