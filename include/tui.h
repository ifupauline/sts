/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Terminal user interface, IRC style:
 *
 *   +-----------------------------------------------+-----------+
 *   | title: room, people, broker                               |
 *   +-----------------------------------------------+-----------+
 *   | 12:01 <alice> hi                              | alice     |
 *   | 12:02 <bob> hello                             | bob       |
 *   |                                               | carol     |
 *   +-----------------------------------------------+-----------+
 *   | status: time, nick, windows, unread, connection           |
 *   | [#room] input line                                        |
 *   +-----------------------------------------------------------+
 *
 * One window per room. In plain mode (no terminal, or asked for) lines are
 * printed as they come and input is read line by line, for scripts.
 *
 * Lines may contain SGR escape sequences (ESC [ ... m) made with the
 * helpers below; everything else must already be sanitized.
 */
#ifndef STS_TUI_H
#define STS_TUI_H

#include <stddef.h>
#include <stdint.h>

#include "log.h"
#include "util.h"

#define TUI_WINDOWS_MAX 16
#define TUI_LINES_MAX 2000
#define TUI_INPUT_MAX 2048
#define TUI_HISTORY_MAX 100
#define TUI_NAME_MAX (STS_ROOM_MAX + 2)
#define TUI_NICK_NAME_MAX (STS_NICK_MAX + 8)
#define TUI_TEXT_MAX 512

/* SGR sequences */
#define TUI_RESET "\033[0m"
#define TUI_BOLD "\033[1m"
#define TUI_DIM "\033[2m"

enum tui_line_kind {
	TUI_LINE_NOTICE, /* events: no unread mark */
	TUI_LINE_MESSAGE, /* counted as unread */
	TUI_LINE_HIGHLIGHT, /* our nick was mentioned */
};

struct tui_nick {
	char name[TUI_NICK_NAME_MAX];
	int color; /* 1 to TUI_NICK_COLORS */
	int away;
	int self;
	int verified;
	int devices; /* sessions of the same identity */
};

struct tui_window {
	char name[TUI_NAME_MAX];
	char title[TUI_TEXT_MAX];
	char state[64]; /* "connected", "connecting..." */
	char *lines[TUI_LINES_MAX];
	size_t first;
	size_t count;
	int scroll; /* rows scrolled back from the bottom */
	uint64_t dropped; /* lines removed from the front so far */
	uint64_t marker; /* 1 + number of the first unread line, 0: none */
	int unread;
	int highlight;
	struct tui_nick *nicks;
	size_t nick_count;
};

struct tui_ops {
	void (*submit)(void *ud, const char *line);
	void (*quit)(void *ud);
	/* optional: every line printed, without escape sequences */
	void (*line)(void *ud, int win, const char *text);
};

struct tui {
	int fullscreen;
	int colors;
	int rows;
	int cols;
	int dirty;
	int too_small;

	struct tui_window *win[TUI_WINDOWS_MAX];
	int win_count;
	int cur;
	char nick[STS_NICK_MAX + 1];
	int nick_color;
	char extra[TUI_TEXT_MAX]; /* end of the status bar */

	char input[TUI_INPUT_MAX];
	size_t input_len;
	size_t cursor;
	char *history[TUI_HISTORY_MAX];
	int history_count;
	int history_pos; /* -1 when editing a new line */
	char saved[TUI_INPUT_MAX];

	/* tab completion */
	int completing;
	size_t comp_start;
	char comp_prefix[TUI_NICK_NAME_MAX];
	int comp_index;
	const char *const *commands;

	/* incomplete escape sequence or line */
	char pending[TUI_INPUT_MAX];
	size_t pending_len;
	uint64_t pending_ms;

	struct tui_ops ops;
	void *ud;
};

/*
 * @fullscreen  0 for plain mode
 * @colors      use colors
 * @commands    NULL terminated, for completion
 */
int tui_init(struct tui *t, int fullscreen, int colors,
	     const char *const *commands, const struct tui_ops *ops, void *ud);
void tui_end(struct tui *t);

/* @return the new window's index, or -1 */
int tui_window_add(struct tui *t, const char *name);
void tui_window_remove(struct tui *t, int win);
void tui_window_select(struct tui *t, int win);
int tui_window_find(const struct tui *t, const char *name);

/* @brief add a line, the time of day is prepended */
void tui_print(struct tui *t, int win, enum tui_line_kind kind, const char *fmt,
	       ...) STS_PRINTF(4, 5);

void tui_set_title(struct tui *t, int win, const char *title);
void tui_set_state(struct tui *t, int win, const char *state);
void tui_set_nicks(struct tui *t, int win, const struct tui_nick *nicks,
		   size_t count);
void tui_set_self(struct tui *t, const char *nick, int color);
/* @brief text at the end of the status bar, for every window */
void tui_set_extra(struct tui *t, const char *text);
void tui_clear(struct tui *t, int win);

/* @brief feed bytes read from the keyboard or stdin */
void tui_feed(struct tui *t, const char *buf, size_t len);

/* @brief end of input (plain mode) */
void tui_eof(struct tui *t);

/* @brief timers and resizing, call regularly */
void tui_tick(struct tui *t);

/* @brief draw if anything changed */
void tui_render(struct tui *t);

#define TUI_NICK_COLORS 11 /* numbered 1 to 11, 0 is the default */

/*
 * @return the usual color of a person: from their fingerprint and nick,
 *         the same on every screen. A room may give another one when
 *         someone present already has it.
 */
int tui_nick_color(const uint8_t *fpr, const char *nick);

/* @return SGR sequence for a nick color (empty without colors) */
const char *tui_color(const struct tui *t, int color);
/* @return @seq, or "" without colors */
const char *tui_sgr(const struct tui *t, const char *seq);

/* @return columns used by @s, escape sequences excluded */
size_t tui_text_width(const char *s);

#endif /* STS_TUI_H */
