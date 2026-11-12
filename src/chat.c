// SPDX-License-Identifier: Apache-2.0
/*
 * The chat application: one MQTT connection and one protocol session per
 * room, the user interface and the commands.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chat.h"
#include "crypto.h"
#include "log.h"
#include "mqtt.h"
#include "room.h"
#include "setup.h"
#include "transfer.h"
#include "trust.h"
#include "tui.h"
#include "util.h"

#define STATUS_WIN 0
#define TICK_MS 100
#define RETRY_MIN_S 1
#define RETRY_MAX_S 60
#define QUIT_TIMEOUT_MS 4000
#define READ_CHUNK 4096

struct app;

struct chat_room {
	struct app *app;
	char name[STS_ROOM_MAX + 1];
	int has_password;
	struct sts_room room;
	struct sts_mqtt mqtt;
	char topic[STS_MQTT_TOPIC_MAX];
	char client_id[STS_MQTT_CLIENTID_MAX];
	int ready;
	int ever_ready;
	int parting; /* LEAVE sent, closing the connection */
	uint64_t retry_ms; /* reconnect then, 0 if not planned */
	int backoff_s;
	int nicks_dirty;
	int hinted; /* last hint given about connection errors */
	size_t people; /* shown in the title */
	struct sts_xfers xfers;
	FILE *log; /* chat log, if asked for */
	/* the color given to each person (fingerprint and nick) seen */
	struct nick_color {
		uint8_t fpr[STS_HASH_LEN];
		char nick[STS_NICK_MAX + 1];
		int color;
	} colors[STS_MAX_MEMBERS + 1];
	size_t ncolors;
};

struct app {
	const struct sts_config *cfg;
	struct sts_identity id;
	struct sts_trust trust;
	struct tui tui;
	struct chat_room *rooms[TUI_WINDOWS_MAX]; /* by window */
	char nick[STS_NICK_MAX + 1];
	int input_eof;
	int quitting;
	uint64_t quit_deadline_ms;
	int done;
	unsigned int xfer_counter;
};

static const char *const commands[] = {
	"/accept",  "/cancel", "/clear", "/files", "/fingerprint", "/help",
	"/join",    "/me",     "/msg",	 "/names", "/nick",	   "/part",
	"/quit",    "/refuse", "/rekey", "/send",  "/status",	   "/trust",
	"/untrust", "/who",    "/whois", "/win",   NULL,
};

static struct app *log_app;

/* --- output -------------------------------------------------------------- */

#define say(a, win, ...) \
	tui_print(&(a)->tui, (win), TUI_LINE_NOTICE, __VA_ARGS__)

/* "-!- " notice prefix */
static const char *bang(const struct app *a)
{
	return a->tui.colors ? "\033[2;36m-!-\033[0m " : "-!- ";
}

static const char *sgr(const struct app *a, const char *seq)
{
	return tui_sgr(&a->tui, seq);
}

static const char *ncolor(const struct app *a, int color)
{
	return tui_color(&a->tui, color);
}

static void log_sink(enum sts_log_level level, const char *line)
{
	struct app *a = log_app;

	if (a == NULL) {
		fprintf(stderr, "%s\n", line);
		return;
	}
	tui_print(&a->tui, a->tui.cur, TUI_LINE_NOTICE, "%s%s%s%s", bang(a),
		  level <= STS_LOG_WARN ? sgr(a, "\033[33m") : "", line,
		  sgr(a, TUI_RESET));
}

static int room_win(const struct app *a, const struct chat_room *cr)
{
	int i;

	for (i = 0; i < a->tui.win_count; i++)
		if (a->rooms[i] == cr)
			return i;
	return STATUS_WIN;
}

static struct chat_room *current_room(struct app *a)
{
	int cur = a->tui.cur;

	if (cur < 0 || cur >= TUI_WINDOWS_MAX)
		return NULL;
	return a->rooms[cur];
}

static void member_name(const struct chat_room *cr, const struct sts_member *m,
			char *out, size_t cap)
{
	sts_room_display_name(&cr->room, m, out, cap);
}

static const char *trust_label(const struct app *a, const uint8_t *fpr)
{
	size_t i;

	if (memcmp(fpr, a->id.fpr, STS_HASH_LEN) == 0)
		return "you";
	for (i = 0; i < a->trust.count; i++)
		if (memcmp(a->trust.entries[i].fpr, fpr, STS_HASH_LEN) == 0)
			return a->trust.entries[i].verified ? "verified" :
							      "not verified";
	return "new";
}

/* --- nick list and titles ------------------------------------------------ */

static int same_identity_count(const struct chat_room *cr, const uint8_t *fpr)
{
	int n = memcmp(fpr, cr->app->id.fpr, STS_HASH_LEN) == 0;
	size_t i;

	for (i = 0; i < STS_MEMBER_SLOTS; i++) {
		const struct sts_member *m = cr->room.members[i];

		if (m != NULL &&
		    (m->state == STS_MEMBER_ACTIVE ||
		     m->state == STS_MEMBER_AWAY) &&
		    memcmp(m->fpr, fpr, STS_HASH_LEN) == 0)
			n++;
	}
	return n;
}

static void update_title(struct app *a, struct chat_room *cr)
{
	const struct sts_config *cfg = a->cfg;
	char title[TUI_TEXT_MAX];

	snprintf(title, sizeof(title),
		 "#%s - %zu %s - %s:%d%s - end-to-end encrypted%s", cr->name,
		 cr->people, cr->people == 1 ? "person" : "people", cfg->broker,
		 cfg->port, cfg->tls ? " (TLS)" : "",
		 cr->has_password ? ", password protected" : "");
	tui_set_title(&a->tui, room_win(a, cr), title);
}

/* @fpr with @nick is in the room now: us, or a member */
static int present(struct chat_room *cr, const uint8_t *fpr, const char *nick)
{
	size_t i;

	if (memcmp(fpr, cr->app->id.fpr, STS_HASH_LEN) == 0 &&
	    strcmp(nick, cr->room.nick) == 0)
		return 1;
	for (i = 0; i < STS_MEMBER_SLOTS; i++) {
		const struct sts_member *m = cr->room.members[i];

		if (m != NULL &&
		    (m->state == STS_MEMBER_ACTIVE ||
		     m->state == STS_MEMBER_AWAY) &&
		    memcmp(m->fpr, fpr, STS_HASH_LEN) == 0 &&
		    strcmp(m->nick, nick) == 0)
			return 1;
	}
	return 0;
}

/*
 * The color of a person in a room: their usual one (tui_nick_color()),
 * or, if someone present already has it, the next free one. Once given it
 * stays, so that two people never share a color while there are enough.
 */
static int room_color(struct chat_room *cr, const uint8_t *fpr,
		      const char *nick)
{
	int taken[TUI_NICK_COLORS + 1] = { 0 };
	int want = tui_nick_color(fpr, nick);
	struct nick_color *e = NULL;
	size_t i;
	int k;

	for (i = 0; i < cr->ncolors; i++)
		if (memcmp(cr->colors[i].fpr, fpr, STS_HASH_LEN) == 0 &&
		    strcmp(cr->colors[i].nick, nick) == 0)
			return cr->colors[i].color;

	for (i = 0; i < cr->ncolors; i++)
		if (present(cr, cr->colors[i].fpr, cr->colors[i].nick))
			taken[cr->colors[i].color] = 1;
		else if (e == NULL)
			e = &cr->colors[i]; /* someone gone: reuse */
	if (cr->ncolors < STS_ARRAY_SIZE(cr->colors))
		e = &cr->colors[cr->ncolors++];
	if (e == NULL)
		return want;

	for (k = 0; k < TUI_NICK_COLORS; k++) {
		int color = 1 + (want - 1 + k) % TUI_NICK_COLORS;

		if (!taken[color]) {
			want = color;
			break;
		}
	}
	memcpy(e->fpr, fpr, STS_HASH_LEN);
	sts_strlcpy(e->nick, nick, sizeof(e->nick));
	e->color = want;
	return want;
}

static int member_color(struct chat_room *cr, const struct sts_member *m)
{
	return room_color(cr, m->fpr, m->nick);
}

static int self_color(struct chat_room *cr)
{
	return room_color(cr, cr->app->id.fpr, cr->room.nick);
}

static void update_nicks(struct app *a, struct chat_room *cr)
{
	static struct tui_nick list[STS_MAX_MEMBERS + 1];
	size_t n = 0;
	size_t i;

	memset(&list[0], 0, sizeof(list[0]));
	sts_strlcpy(list[0].name, cr->room.nick, sizeof(list[0].name));
	list[0].color = self_color(cr);
	list[0].self = 1;
	list[0].devices = same_identity_count(cr, a->id.fpr);
	n = 1;

	for (i = 0; i < STS_MEMBER_SLOTS && n < STS_ARRAY_SIZE(list); i++) {
		const struct sts_member *m = cr->room.members[i];
		struct tui_nick *e = &list[n];

		if (m == NULL || (m->state != STS_MEMBER_ACTIVE &&
				  m->state != STS_MEMBER_AWAY))
			continue;
		memset(e, 0, sizeof(*e));
		member_name(cr, m, e->name, sizeof(e->name));
		e->color = member_color(cr, m);
		e->away = m->state == STS_MEMBER_AWAY;
		e->verified = sts_trust_is_verified(&a->trust, m->fpr);
		e->devices = same_identity_count(cr, m->fpr);
		n++;
	}
	tui_set_nicks(&a->tui, room_win(a, cr), list, n);
	cr->people = n;
	update_title(a, cr);
	cr->nicks_dirty = 0;
}

static void update_state(struct app *a, struct chat_room *cr)
{
	const char *state;
	char buf[64];

	if (cr->ready)
		state = "connected";
	else if (!sts_mqtt_is_closed(&cr->mqtt))
		state = "connecting...";
	else if (cr->retry_ms != 0) {
		uint64_t now = sts_monotonic_ms();
		unsigned int s =
			cr->retry_ms > now ?
				(unsigned int)((cr->retry_ms - now + 999) /
					       1000) :
				0;

		snprintf(buf, sizeof(buf), "disconnected, retry in %us", s);
		state = buf;
	} else {
		state = "disconnected";
	}
	tui_set_state(&a->tui, room_win(a, cr), state);
}

/* --- room events --------------------------------------------------------- */

/* "nick" in its color */
static void colored(const struct app *a, int color, const char *name, char *out,
		    size_t cap)
{
	snprintf(out, cap, "%s%s%s", ncolor(a, color), name,
		 sgr(a, "\033[39m"));
}

static int mentions(const char *text, const char *nick)
{
	size_t n = strlen(nick);
	const char *p;

	if (n == 0)
		return 0;
	for (p = text; *p != '\0'; p++) {
		if (sts_strncasecmp(p, nick, n) != 0)
			continue;
		if ((p == text || !sts_nick_valid(p - 1, 1)) &&
		    (p[n] == '\0' || !sts_nick_valid(p + n, 1)))
			return 1;
	}
	return 0;
}

static void on_join(struct app *a, struct chat_room *cr,
		    const struct sts_event *ev)
{
	const struct sts_member *m = ev->member;
	enum sts_trust_status st;
	char fpr[STS_FPR_SHORT_STR_LEN];
	char name[TUI_NICK_NAME_MAX];
	char who[TUI_NICK_NAME_MAX + 32];
	int win = room_win(a, cr);

	member_name(cr, m, name, sizeof(name));
	colored(a, member_color(cr, m), name, who, sizeof(who));
	sts_fpr_format_short(m->fpr, fpr);

	if (memcmp(m->fpr, a->id.fpr, STS_HASH_LEN) == 0) {
		say(a, win, "%s%s joined from another device of yours", bang(a),
		    who);
		return;
	}
	if (ev->other_devices > 0) {
		say(a, win, "%s%s joined from another device [%s]", bang(a),
		    who, fpr);
		return;
	}

	st = sts_trust_observe(&a->trust, m->fpr, m->nick);
	switch (st) {
	case STS_TRUST_VERIFIED:
		say(a, win, "%s%s [%s] joined %s(verified)%s", bang(a), who,
		    fpr, sgr(a, "\033[32m"), sgr(a, TUI_RESET));
		break;
	case STS_TRUST_KNOWN:
		say(a, win, "%s%s [%s] joined", bang(a), who, fpr);
		break;
	case STS_TRUST_NEW:
		say(a, win, "%s%s [%s] joined (first time seen)", bang(a), who,
		    fpr);
		break;
	case STS_TRUST_CONFLICT:
		say(a, win,
		    "%s%sWARNING:%s %s [%s] joined with a key that is NOT the one this nick used before. Check with /whois %s",
		    bang(a), sgr(a, "\033[1;91m"), sgr(a, TUI_RESET), who, fpr,
		    name);
		break;
	}
}

static void on_message(struct app *a, struct chat_room *cr,
		       const struct sts_event *ev)
{
	const struct sts_member *m = ev->member;
	char text[STS_TEXT_MAX * 2 + 1];
	char name[TUI_NICK_NAME_MAX];
	char who[TUI_NICK_NAME_MAX + 32];
	enum tui_line_kind kind = TUI_LINE_MESSAGE;
	int win = room_win(a, cr);
	const char *late = "";

	sts_sanitize(ev->text, ev->text_len, text, sizeof(text));
	member_name(cr, m, name, sizeof(name));
	colored(a, member_color(cr, m), name, who, sizeof(who));
	if (mentions(text, cr->room.nick) || ev->is_private)
		kind = TUI_LINE_HIGHLIGHT;
	if (ev->late)
		late = a->tui.colors ? "\033[2m(late)\033[0m " : "(late) ";

	if (ev->is_private && ev->kind == STS_KIND_ACTION)
		tui_print(&a->tui, win, kind, "%s%s(private)%s * %s %s", late,
			  sgr(a, "\033[1;95m"), sgr(a, TUI_RESET), who, text);
	else if (ev->is_private)
		tui_print(&a->tui, win, kind, "%s%s(private)%s <%s> %s", late,
			  sgr(a, "\033[1;95m"), sgr(a, TUI_RESET), who, text);
	else if (ev->kind == STS_KIND_ACTION)
		tui_print(&a->tui, win, kind, "%s * %s %s", late, who, text);
	else
		tui_print(&a->tui, win, kind, "%s<%s> %s", late, who, text);
}

static void room_event(void *ud, const struct sts_event *ev)
{
	struct chat_room *cr = ud;
	struct app *a = cr->app;
	int win = room_win(a, cr);
	char name[TUI_NICK_NAME_MAX];
	char who[TUI_NICK_NAME_MAX + 32];
	static const char *const reasons[] = {
		[STS_LEAVE_QUIT] = "left",
		[STS_LEAVE_TIMEOUT] = "timed out",
		[STS_LEAVE_LOST] = "is gone",
	};

	if (ev->member != NULL) {
		member_name(cr, ev->member, name, sizeof(name));
		colored(a, member_color(cr, ev->member), name, who,
			sizeof(who));
	} else {
		name[0] = '\0';
		who[0] = '\0';
	}

	switch (ev->type) {
	case STS_EV_JOIN:
		on_join(a, cr, ev);
		cr->nicks_dirty = 1;
		break;
	case STS_EV_LEAVE:
		say(a, win, "%s%s %s", bang(a), who,
		    reasons[ev->reason <= STS_LEAVE_LOST ? ev->reason : 0]);
		sts_xfers_gone(&cr->xfers, ev->member->sid);
		cr->nicks_dirty = 1;
		break;
	case STS_EV_AWAY:
		say(a, win, "%s%s lost the connection (may come back)", bang(a),
		    who);
		cr->nicks_dirty = 1;
		break;
	case STS_EV_BACK:
		say(a, win, "%s%s is back", bang(a), who);
		cr->nicks_dirty = 1;
		break;
	case STS_EV_NICK:
		say(a, win, "%s%s is now known as %s", bang(a), ev->old_nick,
		    who);
		if (memcmp(ev->member->fpr, a->id.fpr, STS_HASH_LEN) != 0)
			sts_trust_observe(&a->trust, ev->member->fpr,
					  ev->member->nick);
		cr->nicks_dirty = 1;
		break;
	case STS_EV_FILE:
		sts_xfers_handle(&cr->xfers, ev->member, ev->text,
				 ev->text_len);
		break;
	case STS_EV_MESSAGE:
		on_message(a, cr, ev);
		break;
	case STS_EV_NOTICE:
		if (ev->member != NULL)
			say(a, win, "%s%s: %s", bang(a), who, ev->notice);
		else
			say(a, win, "%s%s", bang(a), ev->notice);
		break;
	}
}

static int room_send(void *ud, const uint8_t *frame, size_t len)
{
	struct chat_room *cr = ud;

	return sts_mqtt_publish(&cr->mqtt, frame, len);
}

static const struct sts_room_ops room_ops = {
	.send = room_send,
	.event = room_event,
};

/* --- file transfers ----------------------------------------------------- */

static void xfer_event(void *ud, const struct sts_xfer_event *ev)
{
	struct chat_room *cr = ud;
	struct app *a = cr->app;
	const struct sts_xfer *x = ev->xfer;
	const struct sts_member *m = sts_room_member(&cr->room, x->sid);
	int win = room_win(a, cr);
	char who[TUI_NICK_NAME_MAX + 32];
	char size[32];
	char speed[64] = "";
	uint64_t secs;

	colored(a, m != NULL ? member_color(cr, m) : 0, x->nick, who,
		sizeof(who));
	sts_xfer_size_str(x->size, size, sizeof(size));

	switch (ev->type) {
	case STS_XFER_EV_OFFER:
		tui_print(
			&a->tui, win, TUI_LINE_HIGHLIGHT,
			"%s%s wants to send you %s%s%s (%s): %s/accept %u%s or /refuse %u",
			bang(a), who, sgr(a, TUI_BOLD), x->name,
			sgr(a, TUI_RESET), size, sgr(a, TUI_BOLD), x->num,
			sgr(a, TUI_RESET), x->num);
		break;
	case STS_XFER_EV_ACCEPTED:
		say(a, win, "%s%s accepted %s, sending...", bang(a), who,
		    x->name);
		break;
	case STS_XFER_EV_REFUSED:
		say(a, win, "%s%s refused %s", bang(a), who, x->name);
		break;
	case STS_XFER_EV_PROGRESS:
		/* the full screen has the progress bar instead */
		if (!a->tui.fullscreen)
			say(a, win, "%s%s: %d%%", bang(a), x->name,
			    ev->percent);
		break;
	case STS_XFER_EV_DONE:
		secs = (sts_monotonic_ms() - x->started_ms) / 1000;
		if (secs > 0)
			snprintf(speed, sizeof(speed), " in %llu s",
				 (unsigned long long)secs);
		if (x->outgoing)
			say(a, win, "%s%s received %s (%s%s)", bang(a), who,
			    x->name, size, speed);
		else
			tui_print(
				&a->tui, win, TUI_LINE_MESSAGE,
				"%sreceived %s from %s (%s%s, SHA-256 checked): %s",
				bang(a), x->name, who, size, speed, ev->detail);
		break;
	case STS_XFER_EV_TOO_BIG: {
		char max[32];

		sts_xfer_size_str(cr->xfers.max_size, max, sizeof(max));
		say(a, win,
		    "%s%s wanted to send you %s (%s), bigger than your max_file_size (%s): refused",
		    bang(a), who, x->name, size, max);
		break;
	}
	case STS_XFER_EV_FAILED:
		say(a, win, "%s%s%s %s failed: %s%s", bang(a),
		    sgr(a, "\033[33m"), x->outgoing ? "sending" : "receiving",
		    x->name, ev->detail, sgr(a, TUI_RESET));
		break;
	}
}

static int xfer_can_send(void *ud)
{
	struct chat_room *cr = ud;

	return cr->ready && sts_mqtt_unacked(&cr->mqtt) < 256;
}

static void rate_str(uint64_t bytes_per_s, char *out, size_t cap)
{
	if (bytes_per_s >= 1024 * 1024)
		snprintf(out, cap, "%.1f MB/s",
			 (double)bytes_per_s / (1024 * 1024));
	else
		snprintf(out, cap, "%.0f KB/s", (double)bytes_per_s / 1024);
}

/* the first running transfer as a bar at the end of the status bar */
static void update_progress(struct app *a)
{
	static uint64_t last_ms;
	const struct sts_xfer *first = NULL;
	uint64_t now = sts_monotonic_ms();
	char text[TUI_TEXT_MAX];
	char bar[16];
	char rate[32] = "";
	char left[32] = "";
	char more[24] = "";
	int count = 0;
	int filled;
	int i;
	int k;

	if (now - last_ms < 250)
		return;
	last_ms = now;

	for (i = 0; i < a->tui.win_count; i++) {
		struct chat_room *cr = a->rooms[i];

		for (k = 0; cr != NULL && k < STS_XFER_SLOTS; k++) {
			const struct sts_xfer *x = &cr->xfers.x[k];

			if (x->state != STS_XFER_ACTIVE)
				continue;
			if (first == NULL)
				first = x;
			count++;
		}
	}
	if (first == NULL) {
		tui_set_extra(&a->tui, "");
		return;
	}

	filled = first->size ? (int)(first->done * 10 / first->size) : 10;
	for (i = 0; i < 10; i++)
		bar[i] = i < filled ? '#' : '-';
	bar[10] = '\0';
	if (now > first->started_ms && first->done > 0) {
		uint64_t speed = first->done * 1000 / (now - first->started_ms);

		rate_str(speed, rate, sizeof(rate));
		if (speed > 0)
			snprintf(left, sizeof(left), " %llus left",
				 (unsigned long long)((first->size -
						       first->done) /
						      speed));
	}
	if (count > 1)
		snprintf(more, sizeof(more), " (+%d more)", count - 1);
	snprintf(text, sizeof(text), "[%u] %s %s [%s] %d%% %s%s /cancel %u%s",
		 first->num, first->outgoing ? "->" : "<-", first->name, bar,
		 first->percent, rate, left, first->num, more);
	tui_set_extra(&a->tui, text);
}

static const struct sts_xfer_ops xfer_ops = {
	.event = xfer_event,
	.can_send = xfer_can_send,
};

/* --- connection ---------------------------------------------------------- */

static void free_room(struct app *a, struct chat_room *cr);

static void schedule_retry(struct chat_room *cr)
{
	uint32_t jitter = 0;

	cr->backoff_s = cr->backoff_s == 0 ? RETRY_MIN_S : cr->backoff_s * 2;
	if (cr->backoff_s > RETRY_MAX_S)
		cr->backoff_s = RETRY_MAX_S;
	sts_random(&jitter, sizeof(jitter));
	cr->retry_ms = sts_monotonic_ms() + (uint64_t)cr->backoff_s * 1000 +
		       jitter % 1000;
}

static void on_ready(void *ud, int session_present)
{
	struct chat_room *cr = ud;
	struct app *a = cr->app;
	int win = room_win(a, cr);

	(void)session_present;
	cr->ready = 1;
	cr->backoff_s = 0;
	cr->retry_ms = 0;
	if (cr->ever_ready)
		say(a, win, "%sreconnected", bang(a));
	else
		say(a, win, "%sconnected to %s:%d%s, joined #%s", bang(a),
		    a->cfg->broker, a->cfg->port,
		    a->cfg->tls ? " over TLS" : "", cr->name);
	cr->ever_ready = 1;
	sts_room_connected(&cr->room);
	update_state(a, cr);
}

static void on_frame(void *ud, const uint8_t *frame, size_t len)
{
	struct chat_room *cr = ud;

	sts_room_handle(&cr->room, frame, len);
}

/* what to do about common connection errors, said once per room */
static void hint(struct app *a, struct chat_room *cr, const char *reason)
{
	const struct sts_config *cfg = a->cfg;
	const char *text = NULL;
	int kind = 0;

	if (strstr(reason, "certificate") != NULL) {
		kind = 1;
		text = cfg->tls_ca_file[0] != '\0' ?
			       "the broker's certificate isn't signed by the authority in tls_ca_file (--ca-file), or isn't made for this host name" :
			       "the broker's certificate isn't signed by an authority your system knows: get the broker's CA file and give it with tls_ca_file (--ca-file), see doc/TLS.md";
	} else if (strstr(reason, "not authorized") != NULL ||
		   strstr(reason, "user name or password") != NULL) {
		kind = 2;
		text = cfg->username[0] != '\0' ?
			       "the broker refuses this username and password" :
			       "the broker wants an account: set username and password (-u, -P), or allow_anonymous true on your own mosquitto";
	} else if (strstr(reason, "subscription") != NULL) {
		kind = 3;
		text = "the broker doesn't allow this topic: check its access rules (acl_file) or the topic_prefix";
	} else if (cfg->tls &&
		   (strstr(reason, "TLS") != NULL ||
		    strstr(reason, "closed by the broker") != NULL)) {
		kind = 4;
		text = "is TLS really on this port? Usually 8883 with TLS, 1883 without";
	} else if (!cfg->tls &&
		   (strstr(reason, "didn't answer") != NULL ||
		    strstr(reason, "closed by the broker") != NULL)) {
		kind = 5;
		text = "if this port uses TLS, add tls = yes (--tls)";
	}
	if (text == NULL || cr->hinted == kind)
		return;
	cr->hinted = kind;
	say(a, room_win(a, cr), "%s%s", bang(a), text);
}

static void on_lost(void *ud, const char *reason)
{
	struct chat_room *cr = ud;
	struct app *a = cr->app;

	cr->ready = 0;
	sts_room_disconnected(&cr->room);
	if (cr->parting || a->quitting)
		return;
	schedule_retry(cr);
	say(a, room_win(a, cr), "%s%s%s%s, retrying in %d s", bang(a),
	    sgr(a, "\033[33m"), reason, sgr(a, TUI_RESET), cr->backoff_s);
	hint(a, cr, reason);
	update_state(a, cr);
	cr->nicks_dirty = 1;
}

static const struct sts_mqtt_cb mqtt_cb = {
	.ready = on_ready,
	.message = on_frame,
	.lost = on_lost,
};

static void connect_room(struct app *a, struct chat_room *cr)
{
	static uint8_t will[STS_MQTT_WILL_MAX];
	const struct sts_config *cfg = a->cfg;
	struct sts_mqtt_opts o;
	size_t will_len = 0;

	cr->retry_ms = 0;
	if (sts_room_prepare_connect(&cr->room, will, sizeof(will),
				     &will_len) != 0)
		will_len = 0;

	memset(&o, 0, sizeof(o));
	o.host = cfg->broker;
	o.port = cfg->port;
	o.tls = cfg->tls;
	o.tls_ca_file = cfg->tls_ca_file;
	o.tls_verify = cfg->tls_verify;
	o.username = cfg->username;
	o.password = cfg->password;
	o.client_id = cr->client_id;
	o.topic = cr->topic;
	o.keepalive_s = cfg->keepalive;
	o.clean_session = 0; /* the broker keeps messages for a while */
	o.will = will;
	o.will_len = will_len;

	if (sts_mqtt_connect(&cr->mqtt, &o) != 0) {
		schedule_retry(cr);
		say(a, room_win(a, cr), "%s%s%s%s, retrying in %d s", bang(a),
		    sgr(a, "\033[33m"), cr->mqtt.error, sgr(a, TUI_RESET),
		    cr->backoff_s);
	}
	sts_memzero(will, sizeof(will));
	update_state(a, cr);
}

static struct chat_room *find_room(struct app *a, const char *name)
{
	int i;

	for (i = 0; i < a->tui.win_count; i++)
		if (a->rooms[i] != NULL &&
		    sts_strcasecmp(a->rooms[i]->name, name) == 0)
			return a->rooms[i];
	return NULL;
}

static void open_log(struct app *a, struct chat_room *cr);

static int join_room(struct app *a, const char *name, const char *password)
{
	struct chat_room *cr;
	char wname[TUI_NAME_MAX];
	char lower[STS_ROOM_MAX + 1];
	uint8_t rnd[8];
	size_t i;
	int win;

	if (name[0] == '#')
		name++;
	if (!sts_room_valid(name)) {
		say(a, a->tui.cur,
		    "%sinvalid room name '%s': letters, digits, '-', '_' and '.', at most %d",
		    bang(a), name, STS_ROOM_MAX);
		return -1;
	}
	/* room names ignore case: show them as everybody else does */
	for (i = 0; name[i] != '\0'; i++)
		lower[i] = (char)(name[i] >= 'A' && name[i] <= 'Z' ?
					  name[i] - 'A' + 'a' :
					  name[i]);
	lower[i] = '\0';
	name = lower;
	cr = find_room(a, name);
	if (cr != NULL) {
		tui_window_select(&a->tui, room_win(a, cr));
		return 0;
	}

	cr = calloc(1, sizeof(*cr));
	if (cr == NULL)
		return -1;
	cr->app = a;
	sts_strlcpy(cr->name, name, sizeof(cr->name));
	cr->has_password = password != NULL && password[0] != '\0';

	/* derives the room keys: takes a moment on purpose */
	if (sts_room_init(&cr->room, &a->id, name, password, a->nick,
			  (unsigned int)a->cfg->rekey_interval, &room_ops,
			  cr) != 0 ||
	    sts_config_topic(a->cfg, cr->room.keys.topic_hex, cr->topic,
			     sizeof(cr->topic)) != 0 ||
	    sts_random(rnd, sizeof(rnd)) != 0) {
		say(a, a->tui.cur, "%scannot set up #%s", bang(a), name);
		sts_room_free(&cr->room);
		free(cr);
		return -1;
	}
	/* same id at each reconnection: the broker keeps our session */
	memcpy(cr->client_id, "sts-", 4);
	sts_hex(rnd, sizeof(rnd), cr->client_id + 4);
	sts_mqtt_init(&cr->mqtt, &mqtt_cb, cr);
	sts_xfers_init(&cr->xfers, &cr->room, &a->xfer_counter, &xfer_ops, cr);
	cr->xfers.max_size = a->cfg->max_file_size;

	snprintf(wname, sizeof(wname), "#%s", name);
	win = tui_window_add(&a->tui, wname);
	if (win < 0) {
		say(a, a->tui.cur, "%stoo many windows", bang(a));
		sts_mqtt_free(&cr->mqtt);
		sts_room_free(&cr->room);
		free(cr);
		return -1;
	}
	a->rooms[win] = cr;
	tui_window_select(&a->tui, win);
	tui_set_self(&a->tui, cr->room.nick, self_color(cr));
	update_nicks(a, cr);
	open_log(a, cr);
	say(a, win, "%sjoining #%s%s...", bang(a), name,
	    cr->has_password ? " (with password)" : "");
	connect_room(a, cr);
	return 0;
}

static void free_room(struct app *a, struct chat_room *cr)
{
	int win = room_win(a, cr);

	sts_xfers_free(&cr->xfers);
	if (cr->log != NULL)
		fclose(cr->log);
	sts_mqtt_free(&cr->mqtt);
	sts_room_free(&cr->room);
	if (win != STATUS_WIN) {
		memmove(&a->rooms[win], &a->rooms[win + 1],
			(size_t)(TUI_WINDOWS_MAX - win - 1) *
				sizeof(a->rooms[0]));
		a->rooms[TUI_WINDOWS_MAX - 1] = NULL;
		tui_window_remove(&a->tui, win);
	}
	sts_memzero(cr, sizeof(*cr));
	free(cr);
}

/* say goodbye and close: completes in the main loop */
static void part_room(struct app *a, struct chat_room *cr)
{
	if (cr->parting)
		return;
	cr->parting = 1;
	if (cr->ready) {
		sts_room_leave(&cr->room);
		sts_mqtt_shutdown(&cr->mqtt);
	} else {
		sts_mqtt_abort(&cr->mqtt);
	}
	(void)a;
}

/* --- commands ------------------------------------------------------------ */

static void cmd_help(struct app *a)
{
	static const char *const lines[] = {
		"Commands:",
		"  /join ROOM [PASSWORD]  join (or create) a room, in a new window",
		"  /part [ROOM]           leave the room",
		"  /msg NICK TEXT         private message to someone in the room",
		"  /me TEXT               action: * you TEXT",
		"  /send NICK FILE        send a file to someone in the room",
		"  /accept [N] [DIR]      accept file N (into ~/Downloads, or DIR)",
		"  /refuse [N]            refuse file N",
		"  /cancel N              stop transfer N",
		"  /files                 transfers in progress",
		"  /nick NICK             change your nick",
		"  /who                   who is in the room (also on the right)",
		"  /whois NICK            fingerprint and details of someone",
		"  /trust NICK            mark NICK's key as verified, after",
		"                         comparing fingerprints in person",
		"  /untrust NICK          remove the verified mark",
		"  /fingerprint           your own fingerprint",
		"  /status                connection and encryption details",
		"  /rekey                 renew your keys now",
		"  /win N                 go to window N (also Alt-N, Ctrl-N, Ctrl-P)",
		"  /clear                 clear the window",
		"  /quit                  leave all rooms and exit (also Ctrl-C)",
		"Keys: PgUp/PgDn scroll, Tab completes nicks and commands,",
		"      Up/Down history, Ctrl-A/E/U/K/W edit the line.",
		"Nick list: + verified, dim = connection lost, (2) = devices.",
	};
	size_t i;

	for (i = 0; i < STS_ARRAY_SIZE(lines); i++)
		say(a, a->tui.cur, "%s", lines[i]);
}

static struct chat_room *need_room(struct app *a)
{
	struct chat_room *cr = current_room(a);

	if (cr == NULL)
		say(a, a->tui.cur,
		    "%sthis is the status window: /join ROOM first, or Alt-2 for your room",
		    bang(a));
	return cr;
}

/* @return the member named @name, or NULL after saying why */
static const struct sts_member *need_member(struct app *a, struct chat_room *cr,
					    const char *name)
{
	const struct sts_member *m;
	int ambiguous = 0;

	if (name == NULL || name[0] == '\0') {
		say(a, a->tui.cur, "%swho? give a nick", bang(a));
		return NULL;
	}
	m = sts_room_find(&cr->room, name, &ambiguous);
	if (ambiguous) {
		say(a, a->tui.cur,
		    "%sseveral people are called %s: add the fingerprint, like %s#ab12 (see /who)",
		    bang(a), name, name);
		return NULL;
	}
	if (m == NULL)
		say(a, a->tui.cur, "%sno %s in #%s", bang(a), name, cr->name);
	return m;
}

/* send @text in pieces of at most STS_TEXT_MAX bytes, cut between characters */
static void send_text(struct app *a, struct chat_room *cr,
		      enum sts_msg_kind kind, const char *text,
		      const struct sts_member *to)
{
	size_t len = strlen(text);
	char who[TUI_NICK_NAME_MAX + 32];
	char name[TUI_NICK_NAME_MAX];
	int win = room_win(a, cr);
	size_t n;
	int sent;

	while (len > 0) {
		n = len > STS_TEXT_MAX ? STS_TEXT_MAX : len;
		while (n < len && n > 0 &&
		       ((unsigned char)text[n] & 0xc0) == 0x80)
			n--;

		if (to != NULL) {
			sent = sts_room_send_private(&cr->room, to->fpr, kind,
						     text, n);
			if (sent <= 0) {
				say(a, win, "%scannot send to %s", bang(a),
				    to->nick);
				return;
			}
		} else if (sts_room_send(&cr->room, kind, text, n) != 0) {
			say(a, win, "%scannot send: too many messages waiting",
			    bang(a));
			return;
		}

		colored(a, self_color(cr), cr->room.nick, who, sizeof(who));
		if (to != NULL) {
			member_name(cr, to, name, sizeof(name));
			tui_print(&a->tui, win, TUI_LINE_NOTICE,
				  "%s(private to %s)%s %s<%s> %.*s",
				  sgr(a, "\033[95m"), name, sgr(a, TUI_RESET),
				  kind == STS_KIND_ACTION ? "* " : "", who,
				  (int)n, text);
		} else if (kind == STS_KIND_ACTION) {
			tui_print(&a->tui, win, TUI_LINE_NOTICE, " * %s %.*s",
				  who, (int)n, text);
		} else {
			tui_print(&a->tui, win, TUI_LINE_NOTICE, "<%s> %.*s",
				  who, (int)n, text);
		}
		text += n;
		len -= n;
	}
}

static void cmd_who(struct app *a, struct chat_room *cr)
{
	char name[TUI_NICK_NAME_MAX];
	char who[TUI_NICK_NAME_MAX + 32];
	char fpr[STS_FPR_SHORT_STR_LEN];
	size_t i;

	sts_fpr_format_short(a->id.fpr, fpr);
	colored(a, self_color(cr), cr->room.nick, who, sizeof(who));
	say(a, a->tui.cur, "%s%zu in #%s:", bang(a),
	    sts_room_member_count(&cr->room) + 1, cr->name);
	say(a, a->tui.cur, "    %s [%s] (you)", who, fpr);
	for (i = 0; i < STS_MEMBER_SLOTS; i++) {
		const struct sts_member *m = cr->room.members[i];

		if (m == NULL || (m->state != STS_MEMBER_ACTIVE &&
				  m->state != STS_MEMBER_AWAY))
			continue;
		member_name(cr, m, name, sizeof(name));
		colored(a, member_color(cr, m), name, who, sizeof(who));
		sts_fpr_format_short(m->fpr, fpr);
		say(a, a->tui.cur, "    %s [%s] %s%s", who, fpr,
		    trust_label(a, m->fpr),
		    m->state == STS_MEMBER_AWAY ? ", connection lost" : "");
	}
}

static void cmd_whois(struct app *a, struct chat_room *cr, const char *name)
{
	const struct sts_member *m = need_member(a, cr, name);
	char fpr[STS_FPR_STR_LEN];
	char who[TUI_NICK_NAME_MAX + 32];
	uint64_t now = sts_monotonic_ms();
	uint64_t since;

	if (m == NULL)
		return;
	sts_fpr_format(m->fpr, fpr);
	colored(a, member_color(cr, m), m->nick, who, sizeof(who));
	since = now > m->created_ms ? (now - m->created_ms) / 1000 : 0;
	say(a, a->tui.cur, "%s%s", bang(a), who);
	say(a, a->tui.cur, "    fingerprint %s", fpr);
	say(a, a->tui.cur, "    %s, %d device(s), seen for %lu min",
	    trust_label(a, m->fpr), same_identity_count(cr, m->fpr),
	    (unsigned long)(since / 60));
	say(a, a->tui.cur,
	    "    compare the fingerprint with %s (in person, on the phone), then /trust %s",
	    m->nick, name);
}

static void cmd_trust(struct app *a, struct chat_room *cr, const char *name,
		      int verified)
{
	const struct sts_member *m = need_member(a, cr, name);
	char fpr[STS_FPR_STR_LEN];
	size_t i;

	if (m == NULL)
		return;
	if (sts_trust_set_verified(&a->trust, m->fpr, m->nick, verified) != 0) {
		say(a, a->tui.cur, "%scannot save %s", bang(a), a->trust.path);
		return;
	}
	sts_fpr_format(m->fpr, fpr);
	say(a, a->tui.cur, "%s%s's key %s is %s", bang(a), m->nick, fpr,
	    verified ? "now verified" : "no longer verified");
	for (i = 0; i < TUI_WINDOWS_MAX; i++)
		if (a->rooms[i] != NULL)
			a->rooms[i]->nicks_dirty = 1;
}

static void cmd_status(struct app *a)
{
	const struct sts_config *cfg = a->cfg;
	char fpr[STS_FPR_STR_LEN];
	int i;

	sts_fpr_format(a->id.fpr, fpr);
	say(a, a->tui.cur, "%ssts %s, you are %s", bang(a), STS_VERSION,
	    a->nick);
	say(a, a->tui.cur, "    fingerprint %s", fpr);
	say(a, a->tui.cur, "    broker %s:%d, %s, topic prefix %s", cfg->broker,
	    cfg->port,
	    cfg->tls ? (cfg->tls_verify ? "TLS" :
					  "TLS without certificate check") :
		       "no TLS (the network sees MQTT metadata)",
	    cfg->topic_prefix);
	for (i = 0; i < a->tui.win_count; i++) {
		struct chat_room *cr = a->rooms[i];
		const struct sts_room_stats *s;

		if (cr == NULL)
			continue;
		s = &cr->room.stats;
		say(a, a->tui.cur,
		    "    #%s: %s, %zu other(s), sent %lu, received %lu, rejected %lu, recovered %lu, unacked %zu",
		    cr->name, cr->ready ? "connected" : "not connected",
		    sts_room_member_count(&cr->room), s->sent, s->received,
		    s->rejected, s->recovered, sts_mqtt_unacked(&cr->mqtt));
		say(a, a->tui.cur, "        MQTT topic %s", cr->topic);
	}
	say(a, a->tui.cur,
	    "    messages: AES-256-GCM with per-sender keys, signed (ECDSA P-256)");
}

static void cmd_nick(struct app *a, const char *nick)
{
	int i;

	if (nick == NULL || !sts_nick_valid(nick, strlen(nick))) {
		say(a, a->tui.cur,
		    "%susage: /nick NICK (1 to %d letters, digits or _-.[]^`{}|)",
		    bang(a), STS_NICK_MAX);
		return;
	}
	sts_strlcpy(a->nick, nick, sizeof(a->nick));
	for (i = 0; i < a->tui.win_count; i++) {
		if (a->rooms[i] == NULL)
			continue;
		sts_room_set_nick(&a->rooms[i]->room, nick);
		a->rooms[i]->nicks_dirty = 1;
	}
	tui_set_self(&a->tui, nick, a->tui.nick_color);
	say(a, a->tui.cur, "%syou are now known as %s", bang(a), nick);
}

static void cmd_quit(struct app *a)
{
	int i;

	if (a->quitting)
		return;
	a->quitting = 1;
	a->quit_deadline_ms = sts_monotonic_ms() + QUIT_TIMEOUT_MS;
	for (i = 0; i < a->tui.win_count; i++)
		if (a->rooms[i] != NULL)
			part_room(a, a->rooms[i]);
}

/* split "WORD rest": @line is modified, *rest points after the spaces */
static char *word(char *line, char **rest)
{
	char *end;

	while (*line == ' ')
		line++;
	end = line + strcspn(line, " ");
	if (*end != '\0') {
		*end++ = '\0';
		while (*end == ' ')
			end++;
	}
	*rest = end;
	return line;
}

/* --- file commands ------------------------------------------------------ */

static void cmd_send(struct app *a, struct chat_room *cr, char *rest)
{
	const struct sts_member *m;
	char path[STS_PATH_MAX];
	char err[STS_PATH_MAX + 64];
	char size[32];
	char *nick = word(rest, &rest);
	int num;

	if (nick[0] == '\0' || rest[0] == '\0') {
		say(a, a->tui.cur, "%susage: /send NICK FILE", bang(a));
		return;
	}
	m = need_member(a, cr, nick);
	if (m == NULL)
		return;
	if (sts_path_expand(rest, NULL, path, sizeof(path)) != 0) {
		say(a, a->tui.cur, "%spath too long", bang(a));
		return;
	}
	num = sts_xfer_send(&cr->xfers, m->sid, path, err, sizeof(err));
	if (num < 0) {
		say(a, a->tui.cur, "%s%s", bang(a), err);
		return;
	}
	sts_xfer_size_str(sts_xfer_find(&cr->xfers, (unsigned int)num)->size,
			  size, sizeof(size));
	say(a, room_win(a, cr),
	    "%soffered %s (%s) to %s [%d], waiting for an answer (/cancel %d)",
	    bang(a), path, size, m->nick, num, num);
}

/* the transfer @num, or the only offer waiting if @num is 0 */
static struct sts_xfer *find_xfer(struct app *a, unsigned int num,
				  struct chat_room **room)
{
	struct sts_xfer *found = NULL;
	int count = 0;
	int i;
	int k;

	for (i = 0; i < a->tui.win_count; i++) {
		struct chat_room *cr = a->rooms[i];

		if (cr == NULL)
			continue;
		for (k = 0; k < STS_XFER_SLOTS; k++) {
			struct sts_xfer *x = &cr->xfers.x[k];

			if (x->state == STS_XFER_FREE ||
			    x->state == STS_XFER_FINISHED)
				continue;
			if (num != 0 ? x->num == num :
				       !x->outgoing &&
					       x->state == STS_XFER_OFFERED) {
				found = x;
				*room = cr;
				count++;
			}
		}
	}
	return count == 1 ? found : NULL;
}

static void default_download_dir(char *out, size_t cap)
{
	char home[STS_PATH_MAX];

	if (sts_home_dir(home, sizeof(home)) != 0) {
		sts_strlcpy(out, ".", cap);
		return;
	}
	if (snprintf(out, cap, "%.*s/Downloads", (int)(cap - 16), home) < 0 ||
	    !sts_is_dir(out))
		sts_strlcpy(out, home, cap);
}

static void cmd_answer(struct app *a, char *rest, int accept)
{
	struct chat_room *cr = NULL;
	struct sts_xfer *x;
	char dir[STS_PATH_MAX];
	char err[STS_PATH_MAX + 64];
	unsigned int num = 0;
	char *arg = rest;
	char *end;

	/* "[N] [DIR]" */
	while (*arg == ' ')
		arg++;
	if (*arg >= '0' && *arg <= '9') {
		num = (unsigned int)strtoul(arg, &end, 10);
		arg = end;
		while (*arg == ' ')
			arg++;
	}
	x = find_xfer(a, num, &cr);
	if (x == NULL || x->outgoing || x->state != STS_XFER_OFFERED) {
		if (num != 0)
			say(a, a->tui.cur, "%sno file offer %u", bang(a), num);
		else
			say(a, a->tui.cur, "%swhich one? /%s N (see /files)",
			    bang(a), accept ? "accept" : "refuse");
		return;
	}
	num = x->num;
	if (!accept) {
		say(a, room_win(a, cr), "%srefused %s from %s", bang(a),
		    x->name, x->nick);
		sts_xfer_refuse(&cr->xfers, num);
		return;
	}
	if (arg[0] != '\0') {
		if (sts_path_expand(arg, NULL, dir, sizeof(dir)) != 0) {
			say(a, a->tui.cur, "%spath too long", bang(a));
			return;
		}
	} else {
		default_download_dir(dir, sizeof(dir));
	}
	if (sts_xfer_accept(&cr->xfers, num, dir, err, sizeof(err)) != 0) {
		say(a, a->tui.cur, "%s%s", bang(a), err);
		return;
	}
	say(a, room_win(a, cr), "%sreceiving %s from %s into %s...", bang(a),
	    x->name, x->nick, dir);
}

static void cmd_cancel(struct app *a, const char *arg)
{
	struct chat_room *cr = NULL;
	unsigned int num = (unsigned int)strtoul(arg, NULL, 10);
	struct sts_xfer *x = num ? find_xfer(a, num, &cr) : NULL;

	if (x == NULL) {
		say(a, a->tui.cur, "%susage: /cancel N (see /files)", bang(a));
		return;
	}
	say(a, room_win(a, cr), "%scancelled %s", bang(a), x->name);
	sts_xfer_cancel(&cr->xfers, num);
}

static void cmd_files(struct app *a)
{
	static const char *const states[] = {
		[STS_XFER_OFFERED] = "waiting for an answer",
		[STS_XFER_ACTIVE] = "in progress",
	};
	char size[32];
	int shown = 0;
	int i;
	int k;

	for (i = 0; i < a->tui.win_count; i++) {
		struct chat_room *cr = a->rooms[i];

		if (cr == NULL)
			continue;
		for (k = 0; k < STS_XFER_SLOTS; k++) {
			const struct sts_xfer *x = &cr->xfers.x[k];

			if (x->state != STS_XFER_OFFERED &&
			    x->state != STS_XFER_ACTIVE)
				continue;
			sts_xfer_size_str(x->size, size, sizeof(size));
			say(a, a->tui.cur,
			    "    [%u] %s %s in #%s: %s (%s), %s, %d%%", x->num,
			    x->outgoing ? "to" : "from", x->nick, cr->name,
			    x->name, size, states[x->state], x->percent);
			shown++;
		}
	}
	if (shown == 0)
		say(a, a->tui.cur, "%sno file transfers", bang(a));
}

/* commands for the room of the current window */
static void room_command(struct app *a, struct chat_room *cr, const char *cmd,
			 char *rest)
{
	const struct sts_member *m;
	char *arg;

	if (strcmp(cmd, "/me") == 0) {
		if (rest[0] != '\0')
			send_text(a, cr, STS_KIND_ACTION, rest, NULL);
	} else if (strcmp(cmd, "/msg") == 0 || strcmp(cmd, "/query") == 0) {
		arg = word(rest, &rest);
		if (arg[0] == '\0' || rest[0] == '\0') {
			say(a, a->tui.cur, "%susage: /msg NICK TEXT", bang(a));
			return;
		}
		m = need_member(a, cr, arg);
		if (m != NULL)
			send_text(a, cr, STS_KIND_TEXT, rest, m);
	} else if (strcmp(cmd, "/who") == 0 || strcmp(cmd, "/names") == 0) {
		cmd_who(a, cr);
	} else if (strcmp(cmd, "/whois") == 0) {
		cmd_whois(a, cr, word(rest, &rest));
	} else if (strcmp(cmd, "/trust") == 0) {
		cmd_trust(a, cr, word(rest, &rest), 1);
	} else if (strcmp(cmd, "/untrust") == 0) {
		cmd_trust(a, cr, word(rest, &rest), 0);
	} else if (strcmp(cmd, "/send") == 0) {
		cmd_send(a, cr, rest);
	} else if (strcmp(cmd, "/rekey") == 0) {
		if (sts_room_rekey(&cr->room) == 0)
			say(a, a->tui.cur, "%snew keys for #%s", bang(a),
			    cr->name);
	}
}

static int is_room_command(const char *cmd)
{
	static const char *const names[] = {
		"/me",	  "/msg",   "/query",	"/who",	  "/names",
		"/whois", "/trust", "/untrust", "/rekey", "/send",
	};
	size_t i;

	for (i = 0; i < STS_ARRAY_SIZE(names); i++)
		if (strcmp(cmd, names[i]) == 0)
			return 1;
	return 0;
}

static void cmd_part(struct app *a, const char *arg)
{
	struct chat_room *cr;

	if (arg[0] != '\0') {
		cr = find_room(a, arg[0] == '#' ? arg + 1 : arg);
		if (cr == NULL)
			say(a, a->tui.cur, "%snot in %s", bang(a), arg);
	} else {
		cr = need_room(a);
	}
	if (cr != NULL) {
		say(a, STATUS_WIN, "%sleft #%s", bang(a), cr->name);
		part_room(a, cr);
	}
}

static void cmd_win(struct app *a, const char *arg)
{
	int n = atoi(arg);

	if (n < 1 || n > a->tui.win_count)
		say(a, a->tui.cur, "%susage: /win 1..%d", bang(a),
		    a->tui.win_count);
	else
		tui_window_select(&a->tui, n - 1);
}

static void run_command(struct app *a, char *line)
{
	struct chat_room *cr;
	char fpr[STS_FPR_STR_LEN];
	char *rest;
	char *cmd = word(line, &rest);
	char *arg;

	if (strcmp(cmd, "/help") == 0) {
		cmd_help(a);
	} else if (strcmp(cmd, "/quit") == 0 || strcmp(cmd, "/exit") == 0) {
		cmd_quit(a);
	} else if (strcmp(cmd, "/join") == 0) {
		arg = word(rest, &rest);
		if (arg[0] == '\0')
			say(a, a->tui.cur, "%susage: /join ROOM [PASSWORD]",
			    bang(a));
		else
			join_room(a, arg, rest);
	} else if (strcmp(cmd, "/part") == 0 || strcmp(cmd, "/leave") == 0) {
		cmd_part(a, word(rest, &rest));
	} else if (strcmp(cmd, "/nick") == 0) {
		cmd_nick(a, word(rest, &rest));
	} else if (strcmp(cmd, "/fingerprint") == 0) {
		sts_fpr_format(a->id.fpr, fpr);
		say(a, a->tui.cur, "%syour fingerprint: %s", bang(a), fpr);
	} else if (strcmp(cmd, "/status") == 0) {
		cmd_status(a);
	} else if (strcmp(cmd, "/clear") == 0) {
		tui_clear(&a->tui, a->tui.cur);
	} else if (strcmp(cmd, "/win") == 0 || strcmp(cmd, "/window") == 0) {
		cmd_win(a, word(rest, &rest));
	} else if (strcmp(cmd, "/accept") == 0) {
		cmd_answer(a, rest, 1);
	} else if (strcmp(cmd, "/refuse") == 0) {
		cmd_answer(a, rest, 0);
	} else if (strcmp(cmd, "/cancel") == 0) {
		cmd_cancel(a, word(rest, &rest));
	} else if (strcmp(cmd, "/files") == 0) {
		cmd_files(a);
	} else if (is_room_command(cmd)) {
		cr = need_room(a);
		if (cr != NULL)
			room_command(a, cr, cmd, rest);
	} else {
		say(a, a->tui.cur, "%sunknown command %s, try /help", bang(a),
		    cmd);
	}
}

static void on_submit(void *ud, const char *input)
{
	struct app *a = ud;
	char line[TUI_INPUT_MAX];
	struct chat_room *cr;

	/* what we show and send is safe to print */
	sts_sanitize((const uint8_t *)input, strlen(input), line, sizeof(line));
	if (line[0] == '\0')
		return;
	if (line[0] == '/' && line[1] != '/') {
		run_command(a, line);
	} else {
		cr = need_room(a);
		if (cr != NULL)
			send_text(a, cr, STS_KIND_TEXT,
				  line[0] == '/' ? line + 1 : line, NULL);
	}
	sts_memzero(line, sizeof(line));
}

static void on_quit(void *ud)
{
	cmd_quit(ud);
}

static void log_line(FILE *fp, const char *text)
{
	char stamp[32];
	struct tm tm;

	sts_localtime((time_t)(sts_wallclock_ms() / 1000), &tm);
	strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm);
	fprintf(fp, "%s %s\n", stamp, text);
	fflush(fp);
}

/* every line of a room's window goes to its log */
static void on_line(void *ud, int win, const char *text)
{
	struct app *a = ud;
	struct chat_room *cr;

	if (win < 0 || win >= TUI_WINDOWS_MAX)
		return;
	cr = a->rooms[win];
	if (cr != NULL && cr->log != NULL)
		log_line(cr->log, text);
}

static void open_log(struct app *a, struct chat_room *cr)
{
	char path[STS_PATH_MAX + STS_ROOM_MAX + 8];
	char text[STS_PATH_MAX + 64];

	if (!a->cfg->log)
		return;
	snprintf(path, sizeof(path), "%s/%s.log", a->cfg->log_dir, cr->name);
	if (sts_mkdirs(a->cfg->log_dir) == 0)
		cr->log = sts_file_append(path);
	if (cr->log == NULL) {
		say(a, room_win(a, cr), "%scannot open the chat log %s",
		    bang(a), path);
		return;
	}
	snprintf(text, sizeof(text), "---- #%s, as %s ----", cr->name, a->nick);
	log_line(cr->log, text);
	say(a, room_win(a, cr), "%schat log: %s", bang(a), path);
}

static const struct tui_ops tui_ops = {
	.submit = on_submit,
	.quit = on_quit,
	.line = on_line,
};

/* --- main loop ----------------------------------------------------------- */

static void service_rooms(struct app *a)
{
	uint64_t now = sts_monotonic_ms();
	int i;

	for (i = a->tui.win_count - 1; i >= 0; i--) {
		struct chat_room *cr = a->rooms[i];

		if (cr == NULL)
			continue;
		sts_mqtt_process(&cr->mqtt);
		if (cr->parting) {
			if (sts_mqtt_is_closed(&cr->mqtt))
				free_room(a, cr);
			continue;
		}
		sts_room_tick(&cr->room);
		sts_xfers_tick(&cr->xfers);
		if (cr->retry_ms != 0 && now >= cr->retry_ms &&
		    sts_mqtt_is_closed(&cr->mqtt))
			connect_room(a, cr);
		if (cr->nicks_dirty)
			update_nicks(a, cr);
		update_state(a, cr);
	}
	update_progress(a);
	if (current_room(a) != NULL)
		tui_set_self(&a->tui, current_room(a)->room.nick,
			     self_color(current_room(a)));
	else
		tui_set_self(&a->tui, a->nick,
			     tui_nick_color(a->id.fpr, a->nick));
}

static void wait_io(struct app *a)
{
	struct sts_wait w[TUI_WINDOWS_MAX];
	char buf[READ_CHUNK];
	size_t n = 0;
	int input = 0;
	int i;
	long got;

	for (i = 0; i < a->tui.win_count; i++) {
		intptr_t sock;
		int want_write;

		if (a->rooms[i] == NULL)
			continue;
		sts_mqtt_wait_spec(&a->rooms[i]->mqtt, &sock, &want_write);
		if (sock == STS_SOCK_INVALID)
			continue;
		memset(&w[n], 0, sizeof(w[n]));
		w[n].sock = sock;
		w[n].want_write = want_write;
		n++;
	}
	if (sts_wait(w, n, !a->input_eof, TICK_MS, &input) != 0)
		return;
	if (!input)
		return;

	while ((got = sts_input_read(buf, sizeof(buf))) > 0)
		tui_feed(&a->tui, buf, (size_t)got);
	if (got == 0 || got == STS_IO_ERROR) {
		a->input_eof = 1;
		tui_eof(&a->tui);
	}
	sts_memzero(buf, sizeof(buf));
}

static void banner(struct app *a, int created)
{
	const struct sts_config *cfg = a->cfg;
	char fpr[STS_FPR_STR_LEN];

	sts_fpr_format(a->id.fpr, fpr);
	say(a, STATUS_WIN, "%ssts %s - end-to-end encrypted chat over MQTT",
	    bang(a), STS_VERSION);
	say(a, STATUS_WIN, "%s%s identity %s", bang(a),
	    created ? "new" : "your", cfg->identity);
	say(a, STATUS_WIN, "%sfingerprint %s", bang(a), fpr);
	if (!sts_identity_is_protected(cfg->identity))
		say(a, STATUS_WIN,
		    "%sthe identity key has no passphrase: sts --passphrase %s protects it",
		    bang(a), cfg->identity);
	if (sts_broker_is_public(cfg->broker))
		say(a, STATUS_WIN,
		    "%s%s is a public broker: nobody can read the messages, but anyone can see that the room's topic is in use and when%s",
		    bang(a), cfg->broker,
		    cfg->tls ? "" : " (tls = yes hides it from the network)");
	if (cfg->tls && !cfg->tls_verify)
		say(a, STATUS_WIN,
		    "%s%stls_verify is off: the broker isn't authenticated%s",
		    bang(a), sgr(a, "\033[33m"), sgr(a, TUI_RESET));
	if (cfg->room_count == 0)
		say(a, STATUS_WIN, "%stype /join ROOM to start, /help for help",
		    bang(a));
}

int sts_chat_run(const struct sts_config *cfg)
{
	static struct app app;
	struct app *a = &app;
	int fullscreen;
	int colors;
	int created = 0;
	int i;

	memset(a, 0, sizeof(*a));
	a->cfg = cfg;
	sts_strlcpy(a->nick, cfg->nick, sizeof(a->nick));

	if (sts_setup_identity(&a->id, cfg->identity, &created) != 0) {
		fprintf(stderr, "sts: cannot load or create the identity %s\n",
			cfg->identity);
		return EXIT_FAILURE;
	}
	if (sts_file_shared(cfg->identity))
		fprintf(stderr, "sts: warning: %s can be read by other users\n",
			cfg->identity);
	if (sts_trust_load(&a->trust, cfg->known_peers) != 0) {
		fprintf(stderr, "sts: cannot read %s\n", cfg->known_peers);
		sts_identity_free(&a->id);
		return EXIT_FAILURE;
	}

	fullscreen = cfg->ui == STS_UI_TUI ||
		     (cfg->ui == STS_UI_AUTO && sts_term_is_tty());
	if (fullscreen && !sts_term_is_tty()) {
		fprintf(stderr,
			"sts: the full screen interface needs a terminal\n");
		fullscreen = 0;
	}
	colors = sts_term_is_tty() && getenv("NO_COLOR") == NULL;

	sts_signals_install();
	if (tui_init(&a->tui, fullscreen, colors, commands, &tui_ops, a) != 0) {
		fprintf(stderr, "sts: cannot set up the terminal\n");
		sts_trust_free(&a->trust);
		sts_identity_free(&a->id);
		return EXIT_FAILURE;
	}
	tui_window_add(&a->tui, "sts");
	tui_set_title(&a->tui, STATUS_WIN,
		      "sts - status window - /help for help");
	tui_set_self(&a->tui, a->nick, tui_nick_color(a->id.fpr, a->nick));
	log_app = a;
	sts_log_set_sink(log_sink);

	banner(a, created);
	for (i = 0; i < cfg->room_count; i++)
		join_room(a, cfg->rooms[i].name, cfg->rooms[i].password);
	/* start in the first room */
	if (a->tui.win_count > 1)
		tui_window_select(&a->tui, 1);

	while (!a->done) {
		tui_render(&a->tui);
		wait_io(a);
		if (sts_signals_quit())
			cmd_quit(a);
		service_rooms(a);
		tui_tick(&a->tui);

		if (a->quitting) {
			int open = 0;

			for (i = 0; i < a->tui.win_count; i++)
				open += a->rooms[i] != NULL;
			if (open == 0 ||
			    sts_monotonic_ms() >= a->quit_deadline_ms)
				a->done = 1;
		}
	}

	for (i = a->tui.win_count - 1; i >= 0; i--)
		if (a->rooms[i] != NULL)
			free_room(a, a->rooms[i]);
	sts_log_set_sink(NULL);
	log_app = NULL;
	tui_end(&a->tui);
	sts_trust_free(&a->trust);
	sts_identity_free(&a->id);
	return EXIT_SUCCESS;
}
