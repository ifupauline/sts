// SPDX-License-Identifier: Apache-2.0
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "crypto.h"
#include "log.h"
#include "platform.h"
#include "setup.h"
#include "util.h"

#define ANSWER_MAX 512
#define TRIES 3

/* @brief ask until @check accepts the answer, @return 0 or -1 */
static int ask(const char *question, const char *def, char *out, size_t cap,
	       int secret)
{
	char prompt[ANSWER_MAX];

	if (def != NULL && def[0] != '\0')
		snprintf(prompt, sizeof(prompt), "%s [%s]: ", question, def);
	else
		snprintf(prompt, sizeof(prompt), "%s: ", question);
	if (sts_ask(prompt, out, cap, secret) != 0)
		return -1;
	if (out[0] == '\0' && def != NULL)
		sts_strlcpy(out, def, cap);
	return 0;
}

static int ask_yes(const char *question, int def)
{
	char answer[16];

	if (ask(question, def ? "Y/n" : "y/N", answer, sizeof(answer), 0) != 0)
		return -1;
	if (strcmp(answer, "Y/n") == 0 || strcmp(answer, "y/N") == 0)
		return def;
	return answer[0] == 'y' || answer[0] == 'Y';
}

/* ask for a setting until it is valid */
static int ask_setting(struct sts_config *cfg, const char *key,
		       const char *question, const char *def, char *out,
		       size_t cap, int secret)
{
	char err[512];

	for (;;) {
		if (ask(question, def, out, cap, secret) != 0)
			return -1;
		if (key == NULL ||
		    sts_config_set(cfg, key, out, ".", err, sizeof(err)) == 0)
			return 0;
		printf("  %s\n", err);
	}
}

/* a new passphrase, typed twice; "" for none */
static int ask_new_passphrase(char *out, size_t cap)
{
	char again[STS_PASSPHRASE_MAX];

	for (;;) {
		if (ask("New passphrase (empty for none)", NULL, out, cap, 1) !=
			    0 ||
		    ask("The same again", NULL, again, sizeof(again), 1) != 0)
			return -1;
		if (strcmp(out, again) == 0)
			break;
		printf("  they differ, again\n");
	}
	sts_memzero(again, sizeof(again));
	if (out[0] != '\0' && strlen(out) < 8)
		printf("  that's short: anyone who gets the file can try many passphrases\n");
	return 0;
}

int sts_setup_identity(struct sts_identity *id, const char *path, int *created)
{
	char pass[STS_PASSPHRASE_MAX];
	char prompt[STS_PATH_MAX + 32];
	int rc;
	int i;

	rc = sts_identity_load_or_create(id, path, created);
	if (rc != STS_IDENTITY_LOCKED)
		return rc;

	snprintf(prompt, sizeof(prompt), "Passphrase of %s: ", path);
	for (i = 0; i < TRIES; i++) {
		if (sts_ask(prompt, pass, sizeof(pass), 1) != 0) {
			fprintf(stderr,
				"sts: %s is protected by a passphrase, start sts on a terminal\n",
				path);
			return -1;
		}
		rc = sts_identity_load(id, path, pass);
		sts_memzero(pass, sizeof(pass));
		if (rc != STS_IDENTITY_LOCKED)
			return rc;
		fprintf(stderr, "wrong passphrase\n");
	}
	return -1;
}

int sts_setup_passphrase(const char *path)
{
	struct sts_identity id;
	char pass[STS_PASSPHRASE_MAX];
	char fpr[STS_FPR_STR_LEN];
	int created = 0;

	if (!sts_file_exists(path)) {
		fprintf(stderr, "sts: %s doesn't exist\n", path);
		return EXIT_FAILURE;
	}
	if (sts_crypto_init() != 0 ||
	    sts_setup_identity(&id, path, &created) != 0)
		return EXIT_FAILURE;
	sts_fpr_format(id.fpr, fpr);
	printf("identity %s\nfingerprint %s\n", path, fpr);

	if (ask_new_passphrase(pass, sizeof(pass)) != 0 ||
	    sts_identity_save(&id, path, pass) != 0) {
		fprintf(stderr, "sts: cannot save %s\n", path);
		sts_identity_free(&id);
		return EXIT_FAILURE;
	}
	printf(pass[0] != '\0' ? "%s is now protected by the passphrase\n" :
				 "%s is no longer protected by a passphrase\n",
	       path);
	sts_memzero(pass, sizeof(pass));
	sts_identity_free(&id);
	return EXIT_SUCCESS;
}

static void append(char *buf, size_t cap, const char *fmt, ...)
	STS_PRINTF(3, 4);

static void append(char *buf, size_t cap, const char *fmt, ...)
{
	size_t len = strlen(buf);
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf + len, cap - len, fmt, ap);
	va_end(ap);
}

/* a path that means the same from anywhere: "~/..." or absolute */
static void stable_path(const char *in, char *out, size_t cap)
{
	char cwd[STS_PATH_MAX];

	if (in[0] == '/' || in[0] == '~' || getcwd(cwd, sizeof(cwd)) == NULL)
		sts_strlcpy(out, in, cap);
	else
		snprintf(out, cap, "%.*s/%s", (int)(cap / 2), cwd, in);
}

int sts_setup_init(void)
{
	static char text[8192];
	struct sts_config cfg;
	struct sts_identity id;
	char nick[ANSWER_MAX];
	char room[ANSWER_MAX];
	char room_pw[ANSWER_MAX];
	char broker[ANSWER_MAX];
	char port[ANSWER_MAX];
	char prefix[ANSWER_MAX];
	char ca[ANSWER_MAX] = "";
	char identity[ANSWER_MAX];
	char stable[STS_PATH_MAX];
	char path[ANSWER_MAX];
	char full[STS_PATH_MAX];
	char dir[STS_PATH_MAX];
	char pass[STS_PASSPHRASE_MAX] = "";
	char fpr[STS_FPR_STR_LEN];
	char err[512];
	const char *user = getenv("USER");
	int created = 0;
	int tls;

	sts_config_init(&cfg);
	if (user == NULL || !sts_nick_valid(user, strlen(user)))
		user = "guest";

	printf("This creates your sts configuration. Press Enter to keep the\n"
	       "value in [brackets].\n\n");
	if (ask_setting(&cfg, "nick", "Your nick", user, nick, sizeof(nick),
			0) != 0)
		goto no_terminal;

	printf("\nPeople are in the same room when they use the same broker,\n"
	       "topic prefix, room name and password.\n");
	if (ask_setting(&cfg, "room", "Room to join", "lobby", room,
			sizeof(room), 0) != 0 ||
	    ask("Room password (empty for none, hidden)", NULL, room_pw,
		sizeof(room_pw), 1) != 0 ||
	    ask_setting(&cfg, "broker", "MQTT broker", "broker.emqx.io", broker,
			sizeof(broker), 0) != 0)
		goto no_terminal;

	tls = ask_yes("Use TLS to the broker", 0);
	if (tls < 0 || ask_setting(&cfg, "port", "Port", tls ? "8883" : "1883",
				   port, sizeof(port), 0) != 0)
		goto no_terminal;
	if (tls) {
		printf("If the broker uses its own certificate authority, give its CA\n"
		       "file (ca.crt); for a public certificate, press Enter.\n");
		for (;;) {
			if (ask("CA file", NULL, ca, sizeof(ca), 0) != 0)
				goto no_terminal;
			if (ca[0] == '\0' ||
			    (sts_path_expand(ca, NULL, full, sizeof(full)) ==
				     0 &&
			     sts_file_exists(full)))
				break;
			printf("  no such file\n");
		}
	}
	if (ask_setting(&cfg, "topic_prefix", "Topic prefix", "sts", prefix,
			sizeof(prefix), 0) != 0 ||
	    ask_setting(&cfg, "identity", "Identity key file",
			"~/.sts/identity.key", identity, sizeof(identity),
			0) != 0)
		goto no_terminal;

	if (sts_crypto_init() != 0)
		return EXIT_FAILURE;
	if (!sts_file_exists(cfg.identity)) {
		printf("\nThe identity key proves who you are; keep the file private.\n"
		       "A passphrase protects it if someone copies the file.\n");
		if (ask_new_passphrase(pass, sizeof(pass)) != 0)
			goto no_terminal;
		if (sts_identity_load_or_create(&id, cfg.identity, &created) !=
			    0 ||
		    sts_identity_save(&id, cfg.identity, pass) != 0) {
			fprintf(stderr, "sts: cannot create %s\n",
				cfg.identity);
			return EXIT_FAILURE;
		}
		sts_memzero(pass, sizeof(pass));
	} else if (sts_setup_identity(&id, cfg.identity, &created) != 0) {
		return EXIT_FAILURE;
	}
	sts_fpr_format(id.fpr, fpr);
	sts_identity_free(&id);

	for (;;) {
		if (ask("\nSave the configuration as", "~/.sts/sts.conf", path,
			sizeof(path), 0) != 0)
			goto no_terminal;
		if (sts_path_expand(path, NULL, full, sizeof(full)) != 0)
			continue;
		if (!sts_file_exists(full) ||
		    ask_yes("It exists, replace it", 0) == 1)
			break;
	}

	snprintf(text, sizeof(text),
		 "# sts configuration, made by sts --init.\n"
		 "# Start with: sts -c %s\n"
		 "# Every setting is explained in \"man sts\".\n\n"
		 "broker = %s\nport = %s\ntls = %s\n",
		 path, broker, port, tls ? "yes" : "no");
	if (ca[0] != '\0') {
		stable_path(ca, stable, sizeof(stable));
		append(text, sizeof(text), "tls_ca_file = %s\n", stable);
	}
	stable_path(identity, stable, sizeof(stable));
	append(text, sizeof(text),
	       "#username = me\n#password = secret\n"
	       "topic_prefix = %s\n\n"
	       "nick = %s\nidentity = %s\nknown_peers = ~/.sts/known_peers\n\n",
	       prefix, nick, stable);
	append(text, sizeof(text), "room = %s%s%s\n\n", room,
	       room_pw[0] != '\0' ? " " : "", room_pw);
	append(text, sizeof(text),
	       "# keep a chat log in log_dir\n#log = no\n"
	       "#log_dir = ~/.sts/logs\n"
	       "# largest file you send or accept (K, M or G)\n"
	       "#max_file_size = 16M\n");
	sts_memzero(room_pw, sizeof(room_pw));

	sts_path_dirname(full, dir, sizeof(dir));
	sts_mkdirs(dir);
	if (sts_file_write_atomic(full, text, strlen(text), 1) != 0) {
		fprintf(stderr, "sts: cannot write %s\n", full);
		sts_memzero(text, sizeof(text));
		return EXIT_FAILURE;
	}
	sts_memzero(text, sizeof(text));

	/* read it back as sts will */
	sts_config_init(&cfg);
	if (sts_config_load(&cfg, full, err, sizeof(err)) != 0 ||
	    sts_config_check(&cfg, err, sizeof(err)) != 0) {
		fprintf(stderr, "sts: %s\n", err);
		return EXIT_FAILURE;
	}
	printf("\nSaved %s (readable by you only).\n"
	       "Your fingerprint: %s\n"
	       "Start with:\n  sts -c %s\n",
	       full, fpr, path);
	return EXIT_SUCCESS;

no_terminal:
	fprintf(stderr, "sts: --init needs a terminal\n");
	return EXIT_FAILURE;
}
