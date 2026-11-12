// SPDX-License-Identifier: Apache-2.0
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "room.h"
#include "test.h"

static char dir[STS_PATH_MAX];

static void write_file(const char *path, const char *text)
{
	FILE *fp = fopen(path, "wb");

	REQUIRE(fp != NULL);
	fputs(text, fp);
	fclose(fp);
}

/* load @text as a config file, @return what sts_config_load() returns */
static int load(struct sts_config *cfg, const char *text, char *err,
		size_t errlen)
{
	char path[STS_PATH_MAX + 32];

	snprintf(path, sizeof(path), "%s/test.conf", dir);
	write_file(path, text);
	sts_config_init(cfg);
	return sts_config_load(cfg, path, err, errlen);
}

static const char *const minimal = "broker = localhost\n"
				   "port = 1883\n"
				   "topic_prefix = test\n"
				   "nick = alice\n"
				   "identity = keys/alice.key\n"
				   "known_peers = ~/peers\n";

static void test_shipped_config(void)
{
	struct sts_config cfg;
	char home[STS_PATH_MAX];
	char want[STS_PATH_MAX + 32];
	char err[512];

	sts_config_init(&cfg);
	REQUIRE(sts_config_load(&cfg, STS_SOURCE_DIR "/configs/sts.conf", err,
				sizeof(err)) == 0);
	CHECK(sts_config_check(&cfg, err, sizeof(err)) == 0);
	CHECK(strcmp(cfg.broker, "broker.emqx.io") == 0);
	CHECK(cfg.port == 1883);
	CHECK(cfg.tls == 0 && cfg.tls_verify == 1);
	CHECK(strcmp(cfg.topic_prefix, "wonderland") == 0);
	CHECK(strcmp(cfg.nick, "yournickname") == 0);
	CHECK(cfg.room_count == 1 &&
	      strcmp(cfg.rooms[0].name, "youroom") == 0 &&
	      cfg.rooms[0].password[0] == '\0');
	REQUIRE(sts_home_dir(home, sizeof(home)) == 0);
	snprintf(want, sizeof(want), "%s/.sts/identity.key", home);
	CHECK(strcmp(cfg.identity, want) == 0);
	CHECK(cfg.rekey_interval == 600 && cfg.keepalive == 30);
}

static void test_alice_and_bob(void)
{
	struct sts_config a;
	struct sts_config b;
	char err[512];

	sts_config_init(&a);
	sts_config_init(&b);
	REQUIRE(sts_config_load(&a, STS_SOURCE_DIR "/configs/alice.conf", err,
				sizeof(err)) == 0);
	REQUIRE(sts_config_load(&b, STS_SOURCE_DIR "/configs/bob.conf", err,
				sizeof(err)) == 0);
	CHECK(sts_config_check(&a, err, sizeof(err)) == 0);
	CHECK(sts_config_check(&b, err, sizeof(err)) == 0);
	/* the same room, two people */
	CHECK(strcmp(a.broker, b.broker) == 0 && a.port == b.port);
	CHECK(strcmp(a.topic_prefix, b.topic_prefix) == 0);
	CHECK(strcmp(a.rooms[0].name, b.rooms[0].name) == 0);
	CHECK(strcmp(a.nick, "alice") == 0 && strcmp(b.nick, "bob") == 0);
	CHECK(strcmp(a.identity, b.identity) != 0);
	CHECK(strcmp(a.known_peers, b.known_peers) != 0);
}

static void test_values(void)
{
	struct sts_config cfg;
	char want[STS_PATH_MAX + 32];
	char text[2048];
	char err[512];

	snprintf(text, sizeof(text),
		 "\xef\xbb\xbf# comment\r\n"
		 "%s"
		 "  keepalive   =  45 \r\n"
		 "tls = yes\n"
		 "tls_verify = off\n"
		 "tls_ca_file = ca.pem\n"
		 "username = me\n"
		 "password = p#ss = word\n"
		 "room = #neotokyo\n"
		 "room = lab   correct horse battery\n"
		 "; also a comment\n"
		 "ui = plain\n"
		 "rekey_interval = 0\n"
		 "max_file_size = 100M\n"
		 "log = yes\n"
		 "log_dir = logs\n",
		 minimal);
	REQUIRE(load(&cfg, text, err, sizeof(err)) == 0);
	CHECK(sts_config_check(&cfg, err, sizeof(err)) == 0);
	CHECK(cfg.keepalive == 45);
	CHECK(cfg.tls == 1 && cfg.tls_verify == 0);
	CHECK(strcmp(cfg.password, "p#ss = word") == 0);
	CHECK(cfg.room_count == 2);
	CHECK(strcmp(cfg.rooms[0].name, "neotokyo") == 0);
	CHECK(strcmp(cfg.rooms[1].name, "lab") == 0);
	CHECK(strcmp(cfg.rooms[1].password, "correct horse battery") == 0);
	CHECK(cfg.ui == STS_UI_PLAIN);
	CHECK(cfg.rekey_interval == 0);
	CHECK(cfg.max_file_size == 100ULL * 1024 * 1024);
	CHECK(cfg.log == 1);

	/* relative to the file's directory */
	snprintf(want, sizeof(want), "%s/keys/alice.key", dir);
	CHECK(strcmp(cfg.identity, want) == 0);
	snprintf(want, sizeof(want), "%s/ca.pem", dir);
	CHECK(strcmp(cfg.tls_ca_file, want) == 0);
	CHECK(strstr(cfg.known_peers, "~") == NULL);
}

static void test_errors(void)
{
	static const struct {
		const char *text;
		const char *error;
	} cases[] = {
		{ "colour = red\n", "test.conf:7: unknown setting 'colour'" },
		{ "color = pink\n", "unknown setting 'color'" },
		{ "port = 0\n", "port: invalid value '0'" },
		{ "port = 99999\n", "port: invalid value" },
		{ "port = 18a\n", "port: invalid value" },
		{ "broker = mqtt://x.org\n", "host name only" },
		{ "broker = a b\n", "broker: invalid" },
		{ "nick = a b\n", "nick: invalid 'a b'" },
		{ "room = a/b\n", "invalid room name 'a/b'" },
		{ "room = a\nroom = A\n", "room 'A' listed twice" },
		{ "topic_prefix = a/+/b\n", "topic_prefix: invalid" },
		{ "topic_prefix = /a\n", "topic_prefix: invalid" },
		{ "tls = maybe\n", "tls: invalid value 'maybe'" },
		{ "rekey_interval = 5\n", "rekey_interval: 0 (off) or 60" },
		{ "ui = gui\n", "ui: auto, tui or plain" },
		{ "max_file_size = 10X\n", "max_file_size: a size like" },
		{ "max_file_size = 0\n", "max_file_size: a size like" },
		{ "max_file_size = 65G\n", "max_file_size: a size like" },
		{ "notify = beep\n", "unknown setting 'notify'" },
		{ "log = maybe\n", "log: invalid value" },
		{ "just words\n", "expected 'setting = value'" },
	};
	struct sts_config cfg;
	char text[2048];
	char err[512];
	size_t i;

	for (i = 0; i < STS_ARRAY_SIZE(cases); i++) {
		snprintf(text, sizeof(text), "%s%s", minimal, cases[i].text);
		CHECK(load(&cfg, text, err, sizeof(err)) != 0);
		if (strstr(err, cases[i].error) == NULL) {
			fprintf(stderr, "  got '%s', wanted '%s'\n", err,
				cases[i].error);
			CHECK(0);
		}
	}

	/* too many rooms */
	snprintf(text, sizeof(text), "%s", minimal);
	for (i = 0; i <= STS_CONFIG_ROOMS_MAX; i++)
		snprintf(text + strlen(text), sizeof(text) - strlen(text),
			 "room = r%zu\n", i);
	CHECK(load(&cfg, text, err, sizeof(err)) != 0);
	CHECK(strstr(err, "too many rooms") != NULL);

	/* every connection setting is required */
	CHECK(load(&cfg, "nick = alice\n", err, sizeof(err)) == 0);
	CHECK(sts_config_check(&cfg, err, sizeof(err)) != 0);
	CHECK(strstr(err, "'broker' is not set") != NULL);
	snprintf(text, sizeof(text), "%s", minimal);
	*strstr(text, "topic_prefix") = '#';
	CHECK(load(&cfg, text, err, sizeof(err)) == 0);
	CHECK(sts_config_check(&cfg, err, sizeof(err)) != 0);
	CHECK(strstr(err, "'topic_prefix' is not set") != NULL);

	snprintf(text, sizeof(text), "%spassword = x\n", minimal);
	CHECK(load(&cfg, text, err, sizeof(err)) == 0);
	CHECK(sts_config_check(&cfg, err, sizeof(err)) != 0);

	sts_config_init(&cfg);
	CHECK(sts_config_load(&cfg, "/nonexistent/sts.conf", err,
			      sizeof(err)) != 0);
	CHECK(strstr(err, "cannot open") != NULL);
}

static enum sts_args_result args(struct sts_config *cfg, const char *a1,
				 const char *a2, const char *a3, const char *a4,
				 const char *a5, const char *a6)
{
	static char name[] = "sts";
	char *argv[8] = { name };
	const char *in[] = { a1, a2, a3, a4, a5, a6 };
	int argc = 1;
	size_t i;

	for (i = 0; i < STS_ARRAY_SIZE(in) && in[i] != NULL; i++)
		argv[argc++] = (char *)in[i];
	sts_config_init(cfg);
	return sts_config_parse_args(cfg, argc, argv);
}

static void test_args(void)
{
	struct sts_config cfg;
	char path[STS_PATH_MAX + 32];
	char home[STS_PATH_MAX];
	char want[STS_PATH_MAX + 32];
	char text[2048];

	snprintf(path, sizeof(path), "%s/args.conf", dir);
	snprintf(text, sizeof(text), "%sroom = one\nroom = two\n", minimal);
	write_file(path, text);
	REQUIRE(sts_home_dir(home, sizeof(home)) == 0);

	CHECK(args(&cfg, NULL, NULL, NULL, NULL, NULL, NULL) == STS_ARGS_ERROR);
	CHECK(args(&cfg, "-h", NULL, NULL, NULL, NULL, NULL) ==
	      STS_ARGS_EXIT_OK);
	CHECK(args(&cfg, "--version", NULL, NULL, NULL, NULL, NULL) ==
	      STS_ARGS_EXIT_OK);
	CHECK(args(&cfg, "-c", path, "--bogus", NULL, NULL, NULL) ==
	      STS_ARGS_ERROR);
	CHECK(args(&cfg, "-c", path, "extra", NULL, NULL, NULL) ==
	      STS_ARGS_ERROR);
	CHECK(args(&cfg, "--config=", path, NULL, NULL, NULL, NULL) ==
	      STS_ARGS_ERROR);

	/* 1. the file alone */
	REQUIRE(args(&cfg, "-c", path, NULL, NULL, NULL, NULL) == STS_ARGS_OK);
	CHECK(cfg.room_count == 2 && strcmp(cfg.nick, "alice") == 0);
	REQUIRE(args(&cfg, "--config", path, NULL, NULL, NULL, NULL) ==
		STS_ARGS_OK);
	REQUIRE(args(&cfg, "--config=x.conf", NULL, NULL, NULL, NULL, NULL) ==
		STS_ARGS_ERROR); /* no such file */

	/* ... can't be mixed with options */
	CHECK(args(&cfg, "-c", path, "-n", "bob", NULL, NULL) ==
	      STS_ARGS_ERROR);
	CHECK(args(&cfg, "-nbob", "-c", path, NULL, NULL, NULL) ==
	      STS_ARGS_ERROR);
	CHECK(args(&cfg, "-c", path, "--plain", NULL, NULL, NULL) ==
	      STS_ARGS_ERROR);
	CHECK(args(&cfg, "-c", path, "-c", path, NULL, NULL) == STS_ARGS_ERROR);

	/* 2. the command line alone: -b and -p, defaults for the rest */
	CHECK(args(&cfg, "-b", "localhost", NULL, NULL, NULL, NULL) ==
	      STS_ARGS_ERROR);
	CHECK(args(&cfg, "-p", "1883", "-n", "bob", NULL, NULL) ==
	      STS_ARGS_ERROR);
	REQUIRE(args(&cfg, "-b", "localhost", "-p", "1883", NULL, NULL) ==
		STS_ARGS_OK);
	CHECK(strcmp(cfg.broker, "localhost") == 0 && cfg.port == 1883);
	CHECK(strcmp(cfg.topic_prefix, "sts") == 0);
	CHECK(sts_nick_valid(cfg.nick, strlen(cfg.nick)));
	snprintf(want, sizeof(want), "%s/.sts/identity.key", home);
	CHECK(strcmp(cfg.identity, want) == 0);
	snprintf(want, sizeof(want), "%s/.sts/known_peers", home);
	CHECK(strcmp(cfg.known_peers, want) == 0);
	CHECK(cfg.room_count == 0 && cfg.tls == 0);

	REQUIRE(args(&cfg, "-nbob", "--broker=b.example", "-p1883", "-r",
		     "lab:pass word", "--room=#ops") == STS_ARGS_OK);
	CHECK(strcmp(cfg.nick, "bob") == 0);
	CHECK(strcmp(cfg.broker, "b.example") == 0);
	CHECK(cfg.room_count == 2);
	CHECK(strcmp(cfg.rooms[0].name, "lab") == 0 &&
	      strcmp(cfg.rooms[0].password, "pass word") == 0);
	CHECK(strcmp(cfg.rooms[1].name, "ops") == 0 &&
	      cfg.rooms[1].password[0] == '\0');

	REQUIRE(args(&cfg, "-b", "x", "-p", "8883", "--tls", "--insecure") ==
		STS_ARGS_OK);
	CHECK(cfg.port == 8883 && cfg.tls == 1 && cfg.tls_verify == 0);
	REQUIRE(args(&cfg, "-b", "x", "-p", "1", "--plain", NULL) ==
		STS_ARGS_OK);
	CHECK(cfg.ui == STS_UI_PLAIN);
	CHECK(args(&cfg, "-b", "x", "-p", "1", "-C", "red") == STS_ARGS_ERROR);
	CHECK(args(&cfg, "-b", "x", "-p", "0", NULL, NULL) == STS_ARGS_ERROR);
	REQUIRE(args(&cfg, "-b", "x", "-p", "1", "-i", "/abs/id.key") ==
		STS_ARGS_OK);
	CHECK(strcmp(cfg.identity, "/abs/id.key") == 0);
	REQUIRE(args(&cfg, "-b", "x", "-p", "1", "-k", "peers") == STS_ARGS_OK);
	CHECK(strcmp(cfg.known_peers, "./peers") == 0);
}

static void test_topic(void)
{
	struct sts_config cfg;
	char out[64];

	sts_config_init(&cfg);
	sts_strlcpy(cfg.topic_prefix, "wonderland/sts",
		    sizeof(cfg.topic_prefix));
	CHECK(sts_config_topic(&cfg, "00ff", out, sizeof(out)) == 0);
	CHECK(strcmp(out, "wonderland/sts/00ff") == 0);
	CHECK(sts_config_topic(&cfg, "00ff", out, 8) != 0);
	CHECK(sts_broker_is_public("Broker.EMQX.io"));
	CHECK(!sts_broker_is_public("localhost"));
}

int main(void)
{
	test_tmpdir(dir, sizeof(dir));
	RUN(test_shipped_config);
	RUN(test_alice_and_bob);
	RUN(test_values);
	RUN(test_errors);
	RUN(test_args);
	RUN(test_topic);
	return test_summary();
}
