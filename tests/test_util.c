// SPDX-License-Identifier: Apache-2.0
#include <string.h>

#include "room.h"
#include "test.h"
#include "util.h"

static void test_sanitize(void)
{
	const uint8_t bad[] = { 'a', 0xff, 0xc3, 'b', 0xe2, 0x82 };
	const uint8_t overlong[] = { 0xc0, 0xaf };
	const char *s;
	char out[64];

	s = "hello world";
	CHECK(sts_sanitize((const uint8_t *)s, strlen(s), out, sizeof(out)) ==
	      11);
	CHECK(strcmp(out, s) == 0);

	/* ESC [2J clears the screen, BEL, CR rewrites the line */
	s = "a\033[2Jb\x07"
	    "c\rd\x7f"
	    "e";
	sts_sanitize((const uint8_t *)s, strlen(s), out, sizeof(out));
	CHECK(strcmp(out, "a[2Jbcde") == 0);

	s = "caf\xc3\xa9 \xe2\x9c\x93";
	sts_sanitize((const uint8_t *)s, strlen(s), out, sizeof(out));
	CHECK(strcmp(out, s) == 0);

	s = "x\xc2\x9b"
	    "y"; /* U+009B CSI */
	sts_sanitize((const uint8_t *)s, strlen(s), out, sizeof(out));
	CHECK(strcmp(out, "xy") == 0);

	s = "a\xe2\x80\xae"
	    "b"; /* U+202E right-to-left override */
	sts_sanitize((const uint8_t *)s, strlen(s), out, sizeof(out));
	CHECK(strcmp(out, "ab") == 0);

	sts_sanitize(bad, sizeof(bad), out, sizeof(out));
	CHECK(strcmp(out, "a??b??") == 0);
	sts_sanitize(overlong, sizeof(overlong), out, sizeof(out));
	CHECK(strcmp(out, "??") == 0);

	/* never cut a multibyte sequence */
	s = "\xe2\x9c\x93\xe2\x9c\x93";
	CHECK(sts_sanitize((const uint8_t *)s, strlen(s), out, 4) == 3);
	CHECK(sts_sanitize((const uint8_t *)s, strlen(s), out, 1) == 0);
	CHECK(out[0] == '\0');
}

static void test_width(void)
{
	char buf[8];

	CHECK(sts_str_width("hello") == 5);
	CHECK(sts_str_width("caf\xc3\xa9") == 4);
	CHECK(sts_str_width("\xe6\x97\xa5\xe6\x9c\xac") == 4); /* 日本 */
	CHECK(sts_str_width("e\xcc\x81") == 1); /* e + combining acute */
	CHECK(sts_str_width("\xf0\x9f\x98\x80") == 2); /* emoji */
	CHECK(sts_utf8_encode(0x20AC, buf) == 3);
	CHECK(memcmp(buf, "\xe2\x82\xac", 3) == 0);
	CHECK(sts_utf8_encode(0x1F600, buf) == 4);
}

static void test_names(void)
{
	CHECK(sts_nick_valid("alice", 5));
	CHECK(sts_nick_valid("[bob]_^|", 8));
	CHECK(!sts_nick_valid("", 0));
	CHECK(!sts_nick_valid("a b", 3));
	CHECK(!sts_nick_valid("a#b", 3));
	CHECK(!sts_nick_valid("abcdefghijklmnopqrstuvwxy", 25));
	CHECK(!sts_nick_valid("a\033", 2));
	CHECK(!sts_nick_valid("\xc3\xa9", 2));

	CHECK(sts_room_valid("neotokyo"));
	CHECK(sts_room_valid("team-1.ops_x"));
	CHECK(!sts_room_valid(""));
	CHECK(!sts_room_valid("a/b"));
	CHECK(!sts_room_valid("a+"));
	CHECK(!sts_room_valid("#"));
	CHECK(sts_strcasecmp("Alice", "aLICE") == 0);
	CHECK(sts_strcasecmp("alice", "alicia") < 0);
}

static void test_hex(void)
{
	const uint8_t in[] = { 0x00, 0x7f, 0xab, 0xff };
	uint8_t back[4];
	char hex[9];

	sts_hex(in, sizeof(in), hex);
	CHECK(strcmp(hex, "007fabff") == 0);
	CHECK(sts_unhex("007FABff", back, sizeof(back)) == 0);
	CHECK(memcmp(in, back, sizeof(in)) == 0);
	CHECK(sts_unhex("00zz", back, 2) != 0);
}

static void test_paths(void)
{
	char home[STS_PATH_MAX];
	char want[STS_PATH_MAX + 32];
	char out[STS_PATH_MAX];

	REQUIRE(sts_home_dir(home, sizeof(home)) == 0);
	CHECK(sts_path_expand("~/.sts/identity.key", "/etc", out,
			      sizeof(out)) == 0);
	snprintf(want, sizeof(want), "%s/.sts/identity.key", home);
	CHECK(strcmp(out, want) == 0);

	CHECK(sts_path_expand("keys/id.key", "/home/x/sts", out, sizeof(out)) ==
	      0);
	CHECK(strcmp(out, "/home/x/sts/keys/id.key") == 0);
	CHECK(sts_path_expand("/abs/id.key", "/home/x", out, sizeof(out)) == 0);
	CHECK(strcmp(out, "/abs/id.key") == 0);
	CHECK(sts_path_expand("id.key", "/very/long/base", out, 8) != 0);

	sts_path_dirname("configs/sts.conf", out, sizeof(out));
	CHECK(strcmp(out, "configs") == 0);
	sts_path_dirname("sts.conf", out, sizeof(out));
	CHECK(strcmp(out, ".") == 0);
	sts_path_dirname("/sts.conf", out, sizeof(out));
	CHECK(strcmp(out, "/") == 0);
}

static void test_replay_window(void)
{
	struct sts_replay r;
	uint64_t s;

	memset(&r, 0, sizeof(r));
	CHECK(sts_replay_check(&r, 0) != 0);
	CHECK(sts_replay_check(&r, 5) == 0);
	sts_replay_commit(&r, 5);
	CHECK(sts_replay_check(&r, 5) != 0);
	CHECK(sts_replay_check(&r, 3) == 0);
	sts_replay_commit(&r, 3);
	CHECK(sts_replay_check(&r, 3) != 0);

	CHECK(sts_replay_check(&r, 100) == 0);
	sts_replay_commit(&r, 100);
	CHECK(sts_replay_check(&r, 5) != 0);
	CHECK(sts_replay_check(&r, 100 - STS_REPLAY_WINDOW) != 0);
	CHECK(sts_replay_check(&r, 100 - STS_REPLAY_WINDOW + 1) == 0);

	for (s = 37; s <= 100; s++)
		if (sts_replay_check(&r, s) == 0)
			sts_replay_commit(&r, s);
	for (s = 37; s <= 100; s++)
		CHECK(sts_replay_check(&r, s) != 0);
	CHECK(sts_replay_check(&r, 101) == 0);
}

static void test_files(void)
{
	char dir[STS_PATH_MAX];
	char path[STS_PATH_MAX + 32];
	char buf[32];
	FILE *fp;
	size_t n;

	test_tmpdir(dir, sizeof(dir));
	snprintf(path, sizeof(path), "%s/a/b/c", dir);
	CHECK(sts_mkdirs(path) == 0);
	CHECK(sts_mkdirs(path) == 0); /* already there */

	snprintf(path, sizeof(path), "%s/a/b/c/file", dir);
	CHECK(!sts_file_exists(path));
	CHECK(sts_file_write_atomic(path, "first", 5, 1) == 0);
	CHECK(sts_file_write_atomic(path, "second", 6, 1) == 0);
	CHECK(sts_file_exists(path));
	CHECK(!sts_file_shared(path));

	fp = sts_fopen(path, "rb");
	REQUIRE(fp != NULL);
	n = fread(buf, 1, sizeof(buf), fp);
	fclose(fp);
	CHECK(n == 6 && memcmp(buf, "second", 6) == 0);
	remove(path);
}

int main(void)
{
	RUN(test_sanitize);
	RUN(test_width);
	RUN(test_names);
	RUN(test_hex);
	RUN(test_paths);
	RUN(test_replay_window);
	RUN(test_files);
	return test_summary();
}
