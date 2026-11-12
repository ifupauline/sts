// SPDX-License-Identifier: Apache-2.0
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "test.h"
#include "util.h"

static void test_aead(void)
{
	uint8_t key[STS_KEY_LEN];
	uint8_t key2[STS_KEY_LEN];
	uint8_t nonce[STS_NONCE_LEN] = { 0 };
	uint8_t aad[] = "header";
	const char *msg = "attack at dawn";
	size_t len = strlen(msg);
	uint8_t ct[64];
	uint8_t pt[64];
	size_t i;

	REQUIRE(sts_random(key, sizeof(key)) == 0);
	REQUIRE(sts_random(key2, sizeof(key2)) == 0);

	CHECK(sts_aead_seal(key, nonce, aad, sizeof(aad), (const uint8_t *)msg,
			    len, ct) == 0);
	CHECK(memcmp(ct, msg, len) != 0);
	CHECK(sts_aead_open(key, nonce, aad, sizeof(aad), ct, len + STS_TAG_LEN,
			    pt) == 0);
	CHECK(memcmp(pt, msg, len) == 0);

	for (i = 0; i < len + STS_TAG_LEN; i++) {
		ct[i] ^= 0x01;
		CHECK(sts_aead_open(key, nonce, aad, sizeof(aad), ct,
				    len + STS_TAG_LEN, pt) != 0);
		ct[i] ^= 0x01;
	}
	aad[0] ^= 1;
	CHECK(sts_aead_open(key, nonce, aad, sizeof(aad), ct, len + STS_TAG_LEN,
			    pt) != 0);
	aad[0] ^= 1;
	nonce[11] = 1;
	CHECK(sts_aead_open(key, nonce, aad, sizeof(aad), ct, len + STS_TAG_LEN,
			    pt) != 0);
	nonce[11] = 0;
	CHECK(sts_aead_open(key2, nonce, aad, sizeof(aad), ct,
			    len + STS_TAG_LEN, pt) != 0);
	CHECK(sts_aead_open(key, nonce, aad, sizeof(aad), ct, STS_TAG_LEN - 1,
			    pt) != 0);
}

static void test_signatures(void)
{
	struct sts_identity a;
	struct sts_identity b;
	uint8_t hash[STS_HASH_LEN];
	uint8_t sig[STS_SIG_LEN];
	uint8_t bad[STS_PUBKEY_LEN];

	REQUIRE(sts_identity_generate(&a) == 0);
	REQUIRE(sts_identity_generate(&b) == 0);
	sts_sha256("msg", 3, hash);

	CHECK(sts_sign(&a, hash, sig) == 0);
	CHECK(sts_verify(a.pub, hash, sig) == 0);
	CHECK(sts_verify(b.pub, hash, sig) != 0);
	sig[10] ^= 0x80;
	CHECK(sts_verify(a.pub, hash, sig) != 0);
	sig[10] ^= 0x80;
	hash[0] ^= 1;
	CHECK(sts_verify(a.pub, hash, sig) != 0);

	memcpy(bad, a.pub, sizeof(bad));
	bad[40] ^= 0x01;
	CHECK(sts_pubkey_check(a.pub) == 0);
	CHECK(sts_pubkey_check(bad) != 0);

	sts_sha256(a.pub, sizeof(a.pub), hash);
	CHECK(memcmp(hash, a.fpr, STS_HASH_LEN) == 0);
	sts_identity_free(&a);
	sts_identity_free(&b);
}

static void test_ecdh(void)
{
	struct sts_ephemeral a;
	struct sts_ephemeral b;
	uint8_t sa[STS_KEY_LEN];
	uint8_t sb[STS_KEY_LEN];
	uint8_t bad[STS_PUBKEY_LEN];

	REQUIRE(sts_ephemeral_generate(&a) == 0);
	REQUIRE(sts_ephemeral_generate(&b) == 0);
	CHECK(sts_ecdh(&a, b.pub, sa) == 0);
	CHECK(sts_ecdh(&b, a.pub, sb) == 0);
	CHECK(memcmp(sa, sb, sizeof(sa)) == 0);

	/* invalid points are refused (invalid curve attacks) */
	memset(bad, 0, sizeof(bad));
	bad[0] = 0x04;
	CHECK(sts_ecdh(&a, bad, sa) != 0);
	memcpy(bad, b.pub, sizeof(bad));
	bad[64] ^= 1;
	CHECK(sts_ecdh(&a, bad, sa) != 0);
	sts_ephemeral_free(&a);
	sts_ephemeral_free(&b);
}

/* RFC 5869 test case 1 */
static void test_hkdf_vector(void)
{
	const uint8_t salt[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
	const uint8_t info[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
				 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
	const char *expect =
		"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
		"34007208d5b887185865";
	uint8_t ikm[22];
	uint8_t okm[42];
	char hex[2 * sizeof(okm) + 1];

	memset(ikm, 0x0b, sizeof(ikm));
	CHECK(sts_hkdf(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info),
		       okm, sizeof(okm)) == 0);
	sts_hex(okm, sizeof(okm), hex);
	CHECK(strcmp(hex, expect) == 0);
}

/* RFC 7914 section 11, PBKDF2-HMAC-SHA256 */
static void test_pbkdf2_vector(void)
{
	const char *expect =
		"55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
		"49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783";
	uint8_t out[64];
	char hex[2 * sizeof(out) + 1];

	CHECK(sts_pbkdf2((const uint8_t *)"passwd", 6, (const uint8_t *)"salt",
			 4, 1, out, sizeof(out)) == 0);
	sts_hex(out, sizeof(out), hex);
	CHECK(strcmp(hex, expect) == 0);
}

static void test_identity_file(void)
{
	char dir[STS_PATH_MAX];
	char path[STS_PATH_MAX + 32];
	struct sts_identity a;
	struct sts_identity b;
	int created;
	FILE *fp;

	test_tmpdir(dir, sizeof(dir));
	snprintf(path, sizeof(path), "%s/new/dir/identity.key", dir);

	CHECK(sts_identity_load_or_create(&a, path, &created) == 0);
	CHECK(created == 1);
	CHECK(!sts_file_shared(path));
	CHECK(sts_identity_load_or_create(&b, path, &created) == 0);
	CHECK(created == 0);
	CHECK(memcmp(a.fpr, b.fpr, STS_HASH_LEN) == 0);
	sts_identity_free(&a);
	sts_identity_free(&b);

	/* a damaged file is an error, never silently replaced */
	fp = sts_fopen(path, "w");
	REQUIRE(fp != NULL);
	fputs("not a key\n", fp);
	fclose(fp);
	CHECK(sts_identity_load_or_create(&a, path, &created) != 0);
	remove(path);
}

static void test_identity_passphrase(void)
{
	char dir[STS_PATH_MAX];
	char path[STS_PATH_MAX + 32];
	char line[512];
	struct sts_identity a;
	struct sts_identity b;
	int created;
	FILE *fp;

	test_tmpdir(dir, sizeof(dir));
	snprintf(path, sizeof(path), "%s/locked.key", dir);
	REQUIRE(sts_identity_generate(&a) == 0);

	REQUIRE(sts_identity_save(&a, path, "correct horse") == 0);
	CHECK(sts_identity_is_protected(path));
	CHECK(!sts_file_shared(path));
	/* the key isn't in the file */
	fp = sts_fopen(path, "rb");
	REQUIRE(fp != NULL && fgets(line, sizeof(line), fp) != NULL);
	fclose(fp);
	CHECK(strncmp(line, "sts-key-v1:", 11) == 0);

	CHECK(sts_identity_load_or_create(&b, path, &created) ==
	      STS_IDENTITY_LOCKED);
	CHECK(sts_identity_load(&b, path, NULL) == STS_IDENTITY_LOCKED);
	CHECK(sts_identity_load(&b, path, "") == STS_IDENTITY_LOCKED);
	CHECK(sts_identity_load(&b, path, "wrong horse") ==
	      STS_IDENTITY_LOCKED);
	REQUIRE(sts_identity_load(&b, path, "correct horse") == 0);
	CHECK(memcmp(a.fpr, b.fpr, STS_HASH_LEN) == 0);
	sts_identity_free(&b);

	/* removing the passphrase */
	REQUIRE(sts_identity_save(&a, path, "") == 0);
	CHECK(!sts_identity_is_protected(path));
	REQUIRE(sts_identity_load(&b, path, "anything") == 0);
	CHECK(memcmp(a.fpr, b.fpr, STS_HASH_LEN) == 0);
	sts_identity_free(&b);

	/* a damaged protected file is an error, not a wrong passphrase */
	REQUIRE(sts_identity_save(&a, path, "pw") == 0);
	fp = sts_fopen(path, "rb+");
	REQUIRE(fp != NULL);
	fseek(fp, 15, SEEK_SET);
	fputc('z', fp);
	fclose(fp);
	CHECK(sts_identity_load(&b, path, "pw") == -1);
	sts_identity_free(&a);
	remove(path);
}

static void test_fingerprints(void)
{
	uint8_t fpr[STS_HASH_LEN];
	char full[STS_FPR_STR_LEN];
	char shrt[STS_FPR_SHORT_STR_LEN];
	size_t i;

	for (i = 0; i < sizeof(fpr); i++)
		fpr[i] = (uint8_t)(i * 17);
	sts_fpr_format(fpr, full);
	sts_fpr_format_short(fpr, shrt);
	CHECK(strlen(full) == STS_FPR_STR_LEN - 1);
	CHECK(strncmp(full, "0011 2233 4455 6677", 19) == 0);
	CHECK(strcmp(shrt, "0011 2233 4455 6677") == 0);
	CHECK(strstr(full, "AABB") != NULL);
}

int main(void)
{
	REQUIRE(sts_crypto_init() == 0);
	RUN(test_aead);
	RUN(test_signatures);
	RUN(test_ecdh);
	RUN(test_hkdf_vector);
	RUN(test_pbkdf2_vector);
	RUN(test_identity_file);
	RUN(test_identity_passphrase);
	RUN(test_fingerprints);
	return test_summary();
}
