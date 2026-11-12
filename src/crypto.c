// SPDX-License-Identifier: Apache-2.0
#include <stdio.h>
#include <string.h>

#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/platform_util.h"

#include "crypto.h"
#include "log.h"
#include "platform.h"
#include "util.h"

#define ECC_FAMILY PSA_ECC_FAMILY_SECP_R1
#define ECC_BITS 256
#define ALG_SIGN PSA_ALG_ECDSA(PSA_ALG_SHA_256)

int sts_crypto_init(void)
{
	if (psa_crypto_init() != PSA_SUCCESS) {
		ERROR("crypto: psa_crypto_init() failed");
		return -1;
	}
	return 0;
}

int sts_random(void *buf, size_t len)
{
	return psa_generate_random(buf, len) == PSA_SUCCESS ? 0 : -1;
}

void sts_memzero(void *buf, size_t len)
{
	mbedtls_platform_zeroize(buf, len);
}

int sts_memcmp_ct(const void *a, const void *b, size_t len)
{
	const volatile uint8_t *pa = a;
	const volatile uint8_t *pb = b;
	uint8_t diff = 0;
	size_t i;

	for (i = 0; i < len; i++)
		diff |= pa[i] ^ pb[i];
	return diff != 0;
}

/* --- identity ------------------------------------------------------------ */

static int identity_finish(struct sts_identity *id)
{
	size_t olen;

	if (psa_export_public_key(id->key, id->pub, sizeof(id->pub), &olen) !=
		    PSA_SUCCESS ||
	    olen != STS_PUBKEY_LEN) {
		psa_destroy_key(id->key);
		id->key = 0;
		return -1;
	}
	sts_sha256(id->pub, sizeof(id->pub), id->fpr);
	return 0;
}

static void identity_attributes(psa_key_attributes_t *attr)
{
	psa_set_key_type(attr, PSA_KEY_TYPE_ECC_KEY_PAIR(ECC_FAMILY));
	psa_set_key_bits(attr, ECC_BITS);
	psa_set_key_usage_flags(attr,
				PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(attr, ALG_SIGN);
}

int sts_identity_generate(struct sts_identity *id)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

	memset(id, 0, sizeof(*id));
	identity_attributes(&attr);

	if (psa_generate_key(&attr, &id->key) != PSA_SUCCESS) {
		ERROR("crypto: cannot generate an identity key");
		return -1;
	}
	return identity_finish(id);
}

int sts_identity_import(struct sts_identity *id,
			const uint8_t priv[STS_PRIVKEY_LEN])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

	memset(id, 0, sizeof(*id));
	identity_attributes(&attr);

	if (psa_import_key(&attr, priv, STS_PRIVKEY_LEN, &id->key) !=
	    PSA_SUCCESS)
		return -1;
	return identity_finish(id);
}

/*
 * Protected identity file, one line:
 *   sts-key-v1:<salt hex>:<iterations>:<nonce hex>:<ciphertext and tag hex>
 * key = PBKDF2-HMAC-SHA256(passphrase, salt, iterations), AES-256-GCM with
 * the "sts-key-v1" prefix as additional data.
 */
#define KEY_MAGIC "sts-key-v1"
#define KEY_SALT_LEN 16
#define KEY_ITERATIONS 300000
#define KEY_ITERATIONS_MAX 10000000
#define KEY_LINE_MAX 512

static int passphrase_key(const char *passphrase, const uint8_t *salt,
			  unsigned int iterations, uint8_t key[STS_KEY_LEN])
{
	return sts_pbkdf2((const uint8_t *)passphrase, strlen(passphrase), salt,
			  KEY_SALT_LEN, iterations, key, STS_KEY_LEN);
}

int sts_identity_save(const struct sts_identity *id, const char *path,
		      const char *passphrase)
{
	uint8_t priv[STS_PRIVKEY_LEN];
	uint8_t ct[STS_PRIVKEY_LEN + STS_TAG_LEN];
	uint8_t salt[KEY_SALT_LEN];
	uint8_t nonce[STS_NONCE_LEN];
	uint8_t key[STS_KEY_LEN];
	char line[KEY_LINE_MAX];
	char salt_hex[2 * KEY_SALT_LEN + 1];
	char nonce_hex[2 * STS_NONCE_LEN + 1];
	char ct_hex[2 * sizeof(ct) + 1];
	size_t olen;
	int ret = -1;

	if (psa_export_key(id->key, priv, sizeof(priv), &olen) != PSA_SUCCESS ||
	    olen != sizeof(priv))
		return -1;

	if (passphrase == NULL || passphrase[0] == '\0') {
		sts_hex(priv, sizeof(priv), line);
		strcat(line, "\n");
	} else {
		if (sts_random(salt, sizeof(salt)) != 0 ||
		    sts_random(nonce, sizeof(nonce)) != 0)
			goto out;
		if (passphrase_key(passphrase, salt, KEY_ITERATIONS, key) != 0)
			goto out;
		if (sts_aead_seal(key, nonce, (const uint8_t *)KEY_MAGIC,
				  strlen(KEY_MAGIC), priv, sizeof(priv),
				  ct) != 0)
			goto out;
		sts_hex(salt, sizeof(salt), salt_hex);
		sts_hex(nonce, sizeof(nonce), nonce_hex);
		sts_hex(ct, sizeof(ct), ct_hex);
		snprintf(line, sizeof(line), "%s:%s:%u:%s:%s\n", KEY_MAGIC,
			 salt_hex, KEY_ITERATIONS, nonce_hex, ct_hex);
	}
	ret = sts_file_write_atomic(path, line, strlen(line), 1);
out:
	sts_memzero(priv, sizeof(priv));
	sts_memzero(key, sizeof(key));
	sts_memzero(line, sizeof(line));
	return ret;
}

static int identity_create(struct sts_identity *id, const char *path)
{
	char dir[STS_PATH_MAX];

	sts_path_dirname(path, dir, sizeof(dir));
	if (sts_mkdirs(dir) != 0) {
		ERROR("crypto: cannot create the directory %s", dir);
		return -1;
	}

	if (sts_identity_generate(id) != 0)
		return -1;

	if (sts_identity_save(id, path, NULL) != 0) {
		ERROR("crypto: cannot save the identity to %s", path);
		sts_identity_free(id);
		return -1;
	}
	return 0;
}

/* @return the first line of @path without its newline, or -1 */
static int read_key_line(const char *path, char *line, size_t cap)
{
	FILE *fp = sts_fopen(path, "rb");
	size_t n;

	if (fp == NULL) {
		ERROR("crypto: cannot open the identity %s", path);
		return -1;
	}
	n = fread(line, 1, cap - 1, fp);
	fclose(fp);
	line[n] = '\0';
	line[strcspn(line, "\r\n")] = '\0';
	return 0;
}

int sts_identity_is_protected(const char *path)
{
	char line[KEY_LINE_MAX];
	int prot;

	if (read_key_line(path, line, sizeof(line)) != 0)
		return 0;
	prot = strncmp(line, KEY_MAGIC ":", strlen(KEY_MAGIC) + 1) == 0;
	sts_memzero(line, sizeof(line));
	return prot;
}

/* decrypt "salt:iterations:nonce:ct" into @priv */
static int unlock(const char *fields, const char *passphrase,
		  uint8_t priv[STS_PRIVKEY_LEN])
{
	uint8_t ct[STS_PRIVKEY_LEN + STS_TAG_LEN];
	uint8_t salt[KEY_SALT_LEN];
	uint8_t nonce[STS_NONCE_LEN];
	uint8_t key[STS_KEY_LEN];
	char salt_hex[2 * KEY_SALT_LEN + 1];
	char nonce_hex[2 * STS_NONCE_LEN + 1];
	char ct_hex[2 * sizeof(ct) + 1];
	unsigned int iterations;
	char end;
	int ret;

	if (sscanf(fields, "%32[0-9a-f]:%u:%24[0-9a-f]:%96[0-9a-f]%c", salt_hex,
		   &iterations, nonce_hex, ct_hex, &end) != 4 ||
	    strlen(salt_hex) != 2 * KEY_SALT_LEN ||
	    strlen(nonce_hex) != 2 * STS_NONCE_LEN ||
	    strlen(ct_hex) != 2 * sizeof(ct) || iterations == 0 ||
	    iterations > KEY_ITERATIONS_MAX ||
	    sts_unhex(salt_hex, salt, sizeof(salt)) != 0 ||
	    sts_unhex(nonce_hex, nonce, sizeof(nonce)) != 0 ||
	    sts_unhex(ct_hex, ct, sizeof(ct)) != 0)
		return -1;
	if (passphrase == NULL || passphrase[0] == '\0')
		return STS_IDENTITY_LOCKED;

	ret = passphrase_key(passphrase, salt, iterations, key);
	if (ret == 0 &&
	    sts_aead_open(key, nonce, (const uint8_t *)KEY_MAGIC,
			  strlen(KEY_MAGIC), ct, sizeof(ct), priv) != 0)
		ret = STS_IDENTITY_LOCKED;
	sts_memzero(key, sizeof(key));
	return ret;
}

int sts_identity_load(struct sts_identity *id, const char *path,
		      const char *passphrase)
{
	uint8_t priv[STS_PRIVKEY_LEN];
	char line[KEY_LINE_MAX];
	size_t magic = strlen(KEY_MAGIC);
	int ret;

	if (read_key_line(path, line, sizeof(line)) != 0)
		return -1;

	if (sts_file_shared(path))
		WARN("identity file %s is readable by other users, run: chmod 600 %s",
		     path, path);

	if (strncmp(line, KEY_MAGIC ":", magic + 1) == 0)
		ret = unlock(line + magic + 1, passphrase, priv);
	else if (strlen(line) == 2 * STS_PRIVKEY_LEN)
		ret = sts_unhex(line, priv, sizeof(priv));
	else
		ret = -1;
	sts_memzero(line, sizeof(line));

	if (ret == STS_IDENTITY_LOCKED)
		return ret;
	if (ret == 0)
		ret = sts_identity_import(id, priv);
	sts_memzero(priv, sizeof(priv));
	if (ret != 0)
		ERROR("crypto: identity file %s is malformed or contains an invalid key",
		      path);
	return ret;
}

int sts_identity_load_or_create(struct sts_identity *id, const char *path,
				int *created)
{
	*created = 0;
	if (!sts_file_exists(path)) {
		if (identity_create(id, path) != 0)
			return -1;
		*created = 1;
		return 0;
	}
	return sts_identity_load(id, path, NULL);
}

void sts_identity_free(struct sts_identity *id)
{
	if (id->key != 0)
		psa_destroy_key(id->key);
	memset(id, 0, sizeof(*id));
}

/* --- signatures ---------------------------------------------------------- */

int sts_sign(const struct sts_identity *id, const uint8_t hash[STS_HASH_LEN],
	     uint8_t sig[STS_SIG_LEN])
{
	size_t olen;

	if (psa_sign_hash(id->key, ALG_SIGN, hash, STS_HASH_LEN, sig,
			  STS_SIG_LEN, &olen) != PSA_SUCCESS ||
	    olen != STS_SIG_LEN)
		return -1;
	return 0;
}

static int import_public(const uint8_t pub[STS_PUBKEY_LEN], psa_key_id_t *key)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(ECC_FAMILY));
	psa_set_key_bits(&attr, ECC_BITS);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attr, ALG_SIGN);

	/* psa_import_key() checks that the point is on the curve */
	return psa_import_key(&attr, pub, STS_PUBKEY_LEN, key) == PSA_SUCCESS ?
		       0 :
		       -1;
}

int sts_verify(const uint8_t pub[STS_PUBKEY_LEN],
	       const uint8_t hash[STS_HASH_LEN], const uint8_t sig[STS_SIG_LEN])
{
	psa_key_id_t key;
	psa_status_t st;

	if (import_public(pub, &key) != 0)
		return -1;

	st = psa_verify_hash(key, ALG_SIGN, hash, STS_HASH_LEN, sig,
			     STS_SIG_LEN);
	psa_destroy_key(key);
	return st == PSA_SUCCESS ? 0 : -1;
}

int sts_pubkey_check(const uint8_t pub[STS_PUBKEY_LEN])
{
	psa_key_id_t key;

	if (import_public(pub, &key) != 0)
		return -1;
	psa_destroy_key(key);
	return 0;
}

/* --- ECDH ---------------------------------------------------------------- */

int sts_ephemeral_generate(struct sts_ephemeral *eph)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	size_t olen;

	memset(eph, 0, sizeof(*eph));

	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(ECC_FAMILY));
	psa_set_key_bits(&attr, ECC_BITS);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

	if (psa_generate_key(&attr, &eph->key) != PSA_SUCCESS)
		return -1;

	if (psa_export_public_key(eph->key, eph->pub, sizeof(eph->pub),
				  &olen) != PSA_SUCCESS ||
	    olen != STS_PUBKEY_LEN) {
		sts_ephemeral_free(eph);
		return -1;
	}
	return 0;
}

void sts_ephemeral_free(struct sts_ephemeral *eph)
{
	if (eph->key != 0)
		psa_destroy_key(eph->key);
	memset(eph, 0, sizeof(*eph));
}

int sts_ecdh(const struct sts_ephemeral *eph,
	     const uint8_t peer[STS_PUBKEY_LEN], uint8_t out[STS_KEY_LEN])
{
	size_t olen;

	/* PSA validates the peer's point */
	if (psa_raw_key_agreement(PSA_ALG_ECDH, eph->key, peer, STS_PUBKEY_LEN,
				  out, STS_KEY_LEN, &olen) != PSA_SUCCESS ||
	    olen != STS_KEY_LEN) {
		sts_memzero(out, STS_KEY_LEN);
		return -1;
	}
	return 0;
}

/* --- hashing and key derivation ------------------------------------------ */

int sts_hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
	     size_t ikm_len, const uint8_t *info, size_t info_len, uint8_t *out,
	     size_t out_len)
{
	const mbedtls_md_info_t *md;

	md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (md == NULL)
		return -1;

	return mbedtls_hkdf(md, salt, salt_len, ikm, ikm_len, info, info_len,
			    out, out_len) == 0 ?
		       0 :
		       -1;
}

int sts_pbkdf2(const uint8_t *password, size_t password_len,
	       const uint8_t *salt, size_t salt_len, unsigned int iterations,
	       uint8_t *out, size_t out_len)
{
	return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, password,
					     password_len, salt, salt_len,
					     iterations, (uint32_t)out_len,
					     out) == 0 ?
		       0 :
		       -1;
}

void sts_sha256(const void *buf, size_t len, uint8_t out[STS_HASH_LEN])
{
	mbedtls_sha256(buf, len, out, 0);
}

void sts_sha256_init(struct sts_sha256 *h)
{
	mbedtls_sha256_init(&h->ctx);
	mbedtls_sha256_starts(&h->ctx, 0);
}

void sts_sha256_update(struct sts_sha256 *h, const void *buf, size_t len)
{
	mbedtls_sha256_update(&h->ctx, buf, len);
}

void sts_sha256_final(struct sts_sha256 *h, uint8_t out[STS_HASH_LEN])
{
	mbedtls_sha256_finish(&h->ctx, out);
	mbedtls_sha256_free(&h->ctx);
}

/* --- AEAD ---------------------------------------------------------------- */

int sts_aead_seal(const uint8_t key[STS_KEY_LEN],
		  const uint8_t nonce[STS_NONCE_LEN], const uint8_t *aad,
		  size_t aad_len, const uint8_t *pt, size_t len, uint8_t *out)
{
	mbedtls_gcm_context gcm;
	int ret;

	mbedtls_gcm_init(&gcm);
	ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key,
				 STS_KEY_LEN * 8);
	if (ret == 0)
		ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len,
						nonce, STS_NONCE_LEN, aad,
						aad_len, pt, out, STS_TAG_LEN,
						out + len);
	mbedtls_gcm_free(&gcm);
	return ret == 0 ? 0 : -1;
}

int sts_aead_open(const uint8_t key[STS_KEY_LEN],
		  const uint8_t nonce[STS_NONCE_LEN], const uint8_t *aad,
		  size_t aad_len, const uint8_t *ct, size_t ct_len,
		  uint8_t *out)
{
	mbedtls_gcm_context gcm;
	size_t len;
	int ret;

	if (ct_len < STS_TAG_LEN)
		return -1;
	len = ct_len - STS_TAG_LEN;

	mbedtls_gcm_init(&gcm);
	ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key,
				 STS_KEY_LEN * 8);
	if (ret == 0)
		ret = mbedtls_gcm_auth_decrypt(&gcm, len, nonce, STS_NONCE_LEN,
					       aad, aad_len, ct + len,
					       STS_TAG_LEN, ct, out);
	mbedtls_gcm_free(&gcm);
	return ret == 0 ? 0 : -1;
}

/* --- fingerprints -------------------------------------------------------- */

static void fpr_format(const uint8_t *fpr, size_t groups, char *out)
{
	char hex[2 * STS_HASH_LEN + 1];
	size_t i;
	size_t j;
	size_t o = 0;

	sts_hex(fpr, STS_HASH_LEN, hex);

	for (i = 0; i < groups; i++) {
		if (i > 0)
			out[o++] = ' ';
		for (j = 0; j < 4; j++) {
			char c = hex[4 * i + j];

			out[o++] = (c >= 'a' && c <= 'f') ? (char)(c - 32) : c;
		}
	}
	out[o] = '\0';
}

void sts_fpr_format(const uint8_t fpr[STS_HASH_LEN], char out[STS_FPR_STR_LEN])
{
	fpr_format(fpr, STS_HASH_LEN / 2, out);
}

void sts_fpr_format_short(const uint8_t fpr[STS_HASH_LEN],
			  char out[STS_FPR_SHORT_STR_LEN])
{
	fpr_format(fpr, 4, out);
}
