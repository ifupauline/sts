/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Cryptographic primitives, all from mbedtls (PSA API for elliptic curves):
 *
 *   identity / signatures : ECDSA P-256 with SHA-256 (raw r||s, 64 bytes)
 *   key agreement         : ECDH P-256 with ephemeral keys
 *   key derivation        : HKDF-SHA256, PBKDF2-HMAC-SHA256 (room keys)
 *   symmetric encryption  : AES-256-GCM (96-bit nonce, 128-bit tag)
 */
#ifndef STS_CRYPTO_H
#define STS_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "mbedtls/sha256.h"
#include "psa/crypto.h"

#define STS_PUBKEY_LEN 65 /* uncompressed P-256 point 04||X||Y */
#define STS_PRIVKEY_LEN 32
#define STS_SIG_LEN 64
#define STS_KEY_LEN 32
#define STS_HASH_LEN 32
#define STS_NONCE_LEN 12
#define STS_TAG_LEN 16

/* "ABCD 0123 ..." 16 groups of 4 hex digits */
#define STS_FPR_STR_LEN 80
/* first 4 groups */
#define STS_FPR_SHORT_STR_LEN 20

/*
 * @brief       long-term identity, stored in the identity file.
 * @key         PSA handle of the ECDSA private key.
 * @pub         public key.
 * @fpr         fingerprint = SHA-256(pub), what users compare.
 */
struct sts_identity {
	psa_key_id_t key;
	uint8_t pub[STS_PUBKEY_LEN];
	uint8_t fpr[STS_HASH_LEN];
};

/* @brief ECDH key pair, never stored */
struct sts_ephemeral {
	psa_key_id_t key;
	uint8_t pub[STS_PUBKEY_LEN];
};

struct sts_sha256 {
	mbedtls_sha256_context ctx;
};

/* functions return 0 on success and -1 on failure unless stated otherwise */

int sts_crypto_init(void);
int sts_random(void *buf, size_t len);

/* wipe secrets, not optimised out by the compiler */
void sts_memzero(void *buf, size_t len);
/* constant time comparison, 0 if equal */
int sts_memcmp_ct(const void *a, const void *b, size_t len);

int sts_identity_generate(struct sts_identity *id);
int sts_identity_import(struct sts_identity *id,
			const uint8_t priv[STS_PRIVKEY_LEN]);
/* the identity file is protected and no (or a wrong) passphrase was given */
#define STS_IDENTITY_LOCKED (-2)
#define STS_PASSPHRASE_MAX 256

/*
 * @brief       load the identity from @path, or create a new one (and the
 *              directories leading to it) when the file doesn't exist.
 * @created     set to 1 when a new identity was generated.
 * @return      0, -1, or STS_IDENTITY_LOCKED for a protected file: then
 *              use sts_identity_load() with its passphrase.
 */
int sts_identity_load_or_create(struct sts_identity *id, const char *path,
				int *created);

/*
 * @brief       load the identity from @path, protected by @passphrase or
 *              not (@passphrase NULL or "").
 * @return      0, -1, or STS_IDENTITY_LOCKED if the passphrase is wrong.
 */
int sts_identity_load(struct sts_identity *id, const char *path,
		      const char *passphrase);

/* @return 1 if the file at @path is protected by a passphrase */
int sts_identity_is_protected(const char *path);

/*
 * @brief       save the identity, encrypted with @passphrase (AES-256-GCM,
 *              key from PBKDF2-HMAC-SHA256), or in clear if it is NULL or "".
 */
int sts_identity_save(const struct sts_identity *id, const char *path,
		      const char *passphrase);
void sts_identity_free(struct sts_identity *id);

int sts_sign(const struct sts_identity *id, const uint8_t hash[STS_HASH_LEN],
	     uint8_t sig[STS_SIG_LEN]);
/* @return 0 if @sig is a valid signature of @hash by @pub */
int sts_verify(const uint8_t pub[STS_PUBKEY_LEN],
	       const uint8_t hash[STS_HASH_LEN],
	       const uint8_t sig[STS_SIG_LEN]);
/* @return 0 if @pub is a valid P-256 point */
int sts_pubkey_check(const uint8_t pub[STS_PUBKEY_LEN]);

int sts_ephemeral_generate(struct sts_ephemeral *eph);
void sts_ephemeral_free(struct sts_ephemeral *eph);
/* @out receives the 32-byte shared secret, @peer is validated */
int sts_ecdh(const struct sts_ephemeral *eph,
	     const uint8_t peer[STS_PUBKEY_LEN], uint8_t out[STS_KEY_LEN]);

int sts_hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
	     size_t ikm_len, const uint8_t *info, size_t info_len, uint8_t *out,
	     size_t out_len);
int sts_pbkdf2(const uint8_t *password, size_t password_len,
	       const uint8_t *salt, size_t salt_len, unsigned int iterations,
	       uint8_t *out, size_t out_len);

void sts_sha256(const void *buf, size_t len, uint8_t out[STS_HASH_LEN]);
void sts_sha256_init(struct sts_sha256 *h);
void sts_sha256_update(struct sts_sha256 *h, const void *buf, size_t len);
void sts_sha256_final(struct sts_sha256 *h, uint8_t out[STS_HASH_LEN]);

/*
 * @brief       AES-256-GCM encryption, @out receives @len bytes of
 *              ciphertext followed by the STS_TAG_LEN tag. @out may be @pt.
 */
int sts_aead_seal(const uint8_t key[STS_KEY_LEN],
		  const uint8_t nonce[STS_NONCE_LEN], const uint8_t *aad,
		  size_t aad_len, const uint8_t *pt, size_t len, uint8_t *out);

/*
 * @brief       AES-256-GCM decryption of @ct_len bytes (ciphertext and tag)
 *              into @ct_len - STS_TAG_LEN bytes. Fails if the tag is wrong.
 */
int sts_aead_open(const uint8_t key[STS_KEY_LEN],
		  const uint8_t nonce[STS_NONCE_LEN], const uint8_t *aad,
		  size_t aad_len, const uint8_t *ct, size_t ct_len,
		  uint8_t *out);

/* "ABCD 0123 ..." */
void sts_fpr_format(const uint8_t fpr[STS_HASH_LEN], char out[STS_FPR_STR_LEN]);
void sts_fpr_format_short(const uint8_t fpr[STS_HASH_LEN],
			  char out[STS_FPR_SHORT_STR_LEN]);

#endif /* STS_CRYPTO_H */
