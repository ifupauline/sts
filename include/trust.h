/* SPDX-License-Identifier: Apache-2.0 */
#ifndef STS_TRUST_H
#define STS_TRUST_H

/*
 * Trust-on-first-use store of peer identities (~/.sts/known_peers).
 * One line per identity: "<fingerprint hex> <verified 0|1> <last nick>".
 */

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "util.h"

enum sts_trust_status {
	STS_TRUST_NEW, /* first time we see this key */
	STS_TRUST_KNOWN, /* seen before, not verified */
	STS_TRUST_VERIFIED, /* fingerprint verified by the user */
	STS_TRUST_CONFLICT, /* new key using a nick bound to another key */
};

struct sts_trust_entry {
	uint8_t fpr[STS_HASH_LEN];
	int verified;
	char nick[STS_NICK_MAX + 1];
};

struct sts_trust {
	char path[STS_PATH_MAX];
	struct sts_trust_entry *entries;
	size_t count;
	size_t cap;
};

/* @brief load the store, a missing file is an empty store */
int sts_trust_load(struct sts_trust *t, const char *path);
int sts_trust_save(const struct sts_trust *t);
void sts_trust_free(struct sts_trust *t);

/*
 * @brief       look up a peer's key, remember it (and its current nick) and
 *              persist the store if it changed.
 */
enum sts_trust_status sts_trust_observe(struct sts_trust *t,
					const uint8_t fpr[STS_HASH_LEN],
					const char *nick);

/* @brief mark a key as verified by the user */
int sts_trust_set_verified(struct sts_trust *t, const uint8_t fpr[STS_HASH_LEN],
			   const char *nick, int verified);

int sts_trust_is_verified(const struct sts_trust *t,
			  const uint8_t fpr[STS_HASH_LEN]);

#endif /* STS_TRUST_H */
