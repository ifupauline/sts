/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Interactive helpers on the terminal: creating a configuration file,
 * protecting an identity key, unlocking it at start.
 */
#ifndef STS_SETUP_H
#define STS_SETUP_H

#include "crypto.h"

/* @brief sts --init, @return the process exit status */
int sts_setup_init(void);

/* @brief sts --passphrase FILE, @return the process exit status */
int sts_setup_passphrase(const char *path);

/*
 * @brief       load the identity at @path, creating it if needed, asking
 *              for its passphrase if it is protected.
 * @return      0, or -1 after printing why.
 */
int sts_setup_identity(struct sts_identity *id, const char *path, int *created);

#endif /* STS_SETUP_H */
