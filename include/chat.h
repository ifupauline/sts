/* SPDX-License-Identifier: Apache-2.0 */
#ifndef STS_CHAT_H
#define STS_CHAT_H

#include "config.h"

/* @brief run the chat until /quit, @return the process exit status */
int sts_chat_run(const struct sts_config *cfg);

#endif /* STS_CHAT_H */
