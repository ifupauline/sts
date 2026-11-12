// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>

#include "chat.h"
#include "config.h"
#include "crypto.h"
#include "log.h"
#include "platform.h"
#include "setup.h"

int main(int argc, char **argv)
{
	static struct sts_config cfg;
	int status = EXIT_FAILURE;

	if (sts_platform_init() != 0)
		return EXIT_FAILURE;

	sts_config_init(&cfg);
	switch (sts_config_parse_args(&cfg, argc, argv)) {
	case STS_ARGS_OK:
		break;
	case STS_ARGS_EXIT_OK:
		status = EXIT_SUCCESS;
		goto out;
	case STS_ARGS_INIT:
		status = sts_setup_init();
		goto out;
	case STS_ARGS_PASSPHRASE:
		status = sts_setup_passphrase(cfg.identity);
		goto out;
	case STS_ARGS_ERROR:
	default:
		goto out;
	}

	sts_log_set_level(cfg.verbose ? STS_LOG_DEBUG : STS_LOG_WARN);
	if (sts_crypto_init() == 0)
		status = sts_chat_run(&cfg);
out:
	sts_platform_cleanup();
	return status;
}
