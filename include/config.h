/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Settings come either from the configuration file given with -c, alone,
 * or from the command line options, with -b and -p required. The two ways
 * don't mix.
 */
#ifndef STS_CONFIG_H
#define STS_CONFIG_H

#include "mqtt.h"
#include "util.h"

#define STS_PREFIX_MAX 128
#define STS_CONFIG_ROOMS_MAX 8

enum sts_ui_mode {
	STS_UI_AUTO, /* full screen on a terminal, else plain */
	STS_UI_TUI,
	STS_UI_PLAIN, /* line by line, for scripts and pipes */
};

struct sts_config_room {
	char name[STS_ROOM_MAX + 1];
	char password[STS_PASSWORD_MAX + 1];
};

struct sts_config {
	char path[STS_PATH_MAX];
	char dir[STS_PATH_MAX]; /* relative paths start here */

	char broker[STS_MQTT_HOST_MAX];
	int port;
	char username[STS_MQTT_CRED_MAX];
	char password[STS_MQTT_CRED_MAX];
	int tls;
	int tls_verify;
	char tls_ca_file[STS_PATH_MAX];
	char topic_prefix[STS_PREFIX_MAX];
	int keepalive;

	char nick[STS_NICK_MAX + 1];
	char identity[STS_PATH_MAX];
	char known_peers[STS_PATH_MAX];
	int rekey_interval; /* seconds, 0 disables */

	struct sts_config_room rooms[STS_CONFIG_ROOMS_MAX];
	int room_count;

	uint64_t max_file_size; /* bytes, sending and accepting */
	int log; /* keep a chat log */
	char log_dir[STS_PATH_MAX];

	enum sts_ui_mode ui;
	int verbose;

	unsigned int set; /* STS_CFG_* given so far */
};

/* settings without a default */
#define STS_CFG_BROKER (1u << 0)
#define STS_CFG_PORT (1u << 1)
#define STS_CFG_NICK (1u << 2)
#define STS_CFG_IDENTITY (1u << 3)
#define STS_CFG_KNOWN_PEERS (1u << 4)
#define STS_CFG_TOPIC_PREFIX (1u << 5)
#define STS_CFG_REQUIRED ((1u << 6) - 1)

enum sts_args_result {
	STS_ARGS_OK,
	STS_ARGS_EXIT_OK, /* --help or --version printed */
	STS_ARGS_ERROR,
	STS_ARGS_INIT, /* sts --init */
	STS_ARGS_PASSPHRASE, /* sts --passphrase FILE: cfg->identity */
};

void sts_config_init(struct sts_config *cfg);

/*
 * @brief       apply one setting. Paths are resolved against @base_dir
 *              ("~/" is the home directory).
 * @return      0, or -1 with a message in @err.
 */
int sts_config_set(struct sts_config *cfg, const char *key, const char *value,
		   const char *base_dir, char *err, size_t errlen);

/*
 * @brief       read "key = value" lines, '#' starts a comment. Unknown keys
 *              and bad values are errors so that typos don't go unnoticed.
 * @return      0, or -1 with a message ("file:line: ...") in @err.
 */
int sts_config_load(struct sts_config *cfg, const char *path, char *err,
		    size_t errlen);

/*
 * @brief       "-c FILE" alone, or "-b HOST -p PORT [options]" with
 *              defaults for the rest. Errors are printed on stderr.
 */
enum sts_args_result sts_config_parse_args(struct sts_config *cfg, int argc,
					   char **argv);

/* @return 0 if every required setting is there, else -1 and @err */
int sts_config_check(const struct sts_config *cfg, char *err, size_t errlen);

/* @brief "<topic_prefix>/<topic_hex>" */
int sts_config_topic(const struct sts_config *cfg, const char *topic_hex,
		     char *out, size_t cap);

/* @return 1 for well known public brokers, where anybody can listen */
int sts_broker_is_public(const char *host);

void sts_config_usage(const char *argv0);

#endif /* STS_CONFIG_H */
