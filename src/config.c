// SPDX-License-Identifier: Apache-2.0
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "log.h"
#include "room.h"

#define LINE_MAX_LEN 1024

void sts_config_init(struct sts_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->tls_verify = 1;
	cfg->keepalive = 30;
	cfg->rekey_interval = 600;
	cfg->ui = STS_UI_AUTO;
	cfg->max_file_size = 16ULL * 1024 * 1024;
	if (sts_path_expand("~/.sts/logs", NULL, cfg->log_dir,
			    sizeof(cfg->log_dir)) != 0)
		cfg->log_dir[0] = '\0';
}

static int set_err(char *err, size_t errlen, const char *fmt, ...)
	STS_PRINTF(3, 4);

static int set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
	return -1;
}

static int parse_int(const char *s, long min, long max, int *out)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0' || v < min || v > max)
		return -1;
	*out = (int)v;
	return 0;
}

static int parse_bool(const char *s, int *out)
{
	static const char *const yes[] = { "yes", "on", "true", "1" };
	static const char *const no[] = { "no", "off", "false", "0" };
	size_t i;

	for (i = 0; i < STS_ARRAY_SIZE(yes); i++) {
		if (sts_strcasecmp(s, yes[i]) == 0) {
			*out = 1;
			return 0;
		}
		if (sts_strcasecmp(s, no[i]) == 0) {
			*out = 0;
			return 0;
		}
	}
	return -1;
}

/* "1234", "500K", "100M", "2G" (powers of 1024) */
static int parse_size(const char *s, uint64_t *out)
{
	unsigned long long v;
	uint64_t mult = 1;
	char *end;

	errno = 0;
	if (s[0] < '0' || s[0] > '9')
		return -1;
	v = strtoull(s, &end, 10);
	if (errno != 0)
		return -1;
	switch (*end) {
	case 'k':
	case 'K':
		mult = 1024;
		end++;
		break;
	case 'm':
	case 'M':
		mult = 1024 * 1024;
		end++;
		break;
	case 'g':
	case 'G':
		mult = 1024ULL * 1024 * 1024;
		end++;
		break;
	default:
		break;
	}
	if (*end == 'B' || *end == 'b')
		end++;
	if (*end != '\0' || v == 0 || v > (64ULL << 30) / mult)
		return -1;
	*out = (uint64_t)v * mult;
	return 0;
}

static int prefix_valid(const char *p)
{
	size_t len = strlen(p);
	size_t i;

	if (len == 0 || p[0] == '/' || p[len - 1] == '/' ||
	    strstr(p, "//") != NULL)
		return 0;
	for (i = 0; i < len; i++)
		if (p[i] == '+' || p[i] == '#' || (unsigned char)p[i] <= ' ' ||
		    (unsigned char)p[i] >= 0x7f)
			return 0;
	return 1;
}

static int host_valid(const char *h)
{
	size_t i;

	if (h[0] == '\0')
		return 0;
	for (i = 0; h[i] != '\0'; i++)
		if (!((h[i] >= 'a' && h[i] <= 'z') ||
		      (h[i] >= 'A' && h[i] <= 'Z') ||
		      (h[i] >= '0' && h[i] <= '9') || h[i] == '-' ||
		      h[i] == '.' || h[i] == ':' || h[i] == '_'))
			return 0;
	return 1;
}

static int copy(char *dst, size_t cap, const char *key, const char *value,
		char *err, size_t errlen)
{
	if (sts_strlcpy(dst, value, cap) != 0)
		return set_err(err, errlen,
			       "%s is too long (at most %zu bytes)", key,
			       cap - 1);
	return 0;
}

static int set_path(char *dst, size_t cap, const char *key, const char *value,
		    const char *base_dir, char *err, size_t errlen)
{
	if (value[0] == '\0')
		return set_err(err, errlen, "%s: empty path", key);
	if (sts_path_expand(value, base_dir, dst, cap) != 0)
		return set_err(err, errlen, "%s: path too long", key);
	return 0;
}

/* "NAME" or "NAME PASSWORD" (rest of the line) */
static int add_room(struct sts_config *cfg, const char *value, char *err,
		    size_t errlen)
{
	struct sts_config_room *room;
	const char *pw;
	size_t len;
	int i;

	if (value[0] == '#')
		value++; /* "#room", as on IRC */
	len = strcspn(value, " \t");
	pw = value + len;
	while (*pw == ' ' || *pw == '\t')
		pw++;

	if (cfg->room_count >= STS_CONFIG_ROOMS_MAX)
		return set_err(err, errlen, "too many rooms (at most %d)",
			       STS_CONFIG_ROOMS_MAX);
	room = &cfg->rooms[cfg->room_count];
	memset(room, 0, sizeof(*room));
	if (len == 0 || len >= sizeof(room->name))
		return set_err(err, errlen, "invalid room name");
	memcpy(room->name, value, len);
	if (!sts_room_valid(room->name))
		return set_err(
			err, errlen,
			"invalid room name '%s' (letters, digits, '-', '_' and '.')",
			room->name);
	if (sts_strlcpy(room->password, pw, sizeof(room->password)) != 0)
		return set_err(err, errlen, "room password too long");
	for (i = 0; i < cfg->room_count; i++)
		if (sts_strcasecmp(cfg->rooms[i].name, room->name) == 0)
			return set_err(err, errlen, "room '%s' listed twice",
				       room->name);
	cfg->room_count++;
	return 0;
}

int sts_config_set(struct sts_config *cfg, const char *key, const char *value,
		   const char *base_dir, char *err, size_t errlen)
{
	if (strcmp(key, "broker") == 0) {
		if (strstr(value, "://") != NULL)
			return set_err(
				err, errlen,
				"broker: give the host name only, e.g. broker.emqx.io (use 'port' and 'tls' for the rest)");
		if (!host_valid(value))
			goto invalid;
		cfg->set |= STS_CFG_BROKER;
		return copy(cfg->broker, sizeof(cfg->broker), key, value, err,
			    errlen);
	}
	if (strcmp(key, "port") == 0) {
		if (parse_int(value, 1, 65535, &cfg->port) != 0)
			goto invalid;
		cfg->set |= STS_CFG_PORT;
		return 0;
	}
	if (strcmp(key, "username") == 0)
		return copy(cfg->username, sizeof(cfg->username), key, value,
			    err, errlen);
	if (strcmp(key, "password") == 0)
		return copy(cfg->password, sizeof(cfg->password), key, value,
			    err, errlen);
	if (strcmp(key, "tls") == 0) {
		if (parse_bool(value, &cfg->tls) != 0)
			goto invalid;
		return 0;
	}
	if (strcmp(key, "tls_verify") == 0) {
		if (parse_bool(value, &cfg->tls_verify) != 0)
			goto invalid;
		return 0;
	}
	if (strcmp(key, "tls_ca_file") == 0)
		return set_path(cfg->tls_ca_file, sizeof(cfg->tls_ca_file), key,
				value, base_dir, err, errlen);
	if (strcmp(key, "topic_prefix") == 0) {
		if (!prefix_valid(value))
			return set_err(
				err, errlen,
				"topic_prefix: invalid '%s' (no spaces, '+', '#', or '/' at either end)",
				value);
		cfg->set |= STS_CFG_TOPIC_PREFIX;
		return copy(cfg->topic_prefix, sizeof(cfg->topic_prefix), key,
			    value, err, errlen);
	}
	if (strcmp(key, "keepalive") == 0) {
		if (parse_int(value, 5, 3600, &cfg->keepalive) != 0)
			goto invalid;
		return 0;
	}
	if (strcmp(key, "nick") == 0) {
		if (!sts_nick_valid(value, strlen(value)))
			return set_err(
				err, errlen,
				"nick: invalid '%s' (1 to %d letters, digits or _-.[]^`{}|)",
				value, STS_NICK_MAX);
		cfg->set |= STS_CFG_NICK;
		return copy(cfg->nick, sizeof(cfg->nick), key, value, err,
			    errlen);
	}
	if (strcmp(key, "identity") == 0) {
		cfg->set |= STS_CFG_IDENTITY;
		return set_path(cfg->identity, sizeof(cfg->identity), key,
				value, base_dir, err, errlen);
	}
	if (strcmp(key, "known_peers") == 0) {
		cfg->set |= STS_CFG_KNOWN_PEERS;
		return set_path(cfg->known_peers, sizeof(cfg->known_peers), key,
				value, base_dir, err, errlen);
	}
	if (strcmp(key, "rekey_interval") == 0) {
		if (parse_int(value, 0, 86400, &cfg->rekey_interval) != 0 ||
		    (cfg->rekey_interval > 0 && cfg->rekey_interval < 60))
			return set_err(
				err, errlen,
				"rekey_interval: 0 (off) or 60 to 86400 seconds");
		return 0;
	}
	if (strcmp(key, "room") == 0)
		return add_room(cfg, value, err, errlen);
	if (strcmp(key, "max_file_size") == 0) {
		if (parse_size(value, &cfg->max_file_size) != 0)
			return set_err(
				err, errlen,
				"max_file_size: a size like 500K, 100M or 2G (at most 64G), not '%s'",
				value);
		return 0;
	}
	if (strcmp(key, "log") == 0) {
		if (parse_bool(value, &cfg->log) != 0)
			goto invalid;
		return 0;
	}
	if (strcmp(key, "log_dir") == 0)
		return set_path(cfg->log_dir, sizeof(cfg->log_dir), key, value,
				base_dir, err, errlen);
	if (strcmp(key, "ui") == 0) {
		if (strcmp(value, "auto") == 0)
			cfg->ui = STS_UI_AUTO;
		else if (strcmp(value, "tui") == 0 ||
			 strcmp(value, "fullscreen") == 0)
			cfg->ui = STS_UI_TUI;
		else if (strcmp(value, "plain") == 0)
			cfg->ui = STS_UI_PLAIN;
		else
			return set_err(err, errlen,
				       "ui: auto, tui or plain, not '%s'",
				       value);
		return 0;
	}
	return set_err(err, errlen, "unknown setting '%s'", key);

invalid:
	return set_err(err, errlen, "%s: invalid value '%s'", key, value);
}

static char *trim(char *s)
{
	char *end;

	while (*s == ' ' || *s == '\t')
		s++;
	end = s + strlen(s);
	while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
			   end[-1] == '\r' || end[-1] == '\n'))
		*--end = '\0';
	return s;
}

int sts_config_load(struct sts_config *cfg, const char *path, char *err,
		    size_t errlen)
{
	char line[LINE_MAX_LEN];
	char msg[512];
	unsigned long lineno = 0;
	char *key;
	char *value;
	char *sep;
	FILE *fp;
	int ret = 0;

	if (sts_strlcpy(cfg->path, path, sizeof(cfg->path)) != 0)
		return set_err(err, errlen, "%s: path too long", path);
	sts_path_dirname(path, cfg->dir, sizeof(cfg->dir));

	fp = sts_fopen(path, "rb");
	if (fp == NULL)
		return set_err(err, errlen, "cannot open %s: %s", path,
			       strerror(errno));

	while (fgets(line, sizeof(line), fp) != NULL) {
		lineno++;
		if (strchr(line, '\n') == NULL && !feof(fp)) {
			ret = set_err(err, errlen, "%s:%lu: line too long",
				      path, lineno);
			break;
		}
		key = trim(line);
		/* UTF-8 byte order mark some editors add */
		if (lineno == 1 && memcmp(key, "\xef\xbb\xbf", 3) == 0)
			key = trim(key + 3);
		if (key[0] == '\0' || key[0] == '#' || key[0] == ';')
			continue;

		sep = strchr(key, '=');
		if (sep == NULL) {
			ret = set_err(err, errlen,
				      "%s:%lu: expected 'setting = value'",
				      path, lineno);
			break;
		}
		*sep = '\0';
		key = trim(key);
		value = trim(sep + 1);
		if (sts_config_set(cfg, key, value, cfg->dir, msg,
				   sizeof(msg)) != 0) {
			ret = set_err(err, errlen, "%s:%lu: %s", path, lineno,
				      msg);
			break;
		}
	}
	fclose(fp);
	sts_memzero(line, sizeof(line));
	return ret;
}

int sts_config_check(const struct sts_config *cfg, char *err, size_t errlen)
{
	static const struct {
		unsigned int bit;
		const char *key;
	} required[] = {
		{ STS_CFG_BROKER, "broker" },
		{ STS_CFG_PORT, "port" },
		{ STS_CFG_TOPIC_PREFIX, "topic_prefix" },
		{ STS_CFG_NICK, "nick" },
		{ STS_CFG_IDENTITY, "identity" },
		{ STS_CFG_KNOWN_PEERS, "known_peers" },
	};
	size_t i;

	for (i = 0; i < STS_ARRAY_SIZE(required); i++)
		if (!(cfg->set & required[i].bit))
			return set_err(err, errlen,
				       "%s: '%s' is not set (see man sts)",
				       cfg->path, required[i].key);
	if (cfg->password[0] != '\0' && cfg->username[0] == '\0')
		return set_err(err, errlen, "%s: 'password' needs a 'username'",
			       cfg->path);
	return 0;
}

int sts_config_topic(const struct sts_config *cfg, const char *topic_hex,
		     char *out, size_t cap)
{
	int n = snprintf(out, cap, "%s/%s", cfg->topic_prefix, topic_hex);

	return n < 0 || (size_t)n >= cap ? -1 : 0;
}

int sts_broker_is_public(const char *host)
{
	static const char *const known[] = {
		"broker.emqx.io",     "broker.hivemq.com",
		"test.mosquitto.org", "mqtt.eclipseprojects.io",
		"public.mqtthq.com",  "broker-cn.emqx.io",
	};
	size_t i;

	for (i = 0; i < STS_ARRAY_SIZE(known); i++)
		if (sts_strcasecmp(host, known[i]) == 0)
			return 1;
	return 0;
}

void sts_config_usage(const char *argv0)
{
	printf("Usage: %s -c FILE\n"
	       "       %s -b HOST -p PORT [options]\n"
	       "\n"
	       "End-to-end encrypted group chat over MQTT. Either every setting comes\n"
	       "from the configuration FILE (sts --init makes one), or from the\n"
	       "options below; the two can't be mixed. See man sts.\n"
	       "\n"
	       "  -c, --config FILE        configuration file, alone\n"
	       "\n"
	       "  -b, --broker HOST        MQTT broker host name (required without -c)\n"
	       "  -p, --port PORT          MQTT broker port (required without -c)\n"
	       "  -u, --username USER      broker user name\n"
	       "  -P, --password PASS      broker password\n"
	       "      --tls                encrypt the connection to the broker\n"
	       "      --ca-file FILE       trusted authorities for TLS (default: system)\n"
	       "      --insecure           don't check the broker's TLS certificate\n"
	       "  -t, --topic-prefix STR   MQTT topic prefix shared by your group (sts)\n"
	       "      --keepalive SECS     seconds between pings to the broker (30)\n"
	       "  -n, --nick NICK          nickname (your login name)\n"
	       "  -r, --room ROOM[:PASS]   room to join, repeat for several\n"
	       "  -i, --identity FILE      identity key (~/.sts/identity.key)\n"
	       "  -k, --known-peers FILE   fingerprints of known people (~/.sts/known_peers)\n"
	       "      --plain              line by line interface, no full screen\n"
	       "      --log                keep a chat log in ~/.sts/logs\n"
	       "      --max-file-size SIZE largest file sent or accepted (16M)\n"
	       "  -v, --verbose            show protocol details\n"
	       "\n"
	       "  sts --init               create a configuration, step by step\n"
	       "  sts --passphrase FILE    protect an identity key with a passphrase,\n"
	       "                           or change or remove it\n"
	       "\n"
	       "  -V, --version            print the version\n"
	       "  -h, --help               print this help\n"
	       "\n"
	       "Examples:\n"
	       "  %s -c ~/.sts/sts.conf\n"
	       "  %s -b broker.emqx.io -p 1883 -t wonderland -n kira -r neotokyo\n"
	       "Once started, type /help for the commands.\n",
	       argv0, argv0, argv0, argv0);
}

struct option_def {
	char short_name;
	const char *long_name;
	const char *key; /* setting, or NULL for flags */
	int has_arg;
};

static const struct option_def options[] = {
	{ 'c', "config", NULL, 1 },
	{ 'b', "broker", "broker", 1 },
	{ 'p', "port", "port", 1 },
	{ 'u', "username", "username", 1 },
	{ 'P', "password", "password", 1 },
	{ 0, "tls", NULL, 0 },
	{ 0, "ca-file", "tls_ca_file", 1 },
	{ 0, "insecure", NULL, 0 },
	{ 't', "topic-prefix", "topic_prefix", 1 },
	{ 0, "keepalive", "keepalive", 1 },
	{ 'n', "nick", "nick", 1 },
	{ 'r', "room", NULL, 1 },
	{ 'i', "identity", "identity", 1 },
	{ 'k', "known-peers", "known_peers", 1 },
	{ 0, "plain", NULL, 0 },
	{ 'v', "verbose", NULL, 0 },
	{ 'V', "version", NULL, 0 },
	{ 'h', "help", NULL, 0 },
	{ 0, "max-file-size", "max_file_size", 1 },
	{ 0, "log", NULL, 0 },
	{ 0, "init", NULL, 0 },
	{ 0, "passphrase", NULL, 1 },
};

/*
 * @brief       next option of argv: "-x VALUE", "-xVALUE", "--long VALUE"
 *              or "--long=VALUE".
 * @return      1 with *def and *arg set, 0 at the end, -1 on error.
 */
static int next_option(int argc, char **argv, int *i,
		       const struct option_def **def, const char **arg)
{
	const char *s;
	const char *eq;
	size_t len;
	size_t k;

	if (*i >= argc)
		return 0;
	s = argv[(*i)++];
	*def = NULL;
	*arg = NULL;

	if (s[0] == '-' && s[1] == '-' && s[2] != '\0') {
		eq = strchr(s + 2, '=');
		len = eq != NULL ? (size_t)(eq - s - 2) : strlen(s + 2);
		for (k = 0; k < STS_ARRAY_SIZE(options); k++)
			if (strlen(options[k].long_name) == len &&
			    memcmp(options[k].long_name, s + 2, len) == 0)
				*def = &options[k];
		if (*def == NULL) {
			fprintf(stderr, "%s: unknown option '%s'\n", argv[0],
				s);
			return -1;
		}
		if (eq != NULL) {
			if (!(*def)->has_arg) {
				fprintf(stderr, "%s: '--%s' takes no value\n",
					argv[0], (*def)->long_name);
				return -1;
			}
			*arg = eq + 1;
			return 1;
		}
	} else if (s[0] == '-' && s[1] != '\0' && s[1] != '-') {
		for (k = 0; k < STS_ARRAY_SIZE(options); k++)
			if (options[k].short_name == s[1])
				*def = &options[k];
		if (*def == NULL) {
			fprintf(stderr, "%s: unknown option '-%c'\n", argv[0],
				s[1]);
			return -1;
		}
		if (s[2] != '\0') {
			if (!(*def)->has_arg) {
				fprintf(stderr, "%s: unknown option '%s'\n",
					argv[0], s);
				return -1;
			}
			*arg = s + 2;
			return 1;
		}
	} else {
		fprintf(stderr, "%s: unexpected argument '%s'\n", argv[0], s);
		return -1;
	}

	if ((*def)->has_arg) {
		if (*i >= argc) {
			fprintf(stderr, "%s: '%s' needs a value\n", argv[0], s);
			return -1;
		}
		*arg = argv[(*i)++];
	}
	return 1;
}

/* ROOM or ROOM:PASSWORD, as "ROOM PASSWORD" for add_room() */
static int cli_room(struct sts_config *cfg, const char *arg, char *err,
		    size_t errlen)
{
	char buf[STS_ROOM_MAX + STS_PASSWORD_MAX + 8];
	const char *colon = strchr(arg, ':');
	int rc;

	if (colon == NULL)
		return add_room(cfg, arg, err, errlen);
	if (snprintf(buf, sizeof(buf), "%.*s %s", (int)(colon - arg), arg,
		     colon + 1) >= (int)sizeof(buf))
		return set_err(err, errlen, "room password too long");
	rc = add_room(cfg, buf, err, errlen);
	sts_memzero(buf, sizeof(buf));
	return rc;
}

/* settings of the command line mode that the options don't give */
static int cli_defaults(struct sts_config *cfg, char *err, size_t errlen)
{
	const char *user = getenv("USER");

	if (user == NULL || !sts_nick_valid(user, strlen(user)))
		user = "guest";
	if (sts_config_set(cfg, "nick", user, ".", err, errlen) != 0 ||
	    sts_config_set(cfg, "topic_prefix", "sts", ".", err, errlen) != 0 ||
	    sts_config_set(cfg, "identity", "~/.sts/identity.key", ".", err,
			   errlen) != 0 ||
	    sts_config_set(cfg, "known_peers", "~/.sts/known_peers", ".", err,
			   errlen) != 0)
		return -1;
	return 0;
}

static int apply_option(struct sts_config *cfg, const struct option_def *def,
			const char *arg, char *err, size_t errlen)
{
	/* paths on the command line are relative to the current directory */
	if (def->key != NULL)
		return sts_config_set(cfg, def->key, arg, ".", err, errlen);
	if (def->short_name == 'r')
		return cli_room(cfg, arg, err, errlen);
	if (strcmp(def->long_name, "tls") == 0)
		cfg->tls = 1;
	else if (strcmp(def->long_name, "insecure") == 0)
		cfg->tls_verify = 0;
	else if (strcmp(def->long_name, "plain") == 0)
		cfg->ui = STS_UI_PLAIN;
	else if (strcmp(def->long_name, "log") == 0)
		cfg->log = 1;
	else if (def->short_name == 'v')
		cfg->verbose = 1;
	return 0;
}

enum sts_args_result sts_config_parse_args(struct sts_config *cfg, int argc,
					   char **argv)
{
	const struct option_def *def;
	const struct option_def *other = NULL;
	const char *config = NULL;
	const char *arg;
	char name[32];
	char err[512];
	int configs = 0;
	int rc;
	int i;

	/* pass 1: --help, --version, and which of the two ways it is */
	i = 1;
	while ((rc = next_option(argc, argv, &i, &def, &arg)) > 0) {
		if (def->short_name == 'h') {
			sts_config_usage(argv[0]);
			return STS_ARGS_EXIT_OK;
		}
		if (def->short_name == 'V') {
			printf("sts %s\n", STS_VERSION);
			return STS_ARGS_EXIT_OK;
		}
		if (def->short_name == 0 &&
		    (strcmp(def->long_name, "init") == 0 ||
		     strcmp(def->long_name, "passphrase") == 0)) {
			int init = def->long_name[0] == 'i';

			if (argc != (init ? 2 : 3)) {
				fprintf(stderr,
					"%s: --%s takes no other option\n",
					argv[0], def->long_name);
				return STS_ARGS_ERROR;
			}
			if (init)
				return STS_ARGS_INIT;
			if (sts_path_expand(arg, NULL, cfg->identity,
					    sizeof(cfg->identity)) != 0)
				return STS_ARGS_ERROR;
			return STS_ARGS_PASSPHRASE;
		}
		if (def->short_name == 'c') {
			config = arg;
			configs++;
		} else if (other == NULL) {
			other = def;
		}
	}
	if (rc < 0) {
		fprintf(stderr, "Try '%s --help'.\n", argv[0]);
		return STS_ARGS_ERROR;
	}

	/* 1. everything from the file */
	if (config != NULL) {
		if (configs > 1 || other != NULL) {
			if (other == NULL) {
				fprintf(stderr, "%s: -c given twice\n",
					argv[0]);
				return STS_ARGS_ERROR;
			}
			if (other->short_name != 0)
				snprintf(name, sizeof(name), "-%c",
					 other->short_name);
			else
				snprintf(name, sizeof(name), "--%s",
					 other->long_name);
			fprintf(stderr,
				"%s: -c can't be combined with %s: put the settings in the file,\n"
				"or start without -c: %s -b HOST -p PORT [options]\n",
				argv[0], name, argv[0]);
			return STS_ARGS_ERROR;
		}
		if (sts_config_load(cfg, config, err, sizeof(err)) != 0 ||
		    sts_config_check(cfg, err, sizeof(err)) != 0) {
			fprintf(stderr, "%s: %s\n", argv[0], err);
			return STS_ARGS_ERROR;
		}
		return STS_ARGS_OK;
	}

	/* 2. everything from the command line */
	if (other == NULL) {
		fprintf(stderr,
			"%s: give a configuration file or a broker:\n"
			"  %s -c FILE                    (%s --init makes one)\n"
			"  %s -b HOST -p PORT [options]\n"
			"See '%s --help'.\n",
			argv[0], argv[0], argv[0], argv[0], argv[0]);
		return STS_ARGS_ERROR;
	}
	if (cli_defaults(cfg, err, sizeof(err)) != 0) {
		fprintf(stderr, "%s: %s\n", argv[0], err);
		return STS_ARGS_ERROR;
	}
	i = 1;
	while (next_option(argc, argv, &i, &def, &arg) > 0) {
		if (apply_option(cfg, def, arg, err, sizeof(err)) != 0) {
			fprintf(stderr, "%s: %s\n", argv[0], err);
			return STS_ARGS_ERROR;
		}
	}
	if (!(cfg->set & STS_CFG_BROKER) || !(cfg->set & STS_CFG_PORT)) {
		fprintf(stderr,
			"%s: without -c, both -b HOST and -p PORT are needed\n",
			argv[0]);
		return STS_ARGS_ERROR;
	}
	if (sts_config_check(cfg, err, sizeof(err)) != 0) {
		fprintf(stderr, "%s: %s\n", argv[0], err);
		return STS_ARGS_ERROR;
	}
	return STS_ARGS_OK;
}
