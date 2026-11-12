// SPDX-License-Identifier: Apache-2.0
#include <stdarg.h>
#include <stdio.h>

#include "log.h"

static enum sts_log_level log_level = STS_LOG_INFO;
static void (*log_sink)(enum sts_log_level level, const char *line);

static const char *const level_names[] = { "error", "warn", "info", "debug" };

void sts_log_set_level(enum sts_log_level level)
{
	log_level = level;
}

enum sts_log_level sts_log_get_level(void)
{
	return log_level;
}

void sts_log_set_sink(void (*sink)(enum sts_log_level level, const char *line))
{
	log_sink = sink;
}

void sts_log(enum sts_log_level level, const char *fmt, ...)
{
	char line[1024];
	va_list args;

	if (level > log_level)
		return;

	va_start(args, fmt);
	vsnprintf(line, sizeof(line), fmt, args);
	va_end(args);

	if (log_sink != NULL) {
		log_sink(level, line);
		return;
	}
	fprintf(stderr, "[%s] %s\n", level_names[level], line);
}
