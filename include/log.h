/* SPDX-License-Identifier: Apache-2.0 */
#ifndef STS_LOG_H
#define STS_LOG_H

enum sts_log_level {
	STS_LOG_ERROR = 0,
	STS_LOG_WARN = 1,
	STS_LOG_INFO = 2,
	STS_LOG_DEBUG = 3,
};

#ifdef __MINGW32__
#define STS_PRINTF(fmt, args) __attribute__((format(gnu_printf, fmt, args)))
#else
#define STS_PRINTF(fmt, args) __attribute__((format(printf, fmt, args)))
#endif

void sts_log_set_level(enum sts_log_level level);
enum sts_log_level sts_log_get_level(void);

/*
 * @brief       send formatted log lines (without trailing newline) to @sink
 *              instead of stderr. The user interface installs one so log
 *              output doesn't break the screen. NULL restores stderr.
 */
void sts_log_set_sink(void (*sink)(enum sts_log_level level, const char *line));

void sts_log(enum sts_log_level level, const char *fmt, ...) STS_PRINTF(2, 3);

#define ERROR(...) sts_log(STS_LOG_ERROR, __VA_ARGS__)
#define WARN(...) sts_log(STS_LOG_WARN, __VA_ARGS__)
#define INFO(...) sts_log(STS_LOG_INFO, __VA_ARGS__)
#define DEBUG(...) sts_log(STS_LOG_DEBUG, __VA_ARGS__)

#endif /* STS_LOG_H */
