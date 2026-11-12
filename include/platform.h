/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Operating system abstraction: sockets, waiting for I/O, the terminal,
 * files, clocks and signals, implemented by platform_posix.c.
 */
#ifndef STS_PLATFORM_H
#define STS_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

/* socket handle, the same type on every platform */
#define STS_SOCK_INVALID ((intptr_t)(-1))

/* sts_sock_send() / sts_sock_recv() results besides byte counts */
#define STS_IO_AGAIN (-2) /* would block, retry when ready */
#define STS_IO_ERROR (-1)

#define STS_ADDR_MAX 8

struct sts_addr {
	int family;
	int len;
	unsigned char data[128];
};

struct sts_addrs {
	size_t count;
	struct sts_addr addr[STS_ADDR_MAX];
};

/*
 * @brief       process-wide setup (SIGPIPE ignored). Call once at startup.
 * @return      0 on success, -1 on failure.
 */
int sts_platform_init(void);
void sts_platform_cleanup(void);

/*
 * @brief       resolve @host (name or numeric address, IPv4 or IPv6).
 * @return      0 on success, -1 on failure with an error message in @err.
 */
int sts_resolve(const char *host, int port, struct sts_addrs *out, char *err,
		size_t errlen);

/*
 * @brief       start a non-blocking connect.
 * @return      0 if connected, 1 if in progress (wait until writable, then
 *              call sts_sock_connect_finish()), -1 on failure.
 */
int sts_sock_connect(const struct sts_addr *addr, intptr_t *sock);
int sts_sock_connect_finish(intptr_t sock);

/* @return bytes transferred, 0 on EOF (recv only), STS_IO_AGAIN or STS_IO_ERROR */
long sts_sock_send(intptr_t sock, const void *buf, size_t len);
long sts_sock_recv(intptr_t sock, void *buf, size_t len);
void sts_sock_close(intptr_t sock);

/* @brief description of the last socket error */
const char *sts_sock_error(void);

/* one socket to wait on */
struct sts_wait {
	intptr_t sock;
	int want_write;
	/* results */
	int readable;
	int writable;
};

/*
 * @brief       wait until a socket is ready, keyboard/stdin input is
 *              available (if @watch_input) or @timeout_ms elapsed.
 * @input       set to 1 when input is available.
 * @return      0 on success (timeout included), -1 on failure.
 */
int sts_wait(struct sts_wait *w, size_t n, int watch_input, int timeout_ms,
	     int *input);

/*
 * @brief       read available input bytes without blocking. In raw mode
 *              keys are returned as UTF-8 text and VT escape sequences on
 *              every platform.
 * @return      bytes read, 0 at end of input, STS_IO_AGAIN if nothing.
 */
long sts_input_read(void *buf, size_t len);

/* --- terminal ------------------------------------------------------------ */

/* @return 1 if stdin and stdout are both a terminal */
int sts_term_is_tty(void);

/*
 * @brief       raw keyboard input, VT output and UTF-8. Restored by
 *              sts_term_restore(), also on exit.
 */
int sts_term_raw(void);
void sts_term_restore(void);

/* @return 0 on success with the terminal size, -1 if unknown */
int sts_term_size(int *rows, int *cols);

/* @return 1 once after the terminal was resized */
int sts_term_resized(void);

/* write everything to stdout */
void sts_term_write(const char *buf, size_t len);

/*
 * @brief       ask a question on the terminal (/dev/tty) and read the answer,
 *              without showing it if @secret.
 * @return      0, or -1 without a terminal.
 */
int sts_ask(const char *prompt, char *out, size_t cap, int secret);

/* --- signals ------------------------------------------------------------- */

/* Ctrl-C, termination and hang-up request a clean exit */
void sts_signals_install(void);
int sts_signals_quit(void);

/* --- files --------------------------------------------------------------- */

/* @brief fopen(), the single place files are opened */
FILE *sts_fopen(const char *path, const char *mode);

/* @return 1 if the file exists */
int sts_file_exists(const char *path);

/*
 * @brief       create the directory (and its parents), readable by the
 *              owner only when created.
 */
int sts_mkdirs(const char *path);

/*
 * @brief       replace @path atomically. With @private the file is only
 *              readable by its owner.
 */
int sts_file_write_atomic(const char *path, const void *buf, size_t len,
			  int private_file);

/*
 * @brief       create a new file readable by its owner only, never
 *              following or replacing an existing file or link.
 * @return      the file opened for writing, NULL if @path exists or on error.
 */
FILE *sts_file_create(const char *path);

/* @brief open @path to append, created readable by its owner only */
FILE *sts_file_append(const char *path);

/*
 * @brief       give the file @from the additional name @to, atomically and
 *              only if @to doesn't exist yet.
 * @return      0, 1 if @to exists, -1 on other errors.
 */
int sts_file_link_new(const char *from, const char *to);

/* @return 1 if @path is a directory */
int sts_is_dir(const char *path);

/* @return 1 if other users can read @path */
int sts_file_shared(const char *path);

/* @brief the user's home directory */
int sts_home_dir(char *out, size_t cap);

int sts_path_is_absolute(const char *path);

/* --- time ---------------------------------------------------------------- */

uint64_t sts_monotonic_ms(void);
uint64_t sts_wallclock_ms(void);
void sts_localtime(time_t t, struct tm *tm);

#endif /* STS_PLATFORM_H */
