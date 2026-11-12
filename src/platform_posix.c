// SPDX-License-Identifier: Apache-2.0
/*
 * POSIX implementation of platform.h, for Linux.
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "platform.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static volatile sig_atomic_t sig_quit;
static volatile sig_atomic_t sig_winch;

static struct termios saved_termios;
static int raw_active;

int sts_platform_init(void)
{
	signal(SIGPIPE, SIG_IGN);
	return 0;
}

void sts_platform_cleanup(void)
{
}

int sts_resolve(const char *host, int port, struct sts_addrs *out, char *err,
		size_t errlen)
{
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *ai;
	char portstr[8];
	int rc;

	memset(out, 0, sizeof(*out));
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	snprintf(portstr, sizeof(portstr), "%d", port);

	rc = getaddrinfo(host, portstr, &hints, &res);
	if (rc != 0) {
		snprintf(err, errlen, "%s", gai_strerror(rc));
		return -1;
	}

	for (ai = res; ai != NULL && out->count < STS_ADDR_MAX;
	     ai = ai->ai_next) {
		struct sts_addr *a = &out->addr[out->count];

		if (ai->ai_addrlen > sizeof(a->data))
			continue;
		a->family = ai->ai_family;
		a->len = (int)ai->ai_addrlen;
		memcpy(a->data, ai->ai_addr, ai->ai_addrlen);
		out->count++;
	}
	freeaddrinfo(res);

	if (out->count == 0) {
		snprintf(err, errlen, "no usable address");
		return -1;
	}
	return 0;
}

int sts_sock_connect(const struct sts_addr *addr, intptr_t *sock)
{
	int one = 1;
	int flags;
	int fd;

	*sock = STS_SOCK_INVALID;

	fd = socket(addr->family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0)
		return -1;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
	    fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		close(fd);
		return -1;
	}

	/* chat messages are small and interactive */
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

	*sock = fd;
	if (connect(fd, (const struct sockaddr *)addr->data,
		    (socklen_t)addr->len) == 0)
		return 0;
	if (errno == EINPROGRESS)
		return 1;

	close(fd);
	*sock = STS_SOCK_INVALID;
	return -1;
}

int sts_sock_connect_finish(intptr_t sock)
{
	socklen_t len = sizeof(int);
	int err = 0;

	if (getsockopt((int)sock, SOL_SOCKET, SO_ERROR, &err, &len) != 0)
		return -1;
	if (err != 0) {
		errno = err;
		return -1;
	}
	return 0;
}

long sts_sock_send(intptr_t sock, const void *buf, size_t len)
{
	ssize_t n;

	do {
		n = send((int)sock, buf, len, MSG_NOSIGNAL);
	} while (n < 0 && errno == EINTR);

	if (n >= 0)
		return (long)n;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return STS_IO_AGAIN;
	return STS_IO_ERROR;
}

long sts_sock_recv(intptr_t sock, void *buf, size_t len)
{
	ssize_t n;

	do {
		n = recv((int)sock, buf, len, 0);
	} while (n < 0 && errno == EINTR);

	if (n >= 0)
		return (long)n;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return STS_IO_AGAIN;
	return STS_IO_ERROR;
}

void sts_sock_close(intptr_t sock)
{
	if (sock != STS_SOCK_INVALID)
		close((int)sock);
}

const char *sts_sock_error(void)
{
	return strerror(errno);
}

int sts_wait(struct sts_wait *w, size_t n, int watch_input, int timeout_ms,
	     int *input)
{
	struct pollfd pfd[33];
	size_t count = 0;
	size_t i;
	int rc;

	*input = 0;
	if (n > 32)
		return -1;

	for (i = 0; i < n; i++) {
		w[i].readable = 0;
		w[i].writable = 0;
		pfd[count].fd = (int)w[i].sock;
		pfd[count].events = POLLIN | (w[i].want_write ? POLLOUT : 0);
		pfd[count].revents = 0;
		count++;
	}
	if (watch_input) {
		pfd[count].fd = STDIN_FILENO;
		pfd[count].events = POLLIN;
		pfd[count].revents = 0;
		count++;
	}

	rc = poll(pfd, (nfds_t)count, timeout_ms);
	if (rc < 0)
		return errno == EINTR ? 0 : -1;

	for (i = 0; i < n; i++) {
		short rev = pfd[i].revents;

		/* errors surface as a failing read or write */
		w[i].readable = (rev & (POLLIN | POLLERR | POLLHUP)) != 0;
		w[i].writable = (rev & (POLLOUT | POLLERR | POLLHUP)) != 0;
	}
	if (watch_input && pfd[n].revents != 0)
		*input = 1;
	return 0;
}

long sts_input_read(void *buf, size_t len)
{
	struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
	ssize_t n;

	/* stdin stays blocking (it is shared with the shell): ask first */
	if (poll(&pfd, 1, 0) == 0)
		return STS_IO_AGAIN;
	n = read(STDIN_FILENO, buf, len);
	if (n < 0)
		return (errno == EAGAIN || errno == EINTR) ? STS_IO_AGAIN :
							     STS_IO_ERROR;
	return (long)n;
}

/* --- terminal ------------------------------------------------------------ */

int sts_term_is_tty(void)
{
	return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
}

static void on_winch(int sig)
{
	(void)sig;
	sig_winch = 1;
}

int sts_term_raw(void)
{
	struct sigaction sa;
	struct termios t;

	if (tcgetattr(STDIN_FILENO, &saved_termios) != 0)
		return -1;

	t = saved_termios;
	t.c_iflag &= ~(unsigned int)(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
	t.c_oflag &= ~(unsigned int)OPOST;
	t.c_cflag |= CS8;
	t.c_lflag &= ~(unsigned int)(ECHO | ICANON | IEXTEN | ISIG);
	t.c_cc[VMIN] = 0;
	t.c_cc[VTIME] = 0;

	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) != 0)
		return -1;
	raw_active = 1;
	atexit(sts_term_restore);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_winch;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGWINCH, &sa, NULL);
	return 0;
}

void sts_term_restore(void)
{
	if (!raw_active)
		return;
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_termios);
	raw_active = 0;
}

int sts_term_size(int *rows, int *cols)
{
	struct winsize ws;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != 0 || ws.ws_row == 0 ||
	    ws.ws_col == 0)
		return -1;
	*rows = ws.ws_row;
	*cols = ws.ws_col;
	return 0;
}

int sts_term_resized(void)
{
	if (!sig_winch)
		return 0;
	sig_winch = 0;
	return 1;
}

void sts_term_write(const char *buf, size_t len)
{
	ssize_t n;

	while (len > 0) {
		n = write(STDOUT_FILENO, buf, len);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return;
		}
		buf += n;
		len -= (size_t)n;
	}
}

/* --- signals ------------------------------------------------------------- */

static void on_quit(int sig)
{
	(void)sig;
	sig_quit = 1;
}

void sts_signals_install(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_quit;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);
}

int sts_signals_quit(void)
{
	return sig_quit != 0;
}

/* --- files --------------------------------------------------------------- */

FILE *sts_fopen(const char *path, const char *mode)
{
	return fopen(path, mode);
}

int sts_file_exists(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0;
}

int sts_ask(const char *prompt, char *out, size_t cap, int secret)
{
	struct termios saved;
	struct termios t;
	size_t len = 0;
	ssize_t n;
	char c;
	int fd;

	fd = open("/dev/tty", O_RDWR | O_CLOEXEC);
	if (fd < 0 || cap == 0)
		return -1;
	if (secret && tcgetattr(fd, &saved) == 0) {
		t = saved;
		t.c_lflag &= ~(tcflag_t)ECHO;
		tcsetattr(fd, TCSAFLUSH, &t);
	} else {
		secret = 0;
	}
	if (write(fd, prompt, strlen(prompt)) < 0)
		len = 0;

	for (;;) {
		n = read(fd, &c, 1);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0 || c == '\n')
			break;
		if (len + 1 < cap)
			out[len++] = c;
	}
	if (len > 0 && out[len - 1] == '\r')
		len--;
	out[len] = '\0';
	c = 0;

	if (secret) {
		tcsetattr(fd, TCSAFLUSH, &saved);
		if (write(fd, "\n", 1) < 0)
			len = 0;
	}
	close(fd);
	return n < 0 ? -1 : 0;
}

FILE *sts_file_create(const char *path)
{
	FILE *fp;
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
		  0600);
	if (fd < 0)
		return NULL;
	fp = fdopen(fd, "wb");
	if (fp == NULL)
		close(fd);
	return fp;
}

FILE *sts_file_append(const char *path)
{
	FILE *fp;
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC,
		  0600);
	if (fd < 0)
		return NULL;
	fp = fdopen(fd, "a");
	if (fp == NULL)
		close(fd);
	return fp;
}

int sts_file_link_new(const char *from, const char *to)
{
	if (link(from, to) == 0)
		return 0;
	return errno == EEXIST ? 1 : -1;
}

int sts_is_dir(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int sts_mkdirs(const char *path)
{
	char tmp[1024];
	size_t len;
	size_t i;

	len = strlen(path);
	if (len == 0 || len >= sizeof(tmp))
		return -1;
	memcpy(tmp, path, len + 1);

	for (i = 1; i <= len; i++) {
		if (tmp[i] != '/' && tmp[i] != '\0')
			continue;
		tmp[i] = '\0';
		if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
			return -1;
		if (i < len)
			tmp[i] = '/';
	}
	return 0;
}

int sts_file_write_atomic(const char *path, const void *buf, size_t len,
			  int private_file)
{
	mode_t mode = private_file ? 0600 : 0644;
	char tmp[1100];
	const char *p = buf;
	ssize_t w;
	int fd;
	int n;

	n = snprintf(tmp, sizeof(tmp), "%s.tmp%ld", path, (long)getpid());
	if (n < 0 || (size_t)n >= sizeof(tmp))
		return -1;

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (fd < 0)
		return -1;

	/* enforce the mode whatever the umask */
	if (fchmod(fd, mode) != 0)
		goto fail;

	while (len > 0) {
		w = write(fd, p, len);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			goto fail;
		}
		p += w;
		len -= (size_t)w;
	}

	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		unlink(tmp);
		return -1;
	}
	if (rename(tmp, path) != 0) {
		unlink(tmp);
		return -1;
	}
	return 0;
fail:
	close(fd);
	unlink(tmp);
	return -1;
}

int sts_file_shared(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && (st.st_mode & 077) != 0;
}

int sts_home_dir(char *out, size_t cap)
{
	const char *home = getenv("HOME");
	struct passwd *pw;
	int n;

	if (home == NULL || home[0] == '\0') {
		pw = getpwuid(getuid());
		if (pw == NULL || pw->pw_dir == NULL)
			return -1;
		home = pw->pw_dir;
	}

	n = snprintf(out, cap, "%s", home);
	return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

int sts_path_is_absolute(const char *path)
{
	return path[0] == '/';
}

/* --- time ---------------------------------------------------------------- */

uint64_t sts_monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

uint64_t sts_wallclock_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

void sts_localtime(time_t t, struct tm *tm)
{
	localtime_r(&t, tm);
}
