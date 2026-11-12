/* SPDX-License-Identifier: Apache-2.0 */
/*
 * TLS client over a non-blocking socket, with mbedtls. The broker's
 * certificate is checked against the system's certificate authorities (or
 * a given CA file) and its host name.
 */
#ifndef STS_TLS_H
#define STS_TLS_H

#include <stddef.h>
#include <stdint.h>

#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#define STS_TLS_WANT_READ 1
#define STS_TLS_WANT_WRITE 2

struct sts_tls {
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt ca;
	intptr_t sock;
	int ready;
	char error[160];
};

/*
 * @ca_file     PEM file of trusted authorities, NULL or "" for the system's.
 * @verify      0 disables certificate checks (testing only).
 * @return      0 on success, -1 with a message in t->error.
 */
int sts_tls_init(struct sts_tls *t, intptr_t sock, const char *host,
		 const char *ca_file, int verify);

/* @return 0 when done, STS_TLS_WANT_READ/WRITE to call again, -1 on error */
int sts_tls_handshake(struct sts_tls *t);

/* @return like sts_sock_recv() / sts_sock_send() */
long sts_tls_read(struct sts_tls *t, void *buf, size_t len);
long sts_tls_write(struct sts_tls *t, const void *buf, size_t len);

/* @return bytes already decrypted and waiting to be read */
size_t sts_tls_pending(struct sts_tls *t);

void sts_tls_free(struct sts_tls *t);

#endif /* STS_TLS_H */
