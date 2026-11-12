// SPDX-License-Identifier: Apache-2.0
#include <stdio.h>
#include <string.h>

#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "psa/crypto.h"

#include "platform.h"
#include "tls.h"
#include "util.h"

/* where distributions keep the bundle of trusted authorities */
static const char *const ca_bundles[] = {
	"/etc/ssl/certs/ca-certificates.crt", /* Debian, Ubuntu, Arch */
	"/etc/pki/tls/certs/ca-bundle.crt", /* Fedora, RHEL */
	"/etc/ssl/ca-bundle.pem", /* openSUSE */
	"/etc/ssl/cert.pem", /* Alpine */
};

static int rng(void *ctx, unsigned char *buf, size_t len)
{
	(void)ctx;
	return psa_generate_random(buf, len) == PSA_SUCCESS ?
		       0 :
		       MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
	struct sts_tls *t = ctx;
	long n = sts_sock_send(t->sock, buf, len);

	if (n == STS_IO_AGAIN)
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	if (n < 0)
		return MBEDTLS_ERR_NET_SEND_FAILED;
	return (int)n;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
	struct sts_tls *t = ctx;
	long n = sts_sock_recv(t->sock, buf, len);

	if (n == STS_IO_AGAIN)
		return MBEDTLS_ERR_SSL_WANT_READ;
	if (n < 0)
		return MBEDTLS_ERR_NET_RECV_FAILED;
	return (int)n;
}

static void set_error(struct sts_tls *t, const char *what, int ret)
{
	char msg[96];

	mbedtls_strerror(ret, msg, sizeof(msg));
	snprintf(t->error, sizeof(t->error), "%s: %s", what, msg);
}

static int load_system_cas(struct sts_tls *t)
{
	size_t i;

	for (i = 0; i < STS_ARRAY_SIZE(ca_bundles); i++)
		if (sts_file_exists(ca_bundles[i]) &&
		    mbedtls_x509_crt_parse_file(&t->ca, ca_bundles[i]) >= 0)
			return 0;
	return -1;
}

int sts_tls_init(struct sts_tls *t, intptr_t sock, const char *host,
		 const char *ca_file, int verify)
{
	int ret;

	memset(t, 0, sizeof(*t));
	t->sock = sock;
	mbedtls_ssl_init(&t->ssl);
	mbedtls_ssl_config_init(&t->conf);
	mbedtls_x509_crt_init(&t->ca);

	ret = mbedtls_ssl_config_defaults(&t->conf, MBEDTLS_SSL_IS_CLIENT,
					  MBEDTLS_SSL_TRANSPORT_STREAM,
					  MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		set_error(t, "TLS configuration", ret);
		return -1;
	}
	mbedtls_ssl_conf_rng(&t->conf, rng, NULL);
	mbedtls_ssl_conf_min_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_2);

	if (verify) {
		if (ca_file != NULL && ca_file[0] != '\0') {
			ret = mbedtls_x509_crt_parse_file(&t->ca, ca_file);
			if (ret < 0) {
				set_error(t, ca_file, ret);
				return -1;
			}
		} else if (load_system_cas(t) != 0) {
			snprintf(
				t->error, sizeof(t->error),
				"no trusted certificate authorities found, set tls_ca_file");
			return -1;
		}
		mbedtls_ssl_conf_ca_chain(&t->conf, &t->ca, NULL);
		mbedtls_ssl_conf_authmode(&t->conf,
					  MBEDTLS_SSL_VERIFY_REQUIRED);
	} else {
		mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_NONE);
	}

	ret = mbedtls_ssl_setup(&t->ssl, &t->conf);
	if (ret == 0)
		ret = mbedtls_ssl_set_hostname(&t->ssl, host);
	if (ret != 0) {
		set_error(t, "TLS setup", ret);
		return -1;
	}
	mbedtls_ssl_set_bio(&t->ssl, t, bio_send, bio_recv, NULL);
	return 0;
}

int sts_tls_handshake(struct sts_tls *t)
{
	char info[128];
	uint32_t flags;
	int ret;

	ret = mbedtls_ssl_handshake(&t->ssl);
	if (ret == 0) {
		t->ready = 1;
		return 0;
	}
	if (ret == MBEDTLS_ERR_SSL_WANT_READ)
		return STS_TLS_WANT_READ;
	if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
		return STS_TLS_WANT_WRITE;

	flags = mbedtls_ssl_get_verify_result(&t->ssl);
	if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED && flags != 0 &&
	    flags != (uint32_t)-1) {
		mbedtls_x509_crt_verify_info(info, sizeof(info), "", flags);
		info[strcspn(info, "\n")] = '\0';
		snprintf(t->error, sizeof(t->error),
			 "broker certificate rejected: %s", info);
	} else {
		set_error(t, "TLS handshake", ret);
	}
	return -1;
}

long sts_tls_read(struct sts_tls *t, void *buf, size_t len)
{
	int ret;

	for (;;) {
		ret = mbedtls_ssl_read(&t->ssl, buf, len);
		if (ret >= 0)
			return ret;
		switch (ret) {
		case MBEDTLS_ERR_SSL_WANT_READ:
		case MBEDTLS_ERR_SSL_WANT_WRITE:
			return STS_IO_AGAIN;
		case MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET:
			continue; /* TLS 1.3, not data */
		case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
			return 0;
		default:
			set_error(t, "TLS read", ret);
			return STS_IO_ERROR;
		}
	}
}

long sts_tls_write(struct sts_tls *t, const void *buf, size_t len)
{
	int ret = mbedtls_ssl_write(&t->ssl, buf, len);

	if (ret >= 0)
		return ret;
	if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
	    ret == MBEDTLS_ERR_SSL_WANT_WRITE)
		return STS_IO_AGAIN;
	set_error(t, "TLS write", ret);
	return STS_IO_ERROR;
}

size_t sts_tls_pending(struct sts_tls *t)
{
	return mbedtls_ssl_get_bytes_avail(&t->ssl);
}

void sts_tls_free(struct sts_tls *t)
{
	if (t->ready)
		mbedtls_ssl_close_notify(&t->ssl);
	mbedtls_ssl_free(&t->ssl);
	mbedtls_ssl_config_free(&t->conf);
	mbedtls_x509_crt_free(&t->ca);
	memset(t, 0, sizeof(*t));
}
