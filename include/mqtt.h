/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Small non-blocking MQTT 3.1.1 client for one topic, built on the paho
 * MQTTPacket serializers.
 *
 * - QoS 1 in both directions: messages are acknowledged hop by hop and kept
 *   until the broker has them, across reconnections.
 * - With clean_session off the broker keeps the subscription and queues
 *   messages while the client is offline (same client id each time).
 * - Optional TLS, see tls.h.
 *
 * The caller waits on the socket from sts_mqtt_wait_spec() and calls
 * sts_mqtt_process() after every wait (at least every 250 ms for timers).
 */
#ifndef STS_MQTT_H
#define STS_MQTT_H

#include <stddef.h>
#include <stdint.h>

#include "platform.h"
#include "tls.h"
#include "util.h"

#define STS_MQTT_HOST_MAX 256
#define STS_MQTT_TOPIC_MAX 256
#define STS_MQTT_CRED_MAX 128
#define STS_MQTT_CLIENTID_MAX 24
#define STS_MQTT_WILL_MAX 4096
#define STS_MQTT_INFLIGHT 16
#define STS_MQTT_QUEUE_MAX 4096

enum sts_mqtt_state {
	STS_MQTT_CLOSED = 0,
	STS_MQTT_CONNECTING, /* TCP */
	STS_MQTT_TLS, /* TLS handshake */
	STS_MQTT_CONNACK, /* CONNECT sent */
	STS_MQTT_SUBACK, /* SUBSCRIBE sent */
	STS_MQTT_READY,
	STS_MQTT_DRAINING, /* shutting down once everything is acked */
	STS_MQTT_CLOSING, /* DISCONNECT being flushed */
};

struct sts_mqtt_opts {
	const char *host;
	int port;
	int tls;
	const char *tls_ca_file; /* NULL: system authorities */
	int tls_verify;
	const char *username; /* NULL or "" for none */
	const char *password;
	const char *client_id;
	const char *topic; /* publish and subscribe */
	int keepalive_s;
	int clean_session;
	const uint8_t *will; /* published if we vanish, or NULL */
	size_t will_len;
};

struct sts_mqtt_cb {
	/* subscribed: messages can flow */
	void (*ready)(void *ud, int session_present);
	void (*message)(void *ud, const uint8_t *payload, size_t len);
	/* connecting failed or the connection was lost */
	void (*lost)(void *ud, const char *reason);
};

struct sts_mqtt_msg;

struct sts_mqtt {
	enum sts_mqtt_state state;
	intptr_t sock;
	int use_tls;
	struct sts_tls tls;
	int tls_want_write;
	size_t tls_retry; /* length of a TLS write to repeat */

	char host[STS_MQTT_HOST_MAX];
	int port;
	int tls_verify;
	char tls_ca_file[STS_PATH_MAX];
	char username[STS_MQTT_CRED_MAX];
	char password[STS_MQTT_CRED_MAX];
	char client_id[STS_MQTT_CLIENTID_MAX];
	char topic[STS_MQTT_TOPIC_MAX];
	uint64_t keepalive_ms;
	int clean_session;
	uint8_t will[STS_MQTT_WILL_MAX];
	size_t will_len;

	struct sts_addrs addrs;
	size_t addr_next;
	uint64_t attempt_deadline_ms;
	uint64_t connect_deadline_ms;

	uint8_t *out;
	size_t out_len;
	size_t out_off;
	size_t out_cap;
	uint8_t *in;
	size_t in_len;
	size_t in_cap;

	struct sts_mqtt_msg *queue; /* unacknowledged, oldest first */
	struct sts_mqtt_msg *queue_tail;
	size_t queued;
	size_t inflight;
	uint16_t next_pid;
	uint16_t sub_pid;
	int session_present;

	uint64_t last_tx_ms;
	uint64_t last_rx_ms;
	uint64_t ping_sent_ms;
	uint64_t drain_deadline_ms;

	struct sts_mqtt_cb cb;
	void *ud;
	char error[512];
};

void sts_mqtt_init(struct sts_mqtt *m, const struct sts_mqtt_cb *cb, void *ud);

/*
 * @brief       start connecting (resolves the host name first, blocking).
 *              Messages still unacknowledged from a previous connection are
 *              sent again once subscribed.
 * @return      0 when started, -1 on immediate failure (see m->error).
 */
int sts_mqtt_connect(struct sts_mqtt *m, const struct sts_mqtt_opts *opts);

/* @brief socket to wait on (STS_SOCK_INVALID when closed) */
void sts_mqtt_wait_spec(const struct sts_mqtt *m, intptr_t *sock,
			int *want_write);

void sts_mqtt_process(struct sts_mqtt *m);

/* @brief queue a QoS 1 message, @return -1 if the queue is full */
int sts_mqtt_publish(struct sts_mqtt *m, const uint8_t *data, size_t len);

int sts_mqtt_is_ready(const struct sts_mqtt *m);
int sts_mqtt_is_closed(const struct sts_mqtt *m);

/* @brief messages not acknowledged by the broker yet */
size_t sts_mqtt_unacked(const struct sts_mqtt *m);

/*
 * @brief       finish sending, then unsubscribe (persistent session) and
 *              disconnect: the broker discards the will. Completes within a
 *              few seconds in sts_mqtt_process().
 */
void sts_mqtt_shutdown(struct sts_mqtt *m);

/* @brief close now, no callback */
void sts_mqtt_abort(struct sts_mqtt *m);

/* @brief free the queue and buffers */
void sts_mqtt_free(struct sts_mqtt *m);

const char *sts_mqtt_state_name(enum sts_mqtt_state st);

#endif /* STS_MQTT_H */
