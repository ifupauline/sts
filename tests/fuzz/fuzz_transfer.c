// SPDX-License-Identifier: Apache-2.0
/*
 * FILE frames, as a member of the room sends them once decrypted. Bob
 * receives from Alice and accepts every offer; he also offers a file to
 * Alice at the start of each input, so the answers to it can be tried.
 *
 * The input is a list of frames, each a 2 byte big endian length and the
 * bytes. When the first byte of a frame (the operation) has its top bit
 * set, the bit is removed and the next 8 bytes become the id of Bob's
 * offer, which is random. Time moves on between the frames.
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../bus.h"
#include "fuzz.h"
#include "platform.h"
#include "transfer.h"

static struct bus bus;
static struct client *alice;
static struct client *bob;
static struct sts_xfers xs;
static unsigned int counter;
static char tmp[32];
static char dir[64];
static char src[96];

/* FUZZ_DEBUG=1 shows what happens */
static void on_event(void *ud, const struct sts_xfer_event *ev)
{
	static int debug = -1;

	(void)ud;
	if (debug < 0)
		debug = getenv("FUZZ_DEBUG") != NULL;
	if (debug)
		fprintf(stderr, "event %d %s %s\n", (int)ev->type,
			ev->xfer->name, ev->detail ? ev->detail : "");
}

static uint64_t mono(void *ud)
{
	(void)ud;
	return bus_mono;
}

static const struct sts_xfer_ops ops = {
	.event = on_event,
	.monotonic_ms = mono,
};

static void hook(struct client *c, const struct sts_event *ev)
{
	(void)c;
	if (ev->type == STS_EV_FILE)
		sts_xfers_handle(&xs, ev->member, ev->text, ev->text_len);
}

static void empty_dir(void);

static void cleanup(void)
{
	empty_dir();
	rmdir(dir);
	unlink(src);
	rmdir(tmp);
}

static void setup(void)
{
	FILE *fp;

	snprintf(tmp, sizeof(tmp), "/tmp/sts-fuzz-XXXXXX");
	if (sts_crypto_init() != 0 || mkdtemp(tmp) == NULL)
		abort();
	atexit(cleanup);
	snprintf(dir, sizeof(dir), "%s/in", tmp);
	snprintf(src, sizeof(src), "%s/offer.txt", tmp);
	if (sts_mkdirs(dir) != 0)
		abort();
	fp = fopen(src, "wb");
	if (fp == NULL || fwrite("hello alice\n", 1, 12, fp) != 12)
		abort();
	fclose(fp);

	bus_init(&bus);
	alice = bus_client(&bus);
	bob = bus_client(&bus);
	bob->hook = hook;
	if (bus_join(alice, "neotokyo", "alice") != 0 ||
	    bus_join(bob, "neotokyo", "bob") != 0)
		abort();
	alice->connected = 0;
	bob->connected = 0;
}

/* what was received: Bob never replaces a file, so they pile up */
static void empty_dir(void)
{
	char path[sizeof(dir) + 256 + 2];
	struct dirent *e;
	DIR *d = opendir(dir);

	if (d == NULL)
		return;
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.' &&
		    (e->d_name[1] == '\0' || strcmp(e->d_name, "..") == 0))
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		unlink(path);
	}
	closedir(d);
}

static void accept_offers(void)
{
	char err[256];
	size_t i;

	for (i = 0; i < STS_XFER_SLOTS; i++)
		if (!xs.x[i].outgoing && xs.x[i].state == STS_XFER_OFFERED)
			sts_xfer_accept(&xs, xs.x[i].num, dir, err,
					sizeof(err));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static uint8_t frame[STS_FILE_FRAME_MAX];
	const struct sts_member *from;
	char err[256];
	uint64_t id = 0;
	size_t len;
	size_t i;
	int num;

	if (alice == NULL)
		setup();
	from = member_of(bob, alice);
	if (from == NULL)
		abort();

	sts_xfers_init(&xs, &bob->room, &counter, &ops, NULL);
	xs.max_size = 1024 * 1024;
	num = sts_xfer_send(&xs, alice->room.sid, src, err, sizeof(err));
	for (i = 0; num >= 0 && i < STS_XFER_SLOTS; i++)
		if (xs.x[i].outgoing && xs.x[i].num == (unsigned int)num)
			id = xs.x[i].id;

	while (size >= 2) {
		len = (size_t)data[0] << 8 | data[1];
		data += 2;
		size -= 2;
		if (len > size || len > sizeof(frame))
			len = size < sizeof(frame) ? size : sizeof(frame);
		memcpy(frame, data, len);
		data += len;
		size -= len;
		if (len >= 9 && (frame[0] & 0x80)) {
			frame[0] &= 0x7f;
			for (i = 0; i < 8; i++)
				frame[1 + i] = (uint8_t)(id >> (56 - 8 * i));
		}
		sts_xfers_handle(&xs, from, frame, len);
		accept_offers();
		bus_mono += 700;
		sts_xfers_tick(&xs);
		bus.qhead = 0;
		bus.qtail = 0;
		bus.nlog = 0;
	}
	sts_xfers_free(&xs);
	empty_dir();
	return 0;
}
