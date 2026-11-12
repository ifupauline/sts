// SPDX-License-Identifier: Apache-2.0
/*
 * Frames received on the room topic. Bob is in the room with Alice; the
 * input is either a frame as it comes from the broker, or an inner frame
 * that the harness wraps with the room key, as anyone who knows the room
 * name (and password) could. The first byte chooses:
 *
 *   bit 0  wrap the rest with the room key
 *   bit 1  write Alice's session id as the sender (inner frames)
 *   bit 2  write Bob's session id as the recipient (inner frames)
 *   bit 3  let a second pass, so timers run
 */
#include <string.h>

#include "../bus.h"
#include "crypto.h"
#include "fuzz.h"
#include "room.h"

static struct bus bus;
static struct client *alice;
static struct client *bob;

static void setup(void)
{
	if (sts_crypto_init() != 0)
		abort();
	bus_init(&bus);
	alice = bus_client(&bus);
	bob = bus_client(&bus);
	if (bus_join(alice, "neotokyo", "alice") != 0 ||
	    bus_join(bob, "neotokyo", "bob") != 0)
		abort();
	/* bob takes what comes, alone */
	alice->connected = 0;
}

static size_t wrap(const uint8_t *inner, size_t len, uint8_t *wire)
{
	uint8_t padded[STS_FRAME_MAX + STS_PAD_BLOCK];
	size_t plen =
		(2 + len + STS_PAD_BLOCK - 1) / STS_PAD_BLOCK * STS_PAD_BLOCK;

	memset(padded, 0, sizeof(padded));
	padded[0] = (uint8_t)(len >> 8);
	padded[1] = (uint8_t)len;
	memcpy(&padded[2], inner, len);
	wire[0] = STS_PROTO_MAGIC;
	wire[1] = STS_PROTO_VERSION;
	memset(&wire[2], 0x42, STS_NONCE_LEN);
	sts_aead_seal(alice->room.keys.outer_key, &wire[2], wire, 2, padded,
		      plen, &wire[2 + STS_NONCE_LEN]);
	return 2 + STS_NONCE_LEN + plen + STS_TAG_LEN;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static uint8_t inner[STS_FRAME_MAX];
	static uint8_t wire[STS_WIRE_MAX];
	uint8_t mode;
	size_t len;

	if (alice == NULL)
		setup();
	if (size < 1)
		return 0;
	mode = data[0];
	data++;
	size--;

	if (mode & 1) {
		if (size > STS_FRAME_MAX - 2 * STS_SID_LEN)
			return 0;
		memcpy(inner, data, size);
		len = size;
		if ((mode & 2) && len >= 2 + STS_SID_LEN)
			memcpy(&inner[2], alice->room.sid, STS_SID_LEN);
		if ((mode & 4) && len >= STS_HDR_LEN + STS_SID_LEN)
			memcpy(&inner[STS_HDR_LEN], bob->room.sid, STS_SID_LEN);
		len = wrap(inner, len, wire);
		sts_room_handle(&bob->room, wire, len);
	} else {
		if (size > STS_WIRE_MAX)
			return 0;
		sts_room_handle(&bob->room, data, size);
	}
	if (mode & 8) {
		bus_mono += 1500;
		bus_wall += 1500;
		sts_room_tick(&bob->room);
	}
	bus.qhead = 0;
	bus.qtail = 0;
	bus.nlog = 0;
	bob->nevents = 0;
	return 0;
}
