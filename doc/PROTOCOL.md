# STS v3 protocol

STS is an end-to-end encrypted group chat protocol on top of MQTT. The
broker is not trusted: it relays opaque frames and may drop, delay, reorder,
duplicate or replay them, and anyone who can publish on the topic can inject
frames. None of that lets it read messages, forge them, or pass for a member.

Every client runs the same code. Anyone who knows the room name (and its
password, if it has one) can join or leave at any time.

The implementation is `src/room.c` (protocol), `src/transfer.c` (files),
`src/mqtt.c` (transport) and `src/tls.c` (TLS to the broker). The tests in
`tests/test_room.c` and `tests/test_fuzz.c` run it against an in-memory
broker that loses, reorders and replays frames, and `tests/fuzz/` has the
libFuzzer targets.

## Building blocks

| Purpose               | Algorithm                                         |
| --------------------- | ------------------------------------------------- |
| Identity, signatures  | ECDSA P-256 with SHA-256, raw `r‖s` (64 bytes)    |
| Key agreement         | ECDH P-256 with ephemeral keys                    |
| Key derivation        | HKDF-SHA256 (RFC 5869), PBKDF2-HMAC-SHA256        |
| Encryption            | AES-256-GCM, 96-bit nonce, 128-bit tag            |
| Fingerprint           | SHA-256 of the uncompressed identity public key   |

All cryptography comes from Mbed TLS 3.6 (PSA API). Public keys are
validated when imported (point on the curve), which also rules out
invalid-curve attacks on ECDH. Integers are big endian. `‖` is
concatenation, labels are ASCII strings followed by a NUL byte.

## Keys

- **Identity key**: long-term ECDSA key in the file named by `identity`.
  Its fingerprint is what people compare to make sure they talk to the
  right person (`/whois`, `/trust`). A device should have its own identity.
- **Session**: every start of the program in a room is a session, with a
  random 16-byte `sid_nonce` and the session id
  `sid = SHA-256("STS3/sid" ‖ id_pub ‖ sid_nonce)[0..8]`. The same identity
  can have several sessions (devices) in a room; they are told apart by
  their session id.
- **Ephemeral key**: ECDH key of the session, replaced every
  `rekey_interval` seconds (generation `eph_gen` counts up).
- **Sender key**: random AES key a session encrypts its room messages with.
  It is replaced (`epoch` counts up) when someone leaves, at every rekey,
  after 1000 messages, when a peer restarted its side of the handshake,
  and when a new session becomes active if the key already encrypted a
  message: a newcomer never gets a key that protected what was said
  before it came. The exception is the session's first 10 seconds in the
  room (`STS_DISCOVERY_MS`, from its first connection): the sessions it
  meets then were there before it, and get the key of what it wrote
  meanwhile. A session only gets the sender key once it is active, that
  is once it shows up in the list: see Challenges below.
- **Room keys**, from the room name (in lower case: `NeoTokyo` and
  `neotokyo` are the same room) and password:

  ```
  master   = PBKDF2-HMAC-SHA256("STS3/room" ‖ len(room) ‖ room ‖
                                len(password) ‖ password,
                                salt = "STS3/room-salt", 100000 iterations)
  topic_id = HKDF(master, info = "STS3/topic")[0..16]
  outer    = HKDF(master, info = "STS3/outer")[0..32]
  ```

  The MQTT topic is `<topic_prefix>/<hex(topic_id)>`: neither the room name
  nor the password appear on the broker, and a different password is a
  different room.

## Outer frame

Every MQTT message is

```
'S' (0x53) | version (0x03) | nonce[12] | AES-GCM(outer, nonce, aad = the 2 first bytes,
                                                   len u16 | inner | zero padding)
```

The inner frame is padded to a multiple of 256 bytes, so the broker sees
neither who sends, nor the frame type, nor the exact length. The nonce is
random. The outer layer only hides metadata from people who don't know the
room; everything below is protected by keys of the members themselves.

## Inner frames

All inner frames start with `type u8 | reserved u8 | sender sid[8]`.

| Type | Name    | Protection                  | Purpose                          |
| ---- | ------- | --------------------------- | -------------------------------- |
| 1    | HELLO   | signed                      | announce a session               |
| 2    | KEYDIST | pairwise                    | handshake, sender key            |
| 3    | KEYREQ  | pairwise                    | ask for a sender key again       |
| 4    | DM      | pairwise                    | private message                  |
| 5    | MSG     | sender key + signed         | room message                     |
| 6    | RESEND  | pairwise                    | ask for lost frames              |
| 7    | AWAY    | signed                      | connection lost (MQTT will)      |
| 8    | LEAVE   | signed                      | session ended                    |
| 9    | FILE    | pairwise                    | file transfer                    |

Signatures are over `SHA-256(label ‖ topic_id ‖ frame without signature)`,
with the labels `STS3/HELLO`, `STS3/MSG`, `STS3/AWAY` and `STS3/LEAVE`, so a
frame can't be replayed in another room or as another type.

### HELLO

```
hdr | flags u8 | counter u64 | conn u32 | sid_nonce[16] | id_pub[65]
    | eph_gen u32 | eph_pub[65]
    | nick_len u8 | nick | sk_epoch u32 | sk_seq u64 | signature[64]
```

- `sid` must equal `SHA-256("STS3/sid" ‖ id_pub ‖ sid_nonce)[0..8]`: a
  session id belongs to one identity.
- `counter` increases with every HELLO of the session: older or replayed
  HELLOs are ignored. It replaces the wall clock time stamps of v2, so a
  clock going backwards no longer keeps anyone out.
- `conn` counts the MQTT connections of the session (see AWAY).
- `flags & 1` (WANT_REPLY): please announce yourselves. Sent when joining
  and after a reconnection. Answers are limited to one HELLO per second,
  however many people ask.
- `sk_epoch`, `sk_seq`: the current sender key and the last message number,
  so members notice lost messages even when nothing else comes.

### Pairwise frames: KEYDIST, KEYREQ, DM, RESEND, FILE

```
hdr | recipient sid[8] | sender eph_gen u32 | recipient eph_gen u32 | seq u64
    | echo[16] | nonce[12] | AES-GCM(k, nonce, aad = everything before, plaintext)
```

The two directions have their own key:

```
shared = ECDH(own ephemeral, peer ephemeral)
salt   = SHA-256(eph_lo ‖ eph_hi)
k_lo‖k_hi = HKDF(salt, shared, "STS3/pairwise" ‖ topic_id ‖ id_lo ‖ id_hi
                                ‖ sid_lo ‖ sid_hi ‖ eph_lo ‖ eph_hi)
```

where `lo`/`hi` order the two sessions by session id. The keys are bound to
the room, both identities, both sessions and both ephemeral keys, which are
announced in signed HELLOs: only the two sessions can compute them.

**Challenges.** Each side picks a random 16-byte challenge for the other
and sends it in its KEYDIST. Every pairwise frame must echo the recipient's
current challenge in `echo`. A frame that doesn't is from an earlier
handshake (a replay), and only a KEYDIST is accepted like that, to learn the
peer's new challenge. Sender keys are only taken from KEYDISTs that echo our
current challenge, and a member becomes active (JOIN) only once such a frame
arrives: that proves the session is live, not a recorded HELLO.

Until a session is active, our KEYDISTs to it carry only the challenge, with
epoch 0 and a zero key: a session that never answers the handshake never
shows up in the list, so it must not read the room either. The sender key
goes out when the session becomes active, renewed first if it was used (see
Keys). Epoch 0 is never a real epoch.

If a known member suddenly sends a new challenge, it forgot us (restart,
eviction): we pick a new challenge too, reset its replay window and replace
our sender key. Nonces are random because sequence numbers start over in
that case. Its last 4 challenges are remembered: a KEYDIST of an earlier
handshake, replayed by the broker, is ignored instead of starting over
again.

Plaintexts:

- KEYDIST: `challenge[16] | epoch u32 | sender key[32] | sk_seq u64`
  (epoch 0, zero key and 0 until the recipient is active)
- KEYREQ: empty, answered by a KEYDIST (at most one per second)
- DM: `time ms u64 | kind u8 | text`, sent to every session of the
  recipient's identity
- RESEND: `channel u8 | epoch u32 | count u8 | seq u64 × count` (channel
  0: room messages, 1: pairwise frames)
- FILE: `op u8 | transfer id u64 | ...`, see [File transfers](#file-transfers)

### MSG

```
hdr | epoch u32 | seq u64 | AES-GCM(sender key, nonce = epoch ‖ seq,
                                    aad = hdr ‖ epoch ‖ seq,
                                    time ms u64 | kind u8 | text) | signature[64]
```

Everyone in the room can decrypt with the sender's key, and the signature
proves who wrote it: a member can't forge messages of another one. `kind` is
0 for text, 1 for `/me` actions; text is UTF-8, at most 1024 bytes, and is
cleaned of control characters before being shown.

A MSG whose key hasn't arrived yet is kept for 30 seconds while a KEYREQ
asks for it.

### AWAY and LEAVE

```
hdr | conn u32 | signature[64]
```

LEAVE ends the session. AWAY is given to the broker as the MQTT will of each
connection: the broker publishes it if the connection dies. Members then
show the session as away for up to two minutes; a HELLO with a higher
`conn` brings it back. An AWAY of an older connection is ignored.

## Delivery

MQTT runs with QoS 1 in both directions and a persistent session: the
broker acknowledges every message and keeps messages for a client whose
connection dropped, which gets them when it reconnects. Messages not
acknowledged by the broker are sent again on the next connection.

On top of that, gaps in sequence numbers (room messages and pairwise frames)
are noticed and asked for with RESEND: each session keeps its last 256 room
messages and 8 pairwise frames per member. A missing frame is asked for
three times, then reported as lost. Messages that arrive late are marked so.

## File transfers

A file goes from one session to another in FILE frames, so it is
protected like a private message: only the two sessions can read it, and
nobody else can inject or change a piece. The transfer id is random.

| op | Name   | Rest of the plaintext                               | From     |
| -- | ------ | --------------------------------------------------- | -------- |
| 1  | OFFER  | `size u64 \| SHA-256[32] \| name_len u8 \| name`    | sender   |
| 2  | ACCEPT |                                                     | receiver |
| 3  | REFUSE |                                                     | receiver |
| 4  | DATA   | `offset u64 \| bytes` (1920 bytes per frame)         | sender   |
| 5  | ACK    | `bytes written so far u64`                          | receiver |
| 6  | DONE   | (the SHA-256 matched, the file is saved)            | receiver |
| 7  | CANCEL | `reason u8`: 0 cancelled, 1 SHA-256 mismatch, 2 error, 3 too big | either |

- The sender repeats OFFER every 10 seconds until it gets an answer (for 5
  minutes); the receiver answers a repeated OFFER again.
- The sender keeps at most 32 DATA frames beyond what was acknowledged. The
  receiver writes only the piece at the offset it expects, acknowledges
  every 8 pieces, and repeats its ACK when something arrives out of order;
  a repeated ACK, or no progress for 3 seconds, sends the sender back to
  the last acknowledged offset. A DATA after the end is answered with
  DONE again, in case the first was lost.
- The receiver writes to a temporary file (created new, readable by its
  owner only), checks the SHA-256 at the end and only then links it under
  its name, never replacing an existing file. Names are reduced to a
  single file name: no `/`, no leading dot, no control characters.
- Each side has its own size limit (`max_file_size`, 16 MB by default, at
  most 64 GB): the sender doesn't offer a bigger file, the receiver answers
  a bigger offer with CANCEL reason 3 without asking its user. A transfer
  fails after 3 minutes without progress, or when the other session leaves.
- The sender reads the file as it goes and the receiver writes it as it
  comes: the size of a file costs no memory.
- A receiver keeps 16 transfers at once, at most 4 coming from the same
  session: further offers are answered with REFUSE.

## Trust

The fingerprint of everyone met is kept in `known_peers` with the last nick
they used (trust on first use). The program warns when a nick shows up with
another key than before. `/trust NICK` marks a fingerprint as verified, once
compared in person; verified people have a `+` in the nick list.

## What the broker still sees

Messages, nicks and room names are encrypted, and lengths are rounded to
256 bytes. The broker (and the network, without TLS) still sees the topic,
that is a hash of the room name and password, which client connections use
it, when frames are sent and roughly how big they are. With `tls = yes` the
network sees only a TLS connection to the broker.

## Limits

- 256 other sessions per room, 8 rooms in the configuration file, up to 15
  windows in the program.
- Post-compromise security comes from the periodic rekey: someone who
  stole the current keys of a session reads at most until the next rekey
  (`rekey_interval`, 10 minutes by default) or the next arrival or
  departure.
- Whoever steals an identity key can pass for its owner. The key file is
  created readable by its owner only; keep it that way, and protect it
  with a passphrase (`sts --passphrase FILE`).

## Identity key file

One line, either the private key in hex (64 characters), or, protected by
a passphrase:

```
sts-key-v1:<salt, 16 bytes>:<iterations>:<nonce, 12 bytes>:<encrypted key and tag, 48 bytes>
```

in hex, where the key is encrypted with AES-256-GCM (additional data
`sts-key-v1`) under `PBKDF2-HMAC-SHA256(passphrase, salt, iterations)`,
300000 iterations when sts writes it. A wrong passphrase fails the tag
check.
