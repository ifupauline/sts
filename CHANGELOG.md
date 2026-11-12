# Changes

## 3.0.1 - 2026-11

Security fixes, found by a review of the protocol and the code.

- A session that knew the room password but never finished the handshake
  received the room's keys without ever showing up in the people list, so
  it could read the room unseen. Keys now go only to sessions that are in
  the list, and are renewed first if they already encrypted messages.
- A member could freeze the others' sts with a crafted sequence number
  (an endless loop). Fixed.
- The broker could replay an old handshake to make sts start over and
  renew its keys again and again. Old handshakes are now ignored.
- One member can no longer take every file transfer slot with offers: at
  most 4 at once from the same session.
- If the system has no random numbers, a key renewal fails loudly and is
  retried, instead of silently keeping the old key.
- Everyone in a room gets their own color, also several terminals that
  share the same identity key with different nicks.

## 3.0.0 - 2026-11

The first release.

- End-to-end encrypted and signed group chat over any MQTT broker: room
  messages, private messages (`/msg`), actions (`/me`), several rooms in
  windows, the people of the room on the right.
- File transfers (`/send`, `/accept`, `/refuse`, `/cancel`, `/files`),
  encrypted like private messages, checked with SHA-256, with a progress
  bar and a size limit of your choice (`max_file_size`).
- Fingerprints for every person, `/whois` and `/trust`, and a warning when
  a known nick comes back with another key.
- Keys renewed every 10 minutes and whenever someone joins or leaves.
- Room passwords; room names never reach the broker and ignore case.
- TLS to the broker, with the system's authorities or your own CA file,
  and hints when the connection fails.
- `sts --init` writes a configuration step by step; `sts --passphrase`
  protects the identity key.
- A "new messages" line and an optional chat log.
- A line by line mode for scripts.
- `make install` with a manual page; tests against a real mosquitto,
  sanitizers and fuzzing in the CI.
