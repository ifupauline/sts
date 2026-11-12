# Security model

What sts protects, from whom, and what it doesn't. The protocol itself is
described in [PROTOCOL.md](PROTOCOL.md).

## In one sentence

What you write can be read by the people listed in the room when you
write it, and by nobody else: not the broker, not the network, not someone
who only knows the room name.

## Who is who

| Who                                          | Can                                                           | Can't                                     |
| -------------------------------------------- | ------------------------------------------------------------- | ----------------------------------------- |
| The network (Wi-Fi, provider), without TLS   | see that you use MQTT, which broker, topic, when, how much    | read or change messages, files, nicks, room names |
| The network, with TLS                        | see that you talk to the broker, when, how much               | the same, and also the topic              |
| The broker and whoever runs it               | see topics, connections, when and how much; drop or delay messages | read, forge or change anything        |
| Someone who knows the room name and password, without joining | see who is in the room (nicks, fingerprints) and when they write | read messages or files                 |
| Someone who joins the room                   | read what is written while they are there, then appear in the people list | read what was written before they joined, private messages and files meant for others, write as someone else |
| Someone who left the room                    |                                                               | read what is written after they left      |
| Someone who uses your nick                   | appear with it, with another fingerprint                      | get your fingerprint, or `+` if people verified you |
| Someone who copies your identity key file    | pass for you from then on                                     | read what was recorded before             |
| Someone who controls your computer           | everything you see and type                                   |                                           |

## What is protected

- **Content**: room messages, private messages, files, nicks and room
  names are encrypted on your computer (AES-256-GCM) with keys that only
  the members have.
- **Authenticity**: every message is signed (ECDSA P-256) or sent under a
  key shared by only two sessions; nobody can write as someone else or
  change a message on the way, not even another member.
- **Replays**: an old message sent again by the broker is recognised and
  dropped.
- **Being seen**: nobody gets the keys of the room without showing up in
  the people list first, not even someone who knows the password and
  only half joins.
- **Joining**: when someone joins, everybody who already wrote with their
  current key replaces it: the newcomer only gets keys that encrypted
  nothing yet, so what was said before they came stays unreadable to
  them, even if they recorded it.
- **Leaving**: when someone leaves, everybody replaces their keys: the one
  who left doesn't get what comes next.
- **Key renewal**: every 10 minutes (`rekey_interval`) the keys are
  replaced. Someone who stole the keys in memory of a running sts reads at
  most until the next renewal.
- **Lengths**: frames are padded to 256 bytes. The broker knows which
  connection published a frame, but not its type, its exact size, or the
  identity behind it.
- **Files**: checked with SHA-256 on arrival, saved under a clean name,
  never replacing an existing file.
- **On disk**: the identity key, the known people and the configuration
  are created readable by you only. The identity key can be protected by
  a passphrase (`sts --passphrase FILE`).

## What isn't

- **Metadata**. The broker sees which topic (a hash of the room name and
  password) is used, by which connections, when and how much. TLS hides
  that from the network, not from the broker.
- **Who is in the room**, from people who know the room name and password:
  the announcements are only protected by the room key.
- **Your first 10 seconds in a room.** Right after you join, sts can't
  tell the people already there from someone arriving at the same moment,
  so it doesn't renew your key for them: otherwise a message typed at once
  would be lost for everyone. Someone who joins in those same seconds, and
  recorded the traffic, can read what you wrote in them.
- **Weak room passwords.** Someone who sees the topic (the broker, the
  network without TLS) can try passwords offline. A found password gives
  the metadata above and the possibility to join, not the past content.
  With no password, anyone who guesses the name can join.
- **Nicks**. Anyone can take any nick. Only fingerprints identify people.
- **Everyone seeing the same thing.** Each member encrypts with its own
  key and gives it to each of the others separately. A member can give
  different keys to different people, so that some see one message and
  others another, or nothing. That member can only fake its own words,
  never someone else's, and only towards people in the room.
- **Your computer**. Malware, a shared account, a screen in a public place,
  a backup of your home folder: sts can't help there.
- **Chat logs** (`log = yes`) are plain text on disk.
- **Availability**. The broker can refuse to pass messages on; sts notices
  missing messages and asks for them again, but can't force delivery.
- **History**. Messages are not stored: what was sent while you were away
  for long is gone. That is also a protection.
- **Anonymity**. The broker sees your IP address. Use Tor or a VPN if that
  matters.

## The keys

| Key            | Where                 | Lifetime                 | Protects                          |
| -------------- | --------------------- | ------------------------ | --------------------------------- |
| Identity       | `identity` file       | until you delete it      | who you are (signatures)          |
| Room key       | from name + password  | as long as the room      | metadata from outsiders           |
| Ephemeral      | memory                | 10 minutes               | the pairwise keys (ECDH)          |
| Pairwise       | memory                | 10 minutes               | private messages, files, key exchange |
| Sender key     | memory                | until someone joins or leaves, 10 minutes, or 1000 messages | room messages |

The identity key only signs. Stealing it doesn't decrypt anything that was
recorded: the encryption keys come from ephemeral keys that are thrown
away.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
