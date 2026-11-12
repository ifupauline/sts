# Settings

sts starts in one of two ways, which don't mix:

- `sts -c FILE`: every setting from the configuration file, no other
  option;
- `sts -b HOST -p PORT [options]`: everything on the command line, with
  defaults for what isn't given.

`sts --init` writes a configuration file for you, `man sts` has all of
this in short.

## Configuration file

One `setting = value` per line, `#` starts a comment. Relative paths are
relative to the file, `~/` is your home folder. Unknown settings and
invalid values are reported with the line number.
[configs/sts.conf](../configs/sts.conf) lists every setting with an
explanation.

### Connection

| Setting        | Required | Meaning                                                  |
| -------------- | -------- | -------------------------------------------------------- |
| `broker`       | yes      | broker host name, e.g. `broker.emqx.io`                  |
| `port`         | yes      | 1883 without TLS, usually 8883 with TLS                  |
| `tls`          |          | `yes` for TLS to the broker (`no`), see [TLS](TLS.md)    |
| `tls_ca_file`  |          | certificate authorities to trust (the system's)          |
| `tls_verify`   |          | `no` skips the certificate check: tests only (`yes`)     |
| `username`     |          | if the broker asks for an account                        |
| `password`     |          | idem                                                     |
| `topic_prefix` | yes      | shared by everyone who wants to talk, e.g. `wonderland`  |
| `keepalive`    |          | seconds between pings to the broker, 5 to 3600 (`30`)    |

### You and your rooms

| Setting       | Required | Meaning                                                   |
| ------------- | -------- | --------------------------------------------------------- |
| `nick`        | yes      | letters, digits and `` _ - . [ ] { } ^ ` \| ``, up to 24 |
| `identity`    | yes      | your identity key file, created if missing                |
| `known_peers` | yes      | fingerprints of the people you met                        |
| `room`        |          | `NAME` or `NAME PASSWORD`, one line per room, up to 8     |

Room names are letters, digits, `-`, `_` and `.`, up to 64, and ignore
case: `NeoTokyo` is `neotokyo`.

### Details

| Setting          | Meaning                                                      | Default        |
| ---------------- | ------------------------------------------------------------ | -------------- |
| `rekey_interval` | seconds between key renewals, 60 to 86400, `0` never         | `600`          |
| `ui`             | `auto`, `tui` (full screen) or `plain` (line by line)        | `auto`         |
| `max_file_size`  | largest file you send or accept, `K`, `M` or `G`, up to `64G` | `16M`         |
| `log`            | `yes` keeps a plain text log of each room                    | `no`           |
| `log_dir`        | where the logs go, one `ROOM.log` per room                   | `~/.sts/logs`  |

Offers above your `max_file_size` are refused without asking you, and the
sender is told why. The log has private messages too, marked
`(private)`; it is not encrypted, see the
[security model](SECURITY-MODEL.md).

## Command line

| Option                     | Setting           | Default                    |
| -------------------------- | ----------------- | -------------------------- |
| `-b`, `--broker HOST`      | `broker`          | required                   |
| `-p`, `--port PORT`        | `port`            | required                   |
| `-t`, `--topic-prefix STR` | `topic_prefix`    | `sts`                      |
| `-n`, `--nick NICK`        | `nick`            | your login name            |
| `-r`, `--room ROOM[:PASS]` | `room`            | none, `/join` once started |
| `-i`, `--identity FILE`    | `identity`        | `~/.sts/identity.key`      |
| `-k`, `--known-peers FILE` | `known_peers`     | `~/.sts/known_peers`       |
| `--tls`                    | `tls = yes`       | no TLS                     |
| `--ca-file FILE`           | `tls_ca_file`     | the system's               |
| `--insecure`               | `tls_verify = no` |                            |
| `-u`, `--username USER`    | `username`        |                            |
| `-P`, `--password PASS`    | `password`        |                            |
| `--keepalive SECS`         | `keepalive`       | `30`                       |
| `--plain`                  | `ui = plain`      |                            |
| `--max-file-size SIZE`     | `max_file_size`   | `16M`                      |
| `--log`                    | `log = yes`       | in `~/.sts/logs`           |
| `-v`, `--verbose`          |                   | shows protocol details     |

`-r` can be repeated. A password given with `-P` can be seen by other users
of the computer: put it in a configuration file instead.

Alone on the command line:

| Command                 | What it does                                             |
| ----------------------- | -------------------------------------------------------- |
| `sts --init`            | asks a few questions and writes a configuration file     |
| `sts --passphrase FILE` | protects an identity key with a passphrase, changes it, or removes it (empty) |
| `sts --version`         |                                                          |
| `sts --help`            |                                                          |

## Files

| File                  | What                                                  |
| --------------------- | ----------------------------------------------------- |
| `~/.sts/sts.conf`     | the configuration made by `sts --init`                |
| `~/.sts/identity.key` | your identity key: whoever has it can pass for you    |
| `~/.sts/known_peers`  | fingerprints of the people met, and the verified ones |
| `~/.sts/logs/`        | chat logs, with `log = yes`                           |

All are created readable by you only.
