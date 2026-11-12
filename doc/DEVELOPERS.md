# For developers

```sh
make               # build/bin/sts
make test          # build and run the tests
make asan          # the same with AddressSanitizer and UBSan
make fuzz          # the fuzzers, 60 s each (clang, FUZZ_SECS=...)
sudo make install  # /usr/local (PREFIX=..., DESTDIR=...)
sudo make uninstall
make clean
```

`make` drives CMake in `build/`; `cmake -S . -B build && cmake --build
build` works too (`cmake .` in the source folder is refused). The tests
that use a real broker need `mosquitto`, `openssl` and Python 3 (`pyte`
for the full screen check) and are skipped without them:

- `test_util`, `test_crypto`, `test_config`: helpers, cryptography against
  published test vectors, configuration and command line
- `test_room`, `test_fuzz`: the protocol over an in-memory broker that
  loses, duplicates, reorders and replays messages; thousands of corrupted
  frames
- `test_transfer`: file transfers with losses, corrupt data and hostile
  file names
- `test_mqtt`: the MQTT client against mosquitto (QoS 1, persistent
  sessions, last will, TLS with good and bad certificates)
- `test_cli.py`: real `sts` programs chatting and sending files through
  mosquitto, the chat log, `--init` and passphrases on a
  pseudo terminal, and the full screen interface
- `fuzz_*_seeds`: the fuzz targets run once on their seeds

## Fuzzing

`tests/fuzz/` has three [libFuzzer](https://llvm.org/docs/LibFuzzer.html)
targets, built with clang, AddressSanitizer and UBSan by `make fuzz`:

- `fuzz_room`: frames from the broker, raw or wrapped with the room key as
  any member could, against a member of a room;
- `fuzz_transfer`: file transfer frames (offers, data, answers) as another
  member sends them;
- `fuzz_config`: configuration files.

`make fuzz` runs each for `FUZZ_SECS` seconds (60), keeping what they learn
in `build-fuzz/corpus-*`; a crash leaves a `crash-...` file to replay with
`build-fuzz/fuzz/fuzz_room crash-...`. The CI runs them for 2 minutes on
every push and 20 minutes every Monday. Without `-DSTS_FUZZ=ON` the same
targets are built as normal programs that run their seeds
(`tests/fuzz/seeds/`) once, as part of `make test`: add a crash there once
fixed.

How it works, in short: the room name and password give the MQTT topic and
a room key (PBKDF2, HKDF); every pair of people agrees on keys (ECDH
P-256); each person encrypts with their own key (AES-256-GCM) and signs
(ECDSA P-256); keys are renewed every 10 minutes and whenever someone
leaves; MQTT runs with QoS 1 and lost messages are asked for again. The
whole protocol is in [PROTOCOL.md](PROTOCOL.md), what it protects in the
[security model](SECURITY-MODEL.md).

```
src/, include/
  main, chat     the program: rooms, commands, events
  tui            full screen and plain interfaces, line editor
  room           the STS v3 protocol, independent of MQTT
  transfer       file transfers
  mqtt, tls      MQTT 3.1.1 client, TLS with Mbed TLS
  crypto, trust  keys and signatures, known people
  config         configuration file and command line
  setup          sts --init, passphrases
  platform       sockets, terminal, files
  util, log      text, paths, logging
tests/           tests, fuzz/ the fuzz targets
configs/         sts.conf, alice.conf, bob.conf
doc/             the documentation, sts.1 the manual
vendor/          Mbed TLS and Paho MQTTPacket, unmodified
```

`vendor/` holds unmodified copies of [Mbed TLS](https://github.com/Mbed-TLS/mbedtls)
3.6 and the MQTTPacket part of
[Eclipse Paho embedded C](https://github.com/eclipse/paho.mqtt.embedded-c),
at the versions in `vendor/VERSIONS`, so a clone builds offline. To update
them, change the versions at the top of the Makefile and run `make vendor`;
`make vendor-check` checks `vendor/` against upstream.

## Style

The code follows the Linux kernel coding style, with tabs: format with
`clang-format` and the kernel's `.clang-format`, check with the kernel's
`scripts/checkpatch.pl --no-tree -f`. The build has no warnings with
`-Wall -Wextra` and the others in `CMakeLists.txt` (`-DSTS_WERROR=ON`
makes them errors, as in the CI).

## Releases

1. Set the version in `CMakeLists.txt` (`project(sts VERSION ...)`) and
   in `doc/sts.1`, and describe it in `CHANGELOG.md` (`## 1.2.3 - date`).
2. Push a tag: `git tag v1.2.3 && git push origin v1.2.3`.

The release workflow checks that the versions agree, builds and tests on
Ubuntu 22.04, and publishes the release with a
`sts-VERSION-linux-x86_64.tar.gz` (program, manual, examples,
documentation) and its SHA-256.
