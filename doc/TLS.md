# TLS to the broker

Your messages are always end-to-end encrypted, with or without TLS. TLS
adds a second, outer protection: the network between you and the broker
can't see which room you use, when or how much. The broker must accept TLS,
usually on a separate port (8883 most of the time).

## Certificates in two minutes

With TLS, the broker proves who it is with a **certificate**, a kind of ID
card. sts accepts it only if two things are true:

1. it was signed by a **certificate authority (CA)** that sts trusts;
2. it was made for the name you typed after `-b` (`localhost`,
   `test.mosquitto.org`...).

Otherwise sts refuses the connection: someone could be pretending to be
the broker. Which authorities does sts trust?

- **The public ones** (Let's Encrypt, DigiCert...): they come with your
  system, in `/etc/ssl/certs/`. Nothing to do.
- **Any other one, only if you give it its file**, with
  `tls_ca_file = /path/to/ca.crt` in the configuration file or
  `--ca-file /path/to/ca.crt` on the command line. That's the case of a
  broker you or a friend set up with home-made certificates, and of some
  public brokers.

A CA file (`ca.crt`) is public, not a secret: it can be shared by mail or
chat. Only the `.key` files must stay secret, and you never need them.

## Which case is yours?

| The broker                                                 | What you add               |
| ---------------------------------------------------------- | -------------------------- |
| has no TLS (port 1883)                                     | nothing                    |
| has a public certificate (`test.mosquitto.org` port 8886)  | `--tls`                    |
| has its own authority (your mosquitto, a friend's, `broker.emqx.io` port 8883) | `--tls --ca-file ca.crt` |
| you only want to test, without checking                    | `--tls --insecure`         |

`--insecure` skips the certificate check: your messages stay unreadable,
but a fake broker could see the traffic or block it. Don't keep it.

## Example 1: a public broker with TLS

```sh
sts -b test.mosquitto.org -p 8886 --tls -t wonderland -n kira -r neotokyo
```

or in your copy of `sts.conf`:

```ini
broker = test.mosquitto.org
port = 8886
tls = yes
```

## Example 2: a broker with its own certificate

Ask the person running the broker for its CA file (or download it from the
broker's page: EMQX publishes the one of `broker.emqx.io`), then:

```sh
sts -b broker.example.org -p 8883 --tls --ca-file ~/broker-ca.crt -n kira -r neotokyo
```

or in the configuration file:

```ini
broker = broker.example.org
port = 8883
tls = yes
tls_ca_file = ~/broker-ca.crt
```

To be sure you got the right file, you and the person who sent it both run
this and compare the result, on the phone or in person:

```sh
openssl x509 -in ~/broker-ca.crt -noout -fingerprint -sha256
```

## Example 3: TLS on your own mosquitto

On your computer (Debian, Ubuntu), make an authority and a certificate for
`localhost`:

```sh
sudo apt install mosquitto openssl
mkdir ~/mqtt-certs && cd ~/mqtt-certs
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout ca.key -out ca.crt -subj "/CN=my-mqtt-ca"
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\n" > ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -out server.crt -extfile ext.cnf
sudo mkdir -p /etc/mosquitto/certs
sudo cp ca.crt server.crt server.key /etc/mosquitto/certs/
sudo chown mosquitto: /etc/mosquitto/certs/server.key
```

Tell mosquitto to use them: create `/etc/mosquitto/conf.d/tls.conf` with

```
listener 8883
allow_anonymous true
cafile /etc/mosquitto/certs/ca.crt
certfile /etc/mosquitto/certs/server.crt
keyfile /etc/mosquitto/certs/server.key
```

`allow_anonymous true` lets people in without an account, which is fine on
your own computer. Restart mosquitto and connect:

```sh
sudo systemctl restart mosquitto
sts -b localhost -p 8883 --tls --ca-file ~/mqtt-certs/ca.crt -n kira -r neotokyo
```

To try it alone with two instances, use `configs/alice.conf` and
`configs/bob.conf`, see [Two instances on one computer](USAGE.md#two-instances-on-one-computer).

Your friends need `ca.crt` too, and must connect with the name the
certificate was made for. For a broker on a server with a domain name, a
free [Let's Encrypt](https://letsencrypt.org/) certificate avoids all
this: everybody then connects with just `--tls`.

## When it doesn't connect

sts says what went wrong in the room's window, adds a hint, and keeps
retrying:

| Message                                           | What to do                                       |
| ------------------------------------------------- | ------------------------------------------------ |
| `broker certificate rejected: The certificate is not correctly signed by the trusted CA` | give the broker's CA file with `--ca-file` |
| `broker certificate rejected: The certificate Common Name (CN) does not match with the expected CN` | connect with the name the certificate was made for (`-b`) |
| `broker certificate rejected: The certificate validity has expired` | the broker's certificate must be renewed by whoever runs it |
| `broker refused the connection: not authorized`   | the broker wants an account: `-u` and `-P` (`username`, `password`), or `allow_anonymous true` on your own mosquitto |
| `TLS handshake: ...`                              | this port probably has no TLS: check the port, or remove `--tls` |
| `the broker didn't answer in time`                | this port probably has TLS: add `--tls`          |
| `cannot reach ...`                                | wrong host or port, broker stopped, or a firewall |
