# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue: on
GitHub, open the **Security** tab of this repository and click **Report a
vulnerability**. Only the maintainer sees the report.

Useful to include:

- what an attacker can do (read messages, pass for someone, crash sts...)
  and what they need for it (be the broker, know the room password...);
- the version (`sts --version`) and how to reproduce it;
- a proposed fix, if you have one.

The aim is to answer within a week. Once fixed, the problem is described
in the release notes, with credit to you unless you prefer not.

## Supported versions

Only the latest release gets security fixes.

## What counts

The [security model](doc/SECURITY-MODEL.md) says what sts protects and
what it doesn't. Anything that breaks a promise there is a vulnerability,
for example:

- reading messages or files without being in the room's people list;
- writing as someone else, or changing a message unnoticed;
- someone who left reading what comes after;
- a crafted message or file offer that crashes sts, writes outside the
  download folder, or replaces a file;
- a weakness in the protection of the identity key file.

Limits already listed in the security model (the broker seeing metadata,
nicks anyone can take, an unprotected chat log...) are not.
