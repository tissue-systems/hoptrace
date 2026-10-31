# Security policy

## Reporting a vulnerability

Please don't open a public issue for a security problem. Report it
privately through
[GitHub's advisory form](https://github.com/tissue-systems/hoptrace/security/advisories/new),
or email [security@tissue.systems](mailto:security@tissue.systems), with what
you found and the steps to reproduce it. A small program or a test case that
shows the problem is the most useful thing you can send.

We'll write back within three working days, keep you posted while we work on
a fix, and credit you in the release notes unless you'd rather we didn't.
Please give us 90 days to ship the fix before you publish, or tell us if you
need a different date.

## Supported versions

hoptrace is pre-1.0. Fixes go into the latest 0.x release only.

## What's in scope

hoptrace parses ICMP messages that anyone on the path, or any process on the
same macOS host, can send to its socket. So the things that matter are:

- a packet that makes the parser panic or read out of bounds
- a forged message that a trace books against the wrong request, or that one
  trace takes from another running at the same time
- anything in the Linux error-queue code (`src/sys.rs`), which is `unsafe`

A router that lies about its address, or answers for a hop it isn't, is how
ICMP works rather than a bug in hoptrace. If you're not sure, send it anyway.
