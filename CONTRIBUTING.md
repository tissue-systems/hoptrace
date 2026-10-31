# Contributing

Bug reports and pull requests are welcome. For anything bigger than a small
fix, open an issue first so we can agree on the approach before you spend
time on it. Security problems go to the address in [SECURITY.md](SECURITY.md),
not the issue tracker.

## Reporting a bug

Say which hoptrace and Rust versions you're on, the operating system and
kernel version, and the value of `net.ipv4.ping_group_range` if it's Linux.
The output of `cargo run --example report -- HOST` next to `mtr --report HOST`
for the same host shows most problems.

## Building and testing

CI runs these on Linux and macOS, so run them before you push:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps
```

The tests trace to loopback, which needs permission to open an ICMP datagram
socket (see "Permissions" in the README). Where it's refused, they check the
error instead. Tests that send packets across the internet are ignored by
default:

```sh
cargo test -- --ignored
```

On Linux, `ci/netns.sh` builds a client, a router and a target in network
namespaces, so the error-queue code sees real Time Exceeded and Unreachable
messages. It needs root to set up; the tests themselves run as you:

```sh
sudo ci/netns.sh up
cargo test --test netns --no-run   # prints the path of the test binary
sudo ip netns exec hop-client sudo -u "$USER" HOPTRACE_NETNS=1 \
    target/debug/deps/netns-<hash> --ignored
sudo ci/netns.sh down
```

## Changes to the code

- Keep the minimum Rust version at 1.70. Raising it gets its own pull
  request.
- New behavior comes with a test. A fix comes with a test that fails without
  it. Packet parsing is tested on byte arrays in `src/packet.rs`, so most
  fixes there don't need a network.
- Linux and macOS deliver ICMP to a ping socket differently (see the crate
  docs). A change to how answers are read has to be tried on both.
- Every `unsafe` block gets a `SAFETY:` comment saying why it holds.
- Add a line to `CHANGELOG.md` for anything a user would notice.

## License

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in hoptrace by you, as defined in the Apache-2.0
license, shall be dual licensed as in the README, without any additional
terms or conditions.
