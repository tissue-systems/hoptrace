# hoptrace

A path trace like `mtr --report`, run inside your process. It sends echo
requests with rising TTLs over an unprivileged ICMP datagram socket. An
ordinary user can run it, on Linux and macOS, over IPv4 and IPv6.

```rust
let trace = hoptrace::Tracer::new().trace("1.1.1.1".parse()?)?;
for hop in &trace.hops {
    match (hop.addr, hop.avg) {
        (Some(addr), Some(avg)) => println!("{:>2}  {addr}  {:.1}% loss  {avg:?}", hop.ttl, hop.loss()),
        _ => println!("{:>2}  ???", hop.ttl),
    }
}
```

`examples/report.rs` prints an mtr-style table (addresses changed):

```text
$ cargo run --example report -- -c 5 1.1.1.1
HOST: 1.1.1.1 (1.1.1.1)
                                              Loss%  Snt     Avg    Best    Wrst
  1.|-- 192.168.1.1                            0.0%    5     3.0     2.6     3.4
  2.|-- 198.51.100.17                          0.0%    5    12.8    11.8    13.4
  3.|-- 198.51.100.130                         0.0%    5    14.0    12.1    18.8
  ...
  8.|-- 1.1.1.1                                0.0%    5    16.1    12.8    21.0
```

## Installation

```toml
[dependencies]
hoptrace = "0.1"
```

The minimum Rust version is 1.70. The only dependencies are `socket2` and
`libc`.

## Permissions

macOS lets any process open an ICMP datagram socket. Linux allows it to the
groups in `net.ipv4.ping_group_range`, which covers IPv6 too. The kernel
default is `1 0`, which allows nobody. systemd 243 and later sets
`0 2147483647`, and most current distributions are fine out of the box.
Minimal container images and older systems often aren't. To check and to open
it to every group:

```sh
sysctl net.ipv4.ping_group_range
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee /etc/sysctl.d/60-ping.conf
```

When it isn't allowed, `trace` returns `Error::NotPermitted`, whose message
names the sysctl. `hoptrace::permitted()` asks the same question without
tracing anything.

## What it does

A trace makes `cycles` passes (three by default). Each pass sends one echo
request per TTL from 1 to `max_hops` (30), a few milliseconds apart, then
waits up to 1.5 s for the stragglers. Each `Hop` in the result has the TTL,
the address that answered, requests sent and answered, and the best, mean and
worst round trip. The path ends at the first TTL where the target replies,
or failing that the first where a router says Unreachable, and later passes
stop sending there. If neither happens, the list ends at the last hop that
answered.

Several traces can run at once, in one process or many, without mixing
their answers. Linux and macOS hand back Time Exceeded differently, and the
[crate docs](https://docs.rs/hoptrace) say how each is read.

`trace` blocks. From async code, run it on a blocking thread
(`tokio::task::spawn_blocking`).

It doesn't do name lookups, reverse DNS or AS numbers. It sends only ICMP
echo, and it can't trace past a firewall that drops echo but passes TCP or
UDP. There's no live display. FreeBSD and Windows aren't supported, since
neither has an unprivileged ICMP datagram socket. It builds for Android and
iOS, which have the same socket, but nobody has run it there yet.

On Linux the multi-hop path (Time Exceeded and Unreachable from a router, over
IPv4 and IPv6) is tested against network namespaces with `ci/netns.sh`. On
macOS it has been run over IPv4 on real paths; IPv6 there has only been run to
loopback.

## Alternatives

If you can run a binary, mtr and traceroute do more: TCP and UDP probes, AS
lookups, a live view. mtr 0.93 and later falls back to the same unprivileged
socket on Linux, though it needs root on macOS. Wrapping it means a child
process per trace and reading its report (`mtr -j` gives JSON) back into
numbers.

[trippy](https://crates.io/crates/trippy-core) has a library engine and an
unprivileged mode, on macOS only; on Linux it needs `CAP_NET_RAW`. With raw
sockets it also probes with UDP and TCP and handles ECMP paths properly. It's
a much bigger dependency, and needs Rust 1.78.

[surge-ping](https://crates.io/crates/surge-ping) is an async ping that can
use the same socket and lets you set the TTL. It hands back the answer to each
request rather than a list of hops, and doesn't read the Linux error queue.
`pnet` and the raw-socket traceroute crates can probe with any protocol, and
need root or `CAP_NET_RAW` to do it.

## About

hoptrace is written and maintained by
[Tissue Systems](https://tissue.systems/?ref=hoptrace). We built it for
[Tissue Mast](https://tissue.systems/mast?ref=hoptrace), an on-call paging
and monitoring service, which takes a trace when an uptime check fails. Bug reports and pull requests are welcome whether or not you use
it.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in hoptrace by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
