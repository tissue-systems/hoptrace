//! Traces across the namespaces `ci/netns.sh` builds, so the Linux error
//! queue is read for real: Time Exceeded from the router, Unreachable from
//! it, and the target's reply one hop further on. Run inside `hop-client`
//! with `HOPTRACE_NETNS=1`; anywhere else these return without checking.

#![cfg(target_os = "linux")]

use std::net::IpAddr;
use std::thread;

use hoptrace::{Trace, Tracer};

/// Whether `ci/netns.sh` set things up. In GitHub Actions these tests only
/// ever run inside the namespaces, so a missing variable there is a broken
/// job, not a host to skip.
fn in_netns() -> bool {
    let set = std::env::var_os("HOPTRACE_NETNS").is_some();
    assert!(
        set || std::env::var_os("GITHUB_ACTIONS").is_none(),
        "HOPTRACE_NETNS isn't set; run these inside hop-client"
    );
    set
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn every_request_answered(t: &Trace, cycles: u16) {
    for h in &t.hops {
        assert_eq!((h.sent, h.received), (cycles, cycles), "{t:?}");
    }
}

fn through_the_router(router: &str, target: &str) {
    let t = Tracer::new().cycles(5).trace(ip(target)).unwrap();
    assert!(t.reached, "{t:?}");
    assert_eq!(t.hops.len(), 2, "{t:?}");
    assert_eq!(t.hops[0].addr, Some(ip(router)), "{t:?}");
    assert_eq!(t.hops[1].addr, Some(ip(target)), "{t:?}");
    every_request_answered(&t, 5);
}

fn unreachable_at_the_router(router: &str, target: &str) {
    let t = Tracer::new().cycles(3).trace(ip(target)).unwrap();
    assert!(!t.reached, "{t:?}");
    assert_eq!(t.hops.len(), 1, "{t:?}");
    assert_eq!(t.hops[0].addr, Some(ip(router)), "{t:?}");
    every_request_answered(&t, 3);
}

#[test]
#[ignore = "needs the namespaces from ci/netns.sh"]
fn netns_through_a_router() {
    if in_netns() {
        through_the_router("192.0.2.1", "198.51.100.2");
    }
}

#[test]
#[ignore = "needs the namespaces from ci/netns.sh"]
fn netns_through_a_router_over_ipv6() {
    if in_netns() {
        through_the_router("2001:db8:1::1", "2001:db8:2::2");
    }
}

#[test]
#[ignore = "needs the namespaces from ci/netns.sh"]
fn netns_unreachable_at_the_router() {
    if in_netns() {
        unreachable_at_the_router("192.0.2.1", "203.0.113.1");
    }
}

#[test]
#[ignore = "needs the namespaces from ci/netns.sh"]
fn netns_unreachable_at_the_router_over_ipv6() {
    if in_netns() {
        unreachable_at_the_router("2001:db8:1::1", "2001:db8:3::1");
    }
}

/// Eight traces on eight sockets at once, half to the target and half into
/// the unreachable route. Each gets exactly its own answers.
#[test]
#[ignore = "needs the namespaces from ci/netns.sh"]
fn netns_traces_at_once() {
    if !in_netns() {
        return;
    }
    let runs: Vec<_> = (0..8)
        .map(|i| {
            thread::spawn(move || {
                if i % 2 == 0 {
                    through_the_router("192.0.2.1", "198.51.100.2");
                } else {
                    unreachable_at_the_router("2001:db8:1::1", "2001:db8:3::1");
                }
            })
        })
        .collect();
    for r in runs {
        r.join().unwrap();
    }
}

/// An answer that lands between a pass's last read and its next send leaves
/// an error pending on a Linux socket, and that send fails. With answers
/// arriving 0 to 10 ms late, a few hundred traces hit it.
#[test]
#[ignore = "needs the namespaces from ci/netns.sh"]
fn netns_every_request_goes_out() {
    if !in_netns() {
        return;
    }
    let runs: Vec<_> = (0..4)
        .map(|_| {
            thread::spawn(|| {
                for _ in 0..40 {
                    let t = Tracer::new().cycles(10).trace(ip("198.51.100.2")).unwrap();
                    every_request_answered(&t, 10);
                }
            })
        })
        .collect();
    for r in runs {
        r.join().unwrap();
    }
}
