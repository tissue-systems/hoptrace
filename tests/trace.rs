use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::thread;

use hoptrace::{permitted, Error, Trace, Tracer};

/// Loopback is one hop away. Where the kernel lets this process open a ping
/// socket the trace reaches it at hop 1, and where it doesn't the error says
/// so.
#[test]
fn loopback_or_not_permitted() {
    let to = IpAddr::V4(Ipv4Addr::LOCALHOST);
    match Tracer::new().trace(to) {
        Ok(t) => {
            assert!(permitted());
            assert!(t.reached, "{t:?}");
            assert_eq!(t.hops.len(), 1, "{t:?}");
            assert_eq!(t.hops[0].addr, Some(to));
            assert_eq!((t.hops[0].sent, t.hops[0].received), (3, 3));
            assert!(
                t.hops[0].avg.unwrap() < std::time::Duration::from_millis(50),
                "{t:?}"
            );
        }
        Err(Error::NotPermitted(_)) => assert!(!permitted()),
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn loopback_from_a_source_address() {
    if !permitted() {
        return;
    }
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let t = Tracer::new().cycles(1).source(lo).trace(lo).unwrap();
    assert!(t.reached, "{t:?}");
}

#[test]
fn ipv4_mapped_target_is_traced_as_ipv4() {
    if !permitted() {
        return;
    }
    let t = Tracer::new()
        .cycles(1)
        .trace("::ffff:127.0.0.1".parse().unwrap())
        .unwrap();
    assert_eq!(t.target, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(t.reached, "{t:?}");
}

#[test]
fn longest_wait_doesnt_overflow() {
    if !permitted() {
        return;
    }
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let t = Tracer::new()
        .cycles(1)
        .wait(std::time::Duration::MAX)
        .trace(lo)
        .unwrap();
    assert!(t.reached, "{t:?}");
}

/// IPv6 loopback, where the host has it configured.
#[test]
fn ipv6_loopback() {
    if !permitted() {
        return;
    }
    let to = IpAddr::V6(Ipv6Addr::LOCALHOST);
    match Tracer::new().cycles(2).trace(to) {
        Ok(t) => {
            assert!(t.reached, "{t:?}");
            assert_eq!(t.hops.len(), 1, "{t:?}");
            assert_eq!(t.hops[0].addr, Some(to));
        }
        // A container or CI runner with IPv6 switched off.
        Err(Error::NoRoute(_)) => {}
        Err(e) => panic!("{e}"),
    }
}

fn show(t: &Trace) {
    for h in &t.hops {
        eprintln!(
            "{:>2} {:?} {}/{} {:?}",
            h.ttl, h.addr, h.received, h.sent, h.avg
        );
    }
}

#[test]
#[ignore = "sends packets across the internet"]
fn public_resolver() {
    let t = Tracer::new().trace("1.1.1.1".parse().unwrap()).unwrap();
    show(&t);
    assert!(t.hops.len() > 1, "{t:?}");
}

/// Each of several traces running at once keeps to its own path: a trace that
/// reached its target ends on the target's address, never on a router or
/// target of another.
#[test]
#[ignore = "sends packets across the internet"]
fn concurrent_traces_keep_to_their_own_path() {
    let targets: Vec<IpAddr> = ["1.1.1.1", "9.9.9.10", "9.9.9.9", "8.8.8.8"]
        .iter()
        .map(|t| t.parse().unwrap())
        .collect();
    let handles: Vec<_> = targets
        .iter()
        .map(|&to| thread::spawn(move || Tracer::new().trace(to).unwrap()))
        .collect();
    for h in handles {
        let t = h.join().unwrap();
        eprintln!("{} reached={}", t.target, t.reached);
        show(&t);
        if t.reached {
            assert_eq!(t.hops.last().unwrap().addr, Some(t.target), "{t:?}");
        }
        let others: Vec<IpAddr> = targets.iter().copied().filter(|x| *x != t.target).collect();
        assert!(
            !t.hops
                .iter()
                .any(|h| h.addr.is_some_and(|a| others.contains(&a))),
            "another trace's target in {t:?}"
        );
    }
}

#[test]
#[ignore = "needs IPv6 internet access"]
fn public_resolver_over_ipv6() {
    let t = Tracer::new()
        .trace("2606:4700:4700::1111".parse().unwrap())
        .unwrap();
    show(&t);
    assert!(t.hops.len() > 1, "{t:?}");
}
