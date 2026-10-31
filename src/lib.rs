//! Path traces in the style of mtr's report mode, over an unprivileged ICMP
//! socket.
//!
//! A trace makes a few passes over the path. Each pass sends one echo
//! request per TTL, from 1 up to the hop count, and each hop in the result
//! says who answered at that TTL, how many requests it answered and how long
//! the answers took. It runs in your process on a `SOCK_DGRAM` /
//! `IPPROTO_ICMP` socket. That needs no raw socket and no special privilege.
//!
//! ```no_run
//! let trace = hoptrace::Tracer::new().trace("1.1.1.1".parse()?)?;
//! for hop in &trace.hops {
//!     match (hop.addr, hop.avg) {
//!         (Some(addr), Some(avg)) => println!("{:>2}  {addr}  {:.1}% loss  {avg:?}", hop.ttl, hop.loss()),
//!         _ => println!("{:>2}  ???", hop.ttl),
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`Tracer::trace`] blocks for the length of the trace, which with the
//! defaults is a few seconds. From async code, run it on a blocking thread
//! (`tokio::task::spawn_blocking` or your runtime's equivalent). Traces in
//! parallel threads don't see each other's answers.
//!
//! # Permissions
//!
//! macOS lets any process open an ICMP datagram socket. Linux allows it to
//! the groups in the `net.ipv4.ping_group_range` sysctl, which also covers
//! IPv6. The kernel's default is `1 0`, an empty range: nobody may.
//! systemd 243 and later sets `0 2147483647`, every group, and most current
//! distributions allow it already. Minimal images and older systems often
//! don't. Check with `sysctl net.ipv4.ping_group_range`, and to let every
//! group in:
//!
//! ```text
//! sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
//! ```
//!
//! and put the same line in a file under `/etc/sysctl.d/` to keep it across
//! reboots. When the kernel says no, [`Tracer::trace`] returns
//! [`Error::NotPermitted`], and [`permitted`] tells you up front.
//!
//! # How the answers come back
//!
//! Who answered a TTL is read differently on each system.
//!
//! macOS hands every ICMP message for the socket to `recvfrom`, Time Exceeded
//! included, with the IPv4 header in front. The message quotes our request,
//! whose sequence number names the TTL it was sent with. Every ICMP socket on
//! the host sees every such message. Each trace sends with an identifier
//! and sequence base of its own, picked at random, and keeps only the
//! messages that quote both. Where the router quoted enough of the request,
//! the trace's random token has to match too.
//!
//! A Linux ping socket receives only its own echo replies. Time Exceeded and
//! Unreachable go to the socket's error queue once `IP_RECVERR` is set, and
//! are read with `recvmsg(MSG_ERRQUEUE)`. The payload is the router's quote of
//! our request, and the router's address is the offender in the
//! `sock_extended_err`.
//!
//! An echo reply from the target means it answered at that TTL, and the trace
//! ends there. So does an Unreachable, unless the target answered on some
//! other pass: nothing past it gets through.
//!
//! Round trips are timed in user space, when poll(2) wakes the thread and the
//! answer is read. A loaded host adds its scheduling delay to them. On an
//! idle Mac, loopback measures about 0.1 ms.
//!
//! It's tested on Linux and macOS. It also builds for Android and iOS, which
//! have the same sockets, but hasn't been run there. FreeBSD and Windows have
//! no unprivileged ICMP datagram socket, and the crate doesn't build for them.

#![warn(missing_docs)]

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
compile_error!(
    "hoptrace needs an unprivileged ICMP datagram socket, which only Linux and macOS have"
);

mod packet;
mod sys;

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockRef, Socket, Type};

use packet::Answer;

/// Settings for a trace, starting from [`Tracer::new`].
#[derive(Debug, Clone)]
pub struct Tracer {
    cycles: u16,
    max_hops: u8,
    wait: Duration,
    send_gap: Duration,
    source_v4: Option<Ipv4Addr>,
    source_v6: Option<Ipv6Addr>,
    tag: Vec<u8>,
}

impl Default for Tracer {
    fn default() -> Self {
        Tracer {
            cycles: 3,
            max_hops: 30,
            wait: Duration::from_millis(1500),
            send_gap: Duration::from_millis(5),
            source_v4: None,
            source_v6: None,
            tag: packet::TAG.to_vec(),
        }
    }
}

impl Tracer {
    /// Three passes, up to 30 hops, 1.5 s for the last answers of a pass and
    /// 5 ms between requests.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many passes over the path; mtr's `-c`. At least one. mtr's
    /// report mode defaults to 10, for a finer loss figure and a longer
    /// trace.
    #[must_use]
    pub fn cycles(mut self, cycles: u16) -> Self {
        self.cycles = cycles.max(1);
        self
    }

    /// The highest TTL tried, and so the most hops a trace can have. At
    /// least one.
    #[must_use]
    pub fn max_hops(mut self, max_hops: u8) -> Self {
        self.max_hops = max_hops.max(1);
        self
    }

    /// How long a pass waits for answers after its last request, up to a
    /// minute. A pass ends early once every TTL up to the end of the path
    /// has answered.
    #[must_use]
    pub fn wait(mut self, wait: Duration) -> Self {
        self.wait = wait.clamp(SHORTEST, LONGEST);
        self
    }

    /// The gap between two requests of one pass. Routers rate-limit the ICMP
    /// they send, and a burst of requests that all expire at the same router
    /// can lose answers to that limit rather than to the path. Up to a
    /// minute.
    #[must_use]
    pub fn send_gap(mut self, gap: Duration) -> Self {
        self.send_gap = gap.clamp(SHORTEST, LONGEST);
        self
    }

    /// The bytes each request carries ahead of the trace's token, so a packet
    /// capture shows what sent it. `hoptrace` unless set; anything past 32
    /// bytes is cut off.
    #[must_use]
    pub fn tag(mut self, tag: &[u8]) -> Self {
        self.tag = tag[..tag.len().min(packet::MAX_TAG)].to_vec();
        self
    }

    /// Sends from `addr` when the target is in its address family. Call it
    /// once for each family to set both. Once a source is set, tracing to a
    /// family without one fails with [`Error::NoSource`].
    #[must_use]
    pub fn source(mut self, addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(a) => self.source_v4 = Some(a),
            IpAddr::V6(a) => self.source_v6 = Some(a),
        }
        self
    }

    /// Traces the path to `to`, blocking until the last pass is done.
    ///
    /// An IPv4-mapped IPv6 address (`::ffff:192.0.2.1`) is traced as the
    /// IPv4 address it holds, and that's the `target` in the result. A
    /// multicast, broadcast or unspecified address is refused with
    /// [`Error::InvalidTarget`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidTarget`] for a target that isn't one host.
    /// - [`Error::NoSource`] when sources are set, but none in the target's
    ///   family.
    /// - [`Error::NotPermitted`] when the kernel won't open the socket.
    /// - [`Error::NoRoute`] when the host has no way to send to the target.
    /// - [`Error::Ttl`] when the kernel won't set a TTL on the socket.
    /// - [`Error::Send`] when the first request can't go out for another
    ///   reason. Later requests that fail count as lost instead.
    /// - [`Error::Io`] for anything else the socket returns while it's set up.
    pub fn trace(&self, to: IpAddr) -> Result<Trace, Error> {
        let to = match to {
            IpAddr::V6(a) => a.to_ipv4_mapped().map_or(to, IpAddr::V4),
            v4 => v4,
        };
        let multi = match to {
            IpAddr::V4(a) => a.is_broadcast() || a.is_multicast(),
            IpAddr::V6(a) => a.is_multicast(),
        };
        if multi || to.is_unspecified() {
            return Err(Error::InvalidTarget(to));
        }
        let sock = self.open(to)?;
        let v6 = to.is_ipv6();
        let token = token();
        let mut run = Run {
            sock,
            target: to,
            v6,
            ident: u16::from_be_bytes([token[0], token[1]]),
            tag: &self.tag,
            token,
            sent: HashMap::new(),
            answers: Vec::new(),
            tally: Tally::default(),
        };
        let base = u16::from_be_bytes([token[2], token[3]]);
        let dest = SocketAddr::new(to, 0);
        for cycle in 0..self.cycles {
            let top = run.tally.end().unwrap_or(self.max_hops);
            for ttl in 1..=top {
                if run.tally.end().is_some_and(|end| ttl > end) {
                    break;
                }
                // Sequence numbers wrap after 65536 requests, by which time
                // the request that had the number before is long settled.
                let seq =
                    base.wrapping_add((cycle as u32 * self.max_hops as u32 + ttl as u32) as u16);
                set_ttl(&run.sock, v6, ttl).map_err(Error::Ttl)?;
                let request = packet::echo_request(v6, run.ident, seq, &self.tag, &token);
                // On Linux, an ICMP error that arrived since the last read
                // is left pending on the socket, and the next send returns
                // it instead of sending. That clears it, so one retry sends.
                let sent = run
                    .sock
                    .send_to(&request, dest)
                    .or_else(|_| run.sock.send_to(&request, dest));
                match sent {
                    Ok(_) => {
                        run.sent.insert(
                            seq,
                            Sent {
                                ttl,
                                at: Instant::now(),
                            },
                        );
                    }
                    // The first request going out is what shows the socket
                    // works. Later ones can fail for a moment (a full send
                    // buffer, a route flapping) and count as lost.
                    Err(e) if cycle == 0 && ttl == 1 => return Err(Error::from_send(e)),
                    Err(_) => {}
                }
                *run.tally.sent.entry(ttl).or_default() += 1;
                run.pump(Instant::now() + self.send_gap, |_| false);
            }
            let cycle = cycle as usize;
            run.pump(Instant::now() + self.wait, |t| {
                let end = t.end().unwrap_or(top);
                (1..=end).all(|ttl| t.rtts.get(&ttl).is_some_and(|r| r.len() > cycle))
            });
        }
        Ok(Trace {
            target: to,
            reached: run.tally.reached_at.is_some(),
            hops: run.tally.hops(),
        })
    }

    /// An unconnected ICMP datagram socket for `to`'s family, bound to the
    /// source when one is set, non-blocking, and on Linux with the error
    /// queue switched on.
    fn open(&self, to: IpAddr) -> Result<UdpSocket, Error> {
        let (domain, protocol) = match to {
            IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4),
            IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
        };
        let any_source = self.source_v4.is_some() || self.source_v6.is_some();
        let from = match to {
            IpAddr::V4(_) => self.source_v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.source_v6.map(IpAddr::V6),
        };
        let from = match (from, to) {
            (Some(from), _) => from,
            (None, _) if any_source => return Err(Error::NoSource(to)),
            (None, IpAddr::V4(_)) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            (None, IpAddr::V6(_)) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let sock = Socket::new(domain, Type::DGRAM, Some(protocol)).map_err(Error::from_socket)?;
        sock.bind(&SocketAddr::new(from, 0).into())?;
        sock.set_nonblocking(true)?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        sys::recverr(&sock, to.is_ipv6())?;
        Ok(UdpSocket::from(sock))
    }
}

/// The most messages one call to `drain` reads off each queue.
pub(crate) const DRAIN: usize = 256;

/// The longest `wait` or `send_gap` a tracer takes.
const LONGEST: Duration = Duration::from_secs(60);

/// The shortest `wait` or `send_gap` a tracer takes.
const SHORTEST: Duration = Duration::from_millis(1);

/// Whether this process may open an ICMP datagram socket, and so trace.
#[must_use]
pub fn permitted() -> bool {
    Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).is_ok()
}

/// The result of [`Tracer::trace`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Trace {
    /// The address traced to. An IPv4-mapped address comes back as plain
    /// IPv4.
    pub target: IpAddr,
    /// Whether the target itself answered.
    pub reached: bool,
    /// One per TTL from 1, up to the TTL the target answered at, or the
    /// last one anything answered at when it never did.
    pub hops: Vec<Hop>,
}

impl Trace {
    /// A trace to `target` that reached nothing and has no hops, for tests
    /// and for results that come from somewhere else. Set the fields from
    /// there.
    #[must_use]
    pub fn new(target: IpAddr) -> Self {
        Trace {
            target,
            reached: false,
            hops: Vec::new(),
        }
    }
}

/// One TTL's answers over the whole trace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Hop {
    /// The TTL, from 1.
    pub ttl: u8,
    /// Who answered, or `None` when nobody did. When different routers
    /// answer a TTL on different passes (ECMP), the first one is kept,
    /// except that the target's own reply always wins.
    pub addr: Option<IpAddr>,
    /// Requests sent with this TTL. One the kernel refused to send is
    /// counted too, and as lost.
    pub sent: u16,
    /// Answers received.
    pub received: u16,
    /// Fastest round trip, `None` when nothing came back. Likewise `avg`
    /// and `worst`.
    pub best: Option<Duration>,
    /// Mean round trip.
    pub avg: Option<Duration>,
    /// Slowest round trip.
    pub worst: Option<Duration>,
}

impl Hop {
    /// A hop at `ttl` with nothing sent or answered, for tests and for
    /// results that come from somewhere else. Set the fields from there.
    #[must_use]
    pub fn new(ttl: u8) -> Self {
        Hop {
            ttl,
            addr: None,
            sent: 0,
            received: 0,
            best: None,
            avg: None,
            worst: None,
        }
    }

    /// Requests that went unanswered, as a percentage.
    #[must_use]
    pub fn loss(&self) -> f64 {
        if self.sent == 0 {
            return 100.0;
        }
        100.0 * self.sent.saturating_sub(self.received) as f64 / self.sent as f64
    }
}

/// Why a trace couldn't run.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The kernel won't let this process open an ICMP datagram socket. On
    /// Linux that's `net.ipv4.ping_group_range`; see the crate docs.
    NotPermitted(io::Error),
    /// This host can't send to the target at all: it has no IPv6, say, or
    /// no route or source address for the target.
    NoRoute(io::Error),
    /// A source address is set for the other family only.
    NoSource(IpAddr),
    /// The target is a multicast, broadcast or unspecified address, which a
    /// trace can't follow to one host.
    InvalidTarget(IpAddr),
    /// The kernel wouldn't set the TTL, or the IPv6 hop limit, on the socket.
    Ttl(io::Error),
    /// The first request couldn't be sent, for a reason other than routing.
    Send(io::Error),
    /// Anything else the socket returned.
    Io(io::Error),
}

impl Error {
    fn from_socket(e: io::Error) -> Error {
        if refused(&e) {
            Error::NotPermitted(e)
        } else if e.raw_os_error() == Some(libc::EAFNOSUPPORT) {
            // A kernel booted without IPv6.
            Error::NoRoute(e)
        } else {
            Error::Io(e)
        }
    }

    fn from_send(e: io::Error) -> Error {
        // Matched on the errno: the ErrorKinds for these are newer than
        // this crate's minimum Rust.
        if matches!(
            e.raw_os_error(),
            Some(libc::EHOSTUNREACH | libc::ENETUNREACH | libc::EADDRNOTAVAIL)
        ) {
            Error::NoRoute(e)
        } else {
            Error::Send(e)
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotPermitted(e) => write!(
                f,
                "not allowed to open an ICMP datagram socket ({e}); on Linux, \
                 add this process's group to net.ipv4.ping_group_range"
            ),
            Error::NoRoute(e) => write!(f, "no route to the target: {e}"),
            Error::NoSource(to) => write!(f, "no source address set in the family of {to}"),
            Error::InvalidTarget(to) => write!(f, "can't trace to {to}, which isn't one host"),
            Error::Ttl(e) => write!(f, "can't set the TTL on the socket: {e}"),
            Error::Send(e) => write!(f, "can't send the first request: {e}"),
            Error::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::NotPermitted(e)
            | Error::NoRoute(e)
            | Error::Ttl(e)
            | Error::Send(e)
            | Error::Io(e) => Some(e),
            Error::NoSource(_) | Error::InvalidTarget(_) => None,
        }
    }
}

/// The kernel refused outright: a permission answer, not a network one.
fn refused(e: &io::Error) -> bool {
    // EPERM is 1 and EACCES 13 on both Linux and macOS.
    e.kind() == io::ErrorKind::PermissionDenied
        || matches!(e.raw_os_error(), Some(libc::EPERM | libc::EACCES))
}

fn set_ttl(sock: &UdpSocket, v6: bool, ttl: u8) -> io::Result<()> {
    if v6 {
        SockRef::from(sock).set_unicast_hops_v6(ttl as u32)
    } else {
        sock.set_ttl(ttl as u32)
    }
}

/// Eight random bytes: std's per-thread random hash keys over the time, the
/// process and a counter, so two traces that start in the same instant, in
/// one process or two, still differ. The first two become the identifier and
/// the next two the sequence base.
fn token() -> [u8; 8] {
    use std::hash::{BuildHasher, Hasher};
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_default();
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(nanos);
    h.write_u32(std::process::id());
    h.write_usize(COUNT.fetch_add(1, Ordering::Relaxed));
    h.finish().to_be_bytes()
}

/// When a request went out, and with which TTL.
struct Sent {
    ttl: u8,
    at: Instant,
}

/// One trace in progress.
struct Run<'a> {
    sock: UdpSocket,
    target: IpAddr,
    v6: bool,
    ident: u16,
    tag: &'a [u8],
    token: [u8; 8],
    /// Requests not yet answered, by sequence number.
    sent: HashMap<u16, Sent>,
    /// Answers read but not yet booked, each with when it was read.
    answers: Vec<(Answer, IpAddr, Instant)>,
    tally: Tally,
}

impl Run<'_> {
    /// Reads and books answers as they arrive, until `until` or until `done`
    /// says there's nothing left to wait for. Each answer is timed when it's
    /// read, so the round trips are as good as the wakeup from poll(2).
    fn pump(&mut self, until: Instant, done: impl Fn(&Tally) -> bool) {
        loop {
            self.drain();
            for (a, from, at) in self.answers.drain(..) {
                let (seq, reply, unreachable) = match a {
                    // Only the target's reply. Another host answering with
                    // our token means the target forwarded or broadcast it.
                    Answer::Reply(_) if from != self.target => continue,
                    Answer::Reply(s) => (s, true, false),
                    Answer::Expired(s) => (s, false, false),
                    Answer::Unreachable(s) => (s, false, true),
                };
                // remove(), so a duplicate answer finds nothing and isn't
                // counted twice.
                if let Some(s) = self.sent.remove(&seq) {
                    self.tally.answer(
                        s.ttl,
                        from,
                        at.saturating_duration_since(s.at),
                        reply,
                        unreachable,
                    );
                }
            }
            if done(&self.tally) {
                return;
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            sys::wait_readable(&self.sock, left);
        }
    }

    /// The answers waiting on the socket, with who sent them.
    fn drain(&mut self) {
        let mut buf = [0u8; 1500];
        let mut errors = 0;
        // A flood of ICMP from elsewhere could keep this busy past the
        // pass's deadline. Whatever is left waits for the next call.
        for _ in 0..DRAIN {
            match self.sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let at = Instant::now();
                    if let Some(a) =
                        packet::parse_answer(self.v6, &buf[..n], self.ident, self.tag, &self.token)
                    {
                        self.answers.push((a, from.ip(), at));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                // On Linux a queued ICMP error also surfaces here, once,
                // ahead of any reply still waiting. The error queue below
                // has its detail.
                Err(_) => {
                    errors += 1;
                    if errors > 2 {
                        break;
                    }
                }
            }
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        sys::drain_errqueue(&self.sock, self.v6, &mut self.answers);
    }
}

/// The answers gathered, per TTL.
#[derive(Default)]
struct Tally {
    sent: HashMap<u8, u16>,
    rtts: HashMap<u8, Vec<Duration>>,
    addrs: HashMap<u8, IpAddr>,
    /// The lowest TTL the target itself answered at.
    reached_at: Option<u8>,
    /// The lowest TTL an Unreachable came back from.
    unreachable_at: Option<u8>,
}

impl Tally {
    /// Where the path ends, once a pass has found it. The target's reply
    /// wins over an Unreachable on another pass: it shows the path does get
    /// through.
    fn end(&self) -> Option<u8> {
        self.reached_at.or(self.unreachable_at)
    }

    fn answer(&mut self, ttl: u8, from: IpAddr, rtt: Duration, reply: bool, unreachable: bool) {
        self.rtts.entry(ttl).or_default().push(rtt);
        // The first router to answer a TTL names it, except that the
        // target's own reply always does: a pass that took a longer path
        // (ECMP) mustn't leave a router's address on the hop the target
        // answered at.
        if reply {
            self.addrs.insert(ttl, from);
            self.reached_at = Some(self.reached_at.map_or(ttl, |r| r.min(ttl)));
        } else {
            self.addrs.entry(ttl).or_insert(from);
        }
        if unreachable {
            self.unreachable_at = Some(self.unreachable_at.map_or(ttl, |u| u.min(ttl)));
        }
    }

    fn hops(&self) -> Vec<Hop> {
        let last_sent = self.sent.keys().copied().max().unwrap_or(0);
        let end = self.end().unwrap_or(last_sent).min(last_sent);
        let mut hops: Vec<Hop> = (1..=end)
            .map(|ttl| {
                let sent = self.sent.get(&ttl).copied().unwrap_or(0);
                let rtts = self.rtts.get(&ttl).map(Vec::as_slice).unwrap_or(&[]);
                Hop {
                    ttl,
                    addr: self.addrs.get(&ttl).copied(),
                    sent,
                    received: (rtts.len() as u16).min(sent),
                    best: rtts.iter().min().copied(),
                    avg: (!rtts.is_empty())
                        .then(|| rtts.iter().sum::<Duration>() / rtts.len() as u32),
                    worst: rtts.iter().max().copied(),
                }
            })
            .collect();
        // Silence after the last router that answered says nothing about
        // where the path goes, so a trace that never reached its target
        // stops at the last answer.
        if self.reached_at.is_none() {
            while hops.last().is_some_and(|h| h.addr.is_none()) {
                hops.pop();
            }
        }
        hops
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(t: &mut Tally, ttl: u8, from: &str, ms: u64, reply: bool) {
        t.answer(
            ttl,
            from.parse().unwrap(),
            Duration::from_millis(ms),
            reply,
            false,
        );
    }

    fn sent(ttls: std::ops::RangeInclusive<u8>, n: u16) -> Tally {
        let mut t = Tally::default();
        for ttl in ttls {
            t.sent.insert(ttl, n);
        }
        t
    }

    #[test]
    fn hops_from_a_tally() {
        let mut t = sent(1..=6, 3);
        at(&mut t, 1, "192.0.2.1", 1, false);
        at(&mut t, 1, "192.0.2.1", 3, false);
        at(&mut t, 1, "192.0.2.1", 2, false);
        at(&mut t, 3, "198.51.100.9", 20, false);
        let hops = t.hops();
        assert_eq!(
            hops.len(),
            3,
            "silent hops past the last answer are cut: {hops:?}"
        );
        let ms = |n| Some(Duration::from_millis(n));
        assert_eq!(
            hops[0],
            Hop {
                ttl: 1,
                addr: Some("192.0.2.1".parse().unwrap()),
                sent: 3,
                received: 3,
                best: ms(1),
                avg: ms(2),
                worst: ms(3),
            }
        );
        assert_eq!(hops[0].loss(), 0.0);
        assert_eq!(
            (hops[1].addr, hops[1].avg),
            (None, None),
            "a hop that never answered stays, empty"
        );
        assert_eq!(hops[1].loss(), 100.0);
        assert!((hops[2].loss() - 66.67).abs() < 0.01);

        at(&mut t, 4, "203.0.113.5", 30, true);
        at(&mut t, 5, "203.0.113.5", 31, true);
        assert_eq!(
            t.hops().len(),
            4,
            "the path ends where the target first answered"
        );
    }

    #[test]
    fn unreachable_ends_the_path() {
        let mut t = sent(1..=5, 1);
        at(&mut t, 1, "192.0.2.1", 1, false);
        t.answer(
            2,
            "192.0.2.2".parse().unwrap(),
            Duration::from_millis(2),
            false,
            true,
        );
        let hops = t.hops();
        assert_eq!(hops.len(), 2);
        assert_eq!(t.reached_at, None);
    }

    /// A router said Unreachable at TTL 3 on one pass, and the target
    /// answered at TTL 5 on another. The target's reply shows the path gets
    /// through, so it's the end.
    #[test]
    fn target_outranks_unreachable() {
        let mut t = sent(1..=6, 2);
        t.answer(
            3,
            "192.0.2.3".parse().unwrap(),
            Duration::from_millis(3),
            false,
            true,
        );
        at(&mut t, 5, "203.0.113.5", 5, true);
        let hops = t.hops();
        assert_eq!(hops.len(), 5, "{hops:?}");
        assert_eq!(hops[4].addr, Some("203.0.113.5".parse().unwrap()));
    }

    /// ECMP: a router answered TTL 2 on one pass before the target did on
    /// another. The target's reply names the hop.
    #[test]
    fn target_reply_names_its_hop() {
        let mut t = sent(1..=2, 3);
        at(&mut t, 1, "192.0.2.1", 1, false);
        at(&mut t, 2, "198.51.100.9", 3, false);
        at(&mut t, 2, "203.0.113.5", 4, true);
        assert_eq!(t.hops()[1].addr, Some("203.0.113.5".parse().unwrap()));
    }

    #[test]
    fn nothing_sent_is_no_hops() {
        assert!(Tally::default().hops().is_empty());
        assert_eq!(
            Hop {
                ttl: 1,
                addr: None,
                sent: 0,
                received: 0,
                best: None,
                avg: None,
                worst: None
            }
            .loss(),
            100.0
        );
    }

    #[test]
    fn loss_survives_a_hop_edited_by_hand() {
        let h = Hop {
            ttl: 1,
            addr: None,
            sent: 2,
            received: 5,
            best: None,
            avg: None,
            worst: None,
        };
        assert_eq!(h.loss(), 0.0);
    }

    #[test]
    fn two_traces_at_once_pick_different_tokens() {
        let (a, b) = (token(), token());
        assert_ne!(a, b);
        assert_ne!(a[..4], b[..4], "identifier and sequence base collide");
    }

    #[test]
    fn errors_say_what_went_wrong() {
        use io::{Error as E, ErrorKind};
        assert!(
            matches!(
                Error::from_socket(E::from_raw_os_error(libc::EPERM)),
                Error::NotPermitted(_)
            ),
            "EPERM"
        );
        assert!(
            matches!(
                Error::from_socket(E::from_raw_os_error(libc::EACCES)),
                Error::NotPermitted(_)
            ),
            "EACCES"
        );
        assert!(matches!(
            Error::from_socket(E::from(ErrorKind::AddrNotAvailable)),
            Error::Io(_)
        ));
        assert!(
            matches!(
                Error::from_socket(E::from_raw_os_error(libc::EAFNOSUPPORT)),
                Error::NoRoute(_)
            ),
            "a kernel without IPv6"
        );
        assert!(matches!(
            Error::from_send(E::from_raw_os_error(libc::EADDRNOTAVAIL)),
            Error::NoRoute(_)
        ));
        // A send refused with EACCES (a broadcast address, say) is not the
        // sysctl's doing.
        assert!(matches!(
            Error::from_send(E::from(ErrorKind::PermissionDenied)),
            Error::Send(_)
        ));
        #[cfg(target_os = "macos")]
        assert!(
            matches!(
                Error::from_send(E::from_raw_os_error(65)),
                Error::NoRoute(_)
            ),
            "EHOSTUNREACH on macOS"
        );
        #[cfg(target_os = "macos")]
        assert!(
            matches!(
                Error::from_send(E::from_raw_os_error(51)),
                Error::NoRoute(_)
            ),
            "ENETUNREACH on macOS"
        );
        #[cfg(target_os = "linux")]
        assert!(
            matches!(
                Error::from_send(E::from_raw_os_error(101)),
                Error::NoRoute(_)
            ),
            "ENETUNREACH on Linux"
        );
        #[cfg(target_os = "linux")]
        assert!(
            matches!(
                Error::from_send(E::from_raw_os_error(113)),
                Error::NoRoute(_)
            ),
            "EHOSTUNREACH on Linux"
        );

        let msg = Error::NotPermitted(E::from_raw_os_error(libc::EACCES)).to_string();
        assert!(msg.contains("ping_group_range"), "{msg}");
    }

    #[test]
    fn source_in_other_family_is_refused() {
        let tracer = Tracer::new().source("192.0.2.10".parse().unwrap());
        match tracer.trace("::1".parse().unwrap()) {
            Err(Error::NoSource(to)) => assert_eq!(to, "::1".parse::<IpAddr>().unwrap()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn settings_have_a_floor_and_a_ceiling() {
        let t = Tracer::new()
            .cycles(0)
            .max_hops(0)
            .wait(Duration::MAX)
            .send_gap(Duration::MAX);
        assert_eq!((t.cycles, t.max_hops), (1, 1));
        assert_eq!((t.wait, t.send_gap), (LONGEST, LONGEST));
        let t = Tracer::new().wait(Duration::ZERO).send_gap(Duration::ZERO);
        assert_eq!((t.wait, t.send_gap), (SHORTEST, SHORTEST));
        let t = Tracer::new().tag(&[b'x'; 100]);
        assert_eq!(t.tag.len(), packet::MAX_TAG);
    }

    #[test]
    fn targets_that_arent_one_host() {
        for to in [
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::",
            "ff02::1",
            "::ffff:0.0.0.0",
        ] {
            match Tracer::new().trace(to.parse().unwrap()) {
                Err(Error::InvalidTarget(_)) => {}
                other => panic!("{to}: {other:?}"),
            }
        }
    }

    #[test]
    fn shareable_across_threads() {
        fn check<T: Send + Sync>() {}
        check::<Tracer>();
        check::<Trace>();
        check::<Error>();
    }
}
