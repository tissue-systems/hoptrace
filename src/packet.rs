//! Echo requests, and reading the ICMP messages that answer them.

/// The bytes a request carries after the ICMP header, ahead of the trace's
/// token, unless [`crate::Tracer::tag`] sets others. A packet capture shows
/// them.
pub(crate) const TAG: &[u8] = b"hoptrace";

/// The longest tag [`crate::Tracer::tag`] takes. Every byte of it goes out
/// in every request.
pub(crate) const MAX_TAG: usize = 32;

/// What one ICMP message says about a request we sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// The target answered the request with this sequence number.
    Reply(u16),
    /// A router on the way says the request with this sequence number ran
    /// out of TTL.
    Expired(u16),
    /// A router, or the target, says the request with this sequence number
    /// can't get through.
    Unreachable(u16),
}

/// RFC 1071 ones-complement checksum.
pub(crate) fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], chunk.get(1).copied().unwrap_or(0)]);
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An echo request. The IPv4 checksum is filled in here. For IPv6 the kernel
/// computes it, since it covers a pseudo-header only the kernel knows.
///
/// Linux replaces the identifier on a ping socket with the socket's own and
/// keeps that socket's errors to itself, so `ident` only matters on macOS,
/// where neither happens.
pub(crate) fn echo_request(v6: bool, ident: u16, seq: u16, tag: &[u8], token: &[u8; 8]) -> Vec<u8> {
    let mut p = vec![if v6 { 128 } else { 8 }, 0, 0, 0];
    p.extend_from_slice(&ident.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(tag);
    p.extend_from_slice(token);
    if !v6 {
        let sum = checksum(&p);
        p[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    p
}

/// Steps over an IPv4 header in front, which macOS leaves on.
fn strip_v4(p: &[u8]) -> Option<&[u8]> {
    if p.first().is_some_and(|b| b >> 4 == 4) {
        let ihl = ((p[0] & 0x0f) as usize) * 4;
        return p.get(ihl..);
    }
    Some(p)
}

/// Reads a message off the socket's ordinary queue.
///
/// An echo reply must carry `token` right after `tag`. An error must quote
/// an echo request with our `ident`, and the token too when the router quoted
/// that much of it (RFC 792 asks for only the first 8 bytes; most routers
/// send more). Either way the sequence number names the request.
pub(crate) fn parse_answer(
    v6: bool,
    packet: &[u8],
    ident: u16,
    tag: &[u8],
    token: &[u8; 8],
) -> Option<Answer> {
    let p = if v6 { packet } else { strip_v4(packet)? };
    if p.len() < 8 {
        return None;
    }
    let (reply, expired, unreach) = if v6 { (129, 3, 1) } else { (0, 11, 3) };
    let ty = p[0];
    if ty == reply {
        let seq = u16::from_be_bytes([p[6], p[7]]);
        return carries(p, tag, token).then_some(Answer::Reply(seq));
    }
    if ty != expired && ty != unreach {
        return None;
    }
    // The quoted datagram: its IP header, then at least the first 8 bytes of
    // our echo request.
    let inner = &p[8..];
    let quoted = if v6 {
        if !inner.first().is_some_and(|b| b >> 4 == 6) || inner.get(6) != Some(&58) {
            return None;
        }
        inner.get(40..)?
    } else {
        if !inner.first().is_some_and(|b| b >> 4 == 4) || inner.get(9) != Some(&1) {
            return None;
        }
        inner.get(((inner[0] & 0x0f) as usize) * 4..)?
    };
    let request = if v6 { 128 } else { 8 };
    if quoted.len() < 8
        || quoted[0] != request
        || u16::from_be_bytes([quoted[4], quoted[5]]) != ident
    {
        return None;
    }
    if quoted.len() >= 8 + tag.len() + token.len() && !carries(quoted, tag, token) {
        return None;
    }
    let seq = u16::from_be_bytes([quoted[6], quoted[7]]);
    Some(if ty == expired {
        Answer::Expired(seq)
    } else {
        Answer::Unreachable(seq)
    })
}

/// Whether the echo message `p` has `token` where our request put it, right
/// after `tag`.
fn carries(p: &[u8], tag: &[u8], token: &[u8; 8]) -> bool {
    let at = 8 + tag.len();
    p.get(at..at + token.len()) == Some(token)
}

/// Reads a Linux error-queue entry: `origin` and `ty` come from the
/// `sock_extended_err`, and `payload` is the router's quote of our request,
/// at least its first 8 bytes. Only the sequence number is read from it: the
/// kernel put its own identifier in the request.
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
pub(crate) fn parse_errqueue(v6: bool, origin: u8, ty: u8, payload: &[u8]) -> Option<Answer> {
    // SO_EE_ORIGIN_ICMP is 2, SO_EE_ORIGIN_ICMP6 is 3.
    let (want_origin, expired, unreach) = if v6 { (3, 3, 1) } else { (2, 11, 3) };
    if origin != want_origin || payload.len() < 8 {
        return None;
    }
    let seq = u16::from_be_bytes([payload[6], payload[7]]);
    match ty {
        t if t == expired => Some(Answer::Expired(seq)),
        t if t == unreach => Some(Answer::Unreachable(seq)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: u16 = 0x5a17;
    const TOKEN: [u8; 8] = *b"abcdefgh";

    fn v4_header(proto: u8) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0] = 0x45;
        h[9] = proto;
        h
    }

    /// A Time Exceeded or Unreachable as macOS hands it over: outer IPv4
    /// header, the ICMP error, the quoted IPv4 header, then the first `quote`
    /// bytes of the request sent with `ident`.
    fn v4_error(ty: u8, ident: u16, seq: u16, token: &[u8; 8], quote: usize) -> Vec<u8> {
        let mut p = v4_header(1);
        p.extend_from_slice(&[ty, 0, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&v4_header(1));
        let req = echo_request(false, ident, seq, TAG, token);
        p.extend_from_slice(&req[..quote.min(req.len())]);
        p
    }

    #[test]
    fn checksum_of_a_request_verifies_to_zero() {
        let p = echo_request(false, ID, 7, TAG, &TOKEN);
        assert_eq!(
            checksum(&p),
            0,
            "a packet with its checksum filled in sums to zero"
        );
        assert_eq!(p[0], 8);
        assert_eq!(&p[4..8], &[0x5a, 0x17, 0, 7]);
        // RFC 1071's worked example.
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            !0xddf2
        );
        assert_eq!(
            checksum(&[0xff]),
            !0xff00,
            "an odd byte is padded with zero"
        );
    }

    #[test]
    fn answers_on_the_ordinary_queue() {
        let mut reply = echo_request(false, ID, 9, TAG, &TOKEN);
        reply[0] = 0;
        assert_eq!(
            parse_answer(false, &reply, ID, TAG, &TOKEN),
            Some(Answer::Reply(9))
        );
        assert_eq!(
            parse_answer(false, &reply, ID, TAG, b"zzzzzzzz"),
            None,
            "another process's echo"
        );
        let mut with_ip = v4_header(1);
        with_ip.extend_from_slice(&reply);
        assert_eq!(
            parse_answer(false, &with_ip, ID, TAG, &TOKEN),
            Some(Answer::Reply(9)),
            "macOS leaves the IPv4 header on"
        );
        let request = echo_request(false, ID, 9, TAG, &TOKEN);
        assert_eq!(
            parse_answer(false, &request, ID, TAG, &TOKEN),
            None,
            "our own request"
        );

        let expired = v4_error(11, ID, 3, &TOKEN, 8);
        assert_eq!(
            parse_answer(false, &expired, ID, TAG, &TOKEN),
            Some(Answer::Expired(3))
        );
        assert_eq!(
            parse_answer(false, &v4_error(3, ID, 4, &TOKEN, 8), ID, TAG, &TOKEN),
            Some(Answer::Unreachable(4))
        );
        assert_eq!(
            parse_answer(false, &v4_error(5, ID, 4, &TOKEN, 8), ID, TAG, &TOKEN),
            None,
            "a redirect"
        );
        let mut udp = expired.clone();
        udp[20 + 8 + 9] = 17;
        assert_eq!(
            parse_answer(false, &udp, ID, TAG, &TOKEN),
            None,
            "quoting a UDP datagram"
        );
        assert_eq!(
            parse_answer(false, &expired[..30], ID, TAG, &TOKEN),
            None,
            "cut short"
        );
    }

    #[test]
    fn answers_over_ipv6() {
        let mut expired = vec![3u8, 0, 0, 0, 0, 0, 0, 0];
        let mut ip6 = vec![0u8; 40];
        ip6[0] = 0x60;
        ip6[6] = 58;
        expired.extend_from_slice(&ip6);
        expired.extend_from_slice(&echo_request(true, ID, 7, TAG, &TOKEN)[..8]);
        assert_eq!(
            parse_answer(true, &expired, ID, TAG, &TOKEN),
            Some(Answer::Expired(7))
        );
        expired[0] = 1;
        assert_eq!(
            parse_answer(true, &expired, ID, TAG, &TOKEN),
            Some(Answer::Unreachable(7))
        );

        let mut reply = echo_request(true, ID, 2, TAG, &TOKEN);
        assert_eq!(reply[0], 128);
        reply[0] = 129;
        assert_eq!(
            parse_answer(true, &reply, ID, TAG, &TOKEN),
            Some(Answer::Reply(2))
        );
        assert_eq!(
            parse_answer(true, &reply[..10], ID, TAG, &TOKEN),
            None,
            "a cut reply has no token"
        );
    }

    /// Two traces running at once on one macOS host see each other's Time
    /// Exceeded. Each keeps only the ones quoting its own request.
    #[test]
    fn other_traces_errors_are_not_ours() {
        let other_ident = v4_error(11, ID ^ 1, 3, &TOKEN, 8);
        assert_eq!(parse_answer(false, &other_ident, ID, TAG, &TOKEN), None);
        let whole = v4_error(11, ID, 3, &TOKEN, 64);
        assert_eq!(
            parse_answer(false, &whole, ID, TAG, &TOKEN),
            Some(Answer::Expired(3)),
            "a full quote with our token"
        );
        assert_eq!(
            parse_answer(false, &whole, ID, TAG, b"zzzzzzzz"),
            None,
            "a full quote of another token"
        );
    }

    #[test]
    fn answers_on_the_error_queue() {
        let req = echo_request(false, ID, 300, TAG, &TOKEN);
        assert_eq!(
            parse_errqueue(false, 2, 11, &req),
            Some(Answer::Expired(300))
        );
        assert_eq!(
            parse_errqueue(false, 2, 3, &req),
            Some(Answer::Unreachable(300))
        );
        assert_eq!(
            parse_errqueue(false, 1, 11, &req),
            None,
            "a local error is not a hop"
        );
        assert_eq!(parse_errqueue(true, 3, 3, &req), Some(Answer::Expired(300)));
        assert_eq!(
            parse_errqueue(true, 3, 1, &req),
            Some(Answer::Unreachable(300))
        );
        assert_eq!(parse_errqueue(false, 2, 11, &req[..4]), None);
    }
}
