//! poll(2), and on Linux the error queue: `IP_RECVERR` and the control
//! messages `recvmsg(MSG_ERRQUEUE)` returns. socket2 wraps `recvmsg`, but not
//! `IP_RECVERR` or the `sock_extended_err` walk, so this calls libc directly.

use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::time::Duration;

/// Blocks until the socket has something to read, on either queue, or until
/// `timeout` runs out. Linux reports a non-empty error queue as `POLLERR`,
/// which poll(2) returns whether or not it was asked for.
pub(crate) fn wait_readable(sock: &UdpSocket, timeout: Duration) {
    let ms = ((timeout.as_micros() + 999) / 1000).min(i32::MAX as u128) as libc::c_int;
    let mut fd = libc::pollfd {
        fd: sock.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd, and the count says one.
    let rc = unsafe { libc::poll(&mut fd, 1, ms) };
    if rc < 0 {
        // EINTR, or something worse. Sleep a little so the caller's loop
        // can't spin, and let it try again.
        std::thread::sleep(timeout.min(Duration::from_millis(1)));
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux::{drain_errqueue, recverr};

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
    use std::os::fd::AsRawFd;
    use std::time::Instant;

    use crate::packet::{parse_errqueue, Answer};

    /// Turns on `IP_RECVERR` (or `IPV6_RECVERR`). Without it a ping socket
    /// throws Time Exceeded away.
    pub(crate) fn recverr(sock: &socket2::Socket, v6: bool) -> std::io::Result<()> {
        let on: libc::c_int = 1;
        let (level, name) = if v6 {
            (libc::SOL_IPV6, libc::IPV6_RECVERR)
        } else {
            (libc::SOL_IP, libc::IP_RECVERR)
        };
        // SAFETY: a valid fd and a c_int option of the right size.
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                level,
                name,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Reads the error queue, up to `crate::DRAIN` entries. The payload of each entry is the
    /// router's quote of our request, at least its first 8 bytes, and the
    /// router is the offender address that follows the `sock_extended_err`.
    pub(crate) fn drain_errqueue(
        sock: &UdpSocket,
        v6: bool,
        out: &mut Vec<(Answer, IpAddr, Instant)>,
    ) {
        for _ in 0..crate::DRAIN {
            let mut data = [0u8; 576];
            let mut control = [0u8; 512];
            let mut iov = libc::iovec {
                iov_base: data.as_mut_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            };
            // SAFETY: msghdr is plain data; every pointer set below outlives the call.
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = control.len() as _;
            // SAFETY: as above.
            let n = unsafe {
                libc::recvmsg(
                    sock.as_raw_fd(),
                    &mut msg,
                    libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
                )
            };
            if n < 0 {
                return;
            }
            let at = Instant::now();
            let payload = &data[..(n as usize).min(data.len())];
            let offender_len = if v6 {
                std::mem::size_of::<libc::sockaddr_in6>()
            } else {
                std::mem::size_of::<libc::sockaddr_in>()
            };
            let need = std::mem::size_of::<libc::sock_extended_err>() + offender_len;
            // SAFETY: CMSG_LEN is arithmetic on its argument.
            let need = unsafe { libc::CMSG_LEN(need as u32) } as usize;
            // SAFETY: CMSG_FIRSTHDR and CMSG_NXTHDR walk the control buffer
            // the kernel filled and stay inside msg_controllen. A message is
            // read only when its cmsg_len covers the sock_extended_err and the
            // offender address after it; the reads are unaligned because
            // nothing promises CMSG_DATA is aligned for either.
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    let c = &*cmsg;
                    let ours = (c.cmsg_level == libc::SOL_IP && c.cmsg_type == libc::IP_RECVERR)
                        || (c.cmsg_level == libc::SOL_IPV6 && c.cmsg_type == libc::IPV6_RECVERR);
                    if ours && c.cmsg_len as usize >= need {
                        let ee = libc::CMSG_DATA(cmsg) as *const libc::sock_extended_err;
                        let e = std::ptr::read_unaligned(ee);
                        let offender = ee.add(1) as *const u8;
                        let from = if v6 {
                            let sa =
                                std::ptr::read_unaligned(offender as *const libc::sockaddr_in6);
                            (sa.sin6_family as i32 == libc::AF_INET6)
                                .then(|| IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)))
                        } else {
                            let sa = std::ptr::read_unaligned(offender as *const libc::sockaddr_in);
                            (sa.sin_family as i32 == libc::AF_INET).then(|| {
                                IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)))
                            })
                        };
                        if let (Some(from), Some(a)) =
                            (from, parse_errqueue(v6, e.ee_origin, e.ee_type, payload))
                        {
                            out.push((a, from, at));
                        }
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }
        }
    }
}
