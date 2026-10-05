//! Operating system settings for sockets and the process.

use std::time::Duration;

/// Per-direction requested TCP buffer sizes. Linux accounts up to twice the
/// request for socket bookkeeping; explicit sizes disable TCP autotuning.
pub const CLIENT_TCP_BUFFER: usize = 512 * 1024;
pub const TARGET_TCP_BUFFER: usize = 1024 * 1024;

/// Bounds kernel TCP buffers before a connection can consume relay capacity.
/// Check the granted sizes too: a kernel minimum or platform-specific policy
/// must not silently exceed the amount included in the admission reservation.
pub fn limit_tcp_buffers(sock: socket2::SockRef<'_>, bytes: usize) -> std::io::Result<()> {
    let maximum = bytes.checked_mul(2).ok_or_else(|| std::io::Error::other("TCP buffer limit overflow"))?;
    sock.set_recv_buffer_size(bytes)?;
    sock.set_send_buffer_size(bytes)?;
    if sock.recv_buffer_size()? > maximum || sock.send_buffer_size()? > maximum {
        return Err(std::io::Error::other("kernel TCP buffers exceed the relay capacity reservation"));
    }
    Ok(())
}

/// Raises this process's soft limit on open files to `want`, or as far as the
/// hard limit allows. Every relayed TCP connection and UDP flow needs a file
/// descriptor; failing only costs capacity, so it is logged.
pub fn raise_open_file_limit(want: nix::libc::rlim_t) {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};
    let (soft, hard) = match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok(limits) => limits,
        Err(e) => return tracing::debug!("reading the open file limit: {e}"),
    };
    let target = want.min(hard);
    if soft >= target {
        return;
    }
    match setrlimit(Resource::RLIMIT_NOFILE, target, hard) {
        Ok(()) => tracing::debug!("open file limit raised from {soft} to {target}"),
        Err(e) => tracing::warn!("could not raise the open file limit from {soft} to {target}: {e}"),
    }
}

/// The open file limit now in effect.
pub fn open_file_limit() -> Option<nix::libc::rlim_t> {
    nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE).ok().map(|(soft, _)| soft)
}

/// Socket options for a TCP connection from a client: no Nagle delay, and a
/// dead peer is noticed within about a minute through keepalives while idle
/// and a user timeout while data is unacknowledged (Linux only; elsewhere
/// TCP's own retransmission timeout applies, after minutes).
pub fn tune_client_tcp(sock: socket2::SockRef<'_>) -> std::io::Result<()> {
    sock.set_tcp_nodelay(true)?;
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10))
        .with_retries(3);
    sock.set_tcp_keepalive(&keepalive)?;
    #[cfg(target_os = "linux")]
    sock.set_tcp_user_timeout(Some(Duration::from_secs(60)))?;
    Ok(())
}

/// Socket options for a relayed TCP connection to a destination: no Nagle
/// delay (the client's own TCP stack already batched the data), and
/// keepalives so connections to vanished hosts do not pile up.
pub fn tune_target_tcp(sock: socket2::SockRef<'_>) -> std::io::Result<()> {
    sock.set_tcp_nodelay(true)?;
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(120))
        .with_interval(Duration::from_secs(30))
        .with_retries(4);
    sock.set_tcp_keepalive(&keepalive)
}

/// RFC 9298: forwarded UDP must not introduce IP fragmentation.
#[cfg(target_os = "linux")]
pub fn no_udp_fragmentation(sock: socket2::SockRef<'_>, ipv6: bool) -> std::io::Result<()> {
    use nix::libc;
    use std::os::fd::AsRawFd;
    let (level, option, value) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, libc::IPV6_PMTUDISC_DO)
    } else {
        (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, libc::IP_PMTUDISC_DO)
    };
    // SAFETY: the descriptor is live, and value/length describe an integer.
    let result = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn no_udp_fragmentation(_sock: socket2::SockRef<'_>, _ipv6: bool) -> std::io::Result<()> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "UDP relay server requires Linux"))
}

/// Asks for larger socket buffers, as far as the kernel allows
/// (`net.core.rmem_max` and `wmem_max` cap them). Returns the sizes granted.
pub fn grow_buffers(sock: socket2::SockRef<'_>, bytes: usize) -> (usize, usize) {
    let _ = sock.set_recv_buffer_size(bytes);
    let _ = sock.set_send_buffer_size(bytes);
    (sock.recv_buffer_size().unwrap_or(0), sock.send_buffer_size().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_file_limit_goes_up_as_far_as_allowed() {
        use nix::sys::resource::{getrlimit, Resource};
        raise_open_file_limit(4096);
        let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        assert!(soft >= hard.min(4096), "soft {soft}, hard {hard}");
        assert_eq!(open_file_limit(), Some(soft));
    }

    #[test]
    fn socket_options_apply() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let sock = socket2::SockRef::from(&client);
        limit_tcp_buffers(socket2::SockRef::from(&client), CLIENT_TCP_BUFFER).unwrap();
        assert!(sock.recv_buffer_size().unwrap() <= 2 * CLIENT_TCP_BUFFER);
        assert!(sock.send_buffer_size().unwrap() <= 2 * CLIENT_TCP_BUFFER);
        tune_client_tcp(socket2::SockRef::from(&client)).unwrap();
        limit_tcp_buffers(socket2::SockRef::from(&client), TARGET_TCP_BUFFER).unwrap();
        assert!(sock.recv_buffer_size().unwrap() <= 2 * TARGET_TCP_BUFFER);
        assert!(sock.send_buffer_size().unwrap() <= 2 * TARGET_TCP_BUFFER);
        tune_target_tcp(socket2::SockRef::from(&client)).unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (rcv, snd) = grow_buffers(socket2::SockRef::from(&udp), 1 << 20);
        assert!(rcv > 0 && snd > 0);
    }

    #[test]
    fn kernel_minimum_cannot_silently_exceed_the_tcp_buffer_reservation() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(limit_tcp_buffers(socket2::SockRef::from(&listener), 1).is_err());
    }
}
