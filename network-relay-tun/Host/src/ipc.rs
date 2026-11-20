//! Bounded Unix IPC primitives. Authentication uses the connected socket's OS
//! credentials before reading any client-controlled bytes.
use crate::protocol::{MAX_REQUEST, Request, decode};
use anyhow::{Result, ensure};
use std::{
    io::{Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::Duration,
};

pub fn authenticate(stream: &UnixStream, owner: u32) -> Result<()> {
    ensure!(owner != 0, "invalid installed owner");
    #[cfg(target_os = "macos")]
    let uid = {
        let mut uid = 0;
        let mut gid = 0;
        ensure!(
            unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0,
            "cannot authenticate local peer"
        );
        uid
    };
    #[cfg(target_os = "linux")]
    let uid = {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        ensure!(
            unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut cred as *mut libc::ucred).cast(),
                    &mut length,
                )
            } == 0,
            "cannot authenticate local peer"
        );
        ensure!(length as usize == std::mem::size_of::<libc::ucred>(), "invalid peer credentials");
        cred.uid
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    compile_error!("peer authentication is not implemented on this platform");
    ensure!(uid == owner, "unauthorized local peer");
    // Darwin inherits O_NONBLOCK from the listener. Request framing uses
    // blocking reads with a timeout, including between consecutive requests.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(())
}

pub fn read_request(stream: &mut impl Read) -> Result<Request> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(length > 0 && length <= MAX_REQUEST, "invalid IPC frame size");
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    decode(&bytes)
}

pub fn write_reply(stream: &mut impl Write, reply: &impl serde::Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(reply)?;
    ensure!(bytes.len() <= MAX_REQUEST, "reply exceeds frame size");
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

pub fn nonce() -> Result<String> {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_header_is_rejected_before_body_read_or_allocation() {
        let mut wire = &u32::MAX.to_be_bytes()[..];
        assert!(read_request(&mut wire).is_err());
    }
    #[test]
    fn frames_round_trip_and_partial_input_is_rejected() {
        let mut wire = Vec::new();
        write_reply(&mut wire, &Request::Status).unwrap();
        assert!(matches!(read_request(&mut &wire[..]).unwrap(), Request::Status));
        for end in 0..wire.len() {
            assert!(read_request(&mut &wire[..end]).is_err());
        }
    }
    #[test]
    fn leases_use_full_random_generation() {
        let a = nonce().unwrap();
        let b = nonce().unwrap();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }
}

#[cfg(test)]
mod peer_tests {
    use super::*;
    #[test]
    fn authenticates_kernel_peer_and_rejects_other_owner() {
        let (server, _client) = UnixStream::pair().unwrap();
        let actual = unsafe { libc::geteuid() };
        if actual == 0 {
            assert!(authenticate(&server, actual).is_err());
        } else {
            authenticate(&server, actual).unwrap();
            assert_eq!(server.read_timeout().unwrap(), Some(Duration::from_secs(60)));
        }
        assert!(authenticate(&server, actual.saturating_add(1)).is_err());
    }
    #[test]
    fn authentication_restores_blocking_reads_for_delayed_requests() {
        let actual = unsafe { libc::geteuid() };
        if actual == 0 {
            return; // Root is intentionally not an eligible installed owner.
        }
        let (mut server, mut client) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        authenticate(&server, actual).unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            write_reply(&mut client, &Request::Status).unwrap();
        });
        assert!(matches!(read_request(&mut server).unwrap(), Request::Status));
        writer.join().unwrap();
    }
}
