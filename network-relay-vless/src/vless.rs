//! The VLESS wire format (version 0), as Xray-core, sing-box and mihomo
//! implement it. There is no specification document; the layout below
//! follows Xray-core's `proxy/vless/encoding`.
//!
//! Request, sent once at the start of the connection:
//!
//! ```text
//! version (1) = 0 | user ID (16) | addons length (1) = 0 | command (1)
//!   | port (2, big endian) | address type (1) | address
//! ```
//!
//! Commands: 1 TCP, 2 UDP (3, Mux, is not used). Address types: 1 IPv4
//! (4 bytes), 2 domain (not used: the relay sends only the addresses its
//! destination rules allowed), 3 IPv6 (16 bytes). The response, which the
//! server sends before its first data, is `version (1) | addons length (1) |
//! addons`. With the UDP command each datagram travels as a 2-byte big-endian
//! length and the payload; one connection carries one destination.

use std::io;
use std::net::{IpAddr, SocketAddr};

pub const VERSION: u8 = 0;

/// The largest UDP payload passed in either direction. Xray-core drops
/// packets over 8190 bytes towards the client (`MultiLengthPacketWriter`,
/// 8192-byte buffers minus the length) and splits longer ones from the
/// client into several datagrams, so nothing larger is sent.
pub const MAX_UDP_PAYLOAD: usize = 8190;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Tcp = 1,
    Udp = 2,
}

/// A VLESS user ID.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UserId(pub [u8; 16]);

impl std::fmt::Debug for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A user ID is a credential.
        f.write_str("UserId(..)")
    }
}

impl UserId {
    /// Parses an ID as Xray-core does (`common/uuid.ParseString`): a UUID
    /// with or without hyphens, or any other string of 1 to 30 bytes, which
    /// stands for the version 5 UUID of SHA-1(zero UUID || string).
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        match bytes.len() {
            32 | 36 => Self::parse_uuid(text),
            1..=30 => {
                let mut input = [0u8; 16].to_vec();
                input.extend_from_slice(bytes);
                let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
                let mut id = [0u8; 16];
                id.copy_from_slice(&digest.as_ref()[..16]);
                id[6] = (id[6] & 0x0f) | (5 << 4);
                id[8] = (id[8] & 0x3f) | 0x80;
                Some(Self(id))
            }
            _ => None,
        }
    }

    fn parse_uuid(text: &str) -> Option<Self> {
        let hex: String = if text.len() == 36 {
            let groups: Vec<&str> = text.split('-').collect();
            let lengths: Vec<usize> = groups.iter().map(|g| g.len()).collect();
            if lengths != [8, 4, 4, 4, 12] {
                return None;
            }
            groups.concat()
        } else {
            text.to_string()
        };
        let mut id = [0u8; 16];
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        Some(Self(id))
    }
}

/// The request header for `command` to `peer`.
pub fn request(id: &UserId, command: Command, peer: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + 16);
    out.push(VERSION);
    out.extend_from_slice(&id.0);
    out.push(0); // no addons: no flow
    out.push(command as u8);
    out.extend_from_slice(&peer.port().to_be_bytes());
    match peer.ip().to_canonical() {
        IpAddr::V4(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(3);
            out.extend_from_slice(&ip.octets());
        }
    }
    out
}

/// Reads the response header off the start of the server's byte stream.
#[derive(Debug, Default)]
pub struct ResponseHeader {
    /// Header bytes consumed so far: the version, then the addons length.
    seen: usize,
    /// Addon bytes still to skip, once their length is known.
    addons_left: usize,
    done: bool,
}

impl ResponseHeader {
    pub fn done(&self) -> bool {
        self.done
    }

    /// Consumes header bytes from the front of `data` and returns how many.
    /// The rest, if any, is payload.
    pub fn feed(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut used = 0;
        while !self.done && used < data.len() {
            let byte = data[used];
            match self.seen {
                0 => {
                    if byte != VERSION {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("the VLESS server answered with version {byte}, not {VERSION}"),
                        ));
                    }
                    self.seen = 1;
                    used += 1;
                }
                1 => {
                    // Addons are a protobuf of at most 255 bytes; this client
                    // requests none, so there is nothing in them to act on.
                    self.addons_left = byte as usize;
                    self.seen = 2;
                    used += 1;
                    self.done = self.addons_left == 0;
                }
                _ => {
                    let skip = self.addons_left.min(data.len() - used);
                    self.addons_left -= skip;
                    used += skip;
                    self.done = self.addons_left == 0;
                }
            }
        }
        Ok(used)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_ids_parse_as_xray_parses_them() {
        let canonical = UserId::parse("b4e4fad1-c320-428e-92dc-f8f6944a7dec").unwrap();
        assert_eq!(canonical.0[..4], [0xb4, 0xe4, 0xfa, 0xd1]);
        assert_eq!(canonical.0[15], 0xec);
        assert_eq!(UserId::parse("b4e4fad1c320428e92dcf8f6944a7dec"), Some(canonical));
        assert_eq!(UserId::parse("B4E4FAD1-C320-428E-92DC-F8F6944A7DEC"), Some(canonical));
        for bad in
            ["", "b4e4fad1-c320-428e-92dc-f8f6944a7de", "b4e4fad1c-320-428e-92dc-f8f6944a7dec", "x".repeat(31).as_str()]
        {
            assert_eq!(UserId::parse(bad), None, "{bad:?}");
        }
        assert_eq!(UserId::parse("g4e4fad1-c320-428e-92dc-f8f6944a7dec"), None);
        // What Xray-core v26.10.31's `uuid.ParseString` returns for these.
        for (text, xray) in [
            ("example", "feb54431-301b-52bb-a6dd-e1e93e81bb9e"),
            ("network-relay-vless-test", "d8192086-cb6a-54c1-a026-945d19b27714"),
        ] {
            assert_eq!(UserId::parse(text), UserId::parse(xray), "{text}");
        }
    }

    #[test]
    fn requests_have_xrays_layout() {
        let id = UserId::parse("b4e4fad1-c320-428e-92dc-f8f6944a7dec").unwrap();
        let v4 = request(&id, Command::Tcp, "192.0.2.7:443".parse().unwrap());
        let mut expected = vec![0];
        expected.extend_from_slice(&id.0);
        expected.extend_from_slice(&[0, 1, 0x01, 0xbb, 1, 192, 0, 2, 7]);
        assert_eq!(v4, expected);
        let v6 = request(&id, Command::Udp, "[2001:db8::1]:53".parse().unwrap());
        assert_eq!(&v6[17..22], &[0, 2, 0, 53, 3]);
        assert_eq!(v6.len(), 22 + 16);
        assert_eq!(v6[22], 0x20);
        // An IPv4-mapped address goes as IPv4, as the relay checked it.
        let mapped = request(&id, Command::Tcp, "[::ffff:192.0.2.7]:443".parse().unwrap());
        assert_eq!(mapped, expected);
    }

    #[test]
    fn response_headers_are_consumed_in_any_split() {
        let mut header = ResponseHeader::default();
        assert_eq!(header.feed(&[0, 0, b'h', b'i']).unwrap(), 2);
        assert!(header.done());
        let mut header = ResponseHeader::default();
        assert_eq!(header.feed(&[0]).unwrap(), 1);
        assert!(!header.done());
        assert_eq!(header.feed(&[3, 9]).unwrap(), 2);
        assert_eq!(header.feed(&[9, 9, b'x']).unwrap(), 2);
        assert!(header.done());
        let error = ResponseHeader::default().feed(&[1, 0]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
