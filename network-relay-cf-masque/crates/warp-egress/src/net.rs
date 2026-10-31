//! A stack-only DNS transport. There is no kernel or direct network variant.

use std::io;
use std::net::{IpAddr, SocketAddr};

use crate::netstack::{NetStack, TcpStream, UdpSocket};

#[derive(Clone)]
pub enum Net {
    Stack(NetStack),
}

impl Net {
    pub fn addresses(&self) -> Vec<IpAddr> {
        match self {
            Self::Stack(stack) => stack.addresses(),
        }
    }

    pub fn check_available(&self) -> io::Result<()> {
        match self {
            Self::Stack(stack) => stack.check_available(),
        }
    }

    pub async fn closed(&self) -> String {
        match self {
            Self::Stack(stack) => stack.closed().await,
        }
    }

    pub async fn connect(&self, remote: SocketAddr) -> io::Result<TcpStream> {
        match self {
            Self::Stack(stack) => stack.connect(remote).await,
        }
    }

    pub fn bind_udp(&self) -> io::Result<UdpSocket> {
        match self {
            Self::Stack(stack) => stack.bind_udp(0),
        }
    }

    pub fn max_udp_payload(&self, destination: IpAddr) -> io::Result<usize> {
        match self {
            Self::Stack(stack) => {
                stack.local_address(destination)?;
                Ok(crate::netstack::max_udp_payload(stack.mtu(), destination.is_ipv4()))
            }
        }
    }
}
