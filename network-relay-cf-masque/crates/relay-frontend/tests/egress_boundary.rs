//! Regression guards for the destination I/O boundary. Ingress listeners,
//! client diagnostics and test fixtures intentionally have separate sockets.

fn production(source: &str) -> String {
    source.split("#[cfg(test)]").next().unwrap().split_whitespace().collect()
}

#[test]
fn destination_resolution_and_opening_cannot_use_host_network_apis() {
    for (name, source) in
        [("connect.rs", include_str!("../src/connect.rs")), ("policy.rs", include_str!("../src/policy.rs"))]
    {
        let source = production(source);
        for forbidden in [
            "ToSocketAddrs",
            "lookup_host",
            "spawn_blocking",
            "tokio::net",
            "TcpSocket",
            "std::net::TcpStream",
            "std::net::UdpSocket",
            "TcpStream::connect",
            "UdpSocket::bind",
            "UdpSocket::connect",
            "socket2",
        ] {
            assert!(!source.contains(forbidden), "{name} bypasses the required egress with {forbidden}");
        }
    }
    let connect = production(include_str!("../src/connect.rs"));
    let policy = production(include_str!("../src/policy.rs"));
    assert!(connect.contains("egress.connect_tcp("));
    assert!(connect.contains("egress.connect_udp("));
    assert!(policy.contains("egress.resolve("));
}

#[test]
fn destination_resets_use_the_stream_abort_capability() {
    // `run` initializes ingress listeners and tunes their native buffers.
    // The preceding request/tunnel code owns destination I/O.
    let server = include_str!("../src/server/mod.rs").split("pub async fn run(").next().unwrap();
    for (name, source) in
        [("server/mod.rs destination handling", server), ("server/pump.rs", include_str!("../src/server/pump.rs"))]
    {
        let source = production(source);
        for forbidden in ["socket2", "set_linger", "std::net::TcpStream", "tokio::net::TcpStream"] {
            assert!(!source.contains(forbidden), "{name} assumes a native target socket through {forbidden}");
        }
    }
    let server = production(server);
    let pump = production(include_str!("../src/server/pump.rs"));
    assert!(server.contains(".abort()"));
    assert!(pump.contains(".abort_handle()"));
}
