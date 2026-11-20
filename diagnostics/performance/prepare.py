"""Build a temporary test module from the exact production code at checkout."""
from pathlib import Path

here = Path(__file__).resolve().parent
root = here.parent.parent

def once(source, before, after):
    if source.count(before) != 1:
        raise RuntimeError("Production anchor changed: " + before)
    return source.replace(before, after)

server = (root / "src/server/mod.rs").read_text()
date = server[server.index("fn http_date_at("):server.index("/// Reads the configuration file again")]
(here / "src/date.rs").write_text(date)
stack = (root / "network-relay-cf-masque/crates/warp-egress/src/netstack.rs").read_text()
for buf, small, large in [("RX", 256, 1024), ("TX", 128, 512)]:
    line = f"const TCP_{buf}_BUFFER: usize = {small} << 10;"
    stack = once(stack, line, line.replace(str(small), f'if cfg!(feature = "large-buffers") {{ {large} }} else {{ {small} }}').replace("= if", "= (if").replace(" << 10;", ") << 10;"))
line = "socket.set_congestion_control(tcp::CongestionControl::Cubic);"
stack = once(stack, line, '''match std::env::var("RELAY_STACK_STUDY").as_deref() {
        Ok("reno") => socket.set_congestion_control(tcp::CongestionControl::Reno),
        Ok("immediate-ack") => {
            socket.set_congestion_control(tcp::CongestionControl::Cubic);
            socket.set_ack_delay(None);
        }
        Ok("original") | Ok("large") => socket.set_congestion_control(tcp::CongestionControl::Cubic),
        _ => panic!("missing stack study variant"),
    }''')
(here / "src/netstack.rs").write_text(stack)
parts = []
for product in ["rs", "nf", "tun"]:
    core = root / f"network-relay-{product}/Core/src"
    data = (core / "client.rs").read_text()
    a = data.index("        let value_len = payload.len() as u64 + 1;")
    b = data.index("        self.stream.write_all(&wire)", a)
    varint = (core / "proto/varint.rs").read_text()
    part = data[a:b].replace("proto::varint::", "").replace("proto::capsule::types::DATAGRAM", "0").replace("proto::datagram::CONTEXT_ID_UDP_PAYLOAD", "0")
    parts.append((part, varint[varint.index("pub const MAX"):varint.index("/// Decodes a variable-length")]))
assert len(set(parts)) == 1
part, varint = parts[0]
(here / "src/wire.rs").write_text(varint + "\nfn owned(payload: &[u8]) -> bytes::BytesMut {\n" + part + "wire\n}\n")
