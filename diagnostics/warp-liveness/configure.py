"""Change exactly one outer, application or inner TCP setting in the loopback fixture."""
from pathlib import Path
import sys

base=Path("network-relay-cf-masque")
mode=sys.argv[1]
def edit(path, old, new, count=1):
    path=base/path
    source=path.read_text()
    if source.count(old)!=count:
        raise ValueError("Unexpected source in "+str(path))
    path.write_text(source.replace(old,new))

if mode=="production-keepalive":
    anchor = "config.max_sockets = max_sockets.or(config.max_sockets);"
    edit("tests/warp_matrix.rs", anchor, "config.keepalive_secs = 15;\n        "+anchor)
elif mode=="application-heartbeat":
    edit("tests/support/persistent.rs", "tokio::time::interval(Duration::from_secs(10))",
         "tokio::time::interval(Duration::from_secs(3))", 2)
elif mode=="inner-reno":
    edit("crates/warp-egress/Cargo.toml", '"socket-tcp-cubic",', '"socket-tcp-cubic", "socket-tcp-reno",')
    edit("crates/warp-egress/src/netstack.rs", "socket.set_congestion_control(tcp::CongestionControl::Cubic);",
         "socket.set_congestion_control(tcp::CongestionControl::Reno);")
elif mode!="reference":
    raise ValueError(mode)
