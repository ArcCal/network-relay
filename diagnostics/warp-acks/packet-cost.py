"""Select independently reversible packet processing strategies for a TCP receive test."""
from pathlib import Path
import subprocess
import sys

variant = sys.argv[1]
if variant not in ("prior", "ack-batch", "permits", "wide", "both"):
    raise SystemExit("unexpected variant")
subprocess.run([sys.executable, "diagnostics/warp-acks/configure.py", "prior" if variant == "prior" else "ack-batch"], check=True)

stack = Path("network-relay-cf-masque/crates/warp-egress/src/netstack.rs")
ip = Path("network-relay-cf-masque/vendor/smoltcp/src/wire/ip.rs")
ip_src = subprocess.check_output(["git", "show", f"HEAD:{ip}"], text=True)
if variant in ("permits", "both"):
    source = stack.read_text()
    before = "            for p in output_batch.drain(..) {"
    assert source.count(before) == 1
    source = source.replace(before, """            let pending = output_batch.len();
            if pending > 1 && pending <= outgoing.max_capacity() {
                if let Ok(permits) = outgoing.try_reserve_many(pending) {
                    for (permit, packet) in permits.zip(output_batch.drain(..)) {
                        permit.send(packet);
                    }
                }
            }
""" + before)
    stack.write_text(source)
    Path("diagnostics/performance/src/netstack.rs").write_text(source)
if variant in ("wide", "both"):
    start = ip_src.index("        // We calculate the sum in native-endian")
    end = ip_src.index("\n    }", start)
    ip_src = ip_src[:start] + Path(__file__).with_name("checksum.rs.in").read_text().rstrip() + ip_src[end:]
ip.write_text(ip_src)
