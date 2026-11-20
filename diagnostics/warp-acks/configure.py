"""Prepare the selected source or a controlled scheduling alternative."""
import subprocess
import sys
from pathlib import Path
mode = sys.argv[1]
if mode not in ("prior", "ack", "batch", "ack-batch"):
    sys.exit("unknown comparison")
root = Path("network-relay-cf-masque")
socket = root / "vendor/smoltcp/src/socket/tcp.rs"
stack = root / "crates/warp-egress/src/netstack.rs"
def git(path, ref):
    return subprocess.check_output(["git", "show", f"{ref}:{path}"], text=True)
def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(old)
    return text.replace(old, new)
ref = "9e7b465" if mode in ("prior","batch") else "HEAD"
socket.write_text(git(socket,ref))
s=git(stack,"HEAD")
if mode in ("batch","ack-batch"):
    s=once(s,"""        loop {
            if outgoing.is_closed()""","""        let mut input_batch = Vec::with_capacity(256);
        let mut output_batch = VecDeque::new();
        loop {
            if outgoing.is_closed()""")
    s=once(s,"            let (out, delay) = {","            let delay = {")
    s=once(s,"                let out: Vec<Bytes> = st.device.tx.drain(..).collect();","                std::mem::swap(&mut st.device.tx, &mut output_batch);")
    s=once(s,"""                let delay = iface.poll_delay(now, sockets).map_or(MAX_IDLE, |d| d.into()).min(MAX_IDLE);
                (out, delay)""","""                iface.poll_delay(now, sockets).map_or(MAX_IDLE, |d| d.into()).min(MAX_IDLE)""")
    s=once(s,"            for p in out {","            for p in output_batch.drain(..) {")
    a=s.index("                p = incoming.recv() => {")
    b=s.index("                _ = self.0.wake",a)
    s=s[:a]+'''                received = incoming.recv_many(&mut input_batch, 256) => {
                    if received == 0 {
                        self.fail("the packet input channel closed");
                        return;
                    }
                    self.lock().device.rx.extend(input_batch.drain(..));
                }
'''+s[b:]
stack.write_text(s)
Path("diagnostics/performance/src/netstack.rs").write_text(s)
