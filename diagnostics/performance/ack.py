"""Build a diagnostic observation and one receipt-compatible ACK policy."""
import subprocess
import sys
from pathlib import Path

root=Path.cwd()
mode=sys.argv[1]
def from_git(path): return subprocess.check_output(["git","show","HEAD:"+path],text=True)
def once(s,old,new):
    if s.count(old)!=1: raise ValueError("Production anchor changed: "+old)
    return s.replace(old,new)

sock="network-relay-cf-masque/vendor/smoltcp/src/socket/tcp.rs"
tcp=from_git(sock)
marker="    /// Return whether to send ACK immediately due to the amount of unacknowledged data."
tcp=once(tcp,marker,'''    /// Numeric-only observations of the benchmark connection.
    pub fn study_credit(&self) -> [usize; 4] {
        [self.flight_size(), self.congestion_controller.inner().window(), self.remote_win_len, self.send_queue()]
    }

'''+marker)
stack=from_git("network-relay-cf-masque/crates/warp-egress/src/netstack.rs")
stack=once(stack,"    pub queued_bytes: usize,", "    pub queued_bytes: usize,\n    pub study: [usize; 4],")
stack=once(stack,"                    queued_bytes: socket.send_queue(),","                    queued_bytes: socket.send_queue(),\n                    study: socket.study_credit(),")
if mode=="smaller-ingress":
    stack=once(stack,"for _ in 0..255 {","for _ in 0..1 {")
elif mode=="interleave":
    line="                iface.poll(now, device, sockets);"
    stack=once(stack,line,'''                iface.poll_maintenance(now);
                let mut received = 0;
                while !device.rx.is_empty() {
                    iface.poll_ingress_single(now, device, sockets);
                    received += 1;
                    if received % 2 == 0 { iface.poll_egress(now, device, sockets); }
                }
                while iface.poll_egress(now, device, sockets) != smoltcp::iface::PollResult::None {}
''')
elif mode=="socket-ack":
    line="        if !self.assembler.is_empty() || !assembler_was_empty {"
    tcp=once(tcp,line,'''        if !repr.payload.is_empty() && self.immediate_ack_to_transmit() {
            self.ack_delay_timer = AckDelayTimer::Idle;
            return Some(self.ack_reply(ip_repr, repr));
        }
'''+line)
elif mode!="original":
    raise ValueError(mode)
Path(sock).write_text(tcp)
Path('diagnostics/performance/src/netstack.rs').write_text(stack)
