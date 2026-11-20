"""Record socket and timer state across a local bulk pause without per-packet instrumentation."""
from pathlib import Path
import subprocess
import sys

kind = sys.argv[1]
if kind not in ("original", "reopen", "window", "defer"):
    sys.exit("unknown strategy")
root = Path("network-relay-cf-masque")
stack = root / "crates/warp-egress/src/netstack.rs"
tcp = root / "vendor/smoltcp/src/socket/tcp.rs"
fast = Path("diagnostics/performance/src/bin/fast.rs")
def source(path):
    ref = "d5bd2b7" if kind in ("reopen", "window") else "abe6d90"
    return subprocess.check_output(["git", "show", f"{ref}:{path}"], text=True)
def replace(s, a, b):
    assert s.count(a) == 1, a
    return s.replace(a, b)

t = source(tcp)
if kind == "reopen":
    t = replace(t, "let window_for_unsent_data = is_window_update", "let window_for_unsent_data = self.remote_win_len == 0 && is_window_update")
if len(sys.argv) > 2 and sys.argv[2] == "kernel":
    tcp.write_text(t)
    Path("diagnostics/performance/src/netstack.rs").write_text(source(stack))
    sys.exit(0)
pos = t.index("    /// Number of octets transmitted but not yet ACKed.")
t = t[:pos] + """    pub fn tail_diagnostics(&self) -> (&'static str, i64, usize, usize, usize, u16, u16, bool, bool) {
        let (timer, due) = match self.timer {
            Timer::Idle {keep_alive_at} => ("idle", keep_alive_at),
            Timer::FastRetransmit => ("fast-retransmit", None),
            Timer::Retransmit {expires_at} => ("retransmit", Some(expires_at)),
            Timer::ZeroWindowProbe {expires_at, ..} => ("zero-window", Some(expires_at)),
            Timer::Close {expires_at} => ("close", Some(expires_at)),
        };
        let flight = if self.remote_last_seq >= self.local_seq_no { self.remote_last_seq - self.local_seq_no } else { 0 };
        (timer, due.map_or(-1, |t| t.total_millis() - Instant::now().total_millis()),
         self.remote_win_len, self.congestion_controller.inner().window(), flight,
         self.scaled_window(), self.last_scaled_window().unwrap_or(0), self.window_to_update(), self.ack_to_transmit())
    }

""" + t[pos:]
tcp.write_text(t)
s = source(stack)
s = replace(s, "    pub queued_bytes: usize,", "    pub queued_bytes: usize,\n    pub tcp: (&'static str, i64, usize, usize, usize, u16, u16, bool, bool),")
s = replace(s, "queued_bytes: socket.send_queue(),", "queued_bytes: socket.send_queue(),\n                    tcp: socket.tail_diagnostics(),")
Path("diagnostics/performance/src/netstack.rs").write_text(s)
b = fast.read_text()
b = replace(b, "    rss_peak_kib_sampled: u64,", "    rss_peak_kib_sampled: u64,\n    #[serde(skip)]\n    clock: Option<Instant>,\n    states: Vec<serde_json::Value>,")
b = replace(b, "    stats.samples += 1;", """    stats.samples += 1;
    let elapsed = stats.clock.get_or_insert_with(Instant::now).elapsed();
    if stats.samples % 3 == 0 && elapsed < Duration::from_millis(1700) {
        stats.states.push(serde_json::json!([elapsed.as_millis(), a.tcp_snapshot(), b.tcp_snapshot()]));
    }""")
# The controlled reader holds its last 320 KiB briefly. The receive buffer
# can then fill while the sender has already queued the entire response.
b = replace(b, "async fn receive_eof(stream: &mut TcpStream)", "async fn receive_eof(stream: &mut TcpStream, controlled: bool)")
b = replace(b, "receive_eof(&mut peer)", "receive_eof(&mut peer, false)")
b = replace(b, "receive_eof(&mut client)", 'receive_eof(&mut client, std::env::var_os("RELAY_CONTROLLED_READER").is_some())')
b = replace(b, "        let n = stream.read(&mut chunk).await?;", """        let boundary = PAYLOAD_LEN - (320 << 10);
        let maximum = if controlled && bytes < boundary { (boundary - bytes).min(chunk.len()) } else { chunk.len() };
        if controlled && bytes == boundary { tokio::time::sleep(Duration::from_millis(80)).await; }
        let n = stream.read(&mut chunk[..maximum]).await?;""")
if kind == "defer":
    b = replace(b, "    let server = tokio::spawn", "    let drain_stack = b.clone();\n    let server = tokio::spawn")
    b = replace(b, "        peer.shutdown().await?;", """        let start_wait = Instant::now();
        while drain_stack.tcp_snapshot().iter().any(|s| s.queued_bytes != 0) && start_wait.elapsed() < Duration::from_secs(2) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        peer.shutdown().await?;""")
Path("diagnostics/performance/src/bin/tail.rs").write_text(b)
