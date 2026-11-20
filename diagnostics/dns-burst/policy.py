"""Compile one candidate with identical normal VLESS and DNS message checks."""
import subprocess
import sys
from pathlib import Path

path = Path("network-relay-vless/src/dns.rs")
source = subprocess.check_output(["git", "show", f"{sys.argv[2] if len(sys.argv) > 2 else 'HEAD'}:{path}"], text=True)
mode = sys.argv[1]
if mode not in ("original", "global", "striped", "shared"):
    raise SystemExit("unknown policy")
if mode != "shared":
    source = source.replace("    cache: Mutex<DnsCache>,", "    cache: Mutex<DnsCache>,\n    gates: [tokio::sync::Mutex<()>; 32],", 1)
    source = source.replace("cache: Mutex::default(),", "cache: Mutex::default(), gates: Default::default(),", 1)
    start = source.index("        let pending = loop {")
    end = source.index("    async fn lookup_uncached", start)
    hit = """        if let Some(result) = self.cache.lock().unwrap().get(&name, Instant::now()) {
            return result.clone().map_err(|error| copy_error(&error));
        }
"""
    guard = ""
    if mode in ("global", "striped"):
        index = "0"
        if mode == "striped":
            guard = """        use std::hash::{DefaultHasher, Hash, Hasher};
        let mut hash = DefaultHasher::new();
        name.hash(&mut hash);
"""
            index = "hash.finish() as usize % self.gates.len()"
        guard += f"        let _held = self.gates[{index}].lock().await;\n" + hit
    source = source[:start] + hit + guard + "        self.lookup_uncached(&name, order).await\n    }\n\n" + source[end:]
anchor = "    #[tokio::test]\n    async fn a_full_cache_retains_active_names"
assert source.count(anchor) == 1
path.write_text(source.replace(anchor, Path("diagnostics/dns-burst/scenario.rs.in").read_text()+anchor))
