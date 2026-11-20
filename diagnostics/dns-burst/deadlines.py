"""Compare two deadline-isolation policies and per-resolver transactions with whole-lookup sharing."""
from pathlib import Path
import subprocess
import sys

mode = sys.argv[1]
if mode not in ("whole", "independent", "deadline", "resolver"):
    raise SystemExit("unexpected experiment")
path = Path("network-relay-vless/src/dns.rs")
ref = "HEAD" if mode == "resolver" else "c4cff72"
source = subprocess.check_output(["git", "show", f"{ref}:{path}"], text=True)
if mode == "independent":
    before = "        let pending = loop {"
    source = source.replace(before, """        if self.config.dns_servers.len() > 1 {
            if let Some(answer) = self.cache.lock().unwrap().get(&name, Instant::now()) {
                return answer.clone().map_err(|error| copy_error(&error));
            }
            return self.lookup_uncached(&name, order).await;
        }
""" + before, 1)
if mode == "deadline":
    before = "        let pending = loop {"
    source = source.replace(before, '        let flight_name = format!("{name}/{:?}", order.deadline);\n' + before, 1)
    source = source.replace("cache.pending.get(&name)", "cache.pending.get(&flight_name)")
    source = source.replace("cache.pending.insert(name.clone(),", "cache.pending.insert(flight_name.clone(),")
    source = source.replace("cache: &self.cache, name: Some(&name)", "cache: &self.cache, name: Some(&flight_name)")
anchor = "    #[tokio::test]\n    async fn a_full_cache_retains_active_names"
assert source.count(anchor) == 1
scenario = Path(__file__).with_name("scenario.rs.in").read_text().replace("delayed_peer(1,", "delayed_peer(2,")
scenario += Path(__file__).with_name("budget.rs.in").read_text()
path.write_text(source.replace(anchor, scenario + anchor))
