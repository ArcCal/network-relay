"""Install one measured cache policy in a disposable checkout of the production resolver."""
import os
from pathlib import Path
import subprocess
import sys

base = Path(__file__).resolve().parent
root = base.parent.parent
source = Path("network-relay-vless/src/dns.rs")
manifest = Path("network-relay-vless/Cargo.toml")

def original(p):
    return subprocess.check_output(["git", "-C", root, "show", "HEAD:" + p.as_posix()], text=True)

def once(source, before, after):
    if source.count(before) != 1:
        raise ValueError("Unexpected production source anchor: " + before)
    return source.replace(before, after)

def candidate(mode):
    s, m = original(source), original(manifest)
    begin = s.index("        if cache.len() >= CACHE_ENTRIES {")
    end = s.index("\n    }", begin)
    if mode == "expiry":
        s = s[:begin] + '''        if cache.len() >= CACHE_ENTRIES && !cache.contains_key(&name) {
            let earliest = cache.iter().min_by_key(|(_, (_, expires))| *expires).map(|(key, _)| key.clone());
            if let Some(key) = earliest { cache.remove(&key); }
        }
        cache.insert(name, (result, now + ttl.min(MAX_TTL)));''' + s[end:]
    elif mode in ("rotating", "clock"):
        s = s[:begin] + '''        cache.insert(name, (result, now + ttl.min(MAX_TTL)));''' + s[end:]
        s = once(s, "use std::collections::HashMap;", "use indexmap::IndexMap;")
        m = once(m, "[dependencies]", '[dependencies]\nindexmap = "2"')
        s = once(s, "cache: Mutex<HashMap<String, (Lookup, Instant)>>", "cache: Mutex<DnsCache>")
        support = (base/"cache.rs.in").read_text()
        if mode == "rotating":
            support = support.replace("((Lookup, Instant), bool)", "(Lookup, Instant)")
            support = support[:support.index("        self.entries.get_mut(name)")] + "        self.entries.get(name)\n" + support[support.index("    }\n\n    fn insert"):]
            support = support.replace("(value, false)", "value")
            a = support.index("            while let Some"); b = support.index("            self.entries.swap_remove_index", a)
            support = support[:a]+support[b:]
        s = once(s, "struct LookupOrder {", support + "\nstruct LookupOrder {")
    elif mode != "original":
        raise ValueError(mode)
    return s,m

if __name__ == "__main__":
    mode = sys.argv[1]
    s,m = candidate(mode)
    if os.environ.get('RELAY_STUDY_TEST') == '1':
        a = s.index("    #[tokio::test]\n    async fn silent_resolvers_cache_failure_at_the_relay_deadline")
        s = s[:a] + (base/"scenario.rs.in").read_text() + s[a:]
    (root/source).write_text(s)
    (root/manifest).write_text(m)
