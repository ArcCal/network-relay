"""Compare bounded eviction using the same actual CF MASQUE DNS transport."""
import subprocess,sys
from pathlib import Path
path=Path("network-relay-cf-masque/crates/warp-egress/src/dns.rs")
s=subprocess.check_output(["git","show", f"{sys.argv[2] if len(sys.argv)>2 else 'HEAD'}:{path}"],text=True)
mode=sys.argv[1]
if mode=="original":
    s=s.replace("entries: IndexMap<QueryKey, Cached>","entries: HashMap<QueryKey, Cached>")
    s=s.replace("        entry.referenced = true;","")
    a=s.index("        if let Some(entry) = self.entries.get_mut(&key)");b=s.index("        self.entries.insert(key",a)
    s=s[:a]+"""        if self.entries.len() >= CACHE_SIZE {
            self.entries.retain(|_,entry| entry.expires>now);
            if self.entries.len() >= CACHE_SIZE {self.entries.clear();}
        }
"""+s[b:]
elif mode in ("earliest","rotate"):
    a=s.index("            // Give active answers");b=s.index("        }\n        self.entries.insert",a)
    mid="""            let index=self.entries.iter().enumerate().min_by_key(|(_,(_,e))|e.expires).unwrap().0;
            self.entries.swap_remove_index(index);
""" if mode=="earliest" else """            let index=self.hand;
            self.hand=(self.hand+1)%CACHE_SIZE;
            self.entries.swap_remove_index(index);
"""
    s=s[:a]+mid+s[b:]
elif mode!="selected":
    raise SystemExit("unknown policy")
a='                "echo.test" => answer(q, 0, false, &known, 120),'
assert s.count(a)==1
s=s.replace(a,'                name if name == "echo.test" || name.starts_with("known-") => answer(q, 0, false, &known, 120),')
anchor="    #[tokio::test]\n    async fn full_dns_cache_preserves"
assert s.count(anchor)==1
path.write_text(s.replace(anchor,Path("diagnostics/cf-dns-capacity/scenario.rs.in").read_text()+anchor))
