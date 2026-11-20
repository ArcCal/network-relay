from pathlib import Path
p=Path("network-relay-rs/src/controller.rs")
s=p.read_text()
anchor="    #[test]\n    fn retention_prioritizes_operational_records()"
assert s.count(anchor)==1
p.write_text(s.replace(anchor,Path("diagnostics/rs-log/scenario.rs.in").read_text()+"\n"+anchor))
