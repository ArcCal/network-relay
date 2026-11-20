"""Apply one bounded change to the exact checkout for an isolated comparison."""
import subprocess
import sys
from pathlib import Path
mode=sys.argv[1]
paths=["src/server/pump.rs","src/server/over_tcp.rs","src/server/h2_stream.rs","tests/in_process.rs"]
def exact(text,old,new):
    assert text.count(old)==1,old
    return text.replace(old,new)
for name in paths:
    source=subprocess.check_output(["git","show","HEAD:"+name],text=True)
    if name=="src/server/pump.rs" and mode=="copy-chunk":
        source=exact(source,"&mut target, CHUNK, CHUNK)","&mut target, 16 * 1024, 16 * 1024)")
    if name=="src/server/h2_stream.rs" and mode=="credit":
        old="send.stream.reserve_capacity(bytes.len().min(64 * 1024));"
        source=exact(source,old,'''if send.stream.capacity() < bytes.len().min(64 * 1024) {
            send.stream.reserve_capacity(bytes.len().min(64 * 1024));
        }''')
    if name=="src/server/over_tcp.rs" and mode=="peer-frames":
        old=".max_concurrent_streams(MAX_STREAMS_HTTP2)"
        source=exact(source,old,old+"\n            .max_frame_size(32 * 1024)")
    if name=="tests/in_process.rs":
        source+="\n"+Path(__file__).with_name("study.rs.in").read_text()
    Path(name).write_text(source)
