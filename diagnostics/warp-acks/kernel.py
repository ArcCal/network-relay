"""Configure only a fresh network namespace and pass its TUN device to the test."""
import fcntl,json,os,struct,subprocess,sys
from pathlib import Path
binary,mode,rtt,n,round_no,evidence=sys.argv[1:]
evidence=Path(evidence)
f=os.open("/dev/net/tun",os.O_RDWR|os.O_NONBLOCK)
name=fcntl.ioctl(f,0x400454CA,struct.pack("16sH",b"relaytest",0x1001)).split(b"\0",1)[0].decode()
subprocess.run(["ip","link","set","lo","up"],check=True)
subprocess.run(["ip","address","add","198.18.0.2/30","dev",name],check=True)
subprocess.run(["ip","link","set",name,"mtu","1280","up"],check=True)
if int(rtt):
    subprocess.run(["tc","qdisc","add","dev",name,"root","netem","delay",rtt+"ms","limit","4096"],check=True)
length=64<<20 if rtt=="0" and n=="1" else 8<<20
with (evidence/"transfers.jsonl").open("a") as out:
    subprocess.run([binary,n,str(length),mode,rtt],env=dict(os.environ,RELAY_TEST_TUN_FD=str(f)),pass_fds=(f,),stdout=out,check=True)
qdiscs=json.loads(subprocess.check_output(["tc","-s","-j","qdisc","show","dev",name]))
with (evidence/"qdiscs.jsonl").open("a") as out:
    print(json.dumps(dict(mode=mode,rtt=rtt,flows=n,round=round_no,qdiscs=qdiscs)),file=out)
assert all(q.get("drops",0)==0 for q in qdiscs),qdiscs
os.close(f)
