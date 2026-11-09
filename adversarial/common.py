import base64,hashlib,json,os,subprocess,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as S
WT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEW=os.path.join(WT,"attest_verify.py")
PT="application/vnd.in-toto+json"; ST="https://in-toto.io/Statement/v1"
def pae(t,p):
    t=t.encode();return b"DSSEv1 %d %s %d %s"%(len(t),t,len(p),p)
class K:
    def __init__(s):
        s.priv=Ed25519PrivateKey.generate()
        s.pub=s.priv.public_key().public_bytes(S.Encoding.Raw,S.PublicFormat.Raw)
        s.id=hashlib.sha256(s.pub).hexdigest()
    def sign(s,m):return s.priv.sign(m)
def stmt(digs,n=1):
    sub=[{"name":"a/f%d"%i,"digest":d} for i,d in enumerate(digs)]
    return {"_type":ST,"subject":sub,"predicateType":"x","predicate":{}}
def env(st,signers,ptype=PT,kidlie=None):
    p=json.dumps(st).encode()
    sigs=[{"keyid":(kidlie or k.id),"sig":base64.b64encode(k.sign(pae(ptype,p))).decode()} for k in signers]
    return {"payloadType":ptype,"payload":base64.b64encode(p).decode(),"signatures":sigs}
def w(path,o):
    open(path,"w").write(json.dumps(o) if not isinstance(o,str) else o);return path
def keysfile(path,ks):
    w(path,{"keys":[{"public_key_hex":k.pub.hex()} for k in ks]});return path
def run(script,args):
    r=subprocess.run([sys.executable,script]+args,capture_output=True,text=True,cwd=WT)
    return r.returncode,r.stdout,r.stderr
def pol(envs,req,keys,art,extra=()):
    a=[]
    for r in req:a+=["--require-keyid",r]
    return run(NEW,a+["--artifact",art,"--key",keys]+list(extra)+list(envs))
