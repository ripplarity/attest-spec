import base64,copy,hashlib,itertools,json,os,random,sys,tempfile
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from common import *
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
N=int(sys.argv[1]) if len(sys.argv)>1 else 2500
seed=int(sys.argv[2]) if len(sys.argv)>2 else 1
random.seed(seed);T=tempfile.mkdtemp()
art=w(os.path.join(T,"art"),"hello");h=hashlib.sha256(b"hello").hexdigest();h2=hashlib.sha256(b"z").hexdigest()
M,C,X=K(),K(),K();ks=[M,C];keys=keysfile(os.path.join(T,"k.json"),ks)
by={k.id:k.pub for k in ks}
S=stmt([{"sha256":h}]);Sb=stmt([{"sha256":h2}])
def model(texts,req):
    """independent invariant over raw file texts"""
    if len(req)<2 or len(set(req))!=len(req) or any(r not in by for r in req):return False
    sets=[]
    for t in texts:
        try:
            e=json.loads(t)
            if e["payloadType"]!=PT:return False
            p=base64.b64decode(e["payload"],validate=True)
            sg=e["signatures"]
            if not isinstance(sg,list) or not sg:return False
            sset=set()
            for s in sg:
                pub=by.get(s["keyid"])
                if pub is None:return False
                try:Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(s["sig"],validate=True),pae(PT,p))
                except Exception:return False
                sset.add(s["keyid"])
            st=json.loads(p)
            if st["_type"]!=ST or not st["subject"]:return False
            ds=set(x["digest"]["sha256"] for x in st["subject"])
            sets.append((sset,ds))
        except Exception:return False
    if any(h not in d for _,d in sets):return False
    return any(all(req[i] in sets[j][0] for i,j in enumerate(pm)) for pm in itertools.permutations(range(len(sets)),len(req)))
def base():
    pool=[env(S,[M]),env(S,[C]),env(S,[M,C]),env(Sb,[C]),env(S,[X]),env(S,[C],kidlie=M.id)]
    return [copy.deepcopy(random.choice(pool)) for _ in range(random.randint(1,4))]
def flip(t):
    b=bytearray(t.encode());
    for _ in range(random.randint(1,2)):
        i=random.randrange(len(b));b[i]^=1<<random.randrange(7)
    return b.decode("utf-8","replace")
acc=0;fa=0;fr=0
for it in range(N):
    envs=base()
    for _ in range(random.randint(0,3)):
        op=random.choice(["drop","dup","reorder","swapkeyid","swapsig","flipjson","payloadflip","none","none"])
        if op=="drop" and envs:envs.pop(random.randrange(len(envs)))
        elif op=="dup" and envs:envs.append(copy.deepcopy(random.choice(envs)))
        elif op=="reorder":random.shuffle(envs)
        elif op=="swapkeyid" and envs:
            e=random.choice(envs)
            if isinstance(e,str):continue
            s=random.choice(e["signatures"]) if e["signatures"] else None
            if s:s["keyid"]=random.choice([M.id,C.id,X.id,M.id.upper()])
        elif op=="swapsig" and len(envs)>1:
            a,b=random.sample(envs,2)
            if isinstance(a,str) or isinstance(b,str):continue
            if a["signatures"] and b["signatures"]:a["signatures"][0]["sig"]=b["signatures"][0]["sig"]
        elif op=="flipjson" and envs:
            i=random.randrange(len(envs));envs[i]=flip(json.dumps(envs[i]))
        elif op=="payloadflip" and envs:
            e=random.choice(envs)
            if isinstance(e,dict):
                p=bytearray(base64.b64decode(e["payload"]));p[random.randrange(len(p))]^=1;e["payload"]=base64.b64encode(bytes(p)).decode()
    texts=[e if isinstance(e,str) else json.dumps(e) for e in envs]
    r=random.choice([[M.id,C.id],[C.id,M.id],[M.id,C.id],[M.id,M.id],[M.id,X.id],[M.id]])
    paths=[w(os.path.join(T,"e%d"%i),t) for i,t in enumerate(texts)]
    if not paths:continue
    rc=pol(paths,r,keys,art)[0]
    want=model(texts,r)
    if rc==0:acc+=1
    if rc==0 and not want:fa+=1;print("FALSE ACCEPT it",it,texts[:2])
    if rc!=0 and want:fr+=1;print("FALSE REJECT it",it,rc)
print("iterations",N,"accepts",acc,"false_accepts",fa,"false_rejects",fr);sys.exit(1 if fa else 0)
