import glob,json,os,sys,hashlib
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from common import *
BASE=os.path.join(os.path.dirname(WT),"attest_verify_14.py")
same=0;n=0
for f in sorted(glob.glob(os.path.join(WT,"vectors","*.dsse.json"))):
    b=f[:-len(".dsse.json")];d=json.load(open(b+".expected.json"))
    key=d.get("key","vectors/test_key.pub.hex")
    pin=hashlib.sha256(bytes.fromhex(open(os.path.join(WT,key)).read().strip())).hexdigest()
    args=[os.path.relpath(f,WT),"--key",key,"--expect-keyid",pin]
    x=run(BASE,args);y=run(NEW,args);n+=1;ok=x==y;same+=ok
    print(os.path.basename(f)[:28].ljust(30),"rc",x[0],y[0],"IDENTICAL" if ok else "DIFF")
print("%d/%d identical"%(same,n));sys.exit(0 if same==n else 1)
