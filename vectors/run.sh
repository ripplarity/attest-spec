#!/usr/bin/env bash
# Runs every vector against attest_verify.py with a pinned keyid; prints N/N OK.
cd "$(dirname "$0")/.."
PY="${PYTHON:-python}"; ok=0; n=0
for f in vectors/*.dsse.json; do
  b="${f%.dsse.json}"; n=$((n+1))
  read -r want key < <($PY -c "import json,sys;d=json.load(open(sys.argv[1]));sys.stdout.buffer.write(('%s %s\n'%(d['exit_code'],d.get('key','vectors/test_key.pub.hex'))).encode())" "$b.expected.json")
  pin=$($PY -c "import hashlib,sys;sys.stdout.buffer.write(hashlib.sha256(bytes.fromhex(open(sys.argv[1]).read().strip())).hexdigest().encode())" "$key")
  $PY attest_verify.py "$f" --key "$key" --expect-keyid "$pin" >/dev/null 2>&1; rc=$?
  if [ "$rc" = "$want" ]; then ok=$((ok+1)); else echo "FAIL $f rc=$rc want=$want"; fi
done
echo "$ok/$n OK"; [ "$ok" = "$n" ]
