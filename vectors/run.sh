#!/usr/bin/env bash
# Runs every vector against attest_verify.py; prints N/N OK.
cd "$(dirname "$0")/.."
PY="${PYTHON:-python}"; ok=0; n=0
for f in vectors/*.dsse.json; do
  b="${f%.dsse.json}"; n=$((n+1))
  $PY attest_verify.py "$f" --key vectors/test_key.pub.hex >/dev/null 2>&1; rc=$?
  want=$($PY -c "import json,sys;print(json.load(open(sys.argv[1]))['exit_code'])" "$b.expected.json")
  if [ "$rc" = "$want" ]; then ok=$((ok+1)); else echo "FAIL $f rc=$rc want=$want"; fi
done
echo "$ok/$n OK"; [ "$ok" = "$n" ]
