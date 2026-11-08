# Migration: nukekit and Stillherd writers to attest-spec v1

Owned by another session; nothing here has been applied. Reference writers: `sovkit/sovkit/attest.py`,
`aiescrow/aiescrow/attest.py` (identical `pae`, `canonical`, `make_envelope`). Verifier: `tools/attest_verify.py`.

## Both writers
1. Add an `attest.py` copy of `make_envelope(statement, priv)` (about 40 lines, stdlib + cryptography).
2. Canonical payload: `json.dumps(stmt, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")`.
   If the writer uses `ensure_ascii=False` anywhere, change it: that is the verified drift bug.
3. Sign `PAE = b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)` with `t = b"application/vnd.in-toto+json"`.
   Signature is base64 (not hex). `keyid = sha256(raw_pub).hexdigest()`.
4. Predicate must carry `producer{tool,version}`, `started`, `ended` (UTC `Z`), `environment{host_os,run_mode}`.
5. Emit `<name>.dsse.json` beside the existing output; keep the old signature file for one release.
6. Copy `attest_verify.py` into `tools/` byte-identical and add a test asserting its sha256 equals the spec repo's.

## nukekit (predicateType `https://ripplarity.com/attestation/nukekit/mirror/v1`)
- Subject: the mirror receipt/manifest file the writer already signs (name = file name, digest = sha256 of its bytes).
- Predicate: existing receipt fields plus the mandatory block; `run_mode` = `MOCK` for fixture mirrors, `REAL` otherwise.
- Diff-level: replace the `sign(canonical(receipt))` call with
  `write(path + ".dsse.json", make_envelope(statement(receipt_file, predicate), key))`.

## Stillherd (predicateType `https://ripplarity.com/attestation/stillherd/silent/v1`)
- Subject: the silent-run report file. Predicate: report fields plus the mandatory block; `DRY-RUN` for dry runs.
- Same replacement as nukekit; rename user-facing "receipt" to "attestation" in new text only.

Acceptance for each: `python tools/attest_verify.py <out>.dsse.json --key <pub hex>` exits 0 on its own output.
