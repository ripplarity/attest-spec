# Migrating another writer to attest-spec v1

Reference writers: `sovkit/sovkit/attest.py` and `aiescrow/aiescrow/attest.py` (same `pae`, `jcs`, `make_envelope`).
Verifier: `tools/attest_verify.py` (byte-identical copy of this repo's `attest_verify.py`).

## Steps for any writer
1. Add an `attest.py` with `make_envelope(statement, priv)` (about 60 lines, stdlib + cryptography).
2. Payload bytes: RFC 8785 (JCS) canonical JSON of the Statement, UTF-8 (SPEC section 4). Only strings, integers,
   booleans, null, arrays and objects: convert floats to strings. If the writer used `ensure_ascii` or Python's
   `sort_keys` for payloads, replace it with the `jcs` function.
3. Sign `PAE = b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)` with `t = b"application/vnd.in-toto+json"`.
   The signature is base64. `keyid = sha256(raw_pub).hexdigest()`.
4. The predicate carries `producer{tool,version}`, `started`, `ended` (UTC `Z`), `environment{host_os,run_mode}`.
5. Subjects are POSIX relative paths with lowercase sha256 hex digests.
6. Emit `<name>.dsse.json` beside the existing output; keep any older signature file for one release.
7. Copy `attest_verify.py` into `tools/` byte-identical and add a test asserting its sha256 equals this repo's copy.
8. Print the tool's keyid from a `keyid` command so adopters can pin it.

## Predicate types
Use the predicateType URI listed for your tool in SPEC section 6; subjects are the files your tool already signs.

Acceptance for each: `python tools/attest_verify.py <out>.dsse.json --key <pub hex> --expect-keyid <keyid>` exits 0.
