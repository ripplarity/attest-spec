# Ripplarity Attestation Format v1

License: CC-BY-4.0 (spec), Apache-2.0 (code). Status: draft. Terminology: the signed statement is an
**attestation**. A **receipt** means a transparency-log inclusion proof only.

## 1. Envelope
DSSE envelope, JSON: `{"payloadType": "application/vnd.in-toto+json", "payload": <base64>,
"signatures": [{"keyid": <hex>, "sig": <base64>}]}`. `sig` is ed25519 over the DSSE PAE (section 2).
Files are named `*.dsse.json` and sit beside the artefact they attest.

## 2. Pre-Authentication Encoding
`PAE = "DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload`.
Lengths are decimal ASCII; `payload` is the raw bytes (the base64-decoded `payload` field, not the base64 text).

## 3. Statement
The payload is an in-toto Statement v1: `_type` = `https://in-toto.io/Statement/v1`;
`subject` = `[{"name": <file name>, "digest": {"sha256": <lowercase hex>}}]` (at least one);
`predicateType` (URI, section 6); `predicate` (object).

## 4. Canonicalisation
DSSE signs bytes, so verifiers MUST NOT re-serialise the payload: they decode, verify, then parse.
Writers produce the payload bytes once, as
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")`.
`ensure_ascii=True` is mandatory (a previous writer used `False`; bytes differed across tools).

## 5. Keys and keyid
Signatures are ed25519. `keyid` = lowercase hex sha256 of the raw 32-byte public key. Verifiers take a raw hex
public key or a `keys.json` of the form `{"keys": [{"keyid": ..., "public_key_hex": ..., "label": ...}]}`
and select the signature whose `keyid` matches.

## 6. Predicates
Mandatory in every predicate: `producer{tool, version}`, `started`, `ended` (UTC ISO-8601 ending in `Z`),
`environment{host_os, run_mode}` where `run_mode` is `REAL`, `MOCK`, `FIXTURE` or `DRY-RUN`.
Domain fields are added beside these. predicateTypes (base `https://ripplarity.com/attestation/`):
- `sovkit/inventory/v1`, `sovkit/drill/v1`, `aiescrow/manifest/v1` (implemented).
- `nukekit/mirror/v1`, `stillherd/silent/v1` (documented only; see `docs/MIGRATION_nukekit_stillherd.md`).
An unknown predicateType is not an error: the verifier checks the signature, prints `VALID-SIGNATURE`,
warns, and exits 5.

## 7. Key pinning
A producer keyid is published in three independent places: (a) the producing repo's README;
(b) `https://ripplarity.com/.well-known/attestation-keys.json`, a `keys.json` (section 5) document
(publishing is a founder action, not yet done); (c) the key's first transparency-log entry (section 8).
A verifier trusts a key only if it matches one of these, obtained out of band from the envelope.

## 8. Transparency-log anchoring (optional)
A Rekor `hashedrekord` entry over the sha256 of the DSSE envelope file; the inclusion proof is embedded in the
envelope as `anchors[]` (an extra top-level array, outside the signed bytes). Verification uses the embedded
proof offline. Anchoring MUST be opt-in (`--anchor rekor`), default OFF. Anchoring publishes the digest
permanently and irrevocably. This specification only describes it; see `docs/ANCHORING.md`.

## 9. Verifier exit codes
0 valid; 2 bad signature or unreadable envelope; 3 subject digest mismatch (`--check-subjects DIR`);
4 malformed statement or missing mandatory fields; 5 unknown predicateType (after `VALID-SIGNATURE`).

## 10. Threat model and non-goals
Detects: payload or signature tampering, subject file substitution (with `--check-subjects`), unknown-type
spoofing (flagged). Does not detect: a compromised producer key, a producer that lies in a signed predicate,
rollback or deletion of attestations (needs a log), time correctness (`started`/`ended` are self-reported
unless anchored). Non-goals: key revocation, encryption, a network protocol.

## 11. Test vectors
`vectors/` holds six vectors made with a committed TEST-ONLY key: three valid (one per implemented
predicateType), bad signature, mutated payload byte, unknown predicateType. `bash vectors/run.sh` prints `6/6 OK`.
