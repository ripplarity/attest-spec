# Ripplarity Attestation Format v1

Revision 1.1 (2026-11-08): added predicateType `dejaspawn/mirror/v1`; `nukekit/mirror/v1` is a deprecated alias, still accepted.

Revision 1.2 (2026-11-08): added predicateType `stillherd/day/v1` (daily attestation; subjects are the day's log files); specified Rekor anchoring and offline `--check-anchors` (exit 6).

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
- `dejaspawn/mirror/v1`, `stillherd/silent/v1`, `stillherd/day/v1` (documented only; see `docs/MIGRATION_nukekit_stillherd.md`). `nukekit/mirror/v1` is DEPRECATED (product renamed to dejaspawn); verifiers keep accepting it as a legacy URI.
An unknown predicateType is not an error: the verifier checks the signature, prints `VALID-SIGNATURE`,
warns, and exits 5.

## 7. Key pinning
A producer keyid is published in three independent places: (a) the producing repo's README;
(b) `https://ripplarity.com/.well-known/attestation-keys.json`, a `keys.json` (section 5) document
(publishing is a founder action, not yet done); (c) the key's first transparency-log entry (section 8).
A verifier trusts a key only if it matches one of these, obtained out of band from the envelope.
Verifiers MUST be given the trusted key (or its keyid, `--expect-keyid`) out of band; a key found beside the
artefact is untrusted unless it matches that pin. Re-signing a modified payload with a fresh key and shipping the
fresh public key alongside must fail verification.

## 8. Transparency-log anchoring (optional)
Digest: `sha256` of the canonical JSON (section 4 convention) of the envelope with the `anchors` key removed.
Entry: Rekor `hashedrekord` v0.0.1: `data.hash` = that digest, `signature.content` = ed25519 over the 32 raw digest
bytes, `publicKey` = producer key PEM. The returned entry is appended to `anchors[]` (top-level, outside the signed
bytes): `{type, url, uuid, logIndex, integratedTime, logID, body, signedEntryTimestamp, inclusionProof}`.
Offline check (`attest_verify.py --check-anchors`, exit 6 on failure; `NO-ANCHORS` and the signature rc if none):
(a) `body` digest equals the envelope digest and its signature verifies; (b) RFC 6962/9162 Merkle inclusion of
`sha256(0x00 || body)` under `rootHash` at `treeSize` (and the embedded checkpoint's size/root agree);
(c) the signedEntryTimestamp (ECDSA P-256 over canonical JSON of `{body, integratedTime, logID, logIndex}`) verifies
under a PINNED Rekor public key supplied with `--rekor-key` (default `rekor.pub` beside the verifier); the verifier
prints that key's sha256 and the pin MUST be compared with the value published by the Sigstore root of trust.
Pinned Rekor key sha256: NOT YET RECORDED (the key is fetched once, from the Sigstore TUF root, at the first real
anchor; no key is committed in this revision). The checkpoint's own log signature is not verified in this revision.
Rekor is contacted only for freshness when `--online` is given; that is NOT implemented (the flag is rejected).
Anchoring MUST be opt-in (`anchor.py --anchor rekor`, founder gate fq-193, env `ATTEST_ANCHOR_OK=1`), default OFF,
and publishes the digest permanently and irrevocably. See `docs/ANCHORING.md`.

## 9. Verifier exit codes
0 valid; 2 bad signature or unreadable envelope; 3 subject digest mismatch (`--check-subjects DIR`);
4 malformed statement or missing mandatory fields; 5 unknown predicateType (after `VALID-SIGNATURE`);
6 anchor failure (`--check-anchors`); 7 anchoring refused by the founder gate (`anchor.py`).

## 10. Threat model and non-goals
Detects: payload or signature tampering, subject file substitution (with `--check-subjects`), unknown-type
spoofing (flagged). Does not detect: a compromised producer key, a producer that lies in a signed predicate,
rollback or deletion of attestations (needs a log), time correctness (`started`/`ended` are self-reported
unless anchored). Non-goals: key revocation, encryption, a network protocol.

## 11. Test vectors
`vectors/` holds six vectors made with a committed TEST-ONLY key: three valid (one per implemented
predicateType), bad signature, mutated payload byte, unknown predicateType. `bash vectors/run.sh` prints `6/6 OK`.
