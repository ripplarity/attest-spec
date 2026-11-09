# Ripplarity Attestation Format v1

Revision 1.5 (2026-11-09): (1) a draft verdict predicateType with its own checker `verdict_check.py` (section 6.1;
vectors 11-14); the verifier stays generic; (2) an optional multi-signer policy, `--require-keyid` repeated (section
12). Compatibility: nothing about envelopes, payloads or single-key verification changed; every attestation a 1.4
verifier accepts, a 1.5 verifier accepts with the same exit code.
Revision 1.4 (2026-11-09): (1) the Rekor entry digest is SHA-512 of JCS(envelope minus `anchors`), signed as Ed25519ph
(Rekor rejects an ed25519 hashedrekord with any other hash; section 8), and the Rekor key sha256 is pinned; (2) keys and
R MUST be prime-order ([L]A = O), with the cofactorless equation stated (section 5); (3) five predicateTypes added
(section 6). Compatibility: a 1.4 verifier accepts every attestation a 1.3 verifier accepted whose keys are prime-order,
which is every key from standard ed25519 key generation; a key with a torsion component was already outside any
conforming producer. Subject digests stay sha256. No 1.3-style (sha256) anchor was ever published (the live log rejected
it), so no anchor is invalidated. 1.3 attestations verify unchanged under 1.4; nothing about envelopes or payloads changed.
Revision 1.3 (2026-11-08): canonicalisation is RFC 8785 (JCS) with a restricted type set; ed25519 verification is
strict RFC 8032; the verifier REQUIRES a pinned keyid; ambiguities resolved (keyids, multiple signatures, subject
names, failure precedence); anchoring digest defined over JCS; internal process text removed.
Revision 1.2: added a daily-log predicateType (section 6); Rekor anchoring and offline `--check-anchors`.
Revision 1.1: added a mirror predicateType; its earlier URI is a deprecated alias, still accepted (section 6).

License: CC-BY-4.0 for this specification (`LICENSE-SPEC`), Apache-2.0 for code (`LICENSE`). Status: draft.
Terminology: the signed statement is an **attestation**. A **receipt** means a transparency-log inclusion proof only.

## 1. Envelope
DSSE envelope, JSON: `{"payloadType": "application/vnd.in-toto+json", "payload": <base64>,
"signatures": [{"keyid": <hex>, "sig": <base64>}]}`. `payloadType` MUST equal exactly
`application/vnd.in-toto+json`. `sig` is ed25519 over the DSSE PAE (section 2). Files are named `*.dsse.json`
and sit beside the artefact they attest. Unknown top-level envelope keys are ignored by verifiers, except that
they are part of the anchoring digest (section 8).

## 2. Pre-Authentication Encoding
`PAE = "DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload`.
Lengths are the decimal ASCII **byte length** of the UTF-8 bytes; `payload` is the raw bytes (the base64-decoded
`payload` field, not the base64 text).

## 3. Statement
The payload is an in-toto Statement v1: `_type` = `https://in-toto.io/Statement/v1`;
`subject` = `[{"name": <name>, "digest": {"sha256": <lowercase hex>}}]` (at least one);
`predicateType` (URI, section 6); `predicate` (object). A subject `name` is a POSIX relative path using `/`: it
MUST NOT be empty, start with `/`, contain `\`, or contain an empty, `.` or `..` segment. The sha256 digest MUST be
64 lowercase hex characters. `--check-subjects DIR` resolves each name relative to `DIR`.

## 4. Canonicalisation
The payload bytes are produced ONCE by the writer as RFC 8785 (JCS) canonical JSON, UTF-8, and verifiers MUST NOT
re-serialise them: they decode, verify, then parse. Payloads MUST contain only strings, integers (absolute value at
most 2^53-1), booleans, null, arrays and objects. Floats, NaN and Infinity are forbidden; encode such values as
strings. Object members are sorted by UTF-16 code units of the key (JCS rule); strings use JCS escaping (only `"`,
`\` and control characters are escaped) and MUST NOT contain lone surrogates.

## 5. Keys, keyid and signature strictness
Signatures are ed25519 per RFC 8032. Verifiers MUST reject: a signature whose scalar S is not canonical (S >= L,
L = 2^252 + 27742317777372353535851937790883648493); a public key or R that is not a canonical on-curve encoding
(y >= 2^255-19, or no square root); a public key or R of small order (the 8-torsion points); and a public key or R
that is not of prime order, that is [L]P != O (a torsion component). The accepted equation is the cofactorless one:
[S]B = R + [k]A with k = SHA-512(R || A || M) mod L, checked on the encoded R. These checks are performed explicitly
before the library verification call.
`keyid` = lowercase hex sha256 of the raw 32-byte public key. The envelope `keyid` is authoritative for selecting
the key and MUST equal the sha256 of the raw key it selects. Verifiers take a raw hex public key or a `keys.json`
of the form `{"keys": [{"keyid": ..., "public_key_hex": ..., "label": ...}]}`.
With several `signatures`, ALL present entries MUST verify under a supplied key and AT LEAST ONE MUST carry the
pinned keyid (section 7); an entry whose keyid is not among the supplied keys makes verification fail.

## 6. Predicates
Mandatory in every predicate: `producer{tool, version}`, `started`, `ended` (UTC ISO-8601 ending in `Z`),
`environment{host_os, run_mode}` where `run_mode` is `REAL`, `MOCK`, `FIXTURE` or `DRY-RUN`.
Domain fields are added beside these. predicateTypes (base `https://ripplarity.com/attestation/`):
- `sovkit/inventory/v1`, `sovkit/drill/v1`, `aiescrow/manifest/v1` (implemented).
- `dejaspawn/mirror/v1`, `stillherd/silent/v1`, `stillherd/day/v1` (documented only; see `docs/MIGRATION_other_writers.md`).
  `nukekit/mirror/v1` is DEPRECATED (renamed to dejaspawn); verifiers keep accepting it as a legacy URI.
- Added in 1.4: `dejaspawn/evidence/v1`, `mictest/participant/v1`, `halflife/receipt/v1`,
  `canceltogether/campaign/v1`, `buyatheorem/lemma/v1`.
- Full-URI entries (producers under their own domain): `https://udoot.com/attestation/egress/v1` (Android
  network-egress receipts; subject `netlog.jsonl`). A predicateType need not sit under the ripplarity base.
- Added in 1.5 (draft): `verdict/v1` (section 6.1).
An unknown predicateType is not an error: the verifier checks the signature, prints `VALID-SIGNATURE`,
warns, and exits 5.

### 6.1 `verdict/v1`: the signed result of probing a software claim
URI: `https://ripplarity.com/attestation/verdict/v1`. The mandatory fields above apply, plus these predicate
fields (all REQUIRED unless marked optional). `verdict_check.py` implements them; `attest_verify.py` does not call it.
- `claim{text, source_url?}`: `text` non-empty; `source_url`, if present, an http(s) URL.
- `subject_tool{name, version}`: the tool probed; both non-empty strings.
- `probe{id, version, sha256}`: `sha256` is the lowercase-hex SHA-256 of the probe code that ran.
- `inputs_digest`, `transcript_digest`: lowercase-hex SHA-256 (64 chars) of the probe inputs and of the run transcript.
- `controls`: a non-empty list of `{name, kind, expected, observed}`; `kind` is `positive` or `negative`.
- `result`: exactly `PASS`, `FAIL` or `INCONCLUSIVE` (case-sensitive).
- `observed_at`: RFC3339 UTC timestamp ending in `Z` (no numeric offsets).
Normative:
1. `controls` MUST contain at least one `positive` control (an input the claim says works, run through the same
   probe, showing the probe can see success).
2. For EVERY control, `observed` MUST equal `expected` in both JSON type and value (the string "1" does not
   equal the number 1). A correctly signed record with a failed control is VALID as a record and NOT ACCEPTED as
   a verdict. A producer with a failed control MAY sign `INCONCLUSIVE` with the controls recorded as observed;
   verifiers keep it as evidence and `verdict_check.py` exits 8 (VERDICT-NOT-TRUSTED). The same exit 8 applies
   to a missing positive control, to `PASS` or `FAIL` with a failed control, and to rule 4.
3. A verdict whose shape is broken (`result` outside the enum, bad digests, non-UTC timestamp, absent or
   malformed `controls`) is malformed: `verdict_check.py` exits 4. Exit 0 means accepted and prints
   `VERDICT-ACCEPTED result=<PASS|FAIL|INCONCLUSIVE>`: accepted means the record can be trusted, not that the
   claim passed. Timestamps and digests use ASCII digits only (`[0-9]`, never a Unicode digit class). Control
   values compare equal only with the same JSON type at every nesting level.
4. The transcript file MUST be a statement subject: `transcript_digest` MUST equal the sha256 of one subject,
   else exit 8.
5. `attest_verify.py` only registers the URI (signature, subject and mandatory-field checks); the domain rules
   above run only in `python verdict_check.py <envelope> --key KEYS --expect-keyid KEYID`.
6. Trust requires `attest_verify.py` exit 0 on the same envelope with the same pinned keyid. `verdict_check.py`
   accepts only a DSSE envelope and runs that verification first; it returns attest_verify's code (2, 3, 4 or 5)
   when that is not 0, so an unsigned statement or a tampered signature is never accepted.
Example predicate (shown without the mandatory fields):
```json
{"claim":{"text":"tool X rejects empty input","source_url":"https://example.com/claim"},
 "subject_tool":{"name":"example-tool","version":"1.0.0"},
 "probe":{"id":"empty-input","version":"1","sha256":"<64 hex>"},
 "inputs_digest":"<64 hex>","transcript_digest":"<64 hex>","result":"PASS",
 "controls":[{"name":"known-good input accepted","kind":"positive","expected":"accept","observed":"accept"},
             {"name":"known-bad input rejected","kind":"negative","expected":"reject","observed":"reject"}],
 "observed_at":"2026-01-01T00:00:00Z"}
```
Vectors 11 (valid), 12 (FAIL with failed control), 13 (INCONCLUSIVE with failed control), 14 (PASS with failed
control): `attest_verify.py` exits 0 on all four; `verdict_check.py` exits 0, 8, 8, 8.

## 7. Key pinning
Verifiers MUST be given the trusted key (or its keyid, `--expect-keyid`) out of band; a key found beside the
artefact is untrusted unless it matches that pin. `attest_verify.py` REQUIRES `--expect-keyid` and exits 2 with
"pinned keyid required (SPEC s7)" without it. Re-signing a modified payload with a fresh key and shipping the
fresh public key alongside MUST fail verification. A producer publishes its keyid in three independent places:
(a) the producing repo's README; (b) `https://<producer-domain>/.well-known/attestation-keys.json`, a `keys.json`
(section 5) document; (c) the key's first transparency-log entry (section 8).
No Ripplarity keyid is published yet; each adopter publishes its own.

## 8. Transparency-log anchoring (optional)
Digest: `sha512(JCS(envelope minus the "anchors" key))`; unknown top-level envelope keys ARE included. Subject
digests (section 3) stay sha256.
Entry: Rekor `hashedrekord` v0.0.1: `data.hash` = `{algorithm: sha512, value: <that digest hex>}`, `signature.content` =
Ed25519ph (RFC 8032, empty context) with PH(M) equal to that digest, `publicKey` = producer key PEM. The returned entry is appended to `anchors[]` (top-level, outside the signed
bytes): `{type, url, uuid, logIndex, integratedTime, logID, body, signedEntryTimestamp, inclusionProof}`.
Offline check (`attest_verify.py --check-anchors`, exit 6 on failure; `NO-ANCHORS` is printed and the prior exit
code is kept if there are none):
(a) `body` digest (sha512) equals the envelope digest and its Ed25519ph signature verifies; (b) RFC 6962/9162 Merkle inclusion of
`sha256(0x00 || body)` under `rootHash` at `treeSize` (and the embedded checkpoint's size/root agree);
(c) the signedEntryTimestamp (ECDSA P-256 over canonical JSON of `{body, integratedTime, logID, logIndex}`) verifies
under a PINNED Rekor public key supplied with `--rekor-key` (default `rekor.pub` beside the verifier); the verifier
prints that key's sha256 and the pin MUST be compared with the value published by the Sigstore root of trust.
Pinned Rekor key sha256: `dce5ef715502ec9f3cdfd11f8cc384b31a6141023d3e7595e9908a81cb6241bd` (`rekor.pub`, fetched from
the Rekor public-key endpoint; not yet cross-checked against the Sigstore TUF root). With the default `rekor.pub` the
verifier enforces this sha256; an explicit `--rekor-key` is trusted as given and its sha256 is printed. The checkpoint's own log
signature is not verified in this revision. Rekor is contacted only for freshness when `--online` is given; that is
NOT implemented (the flag is rejected). Anchoring MUST be opt-in (`anchor.py --anchor rekor`, requires explicit
maintainer approval: set `ATTEST_ANCHOR_OK=1`), default OFF, and publishes the digest permanently and irrevocably.
Live Rekor ACCEPTED this entry format on 2026-11-09 (one approved anchor, log index 3768163947; the offline `--check-anchors` verification of that entry against the pinned Rekor key passed). See `docs/ANCHORING.md`.

## 9. Verifier exit codes and precedence
0 valid; 2 usage (no pin), bad signature, or pin mismatch (reason printed); 3 subject digest mismatch
(`--check-subjects DIR`); 4 unreadable envelope, malformed statement or missing mandatory fields; 5 unknown
predicateType (after `VALID-SIGNATURE`); 6 anchor failure (`--check-anchors`); 7 anchoring refused (`anchor.py`).
When several apply, the first of this order wins: 4 unreadable envelope, 2 bad signature, 2 pin mismatch,
4 malformed statement, 3 subject, 5 unknown type, 6 anchors.

## 10. Threat model and non-goals
Detects: payload or signature tampering, signature malleability, subject file substitution (with
`--check-subjects`), unknown-type spoofing (flagged). Does not detect: a compromised producer key, a producer that
lies in a signed predicate, rollback or deletion of attestations (needs a log), time correctness (`started`/`ended`
are self-reported unless anchored). Non-goals: key revocation, encryption, a network protocol.

## 11. Test vectors
`vectors/` holds fourteen vectors (ten below, plus four verdict vectors, section 6.1) made with a committed TEST-ONLY key (public and worthless): three valid (one per
implemented predicateType), bad signature, mutated payload byte, unknown predicateType, and three strictness
vectors (non-canonical S, small-order key, malformed R) and a mixed-order key (prime-order point plus an 8-torsion
component), all rejected with exit 2. `bash vectors/run.sh` pins the keyid and prints `14/14 OK`.

## 12. Multi-signer policy (optional)
A verifier MAY offer a policy requiring N >= 2 distinct pinned keyids (`--require-keyid K1 --require-keyid K2
--artifact FILE ENV1 ENV2 ... --key KEYS`). It accepts only if ALL hold, offline:
1. every supplied envelope passes sections 1-5 (strict signatures; every signature keyid is a supplied key);
2. every supplied envelope carries a Statement (section 3) with a subject whose sha256 equals the sha256 of FILE;
3. each required keyid has its own valid signature (distinct signature bytes) over a statement naming the artifact.
   Envelopes are containers: one envelope signed by both keys meets the policy, as do two single-signer envelopes
   over the same statement; a keyid listed more than once counts as one key; a missing signature fails;
4. the required keyids are pairwise different (a repeated keyid is rejected); `--expect-keyid` is not accepted;
5. each `--require-keyid` value is exactly 64 lowercase hex characters, byte for byte; it is never lowercased or
   trimmed (one byte form everywhere, as for envelope keyids), and any other form exits 2;
6. every supplied envelope's Statement has a KNOWN predicateType (section 6) and a predicate carrying the mandatory
   fields (section 6), exactly as single-key verification requires;
7. no signature (its decoded bytes) appears in more than one supplied envelope. Ed25519 is deterministic, so the
   same key over the same payload always gives the same bytes: passing one envelope twice, a byte copy, a
   re-serialised copy, a copy with signatures reordered, or a copy with a signature added or removed is one signing
   act counted twice, and is rejected.

Exit codes: 0 policy met; 2 bad signature, unknown signer keyid, required key not supplied, duplicate or fewer than
two keyids, a signature reused across envelopes (rule 7), or policy unmet (a required keyid has no valid
signature); 3 an envelope does not name the artifact digest; 4 unreadable or malformed envelope, key or artifact,
including a missing mandatory predicate field; 5 an unknown predicateType. Precedence: 4, then 2 (signature), then
3, then 5, then 2 (reuse, then policy).
This stops a valid CI attestation from a compromised pipeline being accepted without the maintainer's key; it does
not help if both keys are compromised.
