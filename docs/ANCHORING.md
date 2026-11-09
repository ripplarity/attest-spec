# Anchoring (Rekor) - opt-in, requires explicit maintainer approval

Code: `anchor.py` (writer, the only network-capable file) and `attest_verify.py --check-anchors` (offline, no network).
Tests use a synthetic 4-leaf log and an injected transport; no test or default path contacts a network.

## What it publishes
To the public, append-only Rekor log, permanently and irreversibly: the sha512 of the envelope (with `anchors`
removed), the ed25519 signature over that digest, and the producer public key (PEM). Nothing about the artefact
contents is published, but the key links every anchored artefact to its producer.

## Running the first real anchor (maintainer approval required)
1. The maintainer explicitly approves anchoring for the specific key.
2. `ATTEST_ANCHOR_OK=1 python anchor.py X.dsse.json --key <ed25519 seed hex file> --anchor rekor`
   (without the env var it exits 7 and sends nothing).
3. Fetch the Rekor public key from the Sigstore TUF root, record its sha256 in SPEC.md section 8, save it as `rekor.pub`.
4. `python attest_verify.py X.dsse.json --key <pub> --expect-keyid <id> --check-anchors --rekor-key rekor.pub`
   must print `ANCHORS-OK 1`.
TESTED 2026-11-09 (see "Live test" below): live Rekor REJECTS an ed25519 `hashedrekord` whose data hash is SHA-256
("not in [SHA-512]"). `build_entry` must move to a SHA-512 data hash; that change lands in spec revision 1.4.

## Verification
Offline from the embedded entry: digest match, producer signature, RFC 6962 inclusion proof, SET against the pinned
Rekor key (exit 6 on any failure). `--online` (freshness against the live log) is reserved and not implemented.

## Rekor public key (pinned for `--rekor-key`)
`rekor.pub` was fetched on 2026-11-08 (UTC) with one read-only GET of `https://rekor.sigstore.dev/api/v1/log/publicKey`
(ECDSA P-256, PEM). It has NOT yet been cross-checked against the Sigstore TUF root.
sha256(rekor.pub) = `dce5ef715502ec9f3cdfd11f8cc384b31a6141023d3e7595e9908a81cb6241bd`
SPEC section 8 still says the pin is not recorded; that line is updated in SPEC 1.4 (SPEC 1.3 is frozen).

## Live test 2026-11-09
Attempt: anchor `vectors/01_sovkit_inventory_valid.dsse.json` (TEST-ONLY key) with `ATTEST_ANCHOR_OK=1 python anchor.py ... --anchor rekor`.
Result: REJECTED, nothing was published. Rekor answered HTTP 400:

    {"code":400,"message":"error processing entry: verifying signature: unsupported hash algorithm: \"SHA-256\" not in [SHA-512]"}

Meaning: the live log accepts an ed25519 `hashedrekord` only with a SHA-512 data hash (ed25519ph-style prehash), not the
SHA-256 digest this writer sends. `build_entry` therefore needs a design change (SHA-512 digest and matching signature
scheme, or a different entry kind such as `dsse`), which would also change the SPEC section 8 digest rule. No variant
was tried; the request was replayed once only to capture the error body. Offline verification remains tested only
against the synthetic log.

## SPEC 1.4 (branch spec-1.4, not yet released)
`build_entry` now sends `{algorithm: sha512, value: sha512(JCS(envelope minus anchors))}` and an Ed25519ph signature (RFC 8032,
empty context, PH(M) = that digest), which is the form the error above asks for. The signer is pure Python (`anchor.ed25519ph_sign`)
and reproduces the RFC 8032 section 7.3 "abc" test vector exactly (tested). `--check-anchors` verifies the same form offline.
NOT yet tried against the live log in this pass: whether Rekor accepts exactly this entry is untested.
