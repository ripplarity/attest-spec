# Anchoring (Rekor) - opt-in, requires explicit maintainer approval

Code: `anchor.py` (writer, the only network-capable file) and `attest_verify.py --check-anchors` (offline, no network).
Tests use a synthetic 4-leaf log and an injected transport; no test or default path contacts a network.

## What it publishes
To the public, append-only Rekor log, permanently and irreversibly: the sha256 of the envelope (with `anchors`
removed), the ed25519 signature over that digest, and the producer public key (PEM). Nothing about the artefact
contents is published, but the key links every anchored artefact to its producer.

## Running the first real anchor (maintainer approval required)
1. The maintainer explicitly approves anchoring for the specific key.
2. `ATTEST_ANCHOR_OK=1 python anchor.py X.dsse.json --key <ed25519 seed hex file> --anchor rekor`
   (without the env var it exits 7 and sends nothing).
3. Fetch the Rekor public key from the Sigstore TUF root, record its sha256 in SPEC.md section 8, save it as `rekor.pub`.
4. `python attest_verify.py X.dsse.json --key <pub> --expect-keyid <id> --check-anchors --rekor-key rekor.pub`
   must print `ANCHORS-OK 1`.
UNTESTED: whether live Rekor accepts an ed25519 signature over the raw 32-byte digest in a `hashedrekord`
(the test log is synthetic). If step 2 is rejected, adjust `build_entry` (e.g. use PKIX/ed25519ph) and re-test.

## Verification
Offline from the embedded entry: digest match, producer signature, RFC 6962 inclusion proof, SET against the pinned
Rekor key (exit 6 on any failure). `--online` (freshness against the live log) is reserved and not implemented.
