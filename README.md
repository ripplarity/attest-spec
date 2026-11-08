# attest-spec

One attestation format (DSSE + in-toto Statement v1) for sovkit, aiescrow, and other Ripplarity tools. The
normative text is `SPEC.md`.

Licences: the specification is CC-BY-4.0 (`LICENSE-SPEC`); the code is Apache-2.0 (`LICENSE`).

## Install and verify

    pip install cryptography        # the only dependency (Python 3.10+)
    python attest_verify.py X.dsse.json --key <hex pubkey | keys.json> --expect-keyid <keyid>

`--expect-keyid` is required: it is the keyid you trust, obtained out of band (SPEC section 7). No Ripplarity
keyid is published yet; publish your own (the producing tool prints it, for example `sovkit keyid`).

- Vectors: `bash vectors/run.sh` (expects `9/9 OK`).
- Tests: `python -m pytest -q tests`.
- Optional Rekor anchoring: `docs/ANCHORING.md` (off by default; requires explicit maintainer approval).
- Writing attestations from another tool: `docs/MIGRATION_other_writers.md`.
