<p align="center">
  <img src="assets/logo.svg" width="112" alt="attest-spec logo: a seal with a check mark">
</p>

<h1 align="center">attest-spec: one signed-record format</h1>

<p align="center">
  <b>Every tool signs its records the same way, and anyone can check them offline.</b><br>
  A small, strict profile of DSSE + in-toto Statement v1, with ed25519 signatures and a verifier that requires a pinned key.
</p>

<p align="center">
  <img src="assets/badges.svg" alt="DSSE + in-toto v1 · ed25519, pinned keyid · spec CC-BY-4.0 · code Apache-2.0">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> · <a href="#what-it-defines">What it defines</a> · <a href="#evidence">Evidence</a> · <a href="#faq">FAQ</a>
</p>

<p align="center"><code>python attest_verify.py X.dsse.json --key &lt;pubkey&gt; --expect-keyid &lt;keyid&gt;</code></p>

---

## Why

A signature only means something if you know whose key it is. This format makes that explicit: the verifier refuses to trust a key unless you pin its keyid, obtained out of band. The same envelope serves every tool that adopts it, so one verifier checks them all.

## Quick start

```bash
pip install cryptography        # the only dependency (Python 3.10+)
python attest_verify.py X.dsse.json --key <hex pubkey | keys.json> --expect-keyid <keyid>
bash vectors/run.sh             # expects 9/9 OK
python -m pytest -q tests
```

`--expect-keyid` is required: it is the keyid you trust, obtained out of band (`SPEC.md`, section 7). Producing tools print their own keyid (for example `sovkit keyid`).

## What it defines

| Part | In short |
|---|---|
| Envelope | DSSE JSON with `payloadType` exactly `application/vnd.in-toto+json` and ed25519 signatures over the PAE |
| Statement | in-toto Statement v1; subjects are relative POSIX paths with sha256 digests |
| Canonical form | RFC 8785 (JCS) payload bytes, written once and never re-serialised by verifiers |
| Keys | strict RFC 8032 ed25519; keyid = sha256 of the raw public key; the pin is mandatory |
| Anchoring | optional Rekor anchoring, off by default; the offline `--check-anchors` verifier works against a synthetic log, but the writer is not yet accepted by live Rekor (it requires a SHA-512 hashedrekord; design change pending in revision 1.4, see `docs/ANCHORING.md`) |

The normative text is [`SPEC.md`](SPEC.md). Writing attestations from another tool: [`docs/MIGRATION_other_writers.md`](docs/MIGRATION_other_writers.md).

## Evidence

| Check | Command |
|---|---|
| 9 test vectors, valid and invalid (bad signature, mutated payload, unknown predicate type, …) | `bash vectors/run.sh` |
| Verifier and anchoring tests | `python -m pytest -q tests` |

## Limits

- A valid signature proves the bytes are unchanged and who signed them, not that the content is true.
- No Ripplarity keyid is published yet; pin the keyid of the tool or maintainer you trust.
- An unknown `predicateType` verifies the signature but exits 5, so callers can tell "valid but unrecognised" from "valid".

## FAQ

**Why not plain GPG or a detached `.sig`?** DSSE binds the payload type into what is signed, and in-toto gives a standard way to name the files a statement covers.

**Why must I pin a keyid?** A key shipped beside the artefact could have been swapped along with it. Pinning means you decide out of band whom to trust.

**Does it need a network?** No. Verification is offline; anchoring is optional.

**Who uses it?** sovkit, aiescrow and other Ripplarity tools write this format.

---

<p align="center"><sub>Specification CC-BY-4.0 (<code>LICENSE-SPEC</code>) · code Apache-2.0 (<code>LICENSE</code>) · Ripplarity Inc.</sub></p>
