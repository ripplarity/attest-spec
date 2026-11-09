# Compatibility run

`run_compat.sh` checks that a verifier still accepts what the public consumer repos have committed.

    bash compat/run_compat.sh --verifier attest_verify.py [--keyid stillherd=<hex>] [--keyid dejaspawn=<hex>] [--out compat/DATE.md]

What it does:
1. Shallow-clones `github.com/ripplarity/stillherd` and `github.com/ripplarity/dejaspawn` into `work/compat/<repo>` inside
   this repository (a gitignored `work/compat` folder inside the checkout, read-only, deleted on exit); a system temp
   directory is not used. These two clones are the only network use.
2. Finds every committed attestation: `*.dsse.json`, `*.attestation.json` and `attestation.json`.
3. Reads each repo's pinned keyid with this pattern (case-insensitive): a line containing `keyid` followed on the same
   line by a 64-character lowercase hex string (`keyid.*?([0-9a-f]{64})` on one line), checking the root README first and then
   any `README.md` in the tree. If none is found, pass `--keyid name=hex`; without a keyid a file is reported `SKIP`.
4. Finds the public key: a `*.pub.hex`, `pubkey.hex` or `keys.json` beside the file or in a parent directory; else a
   `pubkey` field (hex or base64) inside the file; else anywhere in the repo a 64-hex string or JSON `pubkey` whose sha256
   equals the keyid.
5. Runs `python <verifier> <file> --key <key> --expect-keyid <keyid>` and writes `compat/<UTC date>.md`: repo, file,
   sha256 of the file, exit code, first output line, plus the verifier's own sha256 and each repo's commit.
   Files under `tests/fixtures/` that fail the pin are recorded `EXPECTED-FAIL (rc N)` (fixture keys are not the
   production key). Legacy-format attestations (not DSSE envelopes) get rc 4 from the verifier; the script appends a
   "legacy format" note to the line. `--keep` leaves the clones in `work/compat` for inspection.

Baselines are committed so a new verifier version can be compared line by line: re-run with the new verifier and diff the
two tables. `rc 0` valid, `5` unknown predicateType (signature valid), `SKIP` no keyid or key found, other codes per SPEC section 9.
