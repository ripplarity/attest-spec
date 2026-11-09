# Compatibility run

`run_compat.sh` checks that a verifier still accepts what the public consumer repos have committed.

    bash compat/run_compat.sh --verifier attest_verify.py [--keyid stillherd=<hex>] [--keyid dejaspawn=<hex>] [--out compat/DATE.md]

What it does:
1. Shallow-clones `github.com/ripplarity/stillherd` and `github.com/ripplarity/dejaspawn` into a temp directory (read-only;
   deleted on exit). These two clones are the only network use.
2. Finds every committed `*.dsse.json`.
3. Reads each repo's pinned keyid from its README with this pattern (case-insensitive): a line containing `keyid` followed
   on the same line by a 64-character lowercase hex string (`keyid[^\n]*?([0-9a-f]{64})`). If it finds none, pass
   `--keyid name=hex`; without a keyid the file is reported as `SKIP`.
4. Finds the public key: a `*.pub.hex`, `pubkey.hex` or `keys.json` beside the file or in a parent directory, else a 64-hex
   string in the README whose sha256 equals the keyid.
5. Runs `python <verifier> <file> --key <key> --expect-keyid <keyid>` and writes `compat/<UTC date>.md`: repo, file,
   sha256 of the file, exit code, first output line, plus the verifier's own sha256 and each repo's commit.

Baselines are committed so a new verifier version can be compared line by line: re-run with the new verifier and diff the
two tables. `rc 0` valid, `5` unknown predicateType (signature valid), `SKIP` no keyid or key found, other codes per SPEC section 9.
