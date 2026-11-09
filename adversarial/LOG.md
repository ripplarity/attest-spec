# Adversarial log: multi-signer policy (SPEC s12)

## 2026-11-09: envelope reuse (false accept, fixed)

Found in review: one envelope signed by both required keys was rejected when passed once, but accepted
(VALID-POLICY, rc 0) when passed twice or as a byte-identical copy under another name. The cause was that matching
went by argument position, never by envelope identity.

The fix (SPEC s12 rules 6-8):
- No decoded signature may appear in more than one supplied envelope. Ed25519 is deterministic, so this catches the
  same path twice, a byte copy, a re-serialised copy, reordered signatures, and a copy with a signature added or
  removed. It does not depend on file bytes or JSON form.
- Matching is a bipartite matching (Kuhn), not a search over permutations. At most 64 envelopes are allowed (rc 2
  above that).
- Policy mode now applies the same predicate checks as single-key mode: unknown predicateType gives rc 5, and a
  missing mandatory field gives rc 4.
- A change of expectation: `one_env_both_keys_plus_extra_m` (both(M,C) plus M alone over the same statement) was
  accepted before. It is now rejected, because M's signature bytes are identical in both envelopes, so it is one
  signing act. The same shape over a different statement is still accepted (new hostile case).

Runs on the fixed tree (attest_verify.py sha256 5dad73f8...):
- `pytest -q`: 60 passed. tests/test_policy.py adds same path twice, byte copy, re-serialised copy, reordered
  signatures, extra-signature and subset re-wraps, unknown predicateType rc 5, missing mandatory field rc 4, the
  envelope cap, and a case that needs an augmenting path.
- `python adversarial/hostile.py`: no unexpected results; all reuse cases are rc 2.
- `python adversarial/fuzz.py 2500 1`, with new mutations (reuse_reorder, reuse_extra, reuse_path) and the model
  extended with the reuse and predicate rules: 2500 iterations, 7 accepts, 0 false accepts, 0 false rejects.
- `python adversarial/differential.py` (against the 1.4 verifier): 10/14 identical. Vectors 11-14 are verdict
  vectors, which 1.4 does not know (rc 5) and 1.5 accepts (rc 0), as intended.
- `bash vectors/run.sh`: 14/14 OK. The compat rerun is row-for-row identical to compat/2026-11-09_v1.5.md.
