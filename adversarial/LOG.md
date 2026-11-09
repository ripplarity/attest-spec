# Adversarial log: multi-signer policy (SPEC s12) and verdict_check (SPEC 6.1)

## 2026-11-09 (second pass): envelopes are containers; verdict_check trust path

Policy decision (review): a dual-signed envelope could always be split into two single-signer envelopes over the
same statement without either key, so a rule requiring "a distinct envelope per key" could be bypassed by repackaging
and added no security. s12 rule 3 now reads: each required keyid has its own valid signature (distinct signature
bytes) over a statement naming the artifact. Matching is a set check, and the 64-envelope cap is gone. Rule 7
(a signature reused across envelopes gives rc 2) and the KNOWN/mandatory checks stay. Flipped on purpose:
`one_env_both_keys` (pytest and hostile) is now rc 0. New: a keyid listed twice in one envelope counts once (rc 2
when the other required key is absent); a split into two envelopes over the same statement is rc 0.

verdict_check (three findings from review, all reproduced and fixed):
1. An unsigned statement printed VERDICT-ACCEPTED, rc 0. verdict_check now accepts only a DSSE envelope, takes
   `--key` and `--expect-keyid`, and runs attest_verify's full verification first, returning its code when that
   is not 0. Tests: a bare statement is rc != 0; a tampered signature is rc 2; a wrong pin is rc 2; a valid
   envelope is rc 0.
2. "ACCEPTED" could be read as PASS. It now prints `VERDICT-ACCEPTED result=<PASS|FAIL|INCONCLUSIVE>`, and a test
   checks that an accepted FAIL prints result=FAIL and no "PASS".
3. `\d` in the RFC3339 regex matched non-ASCII digits. It is now `[0-9]`. Tests use Arabic-Indic and fullwidth
   digits in observed_at, and both are rejected.
Minor, fixed: control equality now compares JSON types recursively ({"a": true} vs {"a": 1}, [1.0] vs [1] fail).
vectors/run.sh passes the key and pin to verdict_check. The vector bytes and expected codes are unchanged.

Runs on this tree (attest_verify.py fef63230..., verdict_check.py 13ac6e49...): pytest 68 passed; vectors 14/14;
hostile: no unexpected results; compat row-for-row identical (table header updated to the new verifier sha);
fuzz 2500 seed 1 (model updated to the set rule): 37 accepts, 0 false accepts, 0 false rejects. Accepts rose
from 7 because the dual-signed single envelope in the mutation pool now meets the policy.

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
