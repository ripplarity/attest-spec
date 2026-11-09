#!/usr/bin/env python3
"""Predicate validator for the `verdict` predicateType (SPEC section 6.1).

Library: `check_verdict(predicate) -> str` ("" when valid, else a reason).
CLI: `python verdict_check.py FILE` (a bare predicate, a statement, or a DSSE
envelope); exit 0 valid, 4 invalid. Signature checking is attest_verify.py's
job; it calls this for the verdict type.
"""

import base64
import json
import re
import sys

VERDICT_TYPE = "https://ripplarity.com/attestation/verdict/v1"
RESULTS = ("PASS", "FAIL", "INCONCLUSIVE")
KINDS = ("positive", "negative")
HEX64 = re.compile(r"[0-9a-f]{64}")
RFC3339_UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z")


def _nonempty(v) -> bool:
    return isinstance(v, str) and bool(v.strip())


def _hex(v) -> bool:
    return isinstance(v, str) and HEX64.fullmatch(v) is not None


def check_verdict(p) -> str:
    if not isinstance(p, dict):
        return "predicate is not an object"
    c = p.get("claim")
    if not (isinstance(c, dict) and _nonempty(c.get("text"))):
        return "claim.text missing"
    if "source_url" in c and not (
        isinstance(c["source_url"], str)
        and re.fullmatch(r"https?://\S+", c["source_url"])
    ):
        return "claim.source_url must be an http(s) URL"
    t = p.get("subject_tool")
    if not (
        isinstance(t, dict) and _nonempty(t.get("name")) and _nonempty(t.get("version"))
    ):
        return "subject_tool{name,version} missing"
    pr = p.get("probe")
    if not (
        isinstance(pr, dict)
        and _nonempty(pr.get("id"))
        and _nonempty(pr.get("version"))
        and _hex(pr.get("sha256"))
    ):
        return "probe{id,version,sha256} missing or sha256 not 64 lowercase hex"
    if not _hex(p.get("inputs_digest")):
        return "inputs_digest must be 64 lowercase hex"
    if not _hex(p.get("transcript_digest")):
        return "transcript_digest must be 64 lowercase hex"
    if p.get("result") not in RESULTS:
        return "result must be PASS, FAIL or INCONCLUSIVE"
    ts = p.get("observed_at")
    if not (isinstance(ts, str) and RFC3339_UTC.fullmatch(ts)):
        return "observed_at must be RFC3339 UTC ending in Z"
    ctl = p.get("controls")
    if not isinstance(ctl, list) or not ctl:
        return "controls missing or empty"
    for i, k in enumerate(ctl):
        if not (
            isinstance(k, dict)
            and _nonempty(k.get("name"))
            and k.get("kind") in KINDS
            and "expected" in k
            and "observed" in k
        ):
            return f"controls[{i}] needs name, kind (positive|negative), expected, observed"
        if k["expected"] != k["observed"] or type(k["expected"]) is not type(
            k["observed"]
        ):
            return f"control failed: {k['name']} (observed differs from expected)"
    if not any(k["kind"] == "positive" for k in ctl):
        return "no positive control present"
    return ""


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: verdict_check.py FILE", file=sys.stderr)
        return 2
    try:
        d = json.load(open(argv[0], encoding="utf-8"))
        if "payload" in d:
            d = json.loads(base64.b64decode(d["payload"], validate=True))
        if "predicate" in d:
            if d.get("predicateType") != VERDICT_TYPE:
                raise ValueError("predicateType is not verdict")
            d = d["predicate"]
    except Exception as e:
        print(f"UNREADABLE: {e}", file=sys.stderr)
        return 4
    why = check_verdict(d)
    if why:
        print(f"INVALID-VERDICT: {why}", file=sys.stderr)
        return 4
    print("VALID-VERDICT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
