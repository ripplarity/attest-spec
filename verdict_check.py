#!/usr/bin/env python3
"""Predicate validator for the `verdict` predicateType (SPEC section 6.1).

Library: `check_verdict(predicate) -> str` ("" when valid, else a reason); `check_trust(predicate, subjects)`.
CLI: `python verdict_check.py ENVELOPE --key KEYS --expect-keyid KEYID`. Only a DSSE envelope is accepted, and
attest_verify.py's full verification runs on it first (strict signature, pinned keyid, subject, mandatory fields):
an unsigned or tampered statement can never be accepted. Exit codes: attest_verify's own code (2, 3, 4, 5) when it
does not return 0; 4 not an envelope or malformed verdict shape; 8 VERDICT-NOT-TRUSTED; 0 accepted, printed as
"VERDICT-ACCEPTED result=<PASS|FAIL|INCONCLUSIVE>" (accepted means the record is trustworthy, not that the claim passed).
attest_verify.py does not call this module.
"""

import base64
import contextlib
import io
import json
import os
import re
import sys

VERDICT_TYPE = "https://ripplarity.com/attestation/verdict/v1"
RESULTS = ("PASS", "FAIL", "INCONCLUSIVE")
KINDS = ("positive", "negative")
HEX64 = re.compile(r"[0-9a-f]{64}")
# [0-9], never \d: \d also matches non-ASCII digits (Arabic-Indic, fullwidth, ...)
RFC3339_UTC = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z"
)


def same(a, b) -> bool:
    """Equality that also requires the same JSON type at every level (true != 1, 1 != 1.0, nested too)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return a == b


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
    return ""


def check_trust(p, subjects) -> str:
    """Domain rules on a well-shaped predicate; "" = accepted, else why NOT TRUSTED (rc 8)."""
    for k in p["controls"]:
        if not same(k["expected"], k["observed"]):
            return f"control failed: {k['name']} (observed differs from expected)"
    if not any(k["kind"] == "positive" for k in p["controls"]):
        return "no positive control present"
    if not any(
        isinstance(s, dict)
        and isinstance(s.get("digest"), dict)
        and s["digest"].get("sha256") == p["transcript_digest"]
        for s in subjects
    ):
        return "transcript_digest matches no statement subject"
    return ""


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="verdict_check.py")
    ap.add_argument("envelope")
    ap.add_argument("--key", required=True)
    ap.add_argument("--expect-keyid", required=True)
    a = ap.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        env = json.load(open(a.envelope, encoding="utf-8"))
        if not (isinstance(env, dict) and "payload" in env and "signatures" in env):
            raise ValueError("not a DSSE envelope (a bare statement is never accepted)")
    except Exception as e:
        print(f"UNREADABLE: {e}", file=sys.stderr)
        return 4
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import attest_verify

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = attest_verify.main(
            [a.envelope, "--key", a.key, "--expect-keyid", a.expect_keyid]
        )
    if rc != 0:
        print(
            f"VERDICT-NOT-VERIFIED: attest_verify exit {rc} ({out.getvalue().strip() or 'see above'})",
            file=sys.stderr,
        )
        return rc
    try:
        d = json.loads(base64.b64decode(env["payload"], validate=True))
        if d.get("predicateType") != VERDICT_TYPE:
            raise ValueError("predicateType is not verdict")
        pred, subjects = d["predicate"], d["subject"]
        if not isinstance(subjects, list):
            raise ValueError("subject is not a list")
    except Exception as e:
        print(f"UNREADABLE: {e}", file=sys.stderr)
        return 4
    why = check_verdict(pred)
    if why:
        print(f"MALFORMED: {why}", file=sys.stderr)
        return 4
    why = check_trust(pred, subjects)
    if why:
        print(f"VERDICT-NOT-TRUSTED: {why}", file=sys.stderr)
        return 8
    print(f"VERDICT-ACCEPTED result={pred['result']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
