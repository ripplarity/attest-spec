import copy
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import verdict_check as vc

H = "a" * 64


def good():
    return {
        "claim": {"text": "X rejects empty input", "source_url": "https://example.com/c"},
        "subject_tool": {"name": "t", "version": "1"},
        "probe": {"id": "p", "version": "1", "sha256": H},
        "inputs_digest": H,
        "controls": [
            {"name": "good", "kind": "positive", "expected": "accept", "observed": "accept"},
            {"name": "bad", "kind": "negative", "expected": "reject", "observed": "reject"},
        ],
        "result": "PASS",
        "transcript_digest": H,
        "observed_at": "2026-01-01T00:00:00Z",
    }


def test_valid():
    assert vc.check_verdict(good()) == ""


SUBJ = [{"name": "t.txt", "digest": {"sha256": H}}]


def test_failing_control():
    p = good()
    p["controls"][0]["observed"] = "reject"
    assert vc.check_verdict(p) == ""
    assert "control failed" in vc.check_trust(p, SUBJ)


def test_type_and_value_match():
    p = good()
    p["controls"][0]["expected"], p["controls"][0]["observed"] = "1", 1
    assert "control failed" in vc.check_trust(p, SUBJ)


def test_transcript_must_be_subject():
    assert vc.check_trust(good(), SUBJ) == ""
    assert "subject" in vc.check_trust(good(), [{"name": "x", "digest": {"sha256": "b" * 64}}])


def test_missing_controls():
    p = good()
    del p["controls"]
    assert "controls" in vc.check_verdict(p)
    p = good()
    p["controls"] = []
    assert "controls" in vc.check_verdict(p)


def test_no_positive_control():
    p = good()
    p["controls"] = [p["controls"][1]]
    assert "positive" in vc.check_trust(p, SUBJ)


def test_bad_result_enum():
    for v in ("pass", "OK", None):
        p = good()
        p["result"] = v
        assert "result" in vc.check_verdict(p)


def test_non_utc_timestamp():
    for v in ("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00", "2026-01-01T00:00:00+05:30"):
        p = good()
        p["observed_at"] = v
        assert "observed_at" in vc.check_verdict(p)


def test_bad_digest():
    p = copy.deepcopy(good())
    p["probe"]["sha256"] = "A" * 64
    assert "probe" in vc.check_verdict(p)


def _run(name):
    return subprocess.run(
        [sys.executable, str(ROOT / "verdict_check.py"), str(ROOT / "vectors" / name)],
        capture_output=True,
    ).returncode


def test_cli_vectors():
    assert _run("11_verdict_valid.dsse.json") == 0
    for n in ("12_verdict_failed_control", "13_verdict_inconclusive_failed_control", "14_verdict_pass_failed_control"):
        assert _run(n + ".dsse.json") == 8
