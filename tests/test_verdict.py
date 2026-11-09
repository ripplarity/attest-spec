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
        "claim": {
            "text": "X rejects empty input",
            "source_url": "https://example.com/c",
        },
        "subject_tool": {"name": "t", "version": "1"},
        "probe": {"id": "p", "version": "1", "sha256": H},
        "inputs_digest": H,
        "controls": [
            {
                "name": "good",
                "kind": "positive",
                "expected": "accept",
                "observed": "accept",
            },
            {
                "name": "bad",
                "kind": "negative",
                "expected": "reject",
                "observed": "reject",
            },
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
    assert "subject" in vc.check_trust(
        good(), [{"name": "x", "digest": {"sha256": "b" * 64}}]
    )


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
    for v in (
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:00",
        "2026-01-01T00:00:00+05:30",
    ):
        p = good()
        p["observed_at"] = v
        assert "observed_at" in vc.check_verdict(p)


def test_bad_digest():
    p = copy.deepcopy(good())
    p["probe"]["sha256"] = "A" * 64
    assert "probe" in vc.check_verdict(p)


TEST_KEY = ROOT / "vectors" / "test_key.pub.hex"


def _pin(keyfile=TEST_KEY):
    import hashlib

    return hashlib.sha256(bytes.fromhex(Path(keyfile).read_text().strip())).hexdigest()


def _cli(path, key=TEST_KEY, pin=None):
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "verdict_check.py"),
            str(path),
            "--key",
            str(key),
            "--expect-keyid",
            pin or _pin(key),
        ],
        capture_output=True,
        text=True,
    )


def _run(name):
    return _cli(ROOT / "vectors" / name).returncode


def _signed(tmp_path, pred, tamper=False):
    import base64

    import attest_verify as av
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    k = Ed25519PrivateKey.generate()
    raw = k.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    kf = tmp_path / "k.hex"
    kf.write_text(raw.hex())
    pred = dict(
        pred,
        producer={"tool": "t", "version": "1"},
        started="2026-01-01T00:00:00Z",
        ended="2026-01-01T00:00:01Z",
        environment={"host_os": "linux", "run_mode": "REAL"},
    )
    st = {
        "_type": av.STATEMENT_TYPE,
        "subject": SUBJ,
        "predicateType": vc.VERDICT_TYPE,
        "predicate": pred,
    }
    payload = json.dumps(st).encode()
    sig = k.sign(av.pae(av.PAYLOAD_TYPE, payload))
    if tamper:
        sig = bytes([sig[0] ^ 1]) + sig[1:]
    e = tmp_path / "v.dsse.json"
    e.write_text(
        json.dumps(
            {
                "payloadType": av.PAYLOAD_TYPE,
                "payload": base64.b64encode(payload).decode(),
                "signatures": [
                    {"keyid": av.keyid(raw), "sig": base64.b64encode(sig).decode()}
                ],
            }
        )
    )
    return e, kf, st


def test_cli_valid_envelope_prints_result(tmp_path):
    e, kf, _ = _signed(tmp_path, good())
    r = _cli(e, kf)
    assert r.returncode == 0 and r.stdout.strip() == "VERDICT-ACCEPTED result=PASS"


def test_cli_accepted_fail_says_fail(tmp_path):
    p = good()
    p["result"] = "FAIL"
    e, kf, _ = _signed(tmp_path, p)
    r = _cli(e, kf)
    assert r.returncode == 0 and r.stdout.strip() == "VERDICT-ACCEPTED result=FAIL"
    assert "PASS" not in r.stdout


def test_cli_bare_statement_never_accepted(tmp_path):
    p = good()
    p["result"] = "FAIL"
    _, kf, st = _signed(tmp_path, p)
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps(st))
    r = _cli(bare, kf)
    assert r.returncode != 0 and "ACCEPTED" not in r.stdout


def test_cli_tampered_signature_rejected(tmp_path):
    e, kf, _ = _signed(tmp_path, good(), tamper=True)
    r = _cli(e, kf)
    assert r.returncode == 2 and "ACCEPTED" not in r.stdout


def test_cli_wrong_pin_rejected(tmp_path):
    e, kf, _ = _signed(tmp_path, good())
    r = _cli(e, kf, pin="0" * 64)
    assert r.returncode == 2 and "ACCEPTED" not in r.stdout


def test_non_ascii_digits_in_timestamp_rejected():
    arabic_indic = "".join(
        chr(0x0660 + int(c)) if c.isdigit() else c for c in "2026-01-01T00:00:00Z"
    )
    fullwidth = "".join(
        chr(0xFF10 + int(c)) if c.isdigit() else c for c in "2026-01-01T00:00:00Z"
    )
    for v in (arabic_indic, fullwidth):
        p = good()
        p["observed_at"] = v
        assert "observed_at" in vc.check_verdict(p), v


def test_nested_control_types_compared():
    p = good()
    p["controls"][0]["expected"], p["controls"][0]["observed"] = {"a": True}, {"a": 1}
    assert "control failed" in vc.check_trust(p, SUBJ)
    p["controls"][0]["expected"], p["controls"][0]["observed"] = [1.0], [1]
    assert "control failed" in vc.check_trust(p, SUBJ)
    p["controls"][0]["expected"], p["controls"][0]["observed"] = (
        {"a": [1, {"b": "x"}]},
        {"a": [1, {"b": "x"}]},
    )
    assert vc.check_trust(p, SUBJ) == ""


def test_cli_vectors():
    assert _run("11_verdict_valid.dsse.json") == 0
    for n in (
        "12_verdict_failed_control",
        "13_verdict_inconclusive_failed_control",
        "14_verdict_pass_failed_control",
    ):
        assert _run(n + ".dsse.json") == 8


def test_gen_vectors_reproduces_committed_bytes(tmp_path):
    import os

    env = dict(os.environ, VECTORS_OUT=str(tmp_path))
    r = subprocess.run(
        [sys.executable, str(ROOT / "gen_vectors.py")],
        cwd=ROOT,
        env=env,
        capture_output=True,
    )
    assert r.returncode == 0, r.stderr
    gen = sorted(p.name for p in tmp_path.iterdir())
    committed = sorted(
        p.name
        for p in (ROOT / "vectors").iterdir()
        if p.name != "run.sh" and p.name != "README.md"
    )
    assert gen == committed
    for n in gen:  # Ed25519 is deterministic: nothing excluded
        assert (tmp_path / n).read_bytes() == (ROOT / "vectors" / n).read_bytes(), n
