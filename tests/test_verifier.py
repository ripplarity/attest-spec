import base64
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import attest_verify as av

VEC = ROOT / "vectors" / "01_sovkit_inventory_valid.dsse.json"
KEY = ROOT / "vectors" / "test_key.pub.hex"
PIN = hashlib.sha256(bytes.fromhex(KEY.read_text().strip())).hexdigest()
PRIV = Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex((ROOT / "vectors" / "test_key.ed25519").read_text().strip())
)


def run(env, *extra, key=KEY, pin=PIN):
    a = [sys.executable, str(ROOT / "attest_verify.py"), str(env), "--key", str(key)]
    if pin:
        a += ["--expect-keyid", pin]
    return subprocess.run(a + list(extra), capture_output=True, text=True)


def test_unpinned_exits_2_with_message():
    r = run(VEC, pin=None)
    assert r.returncode == 2 and "pinned keyid required (SPEC s7)" in r.stderr


def test_wrong_pin_exits_2_with_reason():
    r = run(VEC, pin="00" * 32)
    assert r.returncode == 2 and "key does not match pin" in r.stderr


def test_unreadable_envelope_exits_4(tmp_path):
    p = tmp_path / "x.dsse.json"
    p.write_text("{not json")
    assert run(p).returncode == 4


def test_jcs_rfc8785_properties():
    assert av.jcs({"b": 1, "a": [True, None, "x"]}) == b'{"a":[true,null,"x"],"b":1}'
    assert av.jcs({"\U00010000": 1, "￿": 2}) == '{"\U00010000":1,"￿":2}'.encode()
    assert av.jcs("é" + chr(10)) == ('"é' + chr(92) + 'n"').encode()
    for bad in (1.5, float("nan"), 2**60, "\ud800"):
        with pytest.raises(ValueError):
            av.jcs(bad)


def test_strict_rejects_noncanonical_and_small_order():
    sig = PRIV.sign(b"m")
    raw = bytes.fromhex(KEY.read_text().strip())
    assert av.strict_ed25519_ok(raw, sig) == ""
    big_s = sig[:32] + (int.from_bytes(sig[32:], "little") + av._L).to_bytes(
        32, "little"
    )
    assert "S" in av.strict_ed25519_ok(raw, big_s)
    assert av.strict_ed25519_ok((1).to_bytes(32, "little"), sig)
    assert av.strict_ed25519_ok((av._P + 1).to_bytes(32, "little"), sig)  # y >= p


def _env_with(tmp_path, extra_sig=None, tweak=None):
    d = json.loads(VEC.read_text())
    if extra_sig:
        d["signatures"].append(extra_sig)
    if tweak:
        tweak(d)
    p = tmp_path / "e.dsse.json"
    p.write_text(json.dumps(d))
    return p


def test_extra_unverifiable_signature_fails(tmp_path):
    other = Ed25519PrivateKey.generate()
    msg = av.pae(
        av.PAYLOAD_TYPE, base64.b64decode(json.loads(VEC.read_text())["payload"])
    )
    sig = base64.b64encode(other.sign(msg)).decode()
    p = _env_with(tmp_path, {"keyid": "ab" * 32, "sig": sig})
    assert run(p).returncode == 2  # ALL entries must verify under a supplied key


def test_wrong_keyid_label_fails(tmp_path):
    p = _env_with(
        tmp_path, tweak=lambda d: d["signatures"][0].__setitem__("keyid", "cd" * 32)
    )
    assert run(p).returncode == 2


def test_bad_payload_type_is_unreadable(tmp_path):
    p = _env_with(tmp_path, tweak=lambda d: d.__setitem__("payloadType", "text/plain"))
    assert run(p).returncode == 4


@pytest.mark.parametrize(
    "name", ["../x", "/abs", "a//b", "a" + chr(92) + "b", "./x", ""]
)
def test_bad_subject_names(name):
    assert not av.subject_name_ok(name)
    assert av.subject_name_ok("dir/file.json")


def test_unknown_envelope_keys_ignored_but_in_anchor_digest(tmp_path):
    p = _env_with(tmp_path, tweak=lambda d: d.__setitem__("extra", "v"))
    assert run(p).returncode == 0
    d = json.loads(VEC.read_text())
    d2 = dict(d, extra="v")
    assert av.envelope_digest(d) != av.envelope_digest(d2)
    assert av.envelope_digest(dict(d2, anchors=[1])) == av.envelope_digest(d2)


def test_subject_precedence_over_unknown_type(tmp_path):
    shutil.copy(
        ROOT / "vectors" / "06_unknown_predicate_type.dsse.json",
        tmp_path / "u.dsse.json",
    )
    r = run(tmp_path / "u.dsse.json", "--check-subjects", str(tmp_path))
    assert r.returncode == 3  # subject mismatch outranks unknown type (5)
