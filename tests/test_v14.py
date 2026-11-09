import base64
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import anchor
import attest_verify as av
from test_anchor import PRIV, FakeRekor

VEC = ROOT / "vectors" / "01_sovkit_inventory_valid.dsse.json"
RFC_SEED = bytes.fromhex(
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
)
RFC_PUB = bytes.fromhex(
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
)
RFC_SIG = bytes.fromhex(
    "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41"
    "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406"
)


def test_ed25519ph_matches_rfc8032_vector():
    d = hashlib.sha512(b"abc").digest()
    assert anchor.ed25519ph_sign(RFC_SEED, d) == RFC_SIG
    assert av.ed25519ph_verify(RFC_PUB, d, RFC_SIG)
    assert not av.ed25519ph_verify(RFC_PUB, hashlib.sha512(b"abd").digest(), RFC_SIG)


def test_anchor_digest_is_sha512_of_jcs_without_anchors(tmp_path):
    env = json.loads(VEC.read_text())
    want = hashlib.sha512(av.jcs(env)).hexdigest()
    assert (
        av.envelope_digest(dict(env, anchors=[{"x": 1}])) == want and len(want) == 128
    )
    entry = anchor.build_entry(env, PRIV)
    assert entry["spec"]["data"]["hash"] == {"algorithm": "sha512", "value": want}


def test_wrong_hash_algorithm_in_anchor_is_rejected(tmp_path):
    env = tmp_path / "e.dsse.json"
    shutil.copy(VEC, env)
    fr = FakeRekor()
    anchor.anchor_rekor(env, PRIV, post=fr.post)
    d = json.loads(env.read_text())
    body = json.loads(base64.b64decode(d["anchors"][0]["body"]))
    assert body["spec"]["data"]["hash"]["algorithm"] == "sha512"
    body["spec"]["data"]["hash"]["algorithm"] = "sha256"
    d["anchors"][0]["body"] = base64.b64encode(json.dumps(body).encode()).decode()
    env.write_text(json.dumps(d))
    (tmp_path / "rekor.pub").write_bytes(fr.pem)
    pin = hashlib.sha256(
        bytes.fromhex((ROOT / "vectors" / "test_key.pub.hex").read_text().strip())
    ).hexdigest()
    r = subprocess.run(
        [
            sys.executable,
            str(ROOT / "attest_verify.py"),
            str(env),
            "--key",
            str(ROOT / "vectors" / "test_key.pub.hex"),
            "--expect-keyid",
            pin,
            "--check-anchors",
            "--rekor-key",
            str(tmp_path / "rekor.pub"),
        ],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 6


def test_default_rekor_pub_is_pinned_by_sha256(tmp_path):
    assert (
        hashlib.sha256((ROOT / "rekor.pub").read_bytes()).hexdigest()
        == av.REKOR_KEY_SHA256
    )
    shutil.copy(ROOT / "attest_verify.py", tmp_path / "attest_verify.py")
    (tmp_path / "rekor.pub").write_text("not the pinned key")
    env = tmp_path / "e.dsse.json"
    shutil.copy(VEC, env)
    d = json.loads(env.read_text())
    d["anchors"] = [{"x": 1}]
    env.write_text(json.dumps(d))
    key = ROOT / "vectors" / "test_key.pub.hex"
    pin = hashlib.sha256(bytes.fromhex(key.read_text().strip())).hexdigest()
    r = subprocess.run(
        [
            sys.executable,
            str(tmp_path / "attest_verify.py"),
            str(env),
            "--key",
            str(key),
            "--expect-keyid",
            pin,
            "--check-anchors",
        ],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 6 and "pinned sha256" in r.stderr


def test_mixed_order_key_rejected_with_reason():
    raw = bytes.fromhex(
        (ROOT / "vectors" / "10_mixed_order_key.pub.hex").read_text().strip()
    )
    why = av.strict_ed25519_ok(raw, PRIV.sign(b"m"))
    assert "prime-order" in why
    good = bytes.fromhex((ROOT / "vectors" / "test_key.pub.hex").read_text().strip())
    assert av.strict_ed25519_ok(good, PRIV.sign(b"m")) == ""
    assert av.prime_order(av.decompress(good))


def test_new_predicate_types_known_and_unknown_still_exit_5():
    for t in (
        "dejaspawn/evidence/v1",
        "mictest/participant/v1",
        "halflife/receipt/v1",
        "canceltogether/campaign/v1",
        "buyatheorem/lemma/v1",
    ):
        assert av.BASE + t in av.KNOWN
    assert av.BASE + "nope/x/v1" not in av.KNOWN
