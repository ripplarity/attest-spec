import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import attest_verify as av

ART = b"artifact-bytes"
SHA = hashlib.sha256(ART).hexdigest()


def raw_of(k):
    return k.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def env(path, signers, digest=SHA, tamper=False):
    st = {
        "_type": av.STATEMENT_TYPE,
        "subject": [{"name": "pkg.tgz", "digest": {"sha256": digest}}],
        "predicateType": "https://example.com/p/v1",
        "predicate": {},
    }
    payload = json.dumps(st).encode()
    sigs = [
        {
            "keyid": av.keyid(raw_of(k)),
            "sig": base64.b64encode(k.sign(av.pae(av.PAYLOAD_TYPE, payload))).decode(),
        }
        for k in signers
    ]
    if tamper:
        payload = payload.replace(b"pkg.tgz", b"pkh.tgz")
    path.write_text(
        json.dumps(
            {
                "payloadType": av.PAYLOAD_TYPE,
                "payload": base64.b64encode(payload).decode(),
                "signatures": sigs,
            }
        )
    )
    return str(path)


def run(tmp, envs, req, keys):
    art = tmp / "pkg.tgz"
    art.write_bytes(ART)
    kf = tmp / "keys.json"
    kf.write_text(json.dumps({"keys": [{"public_key_hex": r.hex()} for r in keys]}))
    args = list(envs) + ["--key", str(kf), "--artifact", str(art)]
    for r in req:
        args += ["--require-keyid", r]
    return av.main(args)


def setup():
    ci, mt = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    return ci, mt, av.keyid(raw_of(ci)), av.keyid(raw_of(mt)), [raw_of(ci), raw_of(mt)]


def test_valid_pass(tmp_path):
    ci, mt, cid, mid, keys = setup()
    e1, e2 = env(tmp_path / "a.json", [ci]), env(tmp_path / "b.json", [mt])
    assert run(tmp_path, [e1, e2], [cid, mid], keys) == 0


def test_only_ci(tmp_path):
    ci, mt, cid, mid, keys = setup()
    assert run(tmp_path, [env(tmp_path / "a.json", [ci])], [cid, mid], keys) == 2


def test_only_maintainer(tmp_path):
    ci, mt, cid, mid, keys = setup()
    assert run(tmp_path, [env(tmp_path / "b.json", [mt])], [cid, mid], keys) == 2


def test_same_key_twice(tmp_path):
    ci, mt, cid, mid, keys = setup()
    e1, e2 = env(tmp_path / "a.json", [ci]), env(tmp_path / "b.json", [ci])
    assert run(tmp_path, [e1, e2], [cid, cid], keys) == 2
    assert run(tmp_path, [e1, e2], [cid, mid], keys) == 2


def test_one_envelope_two_signers_not_enough(tmp_path):
    ci, mt, cid, mid, keys = setup()
    e1 = env(tmp_path / "a.json", [ci, mt])
    assert run(tmp_path, [e1], [cid, mid], keys) == 2


def test_digest_mismatch(tmp_path):
    ci, mt, cid, mid, keys = setup()
    e1 = env(tmp_path / "a.json", [ci])
    e2 = env(tmp_path / "b.json", [mt], digest="0" * 64)
    assert run(tmp_path, [e1, e2], [cid, mid], keys) == 3


def test_tampered_payload(tmp_path):
    ci, mt, cid, mid, keys = setup()
    e1 = env(tmp_path / "a.json", [ci])
    e2 = env(tmp_path / "b.json", [mt], tamper=True)
    assert run(tmp_path, [e1, e2], [cid, mid], keys) == 2


def test_unreadable_envelope(tmp_path):
    ci, mt, cid, mid, keys = setup()
    e1 = env(tmp_path / "a.json", [ci])
    bad = tmp_path / "b.json"
    bad.write_text("{")
    assert run(tmp_path, [e1, str(bad)], [cid, mid], keys) == 4


def test_require_keyid_must_be_exact_lowercase_hex(tmp_path):
    ci, mt, cid, mid, keys = setup()
    e1, e2 = env(tmp_path / "a.json", [ci]), env(tmp_path / "b.json", [mt])
    assert run(tmp_path, [e1, e2], [cid.upper(), mid], keys) == 2
    assert run(tmp_path, [e1, e2], [" " + cid, mid], keys) == 2
    assert run(tmp_path, [e1, e2], [cid[:-1], mid], keys) == 2
