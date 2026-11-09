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


PTYPE = av.BASE + "halflife/receipt/v1"
PRED = {
    "producer": {"tool": "t", "version": "1"},
    "started": "2026-11-09T00:00:00Z",
    "ended": "2026-11-09T00:00:01Z",
    "environment": {"host_os": "linux", "run_mode": "REAL"},
}


def env(path, signers, digest=SHA, tamper=False, ptype=PTYPE, pred=None):
    st = {
        "_type": av.STATEMENT_TYPE,
        "subject": [{"name": "pkg.tgz", "digest": {"sha256": digest}}],
        "predicateType": ptype,
        "predicate": PRED if pred is None else pred,
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


def test_one_envelope_two_signers_is_enough(tmp_path):
    # SPEC s12 (1.5): envelopes are containers; two distinct keys signed, so the policy is met.
    ci, mt, cid, mid, keys = setup()
    e1 = env(tmp_path / "a.json", [ci, mt])
    assert run(tmp_path, [e1], [cid, mid], keys) == 0


def test_same_keyid_twice_in_one_envelope_counts_once(tmp_path):
    ci, mt, cid, mid, keys = setup()
    e1 = env(tmp_path / "a.json", [ci, ci])
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


def _both(tmp_path):
    ci, mt, cid, mid, keys = setup()
    return env(tmp_path / "a.json", [ci, mt]), cid, mid, keys


def test_same_envelope_path_twice_rejected(tmp_path):
    a, cid, mid, keys = _both(tmp_path)
    assert run(tmp_path, [a], [cid, mid], keys) == 0
    assert run(tmp_path, [a, a], [cid, mid], keys) == 2


def test_byte_copy_rejected(tmp_path):
    a, cid, mid, keys = _both(tmp_path)
    b = tmp_path / "copy.json"
    b.write_bytes(Path(a).read_bytes())
    assert run(tmp_path, [a, str(b)], [cid, mid], keys) == 2


def test_reordered_signatures_rejected(tmp_path):
    a, cid, mid, keys = _both(tmp_path)
    e = json.loads(Path(a).read_text())
    e["signatures"].reverse()
    b = tmp_path / "rev.json"
    b.write_text(json.dumps(e))
    assert run(tmp_path, [a, str(b)], [cid, mid], keys) == 2


def test_rewrapped_with_extra_signature_rejected(tmp_path):
    ci, mt, cid, mid, keys = setup()
    x = Ed25519PrivateKey.generate()
    a = env(tmp_path / "a.json", [ci, mt])
    b = env(
        tmp_path / "b.json", [mt, x]
    )  # mt's signature bytes equal those in a (Ed25519 is deterministic)
    assert run(tmp_path, [a, b], [cid, mid], keys + [raw_of(x)]) == 2
    c = env(tmp_path / "c.json", [mt])  # the subset re-wrap is the same signing act too
    assert run(tmp_path, [a, c], [cid, mid], keys) == 2


def test_unknown_predicate_type_is_5(tmp_path):
    ci, mt, cid, mid, keys = setup()
    e1 = env(tmp_path / "a.json", [ci], ptype="https://example.com/p/v1")
    e2 = env(tmp_path / "b.json", [mt])
    assert run(tmp_path, [e1, e2], [cid, mid], keys) == 5


def test_missing_mandatory_predicate_is_4(tmp_path):
    ci, mt, cid, mid, keys = setup()
    e1 = env(tmp_path / "a.json", [ci], pred={})
    e2 = env(tmp_path / "b.json", [mt])
    assert run(tmp_path, [e1, e2], [cid, mid], keys) == 4


def test_split_into_two_envelopes_same_statement(tmp_path):
    # repackaging a dual-signed envelope into two single-signer ones: both keys did sign, nothing counted twice
    ci, mt, cid, mid, keys = setup()
    e1, e2 = env(tmp_path / "a.json", [ci]), env(tmp_path / "b.json", [mt])
    assert run(tmp_path, [e1, e2], [cid, mid], keys) == 0


def test_matching_needs_augmenting_path(tmp_path):
    # e1 signed by ci+mt, e2 by ci only: a greedy pick of e1 for ci would fail; matching must give ci->e2, mt->e1.
    # Same statement, so e2's ci signature equals e1's: use a different artifact-naming statement for e2.
    ci, mt, cid, mid, keys = setup()
    e1 = env(tmp_path / "a.json", [ci, mt])
    e2 = env(tmp_path / "b.json", [ci], pred=dict(PRED, ended="2026-11-09T00:00:02Z"))
    assert run(tmp_path, [e1, e2], [cid, mid], keys) == 0


def test_reserialised_copy_rejected(tmp_path):
    a, cid, mid, keys = _both(tmp_path)
    e = json.loads(Path(a).read_text())
    b = tmp_path / "reser.json"
    b.write_text(
        json.dumps({k: e[k] for k in reversed(list(e))}, indent=3, sort_keys=False)
    )
    assert Path(a).read_bytes() != b.read_bytes()
    assert run(tmp_path, [a, str(b)], [cid, mid], keys) == 2
