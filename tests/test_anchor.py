import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import anchor
import attest_verify as av

VEC = ROOT / "vectors" / "01_sovkit_inventory_valid.dsse.json"
PRIV = Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex((ROOT / "vectors" / "test_key.ed25519").read_text().strip())
)
PUBHEX = str(ROOT / "vectors" / "test_key.pub.hex")
PIN = hashlib.sha256(bytes.fromhex(open(PUBHEX).read().strip())).hexdigest()


def H(b):
    return hashlib.sha256(b).digest()


def mth(leaves):
    if len(leaves) == 1:
        return H(b"\x00" + leaves[0])
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return H(b"\x01" + mth(leaves[:k]) + mth(leaves[k:]))


def path(m, leaves):
    """RFC 6962 PATH(m, D[n])."""
    n = len(leaves)
    if n == 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if m < k:
        return path(m, leaves[:k]) + [mth(leaves[k:])]
    return path(m - k, leaves[k:]) + [mth(leaves[:k])]


class FakeRekor:
    """Synthetic log: 3 pre-existing leaves + ours (index 3 of 4)."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.pre = [b"leaf-a", b"leaf-b", b"leaf-c"]

    def post(self, url, data):
        assert url.endswith("/api/v1/log/entries")
        body = json.dumps(
            json.loads(data), sort_keys=True, separators=(",", ":")
        ).encode()
        leaves = self.pre + [body]
        root = mth(leaves)
        b64 = base64.b64encode(body).decode()
        set_payload = json.dumps(
            {"body": b64, "integratedTime": 1700000000, "logID": "abcd", "logIndex": 3},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        cp = "rekor.test\n4\n" + base64.b64encode(root).decode() + "\n"
        return {
            "uuid-1": {
                "body": b64,
                "integratedTime": 1700000000,
                "logID": "abcd",
                "logIndex": 3,
                "verification": {
                    "signedEntryTimestamp": base64.b64encode(
                        self.key.sign(set_payload, ec.ECDSA(hashes.SHA256()))
                    ).decode(),
                    "inclusionProof": {
                        "logIndex": 3,
                        "treeSize": 4,
                        "rootHash": root.hex(),
                        "hashes": [h.hex() for h in path(3, leaves)],
                        "checkpoint": cp,
                    },
                },
            }
        }


@pytest.fixture
def anchored(tmp_path):
    env = tmp_path / "e.dsse.json"
    shutil.copy(VEC, env)
    fr = FakeRekor()
    anchor.anchor_rekor(env, PRIV, post=fr.post)
    (tmp_path / "rekor.pub").write_bytes(fr.pem)
    return env, fr, tmp_path


def run(env, pem, *extra):
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "attest_verify.py"),
            str(env),
            "--key",
            PUBHEX,
            "--expect-keyid",
            PIN,
            "--check-anchors",
            "--rekor-key",
            str(pem),
            *extra,
        ],
        capture_output=True,
        text=True,
    )


def mutate(env, fn):
    d = json.loads(env.read_text())
    fn(d["anchors"][0])
    env.write_text(json.dumps(d))


def test_anchor_stored_outside_signed_bytes_and_verifies(anchored):
    env, fr, tmp = anchored
    d = json.loads(env.read_text())
    assert len(d["anchors"]) == 1 and d["anchors"][0]["inclusionProof"]["treeSize"] == 4
    r = run(env, tmp / "rekor.pub")
    assert r.returncode == 0 and "ANCHORS-OK 1" in r.stdout


def test_tampered_proof_hash_exit6(anchored):
    env, fr, tmp = anchored

    def f(a):
        h = a["inclusionProof"]["hashes"]
        h[0] = "00" * 32

    mutate(env, f)
    assert run(env, tmp / "rekor.pub").returncode == 6


def test_wrong_root_exit6(anchored):
    env, fr, tmp = anchored
    mutate(env, lambda a: a["inclusionProof"].__setitem__("rootHash", "11" * 32))
    assert run(env, tmp / "rekor.pub").returncode == 6


def test_wrong_set_key_exit6(anchored):
    env, fr, tmp = anchored
    other = FakeRekor()
    (tmp / "other.pub").write_bytes(other.pem)
    assert run(env, tmp / "other.pub").returncode == 6


def test_set_over_altered_integrated_time_exit6(anchored):
    env, fr, tmp = anchored
    mutate(env, lambda a: a.__setitem__("integratedTime", 1700000001))
    assert run(env, tmp / "rekor.pub").returncode == 6


def test_envelope_changed_after_anchoring_exit6(anchored):
    env, fr, tmp = anchored
    d = json.loads(env.read_text())
    d["signatures"][0]["keyid"] = "00" * 32
    env.write_text(json.dumps(d))
    assert (
        run(env, tmp / "rekor.pub").returncode != 0
    )  # signature check fails first (2)


def test_no_anchors_prints_and_keeps_rc():
    r = subprocess.run(
        [
            sys.executable,
            str(ROOT / "attest_verify.py"),
            str(VEC),
            "--key",
            PUBHEX,
            "--expect-keyid",
            PIN,
            "--check-anchors",
        ],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0 and "NO-ANCHORS" in r.stdout


def test_merkle_all_indexes_and_sizes():
    for n in range(1, 9):
        leaves = [bytes([i]) * 3 for i in range(n)]
        root = mth(leaves)
        for i in range(n):
            assert av.verify_inclusion(
                i, n, H(b"\x00" + leaves[i]), path(i, leaves), root
            )
            assert not av.verify_inclusion(
                i, n, H(b"\x00" + b"x"), path(i, leaves), root
            )


def test_gate_refuses_without_env(tmp_path, monkeypatch):
    monkeypatch.delenv("ATTEST_ANCHOR_OK", raising=False)
    env = tmp_path / "e.dsse.json"
    shutil.copy(VEC, env)
    with pytest.raises(anchor.AnchorGateError, match="maintainer approval"):
        anchor.anchor_rekor(env, PRIV)
    r = subprocess.run(
        [
            sys.executable,
            str(ROOT / "anchor.py"),
            str(env),
            "--key",
            str(ROOT / "vectors" / "test_key.ed25519"),
            "--anchor",
            "rekor",
        ],
        capture_output=True,
        text=True,
        env={k: v for k, v in os.environ.items() if k != "ATTEST_ANCHOR_OK"},
    )
    assert r.returncode == 7 and "ATTEST_ANCHOR_OK" in r.stderr
    assert "anchors" not in json.loads(env.read_text())
