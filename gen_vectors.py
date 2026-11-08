#!/usr/bin/env python3
"""Regenerate vectors/ deterministically from the TEST-ONLY key (ed25519 is deterministic)."""

import base64
import hashlib
import json
import os

from attest_verify import BASE, PAYLOAD_TYPE, keyid, pae
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

V = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")
seed = hashlib.sha256(b"attest-spec TEST-ONLY key").digest()
priv = Ed25519PrivateKey.from_private_bytes(seed)
raw = priv.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
open(f"{V}/test_key.ed25519", "w").write(seed.hex() + "\n")
open(f"{V}/test_key.pub.hex", "w").write(raw.hex() + "\n")


def canon(o):
    return json.dumps(
        o, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def stmt(ptype, name, extra):
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": name,
                "digest": {"sha256": hashlib.sha256(name.encode()).hexdigest()},
            }
        ],
        "predicateType": ptype,
        "predicate": {
            "producer": {"tool": "vector-gen", "version": "0.1.0"},
            "started": "2026-01-01T00:00:00Z",
            "ended": "2026-01-01T00:00:01Z",
            "environment": {"host_os": "test", "run_mode": "FIXTURE"},
            **extra,
        },
    }


def env(payload, tweak=None):
    sig = priv.sign(pae(PAYLOAD_TYPE, payload))
    if tweak:
        sig = tweak(sig)
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": keyid(raw), "sig": base64.b64encode(sig).decode()}],
    }


def put(name, e, code, valid, reason):
    with open(f"{V}/{name}.dsse.json", "w") as f:
        json.dump(e, f, indent=2)
        f.write("\n")
    with open(f"{V}/{name}.expected.json", "w") as f:
        json.dump({"valid": valid, "exit_code": code, "reason": reason}, f, indent=2)
        f.write("\n")


inv = canon(
    stmt(
        BASE + "sovkit/inventory/v1", "inventory.json", {"objects": 3, "tenant": "tést"}
    )
)
drl = canon(
    stmt(BASE + "sovkit/drill/v1", "drill.json", {"copied": 3, "diff_empty": True})
)
man = canon(
    stmt(
        BASE + "aiescrow/manifest/v1",
        "manifest.json",
        {"escrow_id": "00000000-0000-0000-0000-000000000000"},
    )
)
put("01_sovkit_inventory_valid", env(inv), 0, True, "valid")
put("02_sovkit_drill_valid", env(drl), 0, True, "valid")
put("03_aiescrow_manifest_valid", env(man), 0, True, "valid")
put(
    "04_bad_signature",
    env(inv, lambda s: bytes([s[0] ^ 1]) + s[1:]),
    2,
    False,
    "signature does not verify",
)
e = env(inv)
b = bytearray(inv)
b[40] ^= 1
e["payload"] = base64.b64encode(bytes(b)).decode()
put("05_mutated_payload", e, 2, False, "payload byte changed after signing")
unk = canon(stmt("https://example.com/other/v1", "x.bin", {}))
put(
    "06_unknown_predicate_type",
    env(unk),
    5,
    True,
    "signature valid, unknown predicateType warns",
)
