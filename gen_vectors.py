#!/usr/bin/env python3
"""Regenerate vectors/ deterministically from the TEST-ONLY key (ed25519 is deterministic)."""

import base64
import hashlib
import json
import os

from attest_verify import _L, _P, BASE, PAYLOAD_TYPE, decompress, jcs, keyid, pae
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


def env(payload, tweak=None, kid=None):
    sig = priv.sign(pae(PAYLOAD_TYPE, payload))
    if tweak:
        sig = tweak(sig)
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {"keyid": kid or keyid(raw), "sig": base64.b64encode(sig).decode()}
        ],
    }


def put(name, e, code, valid, reason, key=None):
    with open(f"{V}/{name}.dsse.json", "w", newline="\n") as f:
        json.dump(e, f, indent=2)
        f.write("\n")
    exp = {"valid": valid, "exit_code": code, "reason": reason}
    if key:
        exp["key"] = key
    with open(f"{V}/{name}.expected.json", "w", newline="\n") as f:
        json.dump(exp, f, indent=2)
        f.write("\n")


inv = jcs(
    stmt(
        BASE + "sovkit/inventory/v1", "inventory.json", {"objects": 3, "tenant": "tést"}
    )
)
drl = jcs(
    stmt(BASE + "sovkit/drill/v1", "drill.json", {"copied": 3, "diff_empty": True})
)
man = jcs(
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
unk = jcs(stmt("https://example.com/other/v1", "x.bin", {}))
put(
    "06_unknown_predicate_type",
    env(unk),
    5,
    True,
    "signature valid, unknown predicateType warns",
)

# strictness vectors (RFC 8032): all INVALID, rc 2
put(
    "07_noncanonical_s",
    env(
        inv,
        lambda s: (
            s[:32] + (int.from_bytes(s[32:], "little") + _L).to_bytes(32, "little")
        ),
    ),
    2,
    False,
    "S >= L (malleable signature) must be rejected",
)
identity = (1).to_bytes(32, "little")  # point (0,1): small order
open(f"{V}/08_small_order_key.pub.hex", "w").write(identity.hex() + "\n")
put(
    "08_small_order_key",
    env(inv, lambda s: identity + bytes(32), kid=keyid(identity)),
    2,
    False,
    "small-order public key must be rejected",
    key="vectors/08_small_order_key.pub.hex",
)
y = 2
while decompress(y.to_bytes(32, "little")) is not None:
    y += 1
assert y < _P
put(
    "09_malformed_r",
    env(inv, lambda s: y.to_bytes(32, "little") + s[32:]),
    2,
    False,
    "R is not a valid curve point",
)

# vector 10: mixed-order key A' = A + T, T an 8-torsion point of order 8 (not prime-order: [L]A' != O)
from attest_verify import _add, _mul, encode_point, prime_order  # noqa: E402

yy = 2
while True:
    q = decompress(yy.to_bytes(32, "little"))
    if q is not None:
        t = _mul(_L, q)
        if _mul(4, t) != (0, 1):  # order exactly 8
            break
    yy += 1
mixed = encode_point(_add(decompress(raw), t))
assert not prime_order(decompress(mixed)) and decompress(mixed) is not None
open(f"{V}/10_mixed_order_key.pub.hex", "w").write(mixed.hex() + "\n")
put(
    "10_mixed_order_key",
    env(inv, kid=keyid(mixed)),
    2,
    False,
    "public key has a torsion component ([L]A != O) and must be rejected",
    key="vectors/10_mixed_order_key.pub.hex",
)


# ---- verdict predicateType (SPEC 6.1) ----
def _verdict(controls):
    def h(s):
        return hashlib.sha256(s.encode()).hexdigest()

    return {
        "claim": {
            "text": "tool X rejects empty input",
            "source_url": "https://example.com/claim",
        },
        "subject_tool": {"name": "example-tool", "version": "1.0.0"},
        "probe": {"id": "empty-input", "version": "1", "sha256": h("probe-code")},
        "inputs_digest": h("inputs"),
        "controls": controls,
        "result": "PASS",
        "transcript_digest": h("transcript"),
        "observed_at": "2026-01-01T00:00:00Z",
    }


_ok = [
    {"name": "known-good input accepted", "kind": "positive", "expected": "accept", "observed": "accept"},
    {"name": "known-bad input rejected", "kind": "negative", "expected": "reject", "observed": "reject"},
]
_bad = [dict(_ok[0], observed="reject"), _ok[1]]
_bad_inc = dict(_verdict(_bad), result="INCONCLUSIVE")
_bad_pass = _verdict(_bad)


def _vput(name, pred, why):
    stm = stmt(BASE + "verdict/v1", "transcript.txt", pred)
    stm["subject"][0]["digest"]["sha256"] = pred["transcript_digest"]
    put(name, env(jcs(stm)), 0, True, why)
    e = json.load(open(f"{V}/{name}.expected.json"))
    e["verdict_check_exit_code"] = 8 if "control" in why else 0
    with open(f"{V}/{name}.expected.json", "w", newline="\n") as f:
        json.dump(e, f, indent=2)
        f.write("\n")


_vput("11_verdict_valid", _verdict(_ok), "valid")
_vput("12_verdict_failed_control", dict(_verdict(_bad), result="FAIL"), "good signature, control failed: record valid, verdict not accepted")
_vput("13_verdict_inconclusive_failed_control", _bad_inc, "good signature, control failed (INCONCLUSIVE kept as evidence)")
_vput("14_verdict_pass_failed_control", _bad_pass, "good signature, control failed with PASS: not accepted")
