#!/usr/bin/env python3
"""Opt-in Rekor anchoring for a DSSE envelope (SPEC section 8). Stdlib + cryptography.

Usage: ATTEST_ANCHOR_OK=1 python anchor.py <envelope.dsse.json> --key <ed25519 private key hex file>
                                           --anchor rekor [--rekor-url URL]

This PUBLISHES the envelope digest, signature and public key to a public append-only log,
permanently. It requires explicit maintainer approval: without ATTEST_ANCHOR_OK=1 nothing is sent.
The transport is injectable (`post=`) so tests never touch the network.
"""

import argparse
import base64
import json
import os
import sys
import urllib.request

from attest_verify import envelope_digest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT_URL = "https://rekor.sigstore.dev"
GATE_MSG = (
    "refused: anchoring publishes the envelope digest, signature and public key to a public log "
    "permanently. It requires explicit maintainer approval; set ATTEST_ANCHOR_OK=1 only after that approval."
)


class AnchorGateError(Exception):
    pass


def build_entry(env: dict, priv: Ed25519PrivateKey) -> dict:
    """hashedrekord v0.0.1 proposed entry: digest of the envelope (anchors removed), ed25519
    signature over the 32 raw digest bytes, our public key as PEM."""
    digest = envelope_digest(env)
    sig = priv.sign(bytes.fromhex(digest))
    pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": digest}},
            "signature": {
                "content": base64.b64encode(sig).decode(),
                "publicKey": {"content": base64.b64encode(pem).decode()},
            },
        },
    }


def _urllib_post(url: str, data: bytes) -> dict:
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def anchor_rekor(envelope_path, key, rekor_url=DEFAULT_URL, post=None):
    """Anchor the envelope file and store the entry under anchors[] (outside the signed bytes).
    `key` is an Ed25519PrivateKey. `post(url, bytes) -> dict` is the transport; the default
    (real network) is refused unless ATTEST_ANCHOR_OK=1."""
    if post is None:
        if os.environ.get("ATTEST_ANCHOR_OK") != "1":
            raise AnchorGateError(GATE_MSG)
        post = _urllib_post
    env = json.load(open(envelope_path, encoding="utf-8"))
    entry = build_entry(env, key)
    resp = post(
        rekor_url.rstrip("/") + "/api/v1/log/entries", json.dumps(entry).encode()
    )
    ((uuid, rec),) = resp.items()
    ver = rec["verification"]
    anchor = {
        "type": "rekor",
        "url": rekor_url,
        "uuid": uuid,
        "logIndex": rec["logIndex"],
        "integratedTime": rec["integratedTime"],
        "logID": rec["logID"],
        "body": rec["body"],
        "signedEntryTimestamp": ver["signedEntryTimestamp"],
        "inclusionProof": ver["inclusionProof"],
    }
    env.setdefault("anchors", []).append(anchor)
    with open(envelope_path, "w", encoding="utf-8") as f:
        json.dump(env, f, indent=2)
        f.write("\n")
    return anchor


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("envelope")
    ap.add_argument(
        "--key", required=True, help="file with the ed25519 private key (hex seed)"
    )
    ap.add_argument("--anchor", required=True, choices=["rekor"])
    ap.add_argument("--rekor-url", default=DEFAULT_URL)
    a = ap.parse_args(argv)
    if os.environ.get("ATTEST_ANCHOR_OK") != "1":
        print(GATE_MSG, file=sys.stderr)
        return 7
    seed = bytes.fromhex(open(a.key).read().strip())
    an = anchor_rekor(
        a.envelope, Ed25519PrivateKey.from_private_bytes(seed), a.rekor_url
    )
    print(f"ANCHORED logIndex={an['logIndex']} uuid={an['uuid']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
