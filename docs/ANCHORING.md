# Anchoring (Rekor) - design only, not implemented

No network call exists in this repo. This describes what `--anchor rekor` would do.

1. Compute `d = sha256(bytes of the *.dsse.json file)`.
2. Create a Rekor `hashedrekord` entry: the artefact hash is `d`, the signature is the envelope's ed25519 signature,
   and the public key is the producer's key.
3. Store the returned entry (logIndex, logID, integratedTime, signed entry timestamp, inclusion proof and checkpoint)
   in the envelope under a top-level `anchors[]` array. Anchors sit outside the signed payload, so adding one does
   not change the signature.
4. Offline verification checks the Merkle inclusion proof against the embedded checkpoint; no network is needed.

What it publishes: the envelope digest, the public key and the signature, to a public append-only log, permanently.
Entries cannot be deleted. Nothing about the artefact contents is published, but the digest and key link every
anchored artefact to the producer.

Why founder-gated: it is irreversible, discloses the producer identity (key), and takes a network dependency.
It is default OFF and runs only with an explicit `--anchor rekor` flag, after a founder go-ahead for the specific key.
The key's first log entry is also pin source (c) in SPEC section 7.
