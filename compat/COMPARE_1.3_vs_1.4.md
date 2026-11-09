# Compatibility comparison: verifier 1.3 vs 1.4

1.3 verifier sha256 `ab2681f145e5479dd07a37333a95f3179424ff1c8b94b9cb54bcb3742bbdd5d0` (compat/2026-11-09.md)
1.4 verifier sha256 `51da005156826521b9a55ecf2ad3b5eb2aeb8cf85fb9ba70f231bfce55403687` (shipping verifier, compat/2026-11-09_v1.4c.md; rc-for-rc identical to the earlier 1.4 runs with shas `89fd3a54...` (compat/2026-11-09_v1.4b.md) and `92310326...` (compat/2026-11-09_v1.4.md), 13 files)

| repo | file | file sha256 | rc 1.3 | rc 1.4 | same |
|---|---|---|---|---|---|
| dejaspawn | demo/2026-11-08-self-nuke/attestations/20261108T221012Z-mirror-stripe.json.dsse.json | 2e65742bc437bdb699a5fc4227f3dc039615f1c62c0990c77c6e84f2ac53c954 | 0 | 0 | yes |
| dejaspawn | demo/2026-11-08-self-nuke/attestations/20261108T221015Z-mirror-github.json.dsse.json | e5d22bca927ac0cd0a42cfbc66f7244fa4d12a78ec9572fd4fc5497098980b3b | 0 | 0 | yes |
| dejaspawn | demo/2026-11-08-self-nuke/attestations/20261108T221657Z-drill.json.dsse.json | 38d0e8a84e58b000e93e3bb3b6c4824d5bb94da8a680d43e5cb29b4a39f6ec5a | 0 | 0 | yes |
| dejaspawn | demo/2026-11-08-self-nuke/attestations/20261108T221711Z-mirror-stripe.json.dsse.json | 3b8778487b2d9ffb8bedb6af6a8def5d6711b7e15d828f27f830ebf22cc37242 | 0 | 0 | yes |
| dejaspawn | demo/2026-11-08-self-nuke/attestations/20261108T222131Z-mirror-cloudflare.json.dsse.json | c55141478f11d149b5a5d94f818e2f7de1f700710529d5cd2a4d7a104e8e03de | 0 | 0 | yes |
| dejaspawn | demo/2026-11-08-self-nuke/attestations/20261108T222136Z-drill.json.dsse.json | 209c4a2383a3af6f729f20d7e4a599169df4c933f742cea9bbb983e340c23fca | 0 | 0 | yes |
| dejaspawn | examples/drill_attestation_mock.dsse.json | 15fe0c102a47fce6500a26111cf5d6b61739a057ec2404f629395cdf2857f746 | 0 | 0 | yes |
| stillherd | examples/containment.dsse.json | 29b022efb27e09832f58e0b58e8acafb1b75ac512be9764de16cb8a19247ecff | 0 | 0 | yes |
| stillherd | exitkits/postman-to-hoppscotch/results/attestation.json | a6c31e331f15d6712dfdb443db8a379350f6016c05555c209b188d8821505332 | 4 | 4 | yes |
| stillherd | selfhost/results/hoppscotch.attestation.json | 6150dde25d9bcfa79d98e28258f6cef2e833d4baacaacd3ccc84198fc9f0f2df | 4 | 4 | yes |
| stillherd | selfhost/results/rocketchat.attestation.json | 43dba1f6569fc3f8e274e34eeaf6f388766383402188e365c19bb5dd6b32c7f9 | 4 | 4 | yes |
| stillherd | silent/attestation.json | ea2d9d1a17b90285987d276c4e77743eaba0f59c21e91f579e57dc354be0c0b7 | 4 | 4 | yes |
| stillherd | tests/fixtures/timeline/home/days/fx.dsse.json | 86db4d31fa777cdf6ccac522b7bfdd297da4d10f1c339a9c7bcdbca7aa9b3b76 | EXPECTED-FAIL (rc 4) | EXPECTED-FAIL (rc 4) | yes |

Files: 13. Verdict: IDENTICAL rc-for-rc.
