Test vectors. `test_key.ed25519` is a TEST-ONLY key: it is public and worthless; never trust it for anything.
Regenerate with `python gen_vectors.py` (from the repo root). Each `*.expected.json` gives `valid`, `exit_code`, `reason`.
Run all: `bash vectors/run.sh`.
