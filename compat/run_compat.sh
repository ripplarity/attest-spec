#!/usr/bin/env bash
# Compatibility run: verify every committed *.dsse.json in the public consumer repos with a given verifier.
# Usage: bash compat/run_compat.sh --verifier <path to attest_verify.py> [--keyid name=hex ...] [--out compat/DATE.md]
# Read-only: shallow clones go to a temp dir that is deleted on exit; the only network use is the two clones.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "${PYTHON:-python}" - "$HERE" "$@" <<'PY'
import datetime, glob, hashlib, os, re, shutil, subprocess, sys, tempfile

here, args = sys.argv[1], sys.argv[2:]
verifier, overrides, out = None, {}, None
i = 0
while i < len(args):
    if args[i] == "--verifier":
        verifier = args[i + 1]; i += 2
    elif args[i] == "--keyid":
        k, v = args[i + 1].split("=", 1); overrides[k] = v.lower(); i += 2
    elif args[i] == "--out":
        out = args[i + 1]; i += 2
    else:
        sys.exit("usage: run_compat.sh --verifier PATH [--keyid name=hex] [--out FILE]")
if not verifier or not os.path.isfile(verifier):
    sys.exit("--verifier <path to attest_verify.py> is required")
verifier = os.path.abspath(verifier)
today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
out = out or os.path.join(here, today + ".md")
REPOS = {n: f"https://github.com/ripplarity/{n}" for n in ("stillherd", "dejaspawn")}
HEX64 = re.compile(r"\b[0-9a-f]{64}\b")
# keyid grep: a line mentioning "keyid" in the README, first 64-hex token on it (or the next line)
KEYID_RE = re.compile(r"keyid[^\n]*?([0-9a-f]{64})", re.I)


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def readme_keyid(root):
    for name in ("README.md", "readme.md", "README"):
        p = os.path.join(root, name)
        if os.path.isfile(p):
            m = KEYID_RE.search(open(p, encoding="utf-8", errors="replace").read())
            if m:
                return m.group(1).lower()
    return None


def find_key(root, file, kid):
    """pubkey hex: *.pub.hex / pubkey.hex / keys.json beside the file or above it; else a README hex whose sha256 is the keyid."""
    d = os.path.dirname(file)
    while True:
        for pat in ("*.pub.hex", "pubkey.hex", "keys.json"):
            for c in sorted(glob.glob(os.path.join(d, pat))):
                return c
        if os.path.abspath(d) == os.path.abspath(root):
            break
        d = os.path.dirname(d)
    rp = os.path.join(root, "README.md")
    if os.path.isfile(rp):
        for h in HEX64.findall(open(rp, encoding="utf-8", errors="replace").read()):
            if hashlib.sha256(bytes.fromhex(h)).hexdigest() == kid:
                return h
    return None


rows, notes = [], []
tmp = tempfile.mkdtemp(prefix="attest-compat-")
try:
    for name, url in REPOS.items():
        dest = os.path.join(tmp, name)
        r = subprocess.run(["git", "clone", "--depth", "1", "--quiet", url, dest], capture_output=True, text=True)
        if r.returncode:
            notes.append(f"- {name}: clone failed: {(r.stderr.strip().splitlines() or ['?'])[-1]}")
            rows.append((name, "(clone failed)", "", "-", (r.stderr.strip().splitlines() or ["?"])[-1]))
            continue
        head = subprocess.run(["git", "-C", dest, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
        kid = overrides.get(name) or readme_keyid(dest)
        notes.append(f"- {name}: commit {head}, keyid {kid or 'NOT FOUND in README (use --keyid %s=hex)' % name}")
        files = sorted(
            os.path.join(dp, f)
            for dp, dn, fn in os.walk(dest) if ".git" not in dp.split(os.sep)
            for f in fn if f.endswith(".dsse.json")
        )
        if not files:
            rows.append((name, "(no *.dsse.json committed)", "", "-", ""))
        for f in files:
            rel = os.path.relpath(f, dest).replace(os.sep, "/")
            key = find_key(dest, f, kid) if kid else None
            if not kid or not key:
                why = "no pinned keyid" if not kid else "no public key found"
                rows.append((name, rel, sha(f), "SKIP", why))
                continue
            p = subprocess.run(
                [sys.executable, verifier, f, "--key", key, "--expect-keyid", kid],
                capture_output=True, text=True,
            )
            lines = (p.stdout + p.stderr).strip().splitlines()
            rows.append((name, rel, sha(f), str(p.returncode), lines[0] if lines else ""))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

dist = {}
for r in rows:
    dist[r[3]] = dist.get(r[3], 0) + 1
with open(out, "w", encoding="utf-8", newline="\n") as fh:
    fh.write(f"# Compatibility run {today} (UTC)\n\n")
    fh.write(f"Verifier: `{os.path.basename(verifier)}` sha256 `{sha(verifier)}`\n\n")
    fh.write("\n".join(notes) + "\n\n")
    fh.write("| repo | file | sha256 | rc | first output line |\n|---|---|---|---|---|\n")
    for r in rows:
        fh.write("| " + " | ".join(c.replace("|", "/") for c in r) + " |\n")
    fh.write("\nrc distribution: " + ", ".join(f"{k}={v}" for k, v in sorted(dist.items())) + "\n")
print(f"wrote {out}; rc distribution: {dist}")
PY
