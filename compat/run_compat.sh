#!/usr/bin/env bash
# Compatibility run: verify every committed *.dsse.json in the public consumer repos with a given verifier.
# Usage: bash compat/run_compat.sh --verifier <path to attest_verify.py> [--keyid name=hex ...] [--out compat/DATE.md]
# Read-only: shallow clones go to <repo>/work/compat (gitignored) and are deleted on exit; the only network use is the two clones.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "${PYTHON:-python}" - "$HERE" "$@" <<'PY'
import datetime, glob, hashlib, os, re, shutil, subprocess, sys, tempfile

here, args = sys.argv[1], sys.argv[2:]
verifier, overrides, out, keep, extra = None, {}, None, False, {}
i = 0
while i < len(args):
    if args[i] == "--verifier":
        verifier = args[i + 1]; i += 2
    elif args[i] == "--keyid":
        k, v = args[i + 1].split("=", 1); overrides[k] = v.lower(); i += 2
    elif args[i] == "--repo":
        k, v = args[i + 1].split("=", 1); extra[k] = v; i += 2
    elif args[i] == "--keep":
        keep = True; i += 1
    elif args[i] == "--out":
        out = args[i + 1]; i += 2
    else:
        sys.exit("usage: run_compat.sh --verifier PATH [--keyid name=hex] [--repo name=URL_OR_LOCAL_PATH] [--out FILE]")
if not verifier or not os.path.isfile(verifier):
    sys.exit("--verifier <path to attest_verify.py> is required")
verifier = os.path.abspath(verifier)
today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
out = out or os.path.join(here, today + ".md")
REPOS = {n: f"https://github.com/ripplarity/{n}" for n in ("stillherd", "dejaspawn")}
REPOS.update(extra)  # --repo: extra repos, e.g. a local worktree path (git clone reads it, nothing is written there)
HEX64 = re.compile(r"\b[0-9a-f]{64}\b")
# keyid grep: a line mentioning "keyid" in the README, first 64-hex token on it (or the next line)
KEYID_RE = re.compile(r"keyid[^\n]*?([0-9a-f]{64})", re.I)


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def readme_keyid(root):
    """Root README first, then any README.md in the tree (for example silent/README.md)."""
    cands = [os.path.join(root, "README.md")] + sorted(
        glob.glob(os.path.join(root, "**", "README.md"), recursive=True)
    )
    for p in cands:
        if os.path.isfile(p) and ".git" not in p.split(os.sep):
            m = KEYID_RE.search(open(p, encoding="utf-8", errors="replace").read())
            if m:
                return m.group(1).lower()
    return None


def infile_key(file):
    """A 32-byte public key embedded in the attestation JSON itself (field `pubkey`, hex or base64), as hex."""
    import base64, json
    try:
        v = json.load(open(file, encoding="utf-8")).get("pubkey")
    except Exception:
        return None
    if not isinstance(v, str):
        return None
    if HEX64.fullmatch(v.lower()):
        return v.lower()
    try:
        raw = base64.b64decode(v, validate=True)
        return raw.hex() if len(raw) == 32 else None
    except Exception:
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
    k = infile_key(file)
    if k:
        return k
    # last resort: anywhere in the repo, a 64-hex string or a JSON `pubkey` (hex/base64) whose sha256 is the pinned keyid
    for dp, dn, fn in os.walk(root):
        if ".git" in dp.split(os.sep):
            continue
        for f in sorted(fn):
            q = os.path.join(dp, f)
            if os.path.getsize(q) > 300000:
                continue
            try:
                txt = open(q, encoding="utf-8").read()
            except (UnicodeDecodeError, OSError):
                continue
            cands = HEX64.findall(txt)
            if q.endswith(".json"):
                k2 = infile_key(q)
                if k2:
                    cands.append(k2)
            for h in cands:
                if hashlib.sha256(bytes.fromhex(h)).hexdigest() == kid:
                    return h
    return None


rows, notes = [], []
# clones live in the gitignored work/ folder inside the checkout, never in a system temp directory
tmp = os.path.join(os.path.dirname(here), "work", "compat")
def _rm(func, path, exc):
    os.chmod(path, 0o700)
    func(path)


if os.path.isdir(tmp):
    shutil.rmtree(tmp, onexc=_rm) if sys.version_info >= (3, 12) else shutil.rmtree(tmp, onerror=_rm)
os.makedirs(tmp, exist_ok=True)
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
            for f in fn if f.endswith((".dsse.json", ".attestation.json")) or f == "attestation.json"
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
            rc = str(p.returncode)
            if "tests/fixtures/" in rel and p.returncode:
                rc = f"EXPECTED-FAIL (rc {p.returncode})"  # fixture key is not the pinned production key
            first = lines[0] if lines else ""
            try:
                ver = str(__import__("json").load(open(f, encoding="utf-8")).get("version", ""))
            except Exception:
                ver = ""
            if p.returncode and ver.endswith("-silent-1"):
                first += f" [script note: legacy format {ver}, not a DSSE envelope]"
            rows.append((name, rel, sha(f), rc, first))
finally:
    if not keep:
        shutil.rmtree(tmp, onexc=_rm) if sys.version_info >= (3, 12) else shutil.rmtree(tmp, onerror=_rm)

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
