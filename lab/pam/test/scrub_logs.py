#!/usr/bin/env python3
# =============================================================================
# test/scrub_logs.py - copy harness logs with every credential this run
# generated taken out, so they can leave the runner: pam-harness.yml uploads
# them as an artifact when a run FAILS, so a failure can be read, not guessed
# at. The logs name the harness's synthetic lab accounts and operators (not
# secrets); the credentials pam-up.sh and the suites generated must not go.
#
# Two passes, exact values first (longest first), then shapes:
#   1. EXACT VALUES this run generated, read from --secrets paths (files or
#      directories, walked recursively; a path that does not exist is
#      skipped):
#        * a .env file (KEY=VALUE): every value of 8+ characters, except the
#          keys that are plainly configuration (NOT_SECRET_KEYS) - so a new
#          credential key is redacted by default, not missed;
#        * a JSON file: every string under a key that names a secret
#          (password, token, key, secret, unseal, root, ...), and every
#          string of 16+ characters without spaces that mixes letters and
#          digits (a generated key or password under any key name);
#        * any other text file: the whole content and every line of 8+
#          characters, and the value of KEY=VALUE lines (password files,
#          ha.env, seal.hcl, PEM files);
#        * binary files are skipped (a Raft snapshot is not text in a log).
#   2. SHAPES, for credentials made during the run and never written to
#      .secrets/ (a Vault token issued to a check-out, a JWT): Vault tokens
#      (hvs./hvb./hvr. and legacy s.), JWTs, PEM private-key blocks, and any
#      run of 32+ letters/digits that is not a lowercase SHA-256 (the same
#      rule as lib.sh run_record_unsafe).
# Each hit becomes "[redacted]" / "[redacted:<shape>]".
#
# FAIL CLOSED: no credential values found in --secrets (the run never got
# as far as generating them, or the paths are wrong), an unreadable input,
# or any error -> exit 1 and NOTHING is written, so nothing is uploaded.
# Prints counts only, never a value.
#
# Usage: python3 -I test/scrub_logs.py --secrets .env --secrets .secrets \
#            --out DIR LOGFILE...
# =============================================================================
import argparse
import json
import os
import re
import sys

NOT_SECRET_KEYS = {"DC_FQDN", "DC_PUBLIC_IP", "ITSM_URL", "ITSM_USER"}
SECRET_KEY_RE = re.compile(r"pass|secret|token|key|cred|unseal|root|nonce|hmac|private|auth", re.I)
MIN_EXACT = 8
SHAPES = [
    ("vault-token", re.compile(r"\bhv[sbr]\.[A-Za-z0-9_-]{8,}")),
    ("vault-token", re.compile(r"\bs\.[A-Za-z0-9]{24}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("long-token", re.compile(r"(?<![A-Za-z0-9])(?![0-9a-f]{64}(?![A-Za-z0-9]))[A-Za-z0-9]{32,}")),
]


def random_looking(v: str) -> bool:
    return len(v) >= 16 and not re.search(r"\s", v) and re.search(r"[A-Za-z]", v) and re.search(r"[0-9]", v)


def from_json(obj, key_is_secret=False, out=None):
    out = set() if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            from_json(v, key_is_secret or bool(SECRET_KEY_RE.search(str(k))), out)
    elif isinstance(obj, list):
        for v in obj:
            from_json(v, key_is_secret, out)
    elif isinstance(obj, str):
        v = obj.strip()
        if len(v) >= MIN_EXACT and (key_is_secret or random_looking(v)):
            out.add(v)
    return out


def from_text(text: str, is_env: bool):
    vals = set()
    whole = text.strip()
    if not is_env and len(whole) >= MIN_EXACT:
        vals.add(whole)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if m:
            key, val = m.group(1), m.group(2).strip().strip('"').strip("'")
            if is_env and key in NOT_SECRET_KEYS:
                continue
            if len(val) >= MIN_EXACT:
                vals.add(val)
            if is_env:
                continue
        if not is_env and len(line) >= MIN_EXACT:
            vals.add(line)
    return vals


def secret_values(paths):
    vals = set()
    for p in paths:
        if not os.path.exists(p):
            continue
        files = [p] if os.path.isfile(p) else [os.path.join(d, f) for d, _, fs in os.walk(p) for f in fs]
        for f in files:
            if not os.path.isfile(f):
                continue
            with open(f, "rb") as fh:
                raw = fh.read()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue                     # binary (e.g. a Raft snapshot)
            if f.endswith(".json"):
                try:
                    vals |= from_json(json.loads(text))
                    continue
                except ValueError:
                    pass                     # not really JSON: treat as text
            vals |= from_text(text, is_env=os.path.basename(f).endswith(".env") or os.path.basename(f) == ".env")
    return vals


def scrub(text: str, values):
    n_exact = n_shape = 0
    for v in values:                         # longest first: no partial leftovers
        c = text.count(v)
        if c:
            text = text.replace(v, "[redacted]")
            n_exact += c
    for name, rx in SHAPES:
        text, c = rx.subn(f"[redacted:{name}]", text)
        n_shape += c
    return text, n_exact, n_shape


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--secrets", action="append", default=[], help=".env file or .secrets directory (repeatable)")
    ap.add_argument("--out", required=True)
    ap.add_argument("logs", nargs="+")
    a = ap.parse_args()
    try:
        values = sorted(secret_values(a.secrets), key=len, reverse=True)
        if not values:
            print("scrub_logs: no credential values found in --secrets: refusing to copy any log", file=sys.stderr)
            return 1
        done, exact, shape = {}, 0, 0
        for f in a.logs:
            with open(f, "rb") as fh:
                text = fh.read().decode("utf-8", errors="replace")
            text, e, s = scrub(text, values)
            done[os.path.basename(f)] = text
            exact, shape = exact + e, shape + s
        os.makedirs(a.out, exist_ok=True)
        for name, text in done.items():
            with open(os.path.join(a.out, name), "w", encoding="utf-8") as fh:
                fh.write(text)
    except Exception as e:                   # fail closed, and say why without any value
        print(f"scrub_logs: {type(e).__name__}: nothing written", file=sys.stderr)
        return 1
    print(f"scrub_logs: {len(done)} file(s) copied to {a.out}; {len(values)} credential value(s) known; "
          f"{exact} exact and {shape} shape redaction(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
