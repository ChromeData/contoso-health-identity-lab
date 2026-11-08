#!/usr/bin/env python3
"""
rotate-build-admin.py - give the AD build admin (CORP\\contosoadmin on DC01)
a new random password, keep the Keychain and the Key Vault copy in step, and
prove a Kerberos sign-in. Owner decision: rotate only when he says so.

Run as the lab operator, from the repo root, with DC01 running:
  lab/scripts/operator/op python3 -I lab/scripts/dc/rotate-build-admin.py

Where the password lives (names only):
  * Keychain item contoso-lab-dc01-admin (account contosoadmin): the source
    run-on-dc.py reads (04-Install-CloudSyncAgent.ps1, 10-Install-Adfs.ps1).
  * Key Vault kv-idlab-20f1, secret dc01-admin-password: the copy the build
    guide asks for (lab/scripts/dc/README.md step 4).
  * Terraform state (envs/dev, random_password.admin / output
    dc_admin_password) holds only the FIRST build password. The VM ignores
    admin_password changes, so it is never pushed again; after a rotation it
    is a dead value.

Order (nothing is printed, nothing is in argv, nothing is in a file):
  0. One rotation at a time: an exclusive lock (~/.contoso-operator/
     rotate-build-admin.lock, no secret in it) is held for the whole run.
  1. The current password is read from the Keychain into this process only.
     If the Key Vault copy differs (an earlier run stopped half way), the
     run STOPS before writing anything, so no working value is overwritten.
  2. A new 32-character password is made here (secrets module) and written
     into the SAME Keychain item through `security -i` on stdin (values are
     double-quoted with backslash and " escaped, so an old value with spaces or
     quotes round-trips).
  3. run-on-dc.py gets BOTH passwords from this process on its stdin (never
     re-read from the Keychain) and sends them to DC01 as PROTECTED
     run-command parameters. Reset-BuildAdminPassword.ps1 stops if a service
     or task runs as contosoadmin, resets the account, and checks Kerberos
     with the new and the old password.
  4. The old Keychain value goes back ONLY when DC01 proves AD was not
     touched (REFUSED, DEPENDENTS: FOUND, or the run command was never
     created). In every other case without "RESET: DONE" (an error after the
     reset started, a timeout, Ctrl+C) both values are kept: the NEW one in
     the Keychain, the OLD one in Key Vault (not touched), so the active
     password is never lost.
  5. The Key Vault secret gets a new version with the new value (REST, body
     in memory), read back and compared.
"""
import fcntl
import json
import os
import secrets
import ssl
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request

SAM = "contosoadmin"
SERVICE = "contoso-lab-dc01-admin"
VAULT = "kv-idlab-20f1"
KV_SECRET = "dc01-admin-password"
HERE = os.path.dirname(os.path.abspath(__file__))
# security -i parses its stdin like a shell line: keep to characters that
# need no quoting, and start with a letter so it is never read as an option.
# 32 characters from 66 is about 193 bits.
SYMBOLS = "-_.+"
ALPHABET = string.ascii_letters + string.digits + SYMBOLS
LOCK = os.path.expanduser("~/.contoso-operator/rotate-build-admin.lock")
HIDE = []


def scrub(text):
    for v in HIDE:
        if v:
            text = text.replace(v, "***")
    return text


def new_password(length=32):
    while True:
        pw = secrets.choice(string.ascii_letters) + "".join(secrets.choice(ALPHABET) for _ in range(length - 1))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in SYMBOLS for c in pw)):
            return pw


def keychain_read():
    return subprocess.run(["security", "find-generic-password", "-s", SERVICE, "-a", SAM, "-w"],
                          capture_output=True, text=True, check=True).stdout.rstrip("\n")


def quote(value):
    # security -i splits its line like a shell: inside double quotes, \ and "
    # are escaped with a backslash. A newline cannot be carried at all.
    if "\n" in value or "\r" in value:
        raise SystemExit("a password with a line break cannot go through security -i")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def keychain_write(value):
    # -U updates the existing item. The value goes in on stdin only.
    line = f"add-generic-password -U -s {SERVICE} -a {SAM} -w {quote(value)}\n"
    r = subprocess.run(["security", "-i"], input=line, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"Keychain write failed for {SERVICE} (exit {r.returncode})")
    if keychain_read() != value:
        raise SystemExit(f"Keychain read-back for {SERVICE} did not match")


def tls_context():
    ctx = ssl.create_default_context()
    if not ctx.get_ca_certs():
        for path in ("/etc/ssl/cert.pem", "/opt/homebrew/etc/openssl@3/cert.pem"):
            if os.path.exists(path):
                ctx.load_verify_locations(path)
                break
    return ctx


def kv(method, token, body=None):
    url = f"https://{VAULT}.vault.azure.net/secrets/{KV_SECRET}?api-version=7.4"
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60, context=tls_context()) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise SystemExit(scrub(f"Key Vault {method} {KV_SECRET}: HTTP {e.code}"))


def run_on_dc(new, old):
    # Both values go to run-on-dc.py on its stdin, from this process's memory.
    return subprocess.run([sys.executable, "-I", os.path.join(HERE, "run-on-dc.py"),
                           os.path.join(HERE, "Reset-BuildAdminPassword.ps1"),
                           "--param", f"SamAccountName={SAM}",
                           "--secret", "NewPassword=stdin:NewPassword",
                           "--secret", "OldPassword=stdin:OldPassword", "--timeout", "600"],
                          input=json.dumps({"NewPassword": new, "OldPassword": old}), capture_output=True, text=True)


def ad_state(out):
    """done | unchanged (proven) | unknown (keep both values)."""
    lines = [l.strip() for l in out.splitlines()]
    if any(l.startswith("RESET: DONE") for l in lines):
        return "done"
    if any(l.startswith(("REFUSED:", "DEPENDENTS: FOUND")) for l in lines) or "PUT failed:" in out:
        return "unchanged"
    return "unknown"


def get_token():
    return subprocess.run(["az", "account", "get-access-token", "--resource", "https://vault.azure.net",
                           "--query", "accessToken", "-o", "tsv"], capture_output=True, text=True, check=True).stdout.strip()


def take_lock():
    os.makedirs(os.path.dirname(LOCK), exist_ok=True)
    fh = open(LOCK, "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        raise SystemExit("another rotate-build-admin.py run holds the lock: stopping, nothing changed")
    return fh


def keep_both_message():
    return (f"UNKNOWN: DC01 did not report the result. Keychain {SERVICE} holds the NEW password, "
            f"Key Vault {VAULT}/{KV_SECRET} still holds the OLD one. Check which one AD accepts before anything else.")


def main():
    lock = take_lock()
    try:
        rotate()
    finally:
        lock.close()


def rotate():
    old = keychain_read()
    if not old:
        raise SystemExit(f"Keychain item {SERVICE} is empty: nothing to roll back to, stopping")
    HIDE.append(old)
    token = get_token()
    cur = kv("GET", token)
    if cur.get("value") != old:
        # Two different values = an earlier run may have stopped half way.
        # Writing now could throw away the only copy of the working password.
        raise SystemExit(f"STOP: Key Vault {VAULT}/{KV_SECRET} differs from Keychain {SERVICE}. "
                         "Nothing changed. Find which one AD accepts, make both copies hold it, then run again.")
    print(f"before: Key Vault {VAULT}/{KV_SECRET} matches Keychain {SERVICE}")
    tags = dict(cur.get("tags") or {})

    new = new_password()
    HIDE.append(new)
    keychain_write(new)
    print(f"new password generated and stored in Keychain item {SERVICE} (not shown)", flush=True)

    try:
        r = run_on_dc(new, old)
    except BaseException:
        # Ctrl+C or any failure while DC01 may already be resetting: never
        # roll back on a guess.
        print(keep_both_message())
        raise
    out = scrub(r.stdout + r.stderr)
    print(out.strip())
    state = ad_state(out)
    if state == "unchanged":
        keychain_write(old)
        print(f"AD was not changed: the old password is back in {SERVICE}")
        sys.exit(1)
    if state == "unknown":
        print(keep_both_message())
        sys.exit(1)

    tags["rotated-utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    tags["source"] = f"keychain:{SERVICE}"
    kv("PUT", token, {"value": new, "tags": tags})
    if kv("GET", token).get("value") != new:
        raise SystemExit(f"Key Vault {VAULT}/{KV_SECRET} read-back did not match the new password")
    print(f"Key Vault {VAULT}/{KV_SECRET}: new version written and read back (matches the Keychain)")

    if "KERBEROS: PASS" not in out or "KERBEROS-OLD: REFUSED" not in out:
        print(f"AD password changed and both copies hold it, but a Kerberos check did not pass")
        sys.exit(2)
    print(f"ROTATED: {SAM} has a new password (Keychain {SERVICE}, Key Vault {VAULT}/{KV_SECRET}); "
          "Kerberos works with the new one and refuses the old one")


if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        if isinstance(e.code, str):
            print(scrub(e.code), file=sys.stderr)
            sys.exit(1)
        raise
    except BaseException as e:  # never let a traceback carry a secret
        print(f"rotate-build-admin: failed: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)
