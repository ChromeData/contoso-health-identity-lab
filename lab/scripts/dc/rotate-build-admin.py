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
  1. The current password is read from the Keychain into this process only.
  2. A new 32-character password is made here (secrets module) and written
     into the SAME Keychain item through `security -i` on stdin.
  3. run-on-dc.py sends it to DC01 as a PROTECTED run-command parameter (the
     old one too, on run-on-dc.py's stdin). Reset-BuildAdminPassword.ps1
     stops if a service or task runs as contosoadmin, resets the account,
     and checks Kerberos with the new and the old password.
  4. If DC01 did not report "RESET: DONE", the old Keychain value goes back.
  5. The Key Vault secret gets a new version with the new value (REST, body
     in memory), read back and compared.
"""
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


def keychain_write(value):
    # -U updates the existing item. The value goes in on stdin only.
    line = f"add-generic-password -U -s {SERVICE} -a {SAM} -w {value}\n"
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


def main():
    old = keychain_read()
    if not old:
        raise SystemExit(f"Keychain item {SERVICE} is empty: nothing to roll back to, stopping")
    HIDE.append(old)
    token = subprocess.run(["az", "account", "get-access-token", "--resource", "https://vault.azure.net",
                            "--query", "accessToken", "-o", "tsv"], capture_output=True, text=True, check=True).stdout.strip()
    cur = kv("GET", token)
    print(f"before: Key Vault {VAULT}/{KV_SECRET} {'matches' if cur.get('value') == old else 'DIFFERS FROM'} Keychain {SERVICE}")
    tags = dict(cur.get("tags") or {})

    new = new_password()
    HIDE.append(new)
    keychain_write(new)
    print(f"new password generated and stored in Keychain item {SERVICE} (not shown)", flush=True)

    try:
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "run-on-dc.py"),
                            os.path.join(HERE, "Reset-BuildAdminPassword.ps1"),
                            "--param", f"SamAccountName={SAM}",
                            "--secret", f"NewPassword=keychain:{SERVICE}",
                            "--secret", "OldPassword=stdin:OldPassword", "--timeout", "600"],
                           input=json.dumps({"OldPassword": old}), capture_output=True, text=True)
    except BaseException:
        keychain_write(old)
        print(f"run-on-dc did not finish: the old password is back in {SERVICE}")
        raise
    out = scrub(r.stdout + r.stderr)
    print(out.strip())
    if "RESET: DONE" not in out:
        if "DEPENDENTS: " in out or "REFUSED: " in out or "RESET: FAILED" in out:
            keychain_write(old)
            print(f"AD was not changed: the old password is back in {SERVICE}")
        else:
            # The run never reported, so AD may or may not have changed. Keep
            # one copy of each: the new one in the Keychain, the old one in
            # Key Vault (not touched). Try both with Kerberos before anything else.
            print(f"UNKNOWN: DC01 did not report. Keychain {SERVICE} holds the NEW password, "
                  f"Key Vault {VAULT}/{KV_SECRET} still holds the OLD one. Check which works.")
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
