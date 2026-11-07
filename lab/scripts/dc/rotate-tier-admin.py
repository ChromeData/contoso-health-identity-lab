#!/usr/bin/env python3
"""
rotate-tier-admin.py - give one AD tier admin (t0/t1/t2-adm-01) a new random
password, keep it only in the macOS Keychain, and prove a Kerberos sign-in.

Run as the lab operator, from the repo root, with DC01 running:
  lab/scripts/operator/op python3 -I lab/scripts/dc/rotate-tier-admin.py t0-adm-01

Why this order (the Keychain item is contoso-lab-ad-<account>):
  1. The current password is read from the Keychain into this process only,
     so it can be put back if DC01 never changes the account.
  2. A new 28-character password is made here (secrets module) and written
     straight into the same Keychain item through `security -i` on stdin.
     It is never printed, never in argv, never in a file.
  3. run-on-dc.py sends it to DC01 as a PROTECTED run-command parameter,
     where Reset-TierAdminPassword.ps1 resets the account and asks the KDC
     for a Kerberos ticket with it.
  4. If DC01 did not report "RESET: DONE", the old Keychain value goes back,
     so the Keychain always matches AD.
contosoadmin (the build admin) is refused: other DC01 scripts use it, so its
rotation is the owner's decision.
"""
import os
import secrets
import string
import subprocess
import sys

ALLOWED = ("t0-adm-01", "t1-adm-01", "t2-adm-01")
DOMAIN = "corp.contosohealthlab.com"
HERE = os.path.dirname(os.path.abspath(__file__))
# security -i parses its stdin like a shell line: keep to characters that
# need no quoting. 28 characters from 66 is about 169 bits.
SYMBOLS = "-_.+"
ALPHABET = string.ascii_letters + string.digits + SYMBOLS


def new_password(length=28):
    while True:
        pw = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in SYMBOLS for c in pw)):
            return pw


def keychain_read(service):
    return subprocess.run(["security", "find-generic-password", "-s", service, "-w"],
                          capture_output=True, text=True, check=True).stdout.rstrip("\n")


def keychain_write(service, account, value):
    # -U updates the existing item. The value goes in on stdin only.
    line = f"add-generic-password -U -s {service} -a {account} -w {value}\n"
    r = subprocess.run(["security", "-i"], input=line, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"Keychain write failed for {service} (exit {r.returncode})")
    if keychain_read(service) != value:
        raise SystemExit(f"Keychain read-back for {service} did not match")


def run_reset(sam, service):
    return subprocess.run([sys.executable, "-I", os.path.join(HERE, "run-on-dc.py"),
                           os.path.join(HERE, "Reset-TierAdminPassword.ps1"),
                           "--param", f"SamAccountName={sam}",
                           "--secret", f"NewPassword=keychain:{service}", "--timeout", "600"],
                          capture_output=True, text=True)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ALLOWED:
        raise SystemExit(f"usage: rotate-tier-admin.py {{{'|'.join(ALLOWED)}}}")
    sam = sys.argv[1]
    service, account = f"contoso-lab-ad-{sam}", f"{sam}@{DOMAIN}"

    old = keychain_read(service)
    if not old:
        raise SystemExit(f"Keychain item {service} is empty: nothing to roll back to, stopping")
    new = new_password()
    keychain_write(service, account, new)
    print(f"new password generated and stored in Keychain item {service} (not shown)", flush=True)

    try:
        r = run_reset(sam, service)
    except BaseException:
        keychain_write(service, account, old)
        print(f"run-on-dc did not finish: the old password is back in {service}")
        raise
    out = r.stdout + r.stderr
    for v in (new, old):
        out = out.replace(v, "***")
    print(out.strip())
    if "RESET: DONE" not in out:
        keychain_write(service, account, old)
        print(f"AD was not changed: the old password is back in {service}")
        sys.exit(1)
    if "KERBEROS: PASS" not in out:
        print(f"AD password changed and {service} holds it, but the Kerberos check did not pass")
        sys.exit(2)
    print(f"ROTATED: {sam} has a new password (Keychain {service}); Kerberos sign-in with it works")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as e:  # never let a traceback carry a secret
        print(f"rotate-tier-admin: failed: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)
