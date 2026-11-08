#!/usr/bin/env python3
"""
rotate-tier-admin.py - give one AD tier admin (t0/t1/t2-adm-01) a new random
password, keep it only in the macOS Keychain, and prove a Kerberos sign-in.

Run as the lab operator, from the repo root, with DC01 running:
  lab/scripts/operator/op python3 -I lab/scripts/dc/rotate-tier-admin.py t0-adm-01

contosoadmin (the build admin) is refused here: it has its own tool
(rotate-build-admin.py), and its rotation is the owner's decision.

Where the password lives (names only):
  * Keychain item contoso-lab-ad-<account> (account <account>@<domain>):
    the one working copy.
  * Keychain item contoso-lab-ad-<account>-previous: the OLD value, only
    while a run is in progress or after a run stopped half way. A tier admin
    has no Key Vault copy, so this item is what keeps both values.

Order (nothing is printed, nothing is in argv, nothing is in a file):
  0. One rotation per account at a time: an exclusive lock
     (~/.contoso-operator/rotate-tier-admin-<account>.lock, no secret in it)
     is held for the whole run (Greptile #251: two overlapping runs could
     leave AD and the Keychain with different values).
  1. If a -previous item already exists, an earlier run stopped half way:
     STOP before writing anything, so no working value is overwritten.
  2. The current password is read from the Keychain into this process and
     copied into the -previous item (read back). Values go to `security -i`
     double-quoted with \\ and " escaped, so an old value with spaces or
     quotes round-trips (Greptile #251).
  3. A new 28-character password is made here (secrets module) and written
     into the main item (read back).
  4. run-on-dc.py gets BOTH passwords from this process on its stdin (never
     re-read from the Keychain) and sends them to DC01 as PROTECTED
     run-command parameters. Reset-TierAdminPassword.ps1 resets the account
     and checks Kerberos with the new and the old password.
  5. The old value goes back ONLY when DC01 proves AD was not touched
     (REFUSED, or the run command was never created). In every other case
     without "RESET: DONE" (an error after the reset started, a timeout,
     Ctrl+C) BOTH values are kept: the NEW one in the main item, the OLD one
     in -previous (Greptile #251: a missing marker is not proof).
  6. After "RESET: DONE" the -previous item is deleted: the old value is the
     one being retired.
"""
import fcntl
import json
import os
import secrets
import string
import subprocess
import sys

ALLOWED = ("t0-adm-01", "t1-adm-01", "t2-adm-01")
DOMAIN = "corp.contosohealthlab.com"
HERE = os.path.dirname(os.path.abspath(__file__))
# The generated value needs no quoting and starts with a letter.
# 28 characters from 66 is about 169 bits.
SYMBOLS = "-_.+"
ALPHABET = string.ascii_letters + string.digits + SYMBOLS
LOCK_DIR = os.path.expanduser("~/.contoso-operator")
HIDE = []


def scrub(text):
    for v in HIDE:
        if v:
            text = text.replace(v, "***")
    return text


def new_password(length=28):
    while True:
        pw = secrets.choice(string.ascii_letters) + "".join(secrets.choice(ALPHABET) for _ in range(length - 1))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in SYMBOLS for c in pw)):
            return pw


def quote(value):
    # security -i splits its line like a shell: inside double quotes, \ and "
    # are escaped with a backslash. A newline cannot be carried at all.
    if "\n" in value or "\r" in value:
        raise SystemExit("a password with a line break cannot go through security -i")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def keychain_read(service, missing_ok=False):
    r = subprocess.run(["security", "find-generic-password", "-s", service, "-w"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        if missing_ok:
            return None
        raise SystemExit(f"Keychain item {service} not found")
    return r.stdout.rstrip("\n")


def keychain_write(service, account, value):
    # -U updates the existing item. The value goes in on stdin only.
    line = f"add-generic-password -U -s {service} -a {account} -w {quote(value)}\n"
    r = subprocess.run(["security", "-i"], input=line, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"Keychain write failed for {service} (exit {r.returncode})")
    if keychain_read(service) != value:
        raise SystemExit(f"Keychain read-back for {service} did not match")


def keychain_delete(service):
    subprocess.run(["security", "delete-generic-password", "-s", service], capture_output=True, text=True)
    if keychain_read(service, missing_ok=True) is not None:
        raise SystemExit(f"Keychain item {service} could not be deleted")


def run_on_dc(sam, new, old):
    # Both values go to run-on-dc.py on its stdin, from this process's memory.
    return subprocess.run([sys.executable, "-I", os.path.join(HERE, "run-on-dc.py"),
                           os.path.join(HERE, "Reset-TierAdminPassword.ps1"),
                           "--param", f"SamAccountName={sam}",
                           "--secret", "NewPassword=stdin:NewPassword",
                           "--secret", "OldPassword=stdin:OldPassword", "--timeout", "600"],
                          input=json.dumps({"NewPassword": new, "OldPassword": old}), capture_output=True, text=True)


def ad_state(out):
    """done | unchanged (proven) | unknown (keep both values)."""
    lines = [l.strip() for l in out.splitlines()]
    if any(l.startswith("RESET: DONE") for l in lines):
        return "done"
    if any(l.startswith("REFUSED:") for l in lines) or "PUT failed:" in out:
        return "unchanged"
    return "unknown"


def take_lock(sam):
    os.makedirs(LOCK_DIR, exist_ok=True)
    fh = open(os.path.join(LOCK_DIR, f"rotate-tier-admin-{sam}.lock"), "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        raise SystemExit(f"another rotate-tier-admin.py run for {sam} holds the lock: stopping, nothing changed")
    return fh


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or argv[0] not in ALLOWED:
        raise SystemExit(f"usage: rotate-tier-admin.py {{{'|'.join(ALLOWED)}}}")
    sam = argv[0]
    lock = take_lock(sam)
    try:
        rotate(sam)
    finally:
        lock.close()


def rotate(sam):
    service, account = f"contoso-lab-ad-{sam}", f"{sam}@{DOMAIN}"
    previous = f"{service}-previous"
    keep_both = (f"UNKNOWN: DC01 did not report the result. Keychain {service} holds the NEW password, "
                 f"{previous} holds the OLD one. Check which one AD accepts before anything else.")

    if keychain_read(previous, missing_ok=True) is not None:
        raise SystemExit(f"STOP: Keychain item {previous} exists, so an earlier run stopped half way. "
                         f"Nothing changed. Find which value AD accepts, put it in {service}, delete {previous}, run again.")
    old = keychain_read(service)
    if not old:
        raise SystemExit(f"Keychain item {service} is empty: nothing to roll back to, stopping")
    HIDE.append(old)
    quote(old)  # refuse a value security -i cannot carry before anything is written
    keychain_write(previous, account, old)

    new = new_password()
    HIDE.append(new)
    keychain_write(service, account, new)
    print(f"new password generated and stored in Keychain item {service} (not shown); old one kept in {previous}", flush=True)

    try:
        r = run_on_dc(sam, new, old)
    except BaseException:
        # Ctrl+C or any failure while DC01 may already be resetting: never
        # roll back on a guess.
        print(keep_both)
        raise
    out = scrub(r.stdout + r.stderr)
    print(out.strip())
    state = ad_state(out)
    if state == "unchanged":
        keychain_write(service, account, old)
        keychain_delete(previous)
        print(f"AD was not changed: the old password is back in {service}")
        sys.exit(1)
    if state == "unknown":
        print(keep_both)
        sys.exit(1)

    keychain_delete(previous)
    if "KERBEROS: PASS" not in out or "KERBEROS-OLD: REFUSED" not in out:
        print(f"AD password changed and {service} holds it, but a Kerberos check did not pass")
        sys.exit(2)
    print(f"ROTATED: {sam} has a new password (Keychain {service}); Kerberos works with the new one and refuses the old one")


if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        if isinstance(e.code, str):
            print(scrub(e.code), file=sys.stderr)
            sys.exit(1)
        raise
    except BaseException as e:  # never let a traceback carry a secret
        print(f"rotate-tier-admin: failed: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)
