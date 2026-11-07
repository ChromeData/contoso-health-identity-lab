#!/usr/bin/env python3
# =============================================================================
# test/scrub_logs.test.py - test/scrub_logs.py is what stands between the
# harness's generated credentials and an uploaded artifact, so it is tested
# with the same kinds of files pam-up.sh and the suites write (.env, password
# files, vault-init.json, an app host key map, PEM, a binary snapshot) and
# logs that contain them, plus credentials made during a run (a Vault token,
# a JWT, a private key) that are in no file. Every known secret must be gone
# from every output; the names a reader needs (accounts, hosts, hashes) stay;
# nothing to scrub against -> nothing written (fail closed).
#
# Prints PASS/FAIL per case (test/run-all.sh counts them); exit 1 on any FAIL.
# Stdlib only, offline. Usage: python3 test/scrub_logs.test.py
# =============================================================================
import json
import os
import secrets
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "scrub_logs.py")
FAILS = 0


def case(name, ok, detail=""):
    global FAILS
    print(("PASS  " if ok else "FAIL  ") + name)
    if not ok:
        FAILS += 1
        if detail:
            print("      " + detail.strip().splitlines()[-1])


def run(secret_paths, logs, out):
    args = [sys.executable, "-I", TOOL, "--out", out]
    for s in secret_paths:
        args += ["--secrets", s]
    return subprocess.run(args + logs, capture_output=True, text=True)


with tempfile.TemporaryDirectory() as d:
    pam = os.path.join(d, "pam")
    sec = os.path.join(pam, ".secrets")
    os.makedirs(os.path.join(sec, "operators"))
    os.makedirs(os.path.join(sec, "ha", "snapshots"))
    guac_db = secrets.token_hex(24)
    mp_admin = f"Mp-{secrets.token_hex(12)}-9a"
    app_data = "q0b7Yw9cJ0m3Zr8xV2kN1pL6tS4uH5eF7gD8aB9cC0E="
    with open(os.path.join(pam, ".env"), "w") as f:
        f.write(f"GUAC_DB_PASSWORD={guac_db}\nAPP_DATA_KEY={app_data}\nMIDPOINT_ADMIN_PASSWORD={mp_admin}\n"
                "DC_FQDN=dc01.corp.test.local\nDC_PUBLIC_IP=172.18.0.5\nITSM_USER=pam-broker\n")
    op_pw = f"Op-{secrets.token_urlsafe(18)}"
    with open(os.path.join(sec, "operators", "ops-alice-password"), "w") as f:
        f.write(op_pw + "\n")
    root_token = "hvs." + secrets.token_urlsafe(24)
    unseal = secrets.token_urlsafe(32)
    with open(os.path.join(sec, "vault-init.json"), "w") as f:
        json.dump({"unseal_keys_b64": [unseal], "root_token": root_token, "unseal_threshold": 1}, f)
    app_key = secrets.token_hex(27)[:53]
    with open(os.path.join(sec, "app-hosts.json"), "w") as f:
        json.dump({"host/clinical-app": app_key}, f)
    with open(os.path.join(sec, "psm-checkout.json"), "w") as f:
        json.dump({"account": "tier0-admin-01", "operator": "ops-alice", "ticket": "CHG0040001"}, f)
    with open(os.path.join(sec, "ha", "ha.env"), "w") as f:
        f.write(f"VAULT_HA_UNSEAL_KEY={secrets.token_urlsafe(24)}\n")
    ha_val = open(os.path.join(sec, "ha", "ha.env")).read().split("=", 1)[1].strip()
    with open(os.path.join(sec, "ha", "snapshots", "raft.snap"), "wb") as f:
        f.write(b"\x00\xff\xfe binary snapshot \x81")
    known = [guac_db, mp_admin, app_data, op_pw, root_token, unseal, app_key, ha_val]

    run_token = "hvs." + secrets.token_urlsafe(30)        # issued during the run, in no file
    jwt = "eyJhbGciOiJIUzI1NiJ9." + secrets.token_urlsafe(24) + "." + secrets.token_urlsafe(24)
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow" + secrets.token_hex(40) + "\n-----END RSA PRIVATE KEY-----"
    sha = secrets.token_hex(32)
    log = os.path.join(d, "e2e.log")
    with open(log, "w") as f:
        f.write(f"PASS  checked out tier0-admin-01 for ops-alice (ticket CHG0040001) on dc01.corp.test.local\n"
                f"      guacadmin login with {guac_db} ok\n"
                f"      midPoint admin password {mp_admin}; app data key {app_data}\n"
                f"      operator password: {op_pw}\n"
                f"      vault root {root_token} unseal {unseal}; HA unseal {ha_val}\n"
                f"      app api key {app_key}\n"
                f"      issued token {run_token} and jwt {jwt}\n{pem}\n"
                f"      recording sha256 {sha}\n")
    guacd = os.path.join(d, "docker-guacd.log")
    with open(guacd, "w") as f:
        f.write("guacd[40]: INFO:\tRDP server closed/refused connection: Manually logged off.\n")

    out = os.path.join(d, "out")
    p = run([os.path.join(pam, ".env"), sec, os.path.join(pam, "dynamic-db", ".secrets")], [log, guacd], out)
    got = open(os.path.join(out, "e2e.log")).read() if p.returncode == 0 else ""
    case("scrubs and copies every log (exit 0, one output per input, counts only on stdout)",
         p.returncode == 0 and sorted(os.listdir(out)) == ["docker-guacd.log", "e2e.log"]
         and not any(k in p.stdout + p.stderr for k in known), p.stderr)
    case(".env credentials (hex, Mp-...-9a, base64 data key) are gone; DC_FQDN / DC_PUBLIC_IP stay",
         all(v not in got for v in (guac_db, mp_admin, app_data)) and "dc01.corp.test.local" in got)
    case("a password file's content (operators/ops-alice-password) is gone", op_pw not in got)
    case("vault-init.json: root token and unseal key are gone", root_token not in got and unseal not in got)
    case("a generated key under an innocuous JSON key (app-hosts.json) is gone", app_key not in got)
    case("ha/ha.env value is gone; a binary snapshot in .secrets is skipped without error", ha_val not in got)
    case("names a reader needs stay: account, operator, ticket (psm-checkout.json values are not secrets)",
         all(n in got for n in ("tier0-admin-01", "ops-alice", "CHG0040001")))
    case("credentials made during the run, in no file: Vault token, JWT, private-key block -> redacted by shape",
         run_token not in got and jwt not in got and "PRIVATE KEY-----\nMIIE" not in got
         and "[redacted:vault-token]" in got and "[redacted:jwt]" in got and "[redacted:private-key]" in got)
    case("a lowercase SHA-256 stays (recording hashes are evidence, not secrets)", sha in got)
    alltext = "".join(open(os.path.join(out, n)).read() for n in os.listdir(out)) if p.returncode == 0 else ""
    case("no known credential appears in ANY output file", p.returncode == 0 and not any(k in alltext for k in known))

    out2 = os.path.join(d, "out2")
    p = run([os.path.join(d, "nowhere", ".env"), os.path.join(d, "nowhere", ".secrets")], [log], out2)
    case("nothing to scrub against (no .env / .secrets) -> exit 1 and NOTHING written (fail closed)",
         p.returncode == 1 and not os.path.exists(out2), p.stderr)

    out3 = os.path.join(d, "out3")
    p = run([os.path.join(pam, ".env")], [log, os.path.join(d, "missing.log")], out3)
    case("an unreadable input log -> exit 1 and NOTHING written", p.returncode == 1 and not os.path.exists(out3),
         p.stderr)

print(f"\nscrub_logs.py: {'all cases behaved' if FAILS == 0 else f'{FAILS} case(s) FAILED'}")
sys.exit(1 if FAILS else 0)
