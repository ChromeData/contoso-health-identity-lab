#!/usr/bin/env python3
"""
run-on-dc.py - run one of lab/scripts/dc/*.ps1 on DC01 with SECRET parameters,
without any secret ever touching a command line.

Why: `az vm run-command invoke` has no protected parameters, and when the CLI
rejects an argument it echoes the whole command line, secrets included. This
helper uses the *managed* run command (Microsoft.Compute/virtualMachines/
runCommands, protectedParameters) through the ARM REST API directly:

  * each secret is fetched INSIDE this process, from the macOS Keychain
    (keychain:<service>), from Terraform state (tfoutput:<output name>) or
    from a JSON object the caller writes to stdin (stdin:<key>, for a value
    that lives only in the calling process, e.g. rotate-build-admin.py);
    nothing secret is in argv or the environment;
  * protected parameters are never returned by Azure, and every secret value
    is scrubbed from anything this script prints;
  * the run command resource is deleted afterwards.

Usage (from the repo root):
  lab/scripts/dc/run-on-dc.py lab/scripts/dc/04-Install-CloudSyncAgent.ps1 \
      --param InstallerUrl=https://... --param DomainName=corp.example.com \
      --secret HybridAdminPassword=keychain:contoso-lab-cloudsync \
      --secret DomainAdminPassword=keychain:contoso-lab-dc01-admin

Options: --rg (rg-identity-lab) --vm (vm-dc01) --timeout seconds (3600).
Needs: az login (an ARM token), python3 stdlib only.
"""
import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

API = "2023-09-01"
SECRET_VALUES = []   # every resolved secret; scrubbed from anything printed


def scrub(text):
    for v in SECRET_VALUES:
        if v:
            text = text.replace(v, "***")
    return text


def tls_context():
    # python.org builds on macOS ship without a CA store; fall back to the
    # system bundle (or certifi when installed).
    ctx = ssl.create_default_context()
    if not ctx.get_ca_certs():
        try:
            import certifi
            ctx.load_verify_locations(certifi.where())
        except ImportError:
            for path in ("/etc/ssl/cert.pem", "/opt/homebrew/etc/openssl@3/cert.pem"):
                if os.path.exists(path):
                    ctx.load_verify_locations(path)
                    break
    return ctx


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()


_STDIN = None


def resolve(ref):
    global _STDIN
    kind, _, name = ref.partition(":")
    if kind == "stdin":
        if _STDIN is None:
            _STDIN = json.loads(sys.stdin.read() or "{}")
        if name not in _STDIN:
            raise SystemExit(f"stdin secret '{name}' was not given")
        return _STDIN[name]
    if kind == "keychain":
        return sh("security", "find-generic-password", "-s", name, "-w")
    if kind == "tfoutput":
        tf = os.environ.get("TERRAFORM") or shutil.which("terraform") or os.path.expanduser("~/.local/bin/terraform")
        return sh(tf, "-chdir=lab/terraform/envs/dev", "output", "-raw", name)
    raise SystemExit(f"unknown secret source '{kind}' (use keychain:<service>, tfoutput:<name> or stdin:<key>)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("script")
    ap.add_argument("--param", action="append", default=[], help="Name=value (not secret)")
    ap.add_argument("--secret", action="append", default=[], help="Name=keychain:<svc> | Name=tfoutput:<output> | Name=stdin:<key>")
    ap.add_argument("--rg", default="rg-identity-lab")
    ap.add_argument("--vm", default="vm-dc01")
    ap.add_argument("--timeout", type=int, default=3600)
    a = ap.parse_args()

    secrets = {}
    for s in a.secret:
        name, _, ref = s.partition("=")
        secrets[name] = resolve(ref)
        SECRET_VALUES.append(secrets[name])
    ctx = tls_context()

    sub = sh("az", "account", "show", "--query", "id", "-o", "tsv")
    token = sh("az", "account", "get-access-token", "--resource", "https://management.azure.com", "--query", "accessToken", "-o", "tsv")
    name = "lab-" + uuid.uuid4().hex[:8]
    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{a.rg}/providers/"
           f"Microsoft.Compute/virtualMachines/{a.vm}/runCommands/{name}?api-version={API}")
    location = json.loads(sh("az", "vm", "show", "-g", a.rg, "-n", a.vm, "--query", "{l:location}", "-o", "json"))["l"]

    def call(method, u, body=None):
        req = urllib.request.Request(u, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120, context=ctx) as r:
                raw = r.read().decode()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raise SystemExit(scrub(f"{method} failed: HTTP {e.code}: {e.read().decode()[:1500]}"))

    body = {
        "location": location,
        "properties": {
            "source": {"script": open(a.script, encoding="utf-8").read()},
            "parameters": [{"name": k, "value": v} for k, v in (p.split("=", 1) for p in a.param)],
            "protectedParameters": [{"name": k, "value": v} for k, v in secrets.items()],
            "asyncExecution": True,
            "timeoutInSeconds": a.timeout,
        },
    }
    print(f"run command {name}: {a.script} on {a.vm}", flush=True)
    call("PUT", url, body)
    state, iv = "Pending", {}
    deadline = time.time() + a.timeout + 300
    try:
        while time.time() < deadline:
            time.sleep(15)
            _, res = call("GET", url + "&$expand=instanceView")
            iv = res.get("properties", {}).get("instanceView") or {}
            state = iv.get("executionState", "Pending")
            if state not in ("Pending", "Running", "Unknown"):
                break
        print(scrub(iv.get("output") or ""))
        err = scrub(iv.get("error") or "").strip()
        if err:
            print("--- stderr ---\n" + err)
        print(f"state: {state}, exit code: {iv.get('exitCode')}")
    finally:
        try:
            call("DELETE", url)
        except SystemExit:
            print("note: could not delete the run command resource; delete it in the portal")
    sys.exit(0 if state == "Succeeded" and iv.get("exitCode", 1) == 0 else 1)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as e:   # never let a traceback print a secret
        print("run-on-dc: failed: " + scrub(f"{type(e).__name__}: {e}"), file=sys.stderr)
        sys.exit(1)
