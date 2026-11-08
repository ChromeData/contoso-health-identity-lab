#!/usr/bin/python3 -I
"""Mint (or rotate) the signing key ServiceNow uses to prove who it is to Entra.

WHAT IT DOES
1. Makes a new RSA 2048 key and a self-signed certificate (OpenSSL 3, in a
   private temp folder, mode 700).
2. Packs them into a Java key store (via PKCS#12) with a random password that exists
   only in this process's memory.
3. Uploads the key store to ServiceNow as a sys_certificate record (type
   "Java Key Store") and points the JWT key alias + JWT provider at it.
4. Writes ONLY the public certificate to
   lab/terraform/modules/apps/files/servicenow-fulfilment.pem, which
   Terraform registers on the "ServiceNow - Access Fulfilment" app
   (modules/apps/servicenow_fulfilment.tf).
5. Deletes the temp folder (the private key is then only inside ServiceNow).

WHY A CERTIFICATE, NOT A CLIENT SECRET
Microsoft recommends certificate credentials over client secrets for apps
(Learn, "Certificate credentials for application authentication"): the
private key never travels; Entra only holds the public half; each token
request is a short JWT signed with the key (client_assertion), so there is
no reusable password to leak. ServiceNow signs that JWT itself
(sn_auth.GlideJWTAPI with the jwt_provider below), so no secret is stored
in ServiceNow either - only the key store, encrypted at rest by the instance.

The key store password is random, used once to upload, and stored only in
the two ServiceNow password2 fields that need it (key_store_password,
signing_key_password). It is never printed or written to disk.

ROTATION: run this again, commit the new PEM, merge -> apply (owner
approves). Between the ServiceNow upload and the apply, ServiceNow signs
with a key Entra does not know yet, so fulfilment fails closed (the ticket
goes to the IAM queue) - rotate outside clinic hours.

Usage: /usr/bin/python3 -I lab/servicenow/fulfilment-cert.py [--days 180]
(180 days: the lab's key-credential limit, see envs/dev/lab.tfvars.)
"""
import argparse
import hashlib
import os
import secrets
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import snlib  # noqa: E402

KEYTOOL = shutil.which("keytool") or "/usr/bin/keytool"
OPENSSL = shutil.which("openssl", path="/opt/homebrew/bin:/usr/local/bin") or "openssl"
ALIAS = "contoso-entra-fulfilment"
CERT_NAME = "Contoso - Entra access fulfilment signing key"
PROVIDER_NAME = "Contoso - Entra access fulfilment"
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
PEM_OUT = os.path.join(REPO, "lab", "terraform", "modules", "apps", "files", "servicenow-fulfilment.pem")


def openssl(args, stdin=None):
    r = subprocess.run([OPENSSL] + args, input=stdin, capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"openssl {args[0]} failed: {r.stderr.decode()[:300]}")
    return r.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=180)
    a = ap.parse_args()
    ver = openssl(["version"]).decode()
    if not ver.startswith("OpenSSL 3") and not ver.startswith("OpenSSL 4"):
        raise SystemExit(f"need OpenSSL 3+ (PKCS#12 with AES), found: {ver.strip()}")

    tmp = tempfile.mkdtemp(prefix="snfulfil-")
    os.chmod(tmp, 0o700)
    try:
        key, crt, p12, jks = (os.path.join(tmp, n) for n in ("k.pem", "c.pem", "s.p12", "s.jks"))
        openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                 "-days", str(a.days), "-subj", "/CN=Contoso Health - ServiceNow access fulfilment"])
        pw = secrets.token_urlsafe(32)
        # -passout stdin: the password never appears in argv.
        openssl(["pkcs12", "-export", "-inkey", key, "-in", crt, "-name", ALIAS, "-out", p12,
                 "-passout", "stdin"], stdin=(pw + "\n").encode())
        # ServiceNow's JWT key alias accepts ONLY a Java Key Store (or BC FIPS)
        # as its signing keystore: business rule "validate" on
        # jwt_keystore_aliases refuses PKCS#12 ("Invalid Signing Keystore.
        # Please select an Active JKS..."), read on dev459905 2026-11-07. So
        # the PKCS#12 is converted with keytool. keytool gets the password
        # through :env, set only in that child's environment (not argv, not
        # this shell's environment, not disk).
        r = subprocess.run([KEYTOOL, "-importkeystore", "-noprompt", "-srckeystore", p12, "-srcstoretype", "PKCS12",
                            "-srcstorepass:env", "SNF_PW", "-destkeystore", jks, "-deststoretype", "JKS",
                            "-deststorepass:env", "SNF_PW", "-destkeypass:env", "SNF_PW", "-srcalias", ALIAS],
                           env={"SNF_PW": pw, "PATH": "/usr/bin:/bin"}, capture_output=True)
        if r.returncode != 0:
            raise SystemExit(f"keytool failed: {r.stderr.decode()[:300]}")
        der = openssl(["x509", "-in", crt, "-outform", "DER"])
        thumb = hashlib.sha1(der).hexdigest().upper()
        store_bytes = open(jks, "rb").read()
        pem = open(crt).read()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    sn = snlib.Client()
    cert, how = sn.upsert("sys_certificate", f"name={CERT_NAME}", {
        "name": CERT_NAME,
        "short_description": "Signs the client_assertion ServiceNow sends to Entra (app 'ServiceNow - Access Fulfilment'). Public half: lab/terraform/modules/apps/files/servicenow-fulfilment.pem. Rotate with lab/servicenow/fulfilment-cert.py.",
        "type": "key_store",
        "active": "true",
    })
    # Replace the key store file: delete old attachments, attach the new one.
    for old in sn.query("sys_attachment", f"table_name=sys_certificate^table_sys_id={cert['sys_id']}", ["sys_id"]):
        sn.request("DELETE", f"/api/now/attachment/{old['sys_id']}")
    sn.attach("sys_certificate", cert["sys_id"], "fulfilment.jks", store_bytes, "application/octet-stream")
    sn.update("sys_certificate", cert["sys_id"], {"key_store_password": pw})
    print(f"sys_certificate {how}: {cert['sys_id']}")

    alias, how = sn.upsert("jwt_keystore_aliases", f"name={ALIAS}", {
        "name": ALIAS, "key_source": "sys_certificate", "signing_keystore": cert["sys_id"],
        "signing_algorithm": "rsa_256", "certificate_thumbprint": thumb, "x5t_header": "true",
        "active": "true", "signing_key_password": pw,
    })
    print(f"jwt_keystore_aliases {how}: {alias['sys_id']}")
    del pw

    prov, how = sn.upsert("jwt_provider", f"name={PROVIDER_NAME}", {
        "name": PROVIDER_NAME, "jwt_keystore_alias": alias["sys_id"], "expiry_interval": "300",
    })
    print(f"jwt_provider {how}: {prov['sys_id']}")

    os.makedirs(os.path.dirname(PEM_OUT), exist_ok=True)
    with open(PEM_OUT, "w") as f:
        f.write(pem)
    print(f"public certificate -> {os.path.relpath(PEM_OUT, REPO)} (SHA-1 thumbprint {thumb})")


if __name__ == "__main__":
    main()
