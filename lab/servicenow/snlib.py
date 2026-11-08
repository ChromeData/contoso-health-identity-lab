"""Table API client for the lab's ServiceNow PDI (dev459905).

WHY THIS SHAPE
- The admin password is read from the macOS login Keychain
  (contoso-lab-servicenow-admin / admin) with `security ... -w` into memory.
  It is never printed, never put in argv, never written to disk
  (AGENT-RULES: secrets only in the Keychain).
- The built-in `admin` is the Table API automation account
  (lab/terraform/modules/apps/README.md, "ServiceNow side door"): with SSO on
  it can no longer sign in to the UI, only call the API.
- Fail closed: any HTTP error raises SnError with the status and the body's
  error message. A caller never sees a silent empty result for "could not
  read" (TEAM-RULES-2 section 1).
- Run it with /usr/bin/python3 -I: the python.org framework build on the
  operator Mac has no CA bundle and refuses the instance's certificate.
"""
import base64
import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request

INSTANCE = os.environ.get("SN_INSTANCE_URL", "https://dev459905.service-now.com")
KEYCHAIN_SERVICE = "contoso-lab-servicenow-admin"
KEYCHAIN_ACCOUNT = "admin"


class SnError(RuntimeError):
    def __init__(self, status, message):
        super().__init__(f"ServiceNow {status}: {message}")
        self.status = status


def _keychain_password():
    r = subprocess.run(
        ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"],
        capture_output=True, text=True,
    )
    if r.returncode == 44:
        raise SnError("keychain", f"item {KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT} not found")
    if r.returncode != 0:
        raise SnError("keychain", "could not read the Keychain (locked?)")
    return r.stdout.rstrip("\n")


class Client:
    def __init__(self, instance=INSTANCE, opener=None, password_reader=_keychain_password):
        self.instance = instance.rstrip("/")
        self._opener = opener or urllib.request.urlopen
        self._password_reader = password_reader
        self._auth = None

    def _authz(self):
        if self._auth is None:
            pw = self._password_reader()
            self._auth = "Basic " + base64.b64encode(f"{KEYCHAIN_ACCOUNT}:{pw}".encode()).decode()
        return self._auth

    def request(self, method, path, body=None, params=None, raw=None, content_type="application/json"):
        url = self.instance + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": self._authz(), "Accept": "application/json", "Content-Type": content_type,
        })
        try:
            with self._opener(req, timeout=120) as resp:
                text = resp.read().decode()
                return json.loads(text) if text else None
        except urllib.error.HTTPError as e:
            detail = e.read().decode()[:600]
            try:
                detail = json.loads(detail).get("error", {}).get("message", detail)
            except Exception:
                pass
            raise SnError(e.code, detail) from None

    # --- Table API helpers -------------------------------------------------
    def query(self, table, query, fields=None, limit=100):
        p = {"sysparm_query": query, "sysparm_limit": str(limit), "sysparm_exclude_reference_link": "true"}
        if fields:
            p["sysparm_fields"] = ",".join(fields)
        return self.request("GET", f"/api/now/table/{table}", params=p)["result"]

    def one(self, table, query, fields=None):
        rows = self.query(table, query, fields, limit=2)
        if len(rows) > 1:
            raise SnError("ambiguous", f"{table}: more than one row for {query}")
        return rows[0] if rows else None

    def insert(self, table, values):
        return self.request("POST", f"/api/now/table/{table}", body=values)["result"]

    def update(self, table, sys_id, values):
        return self.request("PATCH", f"/api/now/table/{table}/{sys_id}", body=values)["result"]

    def delete(self, table, sys_id):
        return self.request("DELETE", f"/api/now/table/{table}/{sys_id}")

    def upsert(self, table, key_query, values):
        """Find one row by key_query; update it, or insert it. Returns (row, 'created'|'updated'|'same')."""
        row = self.one(table, key_query, ["sys_id"] + list(values.keys()))
        if row is None:
            return self.insert(table, values), "created"
        changed = {k: v for k, v in values.items() if str(row.get(k, "")) != str(v)}
        if not changed:
            return row, "same"
        return self.update(table, row["sys_id"], changed), "updated"

    def attach(self, table, sys_id, file_name, content, content_type="application/octet-stream"):
        params = {"table_name": table, "table_sys_id": sys_id, "file_name": file_name}
        return self.request("POST", "/api/now/attachment/file", params=params, raw=content,
                            content_type=content_type)["result"]
