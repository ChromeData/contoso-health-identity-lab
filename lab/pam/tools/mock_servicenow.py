#!/usr/bin/env python3
# =============================================================================
# mock_servicenow.py - a ServiceNow Table API stand-in for ticket-gated
# check-out (the itsm-mock compose service). STAND-IN for a ServiceNow
# Personal Developer Instance; tenant time swaps ITSM_URL for the PDI and
# nothing in psm-session.sh changes.
#
# Implements only what psm-session.sh / psm-ssh.sh call, in the shape
# ServiceNow returns:
#
#   GET /api/now/v2/table/<table>?sysparm_query=number=<NUM>
#       &sysparm_fields=a,b,assigned_to.user_name&sysparm_limit=1
#       &sysparm_display_value=false&sysparm_exclude_reference_link=true
#   -> 200 {"result": [ {field: value, ...} ]}   ([] when nothing matches:
#      that is Table API v2 behaviour; v1 answered 404, which is why the
#      broker pins /v2/ - verify: ServiceNow Table API docs, "Versioning")
#   -> 401 without valid Basic credentials (ServiceNow's integration-user
#      pattern; tenant time can move to OAuth client credentials). The mock
#      knows only ITSM_AUTH_SHA256 = sha256("user:password"), set by pam-up.sh
#      from .env: the password itself never enters the container.
#
# Tables:
#   change_request        the changes in ITSM_TICKETS_FILE
#   sysapproval_approver  ServiceNow's approval records, one row per approver
#                         per change - what the broker's DUAL CONTROL check
#                         reads (lib.sh itsm_validate). The lab file keeps
#                         them inline on the change ("approvals": [{"user_name",
#                         "state", "at"}]) so one ticket stays one record; the
#                         mock serves them ONLY as rows of this table, with the
#                         dot-walked reference fields a real instance returns:
#                         {"sysapproval.number": "CHG...", "approver.user_name":
#                         "ops-carol", "state": "approved", "sys_updated_on":
#                         "..."}. change_request never shows an "approvals"
#                         field (ServiceNow has none).
#
# Records come from ITSM_TICKETS_FILE (a JSON list, re-read on every request
# so itsm-ticket.sh and the e2e harness can add tickets without a restart).
# Each change: {"table": "change_request", "number": "CHG0040001",
#   "state": "-1", "approval": "approved", "start_date": "YYYY-MM-DD HH:MM:SS",
#   "end_date": "...", "assigned_to.user_name": "ops-alice",
#   "requested_by.user_name": "ops-alice", "short_description": "...",
#   "approvals": [{"user_name": "ops-carol", "state": "approved", "at": "..."}]}
# - dates in UTC, as ServiceNow stores them (sysparm_display_value=false
# returns stored values, not the user's zone).
#
# Test-only fault injection: ITSM_FAIL_TABLES=t1,t2 makes those tables answer
# HTTP 500 (test/itsm-dual-control.test.sh proves the broker then refuses).
# Compose never sets it.
#
# Lab only: plain HTTP on the compose network, published on 127.0.0.1.
# =============================================================================
import base64
import binascii
import hashlib
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

TICKETS = os.environ.get("ITSM_TICKETS_FILE", "/data/tickets.json")
AUTH_SHA256 = os.environ.get("ITSM_AUTH_SHA256", "").strip().lower()
FAIL_TABLES = {t for t in os.environ.get("ITSM_FAIL_TABLES", "").split(",") if t}
# Approval states ServiceNow stores on sysapproval_approver (stored values).
APPROVAL_STATES = {"requested", "approved", "rejected", "cancelled", "not requested", "not_required"}


def authorized(header: str) -> bool:
    # Fail closed: no configured hash means nobody gets in.
    if len(AUTH_SHA256) != 64 or not header.startswith("Basic "):
        return False
    try:
        pair = base64.b64decode(header[6:].strip(), validate=True)
    except (binascii.Error, ValueError):
        return False
    return hmac.compare_digest(hashlib.sha256(pair).hexdigest(), AUTH_SHA256)


def load_records():
    try:
        with open(TICKETS, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []


def table_rows(table: str):
    """Rows of one table, in ServiceNow's shape (see the header)."""
    records = [r for r in load_records() if isinstance(r, dict)]
    if table == "sysapproval_approver":
        rows = []
        for change in records:
            if change.get("table") != "change_request":
                continue
            for a in change.get("approvals") or []:
                if not isinstance(a, dict) or a.get("state") not in APPROVAL_STATES:
                    continue                      # malformed lab data is not an approval
                rows.append({"sysapproval.number": change.get("number", ""),
                             "approver.user_name": a.get("user_name", ""),
                             "state": a["state"],
                             "sys_updated_on": a.get("at", "")})
        return rows
    return [{k: v for k, v in r.items() if k not in ("table", "approvals")}
            for r in records if r.get("table") == table]


def matches(record, query: str) -> bool:
    # Supports the encoded-query subset the broker sends: field=value terms
    # joined by ^ (AND). Anything else matches nothing rather than everything.
    for term in filter(None, query.split("^")):
        if "=" not in term:
            return False
        field, value = term.split("=", 1)
        if str(record.get(field, "")) != value:
            return False
    return True


class Handler(BaseHTTPRequestHandler):
    server_version = "mock-servicenow/1"

    def _send(self, code: int, body) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802 - http.server naming
        url = urlparse(self.path)
        if url.path == "/health":
            return self._send(200, {"status": "ok"})
        if not authorized(self.headers.get("Authorization") or ""):
            return self._send(401, {"error": {"message": "User Not Authenticated", "detail": "Required to provide Auth information"}, "status": "failure"})
        parts = url.path.strip("/").split("/")
        # /api/now/table/<t> (latest) or /api/now/v2/table/<t>
        if parts[:2] != ["api", "now"] or "table" not in parts or len(parts) <= parts.index("table") + 1:
            return self._send(400, {"error": {"message": "Requested URI does not represent any resource"}, "status": "failure"})
        version = parts[2] if parts[2] != "table" else "latest"
        table = parts[parts.index("table") + 1]
        if table in FAIL_TABLES:
            return self._send(500, {"error": {"message": "injected failure (ITSM_FAIL_TABLES)"}, "status": "failure"})
        qs = parse_qs(url.query)
        query = qs.get("sysparm_query", [""])[0]
        fields = [f for f in qs.get("sysparm_fields", [""])[0].split(",") if f]
        try:
            limit = int(qs.get("sysparm_limit", ["10000"])[0] or 10000)
        except ValueError:
            return self._send(400, {"error": {"message": "sysparm_limit is not a number"}, "status": "failure"})
        rows = [r for r in table_rows(table) if matches(r, query)][:limit]
        result = [{f: r.get(f, "") for f in fields} if fields else r for r in rows]
        if not result and version == "v1":
            return self._send(404, {"error": {"message": "No Record found"}, "status": "failure"})
        return self._send(200, {"result": result})

    def log_message(self, fmt, *args):
        # One line per request (no query string: ticket numbers are fine,
        # but keep the access log shape boring and secret-free).
        sys.stderr.write("mock-servicenow %s %s\n" % (self.command, urlparse(self.path).path))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    # BIND: 0.0.0.0 inside the itsm-mock container (published on 127.0.0.1
    # only); the offline test runs it on the host with BIND=127.0.0.1.
    ThreadingHTTPServer((os.environ.get("BIND", "0.0.0.0"), port), Handler).serve_forever()
