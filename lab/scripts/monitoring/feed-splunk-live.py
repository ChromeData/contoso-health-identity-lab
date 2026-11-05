#!/usr/bin/env python3
"""
feed-splunk-live.py - the LIVE feed: lab tenant logs -> local Splunk, every 5 minutes.

WHAT IT IS
  The second SIEM (lab/splunk, Splunk Enterprise trial in Docker) runs the same
  22 detections as Sentinel, written in SPL. Until this feed it only ever saw
  synthetic test rows (replay-synthetic.py) or a one-off replay
  (ingest-from-loganalytics.sh). This script keeps it fed from the real tenant:
  a per-user LaunchAgent runs `run` every 300 s, so the Splunk alerts judge the
  same sign-ins, audit events and DC01 logons Sentinel judges, a few minutes
  apart.

WHERE THE EVENTS COME FROM (and why there, not Graph)
  The Log Analytics workspace loga-idlab, the same rows Sentinel's rules read:
  Entra's diagnostic setting streams SigninLogs (interactive sign-ins),
  AADNonInteractiveUserSignInLogs and AuditLogs (directory audit) into it; DC01's
  Azure Monitor Agent sends SecurityEvent; Identity Protection sends
  AADUserRiskEvents / AADRiskyUsers; ingest-vault-audit.sh sends VaultCheckout_CL.
  Those seven tables are exactly what lab/splunk/detections/*.spl search
  (sourcetype azure:loganalytics:<table>, Log Analytics column names). Graph's
  auditLogs/signIns and auditLogs/directoryAudits carry the SAME Entra events in
  a different shape (camelCase, status.errorCode instead of ResultType), so
  feeding Graph would need a field-alias layer the twins were never written
  against, and would cover only two of the seven tables. Reading the workspace
  keeps both SIEMs on identical input. ADR 0023 (amendment 2026-11-05) records
  the choice; lab/docs/STAND-INS.md names the production path it stands in for
  (Entra diagnostic settings -> Event Hub -> Splunk Add-on for Microsoft Cloud
  Services).

HOW IT READS (as the lab operator, never a person)
  lab/scripts/operator/op az account get-access-token --resource
  https://api.loganalytics.io  -> a bearer token held in this process only, then
  POST https://api.loganalytics.io/v1/workspaces/<customerId>/query
  (Azure Monitor Logs query API, Learn: "Azure Monitor Log Analytics API
  overview" / "Request format"). The operator holds Owner on the lab
  subscription, which includes Log Analytics read (no new permission).

WATERMARK + DE-DUPLICATION (never sends a row twice)
  Per table, the state file keeps the newest ingestion_time() sent (the
  watermark) and the ids of the rows sent in the last OVERLAP minutes. Each
  run asks for rows ingested after (watermark - OVERLAP), oldest first, and
  drops every row whose Log Analytics record id (_ItemId, the workspace's
  unique id per record - Learn: "Standard columns in Azure Monitor Logs") was
  already sent. The overlap catches a row that becomes queryable a little
  after its ingestion_time; the id set makes the overlap harmless.
  ingestion_time(), not TimeGenerated, because Entra rows reach the workspace
  2-15 min after they happen (TimeGenerated would skip late rows).
  The state is saved after EVERY accepted HEC batch (write-temp + fsync +
  rename), so a crash can at most repeat the one batch that was in flight.
  A run holds an exclusive lock: a second copy refuses to start.

HOW IT WRITES
  Splunk HTTP Event Collector, https://127.0.0.1:8088/services/collector/event
  (Splunk docs: "Format events for HTTP Event Collector"), with its OWN token
  (name contoso_live_feed, pinned to index=entra) whose value lives only in the
  login Keychain (item contoso-splunk-hec-live). `setup` creates that token with
  Splunk's REST API ("data/inputs/http" in the Splunk REST API reference) using
  the admin password from the running stack's lab/splunk/.env, read in this
  process and never printed. Every event: index=entra, the sourcetype the SPL
  expects, source=livefeed:loga-idlab:<Table>, _time = TimeGenerated (so the
  alerts' -1h windows work exactly like Sentinel's), and the record id as the
  indexed field feed_item_id (so a duplicate is one search away).
  An HEC answer other than HTTP 200 + {"code":0} stops the run with a non-zero
  exit (503/unreachable is retried twice first) and the watermark stays where
  the last ACCEPTED batch left it.

HEARTBEAT
  After a run in which every table succeeded, one event
  sourcetype=contoso:livefeed:heartbeat (counts and watermarks, no secrets).
  `check` (used by lab/scripts/demo/preflight.sh) searches Splunk as a
  search-only user (contoso-feed-check, role contoso_feed_reader: capability
  search, index entra only; password in Keychain contoso-splunk-feed-reader)
  and fails when the feed's newest event is older than 15 minutes. A quiet
  tenant still heartbeats, so "nothing happened" is never mistaken for "the
  feed is down".

COMMANDS
  setup      create/verify the HEC token + search-only user, store both in Keychain
  run        one poll (what the LaunchAgent runs every 300 s)
  check      is the newest live-feed event in Splunk younger than --max-age-minutes?
  status     state file + LaunchAgent state
  install    copy this script to the state dir, render the LaunchAgent, load it
  uninstall  unload and remove the LaunchAgent (state and Keychain items kept)

  python3 -I lab/scripts/monitoring/feed-splunk-live.py setup
  python3 -I lab/scripts/monitoring/feed-splunk-live.py run
  python3 -I lab/scripts/monitoring/feed-splunk-live.py install
  python3 -I lab/scripts/monitoring/feed-splunk-live.py check

  Use /usr/bin/python3 (macOS): it trusts the system roots. A python.org build
  without its "Install Certificates" step fails TLS to api.loganalytics.io.

SECRETS
  The HEC token, the Splunk admin password, the reader password and the Log
  Analytics bearer token live in this process's memory and the Keychain only:
  never in argv, a log, the state file or an exception message. Keychain writes
  go through `security -i` on stdin (the repo's pattern, see
  lab/scripts/operator/new-operator-cert.sh).

Python 3.9 compatible (macOS /usr/bin/python3). Standard library only.
"""
import argparse
import base64
import datetime as dt
import fcntl
import json
import os
import plistlib
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2] if len(HERE.parents) > 2 else HERE

# --- fixed names -------------------------------------------------------------------
INDEX = "entra"                                  # the one index every SPL twin searches (app/indexes.conf)
HEC_TOKEN_NAME = "contoso_live_feed"             # Splunk HEC input name (data/inputs/http)
HEC_KEYCHAIN = ("contoso-splunk-hec-live", HEC_TOKEN_NAME)
READER_ROLE = "contoso_feed_reader"
READER_USER = "contoso-feed-check"
READER_KEYCHAIN = ("contoso-splunk-feed-reader", READER_USER)
HEARTBEAT_ST = "contoso:livefeed:heartbeat"
SETUP_ST = "contoso:livefeed:setup"
SOURCE_PREFIX = "livefeed"
AGENT_LABEL = "com.contoso.splunk-live-feed"
SPLUNK_CONTAINER = "contoso-splunk-splunk-1"     # compose project contoso-splunk, service splunk
LA_API = "https://api.loganalytics.io/v1/workspaces/{}/query"
LA_RESOURCE = "https://api.loganalytics.io"
DEFAULT_RG, DEFAULT_WS = "rg-identity-lab", "loga-idlab"

# Table -> sourcetype: the seven tables lab/splunk/detections/*.spl read, named as
# in app/contoso_identity/default/props.conf. Also the allow-list: a table name is
# interpolated into KQL, so nothing outside this map is ever accepted.
TABLES = {
    "SigninLogs": "azure:loganalytics:signinlogs",
    "AADNonInteractiveUserSignInLogs": "azure:loganalytics:aadnoninteractiveusersigninlogs",
    "AuditLogs": "azure:loganalytics:auditlogs",
    "AADUserRiskEvents": "azure:loganalytics:aaduserriskevents",
    "AADRiskyUsers": "azure:loganalytics:aadriskyusers",
    "SecurityEvent": "azure:loganalytics:securityevent",
    "VaultCheckout_CL": "azure:loganalytics:vaultcheckout_cl",
}

# Detection-critical columns first (search-time JSON extraction reads events front
# to back - app/contoso_identity/default/limits.conf). Same list as the replay
# (lab/splunk/ingest-from-loganalytics.sh PRIORITY_JSON), so a live event and a
# replayed one look the same to the SPL.
PRIORITY = ["TimeGenerated", "Type", "UserPrincipalName", "UserDisplayName", "IPAddress", "ResultType",
            "ResultDescription", "AppDisplayName", "ClientAppUsed", "ConditionalAccessStatus", "Location",
            "RiskLevelDuringSignIn", "CorrelationId", "LoggedByService", "Category", "ActivityDisplayName",
            "Result", "OperationName", "LaIngestionTime", "LocationDetails", "ConditionalAccessPolicies",
            "InitiatedBy", "TargetResources", "AdditionalDetails", "EventID", "Computer", "TargetUserName",
            "LogonType", "RiskLevel", "RiskState", "RiskEventType", "RiskDetail", "Operation", "Account",
            "AccountResolved"]
PRIO_INDEX = {k: i for i, k in enumerate(PRIORITY)}

OVERLAP_MIN = 10          # re-read window behind the watermark (de-duplicated by record id)
BACKFILL_HOURS = 24       # first run only: how far back to start
MAX_ROWS = 20000          # per table per run; the rest follows next run (oldest first). Lab
                          # volume is < 1,000 rows per 10 min; more than MAX_ROWS rows inside
                          # one overlap window would stall a table (lower --overlap-minutes)
BATCH = 200               # events per HEC POST
MAX_AGE_MIN = 15          # `check`: the preflight threshold

ISO_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?Z$")
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")   # what we store via `security -i` (no quoting needed)


class FeedError(Exception):
    """A failure that must stop the run loudly (exit 1)."""


def log(msg: str) -> None:
    print("[%s] %s" % (dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), msg), flush=True)


# --- time helpers (exact: Log Analytics prints 7 fractional digits) -------------------------
def tkey(iso: str) -> Tuple[int, str]:
    """Exact sort key of an ISO-8601 UTC timestamp: (epoch seconds, fraction padded to 9
    digits). Floats lose the 100-ns digit and plain string order breaks when fraction
    lengths differ, so the watermark is compared with this."""
    m = ISO_RE.match(iso or "")
    if not m:
        raise FeedError("not an ISO-8601 UTC timestamp: %r" % (iso,))
    secs = int(dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp())
    frac = (m.group(2) or ".")[1:]
    return secs, (frac + "000000000")[:9]


def epoch(iso: str) -> float:
    """TimeGenerated -> HEC "time" (epoch seconds, millisecond precision)."""
    secs, frac = tkey(iso)
    return (secs * 1000 + int(frac[:3])) / 1000.0


def iso_shift(iso: str, minutes: float) -> str:
    """iso + minutes, printed with microseconds (rounded DOWN: a since-bound that is a
    few hundred ns early only re-reads rows the id set already holds)."""
    secs, frac = tkey(iso)
    t = dt.datetime.fromtimestamp(secs, dt.timezone.utc) + dt.timedelta(microseconds=int(frac[:6])) + dt.timedelta(minutes=minutes)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def utcnow_iso(now: Optional[dt.datetime] = None) -> str:
    return (now or dt.datetime.now(dt.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- Log Analytics ---------------------------------------------------------------------------
def build_kql(table: str, since_iso: str, limit: int = MAX_ROWS) -> str:
    if table not in TABLES:
        raise FeedError("unsupported table %r (allowed: %s)" % (table, ", ".join(TABLES)))
    tkey(since_iso)  # validates: only a well-formed timestamp is ever interpolated
    # pack_all(true): every non-empty column as one property bag (nulls/empties dropped,
    # exactly like the replay). _ItemId travels separately as the de-dup key.
    return ("%s\n| extend LaIngestionTime = ingestion_time()\n| where LaIngestionTime > datetime(%s)\n"
            "| top %d by LaIngestionTime asc\n| project Row = pack_all(true), ItemId = _ItemId, LaIngestionTime"
            % (table, since_iso, limit))


def timespan_for(since_iso: str, now: dt.datetime) -> str:
    """The query API also bounds TimeGenerated (timespan). Rows ingested after `since`
    happened before now and at most a day before `since` (Entra's lag is minutes), so
    the window is since - 1 day .. now, rounded up to whole hours."""
    secs, _ = tkey(since_iso)
    hours = int((now.timestamp() - secs) // 3600) + 25
    return "PT%dH" % hours


def parse_rows(resp: dict, table: str) -> List[Tuple[str, str, dict]]:
    """Query API response -> [(item_id, ingestion_iso, row)], in the order returned.
    Fails on any shape it does not expect instead of dropping rows."""
    try:
        t = resp["tables"][0]
        cols = [c["name"] for c in t["columns"]]
    except (KeyError, IndexError, TypeError):
        raise FeedError("%s: unexpected query response shape" % table)
    if cols != ["Row", "ItemId", "LaIngestionTime"]:
        raise FeedError("%s: unexpected columns %s (the KQL projection changed?)" % (table, cols))
    out = []
    for raw, item_id, ing in t["rows"]:
        try:
            row = json.loads(raw) if isinstance(raw, str) else raw
        except ValueError:
            raise FeedError("%s: a Row is not valid JSON" % table)
        if not isinstance(row, dict):
            raise FeedError("%s: a Row is not an object" % table)
        if not item_id or not isinstance(item_id, str):
            raise FeedError("%s: a row has no _ItemId - cannot de-duplicate, refusing to send" % table)
        tkey(ing)
        out.append((item_id, ing, row))
    return out


def _dyn(v):
    """A string that IS JSON text becomes JSON (AADNonInteractiveUserSignInLogs and
    several SigninLogs columns store LocationDetails, AuthenticationDetails... as
    text); a string that only STARTS with [ or { (a display name like "[EXT] Dana")
    is kept verbatim - the replay's jq `dyn` does the same."""
    if isinstance(v, str) and v.lstrip()[:1] in ("[", "{"):
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def to_event(table: str, row: dict, item_id: str, host: str) -> dict:
    """One Log Analytics row -> one HEC envelope (the replay's JQ_TRANSFORM, in Python)."""
    tg = row.get("TimeGenerated")
    if not isinstance(tg, str):
        raise FeedError("%s: row %s has no TimeGenerated" % (table, item_id))
    body = {k: _dyn(v) for k, v in row.items() if not k.startswith("_")}   # _ItemId etc.: workspace system columns
    ordered = dict(sorted(body.items(), key=lambda kv: (PRIO_INDEX.get(kv[0], 999), kv[0])))
    return {"time": epoch(tg), "host": host, "source": "%s:%s:%s" % (SOURCE_PREFIX, host, table),
            "sourcetype": TABLES[table], "index": INDEX, "fields": {"feed_item_id": item_id}, "event": ordered}


# --- state -----------------------------------------------------------------------------------
class State:
    """state.json in the state dir (mode 600). Holds watermarks, the recent record ids,
    the cached workspace id and the last success time - no secrets."""

    def __init__(self, path: Path):
        self.path = path
        self.data = {"version": 1, "tables": {}}
        if path.exists():
            try:
                self.data = json.loads(path.read_text())
            except ValueError:
                raise FeedError("%s is corrupt - inspect it; delete it only if you accept re-sending the backfill window" % path)
            if self.data.get("version") != 1 or not isinstance(self.data.get("tables"), dict):
                raise FeedError("%s has an unknown layout" % path)

    def table(self, name: str) -> dict:
        return self.data["tables"].setdefault(name, {"hwm": None, "seen": {}})

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".state.", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self.data, f, indent=1, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, str(self.path))
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise


def prune_seen(ts: dict, overlap_min: int) -> None:
    """Drop ids that the next query can no longer return (ingested before
    watermark - overlap - 1 min), so the set stays small."""
    if not ts.get("hwm"):
        return
    floor = tkey(iso_shift(ts["hwm"], -(overlap_min + 1)))
    ts["seen"] = {i: ing for i, ing in ts["seen"].items() if tkey(ing) >= floor}


# --- HEC -------------------------------------------------------------------------------------
LOOPBACK = ("127.0.0.1", "localhost", "::1", "[::1]")


def loopback_ctx(url: str) -> Optional[ssl.SSLContext]:
    """Splunk's HEC/REST use its self-signed certificate. Verification is switched
    off ONLY for a loopback URL (the compose file publishes nothing else); any other
    host is refused rather than trusted blindly."""
    u = urllib.parse.urlparse(url)
    if u.hostname not in LOOPBACK:
        raise FeedError("refusing non-loopback Splunk URL %s (certificate checks are off for 127.0.0.1 only)" % url)
    if u.scheme != "https":
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class Hec:
    def __init__(self, url: str, token: str, sleep: Callable[[float], None] = time.sleep):
        self.url = url.rstrip("/")
        self.ctx = loopback_ctx(self.url)
        self._auth = "Splunk " + token        # never logged, never in an exception
        self.sleep = sleep

    def healthy(self) -> bool:
        try:
            with urllib.request.urlopen(self.url + "/services/collector/health", context=self.ctx, timeout=10) as r:
                return r.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def post(self, events: List[dict]) -> None:
        """POST newline-delimited envelopes. Success = HTTP 200 and {"code":0}. 503 or
        unreachable: two retries with back-off. Anything else raises FeedError with
        Splunk's own answer (it never echoes the token)."""
        body = "\n".join(json.dumps(e, separators=(",", ":")) for e in events).encode()
        last = ""
        for attempt in (1, 2, 3):
            req = urllib.request.Request(self.url + "/services/collector/event", data=body, method="POST",
                                         headers={"Authorization": self._auth, "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, context=self.ctx, timeout=120) as r:
                    code, text = r.status, r.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                code, text = e.code, e.read().decode("utf-8", "replace")
            except (urllib.error.URLError, OSError) as e:
                code, text = 0, "unreachable (%s)" % type(e).__name__
            if code == 200:
                try:
                    if json.loads(text).get("code") == 0:
                        return
                except ValueError:
                    pass
            last = "HTTP %s %s" % (code, text[:300].replace("\n", " "))
            if code in (0, 503) and attempt < 3:
                log("WARN: HEC answered %s (attempt %d/3) - retrying" % (last, attempt))
                self.sleep(5 * attempt)
                continue
            break
        raise FeedError("HEC rejected the batch: " + last)


# --- the run ---------------------------------------------------------------------------------
QueryFn = Callable[[str, str], dict]   # (kql, timespan) -> query API JSON


def feed_table(table: str, st: State, query: QueryFn, hec: Hec, host: str, now: dt.datetime,
               overlap_min: int = OVERLAP_MIN, backfill_h: int = BACKFILL_HOURS, batch: int = BATCH,
               dry_run: bool = False) -> Tuple[int, int]:
    """Send one table's new rows. Returns (sent, duplicates_skipped). The watermark and
    id set advance after each ACCEPTED batch and are saved at once."""
    ts = st.table(table)
    since = iso_shift(ts["hwm"], -overlap_min) if ts.get("hwm") else utcnow_iso(now - dt.timedelta(hours=backfill_h))
    rows = parse_rows(query(build_kql(table, since), timespan_for(since, now)), table)
    if len(rows) >= MAX_ROWS:
        log("WARN: %s returned the %d-row cap; the rest follows on the next run" % (table, MAX_ROWS))
    fresh, dups = [], 0
    for item_id, ing, row in rows:
        if item_id in ts["seen"]:
            dups += 1
            continue
        fresh.append((item_id, ing, to_event(table, row, item_id, host)))   # converts ALL before sending any
    if dry_run:
        log("%s: DRY RUN - %d new, %d already sent; nothing sent, state unchanged" % (table, len(fresh), dups))
        return 0, dups
    sent = 0
    for i in range(0, len(fresh), batch):
        chunk = fresh[i:i + batch]
        hec.post([ev for _, _, ev in chunk])
        for item_id, ing, _ in chunk:
            ts["seen"][item_id] = ing
            if not ts.get("hwm") or tkey(ing) > tkey(ts["hwm"]):
                ts["hwm"] = ing
        st.save()
        sent += len(chunk)
    prune_seen(ts, overlap_min)
    st.save()
    log("%s: sent %d, skipped %d already sent, watermark %s" % (table, sent, dups, ts.get("hwm") or "-"))
    return sent, dups


def run_once(st: State, query: QueryFn, hec: Hec, host: str, tables: List[str],
             now: Optional[dt.datetime] = None, dry_run: bool = False, **kw) -> int:
    """All tables; a failed table does not stop the others, but the run then exits 1 and
    writes NO heartbeat (so `check` notices)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    if not dry_run and not hec.healthy():
        raise FeedError("Splunk HEC is not answering on %s - is the container up? (lab/splunk/splunk-up.sh)" % hec.url)
    sent, dups, errors = {}, {}, []
    for t in tables:
        try:
            sent[t], dups[t] = feed_table(t, st, query, hec, host, now, dry_run=dry_run, **kw)
        except FeedError as e:
            errors.append(str(e))
            log("ERROR: %s" % e)
    if errors:
        raise FeedError("%d of %d tables failed this run (no heartbeat written): %s" % (len(errors), len(tables), "; ".join(errors)))
    if dry_run:
        return 0
    fin = dt.datetime.now(dt.timezone.utc)
    hec.post([{"time": round(fin.timestamp(), 3), "host": host, "source": "%s:heartbeat" % SOURCE_PREFIX,
               "sourcetype": HEARTBEAT_ST, "index": INDEX,
               "event": {"status": "ok", "run_started": utcnow_iso(now), "run_finished": utcnow_iso(fin),
                         "sent": sent, "duplicates_skipped": dups,
                         "watermarks": {t: st.table(t).get("hwm") for t in tables}}}])
    st.data["last_success"] = utcnow_iso(fin)
    st.save()
    log("done: %d events sent (%s); heartbeat written" % (sum(sent.values()), ", ".join("%s %d" % kv for kv in sent.items() if kv[1]) or "nothing new"))
    return sum(sent.values())


# --- operator, Keychain, Splunk REST -----------------------------------------------------------
def op_path(arg: Optional[str]) -> str:
    p = arg or os.environ.get("CONTOSO_OP") or str(REPO / "lab" / "scripts" / "operator" / "op")
    if not os.access(p, os.X_OK):
        raise FeedError("operator wrapper not found or not executable: %s (pass --op)" % p)
    return p


def op_capture(op: str, args: List[str], what: str) -> str:
    try:
        p = subprocess.run([op] + args, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        raise FeedError("%s timed out after 300 s" % what)
    if p.returncode != 0:
        # az's stderr carries the reason, never a token.
        raise FeedError("%s failed (exit %d): %s" % (what, p.returncode, p.stderr.strip()[-400:]))
    return p.stdout.strip()


def make_la_query(op: str, workspace_id: str) -> QueryFn:
    token = {"v": None}

    def query(kql: str, timespan: str) -> dict:
        if token["v"] is None:
            token["v"] = op_capture(op, ["az", "account", "get-access-token", "--resource", LA_RESOURCE,
                                         "--query", "accessToken", "-o", "tsv"], "operator token for Log Analytics")
        req = urllib.request.Request(LA_API.format(workspace_id), method="POST",
                                     data=json.dumps({"query": kql, "timespan": timespan}).encode(),
                                     headers={"Authorization": "Bearer " + token["v"], "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise FeedError("Log Analytics query failed: HTTP %d %s" % (e.code, e.read()[:400].decode("utf-8", "replace")))
        except (urllib.error.URLError, OSError) as e:
            raise FeedError("Log Analytics unreachable: %s" % e)
    return query


def workspace_id(st: State, op: str, given: Optional[str]) -> str:
    wid = given or st.data.get("workspace_id")
    if not wid:
        wid = op_capture(op, ["az", "monitor", "log-analytics", "workspace", "show", "-g", DEFAULT_RG, "-n", DEFAULT_WS,
                              "--query", "customerId", "-o", "tsv"], "workspace lookup (%s in %s)" % (DEFAULT_WS, DEFAULT_RG))
    if not GUID_RE.match(wid or ""):
        raise FeedError("workspace customer id is not a GUID: %r" % wid)
    st.data["workspace_id"] = wid
    return wid


def keychain_get(service: str, account: str) -> Optional[str]:
    """None = item not found (exit 44). Any other failure (a locked Keychain) raises:
    "could not read" must never look like "not there"."""
    p = subprocess.run(["security", "find-generic-password", "-s", service, "-a", account, "-w"], capture_output=True, text=True)
    if p.returncode == 44:
        return None
    if p.returncode != 0:
        raise FeedError("could not read Keychain item %s (exit %d) - is the login Keychain unlocked?" % (service, p.returncode))
    return p.stdout.rstrip("\n")


def keychain_set(service: str, account: str, label: str, secret: str) -> None:
    if not SECRET_RE.match(secret):
        raise FeedError("refusing to store a secret with unexpected characters")
    cmd = 'add-generic-password -U -s %s -a %s -l "%s" -w %s\n' % (service, account, label, secret)
    subprocess.run(["security", "-i"], input=cmd, capture_output=True, text=True)
    if keychain_get(service, account) != secret:
        raise FeedError("Keychain item %s did not read back after writing" % service)


MGMT_URL = "https://127.0.0.1:8089"     # Splunk management API (loopback only, docker-compose.yml)


class SplunkRest:
    def __init__(self, user: str, password: str, url: Optional[str] = None):
        self.url = (url or MGMT_URL).rstrip("/")
        self.ctx = loopback_ctx(self.url)
        self._auth = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()

    def call(self, method: str, path: str, data: Optional[dict] = None, ok404: bool = False) -> Optional[dict]:
        body = urllib.parse.urlencode(data, doseq=True).encode() if data is not None else None
        sep = "&" if "?" in path else "?"
        req = urllib.request.Request(self.url + path + sep + "output_mode=json", data=body, method=method,
                                     headers={"Authorization": self._auth})
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=120) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if e.code == 404 and ok404:
                return None
            raise FeedError("Splunk REST %s %s: HTTP %d %s" % (method, path.split("?")[0], e.code, e.read()[:300].decode("utf-8", "replace")))
        except (urllib.error.URLError, OSError) as e:
            raise FeedError("Splunk management API unreachable (%s)" % type(e).__name__)


def splunk_env_path(given: Optional[str]) -> Path:
    """The admin password lives in lab/splunk/.env of the checkout that STARTED the
    running container (splunk-up.sh writes it there, 0600, gitignored). Docker's
    compose label names that directory, so no path is guessed."""
    if given:
        p = Path(given)
    else:
        r = subprocess.run(["docker", "inspect", SPLUNK_CONTAINER, "--format",
                            '{{index .Config.Labels "com.docker.compose.project.working_dir"}}'], capture_output=True, text=True)
        if r.returncode != 0 or not r.stdout.strip():
            raise FeedError("could not read the compose directory of %s (is Splunk running?)" % SPLUNK_CONTAINER)
        p = Path(r.stdout.strip()) / ".env"
    if not p.is_file():
        raise FeedError("Splunk .env not found at %s" % p)
    return p


def read_env_value(path: Path, key: str) -> str:
    for line in path.read_text().splitlines():
        if line.startswith(key + "="):
            v = line.split("=", 1)[1].strip()
            if v:
                return v
    raise FeedError("%s has no %s" % (path, key))


def hec_token_setup(admin: SplunkRest) -> str:
    """Create (or find) the feed's own HEC token pinned to index=entra, read it back,
    store it in Keychain. Splunk REST API reference, data/inputs/http: POST creates
    a token (name, index, indexes; the value is generated when none is given) and
    POST on the named input edits it."""
    path = "/servicesNS/nobody/splunk_httpinput/data/inputs/http"
    cur = admin.call("GET", "%s/%s" % (path, urllib.parse.quote("http://" + HEC_TOKEN_NAME, safe="")), ok404=True)
    if cur is None:
        cur = admin.call("POST", path, {"name": HEC_TOKEN_NAME, "index": INDEX, "indexes": INDEX,
                                        "description": "Contoso lab live feed (lab/scripts/monitoring/feed-splunk-live.py)"})
        log("HEC token %s created" % HEC_TOKEN_NAME)
    c = cur["entry"][0]["content"]
    idx = c.get("indexes")
    idx = idx if isinstance(idx, list) else [s.strip() for s in str(idx or "").split(",") if s.strip()]
    if c.get("index") != INDEX or idx != [INDEX] or str(c.get("disabled")).lower() in ("1", "true"):
        admin.call("POST", "%s/%s" % (path, urllib.parse.quote("http://" + HEC_TOKEN_NAME, safe="")),
                   {"index": INDEX, "indexes": INDEX, "disabled": "0"})
        c = admin.call("GET", "%s/%s" % (path, urllib.parse.quote("http://" + HEC_TOKEN_NAME, safe="")))["entry"][0]["content"]
        idx = c.get("indexes") if isinstance(c.get("indexes"), list) else [c.get("indexes")]
        if c.get("index") != INDEX or idx != [INDEX]:
            raise FeedError("HEC token %s is not pinned to index=%s after the update" % (HEC_TOKEN_NAME, INDEX))
    token = c.get("token") or ""
    if not GUID_RE.match(token):
        raise FeedError("Splunk did not return a GUID token for %s" % HEC_TOKEN_NAME)
    if keychain_get(*HEC_KEYCHAIN) != token:
        keychain_set(HEC_KEYCHAIN[0], HEC_KEYCHAIN[1], "Contoso lab Splunk HEC token (live feed)", token)
        log("HEC token stored in Keychain item %s" % HEC_KEYCHAIN[0])
    log("HEC token %s: pinned to index=%s (read back), value in Keychain only" % (HEC_TOKEN_NAME, INDEX))
    return token


def reader_setup(admin: SplunkRest) -> None:
    """A search-only identity for `check`, so the preflight never needs the admin
    password: role with the single capability `search`, allowed and default index
    entra, no imported roles (Splunk REST API reference: authorization/roles,
    authentication/users)."""
    role = {"capabilities": "search", "srchIndexesAllowed": INDEX, "srchIndexesDefault": INDEX}
    if admin.call("GET", "/services/authorization/roles/" + READER_ROLE, ok404=True) is None:
        admin.call("POST", "/services/authorization/roles", dict(role, name=READER_ROLE))
        log("Splunk role %s created" % READER_ROLE)
    else:
        admin.call("POST", "/services/authorization/roles/" + READER_ROLE, role)
    # Read the role back instead of trusting the POST: exactly `search`, only the entra
    # index, nothing imported (an imported role would bring its capabilities and indexes).
    rc = admin.call("GET", "/services/authorization/roles/" + READER_ROLE)["entry"][0]["content"]
    if rc.get("capabilities") != ["search"] or rc.get("imported_roles") or rc.get("srchIndexesAllowed") != [INDEX]:
        raise FeedError("role %s is broader than search on index=%s (capabilities %s, imported %s, indexes %s)"
                        % (READER_ROLE, INDEX, rc.get("capabilities"), rc.get("imported_roles"), rc.get("srchIndexesAllowed")))
    pw = keychain_get(*READER_KEYCHAIN)
    exists = admin.call("GET", "/services/authentication/users/" + READER_USER, ok404=True) is not None
    works = False
    if exists and pw:
        try:
            SplunkRest(READER_USER, pw).call("GET", "/services/authentication/current-context")
            works = True
        except FeedError:
            works = False
    if not works:
        pw = secrets.token_urlsafe(24)
        if exists:
            admin.call("POST", "/services/authentication/users/" + READER_USER, {"password": pw, "roles": READER_ROLE})
        else:
            admin.call("POST", "/services/authentication/users", {"name": READER_USER, "password": pw, "roles": READER_ROLE})
            log("Splunk user %s created" % READER_USER)
        keychain_set(READER_KEYCHAIN[0], READER_KEYCHAIN[1], "Contoso lab Splunk search-only user (live feed check)", pw)
    ctx = SplunkRest(READER_USER, pw).call("GET", "/services/authentication/current-context")
    roles = ctx["entry"][0]["content"].get("roles")
    if roles != [READER_ROLE]:
        raise FeedError("%s has roles %s, expected only %s" % (READER_USER, roles, READER_ROLE))
    log("Search-only user %s: signs in, roles = [%s], password in Keychain item %s" % (READER_USER, READER_ROLE, READER_KEYCHAIN[0]))


def cmd_setup(a) -> int:
    envp = splunk_env_path(a.splunk_env)
    admin = SplunkRest("admin", read_env_value(envp, "SPLUNK_PASSWORD"))
    token = hec_token_setup(admin)
    reader_setup(admin)
    hec = Hec(a.hec_url, token)
    if not hec.healthy():
        raise FeedError("HEC health endpoint is not answering on %s" % a.hec_url)
    hec.post([{"time": round(time.time(), 3), "host": DEFAULT_WS, "source": "%s:setup" % SOURCE_PREFIX,
               "sourcetype": SETUP_ST, "index": INDEX, "event": {"message": "live feed setup: token accepted"}}])
    log("HEC accepted a setup event with the new token. Next: run, then install.")
    return 0


def cmd_run(a) -> int:
    sd = Path(a.state_dir).expanduser()
    sd.mkdir(parents=True, exist_ok=True)
    os.chmod(str(sd), 0o700)
    with open(str(sd / "lock"), "w") as lockf:          # released when this run ends, however it ends
        try:
            fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log("another run holds %s - not starting a second copy" % (sd / "lock"))
            return 3
        st = State(sd / "state.json")
        token = keychain_get(*HEC_KEYCHAIN)
        if not token:
            raise FeedError("no HEC token in Keychain item %s - run setup first" % HEC_KEYCHAIN[0])
        op = op_path(a.op)
        wid = workspace_id(st, op, a.workspace_id)
        tables = [t.strip() for t in a.tables.split(",") if t.strip()]
        for t in tables:
            if t not in TABLES:
                raise FeedError("unsupported table %r" % t)
        run_once(st, make_la_query(op, wid), Hec(a.hec_url, token), DEFAULT_WS, tables,
                 dry_run=a.dry_run, overlap_min=a.overlap_minutes, backfill_h=a.backfill_hours)
    return 0


def evaluate_check(now_epoch: float, heartbeat_epoch: Optional[float], tenant_epoch: Optional[float],
                   tenant_count: int, max_age_min: int) -> Tuple[bool, str]:
    """Pure verdict for `check`: OK only if the feed's newest event (its heartbeat,
    written after a fully successful poll) reached Splunk within max_age_min."""
    def ago(e):
        return "never" if e is None else "%d min ago" % int((now_epoch - e) // 60)
    newest = max([e for e in (heartbeat_epoch, tenant_epoch) if e is not None], default=None)
    ok = heartbeat_epoch is not None and (now_epoch - heartbeat_epoch) < max_age_min * 60
    msg = ("Splunk live feed: last poll %s, newest tenant event received %s (%d tenant events received in 24 h)"
           % (ago(heartbeat_epoch), ago(tenant_epoch), tenant_count))
    if not ok:
        msg += " - older than %d min: is the LaunchAgent loaded? (feed-splunk-live.py status)" % max_age_min
        if newest is None:
            msg = msg.replace("last poll never", "no feed event in Splunk")
    return ok, msg


def cmd_check(a) -> int:
    pw = keychain_get(*READER_KEYCHAIN)
    if not pw:
        print("Splunk live feed: no search-only password in Keychain item %s - run setup" % READER_KEYCHAIN[0])
        return 1
    q = ('search index=%s source="%s:*" _index_earliest=-24h earliest=-30d latest=+1d '
         '| eval kind=if(sourcetype=="%s","heartbeat",if(sourcetype=="%s","setup","tenant")) '
         '| stats max(_indextime) AS last count BY kind' % (INDEX, SOURCE_PREFIX, HEARTBEAT_ST, SETUP_ST))
    try:
        res = SplunkRest(READER_USER, pw).call("POST", "/services/search/jobs",
                                               {"search": q, "exec_mode": "oneshot", "count": "0"})
    except FeedError as e:
        print("Splunk live feed: could not search Splunk (%s)" % e)
        return 1
    by = {r["kind"]: r for r in res.get("results", [])}
    hb = float(by["heartbeat"]["last"]) if "heartbeat" in by else None
    te = float(by["tenant"]["last"]) if "tenant" in by else None
    ok, msg = evaluate_check(time.time(), hb, te, int(by.get("tenant", {}).get("count", 0)), a.max_age_minutes)
    print(msg)
    return 0 if ok else 1


# --- LaunchAgent -------------------------------------------------------------------------------
PLIST_TEMPLATE = HERE / "launchd" / (AGENT_LABEL + ".plist")
AGENT_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"


def render_plist(template: str, values: Dict[str, str]) -> bytes:
    """Fill the double-underscore placeholders of the repo template and prove the result is a
    valid property list with no placeholder left."""
    out = template
    for k, v in values.items():
        out = out.replace("__%s__" % k, v.replace("&", "&amp;").replace("<", "&lt;"))
    if re.search(r"__[A-Z_]+__", out):
        raise FeedError("plist template has an unfilled placeholder: %s" % re.search(r"__[A-Z_]+__", out).group(0))
    plistlib.loads(out.encode())
    return out.encode()


def launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["launchctl"] + list(args), capture_output=True, text=True)


def cmd_install(a) -> int:
    if keychain_get(*HEC_KEYCHAIN) is None:
        raise FeedError("no HEC token in Keychain item %s - run setup first" % HEC_KEYCHAIN[0])
    sd = Path(a.state_dir).expanduser()
    bindir = sd / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(sd), 0o700)
    target = bindir / "feed-splunk-live.py"
    shutil.copyfile(str(Path(__file__).resolve()), str(target))
    os.chmod(str(target), 0o700)
    rev = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    (bindir / "SOURCE").write_text("%s @ %s, installed %s\n" % (Path(__file__).resolve(), rev or "?", utcnow_iso()))
    logdir = Path.home() / "Library" / "Logs" / "contoso-splunk-live-feed"
    logdir.mkdir(parents=True, exist_ok=True)
    values = {"LABEL": AGENT_LABEL, "PYTHON": a.python, "SCRIPT": str(target), "OP": op_path(a.op),
              "STATE_DIR": str(sd), "LOG": str(logdir / "feed.log"), "PATH": AGENT_PATH}
    data = render_plist(PLIST_TEMPLATE.read_text(), values)
    dest = Path.home() / "Library" / "LaunchAgents" / (AGENT_LABEL + ".plist")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    os.chmod(str(dest), 0o644)
    domain = "gui/%d" % os.getuid()
    launchctl("bootout", "%s/%s" % (domain, AGENT_LABEL))          # not loaded yet = fine
    r = launchctl("bootstrap", domain, str(dest))
    if r.returncode != 0:
        raise FeedError("launchctl bootstrap failed: %s" % r.stderr.strip())
    if launchctl("print", "%s/%s" % (domain, AGENT_LABEL)).returncode != 0:
        raise FeedError("the LaunchAgent did not load")
    log("LaunchAgent %s loaded: runs %s every 300 s (and at load); log %s" % (AGENT_LABEL, target, values["LOG"]))
    return 0


def cmd_uninstall(a) -> int:
    domain = "gui/%d" % os.getuid()
    launchctl("bootout", "%s/%s" % (domain, AGENT_LABEL))
    dest = Path.home() / "Library" / "LaunchAgents" / (AGENT_LABEL + ".plist")
    if dest.exists():
        dest.unlink()
    if launchctl("print", "%s/%s" % (domain, AGENT_LABEL)).returncode == 0:
        raise FeedError("the LaunchAgent is still loaded")
    log("LaunchAgent %s removed. State (watermarks) kept in %s; Keychain items %s and %s kept."
        % (AGENT_LABEL, a.state_dir, HEC_KEYCHAIN[0], READER_KEYCHAIN[0]))
    return 0


def cmd_status(a) -> int:
    sd = Path(a.state_dir).expanduser()
    p = launchctl("print", "gui/%d/%s" % (os.getuid(), AGENT_LABEL))
    if p.returncode == 0:
        keep = [ln.strip() for ln in p.stdout.splitlines() if re.match(r"\s*(state|last exit code|run interval|runs|program) =", ln)]
        print("LaunchAgent %s: loaded; %s" % (AGENT_LABEL, "; ".join(keep)))
    else:
        print("LaunchAgent %s: not loaded" % AGENT_LABEL)
    src = sd / "bin" / "SOURCE"
    if src.exists():
        print("installed from: " + src.read_text().strip())
    if (sd / "state.json").exists():
        st = State(sd / "state.json")
        print("last successful run: %s" % st.data.get("last_success", "never"))
        for t, v in sorted(st.data["tables"].items()):
            print("  %-34s watermark %s (%d recent ids)" % (t, v.get("hwm") or "-", len(v.get("seen", {}))))
    else:
        print("no state yet (%s)" % (sd / "state.json"))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Live feed: lab tenant logs (Log Analytics) -> local Splunk HEC.")
    ap.add_argument("--state-dir", default=os.environ.get("CONTOSO_SPLUNK_FEED_STATE", "~/.contoso-operator/splunk-feed"))
    ap.add_argument("--hec-url", default="https://127.0.0.1:8088")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--splunk-env", help="lab/splunk/.env of the running stack (default: found from the container's compose label)")
    r = sub.add_parser("run")
    r.add_argument("--op")
    r.add_argument("--workspace-id")
    r.add_argument("--tables", default=",".join(TABLES))
    r.add_argument("--overlap-minutes", type=int, default=OVERLAP_MIN)
    r.add_argument("--backfill-hours", type=int, default=BACKFILL_HOURS)
    r.add_argument("--dry-run", action="store_true")
    c = sub.add_parser("check")
    c.add_argument("--max-age-minutes", type=int, default=MAX_AGE_MIN)
    i = sub.add_parser("install")
    i.add_argument("--op")
    i.add_argument("--python", default="/usr/bin/python3")
    sub.add_parser("uninstall")
    sub.add_parser("status")
    a = ap.parse_args(argv)
    a.state_dir = str(Path(a.state_dir).expanduser())
    try:
        return {"setup": cmd_setup, "run": cmd_run, "check": cmd_check, "install": cmd_install,
                "uninstall": cmd_uninstall, "status": cmd_status}[a.cmd](a)
    except FeedError as e:
        log("ERROR: %s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
