#!/usr/bin/env python3
"""
replay-synthetic.py - a SMOKE TEST that the Splunk twins fire, with no tenant and no
az login. It proves each saved search RETURNS ROWS on the synthetic events; it does
not match a specific case to the rule that should catch it (every case's events land
in one index=entra over the same window, so one rule can fire on another case's rows).
Per-case matching would need a per-rule filter the saved searches do not carry.

What it does, in plain words
  1. Reads every detection test case under lab/monitoring/kusto-harness/cases/
     (the same synthetic events the KQL rules were tested with on the Kusto
     emulator), merges each row with the case file's defaults, and sends the
     rows to the local Splunk HTTP Event Collector with the sourcetype the
     SPL twin expects (KQL table SigninLogs -> azure:loganalytics:signinlogs).
     Rows follow the harness row contract (kusto-harness/README.md): "_repeat"
     makes N copies with "{i}" substituted, "ago:30m" / "in:7d" tokens resolve
     against now, and a row without TimeGenerated gets "ago:30m". The HEC
     "time" is the resolved TimeGenerated, so a case lands at the SAME place
     in the rule's windows as it does on the Kusto emulator (a 12-failure
     burst in one 10-minute bin, a DC logon 30 min back, a check-out 40 min
     before the logon). Rows the harness never sees as "now" (ago:3d) stay
     outside the saved searches' windows here too.
  2. Dispatches every "Contoso - ..." saved search in the contoso_identity
     app over the management API, waits for each, and records how many rows
     it returned.
  3. Writes lab/evidence/splunk/<UTC ts>/results.json and SHA256SUMS: which
     searches fired, which did not, and the events sent per sourcetype.

Secrets: reads SPLUNK_PASSWORD and SPLUNK_HEC_TOKEN from lab/splunk/.env in
process. Never prints them, never puts them on a command line.

Usage
  lab/splunk/replay-synthetic.py            # send + search + record
  lab/splunk/replay-synthetic.py --dry-run  # count what would be sent, touch nothing

Limits (say so once): a smoke test on synthetic rows, not tenant logs; it proves the
SPL and the index pipeline return rows, not that each rule caught its own case, and
not Entra. The index is emptied before each run so rows from a previous replay cannot
be counted. A saved search that does not finish within the poll budget, or that fails,
is recorded as an error and is NOT counted as fired. The Log Analytics replay
(ingest-from-loganalytics.sh) is the tenant-backed path.
"""
import argparse, base64, copy, datetime as dt, hashlib, json, os, pathlib, re, ssl, sys, time, urllib.error, urllib.parse, urllib.request

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
CASES = REPO / "lab" / "monitoring" / "kusto-harness" / "cases"
EVID = REPO / "lab" / "evidence" / "splunk"
HEC = "https://127.0.0.1:8088/services/collector/event"
MGMT = "https://127.0.0.1:8089"
APP = "contoso_identity"
INDEX = "entra"                                         # the one index the SPL twins search (app/indexes.conf)
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE  # self-signed, loopback only
REL_TIME = re.compile(r"^(ago|in):(\d+)(s|m|h|d)$")   # same token grammar as kusto-harness/harness.py
DEFAULT_TIME = "ago:30m"                                # a row without TimeGenerated, as in the harness (and KqlLite)
TIME_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"                      # the harness's ingested TimeGenerated text


def load_env():
    env = {}
    for line in (HERE / ".env").read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1); env[k.strip()] = v.strip()
    for k in ("SPLUNK_PASSWORD", "SPLUNK_HEC_TOKEN"):
        if not env.get(k): sys.exit(f"{k} missing in lab/splunk/.env - run splunk-up.sh first")
    return env


def http(url, data=None, headers=None, method=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
        return r.status, r.read()


def sourcetype(table):
    return "azure:loganalytics:" + table.lower()


def expand_rows(rows, defaults):
    """Merge each row over the table defaults; "_repeat": N makes N copies with "{i}" substituted
    in string values (same as harness.expand_rows, so a 12-failure case is 12 events, not 1)."""
    out = []
    for row in rows:
        n = int(row.get("_repeat", 1))
        body = {k: v for k, v in row.items() if k != "_repeat"}
        for i in range(n):
            r = copy.deepcopy(defaults)
            for k, v in body.items():
                r[k] = v.replace("{i}", str(i)) if isinstance(v, str) else copy.deepcopy(v)
            out.append(r)
    return out


def resolve_time(v, now):
    """"ago:30m" / "in:7d" -> datetime relative to now (harness.resolve_value); ISO text passes through."""
    m = REL_TIME.match(v)
    if m:
        unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m.group(3)]
        delta = dt.timedelta(**{unit: int(m.group(2))})
        return now - delta if m.group(1) == "ago" else now + delta
    try:
        return dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


def collect_events():
    """Yield (sourcetype, row) for every table row in every case, defaults merged and _repeat expanded."""
    files = sorted(p for p in CASES.glob("*.json") if not p.name.startswith("_"))
    per_rule = {}
    for f in files:
        d = json.loads(f.read_text())
        defaults = d.get("defaults", {})
        n = 0
        for case in d.get("cases", []):
            for table, rows in (case.get("tables") or {}).items():
                for merged in expand_rows(rows, defaults.get(table, {})):
                    merged.setdefault("_case", case.get("id")); merged.setdefault("_rule", d.get("rule"))
                    yield sourcetype(table), merged
                    n += 1
        per_rule[d.get("rule", f.stem)] = n
    collect_events.per_rule = per_rule


def send(env, events, dry):
    sent, by_st = 0, {}
    now = dt.datetime.now(dt.timezone.utc)
    batch = []
    for st, row in events:
        row = dict(row); row.setdefault("TimeGenerated", DEFAULT_TIME)
        t = resolve_time(row["TimeGenerated"], now) if isinstance(row["TimeGenerated"], str) else None
        if t is None: sys.exit(f"{row.get('_rule')}/{row.get('_case')}: TimeGenerated {row['TimeGenerated']!r} is neither an ago:/in: token nor ISO 8601")
        for k, v in row.items():  # other datetime columns carry the same tokens (harness resolves them in every datetime/string column)
            if isinstance(v, str) and REL_TIME.match(v): row[k] = resolve_time(v, now).strftime(TIME_FMT)
        row["TimeGenerated"] = t.strftime(TIME_FMT)
        row["_synthetic"] = "replay-synthetic"  # marks our rows so reset_index never deletes tenant logs
        batch.append(json.dumps({"time": round(t.timestamp(), 3), "index": INDEX, "sourcetype": st, "event": row}))
        by_st[st] = by_st.get(st, 0) + 1; sent += 1
        if len(batch) >= 50:
            if not dry: post(env, batch)
            batch = []
    if batch and not dry: post(env, batch)
    return sent, by_st


def post(env, batch):
    body = "\n".join(batch).encode()
    code, out = http(HEC, body, {"Authorization": "Splunk " + env["SPLUNK_HEC_TOKEN"], "Content-Type": "application/json"}, "POST")
    if code != 200 or json.loads(out).get("code") != 0:
        sys.exit(f"HEC refused a batch: HTTP {code} {out[:200]!r}")


def rest(env, path, data=None, method=None):
    auth = base64.b64encode(("admin:" + env["SPLUNK_PASSWORD"]).encode()).decode()
    hdr = {"Authorization": "Basic " + auth}
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    code, out = http(MGMT + path + ("&" if "?" in path else "?") + "output_mode=json", body, hdr, method)
    return json.loads(out) if out else {}


def reset_index(env):
    """Empty the replay index before sending, so rows from a previous run cannot be
    counted as proof. Delete then recreate over REST (admin, loopback). Idempotent: a
    missing index is simply (re)created; a brand-new deployment has nothing to clear."""
    # Refuse to wipe the shared index if it holds anything other than our synthetic
    # rows (e.g. a tenant replay from ingest-from-loganalytics.sh keeps its data here).
    try:
        sid = rest(env, f"/servicesNS/nobody/{APP}/search/jobs",
                   {"search": "search index=%s NOT _synthetic=replay-synthetic | head 1" % INDEX,
                    "exec_mode": "blocking", "earliest_time": "0", "latest_time": "now"}, "POST").get("sid")
        if sid:
            res = rest(env, f"/services/search/jobs/{urllib.parse.quote(sid)}/results", method="GET")
            if res.get("results"):
                sys.exit(f"refusing to reset: index {INDEX} holds non-synthetic (tenant) data. "
                         "Run the smoke test on a disposable Splunk or a clean index; this tool will not delete tenant logs.")
    except urllib.error.HTTPError:
        pass  # index not present yet, or search unavailable: the delete below is then a no-op/create
    try:
        rest(env, f"/services/data/indexes/{INDEX}", method="DELETE")
    except urllib.error.HTTPError as e:
        if e.code not in (404, 409):   # 404 = not there yet, 409 = already being cleaned
            raise
    for _ in range(60):
        try:
            rest(env, f"/services/data/indexes/{INDEX}")   # present and queryable again?
            return
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            try:
                rest(env, "/services/data/indexes", {"name": INDEX}, "POST")
            except urllib.error.HTTPError as e2:
                if e2.code != 409:
                    raise
            time.sleep(1)
    sys.exit(f"index {INDEX} did not come back after reset")


def run_searches(env):
    names = [e["name"] for e in rest(env, f"/servicesNS/nobody/{APP}/saved/searches?count=0")["entry"] if e["name"].startswith("Contoso - ")]
    results = {}
    for name in names:
        enc = urllib.parse.quote(name, safe="")
        sid = rest(env, f"/servicesNS/nobody/{APP}/saved/searches/{enc}/dispatch", {"trigger_actions": "0", "dispatch.earliest_time": "-2h", "dispatch.latest_time": "now"}, "POST")["sid"]
        st, done = {}, False
        for _ in range(120):
            st = rest(env, f"/services/search/jobs/{urllib.parse.quote(sid)}")["entry"][0]["content"]
            if st.get("isFailed"): break
            if st.get("isDone"): done = True; break
            time.sleep(1)
        failed, rows = bool(st.get("isFailed")), int(st.get("resultCount", 0))
        # A search that failed, or that never finished within the poll budget, is NOT proof:
        # its (partial) resultCount must not be read as a fired detection.
        errored = failed or not done
        results[name] = {"rows": rows, "sid": sid, "failed": failed, "done": done, "errored": errored}
        print(f"{'ERROR ' if errored else ('FIRED ' if rows else 'quiet ')} {rows:>4}  {name}")
    return results


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--dry-run", action="store_true"); a = ap.parse_args()
    events = list(collect_events())
    env = None if a.dry_run else load_env()
    if not a.dry_run: reset_index(env)
    sent, by_st = send(env, events, a.dry_run)
    print(f"{'would send' if a.dry_run else 'sent'} {sent} synthetic events across {len(by_st)} sourcetypes from {len(collect_events.per_rule)} rule case files")
    if a.dry_run: return
    print("indexing settles for 30 s ..."); time.sleep(30)
    res = run_searches(env)
    fired = sum(1 for r in res.values() if r["rows"] and r["done"] and not r["failed"])
    errored = sum(1 for r in res.values() if r["errored"])
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = EVID / ts; out.mkdir(parents=True, exist_ok=True)
    summary = f"{fired} of {len(res)} saved searches fired (returned rows) on the synthetic events" + (f"; {errored} failed or did not finish (not counted)" if errored else "")
    record = {"when": ts, "what": "Synthetic smoke replay of the KQL harness cases into local Splunk 10.4.4; index emptied first, every Contoso saved search dispatched over -2h.",
              "events_sent": sent, "events_by_sourcetype": by_st, "cases_per_rule": collect_events.per_rule,
              "searches": res, "fired": fired, "errored": errored, "summary": summary,
              "limits": "Synthetic events only. Not tenant logs. A smoke test: proves the SPL twins and the index pipeline return rows, not per-case matching, not Entra. Index emptied before the run; unfinished/failed searches are errors, not fired."}
    (out / "results.json").write_text(json.dumps(record, indent=2))
    digest = hashlib.sha256((out / "results.json").read_bytes()).hexdigest()
    (out / "SHA256SUMS").write_text(f"{digest}  results.json\n")
    print(record["summary"]); print(f"evidence: {out.relative_to(REPO)}")
    if errored: sys.exit(f"{errored} saved search(es) failed or did not finish - not counted as fired")


if __name__ == "__main__":
    main()
