#!/usr/bin/env python3
"""
replay-synthetic.py - prove the Splunk twins fire, with no tenant and no az login.

What it does, in plain words
  1. Reads every detection test case under lab/monitoring/kusto-harness/cases/
     (the same synthetic events the KQL rules were tested with on the Kusto
     emulator), merges each row with the case file's defaults, and sends the
     rows to the local Splunk HTTP Event Collector with the sourcetype the
     SPL twin expects (KQL table SigninLogs -> azure:loganalytics:signinlogs).
     Timestamps are rewritten to "a few minutes ago" so the saved searches'
     earliest=-1h windows see them.
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

Limits (say so once): synthetic rows, not tenant logs; the replay proves the
SPL and the index pipeline, not Entra. The Log Analytics replay
(ingest-from-loganalytics.sh) is the tenant-backed path.
"""
import argparse, base64, datetime as dt, hashlib, json, os, pathlib, ssl, sys, time, urllib.parse, urllib.request

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
CASES = REPO / "lab" / "monitoring" / "kusto-harness" / "cases"
EVID = REPO / "lab" / "evidence" / "splunk"
HEC = "https://127.0.0.1:8088/services/collector/event"
MGMT = "https://127.0.0.1:8089"
APP = "contoso_identity"
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE  # self-signed, loopback only


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


def collect_events():
    """Yield (sourcetype, row) for every table row in every case, defaults merged."""
    files = sorted(p for p in CASES.glob("*.json") if not p.name.startswith("_"))
    per_rule = {}
    for f in files:
        d = json.loads(f.read_text())
        defaults = d.get("defaults", {})
        n = 0
        for case in d.get("cases", []):
            for table, rows in (case.get("tables") or {}).items():
                for row in rows:
                    merged = dict(defaults.get(table, {})); merged.update(row)
                    merged.setdefault("_case", case.get("id")); merged.setdefault("_rule", d.get("rule"))
                    yield sourcetype(table), merged
                    n += 1
        per_rule[d.get("rule", f.stem)] = n
    collect_events.per_rule = per_rule


def send(env, events, dry):
    sent, by_st = 0, {}
    now = dt.datetime.now(dt.timezone.utc)
    batch = []
    for i, (st, row) in enumerate(events):
        t = now - dt.timedelta(minutes=2 + (i % 20))
        row = dict(row); row.setdefault("TimeGenerated", t.strftime("%Y-%m-%dT%H:%M:%SZ"))
        batch.append(json.dumps({"time": int(t.timestamp()), "index": "entra", "sourcetype": st, "event": row}))
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


def run_searches(env):
    names = [e["name"] for e in rest(env, f"/servicesNS/nobody/{APP}/saved/searches?count=0")["entry"] if e["name"].startswith("Contoso - ")]
    results = {}
    for name in names:
        enc = urllib.parse.quote(name, safe="")
        sid = rest(env, f"/servicesNS/nobody/{APP}/saved/searches/{enc}/dispatch", {"trigger_actions": "0", "dispatch.earliest_time": "-2h", "dispatch.latest_time": "now"}, "POST")["sid"]
        for _ in range(120):
            st = rest(env, f"/services/search/jobs/{urllib.parse.quote(sid)}")["entry"][0]["content"]
            if st.get("isDone"): break
            time.sleep(1)
        results[name] = {"rows": int(st.get("resultCount", 0)), "sid": sid, "failed": bool(st.get("isFailed"))}
        print(f"{'FIRED ' if results[name]['rows'] else 'quiet '} {results[name]['rows']:>4}  {name}")
    return results


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--dry-run", action="store_true"); a = ap.parse_args()
    events = list(collect_events())
    env = None if a.dry_run else load_env()
    sent, by_st = send(env, events, a.dry_run)
    print(f"{'would send' if a.dry_run else 'sent'} {sent} synthetic events across {len(by_st)} sourcetypes from {len(collect_events.per_rule)} rule case files")
    if a.dry_run: return
    print("indexing settles for 30 s ..."); time.sleep(30)
    res = run_searches(env)
    fired = sum(1 for r in res.values() if r["rows"])
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = EVID / ts; out.mkdir(parents=True, exist_ok=True)
    record = {"when": ts, "what": "Synthetic replay of the KQL harness cases into local Splunk 10.4.4; every Contoso saved search dispatched over -2h.",
              "events_sent": sent, "events_by_sourcetype": by_st, "cases_per_rule": collect_events.per_rule,
              "searches": res, "summary": f"{fired} of {len(res)} saved searches returned rows on the synthetic events",
              "limits": "Synthetic events only. Not tenant logs. Proves the SPL twins and the index pipeline, not Entra."}
    (out / "results.json").write_text(json.dumps(record, indent=2))
    digest = hashlib.sha256((out / "results.json").read_bytes()).hexdigest()
    (out / "SHA256SUMS").write_text(f"{digest}  results.json\n")
    print(record["summary"]); print(f"evidence: {out.relative_to(REPO)}")


if __name__ == "__main__":
    main()
