#!/usr/bin/env python3
"""run-on-workspace.py - run harness cases on the lab's Log Analytics query engine.

What it does, plainly
  For each case of the named rules (cases/<rule>.json, the same files run.sh
  uses), it builds ONE read-only query:
      let <Table> = view() { print harness_rows = parse_json(@'<case rows>')
                             | mv-expand ... | project <typed columns> };
      ... one let per table the rule reads (an empty typed datatable when the
          case has no rows for it) ...
      <the rule, rendered as modules/monitoring deploys it>
  A `let` with a table's name shadows the real table for that query, so the
  rule reads only the case's synthetic rows. The query goes to loga-idlab
  through the lab operator (`op az monitor log-analytics query`). Nothing is
  ingested or written in the workspace. The answer is judged with the
  harness's own evaluate() (positive: rows that match `expect`; negative:
  zero rows; expectRows / expectNone).

Why it exists
  run.sh needs the Kusto emulator, whose licence only the operator can
  accept (README). This path needs no emulator: it is the real Log
  Analytics engine, with the workspace's own function library. It is still
  NOT a scheduled Sentinel rule: no rule is created, no incident raised,
  and the query period / entity mapping are not exercised.

Limits
  - Rows come from the harness row contract (prepare_rows): "ago:30m" and
    "in:7d" resolve against this machine's clock just before each query, not
    the engine's now(); the cases' windows have minutes of slack.
  - A query body has a size limit (the 1450-row baseline case fits; a much
    larger case may be refused with "Request entity too large" = ERROR).
  - Watchlists, table variants and shim variants are not supported here: a
    case that uses them is reported as SKIPPED, never as passed.

Usage
  lab/monitoring/kusto-harness/run-on-workspace.py --rules a,b [--record DIR]
  Exit 0 = every case passed; 1 = a case failed or errored; 2 = refused.
"""
import argparse, datetime as dt, hashlib, json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
OP = os.path.join(REPO, "lab", "scripts", "operator", "op")
sys.path.insert(0, HERE)
import harness  # noqa: E402  (this folder's harness.py)

RG, WS_NAME = "rg-identity-lab", "loga-idlab"


def op_az(args):
    p = subprocess.run([OP, "az", *args, "-o", "json", "--only-show-errors"], capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def workspace_id():
    # Fail closed: no default id. A failed lookup stops the run.
    rc, out, err = op_az(["monitor", "log-analytics", "workspace", "show", "-g", RG, "-n", WS_NAME, "--query", "customerId"])
    if rc != 0:
        sys.exit(f"REFUSED: could not read workspace {WS_NAME} in {RG} as the operator:\n{err[-600:]}")
    wid = json.loads(out)
    if not isinstance(wid, str) or len(wid) != 36:
        sys.exit(f"REFUSED: workspace lookup returned no customer id ({out[:200]!r})")
    return wid


def coerce(v):
    # az returns every cell as text; turn numbers / booleans back into JSON
    # values so evaluate() compares like the emulator path does.
    if isinstance(v, str):
        if v in ("True", "False", "true", "false"):
            return v.lower() == "true"
        for f in (int, float):
            try:
                return f(v)
            except ValueError:
                pass
    return v


def case_query(ctx, rule, k, base):
    lets = []
    for t, spec in ctx["tables"].items():
        if rule["name"] not in spec["readBy"]:
            continue
        cols = spec["variants"][spec["defaultVariant"]]
        rows = k["tables"].get(t, [])
        prepared = []
        if rows:
            prepared, _ = harness.prepare_rows(rows, cols, spec["learn"], base, k["defaultsKeys"].get(t, set()), spec["learn"])
        if prepared:
            body = harness.append_command(t, cols, spec["learn"], prepared).split("<|\n", 1)[1]
        else:
            body = "datatable(" + ", ".join(f"{c}:{spec['learn'][c]}" for c in cols) + ")[]"
        lets.append(f"let {t} = view() {{ {body} }};")
    return "\n".join(lets) + "\n" + harness.render_rule(rule, k["lets"])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rules", required=True, help="comma list of lab/kql rule names")
    ap.add_argument("--record", help="directory to write results.json + SHA256SUMS into")
    a = ap.parse_args()
    ctx = harness.load_all()
    if ctx["problems"]:
        sys.exit("REFUSED: harness.py check problems:\n" + "\n".join(ctx["problems"]))
    names = [r for r in a.rules.split(",") if r]
    unknown = [r for r in names if r not in ctx["rules"]]
    if unknown:
        sys.exit(f"REFUSED: unknown rule(s): {unknown}")
    wid = workspace_id()
    started = dt.datetime.now(dt.timezone.utc)
    results = []
    for name in names:
        rule = ctx["rules"][name]
        for k in [c for c in ctx["cases"] if c["rule"] == name]:
            entry = {"id": k["id"], "kind": k["kind"], "label": k["label"]}
            if k["watchlists"] or k["tableVariant"] or k["shimVariant"]:
                entry.update(status="SKIPPED", reason="watchlist / table variant / shim variant cases need run.sh")
                results.append(entry)
                print(f"SKIP  {k['id']}", flush=True)
                continue
            q = case_query(ctx, rule, k, dt.datetime.now(dt.timezone.utc))
            with tempfile.NamedTemporaryFile("w", suffix=".kql", delete=False) as f:
                f.write(q)
                qpath = f.name
            try:
                # @file: the Azure CLI reads the argument from the file, so a
                # large case never hits the argv size limit.
                rc, out, err = op_az(["monitor", "log-analytics", "query", "-w", wid, "--analytics-query", "@" + qpath])
            finally:
                os.unlink(qpath)
            if rc != 0:
                entry.update(status="ERROR", failures=[f"query error: {err.strip()[-500:]}"])
            else:
                rows = [{c: coerce(v) for c, v in r.items() if c != "TableName"} for r in json.loads(out)]
                # Output column names are known only when rows came back; for an
                # empty answer, take the expected names so evaluate() reports
                # "no rows", not "unknown column".
                cols = [(c, None) for c in (rows[0] if rows else {c for e in k["expect"] for c in e})]
                fails, _ = harness.evaluate(k, {"rows": rows, "columns": cols})
                entry.update(status="FAIL" if fails else "PASS", rowCount=len(rows), rows=rows[:5], failures=fails)
            results.append(entry)
            print(f"{entry['status']:5} {k['id']}" + (f"  -- {entry['failures'][0][:300]}" if entry.get("failures") else ""), flush=True)
    counts = {s: sum(1 for r in results if r["status"] == s) for s in ("PASS", "FAIL", "ERROR", "SKIPPED")}
    verdict = "PASS" if counts["FAIL"] == 0 and counts["ERROR"] == 0 and counts["PASS"] > 0 else "FAIL"
    print(f"RESULT {verdict} {counts}")
    if a.record:
        os.makedirs(a.record, exist_ok=True)
        doc = {
            "what": "kusto-harness cases run on the Log Analytics query engine (loga-idlab), read-only, rows bound by let",
            "notAScheduledRule": True, "started": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finished": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "result": verdict, "counts": counts, "rules": {n: ctx["rules"][n]["sha256"] for n in names},
            "caseFiles": {n: harness.sha256_file(os.path.join(HERE, "cases", n + ".json")) for n in names},
            "cases": results,
        }
        rp = os.path.join(a.record, "results.json")
        with open(rp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
            f.write("\n")
        with open(os.path.join(a.record, "SHA256SUMS"), "w") as f:
            f.write(f"{hashlib.sha256(open(rp, 'rb').read()).hexdigest()}  results.json\n")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
