#!/usr/bin/env python3
"""check-adr-status.py - fail when an ADR says a script never ran, but the
capture log has a row that names that script (karen-review E2).

Why: the ADR index said "nothing has been applied to a tenant" weeks after the
first tenant run. One self-contradiction makes a reader distrust every status
word. This check catches the commonest kind: an ADR item that says a named
script "never ran" / "has not run" while lab/evidence/capture-log.csv records
a run of it.

How: each ADR is split into items (a bullet with its continuation lines, or a
paragraph). An item is a CLAIM when it contains a "not run" phrase (including
the status-line form "Not run: X") and names a
script (`*.ps1`, `*.sh`, `*.py`, `*.mjs`). A claim FAILS when that script's
file name appears in the `what` column of any capture-log row.

Limits (said plainly): it reads words, not meaning. An item like "X ran, Y has
never run" fails if X has a row; reword such an item into two. It does not
check claims that name no script.

Exit: 0 = no contradiction, 1 = at least one, 2 = could not read an input
(fail closed: a missing capture log is not "no contradiction").

Usage: check-adr-status.py [--adr-dir DIR] [--capture-log FILE]
"""
import argparse
import csv
import glob
import os
import re
import sys

NOT_RUN = re.compile(
    r"\b(never run|has never run|never ran|never been run|not yet run|"
    r"not run yet|has not run|has not been run|not been run|"
    # Bare "Not run: X" is the ADR status-line form (ADR 0003 uses it). The
    # colon is required: a bare "NOT RUN" is also a result label in tables
    # (ADR 0026), and that is not a claim about a script.
    r"not run(?=\s*:))\b",
    re.IGNORECASE,
)
SCRIPT = re.compile(r"([A-Za-z0-9_.-]+\.(?:ps1|sh|py|mjs))\b")


def items(text):
    """Split markdown into bullet items and paragraphs, whitespace-normalised."""
    out, cur = [], []
    for line in text.splitlines():
        starts_item = re.match(r"\s*([-*]|\d+\.)\s", line) is not None
        if not line.strip() or starts_item or line.startswith("#"):
            if cur:
                out.append(" ".join(cur))
            cur = [line.strip()] if line.strip() else []
        else:
            cur.append(line.strip())
    if cur:
        out.append(" ".join(cur))
    return [re.sub(r"\s+", " ", i) for i in out if i]


def run_rows(path):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows or "what" not in rows[0]:
        raise ValueError(f"{path}: no rows or no 'what' column")
    return rows


def check(adr_dir, capture_log):
    rows = run_rows(capture_log)
    problems = []
    files = sorted(glob.glob(os.path.join(adr_dir, "[0-9][0-9][0-9][0-9]-*.md")))
    if not files:
        raise ValueError(f"{adr_dir}: no ADR files found")
    for path in files:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for item in items(text):
            if not NOT_RUN.search(item):
                continue
            for script in sorted(set(SCRIPT.findall(item))):
                hits = [r["id"] for r in rows if script in (r.get("what") or "")]
                if hits:
                    problems.append(
                        f"{os.path.basename(path)}: says '{script}' has not run, "
                        f"but capture-log rows {', '.join(hits[:5])} name it: {item[:160]}"
                    )
    return problems


def main(argv=None):
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    ap = argparse.ArgumentParser()
    ap.add_argument("--adr-dir", default=os.path.join(root, "lab/docs/adr"))
    ap.add_argument("--capture-log", default=os.path.join(root, "lab/evidence/capture-log.csv"))
    a = ap.parse_args(argv)
    try:
        problems = check(a.adr_dir, a.capture_log)
    except (OSError, ValueError) as e:
        print(f"could not check: {e}", file=sys.stderr)
        return 2
    for p in problems:
        print(f"::error::{p}")
    if problems:
        print(f"{len(problems)} ADR status claim(s) contradict the capture log")
        return 1
    print("ADR status claims: no contradiction with the capture log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
