#!/usr/bin/env python3
"""compare_claims.py BEFORE.json AFTER.json [--contract claims-contract.json]

Proves the cutover kept the app's claims: BEFORE is what AD FS issued
(13-Get-AdfsClaims.ps1 or the Claims Viewer's ?format=json while it trusts
AD FS), AFTER is what Entra issued (the Claims Viewer after cutover.sh entra).

Passes (exit 0) only when, for the same user:
  * both responses had a valid signature,
  * the Name ID value matches and AFTER uses the contract's Name ID format,
  * every contract claim type is present in BOTH with the same set of values.
Exit 1 = a difference (each one is listed). Exit 2 = bad input.
Claim types listed as "platform" are shown, never compared. Any other extra
claim type is listed as "extra" and fails the run: an app can act on a claim
it did not get before.

Stdlib only. Prints a table, then a JSON verdict on the last line.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load(path):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise SystemExit(f"compare_claims: cannot read {path}: {e}")


def norm(values, mode):
    vals = values if isinstance(values, list) else [values]
    vals = [str(v).strip() for v in vals]
    if mode == "casefold":
        vals = [v.casefold() for v in vals]
    return sorted(set(vals))


def compare(before, after, contract):
    rows, problems = [], []
    for side, doc in (("before", before), ("after", after)):
        if doc.get("signatureValid") is not True:
            problems.append(f"{side}: signature not valid")
        if not isinstance(doc.get("attributes"), dict):
            raise ValueError(f"{side}: no 'attributes' object")

    nid = contract["nameId"]
    b_nid = (before.get("nameId") or {}).get("value")
    a_nid = (after.get("nameId") or {}).get("value")
    same = b_nid is not None and norm(b_nid, nid["compare"]) == norm(a_nid or "", nid["compare"])
    rows.append(("NameID", b_nid, a_nid, "same" if same else "DIFFERENT"))
    if not same:
        problems.append("Name ID value differs")
    a_fmt = (after.get("nameId") or {}).get("format")
    if nid.get("format") and a_fmt != nid["format"]:
        problems.append(f"Name ID format after = {a_fmt}, expected {nid['format']}")

    ba, aa = before["attributes"], after["attributes"]
    for ctype, mode in contract["claims"].items():
        bv, av = ba.get(ctype), aa.get(ctype)
        if bv is None or av is None:
            status = "MISSING " + ("before" if bv is None else "after")
            problems.append(f"{ctype}: {status}")
        elif norm(bv, mode) != norm(av, mode):
            status = "DIFFERENT"
            problems.append(f"{ctype}: {norm(bv, mode)} -> {norm(av, mode)}")
        else:
            status = "same"
        rows.append((ctype, bv, av, status))

    platform = set(contract.get("platform", []))
    known = set(contract["claims"]) | platform
    for ctype in sorted((set(ba) | set(aa)) - known):
        rows.append((ctype, ba.get(ctype), aa.get(ctype), "EXTRA"))
        problems.append(f"{ctype}: extra claim not in the contract")
    for ctype in sorted((set(ba) | set(aa)) & platform):
        rows.append((ctype, ba.get(ctype), aa.get(ctype), "platform (not compared)"))
    return rows, problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("--contract", default=os.path.join(HERE, "claims-contract.json"))
    a = ap.parse_args(argv)
    before, after, contract = load(a.before), load(a.after), load(a.contract)
    try:
        rows, problems = compare(before, after, contract)
    except (KeyError, ValueError) as e:
        print(f"compare_claims: bad input: {e}", file=sys.stderr)
        return 2
    short = lambda v: "-" if v is None else ", ".join(v) if isinstance(v, list) else str(v)
    print(f"{'claim':<70} {'AD FS (before)':<36} {'Entra (after)':<36} result")
    for ctype, bv, av, status in rows:
        print(f"{ctype:<70} {short(bv)[:35]:<36} {short(av)[:35]:<36} {status}")
    verdict = {"same": not problems, "problems": problems,
               "before": before.get("source"), "after": after.get("source")}
    print(json.dumps(verdict))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
