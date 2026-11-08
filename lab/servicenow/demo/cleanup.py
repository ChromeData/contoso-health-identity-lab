#!/usr/bin/python3 -I
"""Delete test tickets from the ServiceNow PDI after a proof run.

  /usr/bin/python3 -I lab/servicenow/demo/cleanup.py RITM0010002 INC0010040 ...

For each RITM: its catalog tasks and approvals, the RITM, then its parent REQ
when no other item is left on it. For each INC / SCTASK: the record and its
approvals. REQ numbers are refused: the PDI ships demo requests whose numbers
repeat (two REQ0010001 seen 2026-11-07), so a REQ is only ever reached through
its own RITM, and a RITM only through the lab's two catalog items. Prints
what it deleted. Entra changes are NOT undone here (prove.py removes the access it
granted, with the ticket number in the justification, so the audit trail stays
complete).
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import snlib  # noqa: E402

TABLE = {"RITM": "sc_req_item", "SCTASK": "sc_task", "INC": "incident"}


def delete_task(sn, table, row, out):
    for a in sn.query("sysapproval_approver", f"sysapproval={row['sys_id']}", ["sys_id"]):
        sn.delete("sysapproval_approver", a["sys_id"])
    sn.delete(table, row["sys_id"])
    out.append(f"deleted {table} {row['number']}")


def clean(sn, numbers):
    out = []
    for n in numbers:
        m = re.match(r"^(RITM|SCTASK|INC)\d{7}$", n)
        if not m:
            raise SystemExit(f"not a ticket number: {n}")
        table = TABLE[m.group(1)]
        q = f"number={n}"
        if table == "sc_req_item":
            # Only items of the lab's own catalog items: the PDI demo data
            # reuses numbers (RITM0010001 twice, seen 2026-11-07).
            q += "^cat_item.nameINRequest app access,Report a leaver: remove app access"
        row = sn.one(table, q, ["sys_id", "number"])
        if row is None:
            out.append(f"not found {n}")
            continue
        if table == "sc_req_item":
            row = sn.one(table, q, ["sys_id", "number", "request"])
            for t in sn.query("sc_task", f"request_item={row['sys_id']}", ["sys_id", "number"]):
                delete_task(sn, "sc_task", t, out)
        delete_task(sn, table, row, out)
        if table == "sc_req_item" and row.get("request"):
            if not sn.query("sc_req_item", f"request={row['request']}", ["sys_id"]):
                req = sn.one("sc_request", f"sys_id={row['request']}", ["sys_id", "number"])
                if req:
                    delete_task(sn, "sc_request", req, out)
    return out


if __name__ == "__main__":
    print("\n".join(clean(snlib.Client(), sys.argv[1:])))
