# Contoso HR (the HR system stand-in)

A small web form that stands in for an HR system such as Workday. HR staff
use it to hire a worker, change a worker's job or department, and make a
worker a leaver. It never asks for or shows a password. Why it looks like
this, and why it sends the way it does: [ADR 0027](../docs/adr/0027-hr-form-as-the-hr-system.md).

## Start it

```bash
node lab/hr-app/server.mjs                         # the lab: saves are sent to Microsoft
node lab/hr-app/server.mjs --store file:/tmp/r.csv # rehearsal on a copy: sends nothing
```

Open http://127.0.0.1:8484. It listens on this Mac only. It needs `gh`
signed in with push access to the lab repo (it uses `gh`'s own sign-in; no
token is passed to it).

## What one save does

1. The form checks the fields and issues the employee number (the next free
   number in the range: 100xxx staff, 200xxx managers, 300xxx executives,
   400xxx IT).
2. It writes one commit to `lab/scripts/mock-hr/hr_feed.csv` on `hr-feed`,
   for example "HR: hire Sam Rivera, Cloud Engineer (Information Technology)".
3. `hr-feed.yml` runs on that commit, signs in as HR-SYNC (GitHub OIDC, no
   secret) and sends only that worker to Entra API-driven inbound
   provisioning (`bulkUpload`).
4. The provisioning agent writes the account into AD on DC01. Cloud Sync
   copies it to Entra ID. Group rules, auto-assignment, AWS SCIM and
   ServiceNow follow.

The form shows "Sending to IT systems", then "Accepted by IT systems" (Microsoft answered 202 and logged no failure while the run waited; not a confirmation) or "Not delivered"
from the run's result. Measured timings: [ADR 0027, "Measured in the tenant"](../docs/adr/0027-hr-form-as-the-hr-system.md#measured-in-the-tenant-2026-11-07)
and capture log E121-E123.

## Files

| File | What it does |
|---|---|
| `server.mjs` | HTTP server (127.0.0.1), form token, the three API routes |
| `lib/roster.mjs` | Roster rules: hire, change, leave, employee number, job catalogue (pure) |
| `lib/store.mjs` | `GitHubStore` (the `hr-feed` file through `gh api`, sha-checked writes, run status) and `FileStore` (rehearsal) |
| `public/index.html` | The form |
| `tests/hr-app.test.mjs` | `node --test`: rules, API on a file store, GitHub store with a fake `gh` |
