# The HR system: OrangeHRM, and its connector to Entra

Contoso Health's HR team works in **OrangeHRM** (the open-source edition,
5.9), running on this Mac in Colima. A small **connector** carries each HR
change to Microsoft Entra **API-driven inbound provisioning**, which writes
the worker into Active Directory. Cloud Sync, group rules, AWS and
ServiceNow follow. Why OrangeHRM and why this shape: [ADR 0028](../docs/adr/0028-orangehrm-as-the-hris.md).

```
HR clicks Save in OrangeHRM
  -> connector (every 60 s) reads one view: 8 HR fields per worker
  -> one commit to lab/scripts/mock-hr/hr_feed.csv on hr-feed (the outbox)
  -> hr-feed.yml signs in as HR-SYNC (GitHub OIDC, no secret)
  -> Entra bulkUpload -> provisioning agent -> AD (DC01) -> Cloud Sync -> Entra
  -> dynamic groups, access packages, AWS (SCIM), ServiceNow
```

## Start it (once per session)

```bash
cd lab/hris/orangehrm
./hris.sh up                                # starts OrangeHRM and its database
cd ../connector && npm ci                   # first time only (mysql2)
node sync.mjs --watch 60                    # the connector, every 60 seconds
```

OrangeHRM: http://127.0.0.1:8585 (this Mac only). Sign in as `Admin`. The
password is in the Keychain item `contoso-hris-admin`
(Keychain Access > search "Contoso HRIS"); never paste it into a terminal.

First time on a new Mac: `./hris.sh up`, `./hris.sh install`,
`./hris.sh connector`, `./hris.sh seed`, then
`node ../connector/sync.mjs --dry-run` must print "No change in OrangeHRM".

Stop it: `./hris.sh down` (data kept). `./hris.sh destroy` deletes all HR data.

## What HR clicks

**Hire**

1. PIM > **Add Employee**. Type the first and last name. Type the
   **Employee Id** (the hospital's range: 100xxx staff, 200xxx managers,
   300xxx executives, 400xxx IT; the next IT number is 400104). Save.
2. **Job** tab: Joined Date, Job Title, Sub Unit, Employment Status. Save.
3. **Report-to** tab: Assigned Supervisors > Add. Type the manager's name,
   pick it, Reporting Method **Direct**. Save.

The connector sends the hire after step 3. Before that it prints
"HELD ... the Job tab is not finished" or "no supervisor yet": a hire goes
out once, complete.

**Job change:** PIM > the worker > **Job** > a new Job Title or Sub Unit >
Save.

**Leaver:** PIM > the worker > **Job** > **Terminate Employment** >
Termination Date and Reason > Save. A date today or earlier is sent at the
next sync. A future date waits until that day.

There is no password anywhere in these screens. Entra's provisioning
service sets the AD account's first password itself.

## Retake reset (after a demo hire)

1. OrangeHRM: the worker must be a past employee (Terminate Employment).
   Then **Maintenance > Purge Records > Purge Employee Records**, pick the
   worker, Purge. (OrangeHRM asks for the Admin password again.)
2. The rest is unchanged: `lab/scripts/demo/reset-demo-hire.sh <number> --apply`
   as the operator removes the row on `hr-feed` and the AD account
   (lab/scripts/demo/README.md).

## Rehearse without a person

`orangehrm/hr-clicks.mjs` does HR's clicks in a headless browser and saves a
screenshot of each screen, with the UTC time of the click that finishes the
task. It uses only the screens above; it never touches the database.

```bash
export PLAYWRIGHT_FROM=~/contoso-health-identity-lab/lab/setup/signup-assist  # in a worktree
node orangehrm/hr-clicks.mjs hire --id 100493 --first Test --last Hris \
  --job "Registered Nurse" --unit Nursing --joined 2026-11-07 --supervisor "Grace Mwangi"
node orangehrm/hr-clicks.mjs move  --id 100493 --unit ICU
node orangehrm/hr-clicks.mjs leave --id 100493 --date 2026-11-07
node orangehrm/hr-clicks.mjs purge --name "Test Hris"
```

## Files

| File | What it does |
|---|---|
| `orangehrm/compose.yaml` | OrangeHRM + MariaDB, 127.0.0.1 only, secrets as files |
| `orangehrm/Dockerfile` | Native arm64 OrangeHRM 5.9 (the official image is amd64 only) |
| `orangehrm/hris.sh` | up, install, connector, seed, status, down, destroy; Keychain passwords |
| `orangehrm/seed.mjs` | The go-live load: the `hr-feed` roster into OrangeHRM |
| `orangehrm/connector-view.sql` | The one view the connector may read (8 fields) |
| `orangehrm/hr-clicks.mjs` | Rehearsal driver: HR's clicks, screenshots, click times |
| `connector/sync.mjs` | The connector (once, `--dry-run`, `--watch 60`) |
| `connector/lib/feed.mjs` | Pure rules: hired, moved, left, came back, held |
| `connector/lib/store.mjs` | The outbox on `hr-feed` through `gh` (sha-checked writes), and each send's result |
| `connector/lib/hris.mjs` | Reads the view as `hr_connector` (password from the Keychain) |
| `connector/tests/connector.test.mjs` | `node --test`: rules, store (fake `gh`), seed, view columns |
