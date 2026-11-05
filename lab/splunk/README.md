# Splunk — the second SIEM (local container, $0)

> **Stand-ins — say both on camera.**
> 1. **Splunk Enterprise 60-day trial** (the real product, time-limited
>    license, in a local container) stands in for a **production Splunk**
>    deployment.
> 2. **The live feed** (`lab/scripts/monitoring/feed-splunk-live.py`, a
>    LaunchAgent on the operator Mac, every 5 minutes) reads the Entra and
>    DC01 rows that Log Analytics (`loga-idlab`) received since its last run
>    and posts them to HEC. It stands in for the production data path:
>    **Entra diagnostic settings → Azure Event Hub → Splunk Add-on for
>    Microsoft Cloud Services** (streaming) or the **Splunk Add-on for
>    Microsoft Azure** (Graph inputs). Same Entra events, pulled every five
>    minutes instead of streamed. `ingest-from-loganalytics.sh` (the older
>    on-demand replay) stays for a Splunk without the feed.
>
> Both rows are in [`STAND-INS.md`](../docs/STAND-INS.md), which holds the
> authoritative wording, so it isn't copied here.

| | |
|---|---|
| **Cost** | **$0.** Splunk trial license; local Docker; querying Analytics-tier Log Analytics tables isn't billed per query; no Event Hub, no app registration. |
| **Secrets** | The admin password and the stack's HEC token are generated into `lab/splunk/.env` (0600, gitignored) and are never printed. The live feed has its **own** HEC token (`contoso_live_feed`, pinned to `index=entra`) in the Keychain item `contoso-splunk-hec-live`, and a search-only user for the preflight check (`contoso-feed-check`, Keychain `contoso-splunk-feed-reader`). It reads Log Analytics as the lab operator (certificate, no new secret); the replay rides your own `az login`. |
| **Trial clock** | 60 days from first boot. When it expires you choose: switch the license group to **Free** (Settings → Licensing), where scheduled searches keep running but **alerts no longer trigger** (Splunk's *About Splunk Free*), or buy a license. Record inside the window. |
| **Scope** | **Frozen.** Splunk is the optional second SIEM: the 22 SPL twins mirror the 22 KQL rules and no new twins are added. A new detection is written in KQL only. The SoD tripwire's rule copy is guarded by a mirror test (`09-SoD-Report.Tests.ps1`, "Ruleset mirror") against `lab/iga/sod-rules.json`. |
| **Status** | **RAN · tenant (2026-11-05, capture-log E113): live.** The feed has run every 5 minutes since 16:14Z. Twelve wrong passwords for two test users from one IP (16:30Z) reached Splunk by the 16:41Z feed run and the *Failed sign-in spike* alert fired on them at 16:45Z (FailedCount 12, likely brute force); Sentinel's KQL twin fired on the same rows at 16:42Z (incident #57). Record: `lab/evidence/splunk/20261105T164502Z-live/`. Earlier: RAN · harness (E61, 2026-10-31), 22 of 22 saved searches fired on synthetic events. The checklist below says which live items are proven. |

---

## What's here

| Path | What it is |
|---|---|
| `docker-compose.yml` | Splunk Enterprise `splunk/splunk:10.4.4`, **amd64-only** image (`platform: linux/amd64`), ports on **127.0.0.1** only: Web 8000, HEC 8088, REST 8089. Refuses to start until you accept the license (below). |
| `splunk-up.sh` | Idempotent bootstrap: `.env`, license gate, drift check, `compose up`, health wait, restarts an already-running container when the app changed (Splunk reads app config only at start), pins the HEC token to `index=entra` and reads it back, then verifies index, app, every scheduled alert in `detections/` (12), HEC and a smoke event. |
| `ingest-from-loganalytics.sh` | The replay: `az monitor log-analytics query` → HEC, per table, batched, incremental (ingestion-time high-water mark), fails loudly. Default tables: `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`; the ITDR rules also need `-T AADUserRiskEvents,AADRiskyUsers,SecurityEvent,VaultCheckout_CL` once those tables have data (`enable_itdr_detections`, the P2 risk log categories in `envs/bootstrap`, DC01 AMA, `lab/scripts/monitoring/ingest-vault-audit.sh`). |
| `detections/*.spl` | The 22 KQL rules in SPL, one readable, paste-able file each with its alert schedule: the five core rules, the eleven ITDR rules (app credential added, consent granted, CA policy / named location / auth strength changed, role assigned outside PIM, privileged-group member added outside PIM, auth method changed by an admin, identity risk, and the AD plane: Tier-0 logon PAM does not account for, privileged AD group change, Kerberoasting, DCSync) and the six second-wave rules (device-code sign-in, risky security-info registration, DC logon outside the operator allow-list, vault anomaly, SoD pair completed, PIM activation without the auth context). All 22 ship enabled. `splunk-up.sh` creates header-only, gitignored `contoso_operator_ips.csv` and `contoso_sod_holdings.csv` when they are missing, so neither search errors: an empty operator allowlist alerts on every DC01 logon, and an empty holdings file limits the SoD tripwire to grants inside its 14-day window. Inventory and KQL twins: [`../kql/README.md`](../kql/README.md). **Source of truth for the Splunk side.** |
| `render-savedsearches.sh` | Builds `app/contoso_identity/default/savedsearches.conf` from the `.spl` files; `--check` fails if the committed `.conf` is stale. |
| `app/contoso_identity/` | Splunk app, bind-mounted into the container: `entra` index, JSON extraction for the seven sourcetypes (three Entra tables + the four ITDR tables), raised extraction limits, the generated alerts, global export. |
| `lib.sh` | Shared helpers (no-secret-leak REST/HEC calls). Sourced, never run. |
| `../scripts/monitoring/feed-splunk-live.py` | **The live feed** (lives with the other feeds): Log Analytics → HEC every 5 minutes as a LaunchAgent, watermark + record-id de-duplication, heartbeat, `check` for the preflight. Setup, install and uninstall: [`lab/scripts/monitoring/README.md`](../scripts/monitoring/README.md#the-splunk-live-feed). |
| `.env.example` | Every key the stack reads. You don't copy it; `splunk-up.sh` writes `.env`. |
| `.gitignore` | Keeps `.env` (password + HEC token), `.state/` (high-water marks, app fingerprint, dry-run tenant data) and Splunk-Web edits (`app/contoso_identity/local/`) out of git — on its own, before the repo-root `.gitignore` lists them. |

---

## Prerequisites

- **Docker.** Apple Silicon: Splunk publishes **no arm64 image** (Docker Hub
  lists only `linux/amd64` for every tag), so it runs under emulation. Use
  Docker Desktop with *"Use Rosetta for x86_64/amd64 emulation"* on, or
  `colima start --vz-rosetta --cpu 4 --memory 8`. Give the VM **≥ 6 GB** if the
  PAM stack (`lab/pam`) runs at the same time. First boot: 5–15 min.
- `jq`, `curl`, `openssl` (macOS ships all three).
- For the replay: Azure CLI signed in (`az login`) as a user with **Log
  Analytics Reader** (or more) on `loga-idlab`, plus the CLI extension
  `az extension add --name log-analytics` (the `query` command lives
  in that extension, not in core `az`).
- Entra diagnostic settings streaming to `loga-idlab`
  (`lab/terraform/envs/bootstrap`, second apply) and an Entra ID P1/P2 licence
  (sign-in logs don't export on the free tier).

## License acceptance — your step, not a script's

Splunk's 10.x image won't start unless two variables carry the exact
acceptance strings. **No script in this repo sets them.**

1. Read the **Splunk General Terms**:
   <https://www.splunk.com/en_us/legal/splunk-general-terms.html>
2. Only if you accept them, edit `lab/splunk/.env` (created by the first
   `./splunk-up.sh` run) and set:
   ```
   SPLUNK_START_ARGS=--accept-license
   SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com
   ```
   (Names and values checked 2026-10 against the `splunk/splunk` Docker Hub page
   and docker-splunk's `entrypoint.sh`.) If either is empty, `docker compose`
   fails with an explanatory `${VAR:?…}` message and `splunk-up.sh` stops.

## Run order

```bash
cd lab/splunk
./splunk-up.sh          # 1st run: writes .env, stops at the license gate
#   (manual) read the terms, set the two lines in .env
./splunk-up.sh          # 2nd run: starts Splunk, verifies index/app/alerts/HEC

# the live feed (once; then the LaunchAgent keeps it running every 5 min):
cd ../..
/usr/bin/python3 -I lab/scripts/monitoring/feed-splunk-live.py setup     # its HEC token + search-only user -> Keychain
/usr/bin/python3 -I lab/scripts/monitoring/feed-splunk-live.py install   # LaunchAgent, runs at once and every 300 s
/usr/bin/python3 -I lab/scripts/monitoring/feed-splunk-live.py check     # newest feed event < 15 min old?

# without the feed (a Splunk on another machine): the on-demand replay
# ./ingest-from-loganalytics.sh --timespan PT24H   (never while the feed is installed: same rows twice)
```

Then in Splunk Web (`http://127.0.0.1:8000`, `admin` / `SPLUNK_PASSWORD` from
`.env`):

- **Search & Reporting** → paste `detections/failed-signin-spike.spl` (the
  side-by-side shot with `lab/kql/failed-signin-spike.kql`).
- **Search & Reporting → Alerts** (filter `Contoso`) → the 22 scheduled
  alerts. **Activity → Triggered Alerts** shows what fired.

Changing a detection: edit `detections/<rule>.spl` → `./render-savedsearches.sh`
→ commit both → `./splunk-up.sh`. Splunk reads app config only when it starts,
so `splunk-up.sh` compares the app's fingerprint with the last verified run
(`.state/app.sha256`) and restarts a container that was already running when
the app changed — then re-verifies. (Restart under emulation takes minutes.)

After a laptop restart: `./splunk-up.sh` again (idempotent). Teardown:
`docker compose down` keeps the indexed data; `docker compose down -v` also
deletes the `splunk-etc`/`splunk-var` volumes (indexed data, trial license
state) — your call.

### Replay details worth knowing

- **Zero-new-secret path.** `az monitor log-analytics query --workspace
  <customer-id GUID> --timespan PT24H --analytics-query "<KQL>"`. The workspace
  GUID is looked up with `az monitor log-analytics workspace show
  --resource-group rg-identity-lab --workspace-name loga-idlab --query
  customerId` (or pass `-w`).
- **Each row travels as one JSON string** (`tostring(pack_all(true))`) because
  the CLI extension `str()`s every cell — numbers and booleans would arrive as
  text and nulls as the word `None`.
- **JSON-in-text columns are parsed.** `AADNonInteractiveUserSignInLogs` stores
  `LocationDetails`, `ConditionalAccessPolicies`, `DeviceDetail`… as **string**
  columns (SigninLogs stores them as `dynamic`). The replay parses them, so the
  SPL sees the same nested `LocationDetails.countryOrRegion` path for both.
- **`_time` = `TimeGenerated`** (HEC envelope `time`, millisecond precision).
- **No duplicates on re-run.** A per-table high-water mark of
  `ingestion_time()` lives in `.state/<Table>.hwm` (gitignored). Ingestion
  time, not `TimeGenerated`, because Entra rows reach Log Analytics 5–15 min
  late and would otherwise be skipped. `--full` ignores it (and warns: rows
  already in Splunk are sent again, which would double `FailedCount`).
- **Scheduled alerts look back from *now*** (1 h; legacy auth 24 h), exactly
  like the Sentinel rules. Replay promptly, or use `--follow`. An event
  replayed 3 h late keeps its true 3-h-old `_time` and only appears in ad-hoc
  searches; edit the inline `earliest=` to look further back.
- **Limits.** A single Log Analytics query returns at most 500,000 rows / ~64 MB
  (verify: current API limits) — irrelevant for a lab tenant, but production
  scale is exactly why the add-on / Event Hub path exists.
- **`--dry-run`** writes the HEC payloads to `.state/dry-run/` without sending;
  **`--input-json FILE -T <Table>`** converts a saved query output offline.

Identity ids the ITDR rules judge by live in
`app/contoso_identity/lookups/` (the KQL side gets the same ids rendered by
Terraform).

#### Identity lookups (ITDR detections)

Committed with a header row only. Header-only = fail closed: nothing counts as
the CI apply identity, no group or user is privileged by id (the detections
fall back to naming, which can only RAISE severity).

| File | Column(s) | Fill from (tenant time) | Used by |
|---|---|---|---|
| `contoso_iac_principals.csv` | `principal_id` | `terraform -chdir=lab/terraform/envs/bootstrap output -json iac_principal_ids` (APPLY service principal object id + client id) | ca-policy-changed, role-assigned-outside-pim, pim-group-member-added-outside-pim, app-consent-granted, app-credential-added |
| `contoso_privileged_groups.csv` | `group_id,name,breakglass,azure_pim` | `terraform -chdir=lab/terraform/envs/dev output -json itdr_privileged_group_ids` (+ `true` in `breakglass` on the Break-Glass-Admins row, and in `azure_pim` on the PIM-Azure-RG-Contributors row) | pim-group-member-added-outside-pim |
| `contoso_privileged_identities.csv` | `object_id,kind` | `Find-ShadowAdmins.ps1 -PrivilegedIdsPath <file>` (break-glass, PIM-group members and eligibles, role holders) | auth-method-changed-by-admin |
| `contoso_operator_ips.csv` (**not committed**: it holds the operator's IP; created header-only by `splunk-up.sh`, gitignored) | `IpRange,Owner,ExpiresOn` (CIDR match, `transforms.conf`) | the same `operator_ip_ranges` that feed the Sentinel `operator_ips` watchlist | dc-logon-outside-operator-allowlist (header-only = every source alerts) |
| `contoso_sod_holdings.csv` (**not committed**: object ids and UPNs; created header-only by `splunk-up.sh`, gitignored) | `UserObjectId,UserPrincipalName,Kind,Name,SnapshotTime` | written by `09-SoD-Report.ps1 -HoldingsSnapshotPath`; copied here by hand at tenant time | sod-violation-granted (header-only = grants inside its 14-day window only) |

The same ids feed the KQL side through Terraform (`modules/monitoring`
variables `iac_principal_ids`, `privileged_group_ids`,
`privileged_user_ids`), so both SIEMs judge the same identities. The values
are object ids, not secrets, but they identify a real tenant. The operator
IP and SoD holdings lookups are gitignored already. The other three are
committed header-only: keep their filled copies out of the public repo (a
local copy of the app, or `git update-index --skip-worktree`). Moving them
to a gitignored path like the other two would be safer; that is not done
yet.

---

## KQL vs SPL — side by side

Same rule, same window, same threshold, same output columns. Schedules,
severity and grouping mirror the Sentinel rules deployed by
`lab/terraform/modules/monitoring`.

| Rule (KQL ↔ SPL file) | Window | Threshold / trigger | Schedule | Severity (Sentinel → Splunk) | Grouping → throttle |
|---|---|---|---|---|---|
| `pim-activation` | 1 h | > 0 rows | 5 min | Medium → 4 | Actor + ActorIp, 1 h |
| `break-glass-signin` | 1 h | > 0 rows | 5 min | High → 5 | UserPrincipalName + IPAddress, 1 h |
| `blocked-country-signin` | 1 h | > 0 rows | 5 min | Medium → 4 | UserPrincipalName + IPAddress, 1 h |
| `failed-signin-spike` | 1 h, 10-min bins | ≥ 10 failures / IP / bin; > 0 rows | 5 min | Medium → 4 | IPAddress, 1 h |
| `legacy-auth` | 24 h, 1-h bins | > 0 rows (StillSucceeding flags successes) | hourly (`5 * * * *`) | Low → 3 | one alert per hit (suppressed 23 h after firing) |

| KQL construct | SPL translation used here |
|---|---|
| `SigninLogs` / `AADNonInteractiveUserSignInLogs` / `AuditLogs` | `index=entra sourcetype=azure:loganalytics:signinlogs` / `…:aadnoninteractiveusersigninlogs` / `…:auditlogs` |
| `where TimeGenerated > ago(1h)` | `earliest=-1h latest=now` (inline, plus `dispatch.earliest_time`) |
| `union (A \| extend SignInType=…), (B \| …)` | `(sourcetype=A OR sourcetype=B)` + `eval SignInType=if(sourcetype==…)` |
| `x == "v"` / `x in ("a","b")` (case-sensitive) | `where x=="v"` / `where in(x, "a", "b")` |
| `x in~ (list)` (case-insensitive) | `search x IN (…)` or `where in(upper(x), …)` |
| `x has "term"` | `where match(x, "(?i)(^\|[^A-Za-z0-9])term($\|[^A-Za-z0-9])")` — KQL's term boundary (non-alphanumeric), no backslash escapes |
| `matches regex @"(?i)^bg-admin-\d{2}@"` | `regex UserPrincipalName="(?i)^bg-admin-[0-9]{2}@"` (RE2's `\d` is ASCII-only, so identical) |
| `tostring(LocationDetails.countryOrRegion)` | `spath path=LocationDetails.countryOrRegion output=…` |
| `coalesce(a, b)` (skips empty strings) | `if(isnotnull(a) AND a!="", a, b)` |
| `mv-apply … where … \| summarize make_set(…)` | `spath path=Arr{} output=X` + `mvfilter(spath(X,"k")==…)` + `mvdedup(mvmap(…, spath(…,"name")))` |
| `take_anyif(name, type == "Group")` | `mvfilter(spath(X,"type")=="Group")` → `mvindex(…, 0)` → `spath(…, "displayName")` |
| `summarize … by IPAddress, bin(TimeGenerated, 10m)` | `bin _time span=10m \| stats … BY IPAddress _time` |
| `count()` / `countif(p)` | `count` / `sum(eval(if(p, 1, 0)))` |
| `dcount(x)` | `dc(x)` — exact (KQL's is an estimate; identical at lab scale) |
| `make_set(x, N)` | `values(x)` then `mvindex(x, 0, N-1)` (values() is sorted) |
| `any(x)` / `min()` / `max()` | `first(x)` / `min()` / `max()` |
| `iff(c, a, b)` / boolean column | `if(c, a, b)` / `"true"`/`"false"` string |
| `project …` / `sort by TimeGenerated desc` | `table …` / `sort 0 - _time` (`0` = no 10,000-row cap) |

Honest differences: KQL `dcount` is approximate where SPL `dc` is exact;
`values()` returns sorted members where `make_set` is unordered; Splunk has no
empty-vs-null distinction for missing JSON keys (the replay drops null/empty
columns via `pack_all(true)`, and the SPL treats missing as empty) — with one
consequence: `stats … BY IPAddress` drops events that have no `IPAddress`,
where KQL's `summarize … by IPAddress` keeps them in an empty-IP group (a
failed sign-in with no client IP is not expected in Entra logs); binned
timestamps print with `%z` (`+0000` — the container runs `TZ=UTC`).

---

## Verification checklist

Offline (done in this repo, re-runnable any time):
- [ ] `python3 -c "import yaml; yaml.safe_load(open('docker-compose.yml'))"` parses.
- [ ] `bash -n` passes on `splunk-up.sh`, `ingest-from-loganalytics.sh`, `render-savedsearches.sh`, `lib.sh` (also under macOS's bash 3.2).
- [ ] `./render-savedsearches.sh --check` → "matches detections/*.spl (22 detections)".
- [ ] `./ingest-from-loganalytics.sh -T SigninLogs --input-json <saved az output> --dry-run` writes one HEC envelope per row to `.state/dry-run/`.

Live (record only when all are ticked):
- [ ] `./splunk-up.sh` prints "HEC token restricted to index=entra (read back)" and ends with "Detections: 22 loaded, 22 scheduled" and "HEC: healthy, smoke event accepted". (The check compares the scheduled count with the number of `.spl` files; all 22 ship `disabled = 0`.)
- [ ] Change a `.spl` search line or `@conf` value (comments are stripped from the `.conf`, so a comment edit changes nothing), re-render, re-run `./splunk-up.sh`: it logs the restart, and the search shown in **Alerts** matches the file.
- [ ] **Settings → Licensing** shows the Enterprise **Trial** and its end date.
- [ ] `index=entra sourcetype=contoso:hec:smoketest` returns the smoke event.
- [x] After the first live-feed run: `index=entra source="livefeed:*" | stats count dc(feed_item_id) by sourcetype` shows six `azure:loganalytics:*` sourcetypes with count = distinct ids (E113; `VaultCheckout_CL` had no rows that day).
- [x] `index=entra sourcetype=azure:loganalytics:signinlogs | head 1` shows `UserPrincipalName`, `ResultType`, `LocationDetails.countryOrRegion` as fields (JSON extraction works).
- [x] Same window, same counts (E113, 2026-11-05 09:00-15:00Z by `TimeGenerated`): Log Analytics and `index=entra source="livefeed:*"` both hold SigninLogs 342, AADNonInteractiveUserSignInLogs 1767, AuditLogs 1646, SecurityEvent 1987, and every Splunk count equals its distinct `feed_item_id` count.
- [x] Re-running the feed sends **0** old events: the second run skipped every row inside its 10-minute overlap as already sent (E113).
- [~] (partly, E113: the failed-sign-in spike, live: 12 wrong passwords for two test users from one IP in one bin gave one row in each SIEM, `Pattern = likely brute force`; the other 21 twins are proven on synthetic events only, E61) Each `detections/*.spl` returns the same row(s) as its `lab/kql/*.kql` twin for the generated signal — in particular **one** `failed-signin-spike` row for Sofia's 12 wrong passwords from one IP, `Pattern = likely brute force`. Both languages bin on 10-minute **clock** boundaries (`:00`, `:10`, …), so type all 12 inside one such bin — 7 + 5 across a boundary gives **zero** rows in both SIEMs.
- [x] **Activity → Triggered Alerts** lists the fired alert: 16:45:02Z, 4 minutes after the feed delivered the last of the 12 rows (E113, screenshot 4).
- [ ] `git status` shows nothing under `lab/splunk/` except intended changes (`.env`, `.state/`, `app/contoso_identity/local/` stay ignored).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `compose` says *Read https://www.splunk.com/… set SPLUNK_START_ARGS…* | License lines in `.env` are empty — the human step above. |
| Container stays `starting`/`unhealthy` for >10 min | Emulated first boot is slow; give the VM more CPU/RAM; `docker compose logs -f splunk`. Raise `SPLUNK_BOOT_TIMEOUT` (seconds). |
| KV Store errors in the Splunk log under emulation | verify: the KV store's database can fail on CPUs/emulators without AVX. This lab uses no KV-store features; searches and alerts still work. |
| HEC `{"code":7,"text":"Incorrect index"}` | The token is pinned to `entra` and something sent elsewhere; re-run `./splunk-up.sh`. |
| HEC `{"code":4}` / 401, or REST "did not accept the admin login" | `.env` was regenerated after first boot. A changed token is re-provisioned on the next `./splunk-up.sh`, but the admin password is only seeded on first boot. Restore the old `.env`, or `docker compose down -v` (deletes indexed data) and start over. |
| Replay: "Log Analytics query failed" | Table has never received data (no diagnostic setting / no P1), missing Reader role, or the `log-analytics` CLI extension isn't installed. |
| Detection returns nothing in an ad-hoc search | The inline `earliest=-1h` — your replayed events may be older. Widen it for the ad-hoc run. |

## Production path (what this replaces)

Entra ID diagnostic settings → **Azure Event Hub** → Splunk (Event Hub input
of the Microsoft cloud add-ons), or the **Splunk Add-on for Microsoft Azure**
pulling sign-in/audit logs from Microsoft Graph with an app registration that
holds `AuditLog.Read.All`. Either delivers continuously and needs a secret or
certificate this lab deliberately avoids. Those add-ons use their own
sourcetypes and the Graph field layout, so the SPL here would be re-pointed
through field aliases/CIM — which is why the replayed sourcetypes are named
`azure:loganalytics:*` and never reuse the add-ons' names.
