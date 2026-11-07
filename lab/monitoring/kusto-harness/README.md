# Kusto-emulator harness for `lab/kql`

Runs the `lab/kql/*.kql` detections (29 since 2026-11-07) on a real KQL
engine, the Azure Data Explorer Kusto emulator ("Kustainer") in a local
container, against synthetic positive and negative events, and publishes a
hashed run record.

**The two rules added on 2026-11-06** (`dormant-privileged-account-reactivation`,
`keyvault-bulk-secret-read`) **have not run on the emulator.** Their 25 cases
ran on the Log Analytics query engine instead, with `run-on-workspace.py`
(below): RAN · harness, on the Log Analytics query engine, 2026-11-06, PASS 25/25, record
[`lab/evidence/kusto/20261106T074249Z-workspace/`](../../evidence/kusto/20261106T074249Z-workspace/)
(capture-log E114). Everything below about the emulator runs is about the 22
rules that existed on those days.

**Status: RAN · harness, once.** On 2026-10-21 (UTC) the operator accepted
the emulator's licence and ran `run.sh --accept-eula`. Record:
[`lab/evidence/kusto/20261021T001217Z/`](../../evidence/kusto/20261021T001217Z/)
(`results.json`, `run.log`, `setup.kql`, 31 rendered queries, `guids.txt`:
none, and a `SHA256SUMS` over all 35 files). Result **PASS**: rules 22/22
passed, 0 not run; cases PASS 223, FAIL 0, ERROR 0, XFAIL 0, XPASS 0. The
three detection fixes it found (CODE NEEDED below) passed their cases on the
engine.

"Imports skipped 12" means 12 rows of the KqlLite fixture file
(`itdr-cases.json`) were not turned into engine cases, because they are not
whole raw table rows: 8 are stage-level rows (`afterSummarize`, aggregated
rows in the middle of a rule) and 4 carry `joinRows` (rows of a rule's
derived `let`). They are not failures, and they were not sent to the engine.
The 277 cases do not include them. Each is listed with
its reason in `results.json` `skippedImports`, and the hand-written cases for
the same rules (`tier0-logon-without-checkout` 8 skipped,
`kerberoast-rc4-service-ticket` 3, `auth-method-changed-by-admin` 1) cover
the same situations with raw events.

What the run is, plainly: the Azure Data Explorer Kusto emulator, a local
container on the author's machine (amd64 under Rosetta on Apple silicon),
with tables built from Learn's column lists and filled with synthetic
events, one case at a time. Sentinel's `_GetWatchlist` is shimmed (below);
Log Analytics and Sentinel do not run here. **It is not a Log Analytics
workspace, not Microsoft Sentinel, and not a tenant**: no analytics rule was
scheduled, no incident was created, and no real sign-in or audit data was
read. It shows that the 22 queries compile on a real KQL engine and return
the expected rows for those events. The scheduling and entity checks listed
under "Not emulated" stay tenant-time checks.

The emulator is licensed under Microsoft's evaluation terms (internal use;
see the next section), and running it means accepting them
(`ACCEPT_EULA=Y`), so only the operator can start it, with an explicit flag:

```bash
lab/monitoring/kusto-harness/run.sh --accept-eula
```

Without `--accept-eula`, `run.sh` prints the licence URL and a summary and
exits 2 before it touches Docker. Nothing is pulled or started, and
`ACCEPT_EULA` is never set. No environment variable can replace the flag.

## The licence: read it before passing `--accept-eula`

- Terms: <https://aka.ms/adx.emulator.license>. The link redirects to
  `https://kustoes.blob.core.windows.net/kusto/ADX-Emulator-Evaluation-Terms.pdf`
  ("Microsoft Software License Terms - Azure Data Explorer Emulator", 3
  pages). As read on 2026-10-20 the PDF was `Last-Modified: 2022-06-01`,
  sha256 `39a4d19c561db5e32c71bdd5d0a44592a86da38e2c01054fd806a6b61ac95dd9`.
  If those have changed, read the terms again.
- In short (this is not legal advice):
  1. The licence is free, for internal business use on your own devices. It
     does not cover a live (production) environment, or commercial,
     non-profit or revenue-generating activity.
  2. You may not reverse engineer, share or redistribute the software, or
     disclose benchmark-test results to third parties without Microsoft's
     written approval.
  3. The software is provided as is, with no warranty and no support. Damages
     are capped at US$5. In the US and Canada your state or province's law
     applies, with venue in King County, WA.
- What that means for this repo, whose `lab/` folder goes public:
  - The image is never committed or mirrored. `run.sh` pulls it from
    `mcr.microsoft.com`.
  - The run record contains no timings: no per-query or per-phase durations
    and no clock times on progress lines. Only the start line and the RESULT
    line carry a clock time (the same as `results.json` started / finished),
    so no per-query benchmark numbers can be derived from it (licence §2 d).
    The 2026-10-21 record follows this: its `results.json` `notRecorded`
    field says per-query timings were left out for that reason. Do not
    publish emulator timings anywhere else in the repo either.
  - The run is evaluation use on the author's own machine: the emulator
    tested the lab's queries, and nothing served users from it.
  - Whether a personal portfolio lab counts as "internal business use", and
    not as "commercial ... activity" (§2 e), is the operator's call. The
    harness cannot decide it.
  - §4 (data): the software "may interact with other Microsoft products that
    collect data".

## Image and CPU architecture

- Image: `mcr.microsoft.com/azuredataexplorer/kustainer-linux`, as Microsoft
  Learn "Install the Azure Data Explorer Kusto emulator" names it (ms.date
  2026-07-23). `run.sh` pins the digest that `:latest` resolved to on
  2026-10-20, `sha256:d5981f2bc0a07b692bbc6c1331c66c50bf65a80896e05457e6e9d789628d8c60`,
  image label build `2026.10.20.1140-2642-34f1c8c-master`, base
  `azurelinux/base/core:3.0`. Learn also mentions a `:stable` tag; on
  2026-10-20 it returned `MANIFEST_UNKNOWN`. `--image` overrides the pin, and
  the record names the image and digest that actually ran.
- **No arm64 image exists.** The registry serves a single
  `application/vnd.docker.distribution.manifest.v2+json`, not a manifest
  list, and its config says `"architecture": "amd64", "os": "linux"`. These
  were read from the manifest and config blob only; the image was not
  pulled. Learn agrees: "ARM processors aren't supported". It also requires
  SSE4.2/AVX2 and at least 2 GB of RAM (4 GB recommended).
- On Apple silicon the engine runs under amd64 emulation. With colima that
  means `colima start --vm-type vz --vz-rosetta`. The colima VM here has
  the Rosetta binfmt handler registered, and `run.sh` checks for it. The
  2026-10-21 run shows the engine starts and answers under Rosetta on this
  Mac (colima 0.10.3, Docker 29.5.2 linux/arm64; the record's
  `environment`). On another host, if the container exits at start,
  `engine.log` in the run directory shows why.

## What `run.sh --accept-eula` does

1. `harness.py check` validates the schemas, shims, case files and import
   offline. If it fails, nothing is started.
2. Preflight:
   - Docker must be reachable. A stopped colima is started with Rosetta.
   - On an arm64 host, amd64 emulation must be present.
   - Docker is shared. While another lab stack runs (`contoso-pam*`,
     `contoso-dyndb*`, `pam-scale*`), the script polls every 60 s for up to
     45 min (`--wait-max`). It never stops anyone else's containers.
3. It runs `docker pull --platform linux/amd64`, then `docker run` with
   `ACCEPT_EULA=Y` and `-m 4g`. The port is bound to `127.0.0.1` only (a
   free port unless `--port`). Then it waits for `.show version`.
4. `harness.py run`:
   - Creates database `ContosoDetections`, the 7 tables, the 2 watchlist
     store tables and the `_GetWatchlist` shim.
   - Runs the 13 engine probes.
   - Runs every case of every rule: clear the tables, ingest the case's rows,
     run the rule, assert.
5. It removes the container (`--keep` leaves it running) and publishes the
   record, whether the run passed or failed, to
   `lab/evidence/kusto/<UTC ts>/` with `guids.txt` and `SHA256SUMS`.
   `--no-publish` keeps the record in a temporary directory instead.
   - If the container exits before it is ready, or never answers
     `.show version` (for example because amd64 emulation lacks a CPU feature
     the engine needs), the record is still published: `engine.log`, and a
     `results.json` with result `ENGINE-START-FAILED`, every rule `NOT RUN`,
     no query sent. The script exits 2 and does not retry.

Other options: `--rules a,b` and `--case <rule>/<id>` give a partial run,
recorded as `PARTIAL-PASS` or `PARTIAL-FAIL`; `--memory`; `--image`.
Exit codes: 0 means every rule passed, 1 means a rule failed, 2 means
refused or preflight failed.

## Tables (`schemas.json`)

- `learnColumns` holds each table's **full** column list (name and type) from
  the Microsoft Learn table reference:
  - `SigninLogs`, `AADNonInteractiveUserSignInLogs`: ms.date 2026-08-27.
  - `AADUserRiskEvents`, `AADRiskyUsers`: ms.date 2026-07-27.
  - `AuditLogs`, `SecurityEvent`: copied from
    `lab/scripts/monitoring/tests/fixtures/table-schemas.json`, which is
    itself from Learn (ms.date 2026-08-27).

  All lists were read on 2026-10-20.
- The harness creates each table with **only the columns the rules use**. On
  every run it computes them: a token scan of every rule that reads the table
  (comments and string literals removed), intersected with `learnColumns`.
  The `.create table` commands are written to the record as `setup.kql`. A
  scan over-approximates slightly: a name a rule reads only from another
  table (e.g. `Category` on `SigninLogs`) is still a real column of this one.
  As a result, a rule that reads a name its table does not have fails to
  compile here, as it would in a workspace.
- The types are Learn's, so the schema traps the rules work around are real
  here. `LocationDetails`, `DeviceDetail` and `ConditionalAccessPolicies` are
  `dynamic` in `SigninLogs` but `string` in `AADNonInteractiveUserSignInLogs`.
- `VaultCheckout_CL` is the lab's own custom table, so
  `lab/terraform/modules/monitoring/telemetry.tf` is its reference
  (`harness.py check` compares the names). It has two variants: `v2`
  (`vault_feed_v2_columns = true`, the default) and `base` (no `Ticket`,
  `Operator` or `ErrorText`).
- `AzureDiagnostics` (Key Vault AuditEvent rows, read by
  `keyvault-bulk-secret-read`) is a **subset**, not Learn's full list:
  AzureDiagnostics gains a column the first time a resource sends a field it
  lacks (Learn, ms.date 2026-09-28), so Learn cannot list every Key Vault
  column. The names and types come from `getschema` on loga-idlab, run as the
  operator on 2026-11-06. Two differ from Learn's page: `identity_claim_appid_g`
  is `string` there (Learn: Guid), and the workspace has `ResourceId` (Learn
  lists `_ResourceId`).
- Watchlist store tables: `Watchlist_operator_ips` has `SearchKey`,
  `IpRange`, `Owner` and `ExpiresOn` (from `itdr_v2.tf`).
  `Watchlist_sod_holdings` has the columns `sod-violation-granted.kql` reads.

## Shims (`shims.kql`; every one is listed in `results.json` `shims`)

| Shim | Variant | Why |
|---|---|---|
| `_GetWatchlist(alias)` | `default` | Sentinel built-in, absent from ADX. It returns the store table's rows with `SearchKey` and the watchlist columns at top level (Learn: "Build queries or rules with watchlists"). |
| `_GetWatchlist(alias)` | `no-items-base-columns` | Sentinel's shape for a watchlist with no items: base columns only, so a projection of `ExpiresOn` / `Name` has nothing to resolve. It tests the rules' `union isfuzzy=true` fail-safe. |
| `_GetWatchlist(alias)` | `absent` | The function is dropped, as on a workspace without Sentinel. |

These need no shim, because ADX has them with the same meaning: `ago()`,
`now()`, `column_ifexists()`, `getschema`, `toscalar()`, `ipv4_*`,
`datatable`. The fixtures' relative times are resolved against the engine's
own `now()` before each case, so `ago()` windows line up whatever the
container clock does.

**Not emulated** (these remain tenant-time checks):

- the scheduled rule's query period, an outer time filter (only the rules'
  own `ago()` filters apply here);
- Sentinel rejecting a rule over a table that has never received data;
- entity mapping, custom details, grouping and suppression;
- Sentinel's own `_GetWatchlist` implementation.

## Rules run as deployed

Each case's query is the rule file, rendered the way
`modules/monitoring/main.tf` `rule_queries` renders it: the committed
placeholder `dynamic([]); // @@NAME@@` is replaced by
`dynamic(<jsonencode(ids)>); // @@NAME@@`. With no `lets`, the committed
empty lists are kept, which is a standalone run that falls back to naming. A
case can render only those placeholder lists. It can never change a rule's
constants.

## Cases

- **Hand-written**: `cases/<rule>.json` covers 17 rules (15 until 2026-11-06). That includes every
  rule the existing fixtures do not cover, plus raw-event versions of the
  fixture rows the import has to skip.

  ```json
  {"rule": "<rule file stem>",
   "defaults": {"<Table>": {"col": "value"}},
   "cases": [{"id": "...", "kind": "positive|negative", "label": "...",
              "tables": {"<Table>": [{"col": "value", "_repeat": 12}]},
              "watchlists": {"operator_ips": [{"SearchKey": "..."}]},
              "lets": {"PrivilegedUserIds": ["<object id>"]},
              "tableVariant": {"VaultCheckout_CL": "base"},
              "shimVariant": {"_GetWatchlist": "absent"},
              "expect": [{"Severity": "High"}], "expectNone": [{"Signal": "..."}],
              "expectRows": 1, "xfail": "CODE-NEEDED-<n>: <reason>"}]}
  ```

  Row values follow these rules:
  - Values are merged over `defaults`.
  - `_repeat: N` makes N copies, substituting `{i}` in string values.
  - `"ago:30m"` and `"in:7d"` in a datetime or string column resolve against
    the engine's `now()`.
  - A row without `TimeGenerated` gets `ago:30m`, like KqlLite.
  - An object given for a `string` column is ingested as its JSON text.
  - Object ids are repeated-digit placeholders (`11111111-1111-1111-1111-111111111111`
    up to `ffffffff-…`), the form the public repo's GUID gate always allows,
    so neither the cases nor a run record (which repeats them) need
    allowlist entries. They are unique within a case file, which is all a
    case needs: every case runs on its own freshly cleared tables. Microsoft
    well-known ids (role templates, first-party apps) stay as they are.
- **Imported** (read only):
  `lab/scripts/monitoring/tests/fixtures/itdr-cases.json`, the KqlLite
  fixtures, covers 10 rules. Every row that is a whole raw table row becomes
  an engine case: positive if it has an `expect`, negative if it has none.
  Its `lets` must be placeholder renders.
  - Skipped, each with the reason recorded in `skippedImports`: stage-level
    rows (`afterSummarize`), rows with non-empty `joinRows` (derived let
    rows), and rows that override non-rendered lets.
  - Fixture columns that are real Learn columns but not in the harness table
    are dropped and noted.
  - `expect` keys the rule does not output (intermediate columns such as
    `Covered`) are recorded as `unassertedExpectColumns`.
  - `cases/_itdr-import-overrides.json` marks imported rows `xfail` by rule
    plus exact label. A stale override is reported, never applied elsewhere.
  - The record stores the import file's sha256.
- Coverage from `harness.py check` (277 cases):

  | | rules | cases | positives | negatives |
  |---|---|---|---|---|
  | all | 22 | 223 | 131 | 92 |
  | hand-written | 15 | 129 | | |
  | imported | 10 | 94 (12 rows skipped) | | |

  Every rule has at least 2 positives and 1 negative. That table is the
  2026-10-21 run's. `harness.py check` on 2026-11-06, with the two new case
  files (13 cases for the dormant rule, 12 for the Key Vault rule, each with
  the old repo's decoys and new ones): **302 cases over 24 rules**, all valid.
- Isolation: before each case the harness clears every table it wrote and
  ingests only that case's rows, using `.append <table> <| print ... |
  mv-expand | project`, typed and in table column order (ingest-from-query
  matches columns by position). The rule therefore sees exactly the case's
  data.
- Assertions:
  - **positive**: at least one row is returned, and each `expect` object
    matches some row. Values compare as JSON; lists compare as multisets,
    because `make_set` order is undefined in Kusto; `true` never equals `1`.
    In a hand-written case, every `expect` column must be an output column.
  - **negative**: zero rows.
  - `expectNone`: no row may match.
  - `expectRows`: exact count.
- Status of each case:
  - PASS or FAIL;
  - ERROR: an engine error (e.g. the rule does not compile), which fails the
    case;
  - XFAIL: an `xfail` case that failed, as expected until its CODE NEEDED
    change lands;
  - XPASS: an `xfail` case that passed, which fails the run. Remove the
    marker.

  A rule passes only with at least one positive and one negative and nothing
  but PASS or XFAIL. A rule none of whose cases reached the engine is
  `NOT RUN`, never FAIL. The run passes only if every rule passes (22 in the
recorded runs).

## Engine probes (`cases/_engine-probes.json`)

The probes are 13 one-line queries about behaviour that Learn does not spell
out but the rules (and KqlLite) rely on. Their answers are recorded rather
than asserted; they explain any case that fails. They cover:

- `mv-apply` over an empty or null array;
- `mv-apply ... to typeof(string)` over objects;
- `arr[-1]`;
- `make_set` over array values;
- `union isfuzzy=true` with a missing function or an unresolved column;
- leftouter null-fill;
- `has_any` with a GUID;
- `ipv4_is_in_any_range` with an empty list;
- `coalesce` with `''`;
- property-bag key order in `tostring()`;
- how the v1 endpoint encodes `dynamic`.

## Run on the workspace instead: `run-on-workspace.py`

No emulator and no licence step: each case becomes one **read-only** query to
loga-idlab's query API (`POST api.loganalytics.io/v1/workspaces/<id>/query`),
sent through the lab operator (`op az rest`). The case's rows are bound with
`let <Table> = view() { print ... | mv-expand | project ... }`, using the
same typed projection `.append` uses here; a `let` with a table's name
shadows the real table for that one query, so the rule reads only the
synthetic rows. The query is the rule rendered as `modules/monitoring`
deploys it. Nothing is ingested or written in the workspace. The answer
keeps its column types: `primary_table()` decodes it as on the emulator
path (a `dynamic` column such as a `make_set()` list arrives as JSON text
and becomes a list), and the same `evaluate()` judges it. A SKIPPED case
makes the run INCOMPLETE (exit 1), never PASS. Offline tests of the decoding
and the verdict: `tests/test_run_on_workspace.py` (in `lab-tests.yml`).

```bash
lab/monitoring/kusto-harness/run-on-workspace.py \
  --rules dormant-privileged-account-reactivation,keyvault-bulk-secret-read \
  --record lab/evidence/kusto/<UTC ts>-workspace
```

What it is and is not: the real Log Analytics engine and function library,
but **not a scheduled rule** (no rule created, no incident, no query period,
no entity mapping) and not real log data. Relative times resolve against the
local clock just before each query. Cases with watchlists, table variants or
shim variants are reported SKIPPED (run.sh only). A query body has a size
limit: a 1500-row case was refused ("Request entity too large"), which is why
the Key Vault baseline case uses short strings in its 1450 rows. The workspace
id is read at run time (no default; a failed lookup stops the run). Exit 0 =
all passed.

Run on 2026-11-06 (RAN · harness, on the Log Analytics query engine, E114): the two new rules, PASS
25/25. The same cases against the OLD Key Vault rule's query (from
Sentinel-Privileged-Access, `ResourceType == "VAULTS"` swapped for the
equivalent `ResourceProvider` filter because the harness table has no
`ResourceType`) failed 7 of 12: it merged two managed identities with no UPN
into one 24-read caller and fired, it counted 30 HTTP 404 "reads" and fired,
and it has no refused-read signal or the output columns the cases assert.
That comparison was a one-off check and has no record in the repo.

## Run record: `lab/evidence/kusto/<UTC ts>/`

| File | Content |
|---|---|
| `results.json` | Schema `contoso-kusto-harness/v1`: start / finish (UTC), `result` (`PASS`, `FAIL`, `PARTIAL-PASS` / `PARTIAL-FAIL` for `--rules` / `--case`, or `ENGINE-START-FAILED`), `fatal`, engine `.show version`, environment (python, docker, colima, image ref / digests / id / platform / build label), licence acceptance (`--accept-eula`), sha256 of every input (rules, cases, schemas, shims, harness, run.sh, itdr-cases.json), table columns, shims, probes, per-rule PASS / FAIL / NOT RUN with counts and xfail ids, per-case status / failures / first 5 rows, skipped imports |
| `run.log` | The run's output |
| `setup.kql` | The management commands sent before the first case (absent if the engine never started) |
| `rendered/<rule>__<sha12>.kql` | Every distinct rendered query that ran |
| `engine.log` | Last emulator log lines, only if the run failed or the engine never started |
| `guids.txt` | Every GUID-shaped value in the record that is neither a repeated-digit placeholder nor in the run's inputs, so was generated by the engine during the run (for example a request or activity id inside an engine message); `# none` when there is none. Each one listed needs a public-allowlist entry scoped to this record's folder, like the lab's other run records. The harness sends its own request ids as plain hex, never in GUID form |
| `SHA256SUMS` | Hashes of all of the above. Verify with `cd lab/evidence/kusto/<ts> && shasum -a 256 -c SHA256SUMS` |

The record contains no host name, user name or harness timings (an
`engine.log` keeps the emulator's own log-line format). All data is
synthetic: RFC 5737 / RFC 1918 addresses, repeated-digit placeholder object
ids, and the lab's fictional users.

## CODE NEEDED: applied 2026-10-20, passed on the engine 2026-10-21

These came up while writing the fixtures. All three are now applied to the
rule and its SPL twin (`lab/splunk/render-savedsearches.sh` re-rendered
`savedsearches.conf`), and their `xfail` markers are gone. On the first run
(`lab/evidence/kusto/20261021T001217Z/`) every case named below PASSED like
any other. That confirms the fixes against the engine and synthetic events,
not against a real tenant's records (CODE-NEEDED-3 still needs one). The SPL
twins have not run on Splunk. KqlLite, the offline interpreter, now treats
`to typeof(string)` as the cast Learn documents, so the offline suite catches
CODE-NEEDED-2 if it ever comes back.

**CODE-NEEDED-1 (applied): `sod-violation-granted.kql` never saw
PIM-for-Groups eligibility.** `IsElig` required `OperationName has "group"`.
Learn's audit-activity reference (PIM section; ms.date 2025-03-25, updated
2026-06-15) lists the eligibility events as `GroupManagement | Add eligible
member to role in PIM completed (permanent|timebound)` and `Remove eligible
member from role in PIM completed (...)`. Neither string contains the term
`group`, so making a nurse eligible for `PIM-EHR-AuditLog-Admins` (SOD-07),
which the header says "fires here, before any activation", never reached the
rule.

```diff
-    | extend IsElig = Category == "GroupManagement" and LoggedByService =~ "PIM"
-                      and OperationName has "eligible member" and OperationName has "group"
-                      and OperationName has "completed"
+    | extend IsElig = Category == "GroupManagement" and LoggedByService =~ "PIM"
+                      and OperationName has "eligible member" and OperationName has "completed"
```

The header's activity strings and the SPL twin (`like(... "%group%")`
dropped) changed with it. Cases: `sod07-pim-groups-eligibility-learn-string`
(positive), and two negatives that keep the looser match honest: the same
string under Category `RoleManagement` (`eligibility-string-under-rolemanagement`)
and a `requested`, not `completed`, eligibility
(`eligibility-requested-not-completed`).

**CODE-NEEDED-2 (applied): `app-credential-added.kql` dropped every new
federated identity credential.** `mv-apply o = OldSet to typeof(string)` and
`mv-apply n = NewSet to typeof(string)` were meant to "compare elements as
text". Learn (mv-expand, which mv-apply uses) says: "The operation of
applying type is cast-only and doesn't include parsing or type-conversion.
Array elements that don't conform with the declared type become null
values". A `FederatedIdentityCredentials` list holds objects, so every new
FIC became null, `Added` stayed empty, and `where AddedCount > 0` dropped the
row. KqlLite stringified on this cast, which is why the offline suite passed.
Case: imported row "positive: a new federated identity credential (GitHub
OIDC trust) is High". Probe: `mv-apply-typeof-string-on-objects`.

```diff
-| mv-apply o = OldSet to typeof(string) on (
-    summarize OldStrings = make_list(o)
+| mv-apply o = OldSet on (
+    summarize OldStrings = make_list(tostring(o))
   )
-| mv-apply n = NewSet to typeof(string) on (
-    where not(set_has_element(OldStrings, n))
-    | summarize Added      = make_list(n),
+| mv-apply n = NewSet on (
+    extend ns = tostring(n)
+    | where not(set_has_element(OldStrings, ns))
+    | summarize Added      = make_list(ns),
```

(the three `extract(..., n)` calls read `ns` too). Learn also says
property-bag key order is not preserved. If an unchanged FIC ever shows up as
"added", compare on `Issuer|Subject` instead of the whole object text. Probe:
`dynamic-key-order-in-tostring`. The SPL twin (`json_array_to_mv`, element
keys) was not affected and is unchanged. Offline: KqlLite's mv-apply cast is
now cast-only (two new self-tests in `Itdr.Tests.ps1`); the old rule text run
through it drops the FIC row at `where AddedCount > 0`, the fixed one returns
it as High.

**CODE-NEEDED-3 (applied; verify the record shape on the first lab
removal): `sod-violation-granted.kql` missed removals that name the group
only in `oldValue`.** `Candidates` read `displayName` / `newValue` only.
Entra writes a removed value in `oldValue` (`Group.DisplayName` old
`"All-Nurses"`, new null). With the `Group` target's `displayName` null as
well, the removal was not recognised, the stale holding stayed "Held", and a
later grant raised a false SoD alert. Case:
`held-then-removed-name-in-oldvalue-only`; the companion case
`held-then-removed-group-target-named` passed before and after.

```diff
-    | extend Candidates = extract_all(@'"(?:displayName|newValue)"\s*:\s*"(?:\\")?([^"\\]+)', tostring(TargetResources))
+    | extend Candidates = extract_all(@'"(?:displayName|newValue|oldValue)"\s*:\s*"(?:\\")?([^"\\]+)', tostring(TargetResources))
```

The SPL twin adds `TargetResources{}.modifiedProperties{}.oldValue`
(`MpOldValues`, quotes trimmed) to `Candidates`.

**What the first run's probes answered (2026-10-21; `results.json` `probes`):**

The probes are recorded, not asserted. Before the run, each open question
below named a way a rule could fail on a real engine. The answers:

- **`mv-apply-empty-array-summarize`: the row is kept.** The record whose
  array is `[]` came back with `n = 0` and `s = []`, so `mv-apply ... on
  (summarize ...)` still runs the subquery once. No rule loses a row over an
  empty array, and the fix drafted for that case (expand
  `iff(array_length(x) > 0, x, dynamic([null]))`) is not needed. The rules
  that rely on it (`app-credential-added`'s first credential,
  `role-assigned-outside-pim` with `modifiedProperties: []`,
  `blocked-country-signin`, `pim-activation-without-auth-context`) passed
  every case. `mv-apply-null-summarize`: a null array gives one record
  (`n = 1`).
- **`fuzzy-union-unresolved-column` / `fuzzy-union-missing-function`: the
  leg is dropped, not an error.** Both returned the other leg's row. So
  "empty watchlist = every source alerts" holds on the engine for
  `dc-logon-outside-operator-allowlist`, and its cases
  `watchlist-no-items-base-columns` and `watchlist-function-absent` passed.
  Sentinel's own `_GetWatchlist` was not exercised (it is shimmed here).
- **`negative-array-index`: not answered; the probe itself is wrong.** The
  engine refused it with `SYN0002`: `last` is a reserved name and has to be
  written `['last']`. The probe query needs a different column name; the
  rule does not use that name. Indirectly, `ad-privileged-group-change`,
  which decides the group with `split(GroupSid, "-")[-1]`, passed all 9 of
  its cases on the engine, including the RID 512 and 519 positives and the
  RID 513 and RID 1200 negatives.
- **`dynamic-key-order-in-tostring`: keys came back in the order given**
  (`oldValue`, `newValue`, `displayName` for that input). The engine did not
  reorder this entry, so the `Group\.ObjectID"[^}]*?newValue` regexes in
  `pim-group-member-added-outside-pim` and `auth-method-changed-by-admin`
  work when the source record lists `displayName` before `newValue`, as
  every synthetic record here does. Whether real `AuditLogs` records always
  do is a tenant-time check (Learn says property-bag order is not
  preserved).

## Checked without the engine (2026-10-20; not a run record)

First pass (harness build):

- ShellCheck 0.11.0 on `run.sh`: clean at every severity (`-S style`).
- Ruff 0.15.14 on `harness.py` (rules E, F, W, B; py39; line length 140):
  clean. At Ruff's default line length (88) only E501 fires.
  `python3 -m py_compile`: OK.
- `harness.py check`: 221 cases over 22 rules, all valid.
- `harness.py render --out DIR` wrote every management command and query a
  run would send. They were reviewed by hand for KQL syntax, column order and
  types.
- `run.sh` without `--accept-eula`, and with only `ACCEPT_EULA=Y` in the
  environment, exits 2 before any Docker call. `harness.py run` without
  `--accept-eula-recorded` refuses as well.
- The driver was exercised end to end against a stub HTTP endpoint that
  answers the v1 REST shape. No KQL ran and no Microsoft software was
  involved. The stub output was discarded and is not evidence.

Second pass (CODE NEEDED applied, placeholder ids, start-failure record;
still no engine):

- `harness.py check`: 277 cases over 22 rules, all valid, no `xfail` left.
  `harness.py render`: 223 case files.
- Ruff 0.15.14 (same rules) and `py_compile` on `harness.py`: clean.
  ShellCheck 0.11.0 `-S style` on `run.sh`: clean. Both refusal paths still
  exit 2.
- `harness.py run --engine-start-failed` with no engine (and no `docker` on
  `PATH`) wrote `ENGINE-START-FAILED`, 22 rules `NOT RUN`, no query sent;
  `harness.py guids` on that record listed one injected random GUID and
  nothing else. Both outputs were discarded and are not evidence.
- ITDR Pester suite 284 passed, 0 failed (282 before, plus the two KqlLite
  cast self-tests); `09-SoD-Report.Tests.ps1` 35 passed;
  `render-savedsearches.sh --check` OK.
- The public GUID gate's matching logic over `lab/kql`, `lab/splunk`,
  `lab/monitoring` and `lab/scripts/monitoring`: no unexpected id.

## Files

| File | Role |
|---|---|
| `run.sh` | The one command: licence gate, preflight, container lifecycle, publish (pass, fail or engine-start failure) |
| `harness.py` | Driver (stdlib only): `check`, `render`, `wait`, `run`, `guids` |
| `schemas.json` | Learn column lists, VaultCheckout_CL variants, watchlist stores |
| `shims.kql` | `_GetWatchlist` shim and its two edge variants |
| `cases/<rule>.json` | Hand-written cases (17 rules) |
| `run-on-workspace.py` | The same cases on the Log Analytics query engine, read-only, through the lab operator (no emulator) |
| `cases/_engine-probes.json` | Engine-semantics probes |
| `cases/_itdr-import-overrides.json` | `xfail` marks on imported fixture rows (none since CODE-NEEDED-2 was applied) |
