# 12 · Proof: before and after

Draft: written before this stage first ran in the lab tenant. Steps marked
(verify) are checked during the first build.

**What you show:** the numbers that prove the lab changed something, sealed so
nobody can quietly edit them afterwards.

**Whisperglass:** *Contoso 09 · Proof*, then *Contoso 11 · Drift, Okta,
reporting*.

**Starts from:** every earlier run sheet done. The "before" numbers already
exist: the KPI baseline in `lab/evidence/kpis/` and the "before" assessment in
`lab/evidence/assessments/`.

## Steps

| # | You do | Look at | You should see |
|---|---|---|---|
| | **Part A · The "after" numbers** | | |
| 1 | Read the Map part of *Contoso 09*. | the lab map | the proof station |
| 2 | `pwsh lab/scripts/powershell/08-Measure-KPIs.ps1 -Label after -CompareTo lab/evidence/kpis/<baseline file>.json` (the baseline is the oldest `.json` in that folder) | the terminal | a before/after table: standing vs eligible admins, % phishing-resistant, Conditional Access coverage, review completion, stale accounts, HR-to-disable minutes, non-human credential findings |
| 3 | `pwsh lab/scripts/powershell/New-KpiOnePager.ps1 -CompareTo lab/evidence/kpis/<baseline file>.json` | the terminal, then the file it prints | the one-page summary of those numbers |
| | **Part B · The "after" assessment** | | |
| 4 | Run the Zero Trust assessment the same way as the "before" run (it was run on its own, then imported) | the terminal | a results folder (verify: same workaround as the "before" run) |
| 5 | `pwsh lab/scripts/powershell/Invoke-BaselineAssessment.ps1 -Phase after -ZeroTrustResultsPath <that folder>` | the terminal | the before/after difference per control |
| 6 | Point at what moved and what did not | the summary | expected to stay failing: the phishing-resistant pilot (CA008) and the documented gaps. Record what the tool says, not what you hoped. |
| | **Part C · Seal it** | | |
| 7 | `pwsh lab/scripts/powershell/Export-EvidencePack.ps1` | the terminal | a pack in `lab/evidence/out/` with a `manifest.json`; every file listed with its hash |
| 8 | Upload the pack to the locked store (the exact `az storage blob upload-batch ... --overwrite false` line is in the evidence plan, row E56) | the terminal | every file uploaded; a second upload of the same file is refused |
| 9 | Write the manifest's SHA-256 into `lab/evidence/capture-log.csv`, then open a PR with the public files | VS Code, then GitHub | one new capture-log row; the PR's checks green |
| | **Part D · Drift and reporting** | | |
| 10 | Switch to *Contoso 11*. `pwsh lab/scripts/powershell/Export-IdentityConfig.ps1 -Public` | the terminal | a snapshot with every id hashed |
| 11 | `pwsh lab/scripts/powershell/Compare-IdentityConfig.ps1 -SnapshotPath <that snapshot>` | the terminal | no findings: the tenant matches the code |
| 12 | `turn open actions`, open the **config-drift** workflow, click **Run workflow** (verify) | GitHub Actions | a green run: "no drift" |
| 13 | Read the Proof part | | |

## Say this, in your own words

- "Before" was measured before any premium setting existed. "After" uses the
  same scripts, so the difference is the lab's work, not a change of ruler.
- The evidence store is write-once: a file can be added, never changed or
  deleted. The pack's hash in the capture log lets anyone check the private
  pack was not edited.
- Some controls still fail, on purpose, and each one has a written reason. A
  report with no failures would not be believable.
- Drift is checked every night: if someone changes the tenant by hand, the
  check opens an issue against the code.

## If something goes wrong

| What you see | Do this |
|---|---|
| The KPI script asks for permissions | Sign in when the browser opens and approve on your phone. |
| The Zero Trust tool fails with a "PrivateData" or module error | Run it on its own and import the results with `-ZeroTrustResultsPath`, as for the "before" run. |
| ScubaGear will not run | It needs Windows. Run it on a temporary Windows VM and import with `-ScubaResultsPath` (verify). |
| The upload says the blob already exists | Expected for a re-run: the store never overwrites. Upload to a new dated folder. |
| Drift findings appear | Read each one: either the code is behind (fix by PR) or someone changed the portal (revert by PR). |

## Do it again

Everything here only reads the tenant or adds new files: run it again any
time, and it writes new dated files next to the old ones.

## Not in this sheet

Locking the evidence store for good (row E57) is a one-way switch. It is a
decision for the end of the lab, made on purpose, not a step to film.
