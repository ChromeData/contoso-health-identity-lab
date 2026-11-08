# AD FS on DC01: README steps 1-6 (2026-11-07)

Capture log **E140** (the run) and **E141** (the Connect Health token flow, dry run).
Everything ran as the lab operator (`lab/scripts/operator/op`), through managed
run commands (`run-on-dc.py`, secrets as protected parameters). No person signed in.

| File | What it shows |
|---|---|
| `01-preflight-start-dc01.txt` | `preflight.sh` started DC01 (it was deallocated) and printed READY |
| `03-install-adfs.log` | The lab-shortcut line; role, DNS, TLS cert, `Install-AdfsFarm` (gMSA, WID); `gmsaHasSeAudit: false` |
| `03b-audit-right-grant-first-try.log` | The grant worked, but the read-back check failed: `secedit` wrote the gMSA by **name** (`gmsa-adfs$`), the check looked for its SID. The check now accepts both |
| `03b-audit-right-grant-readback.log` | Re-run: `holds: true`; the Default Domain Controllers Policy line before and after |
| `04-relying-party.log` | Relying party `urn:contoso:claims-viewer`, 5 rules, two groups, the pilot user |
| `05a-agent-install-first-try-1603.log` | MSI exit 1603: the quiet install needs `AdfsMonitoringEnabled=1` (MSI log: "Please select at least one service") |
| `05b-agent-install.log` | Agent installed (service `AzureADConnectHealthAgent`, Stopped until registered) |
| `05c-agent-cmdlet-syntax.txt` | Agent 4.5.2487.0: `Register-MicrosoftEntraConnectHealthAgent` parameter sets, incl. `-AadToken` and `-Credential`; no service-principal or certificate set |
| `05d-agent-auth-probe-nonexistent-user.txt` | `-Credential` with a user that does not exist (nothing can register): the agent's log names client id `cf6d7e68-...`, scope `https://management.core.windows.net/.default` and the ARM endpoint it registers through. The log file is appended to, so the first lines are from the first probe (02:06Z) |
| `05e-token-flow-dry-run-adm-presenter.json` | `get-agent-token.mjs --dry-run` as adm-presenter (passkey): a token for the agent's client, `amr` = fido + mfa. Not stored, no registration attempted (adm-presenter has no registration role) |
| `06-before-adfs.json` | The "before" claims from 5 real AD FS sign-ins of the pilot user; `signatureValid: true` |
| `06b-adfs-audit-events.txt` | AD FS audit events in DC01's Security log (1200 and 1202 present: step 3b works) |
| `07-install-rerun-idempotent.log` | Install re-run with the fixed checks: skips every step, `gmsaHasSeAudit: true`, `auditLevel: Verbose` |

Not done here: Connect Health registration (needs the flag-on PR, ADR 0031), the
migration report (needs the registered agent), steps 7-10.
