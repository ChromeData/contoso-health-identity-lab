# ITDR playbook drill, 2026-11-05 (RAN · tenant)

Both Sentinel playbooks, deployed in `rg-identity-lab` by
`lab/scripts/monitoring/Deploy-Playbook.ps1` and
`Deploy-ContainmentPlaybook.ps1`, run once each against a drill incident in
the lab tenant. Capture-log rows E40, E40a and E41.

| Step | What ran | Result |
|---|---|---|
| Set-up | A temporary analytics rule raised ONE High incident (#35) naming a throwaway cloud-only user (`itdr-drill-20261105`, no licence, nobody held its password) | Incident #35 with that Account entity |
| Notify (E40a) | `pb-identity-notify`, started from the incident (Sentinel `incidents/runPlaybook`) | Card in **Contoso SOC > Identity-SecOps** (Teams 201, posted by the Workflows bot for `svc-soc-automation`), ServiceNow **INC0010001** opened with `correlation_id` = the incident name, ticket number commented on the incident |
| Contain, run 1 | Approval card; **test-user-b** (team member, NOT in `ITDR-Containment-Approvers`) answered *Contain* | IGNORED: "the responder is not on the containment approver list"; no Graph write |
| Contain, run 2 (deny) | **test-user-a** (listed approver) answered *Reject* | REJECTED, no action; the user stayed enabled with the same session timestamp |
| Contain, run 3 (approve) | **test-user-a** answered *Contain* | revokeSignInSessions 200, confirmCompromised 204, disable 204; Entra audit log: `Update StsRefreshTokenValidFrom Timestamp`, `ConfirmAccountCompromised`, `Disable account` by `pb-identity-contain` |
| Records | Every run | Outcome commented on incident #35 and added as a work note on INC0010001 (the notify ticket, found by correlation id) |
| Clean-up | After the drill | Throwaway user deleted and purged, temporary rule deleted, incident #35 closed (BenignPositive) |

Files: `drill.json` (run ids, action statuses and HTTP codes, the responder
UPN and object id Teams returned, the incident comments, the Entra audit rows,
the ServiceNow work notes, the Teams connection status, the managed identity's
role counts), `approval-card.png` (the card before any answer, as test-user-a
saw it), `notify-card-and-decided-cards.png` (the notify card and the
answered cards rewritten to "Decision recorded"), `SHA256SUMS`.

Found on the way (each is in `drill.json` `notes`):

- The disable answered **204 with no directory role** on the managed
  identity: the Graph app roles alone were enough for a non-admin cloud-only
  user. ADR 0017 and R16 were corrected; the opt-in Authentication
  Administrator role stays off for good.
- The first containment run failed before posting (Logic Apps refuses a
  `method` on an ApiConnectionWebhook action) and logged NO DECISION, no
  action: fail closed. The template was fixed and redeployed first.
- `revokeSignInSessions` answers 200 (Graph v1.0), not 204.

What it does NOT prove:

- The automation rules: these runs were started from the incident. The rules
  (`modules/monitoring`, notify on every incident, containment on High ITDR
  incidents) exist once the apply has run with `TF_SENTINEL_PLAYBOOK_ID`,
  `TF_CONTAINMENT_PLAYBOOK_ID` and `enable_itdr_containment = true`.
- Break-glass refusal, self-approval refusal, the RMAU escalation, a synced
  account (AD flag + `Invoke-AdContainment.ps1`) and any admin target: not run.
- CA006 at the subject's next sign-in: the throwaway user never signed in.
- People: both answers came from lab test users signed in headless
  (`answer-teams-card.mjs`, staff sign-in toolkit), not from an on-call rota.
