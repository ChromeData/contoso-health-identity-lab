# ADR 0022: Okta coexistence built as code (acquired clinic, Okta Integrator Free)

- **Status:** Accepted (lab). BUILT: the Entra side in `modules/apps/okta.tf` behind `enable_okta_federation` (on) and the Okta side as a separate, human-applied root `lab/terraform/okta/`, both with mocked `terraform test` suites. Applied against the lab tenant and an Okta Integrator Free org (E58). The migration runbook (`okta-migration-runbook.md`) stays the operating document; this ADR records why Phase 1 is now code and where its limits are. **RAN · tenant:** E58.
- **Date:** 2026-10-26
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital that has acquired a clinic running Okta). Not a real employer.

## Context

The scenario's acquisition brings a second identity plane. The runbook
(DESIGNED since 2026-10-20) settled the pattern: Okta trusts Entra as an
OpenID Connect identity provider, a routing rule sends the clinic's login
domain to Entra, Conditional Access applies at Entra, and the Okta apps move
one at a time with a rollback each. Everything in Phase 1 was a sequence of
portal clicks in two admin consoles, which is exactly the kind of change the
rest of this platform refuses to make by hand (ADR 0004).

Okta is also the second most-named product in senior identity postings
read in October 2026 (10 of 24), usually as "Okta or Entra". The one
hands-on prescription the career material the author follows makes for IAM
is "federate Okta and Entra end to end and be able to talk about it". The
free Okta Integrator org makes that possible at lab scale.

## Options considered

| Question | Chosen | Rejected, and why |
|---|---|---|
| Direction of trust during coexistence | **Okta trusts Entra** (Entra is the IdP; Okta keeps serving apps that have not moved) | **Entra trusts Okta:** clinic users would stay Okta-mastered, HR would not be their source, and Conditional Access would not see the sign-in. **Big-bang cutover:** day-one lockout risk for a clinic that cannot stop seeing patients |
| Where the Okta configuration lives | **A separate Terraform root** (`lab/terraform/okta/`, provider `okta/okta`), applied by a human after the Entra app exists, like `lab/terraform/aws/` | **Inside `envs/dev`:** the CI identities are Entra and Azure only; adding an Okta API token to the pipeline widens the credential surface for one lab org. **Portal only:** not reviewable, not repeatable |
| The client secret Okta needs | **Entered once by a human into Okta** (the runbook's step), and supplied to the Okta root as a sensitive variable at apply time. Terraform creates the Entra app registration but not the secret in the default path | **Terraform-managed secret in state:** the PLAN identity can read state (`lab/pipelines/README.md` §5). A bounded Key Vault path is offered as an option where the vault module's inputs allow it |
| Routing | **One IdP discovery rule for the clinic's login domain, with the default Okta rule kept as fallback** | **Route everyone:** Okta-only users (no HR record, Phase 0) would be locked out |

## Decision

- Phase 1 of the runbook ("Okta trusts Entra") is code: the Entra app
  registration, service principal, assignment of `App-Okta-Federation-Users`
  and redirect URI in `modules/apps/okta.tf`; the Microsoft IdP, the routing
  rule, the `Clinic-Staff` group and one legacy app in `lab/terraform/okta/`.
- The rollback stays the runbook's: disable the routing rule. In code that
  is one variable, applied by a human, and it is the first thing the validate
  step rehearses.
- Phases 2 onward (moving apps, Okta-only users, decommission) remain
  runbook steps until a second app exists to move; each app that moves is
  its own PR.
- The scope stays small on purpose: one org, 1 to 3 apps, a handful of
  users. Integrator Free is the real product with limits; what production
  adds is marked **[prod]** in the runbook.

## Consequences

- A third provider (`okta/okta`) enters the repository with its own lock
  file and its own API token, kept in the operator Mac's Keychain and used
  only for applies outside CI. The token is never in CI. "Human-applied"
  means applied outside CI from the operator workstation. From 2026-11-05 to
  2026-11-08, AI helpers running as the operator also ran thirteen of these
  applies from unmerged branches, six of them of `okta/` (the last: three
  targeted applies by `lab/okta-migration/cutover.mjs` in the wave-1
  cut-over, E184, 2026-11-08 22:10Z-22:11Z), and the operator ran one more
  `envs/bootstrap` apply at the owner's direction (#282, 23:38Z). The record
  and how each was reconciled: `lab/docs/change-record-outside-the-gate.md`.
  From then on the owner starts or approves each one.
- `Clinic-Staff` membership in Okta is a stand-in for an HR-driven group;
  the decision that clinic users come from HR → AD → Cloud Sync, not from an
  Okta export, is unchanged.
- The Entra app registration is one more non-human identity and is
  inventoried like the others (`06-NHI-Inventory.ps1`, ADR 0018).

## How it is measured

| Measure | Source | Target |
|---|---|---|
| Clinic sign-ins reaching Okta through Entra | Entra sign-in logs for app `okta-clinic-idp`; Okta System Log IdP events | 100% of routed users |
| Sign-ins blocked or challenged by CA at Entra for Okta-bound users | Entra sign-in logs, CA result | Reported, not targeted |
| Rollback time | Timed in the validate step | ≤ 5 minutes |

Results: fill after running. Nothing has been measured.

## Revisit trigger

- The clinic's apps are all moved: the Okta root is destroyed and this ADR
  is marked superseded by the decommission record.
- Okta changes the Integrator Free terms or retires the OIDC IdP
  configuration this relies on (verify: at apply time).

## Evidence

- `lab/terraform/modules/apps/okta.tf`, `tests/okta.tftest.hcl`
- `lab/terraform/okta/` (root, README, tests)
- `lab/terraform/envs/dev/lab.tfvars` (`enable_okta_federation = false`)
- `lab/docs/okta-migration-runbook.md` (Phase 1 now points at the code)

## Sources

- Okta developer docs, "Add Microsoft as an identity provider" and
  "IdP discovery routing rules" (verify: current field names in the
  `okta_idp_oidc` and `okta_policy_rule_idp_discovery` resources).
- Microsoft Learn, "Tutorial: Migrate Okta federation to Microsoft Entra
  authentication" (cited in the lab map's Apps station).
