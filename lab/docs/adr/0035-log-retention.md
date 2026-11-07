# ADR 0035: Log retention - 30 days in the lab, years in production

- **Status:** DESIGNED. The lab keeps 30 days (`envs/dev/main.tf`, `retention_in_days = 30`). The production values below are not built.
- **Date:** 2026-11-07
- **Risk owner:** Identity platform owner (in the lab, the repository maintainer)
- **Next review:** 2027-02-07, or when the lab gets a paid subscription
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

- The Log Analytics workspace `loga-idlab` keeps sign-in, audit and
  security events for 30 days. That is a cost choice for a trial tenant.
- An attacker often stays hidden for longer than 30 days. A breach found
  on day 45 has no sign-in or audit logs from its start.
- HIPAA requires audit controls (45 CFR 164.312(b)). It requires the
  security documentation to be kept for 6 years (164.316(b)(2)(i)). Many
  hospitals keep audit logs for the same 6 years, as policy.
- The evidence store already keeps filed evidence for 6 years
  (`envs/dev/variables.tf`). The raw logs do not.

## Options considered

1. **Keep 30 days everywhere.** Cheapest. Fails an investigation of any
   older breach. Rejected for production.
2. **Keep everything interactive for years.** Simple, and the most
   expensive by far. Rejected.
3. **Tiers (chosen for production):** a short interactive tier for
   hunting and alerts, a long, cheap tier for investigations, and an
   immutable export for audit.

## Decision

**Lab:** 30 days. Said as a cost choice wherever retention comes up.

**Production:**

| Data | Interactive (analytics) | Long-term (archive or data lake tier) | Immutable export |
|---|---|---|---|
| SigninLogs, AuditLogs, AADNonInteractiveUserSignInLogs, SecurityEvent (DCs), AzureActivity | 90 days | 2 years in total | 6 years, to a locked storage account |
| High-volume, low-value tables (for example non-interactive sign-ins) | 30 days, or a cheaper log plan | 1 year | not needed |

- Microsoft Sentinel includes 90 days of analytics retention at no extra
  retention charge. verify: current Sentinel pricing page.
- Long-term retention is set per table. The total retention can be up to
  12 years. verify: Azure Monitor "Manage data retention in a Log
  Analytics workspace".
- The immutable export goes to a storage account in a separate
  subscription, with a locked time-based retention policy and a delete
  lock. The identity team has no Owner role there. That is the same
  pattern as the production evidence store.

## Consequences

- **Cost.** Long-term retention costs far less per GB than analytics
  retention. The real number depends on log volume. Measure the GB per user
  per day from the workspace `Usage` table before you quote a figure.
- **Search speed.** Archived data needs a search job or a restore before
  you can query it. That takes minutes to hours.
- **Detections do not change.** Rules look back 14 days at most.

## Revisit trigger

- The lab moves to a paid subscription.
- An investigation needs data older than the interactive tier.
- HIPAA guidance or the hospital's records policy changes.

## Sources

- 45 CFR 164.312(b) (audit controls) and 164.316(b)(2)(i) (6-year retention of documentation). verify: eCFR.
