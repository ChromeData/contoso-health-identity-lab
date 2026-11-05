# Containment drill, armed and cleaned up by script (RAN · tenant, 2026-11-05)

`lab/scripts/demo/containment-drill.sh` run once end to end as the lab
operator, for the presenter cockpit's on-camera step (piece 7: an approver
opens the card in Contoso SOC and presses Contain). Capture-log row E41b.

| Step | Result |
|---|---|
| `arm` (12:53Z) | Throwaway cloud-only `itdr-drill-20261105` (no licence, password discarded), ONE High incident (#51) from a temporary rule naming only that user, rule disabled, `pb-identity-contain` started, card waiting in Identity-SecOps after 2 min 08 s. Last line `DRILL_INCIDENT=51` |
| `arm` again | `already armed: incident #51`, nothing created (idempotent) |
| Card | test-user-a (a listed approver) pressed **Contain** through `answer-teams-card.mjs`: revoke 200, confirmCompromised 204, disable 204, the user disabled; Entra audit rows by `pb-identity-contain` |
| `arm` after that | refused, exit 4: the drill user is disabled, disarm first |
| `disarm` (12:57Z) | User deleted AND purged (audit: Hard Delete user), temporary rule deleted, incident #51 closed BenignPositive with a comment carrying the containment outcome, read-back clean |
| `disarm` again | clean, nothing to do (idempotent) |

Fixed on the way (`drill.json` `foundOnTheWay`): wait for the incident's
Account entity before starting the playbook; retry a brand-new user's 404;
a fresh rule id per arm (Sentinel refuses a recently deleted id); read a
waiting card's subject from the run trigger's entities. The owner's account
was not used.

What it does NOT prove: the owner pressing the card on camera (not run by
design); the refusal while a card waits about a real account (offline test
`lab/scripts/demo/tests/containment-drill.test.sh` covers it; no such card
was waiting during this run).
