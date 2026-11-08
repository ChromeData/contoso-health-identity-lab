# Correction (added 2026-11-07, after review of PR #237)

This note is not part of the record. The record's files, `README.md` and
`SHA256SUMS` stay as they were written. This file is outside `SHA256SUMS`
on purpose, so the record still verifies (`shasum -a 256 -c SHA256SUMS`).

## What the record overclaims

Three places say that AD FS wrote its sign-in audits (events 1200 and 1202)
to DC01's Security log:

- `README.md` (this folder), row `06b-adfs-audit-events.txt`: "1200 and 1202
  present: step 3b works".
- Capture log row **E140**: "AD FS wrote events 1200 x5 and 1202 x5".
- `lab/adfs/README.md`, table "Measured on DC01", row 6 (now corrected there).

The file they cite does not show that. `06b-adfs-audit-events.txt` holds:

```
"adfsAuditEventsLast20Min":  0,
"byId":  ""
```

That is: in the 20 minutes before that query, the query found **no** AD FS
audit events. No other file in this folder counts events 1200 or 1202.

## What the record does prove

- Step 3b: the gMSA holds "Generate security audits" on DC01
  (`03b-audit-right-grant-readback.log`, `holds: true`, read with `secedit`),
  and AD FS auditing is set to Verbose (`07-install-rerun-idempotent.log`).
- Step 6: 5 real AD FS sign-ins of the pilot user and signed "before" claims
  (`06-before-adfs.json`, `signIns: 5`, `signatureValid: true`).

## What it does not prove

It does **not** prove that AD FS audit events 1200 / 1202 reach the Security
log. The record does not show why the count was 0. (It may be the time
window of the query, or auditing may not work yet.) A new capture must count
the events after a sign-in before anyone says auditing works. Connect Health
and `19-Remove-Adfs.ps1`'s quiet-period gate both depend on these events.
