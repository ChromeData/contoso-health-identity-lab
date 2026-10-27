# Baseline assessment - 20261027T033239Z (before)

Generated (UTC): 2026-10-27T03:32:39.6572470Z by Invoke-BaselineAssessment.ps1 1.0.0.
Source: a run against the tenant (every tool recorded the same tenant id; the id is not published).
Public-safe: no tenant id, domain, user, IP or policy detail text. The raw reports are private,
in the WORM evidence store; the SHA-256 of every raw file is in summary.json (rawManifest).

summary.json SHA-256: `d67dc2259b6cf287d8d07e5f9f516ffa173337ba3d93f2440470e34c9aaf140f`  
Raw manifest.json SHA-256: `842ab702fcab45c1f9e6453c5ee741e257274bbe8e34a4229f945813d6cc9ac2`  
WORM: skipped (-SkipUpload) (0 uploaded, 0 failed) under `evidence/assessments/20261027T033239Z-before/`

## Tools

| Tool | Status | Version | Note |
|---|---|---|---|
| scubaGear | not-selected |  |  |
| zeroTrust | ok | 3.1.0 |  |

## Zero Trust Assessment (pillar: Identity)

Tests passed: **44 / 95** (46.3%). High-risk tests not passed: 28.

Verify the private copy: download the run folder from the WORM container, then
`shasum -a 256 -c SHA256SUMS` inside it, and compare manifest.json's hash with the one above.

