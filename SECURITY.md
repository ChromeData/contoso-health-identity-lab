# Security

This is a **portfolio lab**. It contains no real people, no patient data, and no
credentials.

## Design rules this repo follows

- **No stored credentials in CI.** GitHub Actions authenticates to Entra ID and Azure
  with OIDC workload identity federation. The only GitHub *secrets* are privacy
  masks (the operator's IP allow-list and alert email), not credentials.
- **No pull request can widen the pipeline's own access.** Its identities and
  their RBAC live in `lab/terraform/envs/bootstrap`, which a human applies
  locally. That is change control, not a privilege boundary: the apply
  identity is effectively Tier 0 and sits behind a reviewer-gated environment.
- **Secret scanning gates every PR** (TruffleHog), and every third-party action is
  pinned to a full commit SHA.
- **Generated credentials and tenant data never enter git.** `.env` files,
  `.secrets/`, Terraform state, evidence exports and the real variable files
  (`terraform.tfvars`, `*.auto.tfvars`) are gitignored. The committed
  `lab.tfvars` holds only policy knobs (staging flags, Conditional Access
  settings), no tenant identifiers.

## Reporting a problem

If you find something that looks like a real credential, personal data, or a
security flaw in the patterns shown here, please report it privately: the
repository's **Security & quality** tab → **Report a vulnerability**. Don't
open a public issue with details. If that button isn't shown, open an issue
that only asks for a security contact.

## Using this code

It's written for a disposable lab tenant. Read
[`lab/docs/STAND-INS.md`](lab/docs/STAND-INS.md) and the `verify:` markers
before adapting anything for production, and never point it at a tenant you
can't afford to break. The break-glass and report-only-first patterns exist
because Conditional Access mistakes lock people out.
