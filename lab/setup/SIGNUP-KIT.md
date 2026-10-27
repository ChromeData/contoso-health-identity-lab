# Sign-up kit: the only part a person has to do

**Easiest way:** let the assistant fill the forms and only hand you the CAPTCHA, the
SMS code and the card: `cd lab/setup/signup-assist && npm run setup && cp profile.example.json profile.json`
(edit it), then `npm run microsoft`, `npm run azure`, `npm run okta`, `npm run aws`, `npm run servicenow`.

Six sign-ups, about 20 minutes, in this order. Every value you'll be asked for
is pre-chosen below so you can paste it. When each one finishes, copy the
items under **Hand back** into `lab/setup/handback.env` (copy it from
`handback.env.example`; it is gitignored). Then run
`lab/setup/after-signup.sh` and everything else is done for you.

Use ONE email for all Microsoft sign-ups, and the same browser profile.

> **Create the tenant two days before you need the DC.** A brand-new Entra
> tenant is capped at **600 directory objects for its first 48 hours**
> (Microsoft Learn, *Service limits and restrictions*). The M365 E5 trial alone
> installs about 400 first-party service principals, so the cap is hit by the
> lab's Day-2 groups, and anything that creates an object after that (the
> DC01 managed identity, SSO apps, synced users) fails with
> `The directory object quota limit for the Tenant has been exceeded`. The cap
> lifts automatically; check `GET /beta/organization?$select=directorySizeQuota`
> and `createdDateTime`. A verified custom domain sets the post-cap quota to
> 300,000 (50,000 without one) but does not lift the cap early.

> **Custom domain.** The AD forest is `corp.<your-domain>` and the UPN suffix is
> `<your-domain>` (`lab/scripts/dc/README.md`), so buy one before `enable_dc`
> (any registrar, about $11/yr; Azure App Service Domains refuse free-trial
> subscriptions). Add it in Entra (`POST /domains`), publish the `MS=` TXT
> record, `POST /domains/{id}/verify`, and hand back `CUSTOM_DOMAIN=`.

| # | Service | Link | Cost | Card? |
|---|---|---|---|---|
| 1 | Microsoft 365 E5 trial (gives you the Entra tenant, Entra ID P2, Intune) | https://www.microsoft.com/en-us/microsoft-365/enterprise/e5 → *Try free for one month* | free 30 days, 25 users | yes (cancel before day 30) |
| 2 | Entra ID Governance trial (inside the tenant from 1) | https://admin.microsoft.com → Billing → Purchase services → search *Entra ID Governance* → *Step-Up for Microsoft Entra ID P2* → Start free trial | free 30 days | no |
| 3 | Azure subscription | https://azure.microsoft.com/free | $200 credit, 30 days, spending limit on | yes ($1 hold) |
| 4 | Okta Integrator Free org | https://developer.okta.com/signup/ → Workforce Identity → Integrator Free Plan | free, no expiry | no |
| 5 | AWS account | https://aws.amazon.com/free → **Free plan** | $100 credit, 6 months, no charges on Free plan | payment method asked |
| 6 | ServiceNow developer instance | https://developer.servicenow.com → sign up → *Request Instance* | free | no |

## 1. Microsoft 365 E5 trial

Values to enter:

| Field | Value |
|---|---|
| Company name | `Contoso Health Lab` |
| Company size | 25 people |
| Country | United States |
| Username (your admin) | `admin` |
| Domain name | `contosohealthlab` + four digits you choose, e.g. `contosohealthlab7f3a` → the tenant becomes `contosohealthlab7f3a.onmicrosoft.com` |
| Password | a long one you store in your password manager. This is the tenant creator account; it becomes the **build account** (ADR 0005) and later gets converted to PIM-eligible |

When it finishes you land in https://admin.microsoft.com.

**Hand back:** `ONMICROSOFT_DOMAIN=contosohealthlab7f3a.onmicrosoft.com`,
`ADMIN_UPN=admin@contosohealthlab7f3a.onmicrosoft.com`, `LAB_SUFFIX=7f3a`.

Also do now, same browser: https://admin.microsoft.com → Billing → Your
products → confirm *Microsoft 365 E5* shows 25 licences, and assign one to
`admin`.

## 2. Entra ID Governance trial

In https://admin.microsoft.com: Billing → Purchase services → search
"Microsoft Entra ID Governance" → open **Step-Up for Microsoft Entra ID P2**
→ **Start free trial** → confirm. (E5 already includes P2, which is why you
pick the step-up.) Nothing to hand back; the script checks the licence.

## 3. Azure subscription

https://azure.microsoft.com/free → *Start free* → **sign in with the admin@
account from step 1** (not a personal account). Identity verification by phone
and card; the spending limit is on by default.

**Hand back:** `AZURE_SUBSCRIPTION_ID=` (Azure portal → Subscriptions → the
GUID). The tenant id is read by the script.

## 4. Okta Integrator Free

https://developer.okta.com/signup/ → **Workforce Identity → Integrator Free
Plan**. Values:

| Field | Value |
|---|---|
| Work email | your email (any) |
| Country | United States |
| Company | `Contoso Health Lab` |

Activate from the email. Your org URL looks like
`https://integrator-1234567.okta.com`. Then in the Okta admin console:
Security → API → Tokens → **Create token** named `terraform` → copy it once.

**Hand back:** `OKTA_ORG_NAME=integrator-1234567`, `OKTA_BASE_URL=okta.com`,
and export the token in your shell before running the script:
`export OKTA_API_TOKEN=...` (never in a file).

## 5. AWS

https://aws.amazon.com/free → *Create a free account* → choose the **Free
plan**. Then in the AWS console: IAM Identity Center → **Enable** (region
`us-east-1`) → note the region and the account id (top-right).

For the script: install nothing, just create an SSO profile when asked:
`aws configure sso --profile idlab-admin` (start URL = the Identity Center
"AWS access portal URL"). The script runs `aws sso login` for you.

**Hand back:** `AWS_ACCOUNT_ID=123456789012`, `AWS_REGION=us-east-1`,
`AWS_ACCESS_PORTAL_URL=https://d-xxxxxxxxxx.awsapps.com/start`.

## 6. ServiceNow developer instance

https://developer.servicenow.com → *Sign up* → verify email → sign in →
**Request Instance** → latest release. You get `https://devNNNNNN.service-now.com`
and an admin password (change it when asked).

**Hand back:** `SERVICENOW_INSTANCE_URL=https://devNNNNNN.service-now.com`
(no trailing slash).

## Also hand back

- `OPERATOR_IP=` your public IPv4 (`curl -s https://ifconfig.me`): the Key
  Vault firewall and the DC's network rule are locked to it.
- `ALERT_EMAIL=` an address for alerts (your own is fine).
- `GITHUB_OWNER=ChromeData`, `GITHUB_REPO=contoso-health-identity-lab`.

Then:

```bash
cp lab/setup/handback.env.example lab/setup/handback.env   # fill it in
export OKTA_API_TOKEN=...                                   # from step 4
lab/setup/after-signup.sh            # dry run: shows every step, changes nothing
lab/setup/after-signup.sh --yes      # does it
```

## Optional: Azure OpenAI for the PR AI review

No new sign-up: it is a resource inside the Azure subscription from step 3. The
`ai-review.yml` job is advisory, so the lab works without it.

```bash
az group create -n rg-identity-lab-ai -l eastus2 -o none
az cognitiveservices account create -n oai-idlab-<suffix> -g rg-identity-lab-ai -l eastus2 \
  --kind OpenAI --sku S0 --custom-domain oai-idlab-<suffix> --yes -o none
# pick a model that has quota on your subscription:
#   az cognitiveservices usage list -l eastus2 -o table | grep -i gpt
az cognitiveservices account deployment create -n oai-idlab-<suffix> -g rg-identity-lab-ai \
  --deployment-name gpt-5-mini --model-name gpt-5-mini --model-version 2025-08-07 \
  --model-format OpenAI --sku-name GlobalStandard --sku-capacity 50 -o none
```

**Hand back:** `AZURE_OPENAI_RESOURCE_ID=` (the account's resource id),
`AZURE_OPENAI_ENDPOINT=https://oai-idlab-<suffix>.openai.azure.com/`,
`AZURE_OPENAI_DEPLOYMENT=gpt-5-mini`. `after-signup.sh` then gives the PLAN
identity "Cognitive Services OpenAI User" on it (step B) and sets the GitHub
variables (step C).
