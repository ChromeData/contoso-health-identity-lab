#!/usr/bin/env node
// =============================================================================
// okta :: trust-claims.mjs - let Okta count the MFA Entra already enforced
// -----------------------------------------------------------------------------
//   node lab/terraform/okta/trust-claims.mjs --dry-run   # show what would change
//   node lab/terraform/okta/trust-claims.mjs             # set it, read it back
//   node lab/terraform/okta/trust-claims.mjs --off       # turn it off again
//
// POST-APPLY STEP of this root (README "Trust the Entra MFA"): sets the Entra
// IdP's policy.trustClaims = true. With it, Okta reads the `amr` claim in the
// IdP's ID token and counts those factors toward its own sign-on policies, so
// a clinic user who passed Entra's MFA (CA001) is not asked for an Okta factor
// on top. Okta keeps MFA required; it accepts Entra's proof of it.
//
// WHY A SCRIPT AND NOT TERRAFORM: okta/okta 4.20 has no trust-claims argument
// on okta_idp_oidc (provider schema read 2026-11-05). Okta's API sets it with
// `trustClaims: true` in the IdP's PUT (Okta developer docs, "Configure claims
// sharing" > third-party OIDC IdP > "Configure claims sharing"). The PUT
// replaces the whole IdP, so the object read with GET is sent back with only
// this one field changed, and the read-back checks every other part is the
// same. verify: whether a later `terraform apply` that updates the IdP resets
// the flag - this script is idempotent, so run it after every such apply.
//
// SAFETY: Okta's docs warn that trusting claims an IdP does not send "can break
// a functioning flow". Entra sends `amr` in the ID token only on its v1.0
// endpoints (main.tf locals, read live), so the script refuses to turn trust on
// while the IdP's issuer is not the v1.0 one (sts.windows.net).
//
// SECRETS: the Okta API token comes from OKTA_API_TOKEN (as for the provider)
// or the Keychain item contoso-lab-okta-token, read into this process. The
// GET returns the IdP's client secret; it is sent back unchanged in the PUT
// and never printed. Exit 0 = desired state confirmed; 1 = error; 2 = usage.
// =============================================================================
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

// The org and IdP name from this root's terraform.tfvars (no secrets in it).
export function readTfvars(file) {
  const out = {};
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const m = line.match(/^\s*(okta_org_name|okta_base_url|entra_idp_name)\s*=\s*"([^"]*)"/);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

// The IdP name Terraform uses when terraform.tfvars does not set one: the
// `default` of variable "entra_idp_name" in this root's variables.tf, read
// from the file so the two can never disagree.
export function defaultIdpName(variablesTf) {
  const m = variablesTf.match(/variable\s+"entra_idp_name"\s*\{[\s\S]*?\n\s*default\s*=\s*"([^"]+)"/);
  return m ? m[1] : null;
}

// Key-order-independent equality for the read-back: Okta may return the same
// fields in another order.
export function sameJson(a, b) {
  const canon = (v) => Array.isArray(v) ? v.map(canon)
    : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])])) : v;
  return JSON.stringify(canon(a)) === JSON.stringify(canon(b));
}

// What would change: pure, so it is unit-tested (tests/trust-claims.test.mjs).
export function planTrust(idp, desired) {
  const issuer = (idp.protocol && idp.protocol.issuer && idp.protocol.issuer.url) || '';
  const current = !!(idp.policy && idp.policy.trustClaims);
  if (desired && !/^https:\/\/sts\.windows\.net\/[0-9a-f-]{36}\/$/i.test(issuer)) {
    return { action: 'refuse', current, reason: `the IdP's issuer is ${issuer || '(none)'}, not Entra's v1.0 issuer (https://sts.windows.net/<tenant>/): its ID token carries no amr, so trusting claims would break sign-in. Apply this root's v1.0 endpoints first.` };
  }
  if (current === desired) return { action: 'none', current };
  return { action: 'change', current, desired };
}

// The PUT body: the IdP as read, without read-only fields, with only
// policy.trustClaims changed.
export function putBody(idp, desired) {
  const b = structuredClone(idp);
  for (const k of ['_links', '_embedded', 'id', 'created', 'lastUpdated']) delete b[k];
  b.policy = { ...b.policy, trustClaims: desired };
  return b;
}

// After the PUT: trustClaims is what was asked, and nothing else moved.
export function readBackProblems(before, after, desired) {
  const p = [];
  const same = sameJson;
  if (!!(after.policy && after.policy.trustClaims) !== desired) p.push('policy.trustClaims');
  if (!same(before.protocol.endpoints, after.protocol.endpoints)) p.push('protocol.endpoints');
  if (!same(before.protocol.issuer, after.protocol.issuer)) p.push('protocol.issuer');
  if (!same(before.protocol.scopes, after.protocol.scopes)) p.push('protocol.scopes');
  if (!same(before.protocol.algorithms, after.protocol.algorithms)) p.push('protocol.algorithms');
  const bc = before.protocol.credentials.client, ac = after.protocol.credentials.client;
  if (bc.client_id !== ac.client_id) p.push('client_id');
  if (bc.client_secret !== ac.client_secret) p.push('client_secret (compared, not printed)');
  const { trustClaims: _b, ...bp } = before.policy, { trustClaims: _a, ...ap } = after.policy;
  if (!same(bp, ap)) p.push('policy (other than trustClaims)');
  if (before.status !== after.status || before.name !== after.name || before.issuerMode !== after.issuerMode) p.push('status/name/issuerMode');
  return p;
}

// The whole step, with fetch and the token injectable for the tests.
export async function run({ org, idpName, idpId, desired = true, dryRun = false, token, fetchFn = fetch, log = console.log }) {
  const H = { Authorization: `SSWS ${token}`, Accept: 'application/json', 'Content-Type': 'application/json' };
  const call = async (method, url, body) => {
    const r = await fetchFn(`https://${org}${url}`, { method, headers: H, body: body && JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(`${method} ${url}: HTTP ${r.status} ${j.errorCode || ''} ${j.errorSummary || ''}`.trim());
    return j;
  };
  let idp;
  if (idpId) idp = await call('GET', `/api/v1/idps/${encodeURIComponent(idpId)}`);
  else {
    const all = await call('GET', `/api/v1/idps?type=OIDC&q=${encodeURIComponent(idpName)}`);
    const hits = all.filter((i) => i.name === idpName);
    if (hits.length !== 1) throw new Error(`expected exactly one OIDC IdP named "${idpName}", found ${hits.length}`);
    idp = hits[0];
  }
  const plan = planTrust(idp, desired);
  if (plan.action === 'refuse') throw new Error(plan.reason);
  if (plan.action === 'none') { log(JSON.stringify({ ok: true, idp: idp.id, name: idp.name, trustClaims: plan.current, change: 'none' })); return { changed: false }; }
  if (dryRun) { log(JSON.stringify({ ok: true, dryRun: true, idp: idp.id, name: idp.name, change: `policy.trustClaims ${plan.current} -> ${desired}` })); return { changed: false }; }
  await call('PUT', `/api/v1/idps/${idp.id}`, putBody(idp, desired));
  const after = await call('GET', `/api/v1/idps/${idp.id}`);
  const problems = readBackProblems(idp, after, desired);
  if (problems.length) throw new Error(`read-back differs after the PUT: ${problems.join(', ')} - check the IdP in the Okta admin console`);
  log(JSON.stringify({ ok: true, idp: idp.id, name: idp.name, change: `policy.trustClaims ${plan.current} -> ${desired}`, readBack: 'trustClaims set; endpoints, issuer, scopes, algorithms, client, policy, status unchanged' }));
  return { changed: true };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  const a = process.argv.slice(2);
  const flag = (n) => { const i = a.indexOf(n); if (i < 0) return false; a.splice(i, 1); return true; };
  const val = (n) => { const i = a.indexOf(n); if (i < 0) return undefined; const v = a[i + 1]; a.splice(i, 2); return v; };
  const dryRun = flag('--dry-run'), off = flag('--off');
  let org = val('--org'), idpName = val('--idp-name');
  const idpId = val('--idp-id');
  if (a.length) { console.error('usage: node trust-claims.mjs [--dry-run] [--off] [--org <org>.okta.com] [--idp-name <name> | --idp-id <id>]'); process.exit(2); }
  try {
    const tfv = path.join(HERE, 'terraform.tfvars');
    const t = fs.existsSync(tfv) ? readTfvars(tfv) : {};
    org = org || (t.okta_org_name ? `${t.okta_org_name}.${t.okta_base_url || 'okta.com'}` : null);
    idpName = idpName || t.entra_idp_name || defaultIdpName(fs.readFileSync(path.join(HERE, 'variables.tf'), 'utf8'));
    if (!org || (!idpName && !idpId)) throw new Error('no org / IdP: pass --org and --idp-name (or --idp-id), or run next to this root\'s terraform.tfvars');
    const token = process.env.OKTA_API_TOKEN || execFileSync('security', ['find-generic-password', '-s', 'contoso-lab-okta-token', '-w'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (!token) throw new Error('no Okta API token (OKTA_API_TOKEN or Keychain contoso-lab-okta-token)');
    await run({ org, idpName, idpId, desired: !off, dryRun, token });
  } catch (e) { console.log(JSON.stringify({ ok: false, error: e.message })); process.exit(1); }
}
