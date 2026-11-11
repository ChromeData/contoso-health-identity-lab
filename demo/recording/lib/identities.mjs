// The recording browser signs itself in (PR #196's one sign-in tool,
// lab/scripts/demo/signin/identity.mjs on main). GitHub is the ONLY sign-in
// left to the owner.
//
// One browser context per Entra identity (the tool refuses to mix them):
//   recording window (.recording-profile)  adm-presenter: Entra, Azure,
//       Defender, Sentinel (read-only; PIM-Demo-Readers activated at start)
//       + acr.breakglass for ServiceNow (lib/snow.mjs) + splunk-admin
//       + the owner's own GitHub session
//   staff window (.staff-profile)          test-user-a: My Apps, AWS, Teams
//       (she is a listed containment approver)
//   a fresh window per piece               Sam (one-time pass) in pieces 4-5,
//       adm-ava.lin (passkey) for the PIM piece
// Secrets never pass through the cockpit: the tool reads its own Keychain
// references (identities.json holds names only).
import fs from 'node:fs';
import path from 'node:path';
import { labMain } from './teardown.mjs';

let tool = null;
export async function signinTool(root) {
  if (tool) return tool;
  const main = await labMain(root);
  const f = path.join(main, 'lab/scripts/demo/signin/identity.mjs');
  if (!fs.existsSync(f)) return null;
  tool = await import(f);
  return tool;
}

export const PRESENTER = { id: 'adm-presenter', url: 'https://entra.microsoft.com/', pim: { group: 'PIM-Demo-Readers', hours: 8, reason: 'Recording the Contoso Health demo: read-only portal views' } };
export const STAFF = { id: 'test-user-a', url: 'https://myapps.microsoft.com/?tenantId=86a2e327-4951-4348-a3c4-6f4b79ffd8f2' };
export const SPLUNK = { id: 'splunk-admin', url: 'http://127.0.0.1:8000/en-US/app/search/search' };
export const AVA = { id: 'adm-ava.lin' };
export const AWS_ADMIN = { id: 'adm-labops', upn: 'adm-labops@contosohealthlab.onmicrosoft.com', pim: { group: 'PIM-AWS-Lab-Admins', hours: 2, reason: 'Recording the Contoso Health demo: show Sam in AWS Identity Center (LabAdministrator borrowed for two hours)' } };
// The owner's own Entra account is never signed in by the cockpit (it holds
// real admin rights): refused by id and by the registry's UPN.
export const OWNER_UPN = 'michaelwilliams@contosohealthlab.onmicrosoft.com';
export function assertNotOwner(id, T = null) {
  let upn = '';
  try { upn = T?.identity ? (T.identity(id)?.upn || '') : ''; } catch {}
  if (/^michaelwilliams@/i.test(String(id)) || upn.toLowerCase() === OWNER_UPN) throw new Error(`${id}: the owner's own account is never signed in by the cockpit`);
}
