// lab/servicenow/demo/pim.mjs <identity> <PIM group> <hours> <justification>
// Activates a PIM for Groups membership through the Entra admin center as the
// admin badge (passkey), with the ServiceNow ticket number in the
// justification. Thin wrapper over the lab sign-in tool's activatePim, which
// sets and reads back the duration and proves the active row.
import { activatePim } from '../../scripts/demo/signin/identity.mjs';
const [id, group, hours, reason] = process.argv.slice(2);
if (!id || !group || !hours || !/^(INC|RITM|SCTASK)\d{7}\b/.test(reason || '')) {
  console.error('usage: pim.mjs <identity> <group> <hours> "<INC/RITM/SCTASK number>: reason"');
  process.exit(2);
}
const r = await activatePim(id, group, Number(hours), reason).catch((e) => { console.error(e.message); process.exit(1); });
console.log(JSON.stringify({ group: r.group, endsUtc: r.endsUtc || null, already: !!r.already }));
await r.close();
