// The Mac's displays and their UUIDs, for OBS's screen_capture source
// (setting display_uuid). Read with CoreGraphics through a tiny Swift script
// (tools/displays.swift), never through OBS: OBS 33.0.1 crashes on
// GetInputPropertiesListPropertyItems(display_uuid), even with Screen
// Recording permission, and comes back in a Safe-Mode prompt with the
// websocket off (seen twice on 2026-11-05). Cached in .state/config.json.
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const CONFIG = path.join(ROOT, '.state', 'config.json');

export function readConfig() { try { return JSON.parse(fs.readFileSync(CONFIG, 'utf8')); } catch { return {}; } }
export function writeConfig(patch) {
  const c = { ...readConfig(), ...patch };
  fs.mkdirSync(path.dirname(CONFIG), { recursive: true });
  fs.writeFileSync(CONFIG, JSON.stringify(c, null, 1), { mode: 0o600 });
  return c;
}

export function listDisplays() {
  return new Promise((resolve, reject) => execFile('swift', [path.join(ROOT, 'tools', 'displays.swift')], { timeout: 120000 }, (e, so, se) => {
    if (e) return reject(new Error(`display list (swift): ${(se || e.message).trim().split('\n').pop()}`));
    try { resolve(JSON.parse(so.trim().split('\n').pop())); } catch (x) { reject(new Error(`display list: ${x.message}`)); }
  }));
}

// The display to record: one whose name contains `want` (e.g. "DELL"), else
// the main display. Uses the cached list unless it no longer has that display.
export async function pickDisplay(want = '') {
  const cfg = readConfig();
  const match = (list) => (want ? list.find((d) => d.name.toLowerCase().includes(want.toLowerCase())) : list.find((d) => d.main)) || null;
  let d = cfg.displays ? match(cfg.displays) : null;
  if (!d) {
    const list = await listDisplays();
    writeConfig({ displays: list, displaysAt: new Date().toISOString() });
    d = match(list);
    if (!d && want) throw new Error(`no display named like "${want}" (have: ${list.map((x) => x.name).join(', ')})`);
  }
  return d;
}
