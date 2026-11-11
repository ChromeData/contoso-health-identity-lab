// Screenshot one on-screen window (VS Code or the recording browser, with
// its title bar) into shots/, for rehearsal and dry-run evidence. Uses the
// macOS window list (CoreGraphics through JXA) and `screencapture -l`.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export function windows() {
  const js = `ObjC.import("CoreGraphics");
const arr = ObjC.castRefToObject($.CGWindowListCopyWindowInfo($.kCGWindowListOptionOnScreenOnly | $.kCGWindowListExcludeDesktopElements, 0));
const out = [];
for (let i = 0; i < arr.count; i++) { const w = arr.objectAtIndex(i); const b = ObjC.deepUnwrap(w.objectForKey("kCGWindowBounds"));
  out.push({ id: ObjC.unwrap(w.objectForKey("kCGWindowNumber")), pid: ObjC.unwrap(w.objectForKey("kCGWindowOwnerPID")), owner: ObjC.unwrap(w.objectForKey("kCGWindowOwnerName")), title: ObjC.unwrap(w.objectForKey("kCGWindowName")) || "", layer: ObjC.unwrap(w.objectForKey("kCGWindowLayer")), alpha: ObjC.unwrap(w.objectForKey("kCGWindowAlpha")), w: b.Width, h: b.Height }); }
JSON.stringify(out);`;
  return JSON.parse(execFileSync('osascript', ['-l', 'JavaScript', '-e', js], { encoding: 'utf8', timeout: 15000 }));
}

// match: { owner: /Code/, title: /rehearsal/ } or { pid }
export function winshot(match, file) {
  try {
    const w = windows().find((x) => x.layer === 0 && x.h > 300 && (match.pid ? x.pid === match.pid : true) && (match.owner ? match.owner.test(x.owner) : true) && (match.title ? match.title.test(x.title) : true));
    if (!w) return null;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    execFileSync('screencapture', ['-x', '-o', '-l', String(w.id), file], { timeout: 15000 });
    return file;
  } catch { return null; }
}
