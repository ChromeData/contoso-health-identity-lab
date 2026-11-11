// The stage: exactly one cockpit window in front of the camera.
//
// Review 1 found other windows on camera: the lead's own VS Code window with
// private chat text (app activation brought every VS Code window, or switched
// to its full-screen Space), adm-labops's PIM page during piece 7, the OBS
// window at 0:03. So the cockpit never "activates an app"; it:
//   1. hides every other cockpit process (the other Chrome windows by pid,
//      VS Code, OBS) with System Events (Cmd-H: instant, no animation),
//   2. raises the ONE target window (AXRaise, AXMain), then makes its process
//      frontmost,
//   3. checks the front window afterwards, and tries again once.
// VS Code is matched by bundle id (its process is named "Electron") and its
// demo window by title ("<workspace> (Workspace)"); every other VS Code window
// (e.g. the lead's) stays hidden with the app or is minimized at the start.
import { execFile } from 'node:child_process';
import { windows } from './winshot.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function osa(script, args = []) {
  return new Promise((resolve) => execFile('osascript', ['-e', script, ...args.map(String)], { timeout: 20000 }, (e, so, se) => resolve(e ? `error: ${(se || e.message).trim()}` : so.trim())));
}

// One small System Events statement per call: a combined script lost its
// hides silently (2026-11-05), separate calls are reliable.
const hidePid = (pid) => osa(`tell application "System Events" to set visible of (first process whose unix id is ${+pid}) to false`);
// No Claude window on camera (the owner's Claude desktop app, or a Claude
// Code window): hidden every time the stage is set.
const HIDE_CLAUDE = 'tell application "System Events"\nrepeat with p in (every process whose bundle identifier starts with "com.anthropic.")\nset visible of p to false\nend repeat\nend tell';
const HIDE_OBS = 'tell application "System Events" to if exists process "OBS" then set visible of process "OBS" to false';
const HIDE_CODE = 'tell application "System Events" to if exists (first process whose bundle identifier is "com.microsoft.VSCode") then set visible of (first process whose bundle identifier is "com.microsoft.VSCode") to false';
// Answers "ok|<found>|<was minimized>": found is false when System Events
// cannot see the window from the Space on screen (a full-screen window's
// Space shows no other VS Code window).
const SHOW_CODE = `on run argv
  set found to false
  set wasMin to false
  set t to item 1 of argv
  tell application "System Events"
    set vp to first process whose bundle identifier is "com.microsoft.VSCode"
    set visible of vp to true
    -- By name, every time: "repeat with w in windows" holds index references,
    -- and once the window is raised the same index is ANOTHER window, which
    -- then got AXMain (2026-11-10: the previous stage window kept coming back).
    if exists (first window of vp whose name ends with t) then
      set found to true
      try
        if (value of attribute "AXMinimized" of (first window of vp whose name ends with t)) then
          set wasMin to true
          set value of attribute "AXMinimized" of (first window of vp whose name ends with t) to false
        end if
      end try
      try
        perform action "AXRaise" of (first window of vp whose name ends with t)
      end try
      try
        set value of attribute "AXMain" of (first window of vp whose name ends with t) to true
      end try
    end if
  end tell
  return "ok|" & (found as string) & "|" & (wasMin as string)
end run`;
// Then VS Code is activated through AppKit WITHOUT "all windows" (System
// Events' frontmost brought every VS Code window forward, and with them the
// lead's own window: preview 2, piece 10): only its main window, the demo
// window just raised and made main, comes to the front.
const ACTIVATE_CODE = `ObjC.import('AppKit'); const a = $.NSRunningApplication.runningApplicationsWithBundleIdentifier('com.microsoft.VSCode'); if (a.count) a.objectAtIndex(0).activateWithOptions($.NSApplicationActivateIgnoringOtherApps); 'ok'`;
const activateCode = () => new Promise((resolve) => execFile('osascript', ['-l', 'JavaScript', '-e', ACTIVATE_CODE], { timeout: 15000 }, (e, so, se) => resolve(e ? `error: ${(se || e.message).trim()}` : so.trim())));
// A Chrome instance by pid: AppKit activation of that very process (System
// Events' frontmost picks the app, not the instance; seen 2026-11-05).
const activatePid = (pid) => new Promise((resolve) => execFile('osascript', ['-l', 'JavaScript', '-e', `ObjC.import('AppKit'); const a = $.NSRunningApplication.runningApplicationWithProcessIdentifier(${+pid}); a.unhide; a.activateWithOptions($.NSApplicationActivateIgnoringOtherApps); 'ok'`], { timeout: 15000 }, (e, so, se) => resolve(e ? `error: ${(se || e.message).trim()}` : so.trim())));

const FRONT = `tell application "System Events"
  set fp to first process whose frontmost is true
  set t to ""
  try
    set t to name of front window of fp
  end try
  return (unix id of fp as string) & "|" & t
end tell`;

// target: { kind: 'code', title: 'contoso-demo (Workspace)' } | { kind: 'chrome', pid }
export async function stage(target, otherPids = [], log = () => {}) {
  const hide = otherPids.filter((p) => p && p !== target.pid);
  for (let k = 0; k < 2; k++) {
    // Front first, hide after: the cockpit's Chrome windows are separate
    // processes of ONE app, and activating one un-hides the others (seen
    // 2026-11-05), so the others are hidden only once the target is in front.
    let r;
    if (target.kind === 'code') {
      r = await osa(SHOW_CODE, [target.title]);
      const [ok, found, wasMin] = r.split('|');
      // 2026-11-10 walkthrough: a VS Code activation had switched to the
      // lead's full-screen window's Space, where no demo window can be seen
      // or raised, and every later try stayed there. Back to the desktop
      // Space through a cockpit Chrome window, then raise again.
      if (ok === 'ok' && found !== 'true' && hide.length) {
        log('stage: the demo VS Code window is not on this Space: back through the cockpit browser');
        await activatePid(hide[0]); await sleep(900);
        r = await osa(SHOW_CODE, [target.title]);
      }
      // A window just un-minimized is not main until its animation ends:
      // activating VS Code before that brings its OTHER main window.
      if (r.split('|')[2] === 'true') await sleep(700);
      r = r.startsWith('ok') ? await activateCode() : r;
      // Activation brings VS Code's MAIN window, which is not always the one
      // just raised (2026-11-10: the tour window kept coming back in front of
      // the demo window, try after try): raised once more inside the now
      // active app.
      if (r === 'ok') { await sleep(200); await osa(SHOW_CODE, [target.title]); }
    } else r = await activatePid(target.pid);
    if (r !== 'ok') log(`stage: ${r}`);
    await sleep(250);
    // The other cockpit Chrome windows are NOT hidden: they are one app, and
    // hiding one hides them all (seen 2026-11-05). They sit exactly behind
    // the target (same size and place), so raising it is enough. VS Code
    // (other windows, the lead's own) and OBS are hidden.
    void hide; void hidePid;
    if (target.kind !== 'code') await osa(HIDE_CODE);
    await osa(HIDE_OBS);
    await osa(HIDE_CLAUDE);
    await sleep(350);
    // The top real window on screen (the window list is front to back).
    const top = windows().find((w) => w.layer === 0 && w.w > 400 && w.h > 300) || {};
    const pid = top.pid, title = top.title || '';
    const ok = target.kind === 'code' ? title.endsWith(target.title) : +pid === +target.pid;
    if (ok) return true;
    log(`stage: front is ${title || pid}, not the ${target.kind === 'code' ? 'demo VS Code window' : 'cockpit window'}; again`);
  }
  return false;
}

// Before recording: every VS Code window except the demo one(s) is minimized.
// keep: one title or a list (a run can use the demo AND the tour window).
// leaveFullScreen (--watch, 2026-11-10): the lead's own window sat in full
// screen, so minimizing skipped it, and every VS Code activation switched to
// its Space (N16's first seconds, ~3 min of N17). It is taken out of full
// screen first, then minimized; restoreFullScreen() puts it back afterwards.
// Returns { minimized, fullScreen: [titles taken out of full screen] }.
export async function clearCodeWindows(keep, { leaveFullScreen = false } = {}) {
  const keeps = (Array.isArray(keep) ? keep : [keep]).filter(Boolean);
  const r = await osa(`on run argv
  set lfs to (item 1 of argv) is "1"
  set keeps to rest of argv
  tell application "System Events"
    if not (exists (first process whose bundle identifier is "com.microsoft.VSCode")) then return "0|"
    set vp to first process whose bundle identifier is "com.microsoft.VSCode"
    set n to 0
    set fsl to ""
    repeat with w in windows of vp
      set nm to ""
      try
        set nm to name of w
      end try
      set mine to false
      repeat with k in keeps
        if nm ends with (k as string) then set mine to true
      end repeat
      if not mine then
        try
          set isFs to (value of attribute "AXFullScreen" of w)
          if isFs and lfs then
            set value of attribute "AXFullScreen" of w to false
            set fsl to fsl & nm & linefeed
            repeat 12 times
              delay 0.25
              try
                if (value of attribute "AXFullScreen" of w) is false then exit repeat
              end try
            end repeat
            delay 0.8
            set isFs to false
          end if
          if isFs is false and (value of attribute "AXMinimized" of w) is false then
            set value of attribute "AXMinimized" of w to true
            set n to n + 1
          end if
        end try
      end if
    end repeat
    return (n as string) & "|" & fsl
  end tell
end run`, [leaveFullScreen ? '1' : '0', ...keeps]);
  if (r.startsWith('error')) return { minimized: 0, fullScreen: [], error: r };
  const [n, rest = ''] = r.split('|');
  return { minimized: +n || 0, fullScreen: rest.split('\n').map((x) => x.trim()).filter(Boolean) };
}
export async function minimizeOtherCodeWindows(title, opts) {
  const r = await clearCodeWindows(title, opts);
  return r.error || `${r.minimized} minimized${r.fullScreen.length ? ` (${r.fullScreen.length} taken out of full screen first)` : ''}`;
}
// After the run: the windows taken out of full screen are put back (matched
// by their folder, the part after the last " — ", as the file part changes).
export async function restoreFullScreen(titles = []) {
  const folders = [...new Set(titles.map((t) => t.split(' — ').pop()).filter(Boolean))];
  if (!folders.length) return 'nothing to restore';
  return osa(`on run argv
  tell application "System Events"
    if not (exists (first process whose bundle identifier is "com.microsoft.VSCode")) then return "no VS Code"
    set vp to first process whose bundle identifier is "com.microsoft.VSCode"
    set n to 0
    repeat with w in windows of vp
      try
        set nm to name of w
        repeat with f in argv
          if nm ends with (f as string) then
            set value of attribute "AXMinimized" of w to false
            delay 0.6
            set value of attribute "AXFullScreen" of w to true
            set n to n + 1
            exit repeat
          end if
        end repeat
      end try
    end repeat
    return (n as string) & " put back in full screen"
  end tell
end run`, folders);
}

// --watch start: visible windows of apps that are not part of the demo (by
// name), so the owner can close them (2026-11-10: another app's "File not
// saved" dialog floated over every frame). Nothing is closed or touched.
const SYSTEM_OWNERS = /^(Window Server|Dock|Control Center|SystemUIServer|Notification Center|NotificationCenter|Spotlight|TextInputMenuAgent|TextInputSwitcher|loginwindow|WindowManager|Wallpaper|Screenshot|universalAccessAuthWarn|AutoFill|CursorUIViewService|script-overlay|cursor-ring|human-input|OBS|obs)$/;
export function foreignWindows({ ownPids = [], codeTitles = [] } = {}) {
  let list = [];
  try { list = windows(); } catch { return []; }
  const own = new Set(ownPids.map(Number));
  const out = new Map();
  for (const w of list) {
    if (w.w < 80 || w.h < 60 || w.alpha === 0 || w.layer >= 20 || SYSTEM_OWNERS.test(w.owner || '') || own.has(+w.pid)) continue;
    if (w.owner === 'Code' && codeTitles.some((t) => (w.title || '').endsWith(t))) continue;
    const key = `${w.owner}${w.title ? ` (${w.title})` : ''}`;
    out.set(key, (out.get(key) || 0) + 1);
  }
  return [...out.entries()].map(([k, n]) => (n > 1 ? `${k} x${n}` : k));
}

// The stage watchdog (--watch, with the curtain up): windows of other apps
// on screen right now, by pid (VS Code is left to clearOthers: its demo window
// shares the process). list: a windows() result, to read the screen once.
export function foreignOnScreen({ ownPids = [], list = null } = {}) {
  try { list ||= windows(); } catch { return []; }
  const own = new Set(ownPids.map(Number));
  const out = new Map();
  for (const w of list) {
    if (w.w < 80 || w.h < 60 || w.alpha === 0 || w.layer >= 20 || SYSTEM_OWNERS.test(w.owner || '') || own.has(+w.pid) || w.owner === 'Code' || +w.pid === process.pid) continue;
    out.set(+w.pid, { pid: +w.pid, owner: w.owner, title: w.title });
  }
  return [...out.values()];
}

// Is the demo VS Code window on the current Space (System Events only lists
// those)?
export async function codeWindowHere(title) {
  const r = await osa(`on run argv
  tell application "System Events"
    if not (exists (first process whose bundle identifier is "com.microsoft.VSCode")) then return "no"
    set visible of (first process whose bundle identifier is "com.microsoft.VSCode") to true
    delay 0.8
    repeat with w in windows of (first process whose bundle identifier is "com.microsoft.VSCode")
      try
        if (name of w) ends with (item 1 of argv) then return "yes"
      end try
    end repeat
  end tell
  return "no"
end run`, [title]);
  return r === 'yes';
}

// macOS notification banners (2026-11-07: two banners sat on camera for all of
// N00): closed before each piece and on each map open. Needs the same
// Accessibility access as the stage guard. Returns the number closed.
export async function clearNotifications() {
  const f = new URL('./clear-notifications.applescript', import.meta.url).pathname;
  return new Promise((res) => execFile('osascript', [f], { timeout: 15000 }, (e, out) => res(e ? -1 : +(String(out).match(/closed (\d+)/)?.[1] || 0))));
}
// The pointer, parked at the middle of the screen's right edge (its arrow
// points off screen; the bottom edge would reveal the hidden Dock), so
// neither it nor the cursor ring sits on the map.
export async function parkPointer() {
  // A real mouse-moved event, not only a warp: a warp sends none, so Chrome
  // kept the tab hover card of the tab the hand had last crossed (2026-11-10
  // walkthrough, N04b map steps).
  const js = "ObjC.import('AppKit'); ObjC.import('CoreGraphics'); var f = $.NSScreen.mainScreen.frame; var p = { x: f.size.width - 1, y: Math.round(f.size.height / 2) }; $.CGWarpMouseCursorPosition(p); var e = $.CGEventCreateMouseEvent($(), $.kCGEventMouseMoved, p, $.kCGMouseButtonLeft); $.CGEventPost($.kCGHIDEventTap, e); 'ok'";
  return new Promise((res) => execFile('osascript', ['-l', 'JavaScript', '-e', js], { timeout: 10000 }, () => res()));
}
