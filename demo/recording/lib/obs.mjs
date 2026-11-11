// OBS Studio remote control over its built-in obs-websocket v5 (127.0.0.1:4455).
//
// The cockpit records one file per piece: StartRecord when the piece's first
// step runs, PauseRecord while a WAIT step's light is yellow (Microsoft's sync
// waits never reach the video), ResumeRecord when it turns green, StopRecord
// at the piece's end; then the .mkv is renamed NN-piece.mkv and remuxed to .mp4.
//
// The websocket password is read from the macOS Keychain (contoso-lab-obs-ws)
// inside this process: never logged, never in argv. tools/obs-setup.sh made it.
//
// If OBS cannot be reached, lib/screencap.mjs (macOS `screencapture -v`) takes
// over: one file per piece, but no pause (the README says so).
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { pickDisplay } from './displays.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const FFMPEG = fs.existsSync('/opt/homebrew/bin/ffmpeg') ? '/opt/homebrew/bin/ffmpeg' : 'ffmpeg';
export const SCENE = 'Contoso demo';
const DISPLAY_INPUT = 'Recording display';
const MIC_INPUT = 'Microphone';

function keychain(svc) {
  return execFileSync('security', ['find-generic-password', '-s', svc, '-w'], { encoding: 'utf8' }).trim();
}

export class Obs {
  constructor({ url = 'ws://127.0.0.1:4455', keychainService = 'contoso-lab-obs-ws', log = console.log } = {}) {
    this.url = url; this.svc = keychainService; this.log = log;
    this.ws = null; this.pending = new Map(); this.n = 0; this.events = [];
  }

  // Start OBS in the background if it is not running, then connect and identify.
  async connect({ launch = true, timeoutMs = 25000 } = {}) {
    if (launch && !isRunning()) {
      this.log('obs: starting OBS in the background');
      spawn('open', ['-g', '-a', 'OBS', '--args', '--disable-shutdown-check'], { stdio: 'ignore', detached: true }).unref();
    }
    const end = Date.now() + timeoutMs;
    let last, safeTried = false;
    while (Date.now() < end) {
      try { await this._open(); break; } catch (e) {
        last = e; await sleep(1000);
        // After a crash OBS opens in a Safe-Mode prompt with the websocket
        // off: answer it "Run in Normal Mode" (System Events), once.
        if (!safeTried && isRunning() && Date.now() > end - timeoutMs + 5000) { safeTried = true; if (await leaveSafeMode()) this.log('obs: answered the Safe-Mode prompt: Run in Normal Mode'); }
      }
    }
    if (!this.ws) throw new Error(`OBS websocket not reachable at ${this.url}: ${last?.message || 'timeout'}`);
    // A freshly started OBS answers "not ready to perform the request" for a
    // few seconds after the websocket is up: wait for it.
    for (;;) {
      try { await this.req('GetRecordStatus'); return this; }
      catch (e) { if (!/not ready/i.test(e.message) || Date.now() > end + 30000) throw e; await sleep(1000); }
    }
  }

  _open() {
    return new Promise((resolve, reject) => {
      let ws;
      try { ws = new WebSocket(this.url, 'obswebsocket.json'); } catch (e) { reject(e); return; }
      const fail = (e) => { try { ws.close(); } catch {} reject(e instanceof Error ? e : new Error(e?.message || 'websocket error')); };
      ws.onerror = () => fail(new Error('connection refused'));
      ws.onclose = (ev) => { if (!this.ws) fail(new Error(`closed (${ev.code} ${ev.reason || ''})`)); else { this.ws = null; this.log('obs: connection closed'); } };
      ws.onmessage = (m) => {
        const msg = JSON.parse(typeof m.data === 'string' ? m.data : Buffer.from(m.data).toString());
        if (msg.op === 0) {   // Hello
          const d = { rpcVersion: 1, eventSubscriptions: 64 /* Outputs */ };
          if (msg.d.authentication) {
            const pw = keychain(this.svc);
            const secret = crypto.createHash('sha256').update(pw + msg.d.authentication.salt).digest('base64');
            d.authentication = crypto.createHash('sha256').update(secret + msg.d.authentication.challenge).digest('base64');
          }
          ws.send(JSON.stringify({ op: 1, d }));
        } else if (msg.op === 2) { this.ws = ws; this.version = msg.d.negotiatedRpcVersion; resolve(); }
        else if (msg.op === 7) {
          const p = this.pending.get(msg.d.requestId); if (!p) return;
          this.pending.delete(msg.d.requestId);
          if (msg.d.requestStatus.result) p.resolve(msg.d.responseData || {});
          else p.reject(new Error(`${msg.d.requestType}: ${msg.d.requestStatus.comment || 'code ' + msg.d.requestStatus.code}`));
        } else if (msg.op === 5) { this.events.push(msg.d); if (this.events.length > 50) this.events.shift(); }
      };
    });
  }

  get connected() { return !!this.ws; }

  req(requestType, requestData = {}) {
    if (!this.ws) return Promise.reject(new Error('OBS not connected'));
    const requestId = String(++this.n);
    return new Promise((resolve, reject) => {
      this.pending.set(requestId, { resolve, reject });
      this.ws.send(JSON.stringify({ op: 6, d: { requestType, requestId, requestData } }));
      setTimeout(() => { if (this.pending.delete(requestId)) reject(new Error(`${requestType}: no answer`)); }, 20000);
    });
  }

  close() { try { this.ws?.close(); } catch {} this.ws = null; }

  // The "Contoso demo" scene: the recording display (ScreenCaptureKit display
  // capture, cursor shown) plus the microphone. Built once; re-runs only check.
  async ensureScene({ display = '', recordDir, cursor = true }) {
    const { scenes } = await this.req('GetSceneList');
    if (!scenes.some((s) => s.sceneName === SCENE)) await this.req('CreateScene', { sceneName: SCENE });
    const { inputs } = await this.req('GetInputList');
    const names = new Set(inputs.map((i) => i.inputName));
    if (!names.has(DISPLAY_INPUT)) {
      const { inputKinds } = await this.req('GetInputKindList', { unversioned: true });
      const kind = ['screen_capture', 'display_capture'].find((k) => inputKinds.includes(k));
      if (!kind) throw new Error('this OBS has no screen capture source');
      await this.req('CreateInput', { sceneName: SCENE, inputName: DISPLAY_INPUT, inputKind: kind, inputSettings: { type: 0, show_cursor: cursor }, sceneItemEnabled: true });
    }
    // The display, by UUID from CoreGraphics (lib/displays.mjs), set
    // explicitly: without display_uuid the source stays at width 0 even with
    // permission. NEVER ask OBS for its display list
    // (GetInputPropertiesListPropertyItems): OBS 33.0.1 crashes on it.
    let picked = null;
    try {
      picked = await pickDisplay(display);
      await this.req('SetInputSettings', { inputName: DISPLAY_INPUT, inputSettings: { type: 0, display_uuid: picked.uuid, show_cursor: cursor } });
    } catch (e) { this.log(`obs: display: ${e.message}`); }
    let capture = false;
    for (let k = 0; k < 12 && !capture; k++) { capture = await this.captureOk(); if (!capture) await sleep(250); }
    if (!names.has(MIC_INPUT)) {
      await this.req('CreateInput', { sceneName: SCENE, inputName: MIC_INPUT, inputKind: 'coreaudio_input_capture', inputSettings: { device_id: 'default' }, sceneItemEnabled: true });
    }
    await this.req('SetCurrentProgramScene', { sceneName: SCENE });
    // Recording settings: Simple output, MKV (survives a crash), "High Quality"
    // (Simple output cannot pause when the quality is "Same as stream").
    const p = (c, n, v) => this.req('SetProfileParameter', { parameterCategory: c, parameterName: n, parameterValue: v }).catch((e) => this.log(`obs: ${c}.${n}: ${e.message}`));
    await p('Output', 'Mode', 'Simple');
    await p('SimpleOutput', 'RecQuality', 'HQ');
    // Apple's hardware H.264 encoder: on this Mac, OBS 33's x264 failed to
    // start ("Starting the output failed", nothing in the log); apple_h264 works.
    await p('SimpleOutput', 'RecEncoder', 'apple_h264');
    await p('SimpleOutput', 'RecFormat2', 'mkv');
    await p('SimpleOutput', 'RecFormat', 'mkv');
    if (recordDir) { fs.mkdirSync(recordDir, { recursive: true }); await this.req('SetRecordDirectory', { recordDirectory: recordDir }).catch(async () => p('SimpleOutput', 'FilePath', recordDir)); }
    return { scene: SCENE, display: picked ? `${picked.name || 'display'} ${picked.uuid}` : 'main display', capture };
  }

  // ScreenCaptureKit's display stream can freeze on its last frame (OBS left
  // running overnight, after the display slept: 2026-11-06, a whole take
  // showed a 12:50 AM picture of another window). Setting the source's
  // settings again restarts the stream; done before every session.
  //
  // 2026-11-10 ("ghost mode isn't in OBS"): the stream had STOPPED on
  // 2026-11-07 23:27 (OBS log: "[ mac-screencapture ]: Stream stopped with
  // error -3805", after "no capture source was not found" when the display
  // went offline) and OBS never restarts it by itself. OBS kept showing a dead
  // picture for three days, so nothing on screen (ring, orange box, in-page
  // pointer) reached OBS. The overlays themselves are captured fine once the
  // stream runs (frames: ring, box, tag, pointer and ripple all present).
  // CaptureWatch below catches the next stop and calls this again.
  // OBS only restarts the stream when a setting CHANGES, hence the toggle.
  async refreshCapture() {
    const { inputSettings } = await this.req('GetInputSettings', { inputName: DISPLAY_INPUT });
    await this.req('SetInputSettings', { inputName: DISPLAY_INPUT, inputSettings: { ...inputSettings, show_cursor: !inputSettings.show_cursor } });
    await sleep(1200);
    await this.req('SetInputSettings', { inputName: DISPLAY_INPUT, inputSettings });
    await sleep(1500);
  }

  // The system pointer in the capture (show_cursor). The cockpit's in-page
  // pointer (lib/browser.mjs) glides while the real one stands still, so with
  // both on the video can show two pointers; the caller decides.
  async setCursor(show) {
    const { inputSettings } = await this.req('GetInputSettings', { inputName: DISPLAY_INPUT });
    if (!!inputSettings.show_cursor === !!show) return;
    await this.req('SetInputSettings', { inputName: DISPLAY_INPUT, inputSettings: { ...inputSettings, show_cursor: !!show } });
  }

  // Does the display source actually see the screen? Its width is 0 until
  // macOS has given OBS Screen Recording permission (the owner allows it once).
  async captureOk() {
    try {
      const { sceneItemId } = await this.req('GetSceneItemId', { sceneName: SCENE, sourceName: DISPLAY_INPUT });
      const { sceneItemTransform: t } = await this.req('GetSceneItemTransform', { sceneName: SCENE, sceneItemId });
      return (t.sourceWidth || 0) > 0;
    } catch { return false; }
  }

  // Fit the canvas to the captured display (output 1920 wide, same shape), so
  // nothing is letterboxed. Only when no output is active.
  async fitCanvas(widthPx, heightPx) {
    if (!widthPx || !heightPx) return null;
    const outW = Math.min(1920, widthPx), outH = Math.round((heightPx * outW) / widthPx / 2) * 2;
    await this.req('SetVideoSettings', { baseWidth: widthPx, baseHeight: heightPx, outputWidth: outW, outputHeight: outH }).catch((e) => this.log(`obs: canvas: ${e.message}`));
    // Stretch the display source to the canvas.
    try {
      const { sceneItemId } = await this.req('GetSceneItemId', { sceneName: SCENE, sourceName: DISPLAY_INPUT });
      await this.req('SetSceneItemTransform', { sceneName: SCENE, sceneItemId, sceneItemTransform: { boundsType: 'OBS_BOUNDS_SCALE_INNER', boundsWidth: widthPx, boundsHeight: heightPx, positionX: 0, positionY: 0, boundsAlignment: 0 } });
    } catch (e) { this.log(`obs: transform: ${e.message}`); }
    return { outW, outH };
  }

  async status() { return this.req('GetRecordStatus'); }

  async start(fileBase) {
    // OBS names the file from this pattern (no strftime codes = a fixed name).
    await this.req('SetProfileParameter', { parameterCategory: 'Output', parameterName: 'FilenameFormatting', parameterValue: fileBase });
    const st = await this.status();
    if (st.outputActive) throw new Error('OBS is already recording');
    await this.req('StartRecord');
    for (let i = 0; i < 20; i++) { if ((await this.status()).outputActive) return; await sleep(250); }
    throw new Error('OBS did not start recording');
  }
  async pause() { const s = await this.status(); if (s.outputActive && !s.outputPaused) await this.req('PauseRecord'); }
  async resume() { const s = await this.status(); if (s.outputActive && s.outputPaused) await this.req('ResumeRecord'); }
  async stop() {
    const s = await this.status(); if (!s.outputActive) return null;
    const { outputPath } = await this.req('StopRecord');
    for (let i = 0; i < 40; i++) { if (!(await this.status()).outputActive) break; await sleep(250); }
    return outputPath || null;
  }
}

// OBS's crash-recovery prompt, if it is up: click "Run in Normal Mode".
export function leaveSafeMode() {
  const script = ['tell application "System Events"', '  if not (exists process "OBS") then return "no"', '  tell process "OBS"',
    '    repeat with w in windows', '      try', '        click button "Run in Normal Mode" of w', '        return "clicked"', '      end try',
    '      try', '        click (first button of (entire contents of w) whose name is "Run in Normal Mode")', '        return "clicked"', '      end try',
    '    end repeat', '  end tell', 'end tell', 'return "no"'].join('\n');
  return new Promise((resolve) => execFile('osascript', ['-e', script], { timeout: 20000 }, (e, so) => resolve(!e && so.trim() === 'clicked')));
}

// OBS's current log (it writes one per launch; the newest is the live one).
export function obsLogFile() {
  const dir = path.join(process.env.HOME || '', 'Library', 'Application Support', 'obs-studio', 'logs');
  try {
    const f = fs.readdirSync(dir).filter((n) => n.endsWith('.txt')).map((n) => path.join(dir, n));
    return f.sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0] || null;
  } catch { return null; }
}

// Watches OBS's log for the screen capture stream stopping ("[ mac-screencapture ]:
// Stream stopped ..." : display slept or went offline, macOS interrupted
// ScreenCaptureKit with -3805). OBS shows its last frame forever after that;
// onStop(line) is called once per stop so the caller can refreshCapture().
// Only lines written after start() count (a new OBS launch = a new log file).
export const STREAM_STOPPED = /\[ mac-screencapture \]: Stream stopped/;
export class CaptureWatch {
  constructor({ onStop, everyMs = 2000, file = null } = {}) { Object.assign(this, { onStop, everyMs, fixed: file }); this.timer = null; this.file = null; this.pos = 0; this.stops = 0; }
  _sync() {
    const f = this.fixed || obsLogFile();
    if (f !== this.file) { this.file = f; this.pos = f ? fs.statSync(f).size : 0; }
  }
  start() { this._sync(); if (!this.timer) { this.timer = setInterval(() => this.check(), this.everyMs); this.timer.unref?.(); } return this; }
  stop() { clearInterval(this.timer); this.timer = null; }
  // Reads what OBS appended since the last look; returns the stop lines found.
  check() {
    const f = this.fixed || obsLogFile();
    if (!f) return [];
    if (f !== this.file) { this.file = f; this.pos = 0; }   // OBS was relaunched: its new log is all new
    let buf;
    try {
      const size = fs.statSync(f).size; if (size < this.pos) this.pos = 0; if (size === this.pos) return [];
      const fd = fs.openSync(f, 'r'); buf = Buffer.alloc(size - this.pos); fs.readSync(fd, buf, 0, buf.length, this.pos); fs.closeSync(fd); this.pos = size;
    } catch { return []; }
    const hits = buf.toString('utf8').split('\n').filter((l) => STREAM_STOPPED.test(l));
    for (const l of hits) { this.stops++; try { this.onStop?.(l.trim()); } catch {} }
    return hits;
  }
}

export function isRunning() {
  try { execFileSync('pgrep', ['-x', 'OBS'], { stdio: 'ignore' }); return true; } catch { return false; }
}

// mkv -> mp4 without re-encoding (seconds, not minutes). Keeps the mkv.
export function remux(mkv) {
  const mp4 = mkv.replace(/\.mkv$/i, '.mp4');
  return new Promise((resolve, reject) => {
    execFile(FFMPEG, ['-v', 'error', '-y', '-i', mkv, '-c', 'copy', '-movflags', '+faststart', mp4], (e) => (e ? reject(e) : resolve(mp4)));
  });
}

// The main display's size in pixels, for fitCanvas.
export function mainDisplayPixels() {
  try {
    const j = JSON.parse(execFileSync('system_profiler', ['SPDisplaysDataType', '-json'], { encoding: 'utf8' }));
    for (const gpu of j.SPDisplaysDataType || []) for (const d of gpu.spdisplays_ndrvs || []) {
      if (d.spdisplays_main !== 'spdisplays_yes') continue;
      const m = /(\d+)\s*x\s*(\d+)/.exec(d._spdisplays_pixels || d.spdisplays_pixelresolution || d._spdisplays_resolution || '');
      if (m) return { w: +m[1], h: +m[2], name: d._name };
    }
  } catch {}
  return null;
}

export const pieceFile = (dir, nn, slug) => path.join(dir, `${String(nn).padStart(2, '0')}-${slug}`);
