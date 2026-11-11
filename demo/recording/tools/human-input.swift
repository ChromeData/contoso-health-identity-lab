// human-input: moves the REAL macOS pointer, clicks, scrolls and types like a
// person (CGEvent), and draws the guide mode's ghost target. The cockpit
// (lib/human.mjs) starts it once and talks to it with one JSON object per
// line on stdin; each answer is one JSON line on stdout ({"id":..,"ok":..}).
//
//   swiftc -O tools/human-input.swift -o tools/human-input
//
// Posting events needs Accessibility access for the app that started the
// cockpit (Terminal, iTerm or VS Code): System Settings > Privacy & Security
// > Accessibility. "hello" reports it (trusted: false = not allowed yet).
//
// Coordinates are CoreGraphics global points: origin at the top left of the
// main display, y down, across every display (the same space as the window
// list), so a point is valid on whatever display it falls.
//
// Motion: a cubic Bezier with randomised control points to one side (an
// arc, as a wrist makes), arc-length sampled at 125 Hz, a minimum-jerk speed
// profile skewed so the peak comes early and the landing is long, Fitts' law
// duration (a + b log2(D/W + 1)), a small physiological tremor that fades on
// landing, and on far targets an overshoot (or undershoot) and one short
// correction. Clicks: a brief settle on the target, then down, a 55-115 ms
// hold, up. Scrolling: trackpad-like flicks of continuous pixel deltas with
// a ramp and an exponential momentum tail, short gaps between flicks.
// Typing: per-key cadence with lognormal jitter, word gaps, longer after
// punctuation and before capitals, an occasional short pause. No typos.
import AppKit
import QuartzCore

setvbuf(stdout, nil, _IOLBF, 0)

// ---------------------------------------------------------------- helpers
func now() -> Double { CFAbsoluteTimeGetCurrent() }
func sleepUntil(_ t: Double) { let d = t - now(); if d > 0 { usleep(useconds_t(d * 1_000_000)) } }
func sleepMs(_ ms: Double) { if ms > 0 { usleep(useconds_t(ms * 1000)) } }
func rnd(_ a: Double, _ b: Double) -> Double { Double.random(in: a...b) }
func gauss(_ mu: Double = 0, _ sd: Double = 1) -> Double {
  let u1 = max(Double.random(in: 0..<1), 1e-12), u2 = Double.random(in: 0..<1)
  return mu + sd * sqrt(-2 * log(u1)) * cos(2 * .pi * u2)
}
func clamp(_ v: Double, _ lo: Double, _ hi: Double) -> Double { min(hi, max(lo, v)) }

var primaryH: Double { Double(NSScreen.screens.first?.frame.height ?? 1080) }
func cgRect(_ s: NSScreen) -> CGRect { let f = s.frame; return CGRect(x: f.minX, y: primaryH - f.maxY, width: f.width, height: f.height) }
func screenFor(_ p: CGPoint) -> NSScreen? { NSScreen.screens.first { cgRect($0).contains(p) } ?? NSScreen.main }
func current() -> CGPoint { let p = NSEvent.mouseLocation; return CGPoint(x: p.x, y: primaryH - p.y) }
func clampToScreens(_ p: CGPoint) -> CGPoint {
  if NSScreen.screens.contains(where: { cgRect($0).contains(p) }) { return p }
  guard let s = screenFor(current()) else { return p }
  let r = cgRect(s)
  return CGPoint(x: clamp(p.x, r.minX, r.maxX - 1), y: clamp(p.y, r.minY, r.maxY - 1))
}

let src = CGEventSource(stateID: .hidSystemState)
var buttonDown = false
var cancelUpTo = 0          // commands with an id up to this are cancelled
let cancelLock = NSLock()
var currentId = 0
func cancelled() -> Bool { cancelLock.lock(); defer { cancelLock.unlock() }; return currentId <= cancelUpTo }
struct Cancelled: Error {}
struct Fail: Error { let msg: String }

func postMove(_ p: CGPoint) {
  let t: CGEventType = buttonDown ? .leftMouseDragged : .mouseMoved
  CGEvent(mouseEventSource: src, mouseType: t, mouseCursorPosition: p, mouseButton: .left)?.post(tap: .cghidEventTap)
}

// ------------------------------------------------------------------ motion
func bez(_ p0: CGPoint, _ p1: CGPoint, _ p2: CGPoint, _ p3: CGPoint, _ t: Double) -> CGPoint {
  let u = 1 - t
  let a = u * u * u, b = 3 * u * u * t, c = 3 * u * t * t, d = t * t * t
  return CGPoint(x: a * p0.x + b * p1.x + c * p2.x + d * p3.x, y: a * p0.y + b * p1.y + c * p2.y + d * p3.y)
}
func minJerk(_ t: Double) -> Double { t * t * t * (10 - 15 * t + 6 * t * t) }

// One sub-movement from a to b in `dur` seconds along an arc.
func stroke(_ a: CGPoint, _ b: CGPoint, dur: Double, curve: Double, tremor: Double, skew: Double) throws {
  let dx = b.x - a.x, dy = b.y - a.y, D = hypot(dx, dy)
  if D < 0.5 { postMove(b); return }
  let ux = dx / D, uy = dy / D, px = -uy, py = ux
  let side: Double = Bool.random() ? 1 : -1
  let off1 = side * D * curve * rnd(0.6, 1.2), off2 = side * D * curve * rnd(0.2, 0.9) + gauss(0, D * 0.015)
  let capped = { (o: Double) in clamp(o, -140, 140) }
  let f1 = rnd(0.18, 0.36), f2 = rnd(0.58, 0.82)
  let c1 = CGPoint(x: a.x + dx * f1 + px * capped(off1), y: a.y + dy * f1 + py * capped(off1))
  let c2 = CGPoint(x: a.x + dx * f2 + px * capped(off2), y: a.y + dy * f2 + py * capped(off2))
  // Arc-length table so the speed profile is the one we set.
  let N = 200
  var pts = [CGPoint](); var len = [0.0]
  for i in 0...N { pts.append(bez(a, c1, c2, b, Double(i) / Double(N))) }
  for i in 1...N { len.append(len[i - 1] + hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y)) }
  let L = len[N]
  func at(_ s: Double) -> CGPoint {
    let target = s * L
    var lo = 0, hi = N
    while hi - lo > 1 { let m = (lo + hi) / 2; if len[m] < target { lo = m } else { hi = m } }
    let seg = len[hi] - len[lo], f = seg > 0 ? (target - len[lo]) / seg : 0
    return CGPoint(x: pts[lo].x + (pts[hi].x - pts[lo].x) * f, y: pts[lo].y + (pts[hi].y - pts[lo].y) * f)
  }
  let dt = 0.008
  let steps = max(2, Int(dur / dt))
  let ph = (rnd(0, 6.28), rnd(0, 6.28), rnd(0, 6.28), rnd(0, 6.28))
  let fq = (rnd(6.5, 9.5), rnd(8.5, 12))
  let t0 = now()
  var last = a
  for i in 1...steps {
    if cancelled() { throw Cancelled() }
    let t = Double(i) / Double(steps)
    let s = minJerk(pow(t, skew))
    var p = at(s)
    // Tremor: two small sinusoids per axis, fading out over the landing.
    let env = tremor * min(1, (1 - s) * 6) * min(1, s * 8)
    let tt = Double(i) * dt
    p.x += env * (0.6 * sin(2 * .pi * fq.0 * tt + ph.0) + 0.4 * sin(2 * .pi * fq.1 * tt + ph.1))
    p.y += env * (0.6 * sin(2 * .pi * fq.1 * tt + ph.2) + 0.4 * sin(2 * .pi * fq.0 * tt + ph.3))
    let q = CGPoint(x: p.x.rounded(), y: p.y.rounded())
    if q != last || i == steps { postMove(i == steps ? b : q); last = q }
    sleepUntil(t0 + Double(i) * dt)
  }
}

// A whole reach: Fitts duration, maybe an overshoot / undershoot and a correction.
func humanMove(to raw: CGPoint, width: Double, speed: Double) throws {
  let b = clampToScreens(raw)
  let a = current()
  let D = hypot(b.x - a.x, b.y - a.y)
  if D < 1.5 { postMove(b); return }
  let W = clamp(width, 6, 220)
  var mt = (0.17 + 0.135 * log2(D / W + 1)) * rnd(0.9, 1.12) / max(0.3, speed)
  mt = clamp(mt, 0.12, 1.5)
  let tremor = rnd(0.35, 0.75)
  let ux = (b.x - a.x) / D, uy = (b.y - a.y) / D
  let roll = Double.random(in: 0..<1)
  if D > 360 && roll < 0.65 {
    // Overshoot a little past the target, then come back.
    let o = clamp(D * rnd(0.025, 0.055), 6, 32)
    let mid = clampToScreens(CGPoint(x: b.x + ux * o + gauss(0, 3), y: b.y + uy * o + gauss(0, 3)))
    try stroke(a, mid, dur: mt * 0.86, curve: rnd(0.05, 0.13), tremor: tremor, skew: rnd(0.78, 0.9))
    sleepMs(rnd(35, 90))
    try stroke(mid, b, dur: rnd(0.13, 0.22), curve: rnd(0.0, 0.08), tremor: tremor * 0.5, skew: 0.9)
  } else if D > 140 && roll < 0.85 {
    // Fall a little short, then a small correction.
    let u = clamp(D * rnd(0.03, 0.07), 4, 26)
    let mid = CGPoint(x: b.x - ux * u + gauss(0, 2), y: b.y - uy * u + gauss(0, 2))
    try stroke(a, mid, dur: mt * 0.88, curve: rnd(0.05, 0.13), tremor: tremor, skew: rnd(0.78, 0.9))
    sleepMs(rnd(30, 80))
    try stroke(mid, b, dur: rnd(0.11, 0.18), curve: rnd(0.0, 0.06), tremor: tremor * 0.5, skew: 0.9)
  } else {
    try stroke(a, b, dur: mt, curve: rnd(0.04, 0.12), tremor: tremor, skew: rnd(0.8, 0.92))
  }
}

func mouseButton(_ down: Bool, at p: CGPoint, clickState: Int64) {
  buttonDown = down
  let e = CGEvent(mouseEventSource: src, mouseType: down ? .leftMouseDown : .leftMouseUp, mouseCursorPosition: p, mouseButton: .left)
  e?.setIntegerValueField(.mouseEventClickState, value: clickState)
  e?.post(tap: .cghidEventTap)
}

func humanClick(count: Int, settle: Double?) throws {
  // Settle on the target (a person checks they are on it), a hair of drift.
  let p = current()
  let dwell = settle ?? rnd(90, 240)
  if dwell > 60 && Bool.random() { sleepMs(dwell * 0.5); postMove(CGPoint(x: p.x + Double(Int.random(in: -1...1)), y: p.y + Double(Int.random(in: -1...1)))); sleepMs(dwell * 0.5) }
  else { sleepMs(dwell) }
  if cancelled() { throw Cancelled() }
  let q = current()
  for k in 1...max(1, count) {
    mouseButton(true, at: q, clickState: Int64(k))
    sleepMs(rnd(55, 115))
    mouseButton(false, at: q, clickState: Int64(k))
    if k < count { sleepMs(rnd(70, 120)) }
  }
}

// --------------------------------------------------------------- scrolling
func postScroll(_ dy: Int32, _ dx: Int32) {
  guard dy != 0 || dx != 0 else { return }
  let e = CGEvent(scrollWheelEvent2Source: src, units: .pixel, wheelCount: 2, wheel1: dy, wheel2: dx, wheel3: 0)
  e?.setIntegerValueField(.scrollWheelEventIsContinuous, value: 1)
  e?.post(tap: .cghidEventTap)
}
// dy > 0 scrolls DOWN (the page moves up), in points.
func humanScroll(dy total: Double, dx totalX: Double) throws {
  var left = total, leftX = totalX
  var first = true
  while abs(left) >= 1 || abs(leftX) >= 1 {
    if cancelled() { throw Cancelled() }
    if !first { sleepMs(rnd(110, 240)) }
    first = false
    // A bigger way to go, a harder flick (as on a trackpad).
    let cap = abs(left) > 1800 ? rnd(750, 1050) : rnd(480, 760)
    let d = abs(left) > cap * 1.25 ? cap * (left < 0 ? -1 : 1) : left
    let dX = abs(leftX) > cap * 1.25 ? cap * (leftX < 0 ? -1 : 1) : leftX
    // Profile: a finger ramp (sin) then an exponential momentum tail.
    let dt = 0.008, tf = rnd(0.09, 0.15), tau = rnd(0.15, 0.22), tm = tau * 3
    let n = Int((tf + tm) / dt)
    var w = [Double]()
    for i in 0..<n {
      let t = Double(i) * dt
      w.append(t < tf ? sin(.pi / 2 * (t / tf)) : exp(-(t - tf) / tau))
    }
    let sum = w.reduce(0, +)
    var accY = 0.0, accX = 0.0, sentY = 0.0, sentX = 0.0
    let t0 = now()
    for i in 0..<n {
      if cancelled() { throw Cancelled() }
      accY += d * w[i] / sum; accX += dX * w[i] / sum
      let sy = (accY - sentY).rounded(.towardZero), sx = (accX - sentX).rounded(.towardZero)
      if sy != 0 || sx != 0 { postScroll(Int32(-sy), Int32(-sx)); sentY += sy; sentX += sx }
      sleepUntil(t0 + Double(i + 1) * dt)
    }
    let ry = (d - sentY).rounded(), rx = (dX - sentX).rounded()
    if ry != 0 || rx != 0 { postScroll(Int32(-ry), Int32(-rx)) }
    left -= d; leftX -= dX
  }
}

// ----------------------------------------------------------------- typing
// The window in front: the top normal window on screen (as lib/stage.mjs).
func windowList() -> [[String: Any]] {
  (CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]]) ?? []
}
func bounds(_ w: [String: Any]) -> CGRect {
  guard let b = w[kCGWindowBounds as String] as? [String: Any] else { return .zero }
  return CGRect(x: (b["X"] as? Double) ?? 0, y: (b["Y"] as? Double) ?? 0, width: (b["Width"] as? Double) ?? 0, height: (b["Height"] as? Double) ?? 0)
}
func frontPid() -> Int {
  for w in windowList() {
    let layer = (w[kCGWindowLayer as String] as? Int) ?? 0, r = bounds(w)
    if layer == 0 && r.width > 400 && r.height > 300 { return (w[kCGWindowOwnerPID as String] as? Int) ?? 0 }
  }
  return 0
}
// The top normal window under a point.
func pidAt(_ p: CGPoint) -> Int {
  for w in windowList() {
    let layer = (w[kCGWindowLayer as String] as? Int) ?? 0
    if layer == 0 && bounds(w).contains(p) { return (w[kCGWindowOwnerPID as String] as? Int) ?? 0 }
  }
  return 0
}

let KEYS: [String: CGKeyCode] = ["return": 36, "enter": 36, "tab": 48, "space": 49, "backspace": 51, "delete": 117, "escape": 53,
  "left": 123, "right": 124, "down": 125, "up": 126, "home": 115, "end": 119, "pageup": 116, "pagedown": 121,
  "a": 0, "s": 1, "d": 2, "f": 3, "h": 4, "g": 5, "z": 6, "x": 7, "c": 8, "v": 9, "b": 11, "q": 12, "w": 13, "e": 14, "r": 15,
  "y": 16, "t": 17, "o": 31, "u": 32, "i": 34, "p": 35, "l": 37, "j": 38, "k": 40, "n": 45, "m": 46,
  "1": 18, "2": 19, "3": 20, "4": 21, "5": 23, "6": 22, "7": 26, "8": 28, "9": 25]

func postKey(_ code: CGKeyCode, down: Bool, flags: CGEventFlags = [], unicode: String? = nil) {
  let e = CGEvent(keyboardEventSource: src, virtualKey: code, keyDown: down)
  e?.flags = flags
  if let u = unicode { let chars = Array(u.utf16); e?.keyboardSetUnicodeString(stringLength: chars.count, unicodeString: chars) }
  e?.post(tap: .cghidEventTap)
}
func tapKey(_ code: CGKeyCode, flags: CGEventFlags = [], unicode: String? = nil) {
  postKey(code, down: true, flags: flags, unicode: unicode)
  sleepMs(rnd(35, 75))
  postKey(code, down: false, flags: flags, unicode: unicode)
}

func humanType(_ text: String, pid: Int, mean: Double) throws {
  var prev: Character = " "
  var lastDown = now()
  for ch in text {
    if cancelled() { throw Cancelled() }
    // Never type into another app: the front window must still be the target's.
    if pid > 0 && frontPid() != pid { throw Fail(msg: "focus-lost: the window in front is no longer the target (pid \(frontPid()))") }
    var gap = mean * exp(gauss(0, 0.33))
    if prev == " " { gap += max(0, gauss(mean * 0.7, mean * 0.4)) }
    if ".,:;!?)".contains(prev) { gap += rnd(90, 220) }
    if ch.isUppercase { gap += rnd(25, 70) }
    if ch.isNumber && !prev.isNumber { gap += rnd(30, 90) }
    if prev == " " && Double.random(in: 0..<1) < 0.035 { gap += rnd(250, 600) }
    // gap is key-down to key-down: what the last key's hold took is spent.
    sleepUntil(lastDown + clamp(gap, 45, 900) / 1000)
    lastDown = now()
    switch ch {
    case "\n": tapKey(36)
    case "\t": tapKey(48)
    default: tapKey(0, unicode: String(ch))
    }
    prev = ch
  }
}

// ------------------------------------------------------------- guide ghost
final class Ghost {
  var win: NSWindow?
  let root = CALayer(), ring = CAShapeLayer(), arrow = CAShapeLayer(), label = CATextLayer(), pill = CALayer()

  func show(x: Double, y: Double, w: Double, h: Double, hint: String, from: CGPoint?, capture: Bool) {
    let c = CGPoint(x: x + w / 2, y: y + h / 2)
    guard let scr = screenFor(c) else { return }
    let sr = cgRect(scr)
    if win == nil || win!.frame != scr.frame {
      win?.orderOut(nil)
      let wnd = NSWindow(contentRect: scr.frame, styleMask: .borderless, backing: .buffered, defer: false)
      wnd.isOpaque = false; wnd.backgroundColor = .clear; wnd.hasShadow = false
      wnd.ignoresMouseEvents = true
      wnd.level = .statusBar
      wnd.collectionBehavior = [.canJoinAllSpaces, .stationary, .fullScreenAuxiliary, .ignoresCycle]
      let v = NSView(frame: NSRect(origin: .zero, size: scr.frame.size)); v.wantsLayer = true
      v.layer?.addSublayer(root)
      root.frame = v.bounds
      for l in [ring, pill, arrow] as [CALayer] { root.addSublayer(l) }
      pill.addSublayer(label)
      wnd.contentView = v
      win = wnd
    }
    // Hidden from screen capture unless asked (the owner sees it, OBS should not).
    win!.sharingType = capture ? .readOnly : .none
    let scale = scr.backingScaleFactor
    // Layer space: origin bottom left of this screen.
    func L(_ p: CGPoint) -> CGPoint { CGPoint(x: p.x - sr.minX, y: sr.height - (p.y - sr.minY)) }
    let lc = L(c)
    CATransaction.begin(); CATransaction.setDisableActions(true)
    let r = clamp(min(w, h) / 2 + 10, 16, 46)
    ring.path = CGPath(ellipseIn: CGRect(x: -r, y: -r, width: 2 * r, height: 2 * r), transform: nil)
    ring.position = lc
    // One style with the script card and the page highlight: neutral white.
    ring.fillColor = NSColor(white: 1, alpha: 0.06).cgColor
    ring.strokeColor = NSColor(white: 1, alpha: 0.85).cgColor
    ring.lineWidth = 2
    ring.shadowColor = NSColor.black.cgColor; ring.shadowOpacity = 0.35; ring.shadowRadius = 6; ring.shadowOffset = .zero
    ring.removeAllAnimations()
    let pulse = CABasicAnimation(keyPath: "transform.scale"); pulse.fromValue = 0.94; pulse.toValue = 1.06
    pulse.duration = 1.1; pulse.autoreverses = true; pulse.repeatCount = .infinity
    pulse.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
    ring.add(pulse, forKey: "pulse")
    // The ghost arrow: the macOS arrow's shape, glassy, gliding from where the
    // pointer is to the target and fading, again and again.
    let ap = CGMutablePath()
    let pts: [CGPoint] = [CGPoint(x: 0, y: 0), CGPoint(x: 0, y: -19), CGPoint(x: 4.5, y: -14.5), CGPoint(x: 7.8, y: -21.5), CGPoint(x: 10.6, y: -20.2), CGPoint(x: 7.4, y: -13.4), CGPoint(x: 13.4, y: -13.4)]
    ap.addLines(between: pts); ap.closeSubpath()
    arrow.path = ap
    arrow.fillColor = NSColor(white: 1, alpha: 0.55).cgColor
    arrow.strokeColor = NSColor(white: 0, alpha: 0.55).cgColor
    arrow.lineWidth = 1.2
    arrow.contentsScale = scale; ring.contentsScale = scale
    arrow.removeAllAnimations()
    let start = L(from ?? current())
    let far = hypot(start.x - lc.x, start.y - lc.y) > 30
    arrow.position = lc
    if far {
      let mv = CAKeyframeAnimation(keyPath: "position")
      let mid = CGPoint(x: (start.x + lc.x) / 2 + (lc.y - start.y) * 0.12, y: (start.y + lc.y) / 2 - (lc.x - start.x) * 0.12)
      let path = CGMutablePath(); path.move(to: start); path.addQuadCurve(to: lc, control: mid)
      mv.path = path; mv.duration = 1.0; mv.timingFunction = CAMediaTimingFunction(controlPoints: 0.35, 0.1, 0.25, 1)
      let fade = CAKeyframeAnimation(keyPath: "opacity"); fade.values = [0, 0.9, 0.9, 0]; fade.keyTimes = [0, 0.15, 0.75, 1]; fade.duration = 1.6
      let g = CAAnimationGroup(); g.animations = [mv, fade]; g.duration = 2.2; g.repeatCount = .infinity
      mv.fillMode = .forwards; mv.isRemovedOnCompletion = false
      arrow.add(g, forKey: "glide")
    }
    // The hint: a small dark pill under (or above) the target.
    if hint.isEmpty { pill.isHidden = true } else {
      pill.isHidden = false
      let font = NSFont.systemFont(ofSize: 14, weight: .semibold)
      let size = (hint as NSString).size(withAttributes: [.font: font])
      let pw = ceil(size.width) + 22, phh = ceil(size.height) + 10
      var py = lc.y - r - 12 - phh
      if py < 8 { py = lc.y + r + 12 }
      let px = clamp(lc.x - pw / 2, 8, sr.width - pw - 8)
      pill.frame = CGRect(x: px, y: py, width: pw, height: phh)
      pill.backgroundColor = NSColor(calibratedWhite: 0.07, alpha: 0.82).cgColor
      pill.borderColor = NSColor(calibratedWhite: 1, alpha: 0.10).cgColor; pill.borderWidth = 1
      pill.cornerRadius = min(16, phh / 2)
      label.string = hint; label.font = font; label.fontSize = 14
      label.foregroundColor = NSColor(calibratedWhite: 1, alpha: 0.92).cgColor; label.alignmentMode = .center
      label.contentsScale = scale
      label.frame = CGRect(x: 0, y: 5, width: pw, height: ceil(size.height))
    }
    CATransaction.commit()
    win!.orderFrontRegardless()
  }
  func hide() { win?.orderOut(nil) }
}
let ghost = Ghost()

// ------------------------------------------------------------------ server
func reply(_ id: Int, _ d: [String: Any]) {
  var o = d; o["id"] = id
  if let data = try? JSONSerialization.data(withJSONObject: o), let s = String(data: data, encoding: .utf8) { print(s) }
}
func num(_ o: [String: Any], _ k: String, _ d: Double = 0) -> Double { (o[k] as? NSNumber)?.doubleValue ?? d }

let work = DispatchQueue(label: "human-input.work")

func handle(_ o: [String: Any]) {
  let id = (o["id"] as? NSNumber)?.intValue ?? 0
  let cmd = (o["cmd"] as? String) ?? ""
  if cmd == "cancel" { cancelLock.lock(); cancelUpTo = max(cancelUpTo, (o["upTo"] as? NSNumber)?.intValue ?? id); cancelLock.unlock(); reply(id, ["ok": true]); return }
  if cmd == "ghost" || cmd == "ghostOff" {
    DispatchQueue.main.async {
      if cmd == "ghost" {
        let from: CGPoint? = o["fx"] != nil ? CGPoint(x: num(o, "fx"), y: num(o, "fy")) : nil
        ghost.show(x: num(o, "x"), y: num(o, "y"), w: num(o, "w", 10), h: num(o, "h", 10), hint: (o["hint"] as? String) ?? "", from: from, capture: (o["capture"] as? Bool) ?? false)
      } else { ghost.hide() }
      reply(id, ["ok": true])
    }
    return
  }
  work.async {
    cancelLock.lock(); currentId = id; cancelLock.unlock()
    do {
      switch cmd {
      case "hello":
        let screens = NSScreen.screens.map { s -> [String: Any] in let r = cgRect(s); return ["x": r.minX, "y": r.minY, "w": r.width, "h": r.height, "scale": s.backingScaleFactor, "name": s.localizedName] }
        reply(id, ["ok": true, "trusted": AXIsProcessTrusted(), "screens": screens, "pid": getpid()])
      case "pos": let p = current(); reply(id, ["ok": true, "x": p.x, "y": p.y])
      case "move":
        try humanMove(to: CGPoint(x: num(o, "x"), y: num(o, "y")), width: num(o, "w", 30), speed: num(o, "speed", 1))
        let p = current(); reply(id, ["ok": true, "x": p.x, "y": p.y])
      case "click":
        let target = CGPoint(x: num(o, "x"), y: num(o, "y"))
        if o["x"] != nil { try humanMove(to: target, width: num(o, "w", 30), speed: num(o, "speed", 1)) }
        let pid = Int(num(o, "pid"))
        if pid > 0 { let at = pidAt(current()); if at != pid { throw Fail(msg: "not-target: the window under the pointer belongs to pid \(at), not \(pid)") } }
        try humanClick(count: Int(num(o, "count", 1)), settle: o["settle"] != nil ? num(o, "settle") : nil)
        reply(id, ["ok": true])
      case "scroll":
        if o["x"] != nil { try humanMove(to: CGPoint(x: num(o, "x"), y: num(o, "y")), width: 200, speed: num(o, "speed", 1)) ; sleepMs(rnd(80, 180)) }
        try humanScroll(dy: num(o, "dy"), dx: num(o, "dx"))
        reply(id, ["ok": true])
      case "type":
        try humanType((o["text"] as? String) ?? "", pid: Int(num(o, "pid")), mean: num(o, "mean", 150))
        reply(id, ["ok": true])
      case "key":
        let pid = Int(num(o, "pid"))
        if pid > 0 && frontPid() != pid { throw Fail(msg: "focus-lost: the window in front is not the target") }
        let name = ((o["key"] as? String) ?? "").lowercased()
        guard let code = KEYS[name] else { throw Fail(msg: "unknown key \(name)") }
        var flags: CGEventFlags = []
        for m in (o["mods"] as? [String]) ?? [] {
          switch m { case "cmd": flags.insert(.maskCommand); case "shift": flags.insert(.maskShift); case "alt": flags.insert(.maskAlternate); case "ctrl": flags.insert(.maskControl); default: break }
        }
        sleepMs(rnd(60, 160))
        tapKey(code, flags: flags)
        reply(id, ["ok": true])
      case "win":
        // The front window of a process: bounds, and its display's scale.
        let pid = Int(num(o, "pid"))
        var found: [String: Any]? = nil
        for w in windowList() {
          let layer = (w[kCGWindowLayer as String] as? Int) ?? 0, r = bounds(w)
          if layer == 0 && (w[kCGWindowOwnerPID as String] as? Int) == pid && r.width > 200 && r.height > 200 {
            let s = screenFor(CGPoint(x: r.midX, y: r.midY))
            found = ["x": r.minX, "y": r.minY, "w": r.width, "h": r.height, "scale": s?.backingScaleFactor ?? 2]
            break
          }
        }
        if let f = found { var d = f; d["ok"] = true; d["front"] = frontPid() == pid; reply(id, d) } else { reply(id, ["ok": false, "error": "no window for pid \(pid)"]) }
      case "front": reply(id, ["ok": true, "pid": frontPid()])
      case "waitclick":
        // Guide mode: wait for the PERSON's own click inside the rectangle.
        let pad = num(o, "pad", 6)
        let r = CGRect(x: num(o, "x") - pad, y: num(o, "y") - pad, width: num(o, "w") + 2 * pad, height: num(o, "h") + 2 * pad)
        let end = now() + num(o, "timeout", 1000) / 1000
        var was = (NSEvent.pressedMouseButtons & 1) != 0
        var misses = 0
        var hit = false
        while now() < end && !hit {
          if cancelled() { throw Cancelled() }
          let down = (NSEvent.pressedMouseButtons & 1) != 0
          if down && !was { if r.contains(current()) { hit = true } else { misses += 1 } }
          was = down
          if !hit { sleepMs(8) }
        }
        if hit { let rEnd = now() + 3; while (NSEvent.pressedMouseButtons & 1) != 0 && now() < rEnd { sleepMs(8) } }
        let p = current()
        reply(id, ["ok": true, "hit": hit, "misses": misses, "x": p.x, "y": p.y])
      case "waithover":
        let pad = num(o, "pad", 6)
        let r = CGRect(x: num(o, "x") - pad, y: num(o, "y") - pad, width: num(o, "w") + 2 * pad, height: num(o, "h") + 2 * pad)
        let end = now() + num(o, "timeout", 1000) / 1000, dwell = num(o, "dwell", 250) / 1000
        var since: Double? = nil, hit = false
        while now() < end && !hit {
          if cancelled() { throw Cancelled() }
          if r.contains(current()) { since = since ?? now(); if now() - since! >= dwell { hit = true } } else { since = nil }
          if !hit { sleepMs(15) }
        }
        reply(id, ["ok": true, "hit": hit])
      case "warp":
        CGWarpMouseCursorPosition(CGPoint(x: num(o, "x"), y: num(o, "y"))); reply(id, ["ok": true])
      default: reply(id, ["ok": false, "error": "unknown command \(cmd)"])
      }
    } catch is Cancelled { if buttonDown { mouseButton(false, at: current(), clickState: 1) }; reply(id, ["ok": false, "error": "cancelled"]) }
    catch let f as Fail { reply(id, ["ok": false, "error": f.msg]) }
    catch { reply(id, ["ok": false, "error": "\(error)"]) }
  }
}

Thread {
  while let line = readLine() {
    guard let d = line.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { continue }
    handle(o)
  }
  // stdin closed: the cockpit is gone.
  if buttonDown { mouseButton(false, at: current(), clickState: 1) }
  exit(0)
}.start()

let app = NSApplication.shared
app.setActivationPolicy(.accessory)   // no Dock icon, never takes focus
app.run()
