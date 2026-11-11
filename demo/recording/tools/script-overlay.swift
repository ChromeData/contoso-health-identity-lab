// script-overlay: the presenter's view. A floating card at the top centre of
// the screen, right under the camera, so his eyes stay near the lens. It is
// click-through, above every window, on every Space, and HIDDEN from screen
// capture (sharingType .none), so OBS never records it.
//
// It shows: the current line, point by point, each point ticked off softly as
// speech tracking hears its meaning; a faint preview of the next line; part
// and step progress; a status light (green = talk, amber = cockpit busy or
// loading, red = needs you) with a 2-3 word reason; the take's elapsed time;
// a "re-say" marker on points he went past. Compact mode: one line only.
//
// Global hotkeys (Carbon RegisterEventHotKey: no window focus and no
// Accessibility or Input Monitoring permission needed):
//   ⌃⌥→ or ⌃⌥Space next · ⌃⌥← back · ⌃⌥R redo · ⌃⌥P pause/resume ·
//   ⌃⌥C compact on/off · ⌃⌥H hide/show the card
//   with --clicker also bare PageDown / PageUp (a presentation clicker).
//
// stdin: one JSON state per line (lib/presenter.mjs), {"hide":true} hides it.
// stdout: one JSON event per line, e.g. {"key":"next"}.
//
//   swiftc -O tools/script-overlay.swift -o tools/script-overlay
import AppKit
import Carbon

struct Point { var text: String; var state: String }   // done | todo | hot | missed

final class Card: NSView {
  var part = "", step = "", partProg: Double = 0
  var points: [Point] = [], next = "", nextNew = false
  var light = "amber", reason = "", resay = "", banner = ""
  var t0: Double = 0, pausedAt: Double = 0, paused = false, compact = false
  override var isFlipped: Bool { true }

  let W = NSColor.white
  func a(_ size: CGFloat, _ weight: NSFont.Weight, _ alpha: CGFloat, color: NSColor = .white) -> [NSAttributedString.Key: Any] {
    let p = NSMutableParagraphStyle(); p.lineSpacing = 2
    return [.font: NSFont.systemFont(ofSize: size, weight: weight), .foregroundColor: color.withAlphaComponent(alpha), .paragraphStyle: p]
  }
  var lightColor: NSColor {
    switch light {
    case "green": return NSColor(calibratedRed: 0.27, green: 0.84, blue: 0.45, alpha: 1)
    case "red": return NSColor(calibratedRed: 0.98, green: 0.32, blue: 0.30, alpha: 1)
    case "off": return NSColor(calibratedWhite: 0.6, alpha: 1)
    default: return NSColor(calibratedRed: 0.98, green: 0.72, blue: 0.20, alpha: 1)
    }
  }
  var elapsed: String {
    if t0 <= 0 { return "--:--" }
    let now = paused && pausedAt > 0 ? pausedAt : Date().timeIntervalSince1970 * 1000
    let s = max(0, Int((now - t0) / 1000))
    return String(format: "%d:%02d", s / 60, s % 60)
  }
  // The box never changes size (owner, 2026-11-10): 520 x 210 pt (compact
  // 520 x 112). Long lines shrink a step or two; if still too long the body
  // scrolls to the point being said and fades at its edges.
  static let BOXW: CGFloat = 520, BOXH: CGFloat = 210, COMPACTH: CGFloat = 112
  func body(_ size: CGFloat) -> NSAttributedString {
    let s = NSMutableAttributedString()
    let green = NSColor(calibratedRed: 0.45, green: 0.86, blue: 0.55, alpha: 1)
    let amber = NSColor(calibratedRed: 1.0, green: 0.74, blue: 0.30, alpha: 1)
    var list = points
    if compact, let k = points.firstIndex(where: { $0.state == "hot" || $0.state == "missed" || $0.state == "todo" }) { list = [points[k]] }
    for (k, p) in list.enumerated() {
      if k > 0 { s.append(NSAttributedString(string: "  ", attributes: a(size, .regular, 1))) }
      switch p.state {
      case "done":
        s.append(NSAttributedString(string: "✓ ", attributes: a(size * 0.7, .semibold, 0.85, color: green)))
        s.append(NSAttributedString(string: p.text, attributes: a(size, .regular, 0.42)))
      case "missed":
        s.append(NSAttributedString(string: "↺ ", attributes: a(size * 0.7, .semibold, 0.95, color: amber)))
        var at = a(size, .medium, 0.95, color: NSColor(calibratedRed: 1, green: 0.88, blue: 0.70, alpha: 1))
        at[.underlineStyle] = NSUnderlineStyle.single.rawValue | NSUnderlineStyle.patternDot.rawValue
        at[.underlineColor] = amber.withAlphaComponent(0.8)
        s.append(NSAttributedString(string: p.text, attributes: at))
      case "hot":
        s.append(NSAttributedString(string: p.text, attributes: a(size, .semibold, 1)))
      default:
        s.append(NSAttributedString(string: p.text, attributes: a(size, .regular, 0.82)))
      }
    }
    return s
  }
  // Where the hot (or first missed / unsaid) point starts in the body text.
  func hotOffset() -> Int {
    var n = 0
    var list = points
    if compact { return 0 }
    for p in list { if p.state == "hot" || p.state == "missed" { return n }; n += p.text.count + 2 + (p.state == "done" || p.state == "missed" ? 2 : 0) }
    list = []
    return 0
  }
  var boxH: CGFloat { compact ? Card.COMPACTH : Card.BOXH }
  // The body's frame inside the fixed box.
  var bodyRect: NSRect {
    let top: CGFloat = 44
    let bottom: CGFloat = compact ? 10 : (banner.isEmpty ? 50 : 70)
    return NSRect(x: 18, y: top, width: Card.BOXW - 36, height: boxH - top - bottom)
  }
  // The largest size (21 down to 15) at which the body fits; else 15.
  func fitSize() -> CGFloat {
    let r = bodyRect
    for sz in stride(from: compact ? 20 : 21, through: 15, by: -1) {
      let h = body(CGFloat(sz)).boundingRect(with: NSSize(width: r.width, height: 4000), options: [.usesLineFragmentOrigin]).height
      if h <= r.height { return CGFloat(sz) }
    }
    return 15
  }
  func nextStr() -> NSAttributedString {
    let p = NSMutableParagraphStyle(); p.lineBreakMode = .byTruncatingTail
    let s = NSMutableAttributedString(string: nextNew ? "next part ▸ " : "next ▸ ", attributes: [.font: NSFont.systemFont(ofSize: 11.5, weight: .semibold), .foregroundColor: NSColor.white.withAlphaComponent(0.32), .paragraphStyle: p])
    s.append(NSAttributedString(string: next, attributes: [.font: NSFont.systemFont(ofSize: 13, weight: .regular), .foregroundColor: NSColor.white.withAlphaComponent(0.36), .paragraphStyle: p]))
    return s
  }
  override func draw(_ r: NSRect) {
    let bg = NSBezierPath(roundedRect: bounds.insetBy(dx: 1, dy: 1), xRadius: 16, yRadius: 16)
    NSColor(calibratedWhite: 0.06, alpha: 0.86).setFill(); bg.fill()
    lightColor.withAlphaComponent(light == "red" ? 0.55 : 0.18).setStroke(); bg.lineWidth = light == "red" ? 2 : 1; bg.stroke()
    // Header: light + reason · part · step · elapsed, one line.
    lightColor.setFill(); NSBezierPath(ovalIn: NSRect(x: 16, y: 13, width: 11, height: 11)).fill()
    let reasonS = NSAttributedString(string: paused ? "PAUSED" : reason, attributes: a(12.5, .bold, 0.95, color: paused ? NSColor.white : lightColor))
    reasonS.draw(at: NSPoint(x: 33, y: 10))
    let right = NSAttributedString(string: "\(step)   \(elapsed)", attributes: a(12, .semibold, 0.6))
    let rs = right.size()
    right.draw(at: NSPoint(x: bounds.width - 16 - rs.width, y: 11))
    let left = 33 + reasonS.size().width + 12, room = bounds.width - 16 - rs.width - 12 - left
    if room > 30 {
      let pp = NSMutableParagraphStyle(); pp.lineBreakMode = .byTruncatingTail; pp.alignment = .center
      NSAttributedString(string: part, attributes: [.font: NSFont.systemFont(ofSize: 12, weight: .semibold), .foregroundColor: NSColor.white.withAlphaComponent(0.55), .paragraphStyle: pp])
        .draw(with: NSRect(x: left, y: 11, width: room, height: 16), options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine])
    }
    // Part progress: a hairline under the header.
    NSColor(calibratedWhite: 1, alpha: 0.08).setFill()
    NSBezierPath(rect: NSRect(x: 16, y: 33, width: bounds.width - 32, height: 2)).fill()
    lightColor.withAlphaComponent(0.55).setFill()
    NSBezierPath(rect: NSRect(x: 16, y: 33, width: (bounds.width - 32) * CGFloat(max(0, min(1, partProg))), height: 2)).fill()
    // The body: fitted, clipped to its frame; scrolled to the hot point if it
    // still does not fit, with a soft fade at the clipped edge(s).
    let br = bodyRect, size = fitSize(), txt = body(size)
    let full = txt.boundingRect(with: NSSize(width: br.width, height: 4000), options: [.usesLineFragmentOrigin]).height
    var shift: CGFloat = 0
    if full > br.height {
      let off = min(hotOffset(), txt.length)
      let before = txt.attributedSubstring(from: NSRange(location: 0, length: off))
      let hb = before.length > 0 ? before.boundingRect(with: NSSize(width: br.width, height: 4000), options: [.usesLineFragmentOrigin]).height : 0
      shift = max(0, min(full - br.height, hb - size * 1.4))
    }
    NSGraphicsContext.saveGraphicsState()
    NSBezierPath(rect: br).addClip()
    txt.draw(with: NSRect(x: br.minX, y: br.minY - shift, width: br.width, height: full), options: [.usesLineFragmentOrigin])
    NSGraphicsContext.restoreGraphicsState()
    let bgc = NSColor(calibratedWhite: 0.06, alpha: 0.86)
    if shift > 0, let g = NSGradient(starting: bgc, ending: bgc.withAlphaComponent(0)) { g.draw(in: NSRect(x: br.minX, y: br.minY, width: br.width, height: 14), angle: 90) }
    if full - shift > br.height + 1, let g = NSGradient(starting: bgc.withAlphaComponent(0), ending: bgc) { g.draw(in: NSRect(x: br.minX, y: br.maxY - 16, width: br.width, height: 16), angle: 90) }
    if compact { return }
    var y = br.maxY + 6
    if !banner.isEmpty {
      let pp = NSMutableParagraphStyle(); pp.lineBreakMode = .byTruncatingTail
      NSAttributedString(string: banner, attributes: [.font: NSFont.systemFont(ofSize: 12, weight: .medium), .foregroundColor: NSColor(calibratedRed: 1, green: 0.74, blue: 0.3, alpha: 0.95), .paragraphStyle: pp])
        .draw(with: NSRect(x: 18, y: y, width: bounds.width - 36, height: 17), options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine])
      y += 20
    }
    if !next.isEmpty { nextStr().draw(with: NSRect(x: 18, y: y, width: bounds.width - 36, height: 18), options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine]) }
    let hint = (resay.isEmpty ? "" : "↺ \(resay)   ") + "⌃⌥→ next  ⌃⌥← back  ⌃⌥R redo  ⌃⌥P pause  ⌃⌥C compact"
    let pp = NSMutableParagraphStyle(); pp.lineBreakMode = .byTruncatingTail
    NSAttributedString(string: hint, attributes: [.font: NSFont.systemFont(ofSize: 9.5, weight: .medium), .foregroundColor: NSColor.white.withAlphaComponent(resay.isEmpty ? 0.26 : 0.5), .paragraphStyle: pp])
      .draw(with: NSRect(x: 18, y: boxH - 19, width: bounds.width - 36, height: 13), options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine])
  }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let clicker = CommandLine.arguments.contains("--clicker")
// The camera sits at the top centre of the built-in display: the card goes
// right under the menu bar of the main screen (the one with the menu bar).
let scr = NSScreen.screens.first ?? NSScreen.main!
let vis = scr.visibleFrame
let W: CGFloat = Card.BOXW
let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 520, height: 210), styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
panel.isOpaque = false; panel.backgroundColor = .clear; panel.hasShadow = false
panel.ignoresMouseEvents = true
panel.level = .screenSaver
panel.collectionBehavior = [.canJoinAllSpaces, .stationary, .fullScreenAuxiliary, .ignoresCycle]
panel.sharingType = .none                 // hidden from OBS / screenshots
let card = Card(frame: NSRect(x: 0, y: 0, width: 520, height: 210))
panel.contentView = card
var hiddenByKey = false, shown = false

func place() {
  let w = W, h = card.boxH
  panel.setFrame(NSRect(x: vis.midX - w / 2, y: vis.maxY - h - 4, width: w, height: h), display: true)
  card.frame = NSRect(x: 0, y: 0, width: w, height: h); card.needsDisplay = true
}
func emit(_ o: [String: Any]) {
  if let d = try? JSONSerialization.data(withJSONObject: o), let s = String(data: d, encoding: .utf8) { print(s); fflush(stdout) }
}

// ---- global hotkeys (Carbon) ----
let keys: [(UInt32, UInt32, String)] = {
  let co = UInt32(controlKey | optionKey)
  var k: [(UInt32, UInt32, String)] = [(124, co, "next"), (49, co, "next"), (123, co, "back"), (15, co, "redo"), (35, co, "pause"), (8, co, "compact"), (4, co, "hide")]
  if clicker { k += [(121, 0, "next"), (116, 0, "back")] }
  return k
}()
var refs: [EventHotKeyRef?] = []
var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
InstallEventHandler(GetApplicationEventTarget(), { _, ev, _ in
  var hk = EventHotKeyID()
  GetEventParameter(ev, EventParamName(kEventParamDirectObject), EventParamType(typeEventHotKeyID), nil, MemoryLayout<EventHotKeyID>.size, nil, &hk)
  let i = Int(hk.id)
  if i >= 0 && i < keys.count {
    let what = keys[i].2
    if what == "compact" { card.compact.toggle(); place() }
    else if what == "hide" { hiddenByKey.toggle(); if hiddenByKey { panel.orderOut(nil) } else if shown { panel.orderFrontRegardless() } }
    emit(["key": what])
  }
  return noErr
}, 1, &spec, nil, nil)
for (i, k) in keys.enumerated() {
  var ref: EventHotKeyRef?
  let st = RegisterEventHotKey(k.0, k.1, EventHotKeyID(signature: OSType(0x434B5054), id: UInt32(i)), GetApplicationEventTarget(), 0, &ref)
  if st != noErr { emit(["warn": "hotkey \(k.2) (code \(k.0)) not registered: \(st)"]) }
  refs.append(ref)
}
emit(["ready": true, "hotkeys": keys.count])

// --render out.png: draw the card for the first stdin state into a PNG and
// exit (the card itself is invisible to screenshots, so this is how to see it).
if let i = CommandLine.arguments.firstIndex(of: "--render"), i + 1 < CommandLine.arguments.count {
  let out = CommandLine.arguments[i + 1]
  if let line = readLine(), let d = line.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] {
    card.part = o["part"] as? String ?? ""; card.step = o["step"] as? String ?? ""; card.partProg = o["partProg"] as? Double ?? 0
    card.points = (o["points"] as? [[String: Any]] ?? []).map { Point(text: $0["text"] as? String ?? "", state: $0["state"] as? String ?? "todo") }
    card.next = o["next"] as? String ?? ""; card.light = o["light"] as? String ?? "amber"; card.reason = o["reason"] as? String ?? ""
    card.resay = o["resay"] as? String ?? ""; card.banner = o["banner"] as? String ?? ""; card.t0 = o["t0"] as? Double ?? 0; card.compact = o["compact"] as? Bool ?? false
    let w = W, h = card.boxH
    card.frame = NSRect(x: 0, y: 0, width: w, height: h)
    let rep = card.bitmapImageRepForCachingDisplay(in: card.bounds)!
    card.cacheDisplay(in: card.bounds, to: rep)
    try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: out))
  }
  exit(0)
}

// The elapsed time ticks by itself.
Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { _ in if shown && !hiddenByKey { card.needsDisplay = true } }

DispatchQueue.global().async {
  while let line = readLine() {
    guard let d = line.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { continue }
    DispatchQueue.main.async {
      if o["hide"] as? Bool == true { shown = false; panel.orderOut(nil); return }
      card.part = o["part"] as? String ?? ""; card.step = o["step"] as? String ?? ""
      card.partProg = o["partProg"] as? Double ?? 0
      card.points = (o["points"] as? [[String: Any]] ?? []).map { Point(text: $0["text"] as? String ?? "", state: $0["state"] as? String ?? "todo") }
      // Back-compat: {"lines": [...], "hot": n}
      if card.points.isEmpty, let ls = o["lines"] as? [String] { card.points = ls.map { Point(text: $0, state: "todo") } }
      card.next = o["next"] as? String ?? ""; card.nextNew = o["nextNew"] as? Bool ?? false
      card.light = o["light"] as? String ?? "amber"; card.reason = o["reason"] as? String ?? ""
      card.resay = o["resay"] as? String ?? ""; card.banner = o["banner"] as? String ?? ""
      card.t0 = o["t0"] as? Double ?? 0; card.paused = o["paused"] as? Bool ?? false; card.pausedAt = o["pausedAt"] as? Double ?? 0
      if let c = o["compact"] as? Bool { card.compact = c }
      shown = true
      place(); if !hiddenByKey { panel.orderFrontRegardless() }
    }
  }
  exit(0)
}
signal(SIGTERM) { _ in exit(0) }
app.run()
