// cursor-ring: a yellow, semi-transparent ring (about 40 px) that follows the
// mouse everywhere, for the recording. Click-through, above every window, on
// every Space (also full-screen ones), and visible to OBS display capture.
// It follows the real system pointer, so it works whether the cockpit or the
// owner moves the mouse. Started and stopped by the cockpit (lib/ring.mjs).
//
//   swiftc -O tools/cursor-ring.swift -o tools/cursor-ring
//   tools/cursor-ring [--size 40]
import AppKit

let args = CommandLine.arguments
var size: CGFloat = 40
if let i = args.firstIndex(of: "--size"), i + 1 < args.count, let v = Double(args[i + 1]) { size = CGFloat(v) }

final class RingView: NSView {
  override func draw(_ dirtyRect: NSRect) {
    let inset: CGFloat = 3
    let path = NSBezierPath(ovalIn: bounds.insetBy(dx: inset, dy: inset))
    NSColor(calibratedRed: 1.0, green: 0.84, blue: 0.0, alpha: 0.22).setFill()
    path.fill()
    path.lineWidth = 3
    NSColor(calibratedRed: 1.0, green: 0.78, blue: 0.0, alpha: 0.85).setStroke()
    path.stroke()
  }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)   // no Dock icon, never takes focus

let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: size, height: size),
                    styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
panel.isOpaque = false
panel.backgroundColor = .clear
panel.hasShadow = false
panel.ignoresMouseEvents = true          // click-through
panel.level = .screenSaver               // above every normal window
panel.collectionBehavior = [.canJoinAllSpaces, .stationary, .fullScreenAuxiliary, .ignoresCycle]
panel.sharingType = .readOnly            // screen capture (OBS) sees it
panel.contentView = RingView(frame: NSRect(x: 0, y: 0, width: size, height: size))
panel.orderFrontRegardless()

// Follow the pointer: polled at 60 Hz (needs no Accessibility permission and
// sees every move, by a person or by software).
Timer.scheduledTimer(withTimeInterval: 1.0 / 60.0, repeats: true) { _ in
  let p = NSEvent.mouseLocation
  panel.setFrameOrigin(NSPoint(x: p.x - size / 2, y: p.y - size / 2))
}
signal(SIGTERM) { _ in exit(0) }
app.run()
