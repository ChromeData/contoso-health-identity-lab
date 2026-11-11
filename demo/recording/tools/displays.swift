// Active displays as JSON: CoreGraphics id, UUID (what OBS's screen_capture
// source wants as display_uuid), main or not, name, size. Run by lib/displays.mjs:
//   swift tools/displays.swift

import AppKit
import ApplicationServices
var ids = [CGDirectDisplayID](repeating: 0, count: 16)
var n: UInt32 = 0
CGGetActiveDisplayList(16, &ids, &n)
let main = CGMainDisplayID()
var out: [[String: Any]] = []
for i in 0..<Int(n) {
  let id = ids[i]
  guard let u = CGDisplayCreateUUIDFromDisplayID(id)?.takeRetainedValue() else { continue }
  let uuid = CFUUIDCreateString(nil, u) as String
  var name = ""
  for s in NSScreen.screens { if let num = s.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber, num.uint32Value == id { name = s.localizedName } }
  out.append(["id": Int(id), "uuid": uuid, "main": id == main, "name": name, "w": CGDisplayPixelsWide(id), "h": CGDisplayPixelsHigh(id)])
}
let data = try! JSONSerialization.data(withJSONObject: out)
print(String(data: data, encoding: .utf8)!)
