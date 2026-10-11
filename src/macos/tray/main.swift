import AppKit

let app = NSApplication.shared
let delegate = JwtTrayDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
