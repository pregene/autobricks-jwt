import AppKit

final class JwtTrayDelegate: NSObject, NSApplicationDelegate {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let setup = SetupWindowController()

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem.button?.image = NSImage(systemSymbolName: "key.horizontal", accessibilityDescription: "Autobricks JWT")
        let menu = NSMenu()
        menu.addItem(withTitle: "Settings", action: #selector(showSettings), keyEquivalent: ",")
        menu.addItem(withTitle: "Uninstall Autobricks JWT…", action: #selector(uninstall), keyEquivalent: "")
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit", action: #selector(quit), keyEquivalent: "q")
        menu.items.forEach { $0.target = self }
        statusItem.menu = menu
        showSettings()
    }

    @objc private func showSettings() {
        setup.show()
    }

    @objc private func quit() {
        NSApplication.shared.terminate(nil)
    }

    @objc private func uninstall() {
        let confirmation = NSAlert()
        confirmation.messageText = "Uninstall Autobricks JWT?"
        confirmation.informativeText = "This removes the services, application, configuration, SQLCipher data, backups, HSM objects, logs, sockets, and package receipt. External TrueLog evidence is not changed."
        confirmation.addButton(withTitle: "Uninstall")
        confirmation.addButton(withTitle: "Cancel")
        guard confirmation.runModal() == .alertFirstButtonReturn else { return }
        let command = "/usr/local/libexec/autobricks-jwt-uninstall"
        let script = NSAppleScript(source: "do shell script \"\(command)\" with administrator privileges")
        var error: NSDictionary?
        let output = script?.executeAndReturnError(&error).stringValue
        if let error {
            let alert = NSAlert(); alert.messageText = "Uninstall Failed"; alert.informativeText = error.description; alert.runModal()
            return
        }
        let alert = NSAlert(); alert.messageText = "Uninstall Complete"; alert.informativeText = output ?? "Autobricks JWT was completely removed."; alert.runModal()
        NSApplication.shared.terminate(nil)
    }
}
