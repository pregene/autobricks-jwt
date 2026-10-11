import AppKit

final class SetupWindowController: NSWindowController {
    private let tcp = NSButton(checkboxWithTitle: "TCP", target: nil, action: nil)
    private let tls = NSButton(checkboxWithTitle: "TLS", target: nil, action: nil)
    private let mtls = NSButton(checkboxWithTitle: "Mutual TLS", target: nil, action: nil)
    private let pki = NSButton(checkboxWithTitle: "Autobricks PKI", target: nil, action: nil)
    private let truelog = NSButton(checkboxWithTitle: "Autobricks TrueLog", target: nil, action: nil)
    private let requestLog = NSButton(checkboxWithTitle: "Request log", target: nil, action: nil)
    private let queryLog = NSButton(checkboxWithTitle: "Query log", target: nil, action: nil)
    private let issuanceLog = NSButton(checkboxWithTitle: "Issuance log", target: nil, action: nil)
    private let auditLog = NSButton(checkboxWithTitle: "Audit log", target: nil, action: nil)
    private let requireToken = NSButton(checkboxWithTitle: "Require complete token for query and revocation", target: nil, action: nil)
    private let backup = NSTextField(string: "/usr/local/var/backups/autobricks-jwt")
    private let interval = NSTextField(string: "30")
    private let timeout = NSTextField(string: "3600")
    private let renewal = NSTextField(string: "04:00")
    private let tcpAddress = NSTextField(string: "127.0.0.1:7001")
    private let tlsAddress = NSTextField(string: "0.0.0.0:7002")
    private let mtlsAddress = NSTextField(string: "0.0.0.0:7003")
    private let pkiIssuer = NSPopUpButton(frame: .zero, pullsDown: false)
    private let certificateAddress = NSTextField(string: "127.0.0.1")
    private let certificate = NSTextField(string: "/usr/local/etc/autobricks-jwt/certificate.pem")
    private let privateKey = NSTextField(string: "/usr/local/etc/autobricks-jwt/private-key.pem")
    private let serverChain = NSTextField(string: "/usr/local/etc/autobricks-jwt/server-trust-chain.pem")
    private let clientChain = NSTextField(string: "/usr/local/etc/autobricks-jwt/client-trust-chain.pem")
    private let status = NSTextField(wrappingLabelWithString: "")
    private let installButton = NSButton(title: "Apply", target: nil, action: nil)
    private let closeButton = NSButton(title: "Close", target: nil, action: nil)
    private let configuredMarker = "/usr/local/share/autobricks-jwt/configured"

    init() {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 760, height: 720), styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        super.init(window: window)
        configure(window)
    }

    @available(*, unavailable) required init?(coder: NSCoder) { nil }

    func show() {
        refreshDependencies()
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    private func configure(_ window: NSWindow) {
        window.title = "Autobricks JWT Setup"
        window.center()
        window.isReleasedWhenClosed = false
        [requestLog, queryLog, issuanceLog, requireToken].forEach { $0.state = .on }
        installButton.target = self
        installButton.action = #selector(apply)
        installButton.keyEquivalent = "\r"
        closeButton.target = self
        closeButton.action = #selector(closeWindow)

        let unix = NSTextField(labelWithString: "UNIX (required and always enabled)")
        unix.font = .boldSystemFont(ofSize: NSFont.systemFontSize)
        let transport = NSStackView(views: [unix, tcp, tls, mtls])
        transport.orientation = .horizontal
        transport.spacing = 18
        let integrations = NSStackView(views: [pki, truelog])
        integrations.orientation = .horizontal
        integrations.spacing = 24
        let logs = NSStackView(views: [requestLog, queryLog, issuanceLog, auditLog])
        logs.orientation = .horizontal
        logs.spacing = 16

        let grid = NSGridView(views: [
            row("Security integrations", integrations), row("Service transports", transport),
            row("TCP address", tcpAddress), row("TLS address", tlsAddress), row("mTLS address", mtlsAddress),
            row("PKI issuer", pkiIssuer), row("Server certificate IP", certificateAddress),
            row("Session timeout", timeout), row("Backup directory", backup), row("Backup interval days", interval),
            row("Server certificate", certificate), row("Server private key", privateKey),
            row("Server trust chain", serverChain), row("Client trust chain", clientChain),
            row("Daily certificate check", renewal), row("Logging", logs), row("Token validation", requireToken),
        ])
        grid.rowSpacing = 10
        grid.columnSpacing = 18
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).width = 510

        let title = NSTextField(labelWithString: "Autobricks JWT")
        title.font = .boldSystemFont(ofSize: 24)
        let note = NSTextField(wrappingLabelWithString: "SoftHSM2 is required. UNIX is always enabled. TLS and mutual TLS are available only when Autobricks PKI is installed and selected.")
        note.textColor = .secondaryLabelColor
        status.textColor = .secondaryLabelColor
        let buttonRow = NSView()
        buttonRow.translatesAutoresizingMaskIntoConstraints = false
        installButton.translatesAutoresizingMaskIntoConstraints = false
        closeButton.translatesAutoresizingMaskIntoConstraints = false
        buttonRow.addSubview(installButton)
        buttonRow.addSubview(closeButton)
        NSLayoutConstraint.activate([
            buttonRow.widthAnchor.constraint(equalToConstant: 700),
            buttonRow.heightAnchor.constraint(equalTo: installButton.heightAnchor),
            closeButton.trailingAnchor.constraint(equalTo: buttonRow.trailingAnchor),
            installButton.trailingAnchor.constraint(equalTo: closeButton.leadingAnchor, constant: -12),
            installButton.topAnchor.constraint(equalTo: buttonRow.topAnchor),
            closeButton.centerYAnchor.constraint(equalTo: installButton.centerYAnchor),
        ])
        let stack = NSStackView(views: [title, note, grid, status, buttonRow])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 18
        stack.edgeInsets = NSEdgeInsets(top: 24, left: 28, bottom: 24, right: 28)
        stack.translatesAutoresizingMaskIntoConstraints = false
        window.contentView?.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor),
            stack.topAnchor.constraint(equalTo: window.contentView!.topAnchor),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: window.contentView!.bottomAnchor),
            status.widthAnchor.constraint(equalToConstant: 700),
        ])
        [tcp, tls, mtls, pki, truelog].forEach { $0.target = self; $0.action = #selector(selectionChanged) }
    }

    private func row(_ label: String, _ view: NSView) -> [NSView] {
        let field = NSTextField(labelWithString: label)
        field.font = .systemFont(ofSize: NSFont.systemFontSize, weight: .medium)
        return [field, view]
    }

    private func commandExists(_ path: String) -> Bool { FileManager.default.isExecutableFile(atPath: path) }

    private func pkiExecutable() -> String? {
        ["/usr/local/bin/abpki-cli", "/opt/homebrew/bin/abpki-cli"].first(where: commandExists)
    }

    private func loadPKIIssuers() {
        pkiIssuer.removeAllItems()
        guard let executable = pkiExecutable() else { return }
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = ["list-ca", "valid"]
        process.standardOutput = output
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return }
            let data = output.fileHandleForReading.readDataToEndOfFile()
            guard let text = String(data: data, encoding: .utf8) else { return }
            let issuers = text.split(separator: "\n").compactMap { line -> String? in
                let fields = line.split(whereSeparator: { $0.isWhitespace }).map(String.init)
                guard let status = fields.firstIndex(of: "VALID"), status > 1 else { return nil }
                return fields[1..<status].joined(separator: " ")
            }
            pkiIssuer.addItems(withTitles: Array(Set(issuers)).sorted())
        } catch {
            pkiIssuer.removeAllItems()
        }
    }

    private func refreshDependencies() {
        let softHsm = commandExists("/opt/homebrew/bin/softhsm2-util") || commandExists("/usr/local/bin/softhsm2-util")
        let hasPki = commandExists("/usr/local/bin/abpki-cli") || commandExists("/opt/homebrew/bin/abpki-cli")
        let hasTrueLog = commandExists("/usr/local/bin/ab-truelog-cli") || commandExists("/opt/homebrew/bin/ab-truelog-cli")
        pki.isEnabled = hasPki
        if hasPki { loadPKIIssuers() }
        truelog.isEnabled = hasTrueLog
        if !hasPki { pki.state = .off; tls.state = .off; mtls.state = .off }
        if !hasTrueLog { truelog.state = .off; auditLog.state = .off }
        let configured = FileManager.default.fileExists(atPath: configuredMarker)
        installButton.isEnabled = softHsm && !configured
        status.stringValue = configured ? "Configuration is active." : (softHsm ? "Ready for configuration." : "SoftHSM2 was not found. Configuration cannot continue.")
        selectionChanged()
        if configured { setConfigurationControlsEnabled(false) }
    }

    private func setConfigurationControlsEnabled(_ enabled: Bool) {
        [tcp, tls, mtls, pki, truelog, requestLog, queryLog, issuanceLog, auditLog, requireToken].forEach { $0.isEnabled = enabled }
        [backup, interval, timeout, renewal, tcpAddress, tlsAddress, mtlsAddress,
         certificateAddress, certificate, privateKey, serverChain, clientChain].forEach { $0.isEnabled = enabled }
        pkiIssuer.isEnabled = enabled
    }

    @objc private func closeWindow() {
        window?.close()
    }

    @objc private func selectionChanged() {
        let secure = pki.state == .on && pki.isEnabled
        tls.isEnabled = secure
        mtls.isEnabled = secure
        if !secure { tls.state = .off; mtls.state = .off }
        auditLog.isEnabled = truelog.state == .on && truelog.isEnabled
        if !auditLog.isEnabled { auditLog.state = .off }
        [tcpAddress].forEach { $0.isEnabled = tcp.state == .on }
        tlsAddress.isEnabled = tls.state == .on
        mtlsAddress.isEnabled = mtls.state == .on
        [certificateAddress, certificate, privateKey, serverChain, renewal].forEach { $0.isEnabled = tls.state == .on || mtls.state == .on }
        clientChain.isEnabled = mtls.state == .on
        pkiIssuer.isEnabled = pki.state == .on
    }

    @objc private func apply() {
        guard let days = Int(interval.stringValue), (7...30).contains(days),
              let seconds = Int(timeout.stringValue), (1...86400).contains(seconds) else {
            showResult("Configuration Invalid", "Backup interval must be 7 through 30 days and timeout must be 1 through 86400 seconds.")
            return
        }
        let formatter = DateFormatter(); formatter.dateFormat = "HH:mm"
        guard formatter.date(from: renewal.stringValue) != nil else {
            showResult("Configuration Invalid", "Daily certificate check time must use HH:MM.")
            return
        }
        if pki.state == .on && pkiIssuer.selectedItem == nil {
            showResult("Configuration Invalid", "No valid Autobricks PKI issuer is available.")
            return
        }
        var transports = ["UNIX"]
        if tcp.state == .on { transports.append("TCP") }
        if tls.state == .on { transports.append("TLS") }
        if mtls.state == .on { transports.append("MTLS") }
        let body: [String: Any] = [
            "runtime_transports": transports, "tcp_address": tcpAddress.stringValue,
            "tls_address": tlsAddress.stringValue, "mtls_address": mtlsAddress.stringValue,
            "timeout": seconds, "backup_directory": backup.stringValue, "backup_interval_days": days,
            "server_certificate": certificate.stringValue, "server_private_key": privateKey.stringValue,
            "server_trust_chain": serverChain.stringValue, "client_trust_chain": clientChain.stringValue,
            "certificate_renewal_time": renewal.stringValue,
            "use_pki": pki.state == .on, "use_truelog": truelog.state == .on,
            "pki_issuer": pkiIssuer.selectedItem?.title ?? "",
            "server_certificate_ip": certificateAddress.stringValue,
            "log_request": requestLog.state == .on, "log_query": queryLog.state == .on,
            "log_issuance": issuanceLog.state == .on, "log_audit": auditLog.state == .on,
            "require_token": requireToken.state == .on,
        ]
        installButton.isEnabled = false
        status.stringValue = "Applying configuration and initializing protected storage…"
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let data = try JSONSerialization.data(withJSONObject: body)
                let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("autobricks-jwt-setup-\(UUID().uuidString).json")
                try data.write(to: temporary, options: [.atomic, .completeFileProtection])
                defer { try? FileManager.default.removeItem(at: temporary) }
                let command = "/usr/local/libexec/autobricks-jwt-setup " + self!.shellQuote(temporary.path)
                let script = NSAppleScript(source: "do shell script \"\(self!.appleQuote(command))\" with administrator privileges")
                var error: NSDictionary?
                let output = script?.executeAndReturnError(&error).stringValue
                if let error {
                    let message = error["NSAppleScriptErrorMessage"] as? String ?? "Administrator configuration failed."
                    throw NSError(domain: "AutobricksJWTSetup", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
                }
                DispatchQueue.main.async {
                    self?.installButton.isEnabled = false
                    self?.status.stringValue = "Configuration is active."
                    self?.setConfigurationControlsEnabled(false)
                    self?.showResult("Configuration Complete", output ?? "Autobricks JWT is configured and running.")
                    self?.window?.close()
                }
            } catch {
                DispatchQueue.main.async {
                    self?.installButton.isEnabled = true
                    self?.status.stringValue = "Configuration failed."
                    self?.showResult("Configuration Failed", error.localizedDescription)
                }
            }
        }
    }

    private func shellQuote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    private func appleQuote(_ value: String) -> String { value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") }
    private func showResult(_ title: String, _ detail: String) { let alert = NSAlert(); alert.messageText = title; alert.informativeText = detail; alert.runModal() }
}
