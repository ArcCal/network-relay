import AppKit
import NetworkRelayNFModel
import SwiftUI
import UniformTypeIdentifiers

/// Network Relay NF: a main window to set up and watch the tunnel, and a menu-bar
/// item to switch it on and off. Closing the window keeps the proxy
/// running in the menu bar. It runs a native SOCKS5 proxy and
/// changes nothing else on the Mac.
@main
struct NetworkRelayNFApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var tunnel = TunnelController.shared

    var body: some Scene {
        Window("Network Relay NF", id: "main") {
            MainWindow().environmentObject(tunnel)
        }
        .windowResizability(.contentMinSize)
        .defaultSize(width: 940, height: 660)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
        MenuBarExtra {
            MenuPanel().environmentObject(tunnel)
        } label: {
            Image(systemName: tunnel.status.symbol)
        }
        .menuBarExtraStyle(.window)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        // Keep macOS from saving window state for the app (in memory only,
        // nothing is written).
        UserDefaults.standard.register(defaults: [
            "NSQuitAlwaysKeepsWindows": false,
            "ApplePersistenceIgnoreState": true,
        ])
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        quitOnSIGTERM()
        // Connects only if the user enabled the launch option.
        TunnelController.shared.launched()
    }

    private var terminationSignal: DispatchSourceSignal?

    /// Give this instance's native connections the normal asynchronous
    /// cleanup path when the application receives SIGTERM.
    private func quitOnSIGTERM() {
        // Dispatch handles termination on the main queue.
        signal(SIGTERM) { _ in }
        let source = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        source.setEventHandler {
            Task { @MainActor in NSApp.terminate(nil) }
        }
        source.resume()
        terminationSignal = source
    }

    /// The proxy keeps running in the menu bar when the window closes.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        TunnelController.shared.requestQuit()
    }

    /// Stops only this app instance's native connections.
    func applicationWillTerminate(_ notification: Notification) {
        TunnelController.shared.stopForQuit()
    }
}

/// The Dock icon shows only while the main window is open.
@MainActor
func showInDock(_ shown: Bool) {
    NSApp.setActivationPolicy(shown ? .regular : .accessory)
    if shown {
        NSApp.activate(ignoringOtherApps: true)
    }
}

// MARK: - Look

extension Status {
    /// The menu-bar icon.
    var symbol: String {
        switch self {
        case .stopped: return "shield.slash"
        case .connecting, .reconnecting: return "shield.lefthalf.filled"
        case .connected: return "checkmark.shield.fill"
        case .failed: return "exclamationmark.shield"
        }
    }

    var tint: Color {
        switch self {
        case .stopped: return .gray
        case .connecting: return .blue
        case .connected: return .green
        case .reconnecting: return .orange
        case .failed: return .red
        }
    }

    /// Waiting for the tunnel: the ring turns.
    var isBusy: Bool {
        switch self {
        case .connecting, .reconnecting: return true
        default: return false
        }
    }
}

// MARK: - Main window

enum Tab: Hashable {
    case settings, log, about

    var title: String {
        switch self {
        case .settings: return "Settings"
        case .log: return "Log"
        case .about: return "About"
        }
    }

    var detail: String {
        switch self {
        case .settings: return "Servers and your local proxy"
        case .log: return "Connection activity and diagnostics"
        case .about: return "Application and build information"
        }
    }
}

struct MainWindow: View {
    @EnvironmentObject private var tunnel: TunnelController
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var tab: Tab = .settings
    /// Kept here so unsaved edits survive switching to the log and back.
    @State private var draft = Draft()
    /// Window state only: this app keeps nothing in system preferences.
    @State private var followLatest = true

    var body: some View {
        HStack(spacing: 0) {
            StatusColumn()
                .frame(width: 260)
                .padding(20)
                .frame(maxHeight: .infinity)
                .background {
                    LinearGradient(colors: [NFStyle.accent.opacity(0.10), NFStyle.aqua.opacity(0.04)],
                                   startPoint: .topLeading, endPoint: .bottomTrailing)
                }
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .center, spacing: 20) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(tab.title).font(.title3.weight(.semibold))
                        Text(tab.detail).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 12)
                    Picker("Page", selection: $tab) {
                        Text("Settings").tag(Tab.settings)
                        Text("Log").tag(Tab.log)
                        Text("About").tag(Tab.about)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(width: 230)
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 18)
                Divider().overlay(NFStyle.outline)
                ZStack {
                    switch tab {
                    case .settings:
                        SettingsForm(draft: $draft).transition(.opacity)
                    case .log:
                        LogList(followLatest: $followLatest).padding(20).transition(.opacity)
                    case .about:
                        AboutView().padding(24).transition(.opacity)
                    }
                }
                .animation(reduceMotion ? nil : .easeInOut(duration: 0.2), value: tab)
            }
            .frame(minWidth: 520, maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(minHeight: 600, maxHeight: .infinity)
        .background(NFStyle.background)
        .tint(NFStyle.accent)
        .onAppear { showInDock(true) }
        .onDisappear { showInDock(false) }
        .onChange(of: tunnel.configuration.selectedServer?.id) { _, id in
            // A choice in the sidebar or menu bar also changes the profile
            // whose Transport the form edits. Keep its unsaved fields intact.
            guard let id, draft.servers.contains(where: { $0.id == id }) else { return }
            draft.editing = id
            draft.selectAfterSave = nil
        }
    }
}

struct AboutView: View {
    private let information = AppInformation()

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 16) {
                NFBrandMark(size: 64)
                VStack(alignment: .leading, spacing: 5) {
                    Text("Network Relay NF").font(.title2.bold())
                    Text("A quiet SOCKS5 proxy for your Mac")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            .padding(.vertical, 8)
            VStack(spacing: 16) {
                LabeledContent("App version", value: information.version)
                Divider()
                LabeledContent("Protocol core version", value: information.coreVersion)
                Divider()
                LabeledContent("Source revision", value: information.sourceRevision)
                Divider()
                LabeledContent("Built") {
                    if let date = information.builtAt {
                        Text(date.formatted(date: .abbreviated, time: .standard))
                    } else {
                        Text("Not available")
                    }
                }
            }
            .font(.callout)
            .padding(20)
            .nfCard()
            Text("Network I/O uses Network.framework. The Rust core implements HTTP CONNECT for TCP and CONNECT-UDP for UDP. Destination names are resolved by the relay server. Build time is shown in your local time zone.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
        }
        .textSelection(.enabled)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

/// The power button, the status and the proxy address.
struct StatusColumn: View {
    @EnvironmentObject private var tunnel: TunnelController
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(spacing: 18) {
            HStack(spacing: 10) {
                NFBrandMark()
                Text("Network Relay NF").font(.title3.weight(.semibold))
                Spacer()
            }
            Spacer()
            PowerButton(status: tunnel.status) { tunnel.toggle() }
            VStack(spacing: 6) {
                HStack(spacing: 8) {
                    Circle().fill(tunnel.status.tint).frame(width: 7, height: 7)
                        .accessibilityHidden(true)
                    Text(tunnel.status.title)
                }
                    .font(.title2.weight(.semibold))
                    .contentTransition(.opacity)
                    .help(tunnel.status.title)
                Text(tunnel.status.detail ?? (tunnel.isConfigured ? " " : "Enter the server and account on the right first"))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .lineLimit(4)
                    .frame(minHeight: 40, alignment: .top)
                    .help(tunnel.status.detail ?? (tunnel.isConfigured ? " " : "Enter the server and account on the right first"))
            }
            .animation(reduceMotion ? nil : .easeInOut(duration: 0.25), value: tunnel.status)
            Spacer()
            ServerPicker()
            ProxyRow(settings: tunnel.settings)
        }
    }
}

/// The settings as typed, before they are saved.
struct Draft: Equatable {
    var servers: [Server] = []
    /// The server whose fields the form shows.
    var editing: UUID?
    var listenAddress = "127.0.0.1"
    var port = ""
    var connectOnLaunch = false
    var gssapiKeytab = ""
    var gssapiPrincipals = ""
    /// Only an imported log level overrides the choice made in the Log tab.
    var importedLogLevel: LogLevel?
    /// The server to connect through once saved, chosen by an import that
    /// replaced everything.
    var selectAfterSave: UUID?
    var loaded = false

    init() {}

    init(_ configuration: NetworkRelayNFModel.Configuration) {
        // At the first start, a server to fill in.
        servers = configuration.servers.isEmpty ? [Server()] : configuration.servers
        editing = configuration.selectedServer?.id ?? servers.first?.id
        listenAddress = configuration.listenAddress
        port = String(configuration.port)
        connectOnLaunch = configuration.connectOnLaunch
        gssapiKeytab = configuration.gssapiKeytab
        gssapiPrincipals = configuration.gssapiPrincipals
        loaded = true
    }

    /// Whether these are the saved settings.
    func matches(_ configuration: NetworkRelayNFModel.Configuration, scope: TransferScope = .all) -> Bool {
        let serversMatch = servers == configuration.servers
            && (selectAfterSave == nil || selectAfterSave == configuration.selectedServer?.id)
        let applicationMatches = listenAddress == configuration.listenAddress
            && port == String(configuration.port) && connectOnLaunch == configuration.connectOnLaunch
            && gssapiKeytab == configuration.gssapiKeytab && gssapiPrincipals == configuration.gssapiPrincipals
            && (importedLogLevel == nil || importedLogLevel == configuration.logLevel)
        switch scope {
        case .servers: return serversMatch
        case .application: return applicationMatches
        case .all: return serversMatch && applicationMatches
        }
    }
}

struct SettingsForm: View {
    @EnvironmentObject private var tunnel: TunnelController
    @Binding var draft: Draft
    @State private var message: Message?

    enum Message: Equatable {
        case error(String)
        case done(String)
        case note(String)
    }

    private var editedIndex: Int? {
        draft.servers.firstIndex { $0.id == draft.editing }
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    if editedIndex != nil {
                        Picker("Server", selection: Binding(
                            get: { draft.editing },
                            set: { changeServer($0) })) {
                            ForEach(draft.servers) { server in
                                Text(server.title).tag(Optional(server.id))
                            }
                        }
                        .help("Saved server choices apply immediately. A running proxy reconnects; a disconnected proxy stays disconnected. Other edits still need Save.")
                        TextField("Name", text: field(\.name), prompt: Text("Optional, such as Tokyo"))
                        TextField("Domain", text: field(\.domain), prompt: Text("vpn.example.com"))
                        TextField("IP", text: field(\.serverIP), prompt: Text("Optional"))
                        TextField("Username", text: field(\.username))
                        SecureField("Password", text: field(\.password))
                        Picker("Transport", selection: Binding(
                            get: { field(\.transport, empty: .auto).wrappedValue },
                            set: { changeTransport($0) })) {
                            ForEach(NetworkRelayNFModel.Transport.allCases, id: \.self) { transport in
                                Text(transport.title).tag(transport)
                            }
                        }
                        .help("Saved servers apply this choice immediately; the active proxy reconnects.")
                        if draft.servers[editedIndex!].transport == .auto {
                            Text("Where UDP 443 is blocked, HTTP/3 waits 5 seconds before switching to TCP; when only TCP works, HTTP/2 is faster.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        Text("No servers. Click + to add one, or import a settings file.")
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    HStack(spacing: 10) {
                        Label("Servers", systemImage: "server.rack")
                        Spacer()
                        Button { addServer() } label: { Image(systemName: "plus") }
                            .buttonStyle(.borderless)
                            .help("Add a Server")
                        Button { removeServer() } label: { Image(systemName: "minus") }
                            .buttonStyle(.borderless)
                            .disabled(editedIndex == nil)
                            .help("Remove This Server")
                    }
                }
                Section {
                    TextField("Listen address", text: $draft.listenAddress, prompt: Text("127.0.0.1"))
                    TextField("Port", text: $draft.port, prompt: Text("1080"))
                    if !NetworkRelayNFModel.Settings(listenAddress: draft.listenAddress).listensOnlyLocally
                        && draft.gssapiKeytab.trimmingCharacters(in: .whitespaces).isEmpty {
                        Label("Any device on the same network can use this proxy.", systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                    TextField("Kerberos keytab", text: $draft.gssapiKeytab, prompt: Text("Optional, /path/to/socks.keytab"))
                    TextField("Kerberos clients", text: $draft.gssapiPrincipals, prompt: Text("Optional, alice@EXAMPLE.COM, …"))
                    Text("With a keytab, programs must authenticate with Kerberos (GSS-API) to use the proxy. Kerberos clients limits who may; empty admits every client of the keytab's realm.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } header: {
                    Label("SOCKS5 Proxy on This Mac", systemImage: "network")
                }
                Section {
                    Toggle("Connect when Network Relay NF opens", isOn: $draft.connectOnLaunch)
                } header: {
                    Label("Startup", systemImage: "power")
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            VStack(alignment: .leading, spacing: 10) {
                if let message {
                    messageLabel(message)
                        .transition(.opacity)
                }
                HStack(spacing: 10) {
                    Menu("Import…") {
                        Button("Servers…") { importSettings(.servers) }
                        Button("Application Settings…") { importSettings(.application) }
                        Button("All Settings…") { importSettings(.all) }
                    }
                    .menuStyle(.borderedButton)
                    .help("Import servers, application settings, or all settings into the form")
                    Menu("Export…") {
                        Button("Servers…") { exportSettings(.servers) }
                            .disabled(exportDisabled(.servers))
                        Button("Application Settings…") { exportSettings(.application) }
                            .disabled(exportDisabled(.application))
                        Button("All Settings…") { exportSettings(.all) }
                            .disabled(exportDisabled(.all))
                    }
                    .menuStyle(.borderedButton)
                    .help("Export saved settings; save changes in the chosen section first")
                    Spacer()
                    Button { save() } label: {
                        Label("Save", systemImage: "checkmark")
                    }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                }
            }
            .padding(.horizontal, 20)
            .padding(.top, 14)
            .padding(.bottom, 18)
            .background(.bar)
            .animation(.easeInOut(duration: 0.2), value: message)
        }
        .onAppear {
            if !draft.loaded {
                draft = Draft(tunnel.configuration)
            }
        }
        .onChange(of: draft) {
            if case .done = message, !draft.matches(tunnel.configuration) {
                message = nil
            }
        }
    }

    private func messageLabel(_ message: Message) -> some View {
        let text: String
        let symbol: String
        let color: Color
        switch message {
        case .error(let why):
            text = why
            symbol = "xmark.octagon"
            color = .red
        case .done(let what):
            text = what
            symbol = "checkmark.circle"
            color = .green
        case .note(let what):
            text = what
            symbol = "info.circle"
            color = .secondary
        }
        return Label(text, systemImage: symbol)
            .font(.caption)
            .foregroundStyle(color)
            .lineLimit(3)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(color.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .help(text)
    }

    /// A field of the server the form shows. Through its ID rather than
    /// its place in the list, which changes when a server is removed.
    private func field<T>(_ key: WritableKeyPath<Server, T>, empty: T) -> Binding<T> {
        Binding(
            get: { draft.servers.first(where: { $0.id == draft.editing })?[keyPath: key] ?? empty },
            set: { value in
                if let index = draft.servers.firstIndex(where: { $0.id == draft.editing }) {
                    draft.servers[index][keyPath: key] = value
                }
            })
    }

    private func field(_ key: WritableKeyPath<Server, String>) -> Binding<String> {
        field(key, empty: "")
    }

    /// A saved profile applies its saved settings immediately; merely adding,
    /// removing or importing a draft profile still waits for Save.
    private func changeServer(_ id: UUID?) {
        guard let id, draft.servers.contains(where: { $0.id == id }) else { return }
        guard tunnel.configuration.servers.contains(where: { $0.id == id }) else {
            draft.editing = id
            draft.selectAfterSave = id
            message = .note("Server selected; save this new server before connecting.")
            return
        }
        // Returning to the current saved profile needs no disk write and
        // cancels an earlier draft-only selection, without discarding edits.
        guard tunnel.configuration.selectedServer?.id != id else {
            draft.editing = id
            draft.selectAfterSave = nil
            message = .note("Server selected. Other changes still need Save.")
            return
        }
        var new = tunnel.configuration
        new.selectedServerID = id
        do {
            let reconnecting = try tunnel.save(new)
            draft.editing = id
            draft.selectAfterSave = nil
            message = .note(reconnecting
                ? "Server applied; reconnecting. Other changes still need Save."
                : "Server selection saved. Other changes still need Save.")
        } catch {
            message = .error(error.localizedDescription)
        }
    }

    /// Apply only this choice, preserving every other unsaved form field.
    private func changeTransport(_ transport: NetworkRelayNFModel.Transport) {
        guard let edited = editedIndex else { return }
        let id = draft.servers[edited].id
        var new = tunnel.configuration
        guard let saved = new.servers.firstIndex(where: { $0.id == id }) else {
            guard draft.servers[edited].transport != transport else { return }
            draft.servers[edited].transport = transport
            message = .note("Transport selected; save this new server before connecting.")
            return
        }
        // An imported draft may already show this choice while the saved
        // profile still uses another transport. An explicit choice applies it.
        guard draft.servers[edited].transport != transport
            || new.servers[saved].transport != transport else { return }
        new.servers[saved].transport = transport
        do {
            let reconnecting = try tunnel.save(new)
            draft.servers[edited].transport = transport
            message = .note(reconnecting
                ? "Transport applied; reconnecting. Other changes still need Save."
                : "Transport saved. Other changes still need Save.")
        } catch {
            message = .error(error.localizedDescription)
        }
    }

    private func addServer() {
        let server = Server()
        draft.servers.append(server)
        draft.editing = server.id
    }

    private func removeServer() {
        guard let index = editedIndex else { return }
        draft.servers.remove(at: index)
        draft.editing = draft.servers.isEmpty ? nil : draft.servers[min(index, draft.servers.count - 1)].id
    }

    private func configurationFromDraft(scope: TransferScope = .all) throws -> NetworkRelayNFModel.Configuration {
        var new = tunnel.configuration
        new.servers = draft.servers
        if scope != .servers {
            guard let port = Int(draft.port.trimmingCharacters(in: .whitespaces)) else {
                throw SettingsError.invalidPort
            }
            new.listenAddress = draft.listenAddress
            new.port = port
            new.connectOnLaunch = draft.connectOnLaunch
            new.gssapiKeytab = draft.gssapiKeytab
            new.gssapiPrincipals = draft.gssapiPrincipals
            if let level = draft.importedLogLevel { new.logLevel = level }
        }
        if let id = draft.selectAfterSave {
            new.selectedServerID = id
        }
        return new
    }

    private func save() {
        do {
            var new = try configurationFromDraft()
            // Empty placeholders are not accounts; real profiles still get checked.
            new.servers.removeAll { $0.isSame(as: Server()) }
            // A selected empty placeholder is discarded. Keep the actual
            // saved selection if it survives, rather than jumping to the first.
            if let requested = new.selectedServerID,
               !new.servers.contains(where: { $0.id == requested }),
               let current = tunnel.configuration.selectedServer?.id,
               new.servers.contains(where: { $0.id == current }) {
                new.selectedServerID = current
            }
            new.selectedServerID = new.selectedServer?.id
            let reconnecting = try tunnel.save(new)
            draft.servers = new.servers
            if !draft.servers.contains(where: { $0.id == draft.editing }) {
                draft.editing = new.selectedServer?.id
            }
            draft.port = String(new.port)
            draft.selectAfterSave = nil
            draft.importedLogLevel = nil
            message = .done(reconnecting ? "Saved; reconnecting with the new settings" : "Saved")
        } catch {
            message = .error(error.localizedDescription)
        }
    }

    /// Imports into the existing draft. Nothing is applied until Save.
    private func importSettings(_ scope: TransferScope) {
        var base: NetworkRelayNFModel.Configuration
        do {
            base = try configurationFromDraft(scope: scope)
        } catch {
            message = .error(error.localizedDescription)
            return
        }
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "toml") ?? .plainText, .plainText]
        panel.message = "Choose a settings file exported by Network Relay NF, or a network-relay-nf-core configuration."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let imported: NetworkRelayNFModel.Configuration
        do {
            imported = try NetworkRelayNFModel.Configuration.importing(
                String(contentsOf: url, encoding: .utf8), scope: scope, preserving: base)
        } catch {
            message = .error("Could not import “\(url.lastPathComponent)”: \(error.localizedDescription)")
            return
        }
        let count = imported.servers.count
        var replace = true
        // Ask unless the form holds only an empty server, as at the first start.
        if scope != .application && draft.servers.contains(where: { !$0.isSame(as: Server()) }) {
            let alert = NSAlert()
            alert.messageText = "Import \(count == 1 ? "a server" : "\(count) servers") from “\(url.lastPathComponent)”?"
            alert.informativeText = imported.servers.map(\.title).joined(separator: ", ")
                + "\n\n“Merge” updates matching servers and adds new ones, keeping your application settings. “Replace” replaces "
                + (scope == .all ? "the server list and imports the application's settings." : "the server list only.")
                + " Existing passwords are kept when the file leaves them out. Nothing is applied until Save."
            alert.addButton(withTitle: "Merge")
            alert.addButton(withTitle: "Replace")
            alert.addButton(withTitle: "Cancel")
            switch alert.runModal() {
            case .alertFirstButtonReturn: replace = false
            case .alertSecondButtonReturn: replace = true
            default: return
            }
        }
        if scope != .application {
            let previousIDs = Set(base.servers.map(\.id))
            base.add(serversOf: imported, replacing: replace)
            draft.servers = base.servers
            if replace {
                draft.selectAfterSave = base.selectedServer?.id
                draft.editing = base.selectedServer?.id
            } else if let added = draft.servers.first(where: { !previousIDs.contains($0.id) }) {
                draft.editing = added.id
            } else if !draft.servers.contains(where: { $0.id == draft.editing }) {
                draft.editing = draft.servers.first?.id
            }
        }
        if scope == .application || (scope == .all && replace) {
            draft.listenAddress = imported.listenAddress
            draft.port = String(imported.port)
            draft.connectOnLaunch = imported.connectOnLaunch
            if imported.logLevel != base.logLevel { draft.importedLogLevel = imported.logLevel }
        }
        message = .note(scope == .application
            ? "Imported application settings. Check them, then click Save."
            : "Imported \(count) \(count == 1 ? "server" : "servers"). Check the settings, then click Save.")
    }

    private func exportDisabled(_ scope: TransferScope) -> Bool {
        !draft.matches(tunnel.configuration, scope: scope)
            || (scope != .application && tunnel.configuration.servers.isEmpty)
    }

    /// Writes the saved settings to a TOML file, with the passwords or
    /// without them.
    private func exportSettings(_ scope: TransferScope) {
        let configuration = tunnel.configuration
        var withPasswords = false
        if scope != .application && configuration.servers.contains(where: { !$0.password.isEmpty }) {
            let alert = NSAlert()
            alert.messageText = "Export the passwords too?"
            alert.informativeText = "With the passwords, anyone who gets the file can use your accounts: keep it private. "
                + "Without them, the passwords are entered again after importing."
            alert.addButton(withTitle: "Leave Out Passwords")
            alert.addButton(withTitle: "Include Passwords")
            alert.addButton(withTitle: "Cancel")
            switch alert.runModal() {
            case .alertFirstButtonReturn: withPasswords = false
            case .alertSecondButtonReturn: withPasswords = true
            default: return
            }
        }
        let panel = NSSavePanel()
        switch scope {
        case .servers: panel.nameFieldStringValue = "Network Relay NF Servers.toml"
        case .application: panel.nameFieldStringValue = "Network Relay NF Application Settings.toml"
        case .all: panel.nameFieldStringValue = "Network Relay NF Settings.toml"
        }
        panel.allowedContentTypes = [UTType(filenameExtension: "toml") ?? .plainText]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try writePrivately(Data(configuration.exportedTOML(withPasswords: withPasswords, scope: scope).utf8), to: url)
            message = .done("Exported to “\(url.lastPathComponent)”"
                + (scope == .application ? "" : ", \(withPasswords ? "with" : "without") the passwords"))
        } catch {
            message = .error("Could not export: \(error.localizedDescription)")
        }
    }
}

struct LogList: View {
    @EnvironmentObject private var tunnel: TunnelController
    @Binding var followLatest: Bool
    @State private var exportError: String?

    var body: some View {
        let lines = tunnel.log.filter(tunnel.configuration.logLevel.shows)
        ScrollViewReader { proxy in
            VStack(alignment: .leading, spacing: 10) {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(lines.enumerated()), id: \.offset) { index, line in
                            Text(line)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(color(of: line))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(index)
                        }
                        if lines.isEmpty {
                            Text(tunnel.log.isEmpty
                                ? "No log yet. Once you connect, the client's output appears here."
                                : "Nothing at this level yet.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                        Color.clear.frame(height: 1).id("latest")
                    }
                    .padding(10)
                }
                .nfCard()
                HStack {
                    Picker("Show", selection: Binding(get: { tunnel.configuration.logLevel }, set: { tunnel.setLogLevel($0) })) {
                        ForEach(LogLevel.allCases.reversed(), id: \.self) { level in
                            Text(level.title).tag(level)
                        }
                    }
                    .pickerStyle(.menu)
                    .fixedSize()
                    .help("Detailed adds proxy and native connection diagnostics; Everything also "
                        + "includes native I/O metadata, without packet contents. Changing the level does not reconnect.")
                    Spacer()
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(tunnel.log.joined(separator: "\n"), forType: .string)
                    } label: {
                        Label("Copy All", systemImage: "doc.on.doc")
                    }
                    .help("Copy every retained log line, including levels hidden above")
                    Button { saveLog() } label: {
                        Label("Save…", systemImage: "square.and.arrow.down")
                    }
                        .help("Save every retained log line as plain text, including levels hidden above")
                }
                HStack {
                    Toggle("Follow latest", isOn: $followLatest)
                        .toggleStyle(.switch)
                        .help("Scroll to new log entries; turn off to read earlier entries")
                    Spacer()
                    Button("Latest") {
                        followLatest = true
                        scrollToLatest(proxy)
                    }
                    .help("Show the newest entry and resume following new entries")
                }
                Text("Showing \(lines.count) of \(tunnel.log.count) retained lines. Copy All and Save include all retained lines, at every level. Up to 5,000 recent lines; kept in memory.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .controlSize(.small)
            .onAppear { if followLatest { scrollToLatest(proxy) } }
            .onChange(of: tunnel.log) {
                if followLatest { scrollToLatest(proxy) }
            }
            .onChange(of: tunnel.configuration.logLevel) {
                if followLatest { scrollToLatest(proxy) }
            }
            .onChange(of: followLatest) { _, following in
                if following { scrollToLatest(proxy) }
            }
        }
        .alert("Could Not Save Log", isPresented: Binding(
            get: { exportError != nil },
            set: { if !$0 { exportError = nil } }
        )) {
            Button("OK") { exportError = nil }
        } message: {
            Text(exportError ?? "")
        }
    }

    private func scrollToLatest(_ proxy: ScrollViewProxy) {
        // Wait for SwiftUI to lay out the new tail, including at the retention cap.
        DispatchQueue.main.async {
            guard followLatest else { return }
            withAnimation(.easeOut(duration: 0.2)) {
                proxy.scrollTo("latest", anchor: .bottom)
            }
        }
    }

    private func saveLog() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Network Relay NF.log"
        panel.allowedContentTypes = [.plainText]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try writePrivately(Data(tunnel.log.joined(separator: "\n").utf8), to: url)
            exportError = nil
        } catch {
            exportError = "Could not save “\(url.lastPathComponent)”: \(error.localizedDescription)"
        }
    }

    private func color(of line: String) -> Color {
        if line.contains(" WARN ") || line.contains(" ERROR ") {
            return .orange
        }
        if line.contains(" DEBUG ") || line.contains(" TRACE ") {
            return .secondary
        }
        return .primary
    }
}

// MARK: - Menu-bar panel

struct MenuPanel: View {
    @EnvironmentObject private var tunnel: TunnelController
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(spacing: 16) {
            HStack(spacing: 8) {
                NFBrandMark(size: 28)
                Text("Network Relay NF").font(.headline)
                Spacer()
                Circle()
                    .fill(tunnel.status.tint)
                    .frame(width: 8, height: 8)
                    .accessibilityHidden(true)
            }
            PowerButton(status: tunnel.status) {
                if tunnel.isConfigured {
                    tunnel.toggle()
                } else {
                    openMain()
                }
            }
            VStack(spacing: 4) {
                Text(tunnel.status.title)
                    .font(.title3.weight(.semibold))
                    .contentTransition(.opacity)
                    .help(tunnel.status.title)
                if let detail = tunnel.status.detail {
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .lineLimit(3)
                        .help(detail)
                }
            }
            .frame(maxWidth: .infinity)
            .animation(.easeInOut(duration: 0.25), value: tunnel.status)
            ServerPicker()
            ProxyRow(settings: tunnel.settings)
            HStack(spacing: 4) {
                Button {
                    openMain()
                } label: {
                    Label("Open Main Window", systemImage: "macwindow")
                }
                .buttonStyle(.borderless)
                Spacer()
                Menu {
                    Button("Quit Network Relay NF") { NSApp.terminate(nil) }
                    Divider()
                    Button("Erase All Data and Quit…") { confirmErase() }
                } label: {
                    Image(systemName: "ellipsis.circle").font(.system(size: 15))
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("More")
            }
        }
        .padding(20)
        .frame(width: 320)
        .tint(NFStyle.accent)
    }

    private func openMain() {
        showInDock(true)
        openWindow(id: "main")
    }

    private func confirmErase() {
        let alert = NSAlert()
        alert.messageText = "Erase all data and quit?"
        alert.informativeText = "This deletes all settings, including the server, username and password, and the preferences and window state macOS keeps for this app. Then move Network Relay NF to the Trash, and none of its settings or data are left on this Mac."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Erase and Quit")
        alert.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn {
            tunnel.eraseEverythingAndQuit()
        }
    }
}

// MARK: - Parts

/// The server to connect to. Choosing another while connected reconnects
/// through it, for instance when the one in use is down.
struct ServerPicker: View {
    @EnvironmentObject private var tunnel: TunnelController

    var body: some View {
        let servers = tunnel.configuration.servers
        if servers.count > 1 {
            Picker(selection: Binding(get: { tunnel.configuration.selectedServer?.id }, set: { if let id = $0 { tunnel.use(id) } })) {
                ForEach(servers) { server in
                    Text(server.title).tag(Optional(server.id))
                }
            } label: {
                Label("Server", systemImage: "server.rack")
            }
            .pickerStyle(.menu)
            .help((tunnel.configuration.selectedServer.map { "\($0.title)\n" } ?? "")
                + (tunnel.status.isActive ? "Choosing another server reconnects through it" : "The server to connect to"))
        } else if let server = servers.first {
            Label(server.title, systemImage: "server.rack")
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .help(server.title)
        }
    }
}

/// The big round button: grey when off, a turning ring while connecting,
/// green with a soft glow when connected.
struct PowerButton: View {
    let status: Status
    let action: () -> Void
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            ZStack {
                Circle()
                    .fill(RadialGradient(colors: [status.tint.opacity(0.18), status.tint.opacity(0.03)],
                                         center: .center, startRadius: 20, endRadius: 72))
                    .frame(width: 144, height: 144)
                Circle()
                    .fill(NFStyle.surface)
                    .frame(width: 110, height: 110)
                    .shadow(color: status.tint.opacity(status == .connected ? 0.20 : 0.08), radius: 16, y: 4)
                Circle()
                    .stroke(LinearGradient(colors: [status.tint.opacity(0.55), status.tint.opacity(0.15)],
                                           startPoint: .topLeading, endPoint: .bottomTrailing), lineWidth: 1.5)
                    .frame(width: 110, height: 110)
                if status.isBusy {
                    Spinner(color: status.tint)
                        .frame(width: 110, height: 110)
                        .transition(.opacity)
                }
                Image(systemName: "power")
                    .font(.system(size: 36, weight: .semibold))
                    .foregroundStyle(status == .stopped ? Color.secondary : status.tint)
            }
            .scaleEffect(hovering && !reduceMotion ? 1.04 : 1)
            .contentShape(Circle())
        }
        .buttonStyle(PressableStyle())
        .onHover { inside in
            withAnimation(reduceMotion ? nil : .spring(response: 0.25, dampingFraction: 0.7)) { hovering = inside }
        }
        .animation(reduceMotion ? nil : .easeInOut(duration: 0.4), value: status)
        .accessibilityLabel(status.isActive ? "Disconnect" : "Connect")
        .accessibilityValue(status.title)
        .help(status.isActive ? "Disconnect" : "Connect")
    }
}

struct Spinner: View {
    let color: Color
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var turning = false

    var body: some View {
        Circle()
            .trim(from: 0, to: 0.28)
            .stroke(color, style: StrokeStyle(lineWidth: 3, lineCap: .round))
            .rotationEffect(.degrees(turning ? 360 : 0))
            .animation(reduceMotion ? nil : .linear(duration: 0.9).repeatForever(autoreverses: false), value: turning)
            .onAppear { turning = !reduceMotion }
            .onChange(of: reduceMotion) { _, reduced in turning = !reduced }
            .accessibilityHidden(true)
    }
}

struct PressableStyle: ButtonStyle {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    // SwiftUI's configuration of a button, not NetworkRelayNFModel's settings.
    func makeBody(configuration: ButtonStyleConfiguration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed && !reduceMotion ? 0.93 : 1)
            .animation(reduceMotion ? nil : .spring(response: 0.2, dampingFraction: 0.6), value: configuration.isPressed)
    }
}

struct ProxyRow: View {
    let settings: NetworkRelayNFModel.Settings
    @State private var copied = false

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "network")
                .font(.system(size: 16))
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(settings.listensOnlyLocally ? "SOCKS5 proxy" : "SOCKS5 proxy · open to the LAN")
                    .font(.caption)
                    .foregroundStyle(settings.listensOnlyLocally ? Color.secondary : Color.orange)
                    .help(settings.listensOnlyLocally ? "SOCKS5 proxy" : "SOCKS5 proxy · open to the LAN")
                Text(settings.proxyAddress)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .help(settings.proxyAddress)
            }
            Spacer()
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(settings.proxyAddress, forType: .string)
                withAnimation(.spring(response: 0.3)) { copied = true }
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
                    withAnimation(.easeOut) { copied = false }
                }
            } label: {
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    .foregroundStyle(copied ? Color.green : Color.secondary)
                    .frame(width: 20, height: 20)
                    .contentTransition(.opacity)
            }
            .buttonStyle(.plain)
            .help("Copy Address")
        }
        .padding(12)
        .nfCard()
    }
}
