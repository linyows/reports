import SwiftUI

struct SettingsView: View {
    var body: some View {
        TabView {
            AccountsSettingsTab()
                .tabItem {
                    Label("Accounts", systemImage: "envelope")
                }

            AdvancedSettingsTab()
                .tabItem {
                    Label("Advanced", systemImage: "slider.horizontal.3")
                }
        }
        .frame(width: 500, height: 400)
    }
}

// MARK: - Accounts tab

struct AccountsSettingsTab: View {
    @State private var config = SettingsConfig()
    @State private var selectedID: SettingsAccount.ID?
    @State private var saveMessage: String?
    @State private var newAccountID: SettingsAccount.ID?

    private var configPath: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/.config/reports/config.json"
    }

    private var selectedIndex: Int? {
        guard let selectedID else { return nil }
        return config.accounts.firstIndex { $0.id == selectedID }
    }

    var body: some View {
        HSplitView {
            // Left: account list
            VStack(spacing: 0) {
                List(selection: $selectedID) {
                    ForEach(config.accounts) { account in
                        Text(account.name.isEmpty ? "(unnamed)" : account.name)
                            .padding(.vertical, 4)
                            .tag(account.id)
                    }
                }
                .listStyle(.plain)

                Divider()

                HStack(spacing: 4) {
                    Button {
                        let account = SettingsAccount(name: "new-account")
                        config.accounts.append(account)
                        selectedID = account.id
                        newAccountID = account.id
                    } label: {
                        Image(systemName: "plus")
                    }
                    .buttonStyle(.borderless)

                    Button {
                        if let index = selectedIndex {
                            config.accounts.remove(at: index)
                            selectedID = config.accounts.first?.id
                            save()
                        }
                    } label: {
                        Image(systemName: "minus")
                    }
                    .buttonStyle(.borderless)
                    .disabled(selectedIndex == nil)

                    Spacer()
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 6)
            }
            .frame(width: 130)

            // Right: form
            if let index = selectedIndex {
                AccountFormView(
                    account: $config.accounts[index],
                    saveMessage: $saveMessage,
                    isNew: selectedID == newAccountID,
                    onSave: {
                        newAccountID = nil
                        save()
                    },
                    onCancel: {
                        config.accounts.remove(at: index)
                        newAccountID = nil
                        selectedID = config.accounts.first?.id
                    }
                )
            } else {
                VStack {
                    Spacer()
                    Text("Select an account")
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            }
        }
        .onAppear {
            load()
            selectedID = config.accounts.first?.id
        }
    }

    private func load() {
        guard let data = FileManager.default.contents(atPath: configPath),
              let json = try? JSONDecoder().decode(SettingsJson.self, from: data) else {
            return
        }
        config.dataDir = json.data_dir ?? ""
        config.accounts = (json.accounts ?? []).map { a in
            SettingsAccount(
                name: a.name ?? "default",
                host: a.host,
                port: a.port ?? 993,
                username: a.username,
                password: a.password,
                mailbox: a.mailbox ?? "INBOX",
                tls: a.tls ?? true
            )
        }
    }

    private func save() {
        let accounts = config.accounts.map { a in
            SettingsJsonAccount(
                name: a.name,
                host: a.host,
                port: a.port,
                username: a.username,
                password: a.password,
                mailbox: a.mailbox,
                tls: a.tls
            )
        }
        let json = SettingsJson(
            accounts: accounts,
            data_dir: config.dataDir.isEmpty ? nil : config.dataDir
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(json) else { return }

        let dir = (configPath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        do {
            try data.write(to: URL(fileURLWithPath: configPath))
            saveMessage = "Saved"
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { saveMessage = nil }
        } catch {
            saveMessage = "Error: \(error.localizedDescription)"
        }
    }
}

// MARK: - Account form

struct AccountFormView: View {
    @Binding var account: SettingsAccount
    @Binding var saveMessage: String?
    var isNew: Bool = false
    let onSave: () -> Void
    var onCancel: (() -> Void)?

    var body: some View {
        Form {
            TextField("Name", text: $account.name)
            TextField("Host", text: $account.host, prompt: Text("imap.example.com"))
                .font(.system(.body, design: .monospaced))
            TextField("Port", value: $account.port, format: .number)
                .font(.system(.body, design: .monospaced))
            TextField("Username", text: $account.username, prompt: Text("user@example.com"))
                .font(.system(.body, design: .monospaced))
            SecureField("Password", text: $account.password)
                .font(.system(.body, design: .monospaced))
            TextField("Mailbox", text: $account.mailbox, prompt: Text("INBOX"))
                .font(.system(.body, design: .monospaced))
            Toggle("TLS", isOn: $account.tls)

            HStack {
                if isNew, let onCancel {
                    Button("Cancel") { onCancel() }
                }
                Spacer()
                if let saveMessage {
                    Text(saveMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Button("Save") { onSave() }
                    .keyboardShortcut("s", modifiers: .command)
                    .buttonStyle(.borderedProminent)
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Advanced tab

struct AdvancedSettingsTab: View {
    private var configPath: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/.config/reports/config.json"
    }

    private var configExists: Bool {
        FileManager.default.fileExists(atPath: configPath)
    }

    var body: some View {
        Form {
            Section("Config File") {
                LabeledContent("Path") {
                    Text(configPath)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                LabeledContent("Status") {
                    HStack(spacing: 4) {
                        Circle()
                            .fill(configExists ? Color.passGreen : Color.failRed)
                            .frame(width: 8, height: 8)
                        Text(configExists ? "Found" : "Not found")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            Section {
                HStack {
                    Button("Open in Editor") {
                        NSWorkspace.shared.open(URL(fileURLWithPath: configPath))
                    }
                    .disabled(!configExists)

                    Button("Reveal in Finder") {
                        let url = URL(fileURLWithPath: configPath)
                        NSWorkspace.shared.activateFileViewerSelecting([url])
                    }
                    .disabled(!configExists)
                }
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Settings models

struct SettingsConfig {
    var dataDir: String = ""
    var accounts: [SettingsAccount] = []
}

struct SettingsAccount: Identifiable {
    let id = UUID()
    var name: String = ""
    var host: String = ""
    var port: Int = 993
    var username: String = ""
    var password: String = ""
    var mailbox: String = "INBOX"
    var tls: Bool = true
}

// MARK: - JSON Codable

private struct SettingsJson: Codable {
    var accounts: [SettingsJsonAccount]?
    var data_dir: String?
}

private struct SettingsJsonAccount: Codable {
    var name: String?
    var host: String
    var port: Int?
    var username: String
    var password: String
    var mailbox: String?
    var tls: Bool?
}
