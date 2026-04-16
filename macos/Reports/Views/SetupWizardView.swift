import SwiftUI

struct SetupWizardView: View {
    @EnvironmentObject var viewModel: ReportsViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var step = 0

    // Step 1: Account credentials
    @State private var username = ""
    @State private var password = ""

    // Step 2: Server settings
    @State private var host = ""
    @State private var port = "993"
    @State private var mailbox = "INBOX"
    @State private var tls = true

    // Step 3: Account name
    @State private var accountName = ""

    // Step 4: Sync progress
    @State private var syncPhase = ""
    @State private var syncComplete = false
    @State private var syncError: String?

    @State private var isSaving = false
    @State private var errorMessage: String?

    private let totalSteps = 4

    var body: some View {
        VStack(spacing: 0) {
            // Logo
            Image("Logo")
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(height: 280)
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .padding(.top, 32)
                .padding(.bottom, 24)

            // Step indicator
            HStack(spacing: 8) {
                ForEach(0..<totalSteps, id: \.self) { i in
                    Circle()
                        .fill(i == step ? Color.primary : Color.secondary.opacity(0.3))
                        .frame(width: 8, height: 8)
                }
            }
            .padding(.bottom, 20)

            // Content
            Group {
                switch step {
                case 0: credentialsStep
                case 1: serverStep
                case 2: nameStep
                case 3: syncStep
                default: EmptyView()
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.horizontal, 48)

            Spacer()

            // Error
            if let errorMessage {
                Text(errorMessage)
                    .font(.body)
                    .foregroundStyle(Color.failRed)
                    .padding(.horizontal, 48)
                    .padding(.bottom, 8)
            }

            // Navigation buttons
            if step < 3 {
                HStack {
                    if step > 0 {
                        Button {
                            withAnimation { step -= 1 }
                            errorMessage = nil
                        } label: {
                            Text("Back")
                                .font(.title3)
                                .padding(.horizontal, 20)
                                .padding(.vertical, 8)
                        }
                        .controlSize(.large)
                    }

                    Spacer()

                    if step < 2 {
                        Button {
                            if validateCurrentStep() {
                                withAnimation { step += 1 }
                                if step == 1 { guessServerSettings() }
                                if step == 2 { guessAccountName() }
                            }
                        } label: {
                            Text("Next")
                                .font(.title3)
                                .padding(.horizontal, 20)
                                .padding(.vertical, 8)
                        }
                        .controlSize(.large)
                        .keyboardShortcut(.defaultAction)
                        .disabled(!canAdvance)
                    } else {
                        Button {
                            startSync()
                        } label: {
                            Text("Complete")
                                .font(.title3)
                                .padding(.horizontal, 20)
                                .padding(.vertical, 8)
                        }
                        .controlSize(.large)
                        .keyboardShortcut(.defaultAction)
                        .disabled(accountName.isEmpty || isSaving)
                    }
                }
                .padding(.horizontal, 40)
                .padding(.bottom, 32)
            } else {
                // Sync step — no back/next, just progress or done
                if syncComplete {
                    HStack {
                        Spacer()
                        Button {
                            viewModel.loadReports()
                            viewModel.selectDashboard()
                            viewModel.showAddAccount = false
                            dismiss()
                        } label: {
                            Text("Open Dashboard")
                                .font(.title3)
                                .padding(.horizontal, 20)
                                .padding(.vertical, 8)
                        }
                        .controlSize(.large)
                        .keyboardShortcut(.defaultAction)
                        Spacer()
                    }
                    .padding(.horizontal, 40)
                    .padding(.bottom, 32)
                } else if syncError != nil {
                    HStack {
                        Button {
                            removeAccountFromConfig()
                            syncError = nil
                            isSaving = false
                            withAnimation { step = 0 }
                        } label: {
                            Text("Back to Settings")
                                .font(.title3)
                                .padding(.horizontal, 20)
                                .padding(.vertical, 8)
                        }
                        .controlSize(.large)

                        Spacer()

                        Button {
                            syncError = nil
                            startSyncTask()
                        } label: {
                            Text("Retry")
                                .font(.title3)
                                .padding(.horizontal, 20)
                                .padding(.vertical, 8)
                        }
                        .controlSize(.large)
                    }
                    .padding(.horizontal, 40)
                    .padding(.bottom, 32)
                } else {
                    Spacer()
                        .frame(height: 64)
                }
            }
        }
        .frame(width: 560, height: 680)
    }

    // MARK: - Step Views

    private var credentialsStep: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Mail Account")
                .font(.title2.weight(.semibold))

            TextField("Email address", text: $username)
                .textFieldStyle(.roundedBorder)
                .font(.title3)
                .textContentType(.emailAddress)

            SecureField("Password", text: $password)
                .textFieldStyle(.roundedBorder)
                .font(.title3)
                .textContentType(.password)

            Text("The account where DMARC/TLS-RPT reports are delivered.")
                .font(.body)
                .foregroundStyle(.secondary)
        }
    }

    private var serverStep: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Server Settings")
                .font(.title2.weight(.semibold))

            TextField("IMAP host", text: $host)
                .textFieldStyle(.roundedBorder)
                .font(.title3)

            HStack(spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Port").font(.body).foregroundStyle(.secondary)
                    TextField("993", text: $port)
                        .textFieldStyle(.roundedBorder)
                        .font(.title3)
                        .frame(width: 100)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("Mailbox").font(.body).foregroundStyle(.secondary)
                    TextField("INBOX", text: $mailbox)
                        .textFieldStyle(.roundedBorder)
                        .font(.title3)
                }
            }

            Toggle("Use TLS", isOn: $tls)
                .font(.body)
        }
    }

    private var nameStep: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Account Name")
                .font(.title2.weight(.semibold))

            TextField("e.g. personal, work, dmarc", text: $accountName)
                .textFieldStyle(.roundedBorder)
                .font(.title3)

            Text("A short label to identify this account in the sidebar.")
                .font(.body)
                .foregroundStyle(.secondary)
        }
    }

    private var syncStep: some View {
        VStack(spacing: 24) {
            if syncComplete {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(Color.passGreen)

                Text("Setup Complete")
                    .font(.title2.weight(.semibold))

                Text("Your reports have been fetched and processed.")
                    .font(.body)
                    .foregroundStyle(.secondary)
            } else if let syncError {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(Color.failRed)

                Text("Sync Failed")
                    .font(.title2.weight(.semibold))

                Text(syncError)
                    .font(.body)
                    .foregroundStyle(.primary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 16)
                    .textSelection(.enabled)
            } else {
                ProgressView()
                    .controlSize(.large)

                Text(syncPhase)
                    .font(.title3)
                    .foregroundStyle(.secondary)

                ProgressView(value: syncProgress, total: 1.0)
                    .progressViewStyle(.linear)
                    .frame(maxWidth: 300)
            }
        }
        .frame(maxWidth: .infinity)
    }

    private var syncProgress: Double {
        switch syncPhase {
        case let s where s.contains("Fetching"): return 0.2
        case let s where s.contains("Enriching"): return 0.5
        case let s where s.contains("Aggregating"): return 0.8
        default: return 0.1
        }
    }

    // MARK: - Validation

    private var canAdvance: Bool {
        switch step {
        case 0: return !username.isEmpty && !password.isEmpty
        case 1: return !host.isEmpty
        default: return true
        }
    }

    private func validateCurrentStep() -> Bool {
        errorMessage = nil
        switch step {
        case 0:
            if username.isEmpty { errorMessage = "Email address is required"; return false }
            if password.isEmpty { errorMessage = "Password is required"; return false }
        case 1:
            if host.isEmpty { errorMessage = "IMAP host is required"; return false }
        default: break
        }
        return true
    }

    // MARK: - Auto-detection

    private func guessServerSettings() {
        guard host.isEmpty else { return }
        if let atIndex = username.firstIndex(of: "@") {
            let domain = String(username[username.index(after: atIndex)...])
            host = "imap.\(domain)"
        }
    }

    private func guessAccountName() {
        guard accountName.isEmpty else { return }
        if let atIndex = username.firstIndex(of: "@") {
            let domain = String(username[username.index(after: atIndex)...])
            let parts = domain.split(separator: ".")
            if let first = parts.first {
                accountName = String(first)
            }
        }
    }

    // MARK: - Save & Sync

    private func startSync() {
        isSaving = true
        errorMessage = nil

        // Trim whitespace from all text fields
        username = username.trimmingCharacters(in: .whitespacesAndNewlines)
        host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        port = port.trimmingCharacters(in: .whitespacesAndNewlines)
        mailbox = mailbox.trimmingCharacters(in: .whitespacesAndNewlines)
        accountName = accountName.trimmingCharacters(in: .whitespacesAndNewlines)

        let newAccount: [String: Any] = [
            "name": accountName,
            "host": host,
            "port": Int(port) ?? 993,
            "username": username,
            "password": password,
            "mailbox": mailbox.isEmpty ? "INBOX" : mailbox,
            "tls": tls,
        ]

        let configDir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/reports")
        let configPath = configDir.appendingPathComponent("config.json")

        do {
            try FileManager.default.createDirectory(at: configDir, withIntermediateDirectories: true)

            // Load existing config or create new
            var config: [String: Any] = [:]
            if let existingData = try? Data(contentsOf: configPath),
               let existing = try? JSONSerialization.jsonObject(with: existingData) as? [String: Any] {
                config = existing
            }

            // Append new account to existing accounts array
            var accounts = (config["accounts"] as? [[String: Any]]) ?? []
            accounts.append(newAccount)
            config["accounts"] = accounts

            let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: configPath)
        } catch {
            errorMessage = error.localizedDescription
            isSaving = false
            return
        }

        withAnimation { step = 3 }
        startSyncTask()
    }

    private func removeAccountFromConfig() {
        let configPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/reports/config.json")
        guard let data = try? Data(contentsOf: configPath),
              var config = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              var accounts = config["accounts"] as? [[String: Any]] else { return }

        accounts.removeAll { ($0["name"] as? String) == accountName }
        config["accounts"] = accounts

        if let newData = try? JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys]) {
            try? newData.write(to: configPath)
        }
    }

    private func startSyncTask() {
        syncPhase = "Fetching reports..."
        syncComplete = false
        syncError = nil

        let core = ReportsCore.shared
        let name = accountName
        Task {
            do {
                syncPhase = "Fetching reports from IMAP..."
                try await core.fetchAccount(name)

                syncPhase = "Enriching source IPs..."
                try await core.enrich()

                syncPhase = "Aggregating statistics..."
                try await core.aggregate()

                withAnimation { syncComplete = true }
            } catch {
                syncError = error.localizedDescription
            }
        }
    }
}
