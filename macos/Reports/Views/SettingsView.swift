import SwiftUI

struct SettingsView: View {
    @State private var configPath: String = ""
    @State private var configExists = false

    private var defaultPath: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/.config/reports/config.json"
    }

    var body: some View {
        Form {
            Section("Configuration") {
                LabeledContent("Config File") {
                    VStack(alignment: .trailing, spacing: 4) {
                        Text(defaultPath)
                            .font(.system(.body, design: .monospaced))
                            .foregroundStyle(.secondary)
                        HStack {
                            Circle()
                                .fill(configExists ? .green : .red)
                                .frame(width: 8, height: 8)
                            Text(configExists ? "Found" : "Not found")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                Button("Open in Editor") {
                    NSWorkspace.shared.open(URL(fileURLWithPath: defaultPath))
                }
                .disabled(!configExists)

                Button("Reveal in Finder") {
                    let url = URL(fileURLWithPath: defaultPath)
                    NSWorkspace.shared.activateFileViewerSelecting([url])
                }
                .disabled(!configExists)
            }
        }
        .formStyle(.grouped)
        .frame(width: 500, height: 200)
        .onAppear {
            configExists = FileManager.default.fileExists(atPath: defaultPath)
        }
    }
}
