import SwiftUI

@main
struct ReportsApp: App {
    @StateObject private var viewModel = ReportsViewModel()
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(viewModel)
        }
        .windowStyle(.titleBar)
        .defaultSize(width: 1000, height: 700)
        .commands {
            CommandGroup(after: .newItem) {
                Button("Fetch Reports") {
                    Task { await viewModel.fetchReports() }
                }
                .keyboardShortcut("r", modifiers: [.command])

                Button("Refresh List") {
                    viewModel.loadReports()
                }
                .keyboardShortcut("r", modifiers: [.command, .shift])
            }
        }

        Settings {
            SettingsView()
        }
    }
}
