import SwiftUI

struct ContentView: View {
    @EnvironmentObject var viewModel: ReportsViewModel

    var body: some View {
        Group {
            if viewModel.hasAccounts {
                mainView
            } else {
                SetupWizardView()
            }
        }
        .onAppear {
            viewModel.loadReports()
        }
        .alert("Error", isPresented: .constant(viewModel.errorMessage != nil)) {
            Button("OK") { viewModel.errorMessage = nil }
        } message: {
            Text(viewModel.errorMessage ?? "")
        }
    }

    private var mainView: some View {
        NavigationSplitView {
            SidebarView()
        } detail: {
            Group {
                if viewModel.showDashboard {
                    DashboardView()
                } else if viewModel.showMailSources {
                    MailSourcesView()
                } else {
                    GeometryReader { geo in
                        VStack(spacing: 0) {
                            ReportListView()
                                .frame(maxHeight: .infinity)
                            if viewModel.selectedEntry != nil {
                                Divider()
                                ReportDetailView()
                                    .frame(height: geo.size.height * 0.4)
                            }
                        }
                    }
                }
            }
            .safeAreaInset(edge: .bottom) {
                statusBar
            }
        }
        .sheet(isPresented: $viewModel.showAddAccount) {
            SetupWizardView()
        }
    }

    @ViewBuilder
    private var statusBar: some View {
        if let lastUpdated = viewModel.lastUpdated {
            HStack(spacing: 0) {
                Spacer()
                TimelineView(.periodic(from: .now, by: 60)) { _ in
                    Text("Updated \(lastUpdated, format: .relative(presentation: .named))")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                .help("Last updated: \(lastUpdated.formatted(date: .abbreviated, time: .standard))")
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 4)
        }
    }
}
