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
            if viewModel.showDashboard {
                DashboardView()
            } else if viewModel.showMailSources {
                MailSourcesView()
            } else if viewModel.selectedEntry != nil {
                GeometryReader { geo in
                    VStack(spacing: 0) {
                        ReportListView()
                            .frame(maxHeight: .infinity)
                        Divider()
                        ReportDetailView()
                            .frame(height: geo.size.height * 0.4)
                    }
                }
            } else {
                ReportListView()
            }
        }
        .sheet(isPresented: $viewModel.showAddAccount) {
            SetupWizardView()
        }
    }
}
