import SwiftUI

struct ContentView: View {
    @EnvironmentObject var viewModel: ReportsViewModel

    var body: some View {
        NavigationSplitView {
            SidebarView()
        } detail: {
            if viewModel.showDashboard {
                DashboardView()
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
        .onAppear {
            viewModel.loadReports()
        }
        .alert("Error", isPresented: .constant(viewModel.errorMessage != nil)) {
            Button("OK") { viewModel.errorMessage = nil }
        } message: {
            Text(viewModel.errorMessage ?? "")
        }
    }
}
