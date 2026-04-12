import SwiftUI

struct ContentView: View {
    @EnvironmentObject var viewModel: ReportsViewModel

    var body: some View {
        NavigationSplitView {
            SidebarView()
        } content: {
            ReportListView()
        } detail: {
            ReportDetailView()
        }
        .navigationSplitViewStyle(.balanced)
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
