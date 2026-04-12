import SwiftUI

struct SidebarView: View {
    @EnvironmentObject var viewModel: ReportsViewModel

    var body: some View {
        List(selection: $viewModel.filterType) {
            Section("Reports") {
                Label {
                    HStack {
                        Text("All")
                        Spacer()
                        Text("\(viewModel.entries.count)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "tray.2")
                }
                .tag(nil as ReportType?)

                Label {
                    HStack {
                        Text("DMARC")
                        Spacer()
                        Text("\(viewModel.dmarcCount)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "shield.checkered")
                }
                .tag(ReportType.dmarc as ReportType?)

                Label {
                    HStack {
                        Text("TLS-RPT")
                        Spacer()
                        Text("\(viewModel.tlsrptCount)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "lock.shield")
                }
                .tag(ReportType.tlsrpt as ReportType?)
            }
        }
        .listStyle(.sidebar)
        .navigationTitle("Reports")
        .toolbar {
            ToolbarItem {
                Button {
                    Task { await viewModel.fetchReports() }
                } label: {
                    if viewModel.isFetching {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Image(systemName: "arrow.clockwise")
                    }
                }
                .disabled(viewModel.isFetching)
                .help("Fetch new reports (⌘R)")
            }
        }
    }
}
