import SwiftUI

struct ReportListView: View {
    @EnvironmentObject var viewModel: ReportsViewModel

    var body: some View {
        Group {
            if viewModel.isLoading {
                ProgressView("Loading...")
            } else if viewModel.filteredEntries.isEmpty {
                ContentUnavailableView {
                    Label("No Reports", systemImage: "doc.text.magnifyingglass")
                } description: {
                    Text("Fetch reports from your IMAP accounts using ⌘R")
                }
            } else {
                Table(viewModel.filteredEntries, selection: $viewModel.selectedEntryID) {
                    TableColumn("ACCOUNT") { entry in
                        BadgeLabel(text: entry.account, color: labelColor(for: entry.account))
                    }
                    .width(min: 60, ideal: 90)

                    TableColumn("TYPE") { entry in
                        BadgeLabel(
                            text: entry.type.displayName,
                            color: entry.type == .dmarc ? .orange : Color(.systemTeal)
                        )
                    }
                    .width(min: 50, ideal: 70)

                    TableColumn("DATE") { entry in
                        Text(entry.date)
                            .monospaced()
                    }
                    .width(min: 80, ideal: 130)

                    TableColumn("DOMAIN") { entry in
                        BadgeLabel(text: entry.domain, color: labelColor(for: entry.domain))
                    }
                    .width(min: 80, ideal: 150)

                    TableColumn("ORGANIZATION") { entry in
                        Text(entry.org)
                            .monospaced()
                            .lineLimit(1)
                    }
                    .width(min: 80, ideal: 150)

                    TableColumn("POLICY") { entry in
                        if !entry.policy.isEmpty {
                            BadgeLabel(text: entry.policy, color: policyColor(entry.policy))
                        }
                    }
                    .width(min: 50, ideal: 80)
                }
                .tableStyle(.inset(alternatesRowBackgrounds: true))
            }
        }
        .navigationTitle(navigationTitle)
        .searchable(text: $viewModel.searchText, prompt: "Search reports")
        .onChange(of: viewModel.selectedEntryID) { _, _ in
            if let entry = viewModel.selectedEntry {
                viewModel.loadDetail(for: entry)
            }
        }
    }

    private var navigationTitle: String {
        if let account = viewModel.filterAccount {
            return account
        }
        if let domain = viewModel.filterDomain {
            return domain
        }
        if let filterType = viewModel.filterType {
            return filterType.displayName
        }
        return "All Reports"
    }
}

struct BadgeLabel: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption2.weight(.medium))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }
}
