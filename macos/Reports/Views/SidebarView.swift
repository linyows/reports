import SwiftUI

struct SidebarView: View {
    @EnvironmentObject var viewModel: ReportsViewModel

    private var isTypeFilter: Bool {
        viewModel.filterAccount == nil && viewModel.filterDomain == nil
    }

    var body: some View {
        List {
            Section {
                SidebarButton(
                    title: "Dashboard",
                    icon: "square.grid.2x2",
                    count: viewModel.entries.count,
                    color: .primary,
                    isSelected: viewModel.showDashboard
                ) {
                    viewModel.selectDashboard()
                }

                SidebarButton(
                    title: "All",
                    icon: "tray.full",
                    count: viewModel.entries.count,
                    color: .primary,
                    isSelected: !viewModel.showDashboard && isTypeFilter && viewModel.filterType == nil,
                    isLoading: viewModel.isLoading
                ) {
                    viewModel.clearFilters()
                }

                SidebarButton(
                    title: "DMARC",
                    icon: "shield.checkered",
                    count: viewModel.dmarcCount,
                    color: .primary,
                    isSelected: !viewModel.showDashboard && isTypeFilter && viewModel.filterType == .dmarc,
                    isLoading: viewModel.isLoading
                ) {
                    viewModel.clearFilters()
                    viewModel.filterType = .dmarc
                }

                SidebarButton(
                    title: "TLS-RPT",
                    icon: "lock.shield",
                    count: viewModel.tlsrptCount,
                    color: .primary,
                    isSelected: !viewModel.showDashboard && isTypeFilter && viewModel.filterType == .tlsrpt,
                    isLoading: viewModel.isLoading
                ) {
                    viewModel.clearFilters()
                    viewModel.filterType = .tlsrpt
                }

                SidebarButton(
                    title: "Problems",
                    icon: "exclamationmark.triangle",
                    count: viewModel.problemsCount,
                    color: .problemRed,
                    isSelected: !viewModel.showDashboard && viewModel.filterProblems
                ) {
                    viewModel.clearFilters()
                    viewModel.filterProblems = true
                }

                SidebarButton(
                    title: "Mail Sources",
                    icon: "network",
                    count: viewModel.mailSources.count,
                    color: .primary,
                    isSelected: viewModel.showMailSources,
                    isLoading: viewModel.isLoadingSources
                ) {
                    viewModel.selectMailSources()
                }
            }

            Section {
                ForEach(viewModel.accounts, id: \.name) { account in
                    SidebarButton(
                        title: account.name,
                        showDot: true,
                        count: account.count,
                        color: labelColor(for: account.name),
                        isSelected: !viewModel.showDashboard && viewModel.filterAccount == account.name
                    ) {
                        viewModel.clearFilters()
                        viewModel.filterAccount = account.name
                    }
                }
            } header: {
                SectionHeader(title: "Account", icon: "envelope")
            }

            Section {
                ForEach(viewModel.domains, id: \.name) { domain in
                    SidebarButton(
                        title: domain.name,
                        showDot: true,
                        count: domain.count,
                        color: labelColor(for: domain.name),
                        isSelected: !viewModel.showDashboard && viewModel.filterDomain == domain.name
                    ) {
                        viewModel.clearFilters()
                        viewModel.filterDomain = domain.name
                    }
                }
            } header: {
                SectionHeader(title: "Domain", icon: "globe")
            }
        }
        .listStyle(.sidebar)
        .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 320)
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 0) {
                Divider()
                VStack(spacing: 12) {
                    Button {
                        viewModel.showAddAccount = true
                    } label: {
                        Label("Add Account", systemImage: "plus.circle")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .buttonStyle(.borderless)
                    .help("Add Account (⇧⌘N)")

                    SettingsLink {
                        Label("Settings", systemImage: "gearshape")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .buttonStyle(.borderless)
                    .help("Settings (⌘,)")
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
        }
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

struct SectionHeader: View {
    let title: String
    let icon: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 4) {
            Image(systemName: icon)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(title)
        }
    }
}

struct SidebarButton: View {
    let title: String
    var icon: String? = nil
    var showDot: Bool = false
    let count: Int
    var color: Color = .secondary
    let isSelected: Bool
    var isLoading: Bool = false
    let action: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            if let icon {
                Image(systemName: icon)
                    .foregroundStyle(isSelected ? color : .secondary)
                    .frame(width: 20)
            } else if showDot {
                Circle()
                    .fill(isSelected ? color : Color.gray.opacity(0.4))
                    .frame(width: 8, height: 8)
                    .padding(.leading, 2)
            }
            Text(title)
                .lineLimit(1)
            Spacer()
            if isSelected && isLoading {
                ProgressView()
                    .controlSize(.small)
            } else {
                Text("\(count)")
                    .font(.caption)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 1)
                    .background(isSelected ? color.opacity(0.2) : Color.secondary.opacity(0.1))
                    .foregroundStyle(isSelected ? color : .secondary)
                    .clipShape(Capsule())
            }
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        .background(isSelected ? color.opacity(0.1) : .clear)
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .onTapGesture { action() }
        .onHover { hovering in
            if hovering {
                NSCursor.pointingHand.push()
            } else {
                NSCursor.pop()
            }
        }
    }
}
