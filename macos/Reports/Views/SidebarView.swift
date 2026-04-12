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
                    title: "All",
                    showDot: true,
                    count: viewModel.entries.count,
                    color: .secondary,
                    isSelected: isTypeFilter && viewModel.filterType == nil,
                    isLoading: viewModel.isLoading
                ) {
                    viewModel.clearFilters()
                }

                SidebarButton(
                    title: "DMARC",
                    showDot: true,
                    count: viewModel.dmarcCount,
                    color: .orange,
                    isSelected: isTypeFilter && viewModel.filterType == .dmarc,
                    isLoading: viewModel.isLoading
                ) {
                    viewModel.clearFilters()
                    viewModel.filterType = .dmarc
                }

                SidebarButton(
                    title: "TLS-RPT",
                    showDot: true,
                    count: viewModel.tlsrptCount,
                    color: Color(.systemTeal),
                    isSelected: isTypeFilter && viewModel.filterType == .tlsrpt,
                    isLoading: viewModel.isLoading
                ) {
                    viewModel.clearFilters()
                    viewModel.filterType = .tlsrpt
                }
            } header: {
                SectionHeader(title: "Type", icon: "doc.text")
            }

            Section {
                ForEach(viewModel.accounts, id: \.name) { account in
                    SidebarButton(
                        title: account.name,
                        showDot: true,
                        count: account.count,
                        color: labelColor(for: account.name),
                        isSelected: viewModel.filterAccount == account.name
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
                        isSelected: viewModel.filterDomain == domain.name
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
        .safeAreaInset(edge: .bottom) {
            HStack {
                SettingsLink {
                    Label("Settings", systemImage: "gearshape")
                }
                .buttonStyle(.borderless)
                .help("Settings (⌘,)")
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
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
