import SwiftUI

struct MailSourcesView: View {
    @EnvironmentObject var viewModel: ReportsViewModel
    @State private var showIssuesOnly = false
    @State private var searchText = ""
    @State private var selection: String?

    private var displayedSources: [MailSource] {
        var result = viewModel.mailSources
        if showIssuesOnly {
            result = result.filter { $0.hasIssues }
        }
        if !searchText.isEmpty {
            let q = searchText.lowercased()
            result = result.filter {
                $0.ip.lowercased().contains(q) ||
                $0.ptr.lowercased().contains(q) ||
                $0.asn_org.lowercased().contains(q) ||
                $0.domains.contains { $0.lowercased().contains(q) }
            }
        }
        return result
    }

    var body: some View {
        Group {
            if viewModel.isLoadingSources {
                VStack(spacing: 8) {
                    ProgressView()
                    Text("Aggregating sources...")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else if viewModel.mailSources.isEmpty {
                ContentUnavailableView {
                    Label("No Mail Sources", systemImage: "network")
                } description: {
                    Text("No source IPs found across reports")
                }
            } else {
                Table(displayedSources, selection: $selection) {
                    TableColumn("SOURCE IP") { entry in
                        Text(entry.ip).monospaced()
                    }
                    .width(min: 100, ideal: 140)

                    TableColumn("PTR") { entry in
                        Text(entry.ptrDisplay)
                            .monospaced().lineLimit(1)
                            .foregroundStyle(entry.ptr.isEmpty ? .secondary : .primary)
                    }
                    .width(min: 80, ideal: 180)

                    TableColumn("ASN") { entry in
                        Text(entry.asnDisplay)
                            .monospaced().lineLimit(1)
                    }
                    .width(min: 80, ideal: 200)

                    TableColumn("CC") { entry in
                        Text(entry.countryFlag)
                    }
                    .width(min: 30, ideal: 35)

                    TableColumn("MESSAGES") { entry in
                        Text("\(entry.messages)")
                            .monospaced()
                    }
                    .width(min: 50, ideal: 80)

                    TableColumn("DOMAIN") { entry in
                        HStack(spacing: 4) {
                            ForEach(entry.domains.prefix(3), id: \.self) { domain in
                                BadgeLabel(text: domain, color: labelColor(for: domain))
                            }
                            if entry.domains.count > 3 {
                                Text("+\(entry.domains.count - 3)")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .width(min: 100, ideal: 200)

                    TableColumn("TYPE") { entry in
                        HStack(spacing: 4) {
                            if entry.hasDmarc {
                                BadgeLabel(text: "DMARC", color: .orange)
                            }
                            if entry.hasTlsrpt {
                                BadgeLabel(text: "TLS-RPT", color: .blue)
                            }
                        }
                    }
                    .width(min: 60, ideal: 120)

                    TableColumn("ISSUES") { entry in
                        if entry.totalIssues > 0 {
                            BadgeLabel(text: "\(entry.totalIssues)", color: .problemRed)
                        } else {
                            Text("0")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .width(min: 50, ideal: 70)
                }
                .tableStyle(.inset(alternatesRowBackgrounds: true))
            }
        }
        .navigationTitle("Mail Sources")
        .searchable(text: $searchText, prompt: "Search IPs, hostnames, orgs...")
        .toolbar {
            ToolbarItem {
                Toggle(isOn: $showIssuesOnly) {
                    Label("Issues Only", systemImage: "exclamationmark.triangle")
                }
                .toggleStyle(.button)
                .help("Show only sources with issues")
            }
        }
    }
}
