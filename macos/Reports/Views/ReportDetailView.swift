import SwiftUI

struct ReportDetailView: View {
    @EnvironmentObject var viewModel: ReportsViewModel

    var body: some View {
        Group {
            if let entry = viewModel.selectedEntry, let json = viewModel.detailJSON {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        switch entry.type {
                        case .dmarc:
                            dmarcDetail(json: json)
                        case .tlsrpt:
                            tlsrptDetail(json: json)
                        }
                    }
                    .padding()
                    .textSelection(.enabled)
                }
            } else {
                ContentUnavailableView {
                    Label("Select a Report", systemImage: "doc.text")
                } description: {
                    Text("Choose a report from the list to view details")
                }
            }
        }
        .navigationTitle(viewModel.selectedEntry?.displayTitle ?? "Detail")
        .toolbar {
            if viewModel.selectedEntry != nil, viewModel.detailJSON != nil {
                ToolbarItem {
                    Button {
                        if let json = viewModel.detailJSON {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(json, forType: .string)
                        }
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .help("Copy raw JSON")
                }
            }
        }
    }

    // MARK: - DMARC show (matches CLI: showDmarcTable)

    @ViewBuilder
    private func dmarcDetail(json: String) -> some View {
        if let data = json.data(using: .utf8),
           let report = try? JSONDecoder().decode(DmarcDetail.self, from: data) {
            // Metadata section
            Grid(alignment: .leading, horizontalSpacing: 8, verticalSpacing: 4) {
                metadataRow("Organization:", report.metadata.org_name)
                metadataRow("Report ID:", report.metadata.report_id)
                metadataRow("Domain:", report.policy.domain)
                GridRow {
                    Text("Policy:")
                        .foregroundStyle(.secondary)
                    BadgeLabel(text: report.policy.policy, color: policyColor(report.policy.policy))
                }
            }
            .font(.system(.body, design: .monospaced))
            .padding(.bottom, 12)

            // Records table (matches CLI columns)
            if !report.records.isEmpty {
                Table(report.records) {
                    TableColumn("SOURCE IP") { r in
                        Text(r.source_ip).monospaced()
                    }
                    .width(min: 100, ideal: 140)

                    TableColumn("COUNT") { r in
                        Text("\(r.count)").monospaced()
                    }
                    .width(min: 40, ideal: 55)

                    TableColumn("DISPOSITION") { r in
                        Text(r.disposition).monospaced()
                    }
                    .width(min: 60, ideal: 100)

                    TableColumn("ENVELOPE FROM") { r in
                        Text(r.envelope_from).monospaced().lineLimit(1)
                    }
                    .width(min: 80, ideal: 160)

                    TableColumn("HEADER FROM") { r in
                        Text(r.header_from).monospaced().lineLimit(1)
                    }
                    .width(min: 80, ideal: 160)

                    TableColumn("DKIM") { r in
                        Text(r.dkim_eval)
                            .monospaced()
                            .foregroundStyle(r.dkim_eval == "pass" ? .green : .red)
                    }
                    .width(min: 40, ideal: 50)

                    TableColumn("SPF") { r in
                        Text(r.spf_eval)
                            .monospaced()
                            .foregroundStyle(r.spf_eval == "pass" ? .green : .red)
                    }
                    .width(min: 40, ideal: 50)
                }
                .tableStyle(.inset(alternatesRowBackgrounds: true))
                .frame(minHeight: max(200, CGFloat(report.records.count * 28 + 40)))
            }
        } else {
            rawJSONView(json: json)
        }
    }

    // MARK: - TLS-RPT show

    @ViewBuilder
    private func tlsrptDetail(json: String) -> some View {
        if let data = json.data(using: .utf8),
           let report = try? JSONDecoder().decode(TlsDetail.self, from: data) {
            // Metadata (left-aligned Grid, same as DMARC)
            Grid(alignment: .leading, horizontalSpacing: 8, verticalSpacing: 4) {
                metadataRow("Organization:", report.organization_name)
                metadataRow("Report ID:", report.report_id)
            }
            .font(.system(.body, design: .monospaced))
            .padding(.bottom, 16)

            // Policies
            ForEach(report.policies) { policy in
                VStack(alignment: .leading, spacing: 12) {
                    // Policy header with badge
                    HStack(spacing: 8) {
                        Text(policy.policy_domain)
                            .font(.system(.body, design: .monospaced))
                            .fontWeight(.semibold)
                        BadgeLabel(text: policy.policy_type, color: policyColor(policy.policy_type))
                    }

                    // Session counts with progress bar
                    let total = policy.total_successful + policy.total_failure
                    let ratio = total > 0 ? Double(policy.total_successful) / Double(total) : 1.0

                    HStack(spacing: 24) {
                        Grid(alignment: .leading, horizontalSpacing: 8, verticalSpacing: 2) {
                            GridRow {
                                Text("Successful:")
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                Text("\(policy.total_successful)")
                                    .font(.system(.body, design: .monospaced))
                                    .fontWeight(.semibold)
                                    .foregroundStyle(.green)
                            }
                            GridRow {
                                Text("Failed:")
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                Text("\(policy.total_failure)")
                                    .font(.system(.body, design: .monospaced))
                                    .fontWeight(.semibold)
                                    .foregroundStyle(policy.total_failure > 0 ? .red : .secondary)
                            }
                            GridRow {
                                Text("Total:")
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                Text("\(total)")
                                    .font(.system(.body, design: .monospaced))
                            }
                        }

                        // Success rate bar
                        if total > 0 {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("\(String(format: "%.1f", ratio * 100))% success")
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                GeometryReader { geo in
                                    ZStack(alignment: .leading) {
                                        RoundedRectangle(cornerRadius: 4)
                                            .fill(Color.red.opacity(0.2))
                                            .frame(height: 8)
                                        RoundedRectangle(cornerRadius: 4)
                                            .fill(Color.green)
                                            .frame(width: geo.size.width * ratio, height: 8)
                                    }
                                }
                                .frame(height: 8)
                            }
                            .frame(maxWidth: 200)
                        }
                    }

                    // Failure details table
                    if !policy.failures.isEmpty {
                        Table(policy.failures) {
                            TableColumn("RESULT TYPE") { f in
                                Text(f.result_type).monospaced()
                            }
                            .width(min: 80, ideal: 160)

                            TableColumn("SENDING MTA IP") { f in
                                Text(f.sending_mta_ip).monospaced()
                            }
                            .width(min: 80, ideal: 140)

                            TableColumn("RECEIVING MX") { f in
                                Text(f.receiving_mx_hostname).monospaced()
                            }
                            .width(min: 80, ideal: 180)

                            TableColumn("SESSIONS") { f in
                                Text("\(f.failed_session_count)")
                                    .monospaced()
                                    .foregroundStyle(.red)
                            }
                            .width(min: 50, ideal: 70)
                        }
                        .tableStyle(.inset(alternatesRowBackgrounds: true))
                        .frame(minHeight: max(120, CGFloat(policy.failures.count * 28 + 40)))
                    }
                }
                .padding(12)
                .background(RoundedRectangle(cornerRadius: 8).fill(.background.secondary))
                .padding(.bottom, 8)
            }
        } else {
            rawJSONView(json: json)
        }
    }

    // MARK: - Helpers

    @ViewBuilder
    private func metadataRow(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label)
                .foregroundStyle(.secondary)
            Text(value)
        }
    }

    @ViewBuilder
    private func rawJSONView(json: String) -> some View {
        ScrollView(.horizontal) {
            Text(json)
                .font(.system(.caption, design: .monospaced))
                .padding(8)
        }
    }
}
