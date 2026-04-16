import SwiftUI

/// A DMARC record row enriched with IP info, used as the Table data source.
struct EnrichedDmarcRecord: Identifiable {
    let record: DmarcDetailRecord
    let enrichment: IpEnrichment?

    var id: String { record.id }
}

struct ReportDetailView: View {
    @EnvironmentObject var viewModel: ReportsViewModel

    var body: some View {
        if let entry = viewModel.selectedEntry {
            VStack(spacing: 0) {
                detailHeader(entry: entry, json: viewModel.detailJSON)
                Divider()
                if viewModel.isLoadingDetail || viewModel.detailJSON == nil {
                    VStack(spacing: 8) {
                        ProgressView()
                            .controlSize(.regular)
                        Text("Loading report...")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if let json = viewModel.detailJSON {
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
                }
            }
        }
    }

    @ViewBuilder
    private func detailHeader(entry: ReportEntry, json: String?) -> some View {
        HStack(spacing: 8) {
            Image(systemName: entry.type == .dmarc ? "shield.checkered" : "lock.shield")
                .foregroundStyle(.secondary)
            Text(entry.displayTitle)
                .font(.headline)
                .lineLimit(1)

            // Subtle indicator that background enrichment is still running
            if !viewModel.enrichments.isEmpty || viewModel.isLoadingDetail {
                EmptyView() // placeholder; spinner handled in main body
            }

            Spacer()

            if let json {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(json, forType: .string)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .help("Copy raw JSON")
            }

            Button {
                viewModel.closeDetail()
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.borderless)
            .help("Close detail")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.background.secondary)
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

            // Records table (matches CLI columns with IP enrichment)
            if !report.records.isEmpty {
                let enrichedRows = report.records.map { rec in
                    EnrichedDmarcRecord(
                        record: rec,
                        enrichment: viewModel.enrichments[rec.source_ip]
                    )
                }
                Table(enrichedRows) {
                    TableColumn("SOURCE IP") { row in
                        Text(row.record.source_ip).monospaced()
                    }
                    .width(min: 100, ideal: 130)

                    TableColumn("PTR") { row in
                        let display = row.enrichment?.ptrDisplay(sourceIP: row.record.source_ip) ?? "-"
                        Text(display)
                            .monospaced().lineLimit(1)
                            .foregroundStyle(display == "-" ? .secondary : .primary)
                    }
                    .width(min: 80, ideal: 180)

                    TableColumn("ASN") { row in
                        let display = row.enrichment?.asnDisplay ?? "-"
                        Text(display)
                            .monospaced().lineLimit(1)
                            .foregroundStyle(display == "-" ? .secondary : .primary)
                    }
                    .width(min: 80, ideal: 200)

                    TableColumn("CC") { row in
                        Text(row.enrichment?.countryFlag ?? "-")
                    }
                    .width(min: 30, ideal: 35)

                    TableColumn("COUNT") { row in
                        Text("\(row.record.count)").monospaced()
                    }
                    .width(min: 40, ideal: 55)

                    TableColumn("DISP") { row in
                        Text(row.record.disposition).monospaced()
                    }
                    .width(min: 50, ideal: 80)

                    TableColumn("FROM") { row in
                        Text(row.record.from).monospaced().lineLimit(1)
                    }
                    .width(min: 80, ideal: 180)

                    TableColumn("DKIM") { row in
                        Text(row.record.dkim_eval)
                            .monospaced()
                            .foregroundStyle(row.record.dkim_eval == "pass" ? Color.passGreen : Color.failRed)
                    }
                    .width(min: 40, ideal: 50)

                    TableColumn("SPF") { row in
                        Text(row.record.spf_eval)
                            .monospaced()
                            .foregroundStyle(row.record.spf_eval == "pass" ? Color.passGreen : Color.failRed)
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
                                    .foregroundStyle(Color.passGreen)
                            }
                            GridRow {
                                Text("Failed:")
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                Text("\(policy.total_failure)")
                                    .font(.system(.body, design: .monospaced))
                                    .fontWeight(.semibold)
                                    .foregroundStyle(policy.total_failure > 0 ? Color.failRed : Color.secondary)
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
                                            .fill(Color.failRed.opacity(0.2))
                                            .frame(height: 8)
                                        RoundedRectangle(cornerRadius: 4)
                                            .fill(Color.passGreen)
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
                            .width(min: 80, ideal: 130)

                            TableColumn("PTR") { f in
                                let info = viewModel.enrichments[f.sending_mta_ip]
                                Text(info?.ptrDisplay(sourceIP: f.sending_mta_ip) ?? "-")
                                    .monospaced().lineLimit(1)
                                    .foregroundStyle(info?.ptr.isEmpty ?? true ? .secondary : .primary)
                            }
                            .width(min: 80, ideal: 160)

                            TableColumn("ASN") { f in
                                let info = viewModel.enrichments[f.sending_mta_ip]
                                Text(info?.asnDisplay ?? "-")
                                    .monospaced().lineLimit(1)
                            }
                            .width(min: 80, ideal: 160)

                            TableColumn("RECEIVING MX") { f in
                                Text(f.receiving_mx_hostname).monospaced()
                            }
                            .width(min: 80, ideal: 180)

                            TableColumn("SESSIONS") { f in
                                Text("\(f.failed_session_count)")
                                    .monospaced()
                                    .foregroundStyle(Color.failRed)
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
