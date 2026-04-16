import Charts
import SwiftUI

// MARK: - Aggregated Stats

struct OrgCount: Identifiable, Hashable {
    let org: String
    let count: Int
    var id: String { org }
}

struct CategoryCount: Identifiable, Hashable {
    let category: String
    let count: UInt64
    var id: String { category }
}

struct DomainAuthStat: Identifiable, Hashable {
    let domain: String
    let dkimPass: UInt64
    let dkimFail: UInt64
    let spfPass: UInt64
    let spfFail: UInt64
    var id: String { domain }

    var dkimTotal: UInt64 { dkimPass + dkimFail }
    var spfTotal: UInt64 { spfPass + spfFail }
    var dkimPassRatio: Double { dkimTotal > 0 ? Double(dkimPass) / Double(dkimTotal) : 0 }
    var spfPassRatio: Double { spfTotal > 0 ? Double(spfPass) / Double(spfTotal) : 0 }
}

struct DomainTlsStat: Identifiable, Hashable {
    let domain: String
    let success: UInt64
    let failure: UInt64
    var id: String { domain }

    var total: UInt64 { success + failure }
    var successRatio: Double { total > 0 ? Double(success) / Double(total) : 0 }
}

struct DashboardStats {
    var dmarcOrgs: [OrgCount] = []
    var tlsrptOrgs: [OrgCount] = []

    var domainAuth: [DomainAuthStat] = []
    var dmarcDispositions: [CategoryCount] = []

    var domainTls: [DomainTlsStat] = []
    var tlsPolicyTypes: [CategoryCount] = []
    var tlsFailureTypes: [CategoryCount] = []

    var hasDmarc: Bool { !domainAuth.isEmpty }
    var hasTlsrpt: Bool { !domainTls.isEmpty || !tlsPolicyTypes.isEmpty }
}

// MARK: - Stats Loader

@MainActor
final class DashboardStatsLoader: ObservableObject {
    @Published var isLoading = false
    @Published var stats = DashboardStats()

    func load(entries: [ReportEntry]) async {
        isLoading = true
        defer { isLoading = false }

        var dmarcOrgs: [String: Int] = [:]
        var tlsrptOrgs: [String: Int] = [:]

        // Per-domain DMARC aggregates
        var dkimPass: [String: UInt64] = [:]
        var dkimFail: [String: UInt64] = [:]
        var spfPass: [String: UInt64] = [:]
        var spfFail: [String: UInt64] = [:]
        var dispositions: [String: UInt64] = [:]

        // Per-domain TLS aggregates
        var tlsSuccess: [String: UInt64] = [:]
        var tlsFailure: [String: UInt64] = [:]
        var tlsPolicyTypes: [String: UInt64] = [:]
        var tlsFailureTypes: [String: UInt64] = [:]

        let core = ReportsCore.shared
        let decoder = JSONDecoder()

        for (index, entry) in entries.enumerated() {
            switch entry.type {
            case .dmarc:
                dmarcOrgs[entry.org, default: 0] += 1
                if let json = try? core.show(type: .dmarc, account: entry.account, filename: entry.filename),
                   let data = json.data(using: .utf8),
                   let detail = try? decoder.decode(DmarcDetail.self, from: data) {
                    let domain = detail.policy.domain.isEmpty ? entry.domain : detail.policy.domain
                    for rec in detail.records {
                        if rec.dkim_eval == "pass" {
                            dkimPass[domain, default: 0] += rec.count
                        } else {
                            dkimFail[domain, default: 0] += rec.count
                        }
                        if rec.spf_eval == "pass" {
                            spfPass[domain, default: 0] += rec.count
                        } else {
                            spfFail[domain, default: 0] += rec.count
                        }
                        let disp = rec.disposition.isEmpty ? "none" : rec.disposition
                        dispositions[disp, default: 0] += rec.count
                    }
                }
            case .tlsrpt:
                tlsrptOrgs[entry.org, default: 0] += 1
                if let json = try? core.show(type: .tlsrpt, account: entry.account, filename: entry.filename),
                   let data = json.data(using: .utf8),
                   let detail = try? decoder.decode(TlsDetail.self, from: data) {
                    for policy in detail.policies {
                        let domain = policy.policy_domain.isEmpty ? entry.domain : policy.policy_domain
                        let type = policy.policy_type.isEmpty ? "unknown" : policy.policy_type
                        tlsPolicyTypes[type, default: 0] += policy.total_successful + policy.total_failure
                        tlsSuccess[domain, default: 0] += policy.total_successful
                        tlsFailure[domain, default: 0] += policy.total_failure
                        for f in policy.failures {
                            let ft = f.result_type.isEmpty ? "unknown" : f.result_type
                            tlsFailureTypes[ft, default: 0] += f.failed_session_count
                        }
                    }
                }
            }

            if index % 25 == 0 {
                await Task.yield()
            }
        }

        // Build per-domain structs
        let dmarcDomains = Set(dkimPass.keys).union(dkimFail.keys).union(spfPass.keys).union(spfFail.keys)
        let domainAuth = dmarcDomains.map { d in
            DomainAuthStat(
                domain: d,
                dkimPass: dkimPass[d] ?? 0,
                dkimFail: dkimFail[d] ?? 0,
                spfPass: spfPass[d] ?? 0,
                spfFail: spfFail[d] ?? 0
            )
        }
        .sorted { ($0.dkimTotal + $0.spfTotal) > ($1.dkimTotal + $1.spfTotal) }

        let tlsDomains = Set(tlsSuccess.keys).union(tlsFailure.keys)
        let domainTls = tlsDomains.map { d in
            DomainTlsStat(
                domain: d,
                success: tlsSuccess[d] ?? 0,
                failure: tlsFailure[d] ?? 0
            )
        }
        .sorted { $0.total > $1.total }

        var newStats = DashboardStats()
        newStats.dmarcOrgs = dmarcOrgs.sorted { $0.value > $1.value }.map { OrgCount(org: $0.key, count: $0.value) }
        newStats.tlsrptOrgs = tlsrptOrgs.sorted { $0.value > $1.value }.map { OrgCount(org: $0.key, count: $0.value) }
        newStats.domainAuth = domainAuth
        newStats.dmarcDispositions = dispositions.sorted { $0.value > $1.value }.map { CategoryCount(category: $0.key, count: $0.value) }
        newStats.domainTls = domainTls
        newStats.tlsPolicyTypes = tlsPolicyTypes.sorted { $0.value > $1.value }.map { CategoryCount(category: $0.key, count: $0.value) }
        newStats.tlsFailureTypes = tlsFailureTypes.sorted { $0.value > $1.value }.map { CategoryCount(category: $0.key, count: $0.value) }
        stats = newStats
    }
}

// MARK: - Dashboard View

struct DashboardView: View {
    @EnvironmentObject var viewModel: ReportsViewModel
    @StateObject private var loader = DashboardStatsLoader()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if loader.isLoading {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Aggregating reports...")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                HStack(alignment: .top, spacing: 16) {
                    dmarcColumn
                    mtaStsColumn
                }
            }
            .padding(24)
        }
        .navigationTitle("Dashboard")
        .background(Color(.windowBackgroundColor))
        .task(id: viewModel.entriesVersion) {
            await loader.load(entries: viewModel.entries)
        }
    }

    // MARK: - DMARC Column

    private var dmarcColumn: some View {
        VStack(alignment: .leading, spacing: 16) {
            ColumnHeader(title: "DMARC", color: .orange, icon: "shield.checkered")

            SectionBox(title: "Report Sources") {
                orgChart(data: loader.stats.dmarcOrgs, color: .orange)
            }

            SectionBox(title: "DKIM Authentication by Domain") {
                domainAuthChart(
                    stats: loader.stats.domainAuth,
                    pass: { $0.dkimPass },
                    fail: { $0.dkimFail },
                    ratio: { $0.dkimPassRatio }
                )
            }

            SectionBox(title: "SPF Authentication by Domain") {
                domainAuthChart(
                    stats: loader.stats.domainAuth,
                    pass: { $0.spfPass },
                    fail: { $0.spfFail },
                    ratio: { $0.spfPassRatio }
                )
            }

            SectionBox(title: "Disposition") {
                categoryBar(data: loader.stats.dmarcDispositions, colorFor: policyColor)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    // MARK: - MTA-STS Column

    private var mtaStsColumn: some View {
        VStack(alignment: .leading, spacing: 16) {
            ColumnHeader(title: "MTA-STS", color: .teal, icon: "lock.shield")

            SectionBox(title: "Report Sources") {
                orgChart(data: loader.stats.tlsrptOrgs, color: .teal)
            }

            SectionBox(title: "TLS Sessions by Domain") {
                domainTlsChart(stats: loader.stats.domainTls)
            }

            SectionBox(title: "Policy Type") {
                categoryBar(data: loader.stats.tlsPolicyTypes, colorFor: policyColor)
            }

            SectionBox(title: "Failure Type") {
                categoryBar(data: loader.stats.tlsFailureTypes, colorFor: failureColor)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    // MARK: - Org chart (donut)

    @ViewBuilder
    private func orgChart(data: [OrgCount], color: Color) -> some View {
        if data.isEmpty {
            emptyPlaceholder(height: 80)
        } else {
            let top = Array(data.prefix(8))
            let others = data.dropFirst(8).reduce(0) { $0 + $1.count }
            let display: [OrgCount] = others > 0
                ? top + [OrgCount(org: "Others", count: others)]
                : top
            let total = display.reduce(0) { $0 + $1.count }

            HStack(alignment: .center, spacing: 16) {
                Chart(Array(display.enumerated()), id: \.element.id) { index, item in
                    SectorMark(
                        angle: .value("Count", item.count),
                        innerRadius: .ratio(0.55),
                        angularInset: 1.5
                    )
                    .cornerRadius(2)
                    .foregroundStyle(orgColor(index: index, baseColor: color))
                }
                .frame(width: 140, height: 140)

                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(display.enumerated()), id: \.element.id) { index, item in
                        HStack(spacing: 6) {
                            Circle()
                                .fill(orgColor(index: index, baseColor: color))
                                .frame(width: 8, height: 8)
                            Text(item.org)
                                .font(.caption.monospaced())
                                .lineLimit(1)
                            Spacer()
                            Text("\(item.count)")
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                            let pct = total > 0 ? Double(item.count) / Double(total) * 100 : 0
                            Text("(\(String(format: "%.1f", pct))%)")
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private func orgColor(index: Int, baseColor: Color) -> Color {
        // Generate visually distinct shades by varying opacity/saturation via index
        let opacities: [Double] = [1.0, 0.85, 0.7, 0.55, 0.4, 0.3, 0.22, 0.17, 0.12]
        let i = min(index, opacities.count - 1)
        return baseColor.opacity(opacities[i])
    }

    // MARK: - Per-domain auth chart (DKIM or SPF)

    @ViewBuilder
    private func domainAuthChart(
        stats: [DomainAuthStat],
        pass: @escaping (DomainAuthStat) -> UInt64,
        fail: @escaping (DomainAuthStat) -> UInt64,
        ratio: @escaping (DomainAuthStat) -> Double
    ) -> some View {
        let visible = stats.filter { pass($0) + fail($0) > 0 }.prefix(10)
        if visible.isEmpty {
            emptyPlaceholder(height: 80)
        } else {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(Array(visible)) { stat in
                    stackedDomainBar(
                        domain: stat.domain,
                        pass: pass(stat),
                        fail: fail(stat),
                        ratio: ratio(stat)
                    )
                }
            }
        }
    }

    // MARK: - Per-domain TLS chart

    @ViewBuilder
    private func domainTlsChart(stats: [DomainTlsStat]) -> some View {
        let visible = stats.filter { $0.total > 0 }.prefix(10)
        if visible.isEmpty {
            emptyPlaceholder(height: 80)
        } else {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(Array(visible)) { stat in
                    stackedDomainBar(
                        domain: stat.domain,
                        pass: stat.success,
                        fail: stat.failure,
                        ratio: stat.successRatio
                    )
                }
            }
        }
    }

    // MARK: - Shared per-domain stacked bar

    @ViewBuilder
    private func stackedDomainBar(domain: String, pass: UInt64, fail: UInt64, ratio: Double) -> some View {
        let passRatio = ratio
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(domain)
                    .font(.caption.monospaced())
                    .lineLimit(1)
                Spacer()
                Text("\(String(format: "%.1f", passRatio * 100))%")
                    .font(.caption.monospaced())
                    .foregroundStyle(ratioColor(passRatio))
            }

            Chart {
                BarMark(x: .value("Count", pass))
                    .foregroundStyle(.green)
                    .annotation(position: .overlay) {
                        if pass > 0 {
                            Text("\(pass)")
                                .font(.caption2.weight(.medium))
                                .foregroundStyle(.white)
                        }
                    }
                BarMark(x: .value("Count", fail))
                    .foregroundStyle(.red)
                    .annotation(position: .overlay) {
                        if fail > 0 {
                            Text("\(fail)")
                                .font(.caption2.weight(.medium))
                                .foregroundStyle(.white)
                        }
                    }
            }
            .chartXAxis(.hidden)
            .chartYAxis(.hidden)
            .chartPlotStyle { plot in
                plot.clipShape(RoundedRectangle(cornerRadius: 3))
            }
            .frame(height: 18)
        }
    }

    private func ratioColor(_ ratio: Double) -> Color {
        if ratio >= 0.95 { return .green }
        if ratio >= 0.8 { return .orange }
        return .red
    }

    // MARK: - Category bar (aggregate distribution)

    @ViewBuilder
    private func categoryBar(data: [CategoryCount], colorFor: @escaping (String) -> Color) -> some View {
        let total = data.reduce(UInt64(0)) { $0 + $1.count }
        if total == 0 {
            emptyPlaceholder(height: 60)
        } else {
            VStack(alignment: .leading, spacing: 8) {
                Chart(data) { item in
                    BarMark(x: .value("Count", item.count))
                        .foregroundStyle(colorFor(item.category))
                }
                .chartXAxis(.hidden)
                .chartYAxis(.hidden)
                .chartPlotStyle { plot in
                    plot.clipShape(RoundedRectangle(cornerRadius: 4))
                }
                .frame(height: 20)

                FlowLayout(spacing: 10) {
                    ForEach(data) { item in
                        HStack(spacing: 4) {
                            Circle().fill(colorFor(item.category)).frame(width: 8, height: 8)
                            Text(item.category).font(.caption.monospaced())
                            Text("\(item.count)")
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                            let pct = Double(item.count) / Double(total) * 100
                            Text("(\(String(format: "%.1f", pct))%)")
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func emptyPlaceholder(height: CGFloat) -> some View {
        Text("No data")
            .font(.caption)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, minHeight: height)
    }
}

// MARK: - Column Header

struct ColumnHeader: View {
    let title: String
    let color: Color
    let icon: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundStyle(color)
            Text(title)
                .font(.title2.weight(.semibold))
                .foregroundStyle(color)
        }
    }
}

// MARK: - Section Box

struct SectionBox<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)
            content()
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 8).fill(.background))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.15), lineWidth: 1))
        }
    }
}

// MARK: - Failure type color

private func failureColor(_ type: String) -> Color {
    let lower = type.lowercased()
    if lower.contains("success") { return .green }
    if lower.contains("starttls") || lower.contains("expired") || lower.contains("invalid") { return .red }
    if lower.contains("mismatch") || lower.contains("untrusted") { return .orange }
    if lower.contains("dnssec") || lower.contains("sts") { return .purple }
    return .gray
}

// MARK: - Flow Layout

struct FlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0
        var maxWidth: CGFloat = 0

        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x + size.width > width && x > 0 {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            x += size.width + spacing
            maxWidth = max(maxWidth, x)
            rowHeight = max(rowHeight, size.height)
        }
        return CGSize(width: min(maxWidth, width), height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX
        var y = bounds.minY
        var rowHeight: CGFloat = 0

        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x + size.width > bounds.maxX && x > bounds.minX {
                x = bounds.minX
                y += rowHeight + spacing
                rowHeight = 0
            }
            view.place(at: CGPoint(x: x, y: y), proposal: .unspecified)
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}
