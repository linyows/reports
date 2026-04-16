import Charts
import SwiftUI

// MARK: - Aggregated Stats

struct OrgCount: Identifiable, Hashable {
    let org: String
    let count: Int
    var id: String { org }
}


struct DomainAuthStat: Identifiable, Hashable {
    let domain: String
    let dkimPass: UInt64
    let dkimFail: UInt64
    let spfPass: UInt64
    let spfFail: UInt64
    let dispNone: UInt64
    let dispQuarantine: UInt64
    let dispReject: UInt64
    var id: String { domain }

    var dkimTotal: UInt64 { dkimPass + dkimFail }
    var spfTotal: UInt64 { spfPass + spfFail }
    var dkimPassRatio: Double { dkimTotal > 0 ? Double(dkimPass) / Double(dkimTotal) : 0 }
    var spfPassRatio: Double { spfTotal > 0 ? Double(spfPass) / Double(spfTotal) : 0 }
    var dispTotal: UInt64 { dispNone + dispQuarantine + dispReject }
}

struct DomainTlsStat: Identifiable, Hashable {
    let domain: String
    let success: UInt64
    let failure: UInt64
    let policyTypes: [(name: String, count: UInt64)]
    let failureTypes: [(name: String, count: UInt64)]
    var id: String { domain }

    var total: UInt64 { success + failure }
    var successRatio: Double { total > 0 ? Double(success) / Double(total) : 0 }

    static func == (lhs: DomainTlsStat, rhs: DomainTlsStat) -> Bool { lhs.domain == rhs.domain }
    func hash(into hasher: inout Hasher) { hasher.combine(domain) }
}

struct DashboardStats {
    var dmarcOrgs: [OrgCount] = []
    var tlsrptOrgs: [OrgCount] = []

    var domainAuth: [DomainAuthStat] = []

    var domainTls: [DomainTlsStat] = []

    // Check summary
    var dmarcReports: Int = 0
    var dmarcTotal: UInt64 = 0
    var dmarcPass: UInt64 = 0
    var dmarcFail: UInt64 = 0
    var tlsReports: Int = 0
    var tlsTotalSuccess: UInt64 = 0
    var tlsTotalFailure: UInt64 = 0

    var hasDmarc: Bool { !domainAuth.isEmpty }
    var hasTlsrpt: Bool { !domainTls.isEmpty }

    var dmarcFailRate: Int {
        dmarcTotal > 0 ? Int(dmarcFail * 100 / dmarcTotal) : 0
    }

    var dmarcSummary: AttributedString {
        var s = AttributedString("")
        var num = AttributedString("\(dmarcReports)")
        num.font = .body.monospaced().weight(.bold)
        s += num
        s += plain(" reports, ")
        var fail = AttributedString("\(dmarcFail)/\(dmarcTotal)")
        fail.font = .body.monospaced().weight(.bold)
        s += fail
        s += plain(" messages failed (")
        var rate = AttributedString("\(dmarcFailRate)%")
        rate.font = .body.monospaced().weight(.bold)
        s += rate
        s += plain(")")
        return s
    }

    var tlsSummary: AttributedString {
        var s = AttributedString("")
        var num = AttributedString("\(tlsReports)")
        num.font = .body.monospaced().weight(.bold)
        s += num
        s += plain(" reports, ")
        var fail = AttributedString("\(tlsTotalFailure)")
        fail.font = .body.monospaced().weight(.bold)
        s += fail
        s += plain(" failures")
        return s
    }

    private func plain(_ str: String) -> AttributedString {
        var a = AttributedString(str)
        a.font = .body.monospaced()
        return a
    }
}

// MARK: - Stats Loader

@MainActor
final class DashboardStatsLoader: ObservableObject {
    @Published var isLoading = false
    @Published var stats = DashboardStats()

    func load() async {
        isLoading = true
        defer { isLoading = false }

        let result: DashboardJSON? = await Task.detached(priority: .userInitiated) {
            try? ReportsCore.shared.dashboard()
        }.value

        guard let dash = result else { return }

        var newStats = DashboardStats()
        newStats.dmarcOrgs = dash.dmarc_orgs.sorted { $0.v > $1.v }.map { OrgCount(org: $0.k, count: Int($0.v)) }
        newStats.tlsrptOrgs = dash.tlsrpt_orgs.sorted { $0.v > $1.v }.map { OrgCount(org: $0.k, count: Int($0.v)) }
        newStats.domainAuth = dash.domain_auth.map {
            DomainAuthStat(domain: $0.domain, dkimPass: $0.dkim_pass, dkimFail: $0.dkim_fail, spfPass: $0.spf_pass, spfFail: $0.spf_fail, dispNone: $0.disp_none, dispQuarantine: $0.disp_quarantine, dispReject: $0.disp_reject)
        }.sorted { ($0.dkimTotal + $0.spfTotal) > ($1.dkimTotal + $1.spfTotal) }

        newStats.domainTls = dash.domain_tls.map {
            DomainTlsStat(
                domain: $0.domain, success: $0.success, failure: $0.failure,
                policyTypes: $0.policy_types.map { ($0.k, $0.v) },
                failureTypes: $0.failure_types.map { ($0.k, $0.v) }
            )
        }.sorted { $0.total > $1.total }

        // Summary totals
        newStats.dmarcReports = dash.dmarc_orgs.reduce(0) { $0 + Int($1.v) }
        newStats.tlsReports = dash.tlsrpt_orgs.reduce(0) { $0 + Int($1.v) }
        for stat in newStats.domainAuth {
            newStats.dmarcTotal += stat.dkimTotal
            newStats.dmarcPass += stat.dkimPass
            newStats.dmarcFail += stat.dkimFail
        }
        for stat in newStats.domainTls {
            newStats.tlsTotalSuccess += stat.success
            newStats.tlsTotalFailure += stat.failure
        }

        stats = newStats
    }
}

// MARK: - Dashboard View

struct DashboardView: View {
    @EnvironmentObject var viewModel: ReportsViewModel
    @StateObject private var loader = DashboardStatsLoader()

    var body: some View {
        GeometryReader { geo in
            let wide = geo.size.width >= 1600
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

                    HStack(alignment: .top, spacing: 40) {
                        dmarcColumn(wide: wide)
                        mtaStsColumn(wide: wide)
                    }
                }
                .padding(24)
            }
        }
        .navigationTitle("Dashboard")
        .background(Color(.windowBackgroundColor))
        .task(id: viewModel.entriesVersion) {
            await loader.load()
        }
    }

    // MARK: - DMARC Column

    private func dmarcColumn(wide: Bool) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            ColumnHeader(title: "DMARC")
            Text(loader.stats.dmarcSummary)
                .foregroundStyle(.secondary)

            SectionBox(title: "All Report Sources") {
                orgChart(data: loader.stats.dmarcOrgs, color: .neonYellow)
            }

            let dkim = SectionBox(title: "DKIM Authentication") {
                domainAuthChart(
                    stats: loader.stats.domainAuth,
                    pass: { $0.dkimPass },
                    fail: { $0.dkimFail },
                    ratio: { $0.dkimPassRatio }
                )
            }
            let spf = SectionBox(title: "SPF Authentication") {
                domainAuthChart(
                    stats: loader.stats.domainAuth,
                    pass: { $0.spfPass },
                    fail: { $0.spfFail },
                    ratio: { $0.spfPassRatio }
                )
            }

            if wide {
                HStack(alignment: .top, spacing: 16) {
                    dkim.frame(maxWidth: .infinity)
                    spf.frame(maxWidth: .infinity)
                }
            } else {
                dkim
                spf
            }

            SectionBox(title: "DMARC Disposition") {
                domainDispositionChart(stats: loader.stats.domainAuth)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    // MARK: - TLS-RPT Column

    private func mtaStsColumn(wide: Bool) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            ColumnHeader(title: "TLS-RPT")
            Text(loader.stats.tlsSummary)
                .foregroundStyle(.secondary)

            SectionBox(title: "All Report Sources") {
                orgChart(data: loader.stats.tlsrptOrgs, color: .neonYellow)
            }

            SectionBox(title: "TLS Sessions") {
                domainTlsChart(stats: loader.stats.domainTls)
            }

            let policyType = SectionBox(title: "Policy Type") {
                domainKVChart(stats: loader.stats.domainTls, extract: { $0.policyTypes }, colorFor: policyColor)
            }
            let failureType = SectionBox(title: "Failure Type") {
                domainKVChart(stats: loader.stats.domainTls, extract: { $0.failureTypes }, colorFor: failureColor)
            }

            if wide {
                HStack(alignment: .top, spacing: 16) {
                    policyType.frame(maxWidth: .infinity)
                    failureType.frame(maxWidth: .infinity)
                }
            } else {
                policyType
                failureType
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
                passFailLegend
            }
        }
    }

    // MARK: - Per-domain Disposition chart

    @ViewBuilder
    private func domainDispositionChart(stats: [DomainAuthStat]) -> some View {
        let visible = stats.filter { $0.dispTotal > 0 }.prefix(10)
        if visible.isEmpty {
            emptyPlaceholder(height: 80)
        } else {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(Array(visible)) { stat in
                    let total = stat.dispTotal
                    let noneRatio = total > 0 ? Double(stat.dispNone) / Double(total) * 100 : 0
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(stat.domain)
                                .font(.caption.monospaced())
                                .lineLimit(1)
                            Spacer()
                            if stat.dispReject > 0 {
                                let rejectPct = Double(stat.dispReject) / Double(total) * 100
                                Text("\(String(format: "%.0f", rejectPct))%")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(Color.failRed)
                            } else if stat.dispQuarantine > 0 {
                                let quarantinePct = Double(stat.dispQuarantine) / Double(total) * 100
                                Text("\(String(format: "%.0f", quarantinePct))%")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.orange)
                            } else {
                                Text("\(String(format: "%.0f", noneRatio))%")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.gray)
                            }
                        }

                        Chart {
                            BarMark(x: .value("Count", stat.dispNone))
                                .foregroundStyle(Color.gray)
                                .annotation(position: .overlay) {
                                    if stat.dispNone > 0 {
                                        Text("\(stat.dispNone)")
                                            .font(.caption2.weight(.bold))
                                            .foregroundStyle(Color.barText)
                                    }
                                }
                            BarMark(x: .value("Count", stat.dispQuarantine))
                                .foregroundStyle(Color.orange)
                                .annotation(position: .overlay) {
                                    if stat.dispQuarantine > 0 {
                                        Text("\(stat.dispQuarantine)")
                                            .font(.caption2.weight(.bold))
                                            .foregroundStyle(Color.barText)
                                    }
                                }
                            BarMark(x: .value("Count", stat.dispReject))
                                .foregroundStyle(Color.failRed)
                                .annotation(position: .overlay) {
                                    if stat.dispReject > 0 {
                                        Text("\(stat.dispReject)")
                                            .font(.caption2.weight(.bold))
                                            .foregroundStyle(Color.barText)
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

                // Legend (bottom-right)
                HStack {
                    Spacer()
                    HStack(spacing: 12) {
                        HStack(spacing: 3) {
                            Circle().fill(Color.gray).frame(width: 6, height: 6)
                            Text("none").font(.caption2.monospaced()).foregroundStyle(.gray)
                        }
                        HStack(spacing: 3) {
                            Circle().fill(Color.orange).frame(width: 6, height: 6)
                            Text("quarantine").font(.caption2.monospaced()).foregroundStyle(.orange)
                        }
                        HStack(spacing: 3) {
                            Circle().fill(Color.failRed).frame(width: 6, height: 6)
                            Text("reject").font(.caption2.monospaced()).foregroundStyle(Color.failRed)
                        }
                    }
                }
                .padding(.top, 2)
            }
        }
    }

    // MARK: - Per-domain KV chart (policy type / failure type)

    @ViewBuilder
    private func domainKVChart(
        stats: [DomainTlsStat],
        extract: @escaping (DomainTlsStat) -> [(name: String, count: UInt64)],
        colorFor: @escaping (String) -> Color
    ) -> some View {
        let visible = stats.filter { !extract($0).isEmpty }.prefix(10)
        if visible.isEmpty {
            emptyPlaceholder(height: 80)
        } else {
            let allNames = Array(visible).reduce(into: [String]()) { result, stat in
                for item in extract(stat) where !result.contains(item.name) {
                    result.append(item.name)
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                ForEach(Array(visible)) { stat in
                    let items = extract(stat)
                    let total = items.reduce(UInt64(0)) { $0 + $1.count }
                    let topItem = items.max(by: { $0.count < $1.count })
                    let topPct = total > 0 && topItem != nil ? Double(topItem!.count) / Double(total) * 100 : 0

                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(stat.domain)
                                .font(.caption.monospaced())
                                .lineLimit(1)
                            Spacer()
                            if let topItem {
                                Text("\(String(format: "%.0f", topPct))%")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(colorFor(topItem.name))
                            }
                        }

                        Chart(items, id: \.name) { item in
                            BarMark(x: .value("Count", item.count))
                                .foregroundStyle(colorFor(item.name))
                                .annotation(position: .overlay) {
                                    if item.count > 0 {
                                        Text("\(item.count)")
                                            .font(.caption2.weight(.bold))
                                            .foregroundStyle(Color.barText)
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

                // Legend (bottom-right)
                HStack {
                    Spacer()
                    HStack(spacing: 12) {
                        ForEach(allNames, id: \.self) { name in
                            HStack(spacing: 3) {
                                Circle().fill(colorFor(name)).frame(width: 6, height: 6)
                                Text(name).font(.caption2.monospaced()).foregroundStyle(colorFor(name))
                            }
                        }
                    }
                }
                .padding(.top, 2)
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
                passFailLegend
            }
        }
    }

    private var passFailLegend: some View {
        HStack {
            Spacer()
            HStack(spacing: 12) {
                HStack(spacing: 3) {
                    Circle().fill(Color.passGreen).frame(width: 6, height: 6)
                    Text("pass").font(.caption2.monospaced()).foregroundStyle(Color.passGreen)
                }
                HStack(spacing: 3) {
                    Circle().fill(Color.failRed).frame(width: 6, height: 6)
                    Text("fail").font(.caption2.monospaced()).foregroundStyle(Color.failRed)
                }
            }
        }
        .padding(.top, 2)
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
                    .foregroundStyle(Color.passGreen)
                    .annotation(position: .overlay) {
                        if pass > 0 {
                            Text("\(pass)")
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(Color.barText)
                        }
                    }
                BarMark(x: .value("Count", fail))
                    .foregroundStyle(Color.failRed)
                    .annotation(position: .overlay) {
                        if fail > 0 {
                            Text("\(fail)")
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(Color.barText)
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
        if ratio >= 0.95 { return .passGreen }
        if ratio >= 0.8 { return .orange }
        return .failRed
    }

    // MARK: - Category bar (aggregate distribution)

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

    var body: some View {
        Text(title)
            .font(.title2.weight(.semibold))
            .foregroundStyle(.primary)
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
    if lower.contains("success") { return .passGreen }
    if lower.contains("starttls") || lower.contains("expired") || lower.contains("invalid") { return .failRed }
    if lower.contains("mismatch") || lower.contains("untrusted") { return .orange }
    if lower.contains("dnssec") || lower.contains("sts") { return .purple }
    return .gray
}

