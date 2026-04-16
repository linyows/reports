import Foundation
import SwiftUI

@MainActor
final class ReportsViewModel: ObservableObject {
    @Published var entries: [ReportEntry] = []
    /// Increments each time `entries` is replaced. Views can key `.task(id:)` or
    /// `.onChange` on this to detect refreshes reliably, including edge cases
    /// where the count stays the same but contents differ.
    @Published var entriesVersion: Int = 0
    @Published var selectedEntryID: ReportEntry.ID?
    @Published var detailJSON: String?
    @Published var isFetching = false
    @Published var isLoading = false
    @Published var isLoadingDetail = false
    @Published var errorMessage: String?
    @Published var filterType: ReportType?
    @Published var filterAccount: String?
    @Published var filterDomain: String?
    @Published var searchText = ""
    @Published var filterProblems = false
    @Published var showDashboard = true
    @Published var showMailSources = false
    @Published var enrichments: [String: IpEnrichment] = [:]
    @Published var hasAccounts = true
    @Published var showAddAccount = false
    @Published var mailSources: [MailSource] = []
    @Published var isLoadingSources = false

    private let core = ReportsCore.shared
    private var enrichmentTask: Task<Void, Never>?
    private var detailTask: Task<Void, Never>?
    private var sourcesTask: Task<Void, Never>?

    var selectedEntry: ReportEntry? {
        guard let id = selectedEntryID else { return nil }
        return entries.first { $0.id == id }
    }

    var filteredEntries: [ReportEntry] {
        var result = entries
        if filterProblems {
            result = result.filter { $0.problems > 0 }
        }
        if let filterType {
            result = result.filter { $0.type == filterType }
        }
        if let filterAccount {
            result = result.filter { $0.account == filterAccount }
        }
        if let filterDomain {
            result = result.filter { $0.domain == filterDomain }
        }
        if !searchText.isEmpty {
            let query = searchText.lowercased()
            result = result.filter {
                $0.org.lowercased().contains(query) ||
                $0.domain.lowercased().contains(query) ||
                $0.account.lowercased().contains(query)
            }
        }
        return result
    }

    var dmarcCount: Int { entries.filter { $0.type == .dmarc }.count }
    var tlsrptCount: Int { entries.filter { $0.type == .tlsrpt }.count }
    var problemsCount: Int { entries.filter { $0.problems > 0 }.count }

    var accounts: [(name: String, count: Int)] {
        var counts: [String: Int] = [:]
        for e in entries { counts[e.account, default: 0] += 1 }
        return counts.sorted { $0.key < $1.key }.map { (name: $0.key, count: $0.value) }
    }

    var domains: [(name: String, count: Int)] {
        var counts: [String: Int] = [:]
        for e in entries { counts[e.domain, default: 0] += 1 }
        return counts.sorted { $0.key < $1.key }.map { (name: $0.key, count: $0.value) }
    }

    func clearFilters() {
        filterType = nil
        filterAccount = nil
        filterDomain = nil
        filterProblems = false
        showDashboard = false
        showMailSources = false
    }

    func selectDashboard() {
        closeDetail()
        filterType = nil
        filterAccount = nil
        filterDomain = nil
        filterProblems = false
        showDashboard = true
        showMailSources = false
    }

    func selectMailSources() {
        closeDetail()
        filterType = nil
        filterAccount = nil
        filterDomain = nil
        filterProblems = false
        showDashboard = false
        showMailSources = true
    }

    func loadReports() {
        isLoading = true
        errorMessage = nil

        // Check if config has accounts
        let configPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/reports/config.json").path
        if !FileManager.default.fileExists(atPath: configPath) {
            hasAccounts = false
            isLoading = false
            return
        }
        if let data = FileManager.default.contents(atPath: configPath),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let accounts = json["accounts"] as? [[String: Any]],
           !accounts.isEmpty {
            hasAccounts = true
        } else {
            hasAccounts = false
            isLoading = false
            return
        }

        do {
            entries = try core.list()
            entriesVersion &+= 1
            loadSourcesInBackground()
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }

    private func loadSourcesInBackground() {
        sourcesTask?.cancel()
        isLoadingSources = true
        sourcesTask = Task { [weak self, core] in
            let result: [MailSource] = await Task.detached(priority: .utility) {
                (try? core.sources()) ?? []
            }.value
            if Task.isCancelled { return }
            let sorted = result.sorted {
                if $0.messages != $1.messages { return $0.messages > $1.messages }
                return $0.totalIssues > $1.totalIssues
            }
            await MainActor.run {
                self?.mailSources = sorted
                self?.isLoadingSources = false
            }
        }
    }

    func fetchReports() async {
        isFetching = true
        errorMessage = nil
        do {
            try await core.sync()
            loadReports()
        } catch {
            errorMessage = error.localizedDescription
        }
        isFetching = false
    }

    func loadDetail(for entry: ReportEntry) {
        // Cancel any in-flight work for the previous selection
        detailTask?.cancel()
        enrichmentTask?.cancel()

        selectedEntryID = entry.id
        detailJSON = nil
        isLoadingDetail = true

        detailTask = Task { [weak self] in
            guard let self else { return }
            let json: String? = await Task.detached(priority: .userInitiated) { [core] in
                try? core.show(type: entry.type, account: entry.account, filename: entry.filename)
            }.value

            if Task.isCancelled { return }

            await MainActor.run {
                self.detailJSON = json
                self.isLoadingDetail = false
                if json == nil {
                    self.errorMessage = "Failed to load report"
                }
            }

            if let json {
                let ips = Self.extractIPs(from: json, type: entry.type)
                self.startEnrichment(for: ips)
            }
        }
    }

    func closeDetail() {
        detailTask?.cancel()
        enrichmentTask?.cancel()
        selectedEntryID = nil
        detailJSON = nil
        isLoadingDetail = false
    }

    /// Extract unique source IPs from the report JSON for background enrichment.
    private static func extractIPs(from json: String, type: ReportType) -> [String] {
        guard let data = json.data(using: .utf8) else { return [] }
        switch type {
        case .dmarc:
            guard let report = try? JSONDecoder().decode(DmarcDetail.self, from: data) else { return [] }
            return Array(Set(report.records.map(\.source_ip).filter { !$0.isEmpty }))
        case .tlsrpt:
            guard let report = try? JSONDecoder().decode(TlsDetail.self, from: data) else { return [] }
            let ips = report.policies.flatMap { $0.failures.map(\.sending_mta_ip) }
            return Array(Set(ips.filter { !$0.isEmpty }))
        }
    }

    /// Resolve enrichments off the main thread, publishing each result as it completes.
    private func startEnrichment(for ips: [String]) {
        let pending = ips.filter { enrichments[$0] == nil }
        guard !pending.isEmpty else { return }

        enrichmentTask = Task { [weak self, core] in
            for ip in pending {
                if Task.isCancelled { return }
                let result = await Task.detached(priority: .userInitiated) {
                    core.enrichIP(ip)
                }.value
                if Task.isCancelled { return }
                if let result {
                    await MainActor.run {
                        self?.enrichments[ip] = result
                    }
                }
            }
        }
    }
}
