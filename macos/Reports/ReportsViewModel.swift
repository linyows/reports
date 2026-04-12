import Foundation
import SwiftUI

@MainActor
final class ReportsViewModel: ObservableObject {
    @Published var entries: [ReportEntry] = []
    @Published var selectedEntryID: ReportEntry.ID?
    @Published var detailJSON: String?
    @Published var isFetching = false
    @Published var isLoading = false
    @Published var errorMessage: String?
    @Published var filterType: ReportType?
    @Published var searchText = ""

    private let core = ReportsCore.shared

    var selectedEntry: ReportEntry? {
        guard let id = selectedEntryID else { return nil }
        return entries.first { $0.id == id }
    }

    var filteredEntries: [ReportEntry] {
        var result = entries
        if let filterType {
            result = result.filter { $0.type == filterType }
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

    func loadReports() {
        isLoading = true
        errorMessage = nil
        do {
            entries = try core.list()
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }

    func fetchReports() async {
        isFetching = true
        errorMessage = nil
        do {
            try await core.fetch()
            loadReports()
        } catch {
            errorMessage = error.localizedDescription
        }
        isFetching = false
    }

    func loadDetail(for entry: ReportEntry) {
        selectedEntryID = entry.id
        detailJSON = nil
        do {
            detailJSON = try core.show(type: entry.type, account: entry.account, filename: entry.filename)
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
