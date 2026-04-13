import Foundation
import ReportsKit

/// Swift wrapper around the Zig C ABI (libreports-core).
final class ReportsCore: @unchecked Sendable {
    static let shared = ReportsCore()

    private init() {
        reports_init()
    }

    deinit {
        reports_deinit()
    }

    /// Build a JSON config string from the user's config file path.
    func configJSON() -> String? {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let configPath = "\(home)/.config/reports/config.json"
        guard let data = FileManager.default.contents(atPath: configPath) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    /// Fetch reports from all configured IMAP accounts.
    func fetch() async throws {
        guard let config = configJSON() else {
            throw ReportsError.noConfig
        }
        let result = await Task.detached {
            reports_fetch(config)
        }.value
        if result != 0 {
            throw ReportsError.fetchFailed
        }
    }

    /// List all stored reports.
    func list() throws -> [ReportEntry] {
        guard let config = configJSON() else {
            throw ReportsError.noConfig
        }
        guard let ptr = reports_list(config) else {
            throw ReportsError.listFailed
        }
        defer { reports_free_string(ptr) }

        let json = String(cString: ptr)
        let data = Data(json.utf8)
        return try JSONDecoder().decode([ReportEntry].self, from: data)
    }

    /// Show a specific report as raw JSON string.
    func show(type: ReportType, account: String, filename: String) throws -> String {
        guard let config = configJSON() else {
            throw ReportsError.noConfig
        }
        guard let ptr = reports_show(config, type.rawValue, account, filename) else {
            throw ReportsError.showFailed
        }
        defer { reports_free_string(ptr) }
        return String(cString: ptr)
    }
    private var enrichCache: [String: IpEnrichment] = [:]

    /// Enrich an IP address with PTR, ASN, org, and country info (cached).
    func enrichIP(_ ip: String) -> IpEnrichment? {
        if let cached = enrichCache[ip] { return cached }
        guard let ptr = reports_enrich_ip(ip) else { return nil }
        defer { reports_free_string(ptr) }
        let json = String(cString: ptr)
        guard let data = json.data(using: .utf8) else { return nil }
        guard let result = try? JSONDecoder().decode(IpEnrichment.self, from: data) else { return nil }
        enrichCache[ip] = result
        return result
    }

    /// Clear enrichment cache (e.g., when switching reports).
    func clearEnrichCache() {
        enrichCache.removeAll()
    }
}

enum ReportsError: LocalizedError {
    case noConfig
    case fetchFailed
    case listFailed
    case showFailed

    var errorDescription: String? {
        switch self {
        case .noConfig: return "Configuration file not found at ~/.config/reports/config.json"
        case .fetchFailed: return "Failed to fetch reports"
        case .listFailed: return "Failed to list reports"
        case .showFailed: return "Failed to load report"
        }
    }
}
