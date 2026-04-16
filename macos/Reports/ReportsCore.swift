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

    /// Fetch reports for a specific account only.
    func fetchAccount(_ name: String) async throws {
        guard let config = configJSON() else {
            throw ReportsError.noConfig
        }
        let errorMessage: String? = await Task.detached {
            let errPtr = reports_fetch_account(config, name)
            if let errPtr {
                let msg = String(cString: errPtr)
                reports_free_string(errPtr)
                return msg
            }
            return nil
        }.value
        if let errorMessage {
            throw ReportsError.fetchAccountFailed(errorMessage)
        }
    }

    /// Enrich all source IPs with PTR/ASN/country.
    func enrich() async throws {
        guard let config = configJSON() else {
            throw ReportsError.noConfig
        }
        let result = await Task.detached {
            reports_enrich(config)
        }.value
        if result != 0 {
            throw ReportsError.enrichFailed
        }
    }

    /// Rebuild dashboard and mail sources caches.
    func aggregate() async throws {
        guard let config = configJSON() else {
            throw ReportsError.noConfig
        }
        let result = await Task.detached {
            reports_aggregate(config)
        }.value
        if result != 0 {
            throw ReportsError.aggregateFailed
        }
    }

    /// Sync: fetch + enrich + aggregate in one call.
    func sync() async throws {
        guard let config = configJSON() else {
            throw ReportsError.noConfig
        }
        let result = await Task.detached {
            reports_sync(config)
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
    /// Aggregate dashboard statistics across all reports.
    func dashboard() throws -> DashboardJSON {
        guard let config = configJSON() else {
            throw ReportsError.noConfig
        }
        guard let ptr = reports_dashboard(config) else {
            throw ReportsError.dashboardFailed
        }
        defer { reports_free_string(ptr) }

        let json = String(cString: ptr)
        let data = Data(json.utf8)
        return try JSONDecoder().decode(DashboardJSON.self, from: data)
    }

    /// Aggregate mail sources across all reports.
    func sources() throws -> [MailSource] {
        guard let config = configJSON() else {
            throw ReportsError.noConfig
        }
        guard let ptr = reports_sources(config) else {
            throw ReportsError.sourcesFailed
        }
        defer { reports_free_string(ptr) }

        let json = String(cString: ptr)
        let data = Data(json.utf8)
        return try JSONDecoder().decode([MailSource].self, from: data)
    }

    /// Enrich an IP address with PTR, ASN, org, and country info.
    /// Results are cached persistently in the Zig core (.enrich_cache.jsonl).
    func enrichIP(_ ip: String) -> IpEnrichment? {
        guard let ptr = reports_enrich_ip(ip) else { return nil }
        defer { reports_free_string(ptr) }
        let json = String(cString: ptr)
        guard let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(IpEnrichment.self, from: data)
    }
}

enum ReportsError: LocalizedError {
    case noConfig
    case fetchFailed
    case fetchAccountFailed(String)
    case listFailed
    case showFailed
    case enrichFailed
    case aggregateFailed
    case dashboardFailed
    case sourcesFailed

    var errorDescription: String? {
        switch self {
        case .noConfig: return "Configuration file not found at ~/.config/reports/config.json"
        case .fetchFailed: return "Failed to fetch reports. Connection or authentication failed — check your host, username, and password."
        case .fetchAccountFailed(let message): return message
        case .listFailed: return "Failed to list reports"
        case .showFailed: return "Failed to load report"
        case .enrichFailed: return "Failed to enrich IPs"
        case .aggregateFailed: return "Failed to aggregate"
        case .dashboardFailed: return "Failed to aggregate dashboard statistics"
        case .sourcesFailed: return "Failed to aggregate mail sources"
        }
    }
}
