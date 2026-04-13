import Foundation
import SwiftUI

// MARK: - Policy color (green -> cyan -> blue -> magenta -> gray)

func policyColor(_ policy: String) -> Color {
    switch policy.lowercased() {
    case "reject", "sts":
        return .green
    case "tlsa":
        return .cyan
    case "quarantine":
        return .blue
    case "testing":
        return .purple
    default: // none, no-policy-found, etc.
        return .gray
    }
}

// MARK: - Label color registry (unique colors while palette allows, then hash fallback)

private let labelPalette: [Color] = [
    .blue, .orange, .green, .purple, .red, .teal, .pink, .indigo, .mint, .cyan, .brown, .yellow,
]

final class LabelColorRegistry: @unchecked Sendable {
    static let shared = LabelColorRegistry()
    private var assignments: [String: Color] = [:]
    private var nextIndex = 0

    func color(for text: String) -> Color {
        if let existing = assignments[text] { return existing }
        let color = labelPalette[nextIndex % labelPalette.count]
        nextIndex += 1
        assignments[text] = color
        return color
    }

    func reset() {
        assignments.removeAll()
        nextIndex = 0
    }
}

func labelColor(for text: String) -> Color {
    LabelColorRegistry.shared.color(for: text)
}

enum ReportType: String, Codable, CaseIterable, Identifiable {
    case dmarc
    case tlsrpt

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .dmarc: return "DMARC"
        case .tlsrpt: return "TLS-RPT"
        }
    }
}

struct ReportEntry: Codable, Identifiable, Hashable {
    let account: String
    let type: ReportType
    let org: String
    let reportId: String
    let date: String
    let domain: String
    let policy: String
    let filename: String

    var id: String { "\(account)-\(type.rawValue)-\(reportId)" }

    var displayTitle: String {
        "\(org) — \(domain)"
    }

    enum CodingKeys: String, CodingKey {
        case account, type, org
        case reportId = "id"
        case date, domain, policy, filename
    }
}

// MARK: - DMARC Detail (matches CLI's DmarcDetailJson)

struct DmarcDetail: Codable {
    let metadata: DmarcDetailMetadata
    let policy: DmarcDetailPolicy
    let records: [DmarcDetailRecord]

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        metadata = try container.decodeIfPresent(DmarcDetailMetadata.self, forKey: .metadata) ?? .empty
        policy = try container.decodeIfPresent(DmarcDetailPolicy.self, forKey: .policy) ?? .empty
        records = try container.decodeIfPresent([DmarcDetailRecord].self, forKey: .records) ?? []
    }

    enum CodingKeys: String, CodingKey {
        case metadata
        case policy
        case records
    }
}

struct DmarcDetailMetadata: Codable {
    let org_name: String
    let report_id: String

    static let empty = DmarcDetailMetadata(org_name: "", report_id: "")
}

struct DmarcDetailPolicy: Codable {
    let domain: String
    let policy: String

    static let empty = DmarcDetailPolicy(domain: "", policy: "")
}

struct DmarcDetailRecord: Codable, Identifiable {
    let source_ip: String
    let count: UInt64
    let disposition: String
    let dkim_eval: String
    let spf_eval: String
    let header_from: String
    let envelope_from: String
    let envelope_to: String

    var id: String { "\(source_ip)-\(header_from)-\(count)" }

    /// Merged FROM: "header_from/envelope_from" when they differ, otherwise just header_from.
    var from: String {
        if envelope_from.isEmpty || envelope_from == header_from {
            return header_from
        }
        return "\(header_from)/\(envelope_from)"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        source_ip = try container.decodeIfPresent(String.self, forKey: .source_ip) ?? ""
        count = try container.decodeIfPresent(UInt64.self, forKey: .count) ?? 0
        disposition = try container.decodeIfPresent(String.self, forKey: .disposition) ?? ""
        dkim_eval = try container.decodeIfPresent(String.self, forKey: .dkim_eval) ?? ""
        spf_eval = try container.decodeIfPresent(String.self, forKey: .spf_eval) ?? ""
        header_from = try container.decodeIfPresent(String.self, forKey: .header_from) ?? ""
        envelope_from = try container.decodeIfPresent(String.self, forKey: .envelope_from) ?? ""
        envelope_to = try container.decodeIfPresent(String.self, forKey: .envelope_to) ?? ""
    }

    enum CodingKeys: String, CodingKey {
        case source_ip, count, disposition, dkim_eval, spf_eval
        case header_from, envelope_from, envelope_to
    }
}

// MARK: - TLS-RPT Detail (matches CLI's TlsDetailJson)

struct TlsDetail: Codable {
    let organization_name: String
    let report_id: String
    let policies: [TlsDetailPolicy]

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        organization_name = try container.decodeIfPresent(String.self, forKey: .organization_name) ?? ""
        report_id = try container.decodeIfPresent(String.self, forKey: .report_id) ?? ""
        policies = try container.decodeIfPresent([TlsDetailPolicy].self, forKey: .policies) ?? []
    }

    enum CodingKeys: String, CodingKey {
        case organization_name, report_id, policies
    }
}

struct TlsDetailPolicy: Codable, Identifiable {
    let policy_type: String
    let policy_domain: String
    let total_successful: UInt64
    let total_failure: UInt64
    let failures: [TlsDetailFailure]

    var id: String { "\(policy_type)-\(policy_domain)" }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        policy_type = try container.decodeIfPresent(String.self, forKey: .policy_type) ?? ""
        policy_domain = try container.decodeIfPresent(String.self, forKey: .policy_domain) ?? ""
        total_successful = try container.decodeIfPresent(UInt64.self, forKey: .total_successful) ?? 0
        total_failure = try container.decodeIfPresent(UInt64.self, forKey: .total_failure) ?? 0
        failures = try container.decodeIfPresent([TlsDetailFailure].self, forKey: .failures) ?? []
    }

    enum CodingKeys: String, CodingKey {
        case policy_type, policy_domain, total_successful, total_failure, failures
    }
}

struct TlsDetailFailure: Codable, Identifiable {
    let result_type: String
    let sending_mta_ip: String
    let receiving_mx_hostname: String
    let failed_session_count: UInt64

    var id: String { "\(result_type)-\(sending_mta_ip)" }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        result_type = try container.decodeIfPresent(String.self, forKey: .result_type) ?? ""
        sending_mta_ip = try container.decodeIfPresent(String.self, forKey: .sending_mta_ip) ?? ""
        receiving_mx_hostname = try container.decodeIfPresent(String.self, forKey: .receiving_mx_hostname) ?? ""
        failed_session_count = try container.decodeIfPresent(UInt64.self, forKey: .failed_session_count) ?? 0
    }

    enum CodingKeys: String, CodingKey {
        case result_type, sending_mta_ip, receiving_mx_hostname, failed_session_count
    }
}

// MARK: - IP Enrichment

struct IpEnrichment: Codable {
    let ptr: String
    let asn: String
    let asn_org: String
    let country: String

    /// Display PTR, or "-" if empty or same as source IP.
    func ptrDisplay(sourceIP: String) -> String {
        if ptr.isEmpty || ptr == sourceIP { return "-" }
        return ptr
    }

    /// "AS15169 Google LLC" or "-".
    var asnDisplay: String {
        if asn.isEmpty { return "-" }
        if asn_org.isEmpty { return "AS\(asn)" }
        return "AS\(asn) \(asn_org)"
    }

    /// Country code as flag emoji, e.g. "US" → "🇺🇸".
    var countryFlag: String {
        guard country.count >= 2 else { return "-" }
        let base: UInt32 = 0x1F1E6
        let upper = country.uppercased()
        let scalars = upper.prefix(2).unicodeScalars.compactMap { scalar -> Unicode.Scalar? in
            let offset = scalar.value - 0x41 // 'A'
            guard offset < 26 else { return nil }
            return Unicode.Scalar(base + offset)
        }
        guard scalars.count == 2 else { return "-" }
        return String(scalars.map { Character($0) })
    }
}
