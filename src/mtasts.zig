const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Report = struct {
    organization_name: []const u8,
    start_datetime: []const u8,
    end_datetime: []const u8,
    contact_info: []const u8,
    report_id: []const u8,
    policies: []Policy,

    pub const Policy = struct {
        policy_type: []const u8,
        policy_domain: []const u8,
        mx_host: []const u8,
        total_successful: u64,
        total_failure: u64,
        failures: []FailureDetail,
    };

    pub const FailureDetail = struct {
        result_type: []const u8,
        sending_mta_ip: []const u8,
        receiving_mx_hostname: []const u8,
        receiving_ip: []const u8,
        failed_session_count: u64,
        failure_reason_code: []const u8,
    };

    pub fn deinit(self: *const Report, allocator: Allocator) void {
        allocator.free(self.organization_name);
        allocator.free(self.start_datetime);
        allocator.free(self.end_datetime);
        allocator.free(self.contact_info);
        allocator.free(self.report_id);
        for (self.policies) |p| {
            allocator.free(p.policy_type);
            allocator.free(p.policy_domain);
            allocator.free(p.mx_host);
            for (p.failures) |f| {
                allocator.free(f.result_type);
                allocator.free(f.sending_mta_ip);
                allocator.free(f.receiving_mx_hostname);
                allocator.free(f.receiving_ip);
                allocator.free(f.failure_reason_code);
            }
            allocator.free(p.failures);
        }
        allocator.free(self.policies);
    }

    pub fn toJson(self: *const Report, allocator: Allocator) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(self.*, .{})});
    }
};

const JsonReport = struct {
    @"organization-name": []const u8 = "",
    @"date-range": ?struct {
        @"start-datetime": []const u8 = "",
        @"end-datetime": []const u8 = "",
    } = null,
    @"contact-info": []const u8 = "",
    @"report-id": []const u8 = "",
    policies: ?[]const JsonPolicy = null,
};

const JsonPolicy = struct {
    policy: ?struct {
        @"policy-type": []const u8 = "",
        @"policy-domain": []const u8 = "",
        @"mx-host": ?std.json.Value = null,
    } = null,
    summary: ?struct {
        @"total-successful-session-count": u64 = 0,
        @"total-failure-session-count": u64 = 0,
    } = null,
    @"failure-details": ?[]const JsonFailure = null,
};

const JsonFailure = struct {
    @"result-type": []const u8 = "",
    @"sending-mta-ip": []const u8 = "",
    @"receiving-mx-hostname": []const u8 = "",
    @"receiving-ip": []const u8 = "",
    @"failed-session-count": u64 = 0,
    @"failure-reason-code": []const u8 = "",
};

pub fn parseJson(allocator: Allocator, data: []const u8) !Report {
    const parsed = try std.json.parseFromSlice(JsonReport, allocator, data, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const j = parsed.value;

    var policies: std.ArrayList(Report.Policy) = .empty;
    if (j.policies) |ps| {
        for (ps) |p| {
            var failures: std.ArrayList(Report.FailureDetail) = .empty;
            if (p.@"failure-details") |fds| {
                for (fds) |fd| {
                    try failures.append(allocator, .{
                        .result_type = try allocator.dupe(u8, fd.@"result-type"),
                        .sending_mta_ip = try allocator.dupe(u8, fd.@"sending-mta-ip"),
                        .receiving_mx_hostname = try allocator.dupe(u8, fd.@"receiving-mx-hostname"),
                        .receiving_ip = try allocator.dupe(u8, fd.@"receiving-ip"),
                        .failed_session_count = fd.@"failed-session-count",
                        .failure_reason_code = try allocator.dupe(u8, fd.@"failure-reason-code"),
                    });
                }
            }

            const policy_type = if (p.policy) |pp| pp.@"policy-type" else "";
            const policy_domain = if (p.policy) |pp| pp.@"policy-domain" else "";
            const mx_host: []const u8 = if (p.policy) |pp| blk: {
                const v = pp.@"mx-host" orelse break :blk "";
                switch (v) {
                    .string => |s| break :blk s,
                    .array => |a| break :blk if (a.items.len > 0 and a.items[0] == .string) a.items[0].string else "",
                    else => break :blk "",
                }
            } else "";
            const total_successful = if (p.summary) |ss| ss.@"total-successful-session-count" else 0;
            const total_failure = if (p.summary) |ss| ss.@"total-failure-session-count" else 0;

            try policies.append(allocator, .{
                .policy_type = try allocator.dupe(u8, policy_type),
                .policy_domain = try allocator.dupe(u8, policy_domain),
                .mx_host = try allocator.dupe(u8, mx_host),
                .total_successful = total_successful,
                .total_failure = total_failure,
                .failures = try failures.toOwnedSlice(allocator),
            });
        }
    }

    const start_dt = if (j.@"date-range") |d| d.@"start-datetime" else "";
    const end_dt = if (j.@"date-range") |d| d.@"end-datetime" else "";

    return .{
        .organization_name = try allocator.dupe(u8, j.@"organization-name"),
        .start_datetime = try allocator.dupe(u8, start_dt),
        .end_datetime = try allocator.dupe(u8, end_dt),
        .contact_info = try allocator.dupe(u8, j.@"contact-info"),
        .report_id = try allocator.dupe(u8, j.@"report-id"),
        .policies = try policies.toOwnedSlice(allocator),
    };
}

// --- Tests ---

test "parse tlsrpt json with policy and failures" {
    const allocator = std.testing.allocator;
    const json_data =
        \\{
        \\  "organization-name": "example.com",
        \\  "date-range": { "start-datetime": "2024-01-01T00:00:00Z", "end-datetime": "2024-01-02T00:00:00Z" },
        \\  "contact-info": "tlsrpt@example.com",
        \\  "report-id": "rpt-001",
        \\  "policies": [{
        \\    "policy": { "policy-type": "sts", "policy-domain": "example.com", "mx-host": "mx.example.com" },
        \\    "summary": { "total-successful-session-count": 100, "total-failure-session-count": 2 },
        \\    "failure-details": [{
        \\      "result-type": "certificate-expired",
        \\      "sending-mta-ip": "192.0.2.1",
        \\      "receiving-mx-hostname": "mx.example.com",
        \\      "receiving-ip": "198.51.100.1",
        \\      "failed-session-count": 2,
        \\      "failure-reason-code": "certificate has expired"
        \\    }]
        \\  }]
        \\}
    ;

    const report = try parseJson(allocator, json_data);
    defer report.deinit(allocator);

    try std.testing.expectEqualStrings("example.com", report.organization_name);
    try std.testing.expectEqualStrings("rpt-001", report.report_id);
    try std.testing.expectEqualStrings("2024-01-01T00:00:00Z", report.start_datetime);
    try std.testing.expectEqualStrings("tlsrpt@example.com", report.contact_info);

    try std.testing.expectEqual(@as(usize, 1), report.policies.len);
    try std.testing.expectEqualStrings("sts", report.policies[0].policy_type);
    try std.testing.expectEqualStrings("example.com", report.policies[0].policy_domain);
    try std.testing.expectEqual(@as(u64, 100), report.policies[0].total_successful);
    try std.testing.expectEqual(@as(u64, 2), report.policies[0].total_failure);

    try std.testing.expectEqual(@as(usize, 1), report.policies[0].failures.len);
    try std.testing.expectEqualStrings("certificate-expired", report.policies[0].failures[0].result_type);
    try std.testing.expectEqual(@as(u64, 2), report.policies[0].failures[0].failed_session_count);
}

test "parse tlsrpt json with mx-host as array" {
    const allocator = std.testing.allocator;
    const json_data =
        \\{
        \\  "organization-name": "Google Inc.",
        \\  "date-range": { "start-datetime": "2026-04-07T00:00:00Z", "end-datetime": "2026-04-07T23:59:59Z" },
        \\  "contact-info": "smtp-tls-reporting@google.com",
        \\  "report-id": "2026-04-07T00:00:00Z_example.com",
        \\  "policies": [{
        \\    "policy": {
        \\      "policy-type": "sts",
        \\      "policy-string": ["version: STSv1", "mode: testing", "mx: mx.example.com", "max_age: 86400"],
        \\      "policy-domain": "example.com",
        \\      "mx-host": ["mx.example.com"]
        \\    },
        \\    "summary": { "total-successful-session-count": 1, "total-failure-session-count": 0 }
        \\  }]
        \\}
    ;

    const report = try parseJson(allocator, json_data);
    defer report.deinit(allocator);

    try std.testing.expectEqualStrings("Google Inc.", report.organization_name);
    try std.testing.expectEqual(@as(usize, 1), report.policies.len);
    try std.testing.expectEqualStrings("sts", report.policies[0].policy_type);
    try std.testing.expectEqualStrings("example.com", report.policies[0].policy_domain);
    try std.testing.expectEqualStrings("mx.example.com", report.policies[0].mx_host);
    try std.testing.expectEqual(@as(u64, 1), report.policies[0].total_successful);
}

test "parse tlsrpt json without optional fields" {
    const allocator = std.testing.allocator;
    const json_data =
        \\{
        \\  "organization-name": "minimal.org",
        \\  "contact-info": "",
        \\  "report-id": "rpt-min"
        \\}
    ;

    const report = try parseJson(allocator, json_data);
    defer report.deinit(allocator);

    try std.testing.expectEqualStrings("minimal.org", report.organization_name);
    try std.testing.expectEqualStrings("rpt-min", report.report_id);
    try std.testing.expectEqualStrings("", report.start_datetime);
    try std.testing.expectEqual(@as(usize, 0), report.policies.len);
}

test "toJson produces valid json" {
    const allocator = std.testing.allocator;
    const report = Report{
        .organization_name = "t.com",
        .start_datetime = "2024-01-01",
        .end_datetime = "2024-01-02",
        .contact_info = "x@t.com",
        .report_id = "1",
        .policies = &.{},
    };
    const json = try report.toJson(allocator);
    defer allocator.free(json);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
}
