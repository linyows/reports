const std = @import("std");
const Allocator = std.mem.Allocator;

/// Minimal JSON structures for problem counting (only needed fields).
const DmarcProblemsJson = struct {
    records: []const struct {
        count: u64 = 0,
        dkim_eval: []const u8 = "",
        spf_eval: []const u8 = "",
    } = &.{},
};

const TlsProblemsJson = struct {
    policies: []const struct {
        total_failure: u64 = 0,
    } = &.{},
};

/// Count DMARC problems from raw JSON data.
/// A problem = a record where both DKIM and SPF failed.
pub fn countDmarcProblems(alloc: Allocator, data: []const u8) u64 {
    const parsed = std.json.parseFromSlice(DmarcProblemsJson, alloc, data, .{
        .ignore_unknown_fields = true,
    }) catch return 0;
    defer parsed.deinit();
    var count: u64 = 0;
    for (parsed.value.records) |rec| {
        const dkim_pass = std.mem.eql(u8, rec.dkim_eval, "pass");
        const spf_pass = std.mem.eql(u8, rec.spf_eval, "pass");
        if (!dkim_pass and !spf_pass) count += rec.count;
    }
    return count;
}

/// Count TLS-RPT problems from raw JSON data.
/// A problem = total_failure count across all policies.
pub fn countTlsProblems(alloc: Allocator, data: []const u8) u64 {
    const parsed = std.json.parseFromSlice(TlsProblemsJson, alloc, data, .{
        .ignore_unknown_fields = true,
    }) catch return 0;
    defer parsed.deinit();
    var count: u64 = 0;
    for (parsed.value.policies) |pol| {
        count += pol.total_failure;
    }
    return count;
}

// --- Tests ---

test "countDmarcProblems returns 0 for empty records" {
    const json = "{}";
    try std.testing.expectEqual(@as(u64, 0), countDmarcProblems(std.testing.allocator, json));
}

test "countDmarcProblems returns 0 when all pass" {
    const json =
        \\{"records":[
        \\  {"count":10,"dkim_eval":"pass","spf_eval":"pass"},
        \\  {"count":5,"dkim_eval":"pass","spf_eval":"fail"}
        \\]}
    ;
    try std.testing.expectEqual(@as(u64, 0), countDmarcProblems(std.testing.allocator, json));
}

test "countDmarcProblems counts records where both DKIM and SPF fail" {
    const json =
        \\{"records":[
        \\  {"count":10,"dkim_eval":"pass","spf_eval":"pass"},
        \\  {"count":3,"dkim_eval":"fail","spf_eval":"fail"},
        \\  {"count":7,"dkim_eval":"fail","spf_eval":"fail"},
        \\  {"count":2,"dkim_eval":"fail","spf_eval":"pass"}
        \\]}
    ;
    try std.testing.expectEqual(@as(u64, 10), countDmarcProblems(std.testing.allocator, json));
}

test "countDmarcProblems treats missing eval fields as fail" {
    const json =
        \\{"records":[
        \\  {"count":5}
        \\]}
    ;
    try std.testing.expectEqual(@as(u64, 5), countDmarcProblems(std.testing.allocator, json));
}

test "countDmarcProblems returns 0 for invalid JSON" {
    try std.testing.expectEqual(@as(u64, 0), countDmarcProblems(std.testing.allocator, "not json"));
}

test "countTlsProblems returns 0 for empty policies" {
    const json = "{}";
    try std.testing.expectEqual(@as(u64, 0), countTlsProblems(std.testing.allocator, json));
}

test "countTlsProblems sums total_failure across policies" {
    const json =
        \\{"policies":[
        \\  {"total_failure":3},
        \\  {"total_failure":7},
        \\  {"total_failure":0}
        \\]}
    ;
    try std.testing.expectEqual(@as(u64, 10), countTlsProblems(std.testing.allocator, json));
}

test "countTlsProblems returns 0 for invalid JSON" {
    try std.testing.expectEqual(@as(u64, 0), countTlsProblems(std.testing.allocator, "not json"));
}

test "countTlsProblems returns 0 when all successful" {
    const json =
        \\{"policies":[
        \\  {"total_failure":0},
        \\  {"total_failure":0}
        \\]}
    ;
    try std.testing.expectEqual(@as(u64, 0), countTlsProblems(std.testing.allocator, json));
}
