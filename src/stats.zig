const std = @import("std");
const Allocator = std.mem.Allocator;

// MARK: - JSON structures

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

pub const DmarcDashJson = struct {
    policy: struct {
        domain: []const u8 = "",
    } = .{},
    records: []const DmarcRecord = &.{},

    pub const DmarcRecord = struct {
        count: u64 = 0,
        disposition: []const u8 = "",
        dkim_eval: []const u8 = "",
        spf_eval: []const u8 = "",
    };
};

pub const TlsDashJson = struct {
    policies: []const TlsPolicy = &.{},

    pub const TlsPolicy = struct {
        policy_domain: []const u8 = "",
        policy_type: []const u8 = "",
        total_successful: u64 = 0,
        total_failure: u64 = 0,
        failures: []const TlsFailure = &.{},
    };

    pub const TlsFailure = struct {
        result_type: []const u8 = "",
        failed_session_count: u64 = 0,
    };
};

// MARK: - Aggregation types

pub const DashAgg = struct {
    dkim_pass: u64 = 0,
    dkim_fail: u64 = 0,
    spf_pass: u64 = 0,
    spf_fail: u64 = 0,
    disp_none: u64 = 0,
    disp_quarantine: u64 = 0,
    disp_reject: u64 = 0,
};

pub const TlsDomAgg = struct {
    success: u64 = 0,
    failure: u64 = 0,
};

// MARK: - Problem counting

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

// MARK: - Dashboard aggregation (pure functions)

/// Aggregate a single DMARC report into dashboard accumulators.
pub fn aggregateDmarcReport(
    alloc: Allocator,
    data: []const u8,
    fallback_domain: []const u8,
    domain_auth: *std.StringHashMap(DashAgg),
    dispositions: *std.StringHashMap(u64),
) void {
    const parsed = std.json.parseFromSlice(DmarcDashJson, alloc, data, .{
        .ignore_unknown_fields = true,
    }) catch return;
    defer parsed.deinit();

    const domain = if (parsed.value.policy.domain.len > 0) parsed.value.policy.domain else fallback_domain;
    for (parsed.value.records) |rec| {
        const key = alloc.dupe(u8, domain) catch continue;
        const gop = domain_auth.getOrPut(key) catch {
            alloc.free(key);
            continue;
        };
        if (gop.found_existing) alloc.free(key);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        if (std.mem.eql(u8, rec.dkim_eval, "pass")) gop.value_ptr.dkim_pass += rec.count else gop.value_ptr.dkim_fail += rec.count;
        if (std.mem.eql(u8, rec.spf_eval, "pass")) gop.value_ptr.spf_pass += rec.count else gop.value_ptr.spf_fail += rec.count;
        const disp = if (rec.disposition.len > 0) rec.disposition else "none";
        if (std.mem.eql(u8, disp, "reject")) {
            gop.value_ptr.disp_reject += rec.count;
        } else if (std.mem.eql(u8, disp, "quarantine")) {
            gop.value_ptr.disp_quarantine += rec.count;
        } else {
            gop.value_ptr.disp_none += rec.count;
        }
        hashIncOwned(alloc, dispositions, disp, rec.count);
    }
}

/// Aggregate a single TLS-RPT report into dashboard accumulators.
pub fn aggregateTlsReport(
    alloc: Allocator,
    data: []const u8,
    fallback_domain: []const u8,
    domain_tls: *std.StringHashMap(TlsDomAgg),
    tls_policy_types: *std.StringHashMap(u64),
    tls_failure_types: *std.StringHashMap(u64),
    domain_policy_types: *std.StringHashMap(u64),
    domain_failure_types: *std.StringHashMap(u64),
) void {
    const parsed = std.json.parseFromSlice(TlsDashJson, alloc, data, .{
        .ignore_unknown_fields = true,
    }) catch return;
    defer parsed.deinit();

    for (parsed.value.policies) |pol| {
        const domain = if (pol.policy_domain.len > 0) pol.policy_domain else fallback_domain;
        const dk = alloc.dupe(u8, domain) catch continue;
        const gop = domain_tls.getOrPut(dk) catch {
            alloc.free(dk);
            continue;
        };
        if (gop.found_existing) alloc.free(dk);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        gop.value_ptr.success += pol.total_successful;
        gop.value_ptr.failure += pol.total_failure;

        const pt = if (pol.policy_type.len > 0) pol.policy_type else "unknown";
        hashIncOwned(alloc, tls_policy_types, pt, pol.total_successful + pol.total_failure);
        // Per-domain policy type: "domain\x00type"
        const dpt_key = std.fmt.allocPrint(alloc, "{s}\x00{s}", .{ domain, pt }) catch continue;
        hashIncOwnedPrealloc(alloc, domain_policy_types, dpt_key, pol.total_successful + pol.total_failure);

        for (pol.failures) |f| {
            const ft = if (f.result_type.len > 0) f.result_type else "unknown";
            hashIncOwned(alloc, tls_failure_types, ft, f.failed_session_count);
            const dft_key = std.fmt.allocPrint(alloc, "{s}\x00{s}", .{ domain, ft }) catch continue;
            hashIncOwnedPrealloc(alloc, domain_failure_types, dft_key, f.failed_session_count);
        }
    }
}

/// Increment a counter in a StringHashMap, duplicating the key.
pub fn hashIncOwned(alloc: Allocator, map: *std.StringHashMap(u64), key: []const u8, val: u64) void {
    const duped = alloc.dupe(u8, key) catch return;
    hashIncOwnedPrealloc(alloc, map, duped, val);
}

/// Increment a counter using an already-allocated key (takes ownership on insert, frees on existing).
fn hashIncOwnedPrealloc(alloc: Allocator, map: *std.StringHashMap(u64), key: []u8, val: u64) void {
    const gop = map.getOrPut(key) catch {
        alloc.free(key);
        return;
    };
    if (gop.found_existing) {
        alloc.free(key);
        gop.value_ptr.* += val;
    } else {
        gop.value_ptr.* = val;
    }
}

/// Free all owned keys in a StringHashMap.
pub fn freeMapKeys(alloc: Allocator, map: *std.StringHashMap(u64)) void {
    var it = map.iterator();
    while (it.next()) |kv| alloc.free(kv.key_ptr.*);
    map.deinit();
}

// MARK: - Tests

test "countDmarcProblems returns 0 for empty records" {
    try std.testing.expectEqual(@as(u64, 0), countDmarcProblems(std.testing.allocator, "{}"));
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
        \\{"records":[{"count":5}]}
    ;
    try std.testing.expectEqual(@as(u64, 5), countDmarcProblems(std.testing.allocator, json));
}

test "countDmarcProblems returns 0 for invalid JSON" {
    try std.testing.expectEqual(@as(u64, 0), countDmarcProblems(std.testing.allocator, "not json"));
}

test "countTlsProblems returns 0 for empty policies" {
    try std.testing.expectEqual(@as(u64, 0), countTlsProblems(std.testing.allocator, "{}"));
}

test "countTlsProblems sums total_failure across policies" {
    const json =
        \\{"policies":[{"total_failure":3},{"total_failure":7},{"total_failure":0}]}
    ;
    try std.testing.expectEqual(@as(u64, 10), countTlsProblems(std.testing.allocator, json));
}

test "countTlsProblems returns 0 for invalid JSON" {
    try std.testing.expectEqual(@as(u64, 0), countTlsProblems(std.testing.allocator, "not json"));
}

test "countTlsProblems returns 0 when all successful" {
    const json =
        \\{"policies":[{"total_failure":0},{"total_failure":0}]}
    ;
    try std.testing.expectEqual(@as(u64, 0), countTlsProblems(std.testing.allocator, json));
}

test "hashIncOwned increments existing key" {
    const alloc = std.testing.allocator;
    var map = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &map);

    hashIncOwned(alloc, &map, "a", 3);
    hashIncOwned(alloc, &map, "a", 7);
    hashIncOwned(alloc, &map, "b", 5);

    try std.testing.expectEqual(@as(u64, 10), map.get("a").?);
    try std.testing.expectEqual(@as(u64, 5), map.get("b").?);
}

test "aggregateDmarcReport accumulates auth stats and dispositions" {
    const alloc = std.testing.allocator;
    const json =
        \\{"policy":{"domain":"example.com"},"records":[
        \\  {"count":10,"dkim_eval":"pass","spf_eval":"pass","disposition":"none"},
        \\  {"count":3,"dkim_eval":"fail","spf_eval":"fail","disposition":"reject"},
        \\  {"count":2,"dkim_eval":"pass","spf_eval":"fail","disposition":"quarantine"}
        \\]}
    ;

    var domain_auth = std.StringHashMap(DashAgg).init(alloc);
    defer {
        var it = domain_auth.iterator();
        while (it.next()) |kv| alloc.free(kv.key_ptr.*);
        domain_auth.deinit();
    }
    var dispositions = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &dispositions);

    aggregateDmarcReport(alloc, json, "fallback.com", &domain_auth, &dispositions);

    const agg = domain_auth.get("example.com").?;
    try std.testing.expectEqual(@as(u64, 12), agg.dkim_pass); // 10 + 2
    try std.testing.expectEqual(@as(u64, 3), agg.dkim_fail);
    try std.testing.expectEqual(@as(u64, 10), agg.spf_pass);
    try std.testing.expectEqual(@as(u64, 5), agg.spf_fail); // 3 + 2
    try std.testing.expectEqual(@as(u64, 10), agg.disp_none);
    try std.testing.expectEqual(@as(u64, 2), agg.disp_quarantine);
    try std.testing.expectEqual(@as(u64, 3), agg.disp_reject);

    try std.testing.expectEqual(@as(u64, 10), dispositions.get("none").?);
    try std.testing.expectEqual(@as(u64, 3), dispositions.get("reject").?);
    try std.testing.expectEqual(@as(u64, 2), dispositions.get("quarantine").?);
}

test "aggregateDmarcReport uses fallback domain when policy domain is empty" {
    const alloc = std.testing.allocator;
    const json =
        \\{"records":[{"count":5,"dkim_eval":"pass","spf_eval":"pass"}]}
    ;

    var domain_auth = std.StringHashMap(DashAgg).init(alloc);
    defer {
        var it = domain_auth.iterator();
        while (it.next()) |kv| alloc.free(kv.key_ptr.*);
        domain_auth.deinit();
    }
    var dispositions = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &dispositions);

    aggregateDmarcReport(alloc, json, "fallback.com", &domain_auth, &dispositions);

    try std.testing.expect(domain_auth.get("fallback.com") != null);
    try std.testing.expectEqual(@as(u64, 5), domain_auth.get("fallback.com").?.dkim_pass);
}

test "aggregateTlsReport accumulates sessions and per-domain types" {
    const alloc = std.testing.allocator;
    const json =
        \\{"policies":[
        \\  {"policy_domain":"mx.example.com","policy_type":"sts","total_successful":100,"total_failure":5,
        \\   "failures":[{"result_type":"certificate-expired","failed_session_count":5}]}
        \\]}
    ;

    var domain_tls = std.StringHashMap(TlsDomAgg).init(alloc);
    defer {
        var it = domain_tls.iterator();
        while (it.next()) |kv| alloc.free(kv.key_ptr.*);
        domain_tls.deinit();
    }
    var tls_pt = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &tls_pt);
    var tls_ft = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &tls_ft);
    var dom_pt = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &dom_pt);
    var dom_ft = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &dom_ft);

    aggregateTlsReport(alloc, json, "fallback.com", &domain_tls, &tls_pt, &tls_ft, &dom_pt, &dom_ft);

    const tls = domain_tls.get("mx.example.com").?;
    try std.testing.expectEqual(@as(u64, 100), tls.success);
    try std.testing.expectEqual(@as(u64, 5), tls.failure);
    try std.testing.expectEqual(@as(u64, 105), tls_pt.get("sts").?);
    try std.testing.expectEqual(@as(u64, 5), tls_ft.get("certificate-expired").?);
    // Per-domain compound keys
    try std.testing.expectEqual(@as(u64, 105), dom_pt.get("mx.example.com\x00sts").?);
    try std.testing.expectEqual(@as(u64, 5), dom_ft.get("mx.example.com\x00certificate-expired").?);
}

test "aggregateTlsReport uses fallback domain" {
    const alloc = std.testing.allocator;
    const json =
        \\{"policies":[{"policy_type":"sts","total_successful":10,"total_failure":0}]}
    ;

    var domain_tls = std.StringHashMap(TlsDomAgg).init(alloc);
    defer {
        var it = domain_tls.iterator();
        while (it.next()) |kv| alloc.free(kv.key_ptr.*);
        domain_tls.deinit();
    }
    var tls_pt = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &tls_pt);
    var tls_ft = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &tls_ft);
    var dom_pt = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &dom_pt);
    var dom_ft = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &dom_ft);

    aggregateTlsReport(alloc, json, "fallback.com", &domain_tls, &tls_pt, &tls_ft, &dom_pt, &dom_ft);

    try std.testing.expect(domain_tls.get("fallback.com") != null);
    try std.testing.expectEqual(@as(u64, 10), domain_tls.get("fallback.com").?.success);
}

test "aggregateDmarcReport handles invalid JSON gracefully" {
    const alloc = std.testing.allocator;
    var domain_auth = std.StringHashMap(DashAgg).init(alloc);
    defer domain_auth.deinit();
    var dispositions = std.StringHashMap(u64).init(alloc);
    defer dispositions.deinit();

    aggregateDmarcReport(alloc, "not json", "fallback.com", &domain_auth, &dispositions);
    try std.testing.expectEqual(@as(u32, 0), domain_auth.count());
}

test "aggregateTlsReport handles invalid JSON gracefully" {
    const alloc = std.testing.allocator;
    var domain_tls = std.StringHashMap(TlsDomAgg).init(alloc);
    defer domain_tls.deinit();
    var tls_pt = std.StringHashMap(u64).init(alloc);
    defer tls_pt.deinit();
    var tls_ft = std.StringHashMap(u64).init(alloc);
    defer tls_ft.deinit();
    var dom_pt = std.StringHashMap(u64).init(alloc);
    defer dom_pt.deinit();
    var dom_ft = std.StringHashMap(u64).init(alloc);
    defer dom_ft.deinit();

    aggregateTlsReport(alloc, "not json", "fallback.com", &domain_tls, &tls_pt, &tls_ft, &dom_pt, &dom_ft);
    try std.testing.expectEqual(@as(u32, 0), domain_tls.count());
}

test "aggregateDmarcReport accumulates across multiple calls for same domain" {
    const alloc = std.testing.allocator;
    const json1 =
        \\{"policy":{"domain":"example.com"},"records":[
        \\  {"count":10,"dkim_eval":"pass","spf_eval":"pass","disposition":"none"}
        \\]}
    ;
    const json2 =
        \\{"policy":{"domain":"example.com"},"records":[
        \\  {"count":5,"dkim_eval":"fail","spf_eval":"fail","disposition":"reject"},
        \\  {"count":3,"dkim_eval":"pass","spf_eval":"pass","disposition":"none"}
        \\]}
    ;

    var domain_auth = std.StringHashMap(DashAgg).init(alloc);
    defer {
        var it = domain_auth.iterator();
        while (it.next()) |kv| alloc.free(kv.key_ptr.*);
        domain_auth.deinit();
    }
    var dispositions = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &dispositions);

    aggregateDmarcReport(alloc, json1, "fallback.com", &domain_auth, &dispositions);
    aggregateDmarcReport(alloc, json2, "fallback.com", &domain_auth, &dispositions);

    const agg = domain_auth.get("example.com").?;
    try std.testing.expectEqual(@as(u64, 13), agg.dkim_pass); // 10 + 3
    try std.testing.expectEqual(@as(u64, 5), agg.dkim_fail);
    try std.testing.expectEqual(@as(u64, 13), agg.spf_pass); // 10 + 3
    try std.testing.expectEqual(@as(u64, 5), agg.spf_fail);
    try std.testing.expectEqual(@as(u64, 13), agg.disp_none); // 10 + 3
    try std.testing.expectEqual(@as(u64, 5), agg.disp_reject);
    try std.testing.expectEqual(@as(u64, 13), dispositions.get("none").?);
    try std.testing.expectEqual(@as(u64, 5), dispositions.get("reject").?);
}

test "aggregateDmarcReport accumulates multiple domains separately" {
    const alloc = std.testing.allocator;
    const json1 =
        \\{"policy":{"domain":"a.com"},"records":[
        \\  {"count":10,"dkim_eval":"pass","spf_eval":"pass"}
        \\]}
    ;
    const json2 =
        \\{"policy":{"domain":"b.com"},"records":[
        \\  {"count":7,"dkim_eval":"fail","spf_eval":"fail"}
        \\]}
    ;

    var domain_auth = std.StringHashMap(DashAgg).init(alloc);
    defer {
        var it = domain_auth.iterator();
        while (it.next()) |kv| alloc.free(kv.key_ptr.*);
        domain_auth.deinit();
    }
    var dispositions = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &dispositions);

    aggregateDmarcReport(alloc, json1, "fallback.com", &domain_auth, &dispositions);
    aggregateDmarcReport(alloc, json2, "fallback.com", &domain_auth, &dispositions);

    try std.testing.expectEqual(@as(u32, 2), domain_auth.count());
    try std.testing.expectEqual(@as(u64, 10), domain_auth.get("a.com").?.dkim_pass);
    try std.testing.expectEqual(@as(u64, 7), domain_auth.get("b.com").?.dkim_fail);
}

test "aggregateTlsReport accumulates across multiple calls" {
    const alloc = std.testing.allocator;
    const json1 =
        \\{"policies":[
        \\  {"policy_domain":"mx.example.com","policy_type":"sts","total_successful":100,"total_failure":0}
        \\]}
    ;
    const json2 =
        \\{"policies":[
        \\  {"policy_domain":"mx.example.com","policy_type":"sts","total_successful":50,"total_failure":3,
        \\   "failures":[{"result_type":"certificate-expired","failed_session_count":3}]}
        \\]}
    ;

    var domain_tls = std.StringHashMap(TlsDomAgg).init(alloc);
    defer {
        var it = domain_tls.iterator();
        while (it.next()) |kv| alloc.free(kv.key_ptr.*);
        domain_tls.deinit();
    }
    var tls_pt = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &tls_pt);
    var tls_ft = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &tls_ft);
    var dom_pt = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &dom_pt);
    var dom_ft = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &dom_ft);

    aggregateTlsReport(alloc, json1, "fallback.com", &domain_tls, &tls_pt, &tls_ft, &dom_pt, &dom_ft);
    aggregateTlsReport(alloc, json2, "fallback.com", &domain_tls, &tls_pt, &tls_ft, &dom_pt, &dom_ft);

    const tls = domain_tls.get("mx.example.com").?;
    try std.testing.expectEqual(@as(u64, 150), tls.success); // 100 + 50
    try std.testing.expectEqual(@as(u64, 3), tls.failure);
    try std.testing.expectEqual(@as(u64, 253), tls_pt.get("sts").?); // 100 + 50 + 53
    try std.testing.expectEqual(@as(u64, 3), tls_ft.get("certificate-expired").?);
    try std.testing.expectEqual(@as(u64, 253), dom_pt.get("mx.example.com\x00sts").?);
    try std.testing.expectEqual(@as(u64, 3), dom_ft.get("mx.example.com\x00certificate-expired").?);
}

test "aggregateTlsReport handles multiple domains and failure types" {
    const alloc = std.testing.allocator;
    const json =
        \\{"policies":[
        \\  {"policy_domain":"a.com","policy_type":"sts","total_successful":50,"total_failure":2,
        \\   "failures":[{"result_type":"starttls-not-supported","failed_session_count":2}]},
        \\  {"policy_domain":"b.com","policy_type":"tlsa","total_successful":30,"total_failure":5,
        \\   "failures":[
        \\     {"result_type":"certificate-expired","failed_session_count":3},
        \\     {"result_type":"validation-failure","failed_session_count":2}
        \\   ]}
        \\]}
    ;

    var domain_tls = std.StringHashMap(TlsDomAgg).init(alloc);
    defer {
        var it = domain_tls.iterator();
        while (it.next()) |kv| alloc.free(kv.key_ptr.*);
        domain_tls.deinit();
    }
    var tls_pt = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &tls_pt);
    var tls_ft = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &tls_ft);
    var dom_pt = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &dom_pt);
    var dom_ft = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &dom_ft);

    aggregateTlsReport(alloc, json, "fallback.com", &domain_tls, &tls_pt, &tls_ft, &dom_pt, &dom_ft);

    // Two separate domains
    try std.testing.expectEqual(@as(u32, 2), domain_tls.count());
    try std.testing.expectEqual(@as(u64, 50), domain_tls.get("a.com").?.success);
    try std.testing.expectEqual(@as(u64, 30), domain_tls.get("b.com").?.success);
    try std.testing.expectEqual(@as(u64, 5), domain_tls.get("b.com").?.failure);

    // Global policy types
    try std.testing.expectEqual(@as(u64, 52), tls_pt.get("sts").?); // 50+2
    try std.testing.expectEqual(@as(u64, 35), tls_pt.get("tlsa").?); // 30+5

    // Global failure types
    try std.testing.expectEqual(@as(u64, 2), tls_ft.get("starttls-not-supported").?);
    try std.testing.expectEqual(@as(u64, 3), tls_ft.get("certificate-expired").?);
    try std.testing.expectEqual(@as(u64, 2), tls_ft.get("validation-failure").?);

    // Per-domain compound keys
    try std.testing.expectEqual(@as(u64, 52), dom_pt.get("a.com\x00sts").?);
    try std.testing.expectEqual(@as(u64, 35), dom_pt.get("b.com\x00tlsa").?);
    try std.testing.expectEqual(@as(u64, 2), dom_ft.get("a.com\x00starttls-not-supported").?);
    try std.testing.expectEqual(@as(u64, 3), dom_ft.get("b.com\x00certificate-expired").?);
    try std.testing.expectEqual(@as(u64, 2), dom_ft.get("b.com\x00validation-failure").?);
}

test "hashIncOwned handles empty string key" {
    const alloc = std.testing.allocator;
    var map = std.StringHashMap(u64).init(alloc);
    defer freeMapKeys(alloc, &map);

    hashIncOwned(alloc, &map, "", 5);
    hashIncOwned(alloc, &map, "", 3);
    try std.testing.expectEqual(@as(u64, 8), map.get("").?);
}

// MARK: - JSON string escaping

/// Escape a string for embedding in a JSON string value.
/// Returns the original slice if no escaping is needed, or a new allocation.
/// Caller must free the result if it differs from input.
pub fn jsonEscape(alloc: Allocator, input: []const u8) []const u8 {
    var needs_escape = false;
    for (input) |ch| {
        if (ch == '"' or ch == '\\' or ch < 0x20) {
            needs_escape = true;
            break;
        }
    }
    if (!needs_escape) return input;

    var out: std.ArrayList(u8) = .empty;
    for (input) |ch| {
        switch (ch) {
            '"' => out.appendSlice(alloc, "\\\"") catch return input,
            '\\' => out.appendSlice(alloc, "\\\\") catch return input,
            '\n' => out.appendSlice(alloc, "\\n") catch return input,
            '\r' => out.appendSlice(alloc, "\\r") catch return input,
            '\t' => out.appendSlice(alloc, "\\t") catch return input,
            else => if (ch < 0x20) {
                const hex = "0123456789abcdef";
                out.appendSlice(alloc, "\\u00") catch return input;
                out.append(alloc, hex[ch >> 4]) catch return input;
                out.append(alloc, hex[ch & 0x0f]) catch return input;
            } else {
                out.append(alloc, ch) catch return input;
            },
        }
    }
    return out.toOwnedSlice(alloc) catch input;
}

// MARK: - DNS status evaluation

pub const DnsStatus = enum {
    ok,
    warning,
    critical,

    pub fn label(self: DnsStatus) []const u8 {
        return switch (self) {
            .ok => "ok",
            .warning => "warning",
            .critical => "critical",
        };
    }
};

/// Evaluate overall DNS health for a domain based on record presence and strength.
pub fn evaluateDnsStatus(
    has_dmarc: bool,
    has_spf: bool,
    has_dkim: bool,
    dmarc_policy_weak: bool,
    spf_weak: bool,
) DnsStatus {
    if (!has_dmarc or !has_spf or !has_dkim) return .critical;
    if (dmarc_policy_weak or spf_weak) return .warning;
    return .ok;
}

/// Check if a DMARC policy is weak (p=none means monitor-only, no enforcement).
/// Carefully matches only the "p=" tag, not "sp=" or "np=".
pub fn isDmarcPolicyWeak(dmarc_txt: []const u8) bool {
    var i: usize = 0;
    while (i < dmarc_txt.len) {
        // Find "p="
        const pos = std.mem.indexOf(u8, dmarc_txt[i..], "p=") orelse return false;
        const abs = i + pos;
        // Make sure it's the "p" tag, not "sp=" or "np="
        if (abs == 0 or dmarc_txt[abs - 1] == ';' or dmarc_txt[abs - 1] == ' ') {
            // Check the value after "p="
            const val_start = abs + 2;
            if (val_start + 4 <= dmarc_txt.len and std.mem.eql(u8, dmarc_txt[val_start .. val_start + 4], "none")) {
                return true;
            }
        }
        i = abs + 2;
    }
    return false;
}

/// Check if an SPF record uses soft fail (~all instead of -all).
pub fn isSpfWeak(spf_txt: []const u8) bool {
    return std.mem.indexOf(u8, spf_txt, "~all") != null;
}

// MARK: - DMARC failure classification

pub const FailureType = enum {
    both_fail,
    dkim_only_fail,
    spf_only_fail,

    pub fn label(self: FailureType) []const u8 {
        return switch (self) {
            .both_fail => "DKIM+SPF fail",
            .dkim_only_fail => "DKIM fail only",
            .spf_only_fail => "SPF fail only",
        };
    }

    pub fn hint(self: FailureType) []const u8 {
        return switch (self) {
            .both_fail => "needs DKIM and SPF setup",
            .dkim_only_fail => "needs DKIM setup",
            .spf_only_fail => "needs SPF setup",
        };
    }
};

/// Classify a DMARC failure based on DKIM and SPF evaluation results.
/// Returns null if both pass (not a failure).
pub fn classifyFailure(dkim_pass: bool, spf_pass: bool) ?FailureType {
    if (dkim_pass and spf_pass) return null;
    if (!dkim_pass and !spf_pass) return .both_fail;
    if (!dkim_pass) return .dkim_only_fail;
    return .spf_only_fail;
}

// MARK: - DNS status tests

test "evaluateDnsStatus returns ok when all records present and strong" {
    try std.testing.expectEqual(DnsStatus.ok, evaluateDnsStatus(true, true, true, false, false));
}

test "evaluateDnsStatus returns warning for weak DMARC policy" {
    try std.testing.expectEqual(DnsStatus.warning, evaluateDnsStatus(true, true, true, true, false));
}

test "evaluateDnsStatus returns warning for weak SPF" {
    try std.testing.expectEqual(DnsStatus.warning, evaluateDnsStatus(true, true, true, false, true));
}

test "evaluateDnsStatus returns warning when both weak" {
    try std.testing.expectEqual(DnsStatus.warning, evaluateDnsStatus(true, true, true, true, true));
}

test "evaluateDnsStatus returns critical when DKIM missing" {
    try std.testing.expectEqual(DnsStatus.critical, evaluateDnsStatus(true, true, false, false, false));
}

test "evaluateDnsStatus returns critical when DMARC missing" {
    try std.testing.expectEqual(DnsStatus.critical, evaluateDnsStatus(false, true, true, false, false));
}

test "evaluateDnsStatus returns critical when SPF missing" {
    try std.testing.expectEqual(DnsStatus.critical, evaluateDnsStatus(true, false, true, false, false));
}

test "evaluateDnsStatus returns critical over warning when record missing and weak" {
    try std.testing.expectEqual(DnsStatus.critical, evaluateDnsStatus(true, true, false, true, true));
}

test "isDmarcPolicyWeak detects p=none" {
    try std.testing.expect(isDmarcPolicyWeak("v=DMARC1; p=none; rua=mailto:x@example.com"));
}

test "isDmarcPolicyWeak returns false for p=quarantine" {
    try std.testing.expect(!isDmarcPolicyWeak("v=DMARC1; p=quarantine; rua=mailto:x@example.com"));
}

test "isDmarcPolicyWeak returns false for p=reject" {
    try std.testing.expect(!isDmarcPolicyWeak("v=DMARC1; p=reject; rua=mailto:x@example.com"));
}

test "isDmarcPolicyWeak returns false for sp=none with strong p" {
    try std.testing.expect(!isDmarcPolicyWeak("v=DMARC1; p=reject; sp=none"));
}

test "isDmarcPolicyWeak returns false for np=none with strong p" {
    try std.testing.expect(!isDmarcPolicyWeak("v=DMARC1; p=quarantine; np=none"));
}

test "isDmarcPolicyWeak detects p=none at start of record" {
    try std.testing.expect(isDmarcPolicyWeak("p=none; rua=mailto:x@example.com"));
}

test "isSpfWeak detects ~all" {
    try std.testing.expect(isSpfWeak("v=spf1 include:_spf.google.com ~all"));
}

test "isSpfWeak returns false for -all" {
    try std.testing.expect(!isSpfWeak("v=spf1 ip4:1.2.3.4 -all"));
}

test "classifyFailure returns null when both pass" {
    try std.testing.expectEqual(@as(?FailureType, null), classifyFailure(true, true));
}

test "classifyFailure returns both_fail" {
    try std.testing.expectEqual(FailureType.both_fail, classifyFailure(false, false).?);
}

test "classifyFailure returns dkim_only_fail" {
    try std.testing.expectEqual(FailureType.dkim_only_fail, classifyFailure(false, true).?);
}

test "classifyFailure returns spf_only_fail" {
    try std.testing.expectEqual(FailureType.spf_only_fail, classifyFailure(true, false).?);
}
