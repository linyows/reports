/// C ABI exports for SwiftUI integration.
/// All functions return JSON strings. Use reports_free_string() to release them.
const std = @import("std");
const reports = @import("reports");

const allocator = std.heap.c_allocator;

/// Lazily-initialized global enrich cache, shared by reports_enrich_ip and reports_fetch.
var g_cache: ?reports.enrichcache.Cache = null;
var g_cache_mu: std.Thread.Mutex = .{};

fn getCache(data_dir: []const u8) ?*reports.enrichcache.Cache {
    g_cache_mu.lock();
    defer g_cache_mu.unlock();
    if (g_cache == null) {
        g_cache = reports.enrichcache.Cache.init(allocator, data_dir) catch return null;
    }
    return &g_cache.?;
}

export fn reports_init() void {
    reports.imap.globalInit();
}

export fn reports_deinit() void {
    reports.imap.globalCleanup();
    g_cache_mu.lock();
    defer g_cache_mu.unlock();
    if (g_cache) |*c| {
        c.compactIfNeeded() catch {};
        c.deinit();
        g_cache = null;
    }
}

export fn reports_fetch(config_json: [*:0]const u8) c_int {
    const cfg = reports.config.Config.fromJson(allocator, std.mem.span(config_json)) catch return -1;
    defer cfg.deinit(allocator);

    reports.store.migrateToAccountDirs(cfg.data_dir);
    cfg.ensureDataDir() catch return -1;

    var attempted: usize = 0;
    var succeeded: usize = 0;

    for (cfg.accounts) |acct| {
        if (acct.host.len == 0) continue;
        attempted += 1;

        var client = reports.imap.Client.init(
            allocator,
            acct.host,
            acct.port,
            acct.username,
            acct.password,
            acct.mailbox,
            acct.tls,
        );
        client.connect() catch continue;
        defer client.deinit();

        const st = reports.store.Store.init(allocator, cfg.data_dir, acct.name);

        var fetched_set = st.loadFetchedUids() catch std.AutoHashMap(u32, void).init(allocator);
        defer fetched_set.deinit();

        // searchReports is where the actual IMAP connection + auth happens
        const uids = client.searchReports() catch continue;
        defer allocator.free(uids);

        // If we got here, the connection and auth succeeded
        succeeded += 1;

        var new_uids: std.ArrayList(u32) = .empty;
        for (uids) |uid| {
            if (!fetched_set.contains(uid)) new_uids.append(allocator, uid) catch {};
        }
        const new_uid_slice = new_uids.toOwnedSlice(allocator) catch continue;
        defer allocator.free(new_uid_slice);

        if (new_uid_slice.len == 0) continue;

        const results = reports.fetch.fetchMessages(allocator, &acct, new_uid_slice, null) orelse continue;
        defer reports.fetch.freeResults(allocator, results);

        _ = reports.fetch.processResults(allocator, results, &st, &fetched_set);
    }

    // If all accounts failed to connect/auth, return error
    if (attempted > 0 and succeeded == 0) return -1;

    return 0;
}

/// Fetch reports for a specific account only.
/// @return NULL on success, or error message string on failure. Free with reports_free_string().
export fn reports_fetch_account(config_json: [*:0]const u8, account_name: [*:0]const u8) ?[*:0]u8 {
    const cfg = reports.config.Config.fromJson(allocator, std.mem.span(config_json)) catch
        return errStr("Failed to parse configuration");
    defer cfg.deinit(allocator);

    reports.store.migrateToAccountDirs(cfg.data_dir);
    cfg.ensureDataDir() catch return errStr("Failed to create data directory");

    const name = std.mem.span(account_name);
    for (cfg.accounts) |acct| {
        if (!std.mem.eql(u8, acct.name, name)) continue;
        if (acct.host.len == 0) return errStr("Host is empty");

        var client = reports.imap.Client.init(
            allocator,
            acct.host,
            acct.port,
            acct.username,
            acct.password,
            acct.mailbox,
            acct.tls,
        );
        client.connect() catch return errStr("Failed to initialize IMAP client");
        defer client.deinit();

        const st = reports.store.Store.init(allocator, cfg.data_dir, acct.name);
        var fetched_set = st.loadFetchedUids() catch std.AutoHashMap(u32, void).init(allocator);
        defer fetched_set.deinit();

        const uids = client.searchReports() catch {
            if (reports.imap.lastCurlError()) |curl_msg| {
                return errStr(curl_msg);
            }
            return errStr("IMAP search failed");
        };
        defer allocator.free(uids);

        var new_uids: std.ArrayList(u32) = .empty;
        for (uids) |uid| {
            if (!fetched_set.contains(uid)) new_uids.append(allocator, uid) catch {};
        }
        const new_uid_slice = new_uids.toOwnedSlice(allocator) catch
            return errStr("Memory allocation failed");
        defer allocator.free(new_uid_slice);

        if (new_uid_slice.len == 0) return null;

        const results = reports.fetch.fetchMessages(allocator, &acct, new_uid_slice, null) orelse
            return errStr("Failed to fetch messages");
        defer reports.fetch.freeResults(allocator, results);
        _ = reports.fetch.processResults(allocator, results, &st, &fetched_set);
        return null;
    }

    return errStr("Account not found");
}

fn errStr(msg: []const u8) ?[*:0]u8 {
    const duped = allocator.dupeZ(u8, msg) catch return null;
    return duped.ptr;
}

/// Enrich all source IPs with PTR/ASN/country.
export fn reports_enrich(config_json: [*:0]const u8) c_int {
    const cfg = reports.config.Config.fromJson(allocator, std.mem.span(config_json)) catch return -1;
    defer cfg.deinit(allocator);

    const names = cfg.accountNames(allocator) catch return -1;
    defer allocator.free(names);

    if (getCache(cfg.data_dir)) |cache| {
        const ips = reports.fetch.collectSourceIps(allocator, cfg.data_dir, names) catch return -1;
        defer reports.fetch.freeIpList(allocator, ips);
        reports.enrichcache.enrichParallel(cache, allocator, ips, null);
    }
    return 0;
}

/// Rebuild dashboard and sources caches.
export fn reports_aggregate(config_json: [*:0]const u8) c_int {
    const cfg = reports.config.Config.fromJson(allocator, std.mem.span(config_json)) catch return -1;
    defer cfg.deinit(allocator);

    const names = cfg.accountNames(allocator) catch return -1;
    defer allocator.free(names);

    _ = buildAndCacheDashboard(cfg.data_dir, names);
    _ = buildAndCacheSourcesWithNames(cfg.data_dir, names);
    return 0;
}

/// Sync: fetch + enrich + aggregate in one call.
export fn reports_sync(config_json: [*:0]const u8) c_int {
    if (reports_fetch(config_json) != 0) return -1;
    _ = reports_enrich(config_json);
    _ = reports_aggregate(config_json);
    return 0;
}

export fn reports_list(config_json: [*:0]const u8) ?[*:0]u8 {
    const cfg = reports.config.Config.fromJson(allocator, std.mem.span(config_json)) catch return null;
    defer cfg.deinit(allocator);

    const names = cfg.accountNames(allocator) catch return null;
    defer allocator.free(names);

    const entries = reports.store.listAllReports(allocator, cfg.data_dir, names) catch return null;
    defer reports.store.freeReportEntries(allocator, entries);

    var buf: std.ArrayList(u8) = .empty;
    buf.appendSlice(allocator, "[") catch return null;
    for (entries, 0..) |e, i| {
        if (i > 0) buf.appendSlice(allocator, ",") catch return null;
        const type_str: []const u8 = switch (e.report_type) {
            .dmarc => "dmarc",
            .tlsrpt => "tlsrpt",
        };
        const hash_id = filenameToHashId(e.filename);
        const problems = countProblems(allocator, cfg.data_dir, e);
        const json_entry = std.fmt.allocPrint(allocator, "{{\"account\":\"{s}\",\"type\":\"{s}\",\"org\":\"{s}\",\"id\":\"{s}\",\"date\":\"{s}\",\"domain\":\"{s}\",\"policy\":\"{s}\",\"filename\":\"{s}\",\"problems\":{d}}}", .{
            e.account_name, type_str, e.org_name, hash_id, e.date_begin, e.domain, e.policy, e.filename, problems,
        }) catch return null;
        defer allocator.free(json_entry);
        buf.appendSlice(allocator, json_entry) catch return null;
    }
    buf.appendSlice(allocator, "]") catch return null;
    buf.append(allocator, 0) catch return null;

    const slice = buf.toOwnedSlice(allocator) catch return null;
    return @ptrCast(slice.ptr);
}

// MARK: - Dashboard Stats

const DmarcDashJson = struct {
    policy: struct {
        domain: []const u8 = "",
    } = .{},
    records: []const struct {
        count: u64 = 0,
        disposition: []const u8 = "",
        dkim_eval: []const u8 = "",
        spf_eval: []const u8 = "",
    } = &.{},
};

const TlsDashJson = struct {
    policies: []const struct {
        policy_domain: []const u8 = "",
        policy_type: []const u8 = "",
        total_successful: u64 = 0,
        total_failure: u64 = 0,
        failures: []const struct {
            result_type: []const u8 = "",
            failed_session_count: u64 = 0,
        } = &.{},
    } = &.{},
};

export fn reports_dashboard(config_json: [*:0]const u8) ?[*:0]u8 {
    const cfg = reports.config.Config.fromJson(allocator, std.mem.span(config_json)) catch return null;
    defer cfg.deinit(allocator);

    // Try cache first
    if (readDashboardCache(cfg.data_dir)) |cached| return cached;

    const names = cfg.accountNames(allocator) catch return null;
    defer allocator.free(names);
    return buildAndCacheDashboard(cfg.data_dir, names);
}

const dashboard_cache_filename = ".dashboard_cache.json";

fn readDashboardCache(data_dir: []const u8) ?[*:0]u8 {
    const path = std.fs.path.join(allocator, &.{ data_dir, dashboard_cache_filename }) catch return null;
    defer allocator.free(path);
    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();
    const data = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch return null;
    const result = allocator.dupeZ(u8, data) catch {
        allocator.free(data);
        return null;
    };
    allocator.free(data);
    return result.ptr;
}

fn writeDashboardCache(data_dir: []const u8, json: []const u8) void {
    const path = std.fs.path.join(allocator, &.{ data_dir, dashboard_cache_filename }) catch return;
    defer allocator.free(path);
    const file = std.fs.createFileAbsolute(path, .{}) catch return;
    defer file.close();
    file.writeAll(json) catch {};
}

fn buildAndCacheDashboard(data_dir: []const u8, names: []const []const u8) ?[*:0]u8 {
    const entries = reports.store.listAllReports(allocator, data_dir, names) catch return null;
    defer reports.store.freeReportEntries(allocator, entries);

    const json = buildDashboardJson(data_dir, entries) orelse return null;
    defer allocator.free(json);
    writeDashboardCache(data_dir, json);
    const result = allocator.dupeZ(u8, json) catch return null;
    return result.ptr;
}

const DashAgg = struct {
    dkim_pass: u64 = 0,
    dkim_fail: u64 = 0,
    spf_pass: u64 = 0,
    spf_fail: u64 = 0,
    disp_none: u64 = 0,
    disp_quarantine: u64 = 0,
    disp_reject: u64 = 0,
};

const TlsDomAgg = struct {
    success: u64 = 0,
    failure: u64 = 0,
};

fn buildDashboardJson(data_dir: []const u8, entries: []const reports.store.ReportEntry) ?[]const u8 {
    // Accumulators using owned keys
    var dmarc_orgs = std.StringHashMap(u64).init(allocator);
    defer {
        var it = dmarc_orgs.iterator();
        while (it.next()) |kv| allocator.free(kv.key_ptr.*);
        dmarc_orgs.deinit();
    }
    var tlsrpt_orgs = std.StringHashMap(u64).init(allocator);
    defer {
        var it = tlsrpt_orgs.iterator();
        while (it.next()) |kv| allocator.free(kv.key_ptr.*);
        tlsrpt_orgs.deinit();
    }

    var domain_auth = std.StringHashMap(DashAgg).init(allocator);
    defer {
        var it = domain_auth.iterator();
        while (it.next()) |kv| allocator.free(kv.key_ptr.*);
        domain_auth.deinit();
    }
    var dispositions = std.StringHashMap(u64).init(allocator);
    defer {
        var it = dispositions.iterator();
        while (it.next()) |kv| allocator.free(kv.key_ptr.*);
        dispositions.deinit();
    }

    var domain_tls = std.StringHashMap(TlsDomAgg).init(allocator);
    defer {
        var it = domain_tls.iterator();
        while (it.next()) |kv| allocator.free(kv.key_ptr.*);
        domain_tls.deinit();
    }
    // "domain\x00policy_type" -> count for per-domain policy type breakdown
    var domain_policy_types = std.StringHashMap(u64).init(allocator);
    defer {
        var it2 = domain_policy_types.iterator();
        while (it2.next()) |kv| allocator.free(kv.key_ptr.*);
        domain_policy_types.deinit();
    }
    // "domain\x00failure_type" -> count
    var domain_failure_types = std.StringHashMap(u64).init(allocator);
    defer {
        var it3 = domain_failure_types.iterator();
        while (it3.next()) |kv| allocator.free(kv.key_ptr.*);
        domain_failure_types.deinit();
    }
    var tls_policy_types = std.StringHashMap(u64).init(allocator);
    defer {
        var it = tls_policy_types.iterator();
        while (it.next()) |kv| allocator.free(kv.key_ptr.*);
        tls_policy_types.deinit();
    }
    var tls_failure_types = std.StringHashMap(u64).init(allocator);
    defer {
        var it = tls_failure_types.iterator();
        while (it.next()) |kv| allocator.free(kv.key_ptr.*);
        tls_failure_types.deinit();
    }

    for (entries) |entry| {
        const st = reports.store.Store.init(allocator, data_dir, entry.account_name);
        switch (entry.report_type) {
            .dmarc => {
                hashIncOwned(&dmarc_orgs, entry.org_name, 1);
                const data = st.loadDmarcReport(entry.filename) catch continue;
                defer allocator.free(data);
                const parsed = std.json.parseFromSlice(DmarcDashJson, allocator, data, .{ .ignore_unknown_fields = true }) catch continue;
                defer parsed.deinit();
                const domain = if (parsed.value.policy.domain.len > 0) parsed.value.policy.domain else entry.domain;
                for (parsed.value.records) |rec| {
                    const key = allocator.dupe(u8, domain) catch continue;
                    const gop = domain_auth.getOrPut(key) catch {
                        allocator.free(key);
                        continue;
                    };
                    if (gop.found_existing) allocator.free(key);
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
                    hashIncOwned(&dispositions, disp, rec.count);
                }
            },
            .tlsrpt => {
                hashIncOwned(&tlsrpt_orgs, entry.org_name, 1);
                const data = st.loadTlsReport(entry.filename) catch continue;
                defer allocator.free(data);
                const parsed = std.json.parseFromSlice(TlsDashJson, allocator, data, .{ .ignore_unknown_fields = true }) catch continue;
                defer parsed.deinit();
                for (parsed.value.policies) |pol| {
                    const domain = if (pol.policy_domain.len > 0) pol.policy_domain else entry.domain;
                    const dk = allocator.dupe(u8, domain) catch continue;
                    const gop = domain_tls.getOrPut(dk) catch {
                        allocator.free(dk);
                        continue;
                    };
                    if (gop.found_existing) allocator.free(dk);
                    if (!gop.found_existing) gop.value_ptr.* = .{};
                    gop.value_ptr.success += pol.total_successful;
                    gop.value_ptr.failure += pol.total_failure;
                    const pt = if (pol.policy_type.len > 0) pol.policy_type else "unknown";
                    hashIncOwned(&tls_policy_types, pt, pol.total_successful + pol.total_failure);
                    // Per-domain policy type: "domain\x00type"
                    const dpt_key = std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ domain, pt }) catch continue;
                    const dpt_gop = domain_policy_types.getOrPut(dpt_key) catch {
                        allocator.free(dpt_key);
                        continue;
                    };
                    if (dpt_gop.found_existing) allocator.free(dpt_key);
                    if (!dpt_gop.found_existing) dpt_gop.value_ptr.* = 0;
                    dpt_gop.value_ptr.* += pol.total_successful + pol.total_failure;

                    for (pol.failures) |f| {
                        const ft = if (f.result_type.len > 0) f.result_type else "unknown";
                        hashIncOwned(&tls_failure_types, ft, f.failed_session_count);
                        // Per-domain failure type
                        const dft_key = std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ domain, ft }) catch continue;
                        const dft_gop = domain_failure_types.getOrPut(dft_key) catch {
                            allocator.free(dft_key);
                            continue;
                        };
                        if (dft_gop.found_existing) allocator.free(dft_key);
                        if (!dft_gop.found_existing) dft_gop.value_ptr.* = 0;
                        dft_gop.value_ptr.* += f.failed_session_count;
                    }
                }
            },
        }
    }

    // Build JSON
    var buf: std.ArrayList(u8) = .empty;
    buf.appendSlice(allocator, "{") catch return null;

    // Helper to write a map as sorted array of {"k":"...","v":N}
    writeMapArray(&buf, "dmarc_orgs", &dmarc_orgs);
    buf.appendSlice(allocator, ",") catch return null;
    writeMapArray(&buf, "tlsrpt_orgs", &tlsrpt_orgs);
    buf.appendSlice(allocator, ",") catch return null;
    writeMapArray(&buf, "dispositions", &dispositions);
    buf.appendSlice(allocator, ",") catch return null;
    writeMapArray(&buf, "tls_policy_types", &tls_policy_types);
    buf.appendSlice(allocator, ",") catch return null;
    writeMapArray(&buf, "tls_failure_types", &tls_failure_types);

    // domain_auth
    buf.appendSlice(allocator, ",\"domain_auth\":[") catch return null;
    {
        var first = true;
        var it = domain_auth.iterator();
        while (it.next()) |kv| {
            if (!first) buf.appendSlice(allocator, ",") catch return null;
            first = false;
            const line = std.fmt.allocPrint(allocator, "{{\"domain\":\"{s}\",\"dkim_pass\":{d},\"dkim_fail\":{d},\"spf_pass\":{d},\"spf_fail\":{d},\"disp_none\":{d},\"disp_quarantine\":{d},\"disp_reject\":{d}}}", .{
                kv.key_ptr.*,           kv.value_ptr.dkim_pass,       kv.value_ptr.dkim_fail,   kv.value_ptr.spf_pass, kv.value_ptr.spf_fail,
                kv.value_ptr.disp_none, kv.value_ptr.disp_quarantine, kv.value_ptr.disp_reject,
            }) catch continue;
            defer allocator.free(line);
            buf.appendSlice(allocator, line) catch return null;
        }
    }
    buf.appendSlice(allocator, "]") catch return null;

    // domain_tls with per-domain policy_types and failure_types
    buf.appendSlice(allocator, ",\"domain_tls\":[") catch return null;
    {
        var first = true;
        var it = domain_tls.iterator();
        while (it.next()) |kv| {
            if (!first) buf.appendSlice(allocator, ",") catch return null;
            first = false;
            const dom = kv.key_ptr.*;

            // Collect policy types for this domain
            var pt_buf: std.ArrayList(u8) = .empty;
            defer pt_buf.deinit(allocator);
            pt_buf.appendSlice(allocator, "[") catch continue;
            {
                var pt_first = true;
                var pt_it = domain_policy_types.iterator();
                while (pt_it.next()) |pt_kv| {
                    const compound = pt_kv.key_ptr.*;
                    if (std.mem.indexOfScalar(u8, compound, 0)) |sep| {
                        if (std.mem.eql(u8, compound[0..sep], dom)) {
                            if (!pt_first) pt_buf.appendSlice(allocator, ",") catch continue;
                            pt_first = false;
                            const entry = std.fmt.allocPrint(allocator, "{{\"k\":\"{s}\",\"v\":{d}}}", .{ compound[sep + 1 ..], pt_kv.value_ptr.* }) catch continue;
                            defer allocator.free(entry);
                            pt_buf.appendSlice(allocator, entry) catch continue;
                        }
                    }
                }
            }
            pt_buf.appendSlice(allocator, "]") catch continue;

            // Collect failure types for this domain
            var ft_buf: std.ArrayList(u8) = .empty;
            defer ft_buf.deinit(allocator);
            ft_buf.appendSlice(allocator, "[") catch continue;
            {
                var ft_first = true;
                var ft_it = domain_failure_types.iterator();
                while (ft_it.next()) |ft_kv| {
                    const compound = ft_kv.key_ptr.*;
                    if (std.mem.indexOfScalar(u8, compound, 0)) |sep| {
                        if (std.mem.eql(u8, compound[0..sep], dom)) {
                            if (!ft_first) ft_buf.appendSlice(allocator, ",") catch continue;
                            ft_first = false;
                            const entry = std.fmt.allocPrint(allocator, "{{\"k\":\"{s}\",\"v\":{d}}}", .{ compound[sep + 1 ..], ft_kv.value_ptr.* }) catch continue;
                            defer allocator.free(entry);
                            ft_buf.appendSlice(allocator, entry) catch continue;
                        }
                    }
                }
            }
            ft_buf.appendSlice(allocator, "]") catch continue;

            const line = std.fmt.allocPrint(allocator, "{{\"domain\":\"{s}\",\"success\":{d},\"failure\":{d},\"policy_types\":{s},\"failure_types\":{s}}}", .{
                dom, kv.value_ptr.success, kv.value_ptr.failure, pt_buf.items, ft_buf.items,
            }) catch continue;
            defer allocator.free(line);
            buf.appendSlice(allocator, line) catch return null;
        }
    }
    buf.appendSlice(allocator, "]") catch return null;

    buf.appendSlice(allocator, "}") catch return null;
    return buf.toOwnedSlice(allocator) catch null;
}

fn hashIncOwned(map: *std.StringHashMap(u64), key: []const u8, val: u64) void {
    const duped = allocator.dupe(u8, key) catch return;
    const gop = map.getOrPut(duped) catch {
        allocator.free(duped);
        return;
    };
    if (gop.found_existing) {
        allocator.free(duped);
        gop.value_ptr.* += val;
    } else {
        gop.value_ptr.* = val;
    }
}

fn writeMapArray(buf: *std.ArrayList(u8), name: []const u8, map: *std.StringHashMap(u64)) void {
    const prefix = std.fmt.allocPrint(allocator, "\"{s}\":[", .{name}) catch return;
    defer allocator.free(prefix);
    buf.appendSlice(allocator, prefix) catch return;
    var first = true;
    var it = map.iterator();
    while (it.next()) |kv| {
        if (!first) buf.appendSlice(allocator, ",") catch return;
        first = false;
        const line = std.fmt.allocPrint(allocator, "{{\"k\":\"{s}\",\"v\":{d}}}", .{ kv.key_ptr.*, kv.value_ptr.* }) catch continue;
        defer allocator.free(line);
        buf.appendSlice(allocator, line) catch return;
    }
    buf.appendSlice(allocator, "]") catch return;
}

// MARK: - Mail Sources

const DmarcSourcesJson = struct {
    policy: struct {
        domain: []const u8 = "",
    } = .{},
    records: []const struct {
        source_ip: []const u8 = "",
        count: u64 = 0,
        dkim_eval: []const u8 = "",
        spf_eval: []const u8 = "",
    } = &.{},
};

const TlsSourcesJson = struct {
    policies: []const struct {
        policy_domain: []const u8 = "",
        failures: []const struct {
            sending_mta_ip: []const u8 = "",
            failed_session_count: u64 = 0,
        } = &.{},
    } = &.{},
};

const SourceAgg = struct {
    messages: u64 = 0,
    dmarc_issues: u64 = 0,
    tls_failures: u64 = 0,
    has_dmarc: bool = false,
    has_tlsrpt: bool = false,
    // domain indices into domain list
    domain_indices: std.ArrayList(u16) = .empty,
};

const sources_cache_filename = ".sources_cache.json";

export fn reports_sources(config_json: [*:0]const u8) ?[*:0]u8 {
    const cfg = reports.config.Config.fromJson(allocator, std.mem.span(config_json)) catch return null;
    defer cfg.deinit(allocator);

    // Try reading from cache first
    if (readSourcesCache(cfg.data_dir)) |cached| {
        return cached;
    }

    // Cache miss — compute fresh and write cache
    const names = cfg.accountNames(allocator) catch return null;
    defer allocator.free(names);
    return buildAndCacheSourcesWithNames(cfg.data_dir, names);
}

fn sourceCachePath(data_dir: []const u8) ?[]const u8 {
    return std.fs.path.join(allocator, &.{ data_dir, sources_cache_filename }) catch null;
}

fn readSourcesCache(data_dir: []const u8) ?[*:0]u8 {
    const path = sourceCachePath(data_dir) orelse return null;
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();
    const data = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch return null;

    // Return as null-terminated string
    const result = allocator.dupeZ(u8, data) catch {
        allocator.free(data);
        return null;
    };
    allocator.free(data);
    return result.ptr;
}

fn writeSourcesCache(data_dir: []const u8, json: []const u8) void {
    const path = sourceCachePath(data_dir) orelse return;
    defer allocator.free(path);

    const file = std.fs.createFileAbsolute(path, .{}) catch return;
    defer file.close();
    file.writeAll(json) catch {};
}

fn buildAndCacheSources(data_dir: []const u8) void {
    // Scan account subdirectories from data_dir
    const names = scanAccountNames(data_dir) orelse return;
    defer {
        for (names) |n| allocator.free(n);
        allocator.free(names);
    }
    const entries = reports.store.listAllReports(allocator, data_dir, names) catch return;
    defer reports.store.freeReportEntries(allocator, entries);

    const json = buildSourcesJson(data_dir, entries) orelse return;
    defer allocator.free(json);
    writeSourcesCache(data_dir, json);
}

fn buildAndCacheSourcesWithNames(data_dir: []const u8, names: []const []const u8) ?[*:0]u8 {
    const entries = reports.store.listAllReports(allocator, data_dir, names) catch return null;
    defer reports.store.freeReportEntries(allocator, entries);

    const json = buildSourcesJson(data_dir, entries) orelse return null;
    defer allocator.free(json);

    writeSourcesCache(data_dir, json);

    const result = allocator.dupeZ(u8, json) catch return null;
    return result.ptr;
}

fn buildSourcesJson(data_dir: []const u8, entries: []const reports.store.ReportEntry) ?[]const u8 {
    // IP -> aggregation
    var ip_map = std.StringHashMap(SourceAgg).init(allocator);
    defer {
        var it = ip_map.iterator();
        while (it.next()) |kv| {
            allocator.free(kv.key_ptr.*);
            kv.value_ptr.domain_indices.deinit(allocator);
        }
        ip_map.deinit();
    }

    // Domain dedup list
    var domain_list: std.ArrayList([]const u8) = .empty;
    defer {
        for (domain_list.items) |d| allocator.free(d);
        domain_list.deinit(allocator);
    }
    var domain_map = std.StringHashMap(u16).init(allocator);
    defer domain_map.deinit();

    for (entries) |entry| {
        const st = reports.store.Store.init(allocator, data_dir, entry.account_name);
        switch (entry.report_type) {
            .dmarc => {
                const data = st.loadDmarcReport(entry.filename) catch continue;
                defer allocator.free(data);
                const parsed = std.json.parseFromSlice(DmarcSourcesJson, allocator, data, .{
                    .ignore_unknown_fields = true,
                }) catch continue;
                defer parsed.deinit();

                const domain = if (parsed.value.policy.domain.len > 0) parsed.value.policy.domain else entry.domain;
                const di = domainIndex(&domain_list, &domain_map, domain);

                for (parsed.value.records) |rec| {
                    if (rec.source_ip.len == 0) continue;
                    const ip_key = allocator.dupe(u8, rec.source_ip) catch continue;
                    const gop = ip_map.getOrPut(ip_key) catch {
                        allocator.free(ip_key);
                        continue;
                    };
                    if (gop.found_existing) allocator.free(ip_key);
                    if (!gop.found_existing) gop.value_ptr.* = .{};
                    gop.value_ptr.messages += rec.count;
                    gop.value_ptr.has_dmarc = true;
                    const dkim_pass = std.mem.eql(u8, rec.dkim_eval, "pass");
                    const spf_pass = std.mem.eql(u8, rec.spf_eval, "pass");
                    if (!dkim_pass and !spf_pass) gop.value_ptr.dmarc_issues += rec.count;
                    addDomainIndex(&gop.value_ptr.domain_indices, di);
                }
            },
            .tlsrpt => {
                const data = st.loadTlsReport(entry.filename) catch continue;
                defer allocator.free(data);
                const parsed = std.json.parseFromSlice(TlsSourcesJson, allocator, data, .{
                    .ignore_unknown_fields = true,
                }) catch continue;
                defer parsed.deinit();

                for (parsed.value.policies) |pol| {
                    const domain = if (pol.policy_domain.len > 0) pol.policy_domain else entry.domain;
                    const di = domainIndex(&domain_list, &domain_map, domain);

                    for (pol.failures) |f| {
                        if (f.sending_mta_ip.len == 0) continue;
                        const ip_key = allocator.dupe(u8, f.sending_mta_ip) catch continue;
                        const gop = ip_map.getOrPut(ip_key) catch {
                            allocator.free(ip_key);
                            continue;
                        };
                        if (gop.found_existing) allocator.free(ip_key);
                        if (!gop.found_existing) gop.value_ptr.* = .{};
                        gop.value_ptr.tls_failures += f.failed_session_count;
                        gop.value_ptr.has_tlsrpt = true;
                        addDomainIndex(&gop.value_ptr.domain_indices, di);
                    }
                }
            },
        }
    }

    // Load enrich cache for PTR/ASN/country lookup
    var enrich_cache: ?reports.enrichcache.Cache = reports.enrichcache.Cache.init(allocator, data_dir) catch null;
    defer if (enrich_cache) |*c| c.deinit();

    // Build JSON
    var buf: std.ArrayList(u8) = .empty;
    buf.appendSlice(allocator, "[") catch return null;
    var first = true;
    var it = ip_map.iterator();
    while (it.next()) |kv| {
        if (!first) buf.appendSlice(allocator, ",") catch return null;
        first = false;

        var dbuf: std.ArrayList(u8) = .empty;
        defer dbuf.deinit(allocator);
        dbuf.appendSlice(allocator, "[") catch continue;
        for (kv.value_ptr.domain_indices.items, 0..) |di, j| {
            if (j > 0) dbuf.appendSlice(allocator, ",") catch continue;
            dbuf.appendSlice(allocator, "\"") catch continue;
            if (di < domain_list.items.len) {
                dbuf.appendSlice(allocator, domain_list.items[di]) catch continue;
            }
            dbuf.appendSlice(allocator, "\"") catch continue;
        }
        dbuf.appendSlice(allocator, "]") catch continue;

        const types_str: []const u8 = if (kv.value_ptr.has_dmarc and kv.value_ptr.has_tlsrpt)
            "[\"dmarc\",\"tlsrpt\"]"
        else if (kv.value_ptr.has_dmarc)
            "[\"dmarc\"]"
        else
            "[\"tlsrpt\"]";

        // Lookup enrichment from cache
        var ptr_str: []const u8 = "";
        var asn_str: []const u8 = "";
        var asn_org_str: []const u8 = "";
        var country_str: []const u8 = "";
        var free_ptr = false;
        var free_asn = false;
        var free_asn_org = false;
        var free_country = false;

        if (enrich_cache) |*c| {
            if (c.getDup(kv.key_ptr.*)) |entry| {
                ptr_str = entry.ptr;
                free_ptr = true;
                asn_str = entry.asn;
                free_asn = true;
                asn_org_str = entry.asn_org;
                free_asn_org = true;
                country_str = entry.country;
                free_country = true;
            }
        }
        defer {
            if (free_ptr) allocator.free(ptr_str);
            if (free_asn) allocator.free(asn_str);
            if (free_asn_org) allocator.free(asn_org_str);
            if (free_country) allocator.free(country_str);
        }

        const line = std.fmt.allocPrint(allocator, "{{\"ip\":\"{s}\",\"messages\":{d},\"dmarc_issues\":{d},\"tls_failures\":{d},\"types\":{s},\"domains\":{s},\"ptr\":\"{s}\",\"asn\":\"{s}\",\"asn_org\":\"{s}\",\"country\":\"{s}\"}}", .{
            kv.key_ptr.*,
            kv.value_ptr.messages,
            kv.value_ptr.dmarc_issues,
            kv.value_ptr.tls_failures,
            types_str,
            dbuf.items,
            ptr_str,
            asn_str,
            asn_org_str,
            country_str,
        }) catch continue;
        defer allocator.free(line);
        buf.appendSlice(allocator, line) catch continue;
    }
    buf.appendSlice(allocator, "]") catch return null;

    return buf.toOwnedSlice(allocator) catch null;
}

fn scanAccountNames(data_dir: []const u8) ?[]const []const u8 {
    var dir = std.fs.openDirAbsolute(data_dir, .{ .iterate = true }) catch return null;
    defer dir.close();

    var names: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (it.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        // Skip hidden dirs
        if (entry.name.len > 0 and entry.name[0] == '.') continue;
        const duped = allocator.dupe(u8, entry.name) catch continue;
        names.append(allocator, duped) catch {
            allocator.free(duped);
            continue;
        };
    }
    return names.toOwnedSlice(allocator) catch null;
}

fn domainIndex(list: *std.ArrayList([]const u8), map: *std.StringHashMap(u16), domain: []const u8) u16 {
    if (map.get(domain)) |idx| return idx;
    const duped = allocator.dupe(u8, domain) catch return 0;
    const idx: u16 = @intCast(list.items.len);
    list.append(allocator, duped) catch {
        allocator.free(duped);
        return 0;
    };
    map.put(duped, idx) catch {};
    return idx;
}

fn addDomainIndex(indices: *std.ArrayList(u16), di: u16) void {
    for (indices.items) |existing| {
        if (existing == di) return;
    }
    indices.append(allocator, di) catch {};
}

export fn reports_show(config_json: [*:0]const u8, report_type: [*:0]const u8, account_name: [*:0]const u8, filename: [*:0]const u8) ?[*:0]u8 {
    const cfg = reports.config.Config.fromJson(allocator, std.mem.span(config_json)) catch return null;
    defer cfg.deinit(allocator);

    const st = reports.store.Store.init(allocator, cfg.data_dir, std.mem.span(account_name));

    const type_span = std.mem.span(report_type);
    const fname = std.mem.span(filename);

    const data = if (std.mem.eql(u8, type_span, "dmarc"))
        st.loadDmarcReport(fname) catch return null
    else
        st.loadTlsReport(fname) catch return null;

    const result = allocator.dupeZ(u8, data) catch {
        allocator.free(data);
        return null;
    };
    allocator.free(data);
    return result.ptr;
}

fn countProblems(alloc: std.mem.Allocator, data_dir: []const u8, entry: reports.store.ReportEntry) u64 {
    const st = reports.store.Store.init(alloc, data_dir, entry.account_name);
    switch (entry.report_type) {
        .dmarc => {
            const data = st.loadDmarcReport(entry.filename) catch return 0;
            defer alloc.free(data);
            return reports.stats.countDmarcProblems(alloc, data);
        },
        .tlsrpt => {
            const data = st.loadTlsReport(entry.filename) catch return 0;
            defer alloc.free(data);
            return reports.stats.countTlsProblems(alloc, data);
        },
    }
}

fn filenameToHashId(filename: []const u8) []const u8 {
    if (std.mem.endsWith(u8, filename, ".json")) {
        return filename[0 .. filename.len - 5];
    }
    return filename;
}

export fn reports_enrich_ip(ip: [*:0]const u8) ?[*:0]u8 {
    const ip_span = std.mem.span(ip);

    // Hold g_cache_mu across the entire cache access to prevent a use-after-free
    // if reports_deinit() runs concurrently. Cache.getDup has its own internal
    // mutex but that doesn't protect the g_cache pointer itself.
    g_cache_mu.lock();
    if (g_cache) |*c| {
        if (c.getDup(ip_span)) |entry| {
            g_cache_mu.unlock();
            defer reports.enrichcache.freeEntryFields(allocator, entry);
            const info = reports.enrichcache.entryToIpInfo(allocator, entry) catch return null;
            defer info.deinit(allocator);

            const json = info.toJson(allocator) catch return null;
            defer allocator.free(json);
            const result = allocator.dupeZ(u8, json) catch return null;
            return result.ptr;
        }
    }
    g_cache_mu.unlock();

    // Cache miss (or no cache): resolve via DNS, then try to write back under lock.
    const info = reports.ipinfo.lookup(allocator, ip_span);
    defer info.deinit(allocator);

    g_cache_mu.lock();
    if (g_cache) |*c| {
        // put() appends to JSONL file directly; no separate save step needed.
        c.put(ip_span, info) catch {};
    }
    g_cache_mu.unlock();

    const json = info.toJson(allocator) catch return null;
    defer allocator.free(json);
    const result = allocator.dupeZ(u8, json) catch return null;
    return result.ptr;
}

export fn reports_free_string(ptr: ?[*:0]u8) void {
    if (ptr) |p| {
        const len = std.mem.len(p);
        allocator.free(p[0 .. len + 1]);
    }
}
