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

    for (cfg.accounts) |acct| {
        if (acct.host.len == 0) continue;

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

        const uids = client.searchReports() catch continue;
        defer allocator.free(uids);

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

    // After all messages fetched and reports saved, enrich every unique source IP
    // in parallel using the same worker-pool pattern as IMAP fetch.
    if (getCache(cfg.data_dir)) |cache| {
        const names = cfg.accountNames(allocator) catch return 0;
        defer allocator.free(names);

        const ips = reports.fetch.collectSourceIps(allocator, cfg.data_dir, names) catch return 0;
        defer reports.fetch.freeIpList(allocator, ips);

        reports.enrichcache.enrichParallel(cache, allocator, ips, null);
    }

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
        const json_entry = std.fmt.allocPrint(allocator, "{{\"account\":\"{s}\",\"type\":\"{s}\",\"org\":\"{s}\",\"id\":\"{s}\",\"date\":\"{s}\",\"domain\":\"{s}\",\"policy\":\"{s}\",\"filename\":\"{s}\"}}", .{
            e.account_name, type_str, e.org_name, hash_id, e.date_begin, e.domain, e.policy, e.filename,
        }) catch return null;
        defer allocator.free(json_entry);
        buf.appendSlice(allocator, json_entry) catch return null;
    }
    buf.appendSlice(allocator, "]") catch return null;
    buf.append(allocator, 0) catch return null;

    const slice = buf.toOwnedSlice(allocator) catch return null;
    return @ptrCast(slice.ptr);
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

fn filenameToHashId(filename: []const u8) []const u8 {
    if (std.mem.endsWith(u8, filename, ".json")) {
        return filename[0 .. filename.len - 5];
    }
    return filename;
}

export fn reports_enrich_ip(ip: [*:0]const u8) ?[*:0]u8 {
    const ip_span = std.mem.span(ip);

    // Use the global cache if it has been initialized (by a prior fetch call).
    // This avoids DNS lookups for IPs already resolved during fetch.
    g_cache_mu.lock();
    const have_cache = g_cache != null;
    g_cache_mu.unlock();

    if (have_cache) {
        if (g_cache.?.getDup(ip_span)) |entry| {
            defer reports.enrichcache.freeEntryFields(allocator, entry);
            const info = reports.enrichcache.entryToIpInfo(allocator, entry) catch {
                return fallbackEnrich(ip_span);
            };
            defer info.deinit(allocator);

            const json = info.toJson(allocator) catch return null;
            defer allocator.free(json);
            const result = allocator.dupeZ(u8, json) catch return null;
            return result.ptr;
        }
    }

    return fallbackEnrich(ip_span);
}

fn fallbackEnrich(ip: []const u8) ?[*:0]u8 {
    const info = reports.ipinfo.lookup(allocator, ip);
    defer info.deinit(allocator);

    // If the cache is available, store the freshly resolved result for next time.
    g_cache_mu.lock();
    if (g_cache) |*c| {
        // put() appends to JSONL file directly; no separate save step needed.
        c.put(ip, info) catch {};
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
