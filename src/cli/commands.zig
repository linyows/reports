const std = @import("std");
const reports = @import("reports");
const ui = @import("ui.zig");
const data = @import("data.zig");
const enrich = @import("enrich.zig");

const Config = reports.config.Config;
const Store = reports.store.Store;

// --- Fetch ---

pub fn cmdFetch(allocator: std.mem.Allocator, account_filter: ?[]const u8, refetch: bool) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);

    reports.store.migrateToAccountDirs(cfg.data_dir);
    try cfg.ensureDataDir();

    if (cfg.accounts.len == 0) {
        ui.stderr_file.writeAll("No accounts configured. Edit ~/.config/reports/config.json\n") catch {};
        return;
    }

    reports.imap.globalInit();
    defer reports.imap.globalCleanup();

    ui.stdout_file.writeAll(ui.section_prefix ++ "Messages Fetch\n") catch {};

    for (cfg.accounts) |acct| {
        if (account_filter) |filter| {
            if (!std.mem.eql(u8, acct.name, filter)) continue;
        }

        if (acct.host.len == 0) continue;

        {
            var buf: [128]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, ui.branch_prefix ++ "{s}\n", .{acct.name}) catch "";
            ui.stdout_file.writeAll(msg) catch {};
        }

        const result = fetchForAccount(allocator, &acct, cfg.data_dir, refetch);

        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "Fetched {d} DMARC and {d} TLS-RPT reports\n", .{
            result.dmarc, result.tls,
        }) catch "Done.\n";
        ui.stdout_file.writeAll(msg) catch {};
    }
}

fn fetchForAccount(allocator: std.mem.Allocator, acct: *const Config.Account, data_dir: []const u8, refetch: bool) struct { dmarc: u32, tls: u32 } {
    var client = reports.imap.Client.init(
        allocator,
        acct.host,
        acct.port,
        acct.username,
        acct.password,
        acct.mailbox,
        acct.tls,
    );
    client.connect() catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "IMAP connect failed: {s}\n", .{@errorName(err)}) catch "IMAP connect failed\n";
        ui.stderr_file.writeAll(msg) catch {};
        return .{ .dmarc = 0, .tls = 0 };
    };
    defer client.deinit();

    const st = Store.init(allocator, data_dir, acct.name);

    var fetched_set = st.loadFetchedUids() catch std.AutoHashMap(u32, void).init(allocator);
    defer fetched_set.deinit();

    ui.stdout_file.writeAll(ui.detail_prefix ++ "Searching for report messages...\n") catch {};
    const uids = client.searchReports() catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "IMAP search failed: {s}\n", .{@errorName(err)}) catch "IMAP search failed\n";
        ui.stderr_file.writeAll(msg) catch {};
        return .{ .dmarc = 0, .tls = 0 };
    };
    defer allocator.free(uids);

    var new_uids: std.ArrayList(u32) = .empty;
    for (uids) |uid| {
        if (refetch or !fetched_set.contains(uid)) new_uids.append(allocator, uid) catch {};
    }
    const new_uid_slice = new_uids.toOwnedSlice(allocator) catch return .{ .dmarc = 0, .tls = 0 };
    defer allocator.free(new_uid_slice);

    {
        var buf: [128]u8 = undefined;
        const found_msg = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "Found {d} messages ({d} new)\n", .{ uids.len, new_uid_slice.len }) catch ui.detail_prefix ++ "Found messages\n";
        ui.stdout_file.writeAll(found_msg) catch {};
    }

    if (new_uid_slice.len == 0) return .{ .dmarc = 0, .tls = 0 };

    var progress = std.atomic.Value(usize).init(0);
    var job = reports.fetch.startFetch(allocator, acct, new_uid_slice, &progress) orelse return .{ .dmarc = 0, .tls = 0 };
    defer reports.fetch.freeResults(allocator, job.results);

    while (progress.load(.monotonic) < new_uid_slice.len) {
        {
            var pbuf: [64]u8 = undefined;
            const prog = std.fmt.bufPrint(&pbuf, "\r\x1b[K" ++ ui.detail_prefix ++ "[{d}/{d}]", .{ progress.load(.monotonic), new_uid_slice.len }) catch "";
            ui.stderr_file.writeAll(prog) catch {};
        }
        std.Thread.sleep(200 * std.time.ns_per_ms);
    }
    job.join();
    {
        var pbuf: [64]u8 = undefined;
        const prog = std.fmt.bufPrint(&pbuf, "\r\x1b[K" ++ ui.detail_prefix ++ "[{d}/{d}]\n", .{ new_uid_slice.len, new_uid_slice.len }) catch "\n";
        ui.stderr_file.writeAll(prog) catch {};
    }

    const counts = reports.fetch.processResults(allocator, job.results, &st, &fetched_set);
    return .{ .dmarc = counts.dmarc, .tls = counts.tls };
}

// --- Enrich ---

pub fn cmdEnrich(allocator: std.mem.Allocator) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);
    try enrichAllIps(allocator, &cfg);
}

fn enrichAllIps(allocator: std.mem.Allocator, cfg: *const Config) !void {
    const names = try cfg.accountNames(allocator);
    defer allocator.free(names);

    const ips = try reports.fetch.collectSourceIps(allocator, cfg.data_dir, names);
    defer reports.fetch.freeIpList(allocator, ips);

    if (ips.len == 0) {
        ui.stdout_file.writeAll(ui.section_prefix ++ "IP Enrichment\n") catch {};
        ui.stdout_file.writeAll(ui.branch_prefix ++ "No IPs to enrich\n") catch {};
        return;
    }

    var cache = try reports.enrichcache.Cache.init(allocator, cfg.data_dir);
    defer cache.deinit();

    var pending: usize = 0;
    for (ips) |ip| {
        if (!cache.hasFresh(ip)) pending += 1;
    }

    ui.stdout_file.writeAll(ui.section_prefix ++ "IP Enrichment\n") catch {};
    {
        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, ui.branch_prefix ++ "Enriching ({d} cached, {d} new)...\n", .{
            ips.len - pending, pending,
        }) catch ui.branch_prefix ++ "Enriching IPs...\n";
        ui.stdout_file.writeAll(msg) catch {};
    }

    if (pending == 0) {
        var ebuf: [128]u8 = undefined;
        const emsg = std.fmt.bufPrint(&ebuf, ui.detail_prefix ++ "Enriched {d} IPs\n", .{ips.len}) catch ui.detail_prefix ++ "Enrichment complete\n";
        ui.stdout_file.writeAll(emsg) catch {};
        return;
    }

    var progress = std.atomic.Value(usize).init(0);

    const Spawner = struct {
        fn run(c: *reports.enrichcache.Cache, a: std.mem.Allocator, batch: []const []const u8, p: *std.atomic.Value(usize)) void {
            reports.enrichcache.enrichParallel(c, a, batch, p);
        }
    };

    const thread = std.Thread.spawn(.{}, Spawner.run, .{ &cache, allocator, ips, &progress }) catch {
        reports.enrichcache.enrichParallel(&cache, allocator, ips, &progress);
        return;
    };

    while (progress.load(.monotonic) < ips.len) {
        var pbuf: [64]u8 = undefined;
        const prog = std.fmt.bufPrint(&pbuf, "\r\x1b[K" ++ ui.detail_prefix ++ "[{d}/{d}]", .{ progress.load(.monotonic), ips.len }) catch "";
        ui.stderr_file.writeAll(prog) catch {};
        std.Thread.sleep(200 * std.time.ns_per_ms);
    }
    thread.join();
    ui.stderr_file.writeAll("\r\x1b[K") catch {};
    {
        var ebuf: [128]u8 = undefined;
        const emsg = std.fmt.bufPrint(&ebuf, ui.detail_prefix ++ "Enriched {d} IPs\n", .{ips.len}) catch ui.detail_prefix ++ "Enrichment complete\n";
        ui.stdout_file.writeAll(emsg) catch {};
    }
}

// --- Aggregate ---

pub fn cmdAggregate(allocator: std.mem.Allocator) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);

    const names = cfg.accountNames(allocator) catch return;
    defer allocator.free(names);

    const entries = reports.store.listAllReports(allocator, cfg.data_dir, names) catch return;
    defer reports.store.freeReportEntries(allocator, entries);

    const ips = reports.fetch.collectSourceIps(allocator, cfg.data_dir, names) catch return;
    defer reports.fetch.freeIpList(allocator, ips);

    for ([_][]const u8{ ".sources_cache.json", ".dashboard_cache.json" }) |filename| {
        const path = std.fs.path.join(allocator, &.{ cfg.data_dir, filename }) catch continue;
        defer allocator.free(path);
        std.fs.deleteFileAbsolute(path) catch {};
    }

    ui.stdout_file.writeAll(ui.section_prefix ++ "Reports Aggregation\n") catch {};
    ui.stdout_file.writeAll(ui.branch_prefix ++ "Aggregating...\n") catch {};
    var buf: [128]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "Aggregated {d} reports\n", .{
        entries.len,
    }) catch ui.detail_prefix ++ "Aggregation complete\n";
    ui.stdout_file.writeAll(msg) catch {};
}

// --- DNS ---

pub fn cmdDns(allocator: std.mem.Allocator, domain_filter: ?[]const u8, format: []const u8) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);

    var domains: std.ArrayList([]const u8) = .empty;
    defer {
        for (domains.items) |d| allocator.free(d);
        domains.deinit(allocator);
    }

    if (domain_filter) |d| {
        domains.append(allocator, allocator.dupe(u8, d) catch return) catch {};
    } else {
        const entries = try data.loadEntries(allocator, &cfg, null);
        defer reports.store.freeReportEntries(allocator, entries);

        var domain_set = std.StringHashMap(void).init(allocator);
        defer domain_set.deinit();
        for (entries) |e| {
            if (e.domain.len > 0) domain_set.put(e.domain, {}) catch {};
        }
        var it = domain_set.iterator();
        while (it.next()) |kv| {
            domains.append(allocator, allocator.dupe(u8, kv.key_ptr.*) catch continue) catch {};
        }
    }

    const is_json = std.mem.eql(u8, format, "json");

    const icon_ok = ui.neon_yellow ++ "●" ++ ui.reset;
    const icon_warning = ui.warn_yellow ++ "●" ++ ui.reset;
    const icon_critical = ui.fail_red ++ "●" ++ ui.reset;
    const check_ok = ui.neon_yellow ++ "✓" ++ ui.reset ++ " ";
    const check_warning = ui.warn_yellow ++ "△" ++ ui.reset ++ " ";
    const check_critical = ui.fail_red ++ "✗" ++ ui.reset ++ " ";
    const not_found = ui.dim ++ "(not found)" ++ ui.reset;

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(allocator);
    var json_first = true;
    if (is_json) json_buf.appendSlice(allocator, "[") catch {};

    for (domains.items) |domain| {
        var buf: [2048]u8 = undefined;

        var dmarc_txt: ?[]const u8 = null;
        defer if (dmarc_txt) |t| allocator.free(t);
        var spf_txt: ?[]const u8 = null;
        defer if (spf_txt) |t| allocator.free(t);
        var dkim_txt: ?[]const u8 = null;
        defer if (dkim_txt) |t| allocator.free(t);
        var dkim_selector: []const u8 = "";
        var mta_sts_txt: ?[]const u8 = null;
        defer if (mta_sts_txt) |t| allocator.free(t);
        var tls_rpt_txt: ?[]const u8 = null;
        defer if (tls_rpt_txt) |t| allocator.free(t);

        // DMARC
        {
            const qname = std.fmt.allocPrint(allocator, "_dmarc.{s}", .{domain}) catch continue;
            defer allocator.free(qname);
            dmarc_txt = reports.ipinfo.queryTxt(allocator, qname) catch null;
        }

        // SPF
        {
            if (reports.ipinfo.queryTxt(allocator, domain)) |txt| {
                if (std.mem.indexOf(u8, txt, "v=spf1") != null) {
                    spf_txt = txt;
                } else {
                    allocator.free(txt);
                }
            } else |_| {}
        }

        // DKIM
        for ([_][]const u8{ "default", "google", "selector1", "selector2", "s1", "s2", "dkim", "mail" }) |selector| {
            const qname = std.fmt.allocPrint(allocator, "{s}._domainkey.{s}", .{ selector, domain }) catch continue;
            defer allocator.free(qname);
            if (reports.ipinfo.queryTxt(allocator, qname)) |txt| {
                if (std.mem.indexOf(u8, txt, "DKIM1") != null or std.mem.indexOf(u8, txt, "p=") != null) {
                    dkim_txt = txt;
                    dkim_selector = selector;
                    break;
                } else {
                    allocator.free(txt);
                }
            } else |_| {}
        }

        // MTA-STS
        {
            const qname = std.fmt.allocPrint(allocator, "_mta-sts.{s}", .{domain}) catch continue;
            defer allocator.free(qname);
            mta_sts_txt = reports.ipinfo.queryTxt(allocator, qname) catch null;
        }

        // TLS-RPT
        {
            const qname = std.fmt.allocPrint(allocator, "_smtp._tls.{s}", .{domain}) catch continue;
            defer allocator.free(qname);
            tls_rpt_txt = reports.ipinfo.queryTxt(allocator, qname) catch null;
        }

        const dmarc_policy_weak = if (dmarc_txt) |t| reports.stats.isDmarcPolicyWeak(t) else false;
        const spf_weak = if (spf_txt) |t| reports.stats.isSpfWeak(t) else false;
        const has_dmarc = dmarc_txt != null;
        const has_spf = spf_txt != null;
        const has_dkim = dkim_txt != null;
        const dns_status = reports.stats.evaluateDnsStatus(has_dmarc, has_spf, has_dkim, dmarc_policy_weak, spf_weak);

        if (is_json) {
            if (!json_first) json_buf.appendSlice(allocator, ",") catch continue;
            json_first = false;

            const status_str = dns_status.label();
            const esc = reports.stats.jsonEscape;
            const dmarc_s = if (dmarc_txt) |t| esc(allocator, t) else "";
            defer if (dmarc_txt != null and dmarc_s.ptr != dmarc_txt.?.ptr) allocator.free(dmarc_s);
            const spf_s = if (spf_txt) |t| esc(allocator, t) else "";
            defer if (spf_txt != null and spf_s.ptr != spf_txt.?.ptr) allocator.free(spf_s);
            const dkim_s = if (dkim_txt) |t| esc(allocator, t) else "";
            defer if (dkim_txt != null and dkim_s.ptr != dkim_txt.?.ptr) allocator.free(dkim_s);
            const mta_s = if (mta_sts_txt) |t| esc(allocator, t) else "";
            defer if (mta_sts_txt != null and mta_s.ptr != mta_sts_txt.?.ptr) allocator.free(mta_s);
            const tls_s = if (tls_rpt_txt) |t| esc(allocator, t) else "";
            defer if (tls_rpt_txt != null and tls_s.ptr != tls_rpt_txt.?.ptr) allocator.free(tls_s);

            const line = std.fmt.allocPrint(allocator, "{{\"domain\":\"{s}\",\"status\":\"{s}\",\"dmarc\":\"{s}\",\"spf\":\"{s}\",\"dkim\":\"{s}\",\"dkim_selector\":\"{s}\",\"mta_sts\":\"{s}\",\"tls_rpt\":\"{s}\"}}", .{
                domain, status_str, dmarc_s, spf_s, dkim_s, dkim_selector, mta_s, tls_s,
            }) catch continue;
            defer allocator.free(line);
            json_buf.appendSlice(allocator, line) catch continue;
        } else {
            const icon = switch (dns_status) {
                .ok => icon_ok,
                .warning => icon_warning,
                .critical => icon_critical,
            };

            const hdr = std.fmt.bufPrint(&buf, " {s} {s}\n", .{ icon, domain }) catch "";
            ui.stdout_file.writeAll(hdr) catch {};

            // DMARC
            if (dmarc_txt) |txt| {
                const ci = if (dmarc_policy_weak) check_warning else check_ok;
                const msg = std.fmt.bufPrint(&buf, ui.branch_prefix ++ "{s} DMARC:   {s}\n", .{ ci, txt }) catch "";
                ui.stdout_file.writeAll(msg) catch {};
            } else {
                const msg = std.fmt.bufPrint(&buf, ui.branch_prefix ++ "{s} DMARC:   {s}\n", .{ check_critical, not_found }) catch "";
                ui.stdout_file.writeAll(msg) catch {};
            }

            // SPF
            if (spf_txt) |txt| {
                const ci = if (spf_weak) check_warning else check_ok;
                const msg = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "{s} SPF:     {s}\n", .{ ci, txt }) catch "";
                ui.stdout_file.writeAll(msg) catch {};
            } else {
                const msg = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "{s} SPF:     {s}\n", .{ check_critical, not_found }) catch "";
                ui.stdout_file.writeAll(msg) catch {};
            }

            // DKIM
            if (dkim_txt) |txt| {
                const trunc = if (txt.len > 60) txt[0..60] else txt;
                const msg = std.fmt.allocPrint(allocator, ui.detail_prefix ++ "{s} DKIM:    {s}... ({s}._domainkey)\n", .{ check_ok, trunc, dkim_selector }) catch continue;
                defer allocator.free(msg);
                ui.stdout_file.writeAll(msg) catch {};
            } else {
                const msg = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "{s} DKIM:    {s}\n", .{ check_critical, not_found }) catch "";
                ui.stdout_file.writeAll(msg) catch {};
            }

            // MTA-STS
            if (mta_sts_txt) |txt| {
                const msg = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "{s} MTA-STS: {s}\n", .{ check_ok, txt }) catch "";
                ui.stdout_file.writeAll(msg) catch {};
            } else {
                const msg = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "{s} MTA-STS: {s}\n", .{ check_critical, not_found }) catch "";
                ui.stdout_file.writeAll(msg) catch {};
            }

            // TLS-RPT
            if (tls_rpt_txt) |txt| {
                const msg = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "{s} TLS-RPT: {s}\n", .{ check_ok, txt }) catch "";
                ui.stdout_file.writeAll(msg) catch {};
            } else {
                const msg = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "{s} TLS-RPT: {s}\n", .{ check_critical, not_found }) catch "";
                ui.stdout_file.writeAll(msg) catch {};
            }

            ui.stdout_file.writeAll("\n") catch {};
        }
    }

    if (is_json) {
        json_buf.appendSlice(allocator, "]\n") catch {};
        ui.stdout_file.writeAll(json_buf.items) catch {};
    }
}

// --- Domains ---

pub fn cmdDomains(allocator: std.mem.Allocator, format: []const u8, account: ?[]const u8) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);

    const entries = try data.loadEntries(allocator, &cfg, account);
    defer reports.store.freeReportEntries(allocator, entries);

    var domain_set = std.StringHashMap(void).init(allocator);
    defer domain_set.deinit();

    for (entries) |e| {
        if (e.domain.len > 0) {
            domain_set.put(e.domain, {}) catch continue;
        }
    }

    var domains: std.ArrayList([]const u8) = .empty;
    defer domains.deinit(allocator);
    {
        var it = domain_set.iterator();
        while (it.next()) |kv| {
            domains.append(allocator, kv.key_ptr.*) catch continue;
        }
    }
    std.mem.sortUnstable([]const u8, domains.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    if (std.mem.eql(u8, format, "json")) {
        ui.stdout_file.writeAll("[") catch {};
        for (domains.items, 0..) |d, i| {
            if (i > 0) ui.stdout_file.writeAll(",") catch {};
            const entry = std.fmt.allocPrint(allocator, "\"{s}\"", .{d}) catch continue;
            defer allocator.free(entry);
            ui.stdout_file.writeAll(entry) catch {};
        }
        ui.stdout_file.writeAll("]\n") catch {};
    } else {
        for (domains.items) |d| {
            ui.stdout_file.writeAll(d) catch {};
            ui.stdout_file.writeAll("\n") catch {};
        }
    }
}

// --- Summary ---

pub fn cmdSummary(allocator: std.mem.Allocator, format: []const u8, domain: ?[]const u8, account: ?[]const u8, period: ?[]const u8) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);

    const entries = try data.loadEntries(allocator, &cfg, account);
    defer reports.store.freeReportEntries(allocator, entries);

    const filtered = try data.filterByDomain(allocator, entries, domain);
    defer allocator.free(filtered);

    if (period) |p| {
        if (!std.mem.eql(u8, p, "week") and !std.mem.eql(u8, p, "month") and !std.mem.eql(u8, p, "year")) {
            ui.stderr_file.writeAll("Invalid period: use week, month, or year\n") catch {};
            return;
        }
        try cmdSummaryByPeriod(allocator, &cfg, filtered, format, p);
    } else {
        try cmdSummaryTotal(allocator, &cfg, filtered, format);
    }
}

fn cmdSummaryTotal(allocator: std.mem.Allocator, cfg: *const Config, filtered: []const reports.store.ReportEntry, format: []const u8) !void {
    var stats: data.PeriodStats = .{};

    for (filtered) |entry| {
        const st = Store.init(allocator, cfg.data_dir, entry.account_name);
        switch (entry.report_type) {
            .dmarc => {
                stats.dmarc += 1;
                const report_data = st.loadDmarcReport(entry.filename) catch continue;
                defer allocator.free(report_data);
                data.accumulateDmarcStats(allocator, report_data, &stats.messages, &stats.pass, &stats.fail);
            },
            .tlsrpt => {
                stats.tlsrpt += 1;
            },
        }
    }

    var buf: [512]u8 = undefined;
    if (std.mem.eql(u8, format, "json")) {
        const msg = std.fmt.bufPrint(&buf,
            \\{{"dmarc_reports":{d},"tlsrpt_reports":{d},"messages_evaluated":{d},"dkim_spf_pass":{d},"dkim_spf_fail":{d}}}
            \\
        , .{ stats.dmarc, stats.tlsrpt, stats.messages, stats.pass, stats.fail }) catch return;
        ui.stdout_file.writeAll(msg) catch {};
    } else {
        ui.stdout_file.writeAll(ui.dim) catch {};
        const header = std.fmt.bufPrint(&buf, "{s:<12} {s:>6} {s:>8} {s:>10} {s:>8} {s:>8}\n", .{
            "PERIOD", "DMARC", "TLS-RPT", "MESSAGES", "PASS", "FAIL",
        }) catch return;
        ui.stdout_file.writeAll(header) catch {};
        const sep = std.fmt.bufPrint(&buf, "{s:-<12} {s:->6} {s:->8} {s:->10} {s:->8} {s:->8}\n", .{
            "", "", "", "", "", "",
        }) catch return;
        ui.stdout_file.writeAll(sep) catch {};
        ui.stdout_file.writeAll(ui.reset) catch {};
        const line = std.fmt.bufPrint(&buf, "{s:<12} {d:>6} {d:>8} {d:>10} {d:>8} {d:>8}\n", .{
            "All", stats.dmarc, stats.tlsrpt, stats.messages, stats.pass, stats.fail,
        }) catch return;
        ui.stdout_file.writeAll(line) catch {};
    }
}

fn cmdSummaryByPeriod(allocator: std.mem.Allocator, cfg: *const Config, filtered: []const reports.store.ReportEntry, format: []const u8, period: []const u8) !void {
    var period_map = std.StringHashMap(data.PeriodStats).init(allocator);
    defer {
        var it = period_map.iterator();
        while (it.next()) |kv| allocator.free(kv.key_ptr.*);
        period_map.deinit();
    }

    for (filtered) |entry| {
        const key = data.periodKey(allocator, entry.date_begin, period) catch continue;
        const gop = period_map.getOrPut(key) catch {
            allocator.free(key);
            continue;
        };
        if (gop.found_existing) {
            allocator.free(key);
        } else {
            gop.value_ptr.* = .{};
        }

        const st = Store.init(allocator, cfg.data_dir, entry.account_name);
        switch (entry.report_type) {
            .dmarc => {
                gop.value_ptr.dmarc += 1;
                const report_data = st.loadDmarcReport(entry.filename) catch continue;
                defer allocator.free(report_data);
                data.accumulateDmarcStats(allocator, report_data, &gop.value_ptr.messages, &gop.value_ptr.pass, &gop.value_ptr.fail);
            },
            .tlsrpt => {
                gop.value_ptr.tlsrpt += 1;
            },
        }
    }

    const keys = try allocator.alloc([]const u8, period_map.count());
    defer allocator.free(keys);
    {
        var it = period_map.iterator();
        var i: usize = 0;
        while (it.next()) |kv| {
            keys[i] = kv.key_ptr.*;
            i += 1;
        }
    }
    std.mem.sortUnstable([]const u8, keys, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .gt;
        }
    }.lessThan);

    if (std.mem.eql(u8, format, "json")) {
        try writePeriodJson(allocator, keys, &period_map);
    } else {
        try writePeriodTable(keys, &period_map);
    }
}

fn writePeriodJson(allocator: std.mem.Allocator, keys: []const []const u8, map: *const std.StringHashMap(data.PeriodStats)) !void {
    ui.stdout_file.writeAll("[") catch {};
    for (keys, 0..) |key, i| {
        if (i > 0) ui.stdout_file.writeAll(",") catch {};
        const s = map.get(key) orelse continue;
        const line = try std.fmt.allocPrint(allocator,
            \\
            \\  {{"period":"{s}","dmarc_reports":{d},"tlsrpt_reports":{d},"messages_evaluated":{d},"dkim_spf_pass":{d},"dkim_spf_fail":{d}}}
        , .{ key, s.dmarc, s.tlsrpt, s.messages, s.pass, s.fail });
        defer allocator.free(line);
        ui.stdout_file.writeAll(line) catch {};
    }
    ui.stdout_file.writeAll("\n]\n") catch {};
}

fn writePeriodTable(keys: []const []const u8, map: *const std.StringHashMap(data.PeriodStats)) !void {
    var buf: [512]u8 = undefined;
    ui.stdout_file.writeAll(ui.dim) catch {};
    const header = std.fmt.bufPrint(&buf, "{s:<12} {s:>6} {s:>8} {s:>10} {s:>8} {s:>8}\n", .{
        "PERIOD", "DMARC", "TLS-RPT", "MESSAGES", "PASS", "FAIL",
    }) catch return;
    ui.stdout_file.writeAll(header) catch {};

    const sep = std.fmt.bufPrint(&buf, "{s:-<12} {s:->6} {s:->8} {s:->10} {s:->8} {s:->8}\n", .{
        "", "", "", "", "", "",
    }) catch return;
    ui.stdout_file.writeAll(sep) catch {};
    ui.stdout_file.writeAll(ui.reset) catch {};

    for (keys) |key| {
        const s = map.get(key) orelse continue;
        const line = std.fmt.bufPrint(&buf, "{s:<12} {d:>6} {d:>8} {d:>10} {d:>8} {d:>8}\n", .{
            key, s.dmarc, s.tlsrpt, s.messages, s.pass, s.fail,
        }) catch continue;
        ui.stdout_file.writeAll(line) catch {};
    }
}

// --- Check ---

const CheckResult = struct {
    dmarc_reports: u64 = 0,
    dmarc_total: u64 = 0,
    dmarc_pass: u64 = 0,
    dmarc_fail: u64 = 0,
    dkim_only_fail: u64 = 0,
    spf_only_fail: u64 = 0,
    both_fail: u64 = 0,
    tls_reports: u64 = 0,
    tls_total_success: u64 = 0,
    tls_total_failure: u64 = 0,
    latest_date: []const u8 = "",
};

const CheckDmarcFailRecord = struct {
    account: []const u8,
    domain: []const u8,
    org: []const u8,
    source_ip: []const u8,
    count: u64,
    dkim: []const u8,
    spf: []const u8,
    header_from: []const u8,
};

const CheckTlsFailRecord = struct {
    account: []const u8,
    domain: []const u8,
    org: []const u8,
    policy_type: []const u8,
    result_type: []const u8,
    failed_count: u64,
    receiving_mx: []const u8,
};

const DmarcCheckJson = struct {
    records: []const struct {
        source_ip: []const u8 = "",
        count: u64 = 0,
        dkim_eval: []const u8 = "",
        spf_eval: []const u8 = "",
        header_from: []const u8 = "",
        disposition: []const u8 = "",
    } = &.{},
};

const TlsCheckJson = struct {
    organization_name: []const u8 = "",
    policies: []const struct {
        policy_type: []const u8 = "",
        policy_domain: []const u8 = "",
        total_successful: u64 = 0,
        total_failure: u64 = 0,
        failures: []const struct {
            result_type: []const u8 = "",
            sending_mta_ip: []const u8 = "",
            receiving_mx_hostname: []const u8 = "",
            failed_session_count: u64 = 0,
        } = &.{},
    } = &.{},
};

pub fn cmdCheck(
    allocator: std.mem.Allocator,
    domain_filter: ?[]const u8,
    account_filter: ?[]const u8,
    format: []const u8,
    threshold_str: ?[]const u8,
    max_age_str: ?[]const u8,
) !u8 {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);

    const entries = try data.loadEntries(allocator, &cfg, account_filter);
    defer reports.store.freeReportEntries(allocator, entries);

    const filtered = try data.filterByDomain(allocator, entries, domain_filter);
    defer allocator.free(filtered);

    const threshold: u64 = if (threshold_str) |s| std.fmt.parseInt(u64, s, 10) catch 0 else 0;
    const max_age: u64 = if (max_age_str) |s| std.fmt.parseInt(u64, s, 10) catch 7 else 7;

    var result = CheckResult{};
    var dmarc_fails: std.ArrayList(CheckDmarcFailRecord) = .empty;
    var tls_fails: std.ArrayList(CheckTlsFailRecord) = .empty;

    for (filtered) |entry| {
        if (entry.date_begin.len > 0) {
            if (result.latest_date.len == 0 or std.mem.order(u8, entry.date_begin, result.latest_date) == .gt) {
                result.latest_date = entry.date_begin;
            }
        }

        const st = Store.init(allocator, cfg.data_dir, entry.account_name);
        switch (entry.report_type) {
            .dmarc => {
                result.dmarc_reports += 1;
                const report_data = st.loadDmarcReport(entry.filename) catch continue;
                defer allocator.free(report_data);

                const parsed = std.json.parseFromSlice(DmarcCheckJson, allocator, report_data, .{
                    .ignore_unknown_fields = true,
                }) catch continue;
                defer parsed.deinit();

                for (parsed.value.records) |rec| {
                    result.dmarc_total += rec.count;
                    const dkim_pass = std.mem.eql(u8, rec.dkim_eval, "pass");
                    const spf_pass = std.mem.eql(u8, rec.spf_eval, "pass");
                    if (reports.stats.classifyFailure(dkim_pass, spf_pass)) |ft| {
                        switch (ft) {
                            .both_fail => result.both_fail += rec.count,
                            .dkim_only_fail => result.dkim_only_fail += rec.count,
                            .spf_only_fail => result.spf_only_fail += rec.count,
                        }
                        if (ft == .both_fail) {
                            result.dmarc_fail += rec.count;
                            dmarc_fails.append(allocator, .{
                                .account = entry.account_name,
                                .domain = entry.domain,
                                .org = entry.org_name,
                                .source_ip = allocator.dupe(u8, rec.source_ip) catch continue,
                                .count = rec.count,
                                .dkim = allocator.dupe(u8, rec.dkim_eval) catch continue,
                                .spf = allocator.dupe(u8, rec.spf_eval) catch continue,
                                .header_from = allocator.dupe(u8, rec.header_from) catch continue,
                            }) catch {};
                        } else {
                            result.dmarc_pass += rec.count;
                        }
                    } else {
                        result.dmarc_pass += rec.count;
                    }
                }
            },
            .tlsrpt => {
                result.tls_reports += 1;
                const report_data = st.loadTlsReport(entry.filename) catch continue;
                defer allocator.free(report_data);

                const parsed = std.json.parseFromSlice(TlsCheckJson, allocator, report_data, .{
                    .ignore_unknown_fields = true,
                }) catch continue;
                defer parsed.deinit();

                for (parsed.value.policies) |pol| {
                    result.tls_total_success += pol.total_successful;
                    result.tls_total_failure += pol.total_failure;
                    if (pol.total_failure > 0) {
                        for (pol.failures) |f| {
                            tls_fails.append(allocator, .{
                                .account = entry.account_name,
                                .domain = entry.domain,
                                .org = allocator.dupe(u8, parsed.value.organization_name) catch continue,
                                .policy_type = allocator.dupe(u8, pol.policy_type) catch continue,
                                .result_type = allocator.dupe(u8, f.result_type) catch continue,
                                .failed_count = f.failed_session_count,
                                .receiving_mx = allocator.dupe(u8, f.receiving_mx_hostname) catch continue,
                            }) catch {};
                        }
                    }
                }
            },
        }
    }

    const dmarc_fail_items = dmarc_fails.toOwnedSlice(allocator) catch &.{};
    defer {
        for (dmarc_fail_items) |f| {
            allocator.free(f.source_ip);
            allocator.free(f.dkim);
            allocator.free(f.spf);
            allocator.free(f.header_from);
        }
        if (dmarc_fail_items.len > 0) allocator.free(dmarc_fail_items);
    }
    const tls_fail_items = tls_fails.toOwnedSlice(allocator) catch &.{};
    defer {
        for (tls_fail_items) |f| {
            allocator.free(f.org);
            allocator.free(f.policy_type);
            allocator.free(f.result_type);
            allocator.free(f.receiving_mx);
        }
        if (tls_fail_items.len > 0) allocator.free(tls_fail_items);
    }

    var exit_code: u8 = 0;
    var stale = false;

    if (result.latest_date.len >= 10) {
        const age = data.dateAgeDays(result.latest_date) catch null;
        if (age) |days| {
            if (days > max_age) stale = true;
        }
    } else if (filtered.len == 0) {
        stale = true;
    }

    const dmarc_fail_rate: u64 = if (result.dmarc_total > 0) result.dmarc_fail * 100 / result.dmarc_total else 0;
    const dmarc_exceeded = dmarc_fail_rate > threshold;

    const tls_has_failures = result.tls_total_failure > 0;

    if (dmarc_exceeded or tls_has_failures) {
        exit_code = if (dmarc_fail_rate > 50) 2 else 1;
    }
    if (stale) {
        exit_code = @max(exit_code, 1);
    }

    const show_details = exit_code != 0;
    const dmarc_detail = if (show_details) dmarc_fail_items else &[_]CheckDmarcFailRecord{};
    const tls_detail = if (show_details) tls_fail_items else &[_]CheckTlsFailRecord{};
    if (std.mem.eql(u8, format, "json")) {
        try writeCheckJson(allocator, &result, dmarc_detail, tls_detail, dmarc_fail_rate, stale, exit_code);
    } else {
        try writeCheckText(&result, dmarc_detail, tls_detail, dmarc_fail_rate, stale, max_age, exit_code);
    }

    return exit_code;
}

fn writeCheckText(
    result: *const CheckResult,
    dmarc_fails: []const CheckDmarcFailRecord,
    tls_fails: []const CheckTlsFailRecord,
    dmarc_fail_rate: u64,
    stale: bool,
    max_age: u64,
    exit_code: u8,
) !void {
    const icon_ok = ui.neon_yellow ++ "●" ++ ui.reset;
    const icon_warning = ui.warn_yellow ++ "●" ++ ui.reset;
    const icon_critical = ui.fail_red ++ "●" ++ ui.reset;
    const fail_mark = ui.fail_red ++ "✗" ++ ui.reset;
    const warn_mark = ui.warn_yellow ++ "△" ++ ui.reset;

    var buf: [512]u8 = undefined;

    const status = if (exit_code == 0) "OK" else if (exit_code == 1) "WARNING" else "CRITICAL";
    const icon = if (exit_code == 0) icon_ok else if (exit_code == 1) icon_warning else icon_critical;
    ui.stdout_file.writeAll(" ") catch {};
    ui.stdout_file.writeAll(icon) catch {};
    const status_msg = std.fmt.bufPrint(&buf, " {s}: DMARC {d}/{d} messages failed ({d}%), TLS-RPT {d} failures\n", .{
        status, result.dmarc_fail, result.dmarc_total, dmarc_fail_rate, result.tls_total_failure,
    }) catch "";
    ui.stdout_file.writeAll(status_msg) catch {};

    if (result.dkim_only_fail > 0 or result.spf_only_fail > 0 or result.both_fail > 0) {
        ui.stdout_file.writeAll(ui.branch_prefix ++ fail_mark ++ "  Auth mechanism breakdown (single-mechanism fails still pass DMARC)\n") catch {};
        const breakdown = [_]struct { ft: reports.stats.FailureType, count: u64 }{
            .{ .ft = .both_fail, .count = result.both_fail },
            .{ .ft = .dkim_only_fail, .count = result.dkim_only_fail },
            .{ .ft = .spf_only_fail, .count = result.spf_only_fail },
        };
        for (breakdown) |b| {
            if (b.count > 0) {
                const msg = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "   {s}: {d} messages ({s})\n", .{ b.ft.label(), b.count, b.ft.hint() }) catch "";
                ui.stdout_file.writeAll(msg) catch {};
            }
        }
    }

    if (stale) {
        ui.stdout_file.writeAll("\n") catch {};
        ui.stdout_file.writeAll(ui.branch_prefix ++ warn_mark) catch {};
        const stale_msg = std.fmt.bufPrint(&buf, "  No reports received in the last {d} days (latest: {s})\n", .{
            max_age, if (result.latest_date.len > 0) result.latest_date else "none",
        }) catch "";
        ui.stdout_file.writeAll(stale_msg) catch {};
    }

    if (dmarc_fails.len > 0) {
        ui.stdout_file.writeAll("\n") catch {};
        ui.stdout_file.writeAll(ui.branch_prefix ++ fail_mark) catch {};
        const hdr = std.fmt.bufPrint(&buf, "  DMARC failures ({d} records)\n", .{dmarc_fails.len}) catch "";
        ui.stdout_file.writeAll(hdr) catch {};
        ui.stdout_file.writeAll(ui.detail_prefix ++ "   " ++ ui.dim ++ "SOURCE IP          COUNT  DKIM   SPF    DOMAIN               ORG" ++ ui.reset ++ "\n") catch {};
        ui.stdout_file.writeAll(ui.detail_prefix ++ "   " ++ ui.dim ++ "------------------ ------ ------ ------ -------------------- --------------------" ++ ui.reset ++ "\n") catch {};

        const limit = @min(dmarc_fails.len, 20);
        for (dmarc_fails[0..limit]) |f| {
            var lbuf: [256]u8 = undefined;
            const line = std.fmt.bufPrint(&lbuf, ui.detail_prefix ++ "   {s:<18} {d:>6} {s:<6} {s:<6} {s:<20} {s}\n", .{
                ui.truncate(f.source_ip, 18), f.count, ui.truncate(f.dkim, 6), ui.truncate(f.spf, 6),
                ui.truncate(f.domain, 20), ui.truncate(f.org, 20),
            }) catch continue;
            ui.stdout_file.writeAll(line) catch {};
        }
        if (dmarc_fails.len > 20) {
            const more = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "   " ++ ui.dim ++ "... and {d} more" ++ ui.reset ++ "\n", .{dmarc_fails.len - 20}) catch "";
            ui.stdout_file.writeAll(more) catch {};
        }
    }

    if (tls_fails.len > 0) {
        ui.stdout_file.writeAll("\n") catch {};
        ui.stdout_file.writeAll(ui.branch_prefix ++ fail_mark) catch {};
        const hdr = std.fmt.bufPrint(&buf, "  TLS-RPT failures ({d} records)\n", .{tls_fails.len}) catch "";
        ui.stdout_file.writeAll(hdr) catch {};
        ui.stdout_file.writeAll(ui.detail_prefix ++ "   " ++ ui.dim ++ "RESULT TYPE                  COUNT  RECEIVING MX                 DOMAIN" ++ ui.reset ++ "\n") catch {};
        ui.stdout_file.writeAll(ui.detail_prefix ++ "   " ++ ui.dim ++ "---------------------------- ------ ---------------------------- --------------------" ++ ui.reset ++ "\n") catch {};

        const limit = @min(tls_fails.len, 20);
        for (tls_fails[0..limit]) |f| {
            var lbuf: [256]u8 = undefined;
            const line = std.fmt.bufPrint(&lbuf, ui.detail_prefix ++ "   {s:<28} {d:>6} {s:<28} {s}\n", .{
                ui.truncate(f.result_type, 28), f.failed_count, ui.truncate(f.receiving_mx, 28),
                ui.truncate(f.domain, 20),
            }) catch continue;
            ui.stdout_file.writeAll(line) catch {};
        }
        if (tls_fails.len > 20) {
            const more = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "   " ++ ui.dim ++ "... and {d} more" ++ ui.reset ++ "\n", .{tls_fails.len - 20}) catch "";
            ui.stdout_file.writeAll(more) catch {};
        }
    }
}

fn writeCheckJson(
    allocator: std.mem.Allocator,
    result: *const CheckResult,
    dmarc_fails: []const CheckDmarcFailRecord,
    tls_fails: []const CheckTlsFailRecord,
    dmarc_fail_rate: u64,
    stale: bool,
    exit_code: u8,
) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    const status = if (exit_code == 0) "ok" else if (exit_code == 1) "warning" else "critical";

    const header = try std.fmt.allocPrint(allocator,
        \\{{"status":"{s}","exit_code":{d},"stale":{s},
    , .{ status, exit_code, if (stale) "true" else "false" });
    defer allocator.free(header);
    try buf.appendSlice(allocator, header);

    const dmarc_part = try std.fmt.allocPrint(allocator,
        \\"dmarc":{{"reports":{d},"total":{d},"pass":{d},"fail":{d},"fail_rate":{d},"dkim_only_fail":{d},"spf_only_fail":{d},"both_fail":{d}}},
    , .{ result.dmarc_reports, result.dmarc_total, result.dmarc_pass, result.dmarc_fail, dmarc_fail_rate, result.dkim_only_fail, result.spf_only_fail, result.both_fail });
    defer allocator.free(dmarc_part);
    try buf.appendSlice(allocator, dmarc_part);

    const tls_part = try std.fmt.allocPrint(allocator,
        \\"tls_rpt":{{"reports":{d},"success":{d},"failure":{d}}},
    , .{ result.tls_reports, result.tls_total_success, result.tls_total_failure });
    defer allocator.free(tls_part);
    try buf.appendSlice(allocator, tls_part);

    try buf.appendSlice(allocator, "\"dmarc_failures\":[");
    for (dmarc_fails, 0..) |f, i| {
        if (i > 0) try buf.appendSlice(allocator, ",");
        const item = try std.fmt.allocPrint(allocator,
            \\{{"source_ip":"{s}","count":{d},"dkim":"{s}","spf":"{s}","domain":"{s}","org":"{s}"}}
        , .{ f.source_ip, f.count, f.dkim, f.spf, f.domain, f.org });
        defer allocator.free(item);
        try buf.appendSlice(allocator, item);
    }
    try buf.appendSlice(allocator, "],");

    try buf.appendSlice(allocator, "\"tls_failures\":[");
    for (tls_fails, 0..) |f, i| {
        if (i > 0) try buf.appendSlice(allocator, ",");
        const item = try std.fmt.allocPrint(allocator,
            \\{{"result_type":"{s}","failed_count":{d},"receiving_mx":"{s}","domain":"{s}","org":"{s}"}}
        , .{ f.result_type, f.failed_count, f.receiving_mx, f.domain, f.org });
        defer allocator.free(item);
        try buf.appendSlice(allocator, item);
    }

    const latest = try std.fmt.allocPrint(allocator,
        \\],"latest_report":"{s}"}}
    , .{result.latest_date});
    defer allocator.free(latest);
    try buf.appendSlice(allocator, latest);
    try buf.append(allocator, '\n');

    ui.stdout_file.writeAll(buf.items[0..buf.items.len]) catch {};
}
