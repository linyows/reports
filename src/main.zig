const std = @import("std");
const reports = @import("reports");
const build_options = @import("build_options");

const Config = reports.config.Config;
const Store = reports.store.Store;

const stdout_file = std.fs.File.stdout();
const stderr_file = std.fs.File.stderr();

const logo_text = @embedFile("assets/logo.txt");
const desc_text = @embedFile("assets/desc.txt");

const neon_yellow = "\x1b[38;2;194;255;38m";
const dim = "\x1b[2m";
const reset = "\x1b[0m";

pub fn main() !void {
    var gpa_impl: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa_impl.deinit();
    const allocator = gpa_impl.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];
    const account = getOption(args, "--account");
    const format = getOption(args, "--format");
    const domain = getOption(args, "--domain");
    const period = getOption(args, "--period");
    const report_type = getOption(args, "--type");
    const enrich = !hasFlag(args, "--no-enrich");

    if (std.mem.eql(u8, command, "fetch")) {
        try cmdFetch(allocator, account);
    } else if (std.mem.eql(u8, command, "list")) {
        try cmdList(allocator, format orelse "table", domain, account, report_type);
    } else if (std.mem.eql(u8, command, "show")) {
        if (args.len < 3 or std.mem.startsWith(u8, args[2], "--")) {
            stderr_file.writeAll("Usage: reports show <report-id>\n") catch {};
            return;
        }
        try cmdShow(allocator, args[2], format orelse "table", enrich);
    } else if (std.mem.eql(u8, command, "domains")) {
        try cmdDomains(allocator, format orelse "table", account);
    } else if (std.mem.eql(u8, command, "summary")) {
        try cmdSummary(allocator, format orelse "json", domain, account, period);
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsage();
    } else if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-v")) {
        printVersion();
    } else {
        stderr_file.writeAll("Unknown command: ") catch {};
        stderr_file.writeAll(command) catch {};
        stderr_file.writeAll("\n") catch {};
        printUsage();
    }
}

fn cmdFetch(allocator: std.mem.Allocator, account_filter: ?[]const u8) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);

    reports.store.migrateToAccountDirs(cfg.data_dir);
    try cfg.ensureDataDir();

    if (cfg.accounts.len == 0) {
        stderr_file.writeAll("No accounts configured. Edit ~/.config/reports/config.json\n") catch {};
        return;
    }

    reports.imap.globalInit();
    defer reports.imap.globalCleanup();

    for (cfg.accounts) |acct| {
        if (account_filter) |filter| {
            if (!std.mem.eql(u8, acct.name, filter)) continue;
        }

        if (acct.host.len == 0) continue;

        {
            var buf: [128]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "\nAccount: {s}\n", .{acct.name}) catch "";
            stdout_file.writeAll(msg) catch {};
        }

        const result = fetchForAccount(allocator, &acct, cfg.data_dir);

        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "Fetched {d} DMARC and {d} TLS-RPT reports.\n", .{
            result.dmarc, result.tls,
        }) catch "Done.\n";
        stdout_file.writeAll(msg) catch {};
    }
}

fn fetchForAccount(allocator: std.mem.Allocator, acct: *const Config.Account, data_dir: []const u8) struct { dmarc: u32, tls: u32 } {
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
        stderr_file.writeAll(msg) catch {};
        return .{ .dmarc = 0, .tls = 0 };
    };
    defer client.deinit();

    const st = Store.init(allocator, data_dir, acct.name);

    var fetched_set = st.loadFetchedUids() catch std.AutoHashMap(u32, void).init(allocator);
    defer fetched_set.deinit();

    stdout_file.writeAll("Searching for report messages...\n") catch {};
    const uids = client.searchReports() catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "IMAP search failed: {s}\n", .{@errorName(err)}) catch "IMAP search failed\n";
        stderr_file.writeAll(msg) catch {};
        return .{ .dmarc = 0, .tls = 0 };
    };
    defer allocator.free(uids);

    var new_count: usize = 0;
    for (uids) |uid| {
        if (!fetched_set.contains(uid)) new_count += 1;
    }

    {
        var buf: [128]u8 = undefined;
        const found_msg = std.fmt.bufPrint(&buf, "Found {d} messages ({d} new). Fetching...\n", .{ uids.len, new_count }) catch "Fetching...\n";
        stdout_file.writeAll(found_msg) catch {};
    }

    var dmarc_count: u32 = 0;
    var tls_count: u32 = 0;
    var progress: usize = 0;
    for (uids) |uid| {
        if (fetched_set.contains(uid)) continue;
        progress += 1;
        {
            var pbuf: [64]u8 = undefined;
            const prog = std.fmt.bufPrint(&pbuf, "\r  [{d}/{d}]", .{ progress, new_count }) catch "";
            stderr_file.writeAll(prog) catch {};
        }
        const raw = client.fetchMessage(uid) catch continue;
        defer allocator.free(raw);

        const attachments = reports.mime.extractAttachments(allocator, raw) catch continue;
        defer {
            for (attachments) |att| {
                allocator.free(att.filename);
                allocator.free(att.content_type);
                allocator.free(att.data);
            }
            allocator.free(attachments);
        }

        var saved = false;
        for (attachments) |att| {
            const decompressed = reports.mime.decompress(allocator, att.data, att.filename) catch continue;
            defer allocator.free(decompressed);

            // Try TLS-RPT first (by content-type or JSON parse), then DMARC (XML parse)
            if (isTlsrptContentType(att.content_type)) {
                const report = reports.mtasts.parseJson(allocator, decompressed) catch continue;
                defer report.deinit(allocator);
                st.saveTlsReport(&report) catch continue;
                tls_count += 1;
                saved = true;
            } else if (reports.mtasts.parseJson(allocator, decompressed)) |report| {
                report.deinit(allocator);
                st.saveTlsReport(&report) catch continue;
                tls_count += 1;
                saved = true;
            } else |_| {
                const report = reports.dmarc.parseXml(allocator, decompressed) catch continue;
                defer report.deinit(allocator);
                st.saveDmarcReport(&report) catch continue;
                dmarc_count += 1;
                saved = true;
            }
        }
        if (saved) {
            st.markUidFetched(uid);
            fetched_set.put(uid, {}) catch {};
        }
    }
    if (new_count > 0) stderr_file.writeAll("\n") catch {};

    return .{ .dmarc = dmarc_count, .tls = tls_count };
}

fn cmdDomains(allocator: std.mem.Allocator, format: []const u8, account: ?[]const u8) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);

    const entries = try loadEntries(allocator, &cfg, account);
    defer reports.store.freeReportEntries(allocator, entries);

    // Collect unique domains
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
        stdout_file.writeAll("[") catch {};
        for (domains.items, 0..) |d, i| {
            if (i > 0) stdout_file.writeAll(",") catch {};
            const entry = std.fmt.allocPrint(allocator, "\"{s}\"", .{d}) catch continue;
            defer allocator.free(entry);
            stdout_file.writeAll(entry) catch {};
        }
        stdout_file.writeAll("]\n") catch {};
    } else {
        for (domains.items) |d| {
            stdout_file.writeAll(d) catch {};
            stdout_file.writeAll("\n") catch {};
        }
    }
}

fn cmdList(allocator: std.mem.Allocator, format: []const u8, domain: ?[]const u8, account: ?[]const u8, report_type: ?[]const u8) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);

    const entries = try loadEntries(allocator, &cfg, account);
    defer reports.store.freeReportEntries(allocator, entries);

    const by_domain = try filterByDomain(allocator, entries, domain);
    defer allocator.free(by_domain);

    const filtered = try filterByType(allocator, by_domain, report_type);
    defer allocator.free(filtered);

    if (std.mem.eql(u8, format, "json")) {
        try writeJsonList(allocator, filtered);
    } else {
        try writeTableList(allocator, filtered);
    }
}

fn cmdShow(allocator: std.mem.Allocator, report_id: []const u8, format: []const u8, enrich: bool) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);

    const entries = try loadEntries(allocator, &cfg, null);
    defer reports.store.freeReportEntries(allocator, entries);

    for (entries) |entry| {
        const hash_id = filenameToHashId(entry.filename);
        if (std.mem.indexOf(u8, hash_id, report_id) != null or
            std.mem.indexOf(u8, entry.report_id, report_id) != null or
            std.mem.indexOf(u8, entry.filename, report_id) != null)
        {
            const st = Store.init(allocator, cfg.data_dir, entry.account_name);
            switch (entry.report_type) {
                .dmarc => {
                    const data = try st.loadDmarcReport(entry.filename);
                    defer allocator.free(data);

                    if (std.mem.eql(u8, format, "json")) {
                        stdout_file.writeAll(data) catch {};
                        stdout_file.writeAll("\n") catch {};
                    } else {
                        try showDmarcTable(allocator, data, enrich);
                    }
                },
                .tlsrpt => {
                    const data = try st.loadTlsReport(entry.filename);
                    defer allocator.free(data);

                    if (std.mem.eql(u8, format, "json")) {
                        stdout_file.writeAll(data) catch {};
                        stdout_file.writeAll("\n") catch {};
                    } else {
                        try showTlsTable(allocator, data, enrich);
                    }
                },
            }
            return;
        }
    }

    stderr_file.writeAll("Report not found: ") catch {};
    stderr_file.writeAll(report_id) catch {};
    stderr_file.writeAll("\n") catch {};
}

const PeriodStats = struct {
    dmarc: u32 = 0,
    tlsrpt: u32 = 0,
    messages: u64 = 0,
    pass: u64 = 0,
    fail: u64 = 0,
};

fn cmdSummary(allocator: std.mem.Allocator, format: []const u8, domain: ?[]const u8, account: ?[]const u8, period: ?[]const u8) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);

    const entries = try loadEntries(allocator, &cfg, account);
    defer reports.store.freeReportEntries(allocator, entries);

    const filtered = try filterByDomain(allocator, entries, domain);
    defer allocator.free(filtered);

    if (period) |p| {
        if (!std.mem.eql(u8, p, "week") and !std.mem.eql(u8, p, "month") and !std.mem.eql(u8, p, "year")) {
            stderr_file.writeAll("Invalid period: use week, month, or year\n") catch {};
            return;
        }
        try cmdSummaryByPeriod(allocator, &cfg, filtered, format, p);
    } else {
        try cmdSummaryTotal(allocator, &cfg, filtered, format);
    }
}

fn cmdSummaryTotal(allocator: std.mem.Allocator, cfg: *const Config, filtered: []const reports.store.ReportEntry, format: []const u8) !void {
    var stats: PeriodStats = .{};

    for (filtered) |entry| {
        const st = Store.init(allocator, cfg.data_dir, entry.account_name);
        switch (entry.report_type) {
            .dmarc => {
                stats.dmarc += 1;
                const data = st.loadDmarcReport(entry.filename) catch continue;
                defer allocator.free(data);
                accumulateDmarcStats(allocator, data, &stats.messages, &stats.pass, &stats.fail);
            },
            .tlsrpt => {
                stats.tlsrpt += 1;
            },
        }
    }

    var buf: [512]u8 = undefined;
    if (std.mem.eql(u8, format, "json")) {
        const msg = std.fmt.bufPrint(&buf,
            \\{{"dmarc_reports":{d},"tlsrpt_reports":{d},"total_messages":{d},"dkim_spf_pass":{d},"dkim_spf_fail":{d}}}
            \\
        , .{ stats.dmarc, stats.tlsrpt, stats.messages, stats.pass, stats.fail }) catch return;
        stdout_file.writeAll(msg) catch {};
    } else {
        const labels = [_]struct { label: []const u8, value: u64 }{
            .{ .label = "DMARC Reports:    ", .value = stats.dmarc },
            .{ .label = "TLS-RPT Reports:  ", .value = stats.tlsrpt },
            .{ .label = "Total Messages:   ", .value = stats.messages },
            .{ .label = "DKIM/SPF Pass:    ", .value = stats.pass },
            .{ .label = "DKIM/SPF Fail:    ", .value = stats.fail },
        };
        for (labels) |entry| {
            const msg = std.fmt.bufPrint(&buf, "{s}{d}\n", .{ entry.label, entry.value }) catch continue;
            stdout_file.writeAll(msg) catch {};
        }
    }
}

fn cmdSummaryByPeriod(allocator: std.mem.Allocator, cfg: *const Config, filtered: []const reports.store.ReportEntry, format: []const u8, period: []const u8) !void {
    var period_map = std.StringHashMap(PeriodStats).init(allocator);
    defer {
        var it = period_map.iterator();
        while (it.next()) |kv| allocator.free(kv.key_ptr.*);
        period_map.deinit();
    }

    for (filtered) |entry| {
        const key = periodKey(allocator, entry.date_begin, period) catch continue;
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
                const data = st.loadDmarcReport(entry.filename) catch continue;
                defer allocator.free(data);
                accumulateDmarcStats(allocator, data, &gop.value_ptr.messages, &gop.value_ptr.pass, &gop.value_ptr.fail);
            },
            .tlsrpt => {
                gop.value_ptr.tlsrpt += 1;
            },
        }
    }

    // Collect and sort keys
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

fn periodKey(allocator: std.mem.Allocator, date_begin: []const u8, period: []const u8) ![]u8 {
    // date_begin format: "YYYY-MM-DD HH:MM"
    if (date_begin.len < 10) return error.InvalidDate;

    if (std.mem.eql(u8, period, "year")) {
        return try allocator.dupe(u8, date_begin[0..4]);
    } else if (std.mem.eql(u8, period, "month")) {
        return try allocator.dupe(u8, date_begin[0..7]);
    } else {
        // week: compute ISO week from YYYY-MM-DD
        const year = std.fmt.parseInt(u16, date_begin[0..4], 10) catch return error.InvalidDate;
        const month = std.fmt.parseInt(u8, date_begin[5..7], 10) catch return error.InvalidDate;
        const day = std.fmt.parseInt(u8, date_begin[8..10], 10) catch return error.InvalidDate;
        if (month < 1 or month > 12 or day < 1 or day > 31) return error.InvalidDate;
        const wk = isoWeek(year, month, day);
        return std.fmt.allocPrint(allocator, "{d:0>4}-W{d:0>2}", .{ wk.year, wk.week });
    }
}

fn isoWeek(year: u16, month: u8, day: u8) struct { year: u16, week: u8 } {
    // Day of week: 1=Monday ... 7=Sunday (ISO)
    const dow = dayOfWeek(year, month, day);
    // Ordinal day of year
    const yday = dayOfYear(year, month, day);
    // ISO week calculation: find Thursday of the same week
    // Thursday's ordinal = yday + (4 - dow)
    const thu_yday: i32 = @as(i32, @intCast(yday)) + 4 - @as(i32, @intCast(dow));

    if (thu_yday < 1) {
        // Thursday is in the previous year
        const prev_year = year - 1;
        const prev_days: u16 = if (isLeapYear(prev_year)) 366 else 365;
        const adj_thu: u16 = @intCast(@as(i32, @intCast(prev_days)) + thu_yday);
        const wk: u8 = @intCast((adj_thu - 1) / 7 + 1);
        return .{ .year = prev_year, .week = wk };
    }

    const days_in_year: u16 = if (isLeapYear(year)) 366 else 365;
    if (thu_yday > days_in_year) {
        // Thursday is in the next year
        return .{ .year = year + 1, .week = 1 };
    }

    const wk: u8 = @intCast((@as(u16, @intCast(thu_yday)) - 1) / 7 + 1);
    return .{ .year = year, .week = wk };
}

fn dayOfWeek(year: u16, month: u8, day: u8) u8 {
    // Tomohiko Sakamoto's algorithm: returns 0=Sunday..6=Saturday
    const t = [_]u8{ 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4 };
    var y: i32 = @intCast(year);
    if (month < 3) y -= 1;
    const uy: u32 = @intCast(y);
    const r: u32 = (uy + uy / 4 - uy / 100 + uy / 400 + t[month - 1] + day) % 7;
    // Convert to ISO: 1=Monday..7=Sunday
    if (r == 0) return 7;
    return @intCast(r);
}

fn dayOfYear(year: u16, month: u8, day: u8) u16 {
    const days_before = [_]u16{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
    var d: u16 = days_before[month - 1] + day;
    if (month > 2 and isLeapYear(year)) d += 1;
    return d;
}

fn isLeapYear(year: u16) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}

fn writePeriodJson(allocator: std.mem.Allocator, keys: []const []const u8, map: *const std.StringHashMap(PeriodStats)) !void {
    stdout_file.writeAll("[") catch {};
    for (keys, 0..) |key, i| {
        if (i > 0) stdout_file.writeAll(",") catch {};
        const s = map.get(key) orelse continue;
        const line = try std.fmt.allocPrint(allocator,
            \\
            \\  {{"period":"{s}","dmarc_reports":{d},"tlsrpt_reports":{d},"total_messages":{d},"dkim_spf_pass":{d},"dkim_spf_fail":{d}}}
        , .{ key, s.dmarc, s.tlsrpt, s.messages, s.pass, s.fail });
        defer allocator.free(line);
        stdout_file.writeAll(line) catch {};
    }
    stdout_file.writeAll("\n]\n") catch {};
}

fn writePeriodTable(keys: []const []const u8, map: *const std.StringHashMap(PeriodStats)) !void {
    var buf: [512]u8 = undefined;
    const header = std.fmt.bufPrint(&buf, "{s:<12} {s:>6} {s:>8} {s:>10} {s:>8} {s:>8}\n", .{
        "PERIOD", "DMARC", "TLS-RPT", "MESSAGES", "PASS", "FAIL",
    }) catch return;
    stdout_file.writeAll(header) catch {};

    const sep = std.fmt.bufPrint(&buf, "{s:-<12} {s:->6} {s:->8} {s:->10} {s:->8} {s:->8}\n", .{
        "", "", "", "", "", "",
    }) catch return;
    stdout_file.writeAll(sep) catch {};

    for (keys) |key| {
        const s = map.get(key) orelse continue;
        const line = std.fmt.bufPrint(&buf, "{s:<12} {d:>6} {d:>8} {d:>10} {d:>8} {d:>8}\n", .{
            key, s.dmarc, s.tlsrpt, s.messages, s.pass, s.fail,
        }) catch continue;
        stdout_file.writeAll(line) catch {};
    }
}

fn loadEntries(allocator: std.mem.Allocator, cfg: *const Config, account: ?[]const u8) ![]reports.store.ReportEntry {
    reports.store.migrateToAccountDirs(cfg.data_dir);
    if (account) |name| {
        const st = Store.init(allocator, cfg.data_dir, name);
        return st.listReports();
    }
    const names = try cfg.accountNames(allocator);
    defer allocator.free(names);
    return reports.store.listAllReports(allocator, cfg.data_dir, names);
}

fn accumulateDmarcStats(allocator: std.mem.Allocator, data: []const u8, total: *u64, pass: *u64, fail: *u64) void {
    const parsed = std.json.parseFromSlice(DmarcStatsJson, allocator, data, .{
        .ignore_unknown_fields = true,
    }) catch return;
    defer parsed.deinit();

    for (parsed.value.records) |rec| {
        total.* += rec.count;
        if (std.mem.eql(u8, rec.dkim_eval, "pass") or std.mem.eql(u8, rec.spf_eval, "pass")) {
            pass.* += rec.count;
        } else {
            fail.* += rec.count;
        }
    }
}

fn filterByDomain(allocator: std.mem.Allocator, entries: []const reports.store.ReportEntry, domain: ?[]const u8) ![]const reports.store.ReportEntry {
    const filter = domain orelse return try allocator.dupe(reports.store.ReportEntry, entries);

    var result: std.ArrayList(reports.store.ReportEntry) = .empty;
    for (entries) |e| {
        if (std.mem.eql(u8, e.domain, filter)) {
            try result.append(allocator, e);
        }
    }
    return result.toOwnedSlice(allocator);
}

fn filterByType(allocator: std.mem.Allocator, entries: []const reports.store.ReportEntry, type_filter: ?[]const u8) ![]const reports.store.ReportEntry {
    const filter = type_filter orelse return try allocator.dupe(reports.store.ReportEntry, entries);

    const target: reports.store.ReportType = if (std.mem.eql(u8, filter, "dmarc"))
        .dmarc
    else if (std.mem.eql(u8, filter, "tlsrpt") or std.mem.eql(u8, filter, "tls-rpt") or std.mem.eql(u8, filter, "tls"))
        .tlsrpt
    else
        return try allocator.dupe(reports.store.ReportEntry, entries);

    var result: std.ArrayList(reports.store.ReportEntry) = .empty;
    for (entries) |e| {
        if (e.report_type == target) {
            try result.append(allocator, e);
        }
    }
    return result.toOwnedSlice(allocator);
}

const DmarcStatsJson = struct {
    records: []const struct {
        count: u64 = 0,
        dkim_eval: []const u8 = "",
        spf_eval: []const u8 = "",
    } = &.{},
};

fn writeTableList(allocator: std.mem.Allocator, entries: []const reports.store.ReportEntry) !void {
    _ = allocator;
    var buf: [512]u8 = undefined;

    const header = std.fmt.bufPrint(&buf, "{s:<16} {s:<10} {s:<8} {s:<17} {s:<20} {s:<18} {s:<10}\n", .{
        "ID", "ACCOUNT", "TYPE", "DATE", "DOMAIN", "ORGANIZATION", "POLICY",
    }) catch return;
    stdout_file.writeAll(header) catch {};

    const sep = std.fmt.bufPrint(&buf, "{s:-<16} {s:-<10} {s:-<8} {s:-<17} {s:-<20} {s:-<18} {s:-<10}\n", .{
        "", "", "", "", "", "", "",
    }) catch return;
    stdout_file.writeAll(sep) catch {};

    for (entries) |e| {
        const type_str: []const u8 = switch (e.report_type) {
            .dmarc => "DMARC",
            .tlsrpt => "TLS-RPT",
        };
        const hash_id = filenameToHashId(e.filename);
        const line = std.fmt.bufPrint(&buf, "{s:<16} {s:<10} {s:<8} {s:<17} {s:<20} {s:<18} {s:<10}\n", .{
            hash_id,
            truncate(e.account_name, 9),
            type_str,
            truncate(e.date_begin, 16),
            truncate(e.domain, 19),
            truncate(e.org_name, 17),
            truncate(e.policy, 9),
        }) catch continue;
        stdout_file.writeAll(line) catch {};
    }
}

fn writeJsonList(allocator: std.mem.Allocator, entries: []const reports.store.ReportEntry) !void {
    stdout_file.writeAll("[") catch {};
    for (entries, 0..) |e, i| {
        if (i > 0) stdout_file.writeAll(",") catch {};
        const type_str: []const u8 = switch (e.report_type) {
            .dmarc => "dmarc",
            .tlsrpt => "tlsrpt",
        };
        const hash_id = filenameToHashId(e.filename);
        const json_entry = try std.fmt.allocPrint(allocator, "\n  {{\"account\":\"{s}\",\"type\":\"{s}\",\"org\":\"{s}\",\"id\":\"{s}\",\"date\":\"{s}\",\"domain\":\"{s}\",\"policy\":\"{s}\",\"filename\":\"{s}\"}}", .{
            e.account_name, type_str, e.org_name, hash_id, e.date_begin, e.domain, e.policy, e.filename,
        });
        defer allocator.free(json_entry);
        stdout_file.writeAll(json_entry) catch {};
    }
    stdout_file.writeAll("\n]\n") catch {};
}

fn showDmarcTable(allocator: std.mem.Allocator, data: []const u8, enrich: bool) !void {
    const parsed = try std.json.parseFromSlice(DmarcDetailJson, allocator, data, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const r = parsed.value;

    var buf: [512]u8 = undefined;

    for ([_]struct { label: []const u8, value: []const u8 }{
        .{ .label = "Organization: ", .value = r.metadata.org_name },
        .{ .label = "Report ID:    ", .value = r.metadata.report_id },
        .{ .label = "Domain:       ", .value = r.policy.domain },
        .{ .label = "Policy:       ", .value = r.policy.policy },
    }) |item| {
        stdout_file.writeAll(item.label) catch {};
        stdout_file.writeAll(item.value) catch {};
        stdout_file.writeAll("\n") catch {};
    }
    stdout_file.writeAll("\n") catch {};

    const header = std.fmt.bufPrint(&buf, "{s:<16} {s:<6} {s:<12} {s:<25} {s:<25} {s:<6} {s:<6}\n", .{
        "SOURCE IP", "COUNT", "DISPOSITION", "ENVELOPE FROM", "HEADER FROM", "DKIM", "SPF",
    }) catch return;
    stdout_file.writeAll(header) catch {};

    const sep = std.fmt.bufPrint(&buf, "{s:-<16} {s:-<6} {s:-<12} {s:-<25} {s:-<25} {s:-<6} {s:-<6}\n", .{
        "", "", "", "", "", "", "",
    }) catch return;
    stdout_file.writeAll(sep) catch {};

    // Cache enrichment results to avoid duplicate DNS lookups
    var ip_cache = std.StringHashMap(CachedIpInfo).init(allocator);
    defer {
        var it = ip_cache.valueIterator();
        while (it.next()) |v| v.deinit(allocator);
        ip_cache.deinit();
    }

    for (r.records) |rec| {
        const line = std.fmt.bufPrint(&buf, "{s:<16} {d:<6} {s:<12} {s:<25} {s:<25} {s:<6} {s:<6}\n", .{
            truncate(rec.source_ip, 15),
            rec.count,
            truncate(rec.disposition, 11),
            truncate(rec.envelope_from, 24),
            truncate(rec.header_from, 24),
            truncate(rec.dkim_eval, 5),
            truncate(rec.spf_eval, 5),
        }) catch continue;
        stdout_file.writeAll(line) catch {};

        if (enrich) {
            const cached = lookupCached(allocator, &ip_cache, rec.source_ip);
            writeEnrichLine(&buf, cached, rec.source_ip);
        }
    }
}

const CachedIpInfo = struct {
    ptr: []const u8,
    asn: []const u8,
    asn_org: []const u8,
    country: []const u8,

    fn deinit(self: *const CachedIpInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.ptr);
        allocator.free(self.asn);
        allocator.free(self.asn_org);
        allocator.free(self.country);
    }
};

fn lookupCached(allocator: std.mem.Allocator, cache: *std.StringHashMap(CachedIpInfo), ip: []const u8) *const CachedIpInfo {
    if (cache.getPtr(ip)) |existing| return existing;

    const info = reports.ipinfo.lookup(allocator, ip);
    // Ownership of info's allocated fields transfers to the cache entry.
    // On put failure, we must free them explicitly since info won't be deinit'd.
    const entry = CachedIpInfo{
        .ptr = info.ptr,
        .asn = info.asn,
        .asn_org = info.asn_org,
        .country = info.country,
    };
    // The IP key comes from the parsed JSON data, which lives for the
    // duration of the cache (same scope in showDmarcTable).
    cache.put(ip, entry) catch {
        // put failed — free the allocated strings that would have been owned by the cache
        entry.deinit(allocator);
        const S = struct {
            const empty = CachedIpInfo{ .ptr = "", .asn = "", .asn_org = "", .country = "" };
        };
        return &S.empty;
    };
    return cache.getPtr(ip).?;
}

fn writeEnrichLine(buf: *[512]u8, info: *const CachedIpInfo, source_ip: []const u8) void {
    stdout_file.writeAll(dim) catch {};
    stdout_file.writeAll("  \xe2\x86\x92 ") catch {}; // " → " (UTF-8 arrow)

    if (info.ptr.len > 0 and !std.mem.eql(u8, info.ptr, source_ip)) {
        stdout_file.writeAll(info.ptr) catch {};
    } else {
        stdout_file.writeAll("(no PTR)") catch {};
    }

    if (info.asn.len > 0) {
        const asn_part = std.fmt.bufPrint(buf, " | AS{s}", .{info.asn}) catch "";
        stdout_file.writeAll(asn_part) catch {};
        if (info.asn_org.len > 0) {
            stdout_file.writeAll(" ") catch {};
            stdout_file.writeAll(info.asn_org) catch {};
        }
    }

    if (info.country.len > 0) {
        stdout_file.writeAll(" | ") catch {};
        stdout_file.writeAll(info.country) catch {};
    }

    stdout_file.writeAll(reset) catch {};
    stdout_file.writeAll("\n") catch {};
}

fn showTlsTable(allocator: std.mem.Allocator, data: []const u8, enrich: bool) !void {
    const parsed = try std.json.parseFromSlice(TlsDetailJson, allocator, data, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const r = parsed.value;

    var buf: [512]u8 = undefined;

    stdout_file.writeAll("Organization: ") catch {};
    stdout_file.writeAll(r.organization_name) catch {};
    stdout_file.writeAll("\nReport ID:    ") catch {};
    stdout_file.writeAll(r.report_id) catch {};
    stdout_file.writeAll("\n\n") catch {};

    for (r.policies) |p| {
        const policy_line = std.fmt.bufPrint(&buf, "Policy: {s} ({s})\n", .{ p.policy_domain, p.policy_type }) catch continue;
        stdout_file.writeAll(policy_line) catch {};

        const succ = std.fmt.bufPrint(&buf, "  Successful sessions: {d}\n", .{p.total_successful}) catch continue;
        stdout_file.writeAll(succ) catch {};

        const fail = std.fmt.bufPrint(&buf, "  Failed sessions:     {d}\n", .{p.total_failure}) catch continue;
        stdout_file.writeAll(fail) catch {};

        if (p.failures.len > 0) {
            stdout_file.writeAll("\n  Failures:\n") catch {};
            for (p.failures) |f| {
                const fline = std.fmt.bufPrint(&buf, "    {s}: {s} -> {s} ({d} sessions)\n", .{
                    f.result_type, f.sending_mta_ip, f.receiving_mx_hostname, f.failed_session_count,
                }) catch continue;
                stdout_file.writeAll(fline) catch {};

                if (enrich and f.sending_mta_ip.len > 0) {
                    const info = reports.ipinfo.lookup(allocator, f.sending_mta_ip);
                    defer info.deinit(allocator);
                    const cached = CachedIpInfo{
                        .ptr = info.ptr,
                        .asn = info.asn,
                        .asn_org = info.asn_org,
                        .country = info.country,
                    };
                    stdout_file.writeAll("    ") catch {};
                    writeEnrichLine(&buf, &cached, f.sending_mta_ip);
                }
            }
        }
    }
}

const DmarcDetailJson = struct {
    metadata: struct {
        org_name: []const u8 = "",
        report_id: []const u8 = "",
    },
    policy: struct {
        domain: []const u8 = "",
        policy: []const u8 = "",
    },
    records: []const struct {
        source_ip: []const u8 = "",
        count: u64 = 0,
        disposition: []const u8 = "",
        dkim_eval: []const u8 = "",
        spf_eval: []const u8 = "",
        header_from: []const u8 = "",
        envelope_from: []const u8 = "",
        envelope_to: []const u8 = "",
    } = &.{},
};

const TlsDetailJson = struct {
    organization_name: []const u8 = "",
    report_id: []const u8 = "",
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

/// Extract hash ID from filename (strip .json extension).
fn filenameToHashId(filename: []const u8) []const u8 {
    if (std.mem.endsWith(u8, filename, ".json")) {
        return filename[0 .. filename.len - 5];
    }
    return filename;
}

fn isTlsrptContentType(ct: []const u8) bool {
    return std.mem.indexOf(u8, ct, "application/tlsrpt+gzip") != null or
        std.mem.indexOf(u8, ct, "application/tlsrpt+json") != null;
}

fn truncate(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    return s[0..max];
}

fn printVersion() void {
    stdout_file.writeAll("reports version ") catch {};
    stdout_file.writeAll(build_options.version) catch {};
    stdout_file.writeAll("\n") catch {};
}

fn printUsage() void {
    stdout_file.writeAll(neon_yellow) catch {};
    stdout_file.writeAll(logo_text) catch {};
    stdout_file.writeAll(reset) catch {};
    stdout_file.writeAll(dim) catch {};
    stdout_file.writeAll(desc_text) catch {};
    stdout_file.writeAll(reset) catch {};
    stdout_file.writeAll(
        \\
        \\Usage: reports <command> [options]
        \\
        \\Commands:
        \\  fetch                        Fetch reports from IMAP
        \\  list                         List reports
        \\  show <id>                    Show report details
        \\  summary                      Show summary statistics
        \\  domains                      List domains
        \\  version                      Show version
        \\  help                         Show this help
        \\
        \\Options:
        \\  --account <name>      Target specific account (default: all)
        \\  --format <table|json> Output format (default: table)
        \\  --domain <domain>     Filter by domain
        \\  --type <dmarc|tlsrpt> Filter by report type
        \\  --period <week|month|year> Group summary by period
        \\  --no-enrich            Disable IP enrichment (PTR/ASN/country)
        \\
        \\Configuration: ~/.config/reports/config.json
        \\
    ) catch {};
}

fn getOption(args: []const []const u8, name: []const u8) ?[]const u8 {
    for (args, 0..) |arg, i| {
        if (std.mem.eql(u8, arg, name) and i + 1 < args.len) {
            return args[i + 1];
        }
    }
    return null;
}

fn hasFlag(args: []const []const u8, name: []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, name)) return true;
    }
    return false;
}

// --- Tests ---

test "dayOfWeek returns correct ISO day" {
    // 2024-01-01 is Monday
    try std.testing.expectEqual(@as(u8, 1), dayOfWeek(2024, 1, 1));
    // 2023-12-31 is Sunday
    try std.testing.expectEqual(@as(u8, 7), dayOfWeek(2023, 12, 31));
    // 2026-04-10 is Friday
    try std.testing.expectEqual(@as(u8, 5), dayOfWeek(2026, 4, 10));
    // 2000-01-01 is Saturday
    try std.testing.expectEqual(@as(u8, 6), dayOfWeek(2000, 1, 1));
}

test "dayOfYear returns correct ordinal" {
    try std.testing.expectEqual(@as(u16, 1), dayOfYear(2024, 1, 1));
    try std.testing.expectEqual(@as(u16, 32), dayOfYear(2024, 2, 1));
    try std.testing.expectEqual(@as(u16, 366), dayOfYear(2024, 12, 31)); // leap year
    try std.testing.expectEqual(@as(u16, 365), dayOfYear(2023, 12, 31)); // non-leap
    try std.testing.expectEqual(@as(u16, 60), dayOfYear(2024, 2, 29)); // leap day
}

test "isLeapYear" {
    try std.testing.expect(isLeapYear(2024));
    try std.testing.expect(!isLeapYear(2023));
    try std.testing.expect(isLeapYear(2000));
    try std.testing.expect(!isLeapYear(1900));
}

test "isoWeek known dates" {
    // 2024-01-01 (Mon) is W01 of 2024
    const w1 = isoWeek(2024, 1, 1);
    try std.testing.expectEqual(@as(u16, 2024), w1.year);
    try std.testing.expectEqual(@as(u8, 1), w1.week);

    // 2023-01-01 (Sun) is W52 of 2022
    const w2 = isoWeek(2023, 1, 1);
    try std.testing.expectEqual(@as(u16, 2022), w2.year);
    try std.testing.expectEqual(@as(u8, 52), w2.week);

    // 2020-12-31 (Thu) is W53 of 2020
    const w3 = isoWeek(2020, 12, 31);
    try std.testing.expectEqual(@as(u16, 2020), w3.year);
    try std.testing.expectEqual(@as(u8, 53), w3.week);

    // 2021-01-01 (Fri) is W53 of 2020
    const w4 = isoWeek(2021, 1, 1);
    try std.testing.expectEqual(@as(u16, 2020), w4.year);
    try std.testing.expectEqual(@as(u8, 53), w4.week);

    // 2026-12-31 (Thu) is W53 of 2026
    const w5 = isoWeek(2026, 12, 31);
    try std.testing.expectEqual(@as(u16, 2026), w5.year);
    try std.testing.expectEqual(@as(u8, 53), w5.week);
}

test "periodKey year extracts YYYY" {
    const allocator = std.testing.allocator;
    const key = try periodKey(allocator, "2024-03-15 12:00", "year");
    defer allocator.free(key);
    try std.testing.expectEqualStrings("2024", key);
}

test "periodKey month extracts YYYY-MM" {
    const allocator = std.testing.allocator;
    const key = try periodKey(allocator, "2024-03-15 12:00", "month");
    defer allocator.free(key);
    try std.testing.expectEqualStrings("2024-03", key);
}

test "periodKey week computes ISO week" {
    const allocator = std.testing.allocator;
    // 2024-01-01 is Monday of W01
    const key1 = try periodKey(allocator, "2024-01-01 00:00", "week");
    defer allocator.free(key1);
    try std.testing.expectEqualStrings("2024-W01", key1);

    // 2023-01-01 is Sunday, belongs to 2022-W52
    const key2 = try periodKey(allocator, "2023-01-01 00:00", "week");
    defer allocator.free(key2);
    try std.testing.expectEqualStrings("2022-W52", key2);
}

test "periodKey returns error for short date" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidDate, periodKey(allocator, "2024", "year"));
}

test "periodKey returns error for invalid month or day" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidDate, periodKey(allocator, "2024-00-15 00:00", "week"));
    try std.testing.expectError(error.InvalidDate, periodKey(allocator, "2024-13-15 00:00", "week"));
    try std.testing.expectError(error.InvalidDate, periodKey(allocator, "2024-06-00 00:00", "week"));
    try std.testing.expectError(error.InvalidDate, periodKey(allocator, "2024-06-32 00:00", "week"));
}

test "isTlsrptContentType" {
    try std.testing.expect(isTlsrptContentType("application/tlsrpt+gzip"));
    try std.testing.expect(isTlsrptContentType("application/tlsrpt+json"));
    try std.testing.expect(isTlsrptContentType("application/tlsrpt+gzip; name=\"report.gz\""));
    try std.testing.expect(!isTlsrptContentType("application/gzip"));
    try std.testing.expect(!isTlsrptContentType("application/xml"));
    try std.testing.expect(!isTlsrptContentType("text/plain"));
}
