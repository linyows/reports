const std = @import("std");
const reports = @import("reports");

const Config = reports.config.Config;
const Store = reports.store.Store;

const stdout_file = std.fs.File.stdout();
const stderr_file = std.fs.File.stderr();

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

    if (std.mem.eql(u8, command, "fetch")) {
        try cmdFetch(allocator);
    } else if (std.mem.eql(u8, command, "list")) {
        const format = getOption(args, "--format") orelse "table";
        const domain = getOption(args, "--domain");
        try cmdList(allocator, format, domain);
    } else if (std.mem.eql(u8, command, "show")) {
        if (args.len < 3) {
            stderr_file.writeAll("Usage: reports show <report-id>\n") catch {};
            return;
        }
        const format = getOption(args, "--format") orelse "table";
        try cmdShow(allocator, args[2], format);
    } else if (std.mem.eql(u8, command, "summary")) {
        const format = getOption(args, "--format") orelse "json";
        const domain = getOption(args, "--domain");
        try cmdSummary(allocator, format, domain);
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsage();
    } else {
        stderr_file.writeAll("Unknown command: ") catch {};
        stderr_file.writeAll(command) catch {};
        stderr_file.writeAll("\n") catch {};
        printUsage();
    }
}

fn cmdFetch(allocator: std.mem.Allocator) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);
    try cfg.ensureDataDir();

    if (cfg.imap.host.len == 0) {
        stderr_file.writeAll("IMAP not configured. Edit ~/.config/reports/config.json\n") catch {};
        return;
    }

    reports.imap.globalInit();
    defer reports.imap.globalCleanup();

    const client = reports.imap.Client.init(
        allocator,
        cfg.imap.host,
        cfg.imap.port,
        cfg.imap.username,
        cfg.imap.password,
        cfg.imap.mailbox,
        cfg.imap.tls,
    );

    const st = Store.init(allocator, cfg.data_dir);

    stdout_file.writeAll("Searching for DMARC reports...\n") catch {};
    const dmarc_uids = client.searchDmarcReports() catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "IMAP search failed: {s}\n", .{@errorName(err)}) catch "IMAP search failed\n";
        stderr_file.writeAll(msg) catch {};
        return;
    };
    defer allocator.free(dmarc_uids);

    {
        var buf2: [64]u8 = undefined;
        const found_msg = std.fmt.bufPrint(&buf2, "Found {d} DMARC messages. Fetching...\n", .{dmarc_uids.len}) catch "Fetching...\n";
        stdout_file.writeAll(found_msg) catch {};
    }

    var dmarc_count: u32 = 0;
    for (dmarc_uids, 0..) |uid, idx| {
        {
            var pbuf: [64]u8 = undefined;
            const progress = std.fmt.bufPrint(&pbuf, "\r  [{d}/{d}]", .{ idx + 1, dmarc_uids.len }) catch "";
            stderr_file.writeAll(progress) catch {};
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

        for (attachments) |att| {
            const xml_data = reports.mime.decompress(allocator, att.data, att.filename) catch continue;
            defer allocator.free(xml_data);

            const report = reports.dmarc.parseXml(allocator, xml_data) catch continue;
            st.saveDmarcReport(&report) catch continue;
            dmarc_count += 1;
        }
    }

    stderr_file.writeAll("\n") catch {};
    stdout_file.writeAll("Searching for TLS-RPT reports...\n") catch {};
    const tls_uids = client.searchTlsReports() catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "IMAP search failed: {s}\n", .{@errorName(err)}) catch "IMAP search failed\n";
        stderr_file.writeAll(msg) catch {};
        return;
    };
    defer allocator.free(tls_uids);

    var tls_count: u32 = 0;
    for (tls_uids) |uid| {
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

        for (attachments) |att| {
            const json_data = reports.mime.decompress(allocator, att.data, att.filename) catch continue;
            defer allocator.free(json_data);

            const report = reports.mtasts.parseJson(allocator, json_data) catch continue;
            st.saveTlsReport(&report) catch continue;
            tls_count += 1;
        }
    }

    var buf: [128]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "Fetched {d} DMARC and {d} TLS-RPT reports.\n", .{ dmarc_count, tls_count }) catch "Done.\n";
    stdout_file.writeAll(msg) catch {};
}

fn cmdList(allocator: std.mem.Allocator, format: []const u8, domain: ?[]const u8) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);
    const st = Store.init(allocator, cfg.data_dir);
    const entries = try st.listReports();
    defer {
        for (entries) |e| {
            allocator.free(e.org_name);
            allocator.free(e.report_id);
            allocator.free(e.date_begin);
            allocator.free(e.date_end);
            allocator.free(e.domain);
            allocator.free(e.filename);
        }
        allocator.free(entries);
    }

    const filtered = try filterByDomain(allocator, entries, domain);
    defer allocator.free(filtered);

    if (std.mem.eql(u8, format, "json")) {
        try writeJsonList(allocator, filtered);
    } else {
        try writeTableList(allocator, filtered);
    }
}

fn cmdShow(allocator: std.mem.Allocator, report_id: []const u8, format: []const u8) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);
    const st = Store.init(allocator, cfg.data_dir);
    const entries = try st.listReports();
    defer {
        for (entries) |e| {
            allocator.free(e.org_name);
            allocator.free(e.report_id);
            allocator.free(e.date_begin);
            allocator.free(e.date_end);
            allocator.free(e.domain);
            allocator.free(e.filename);
        }
        allocator.free(entries);
    }

    for (entries) |entry| {
        if (std.mem.indexOf(u8, entry.report_id, report_id) != null or
            std.mem.indexOf(u8, entry.filename, report_id) != null)
        {
            switch (entry.report_type) {
                .dmarc => {
                    const data = try st.loadDmarcReport(entry.filename);
                    defer allocator.free(data);

                    if (std.mem.eql(u8, format, "json")) {
                        stdout_file.writeAll(data) catch {};
                        stdout_file.writeAll("\n") catch {};
                    } else {
                        try showDmarcTable(allocator, data);
                    }
                },
                .tlsrpt => {
                    const data = try st.loadTlsReport(entry.filename);
                    defer allocator.free(data);

                    if (std.mem.eql(u8, format, "json")) {
                        stdout_file.writeAll(data) catch {};
                        stdout_file.writeAll("\n") catch {};
                    } else {
                        try showTlsTable(allocator, data);
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

fn cmdSummary(allocator: std.mem.Allocator, format: []const u8, domain: ?[]const u8) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);
    const st = Store.init(allocator, cfg.data_dir);
    const entries = try st.listReports();
    defer {
        for (entries) |e| {
            allocator.free(e.org_name);
            allocator.free(e.report_id);
            allocator.free(e.date_begin);
            allocator.free(e.date_end);
            allocator.free(e.domain);
            allocator.free(e.filename);
        }
        allocator.free(entries);
    }

    const filtered = try filterByDomain(allocator, entries, domain);
    defer allocator.free(filtered);

    var total_dmarc: u32 = 0;
    var total_tlsrpt: u32 = 0;
    var total_messages: u64 = 0;
    var pass_count: u64 = 0;
    var fail_count: u64 = 0;

    for (filtered) |entry| {
        switch (entry.report_type) {
            .dmarc => {
                total_dmarc += 1;
                const data = st.loadDmarcReport(entry.filename) catch continue;
                defer allocator.free(data);
                accumulateDmarcStats(allocator, data, &total_messages, &pass_count, &fail_count);
            },
            .tlsrpt => {
                total_tlsrpt += 1;
            },
        }
    }

    var buf: [512]u8 = undefined;
    if (std.mem.eql(u8, format, "json")) {
        const msg = std.fmt.bufPrint(&buf,
            \\{{"dmarc_reports":{d},"tlsrpt_reports":{d},"total_messages":{d},"dkim_spf_pass":{d},"dkim_spf_fail":{d}}}
            \\
        , .{ total_dmarc, total_tlsrpt, total_messages, pass_count, fail_count }) catch return;
        stdout_file.writeAll(msg) catch {};
    } else {
        const labels = [_]struct { label: []const u8, value: u64 }{
            .{ .label = "DMARC Reports:    ", .value = total_dmarc },
            .{ .label = "TLS-RPT Reports:  ", .value = total_tlsrpt },
            .{ .label = "Total Messages:   ", .value = total_messages },
            .{ .label = "DKIM/SPF Pass:    ", .value = pass_count },
            .{ .label = "DKIM/SPF Fail:    ", .value = fail_count },
        };
        for (labels) |entry| {
            const msg = std.fmt.bufPrint(&buf, "{s}{d}\n", .{ entry.label, entry.value }) catch continue;
            stdout_file.writeAll(msg) catch {};
        }
    }
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

const DmarcStatsJson = struct {
    records: []const struct {
        count: u64 = 0,
        dkim_eval: []const u8 = "",
        spf_eval: []const u8 = "",
    } = &.{},
};

fn writeTableList(allocator: std.mem.Allocator, entries: []const reports.store.ReportEntry) !void {
    var buf: [512]u8 = undefined;

    const header = std.fmt.bufPrint(&buf, "{s:<8} {s:<25} {s:<30} {s:<17} {s:<20}\n", .{
        "TYPE", "ORGANIZATION", "REPORT ID", "DATE", "DOMAIN",
    }) catch return;
    stdout_file.writeAll(header) catch {};

    const sep = std.fmt.bufPrint(&buf, "{s:-<8} {s:-<25} {s:-<30} {s:-<17} {s:-<20}\n", .{
        "", "", "", "", "",
    }) catch return;
    stdout_file.writeAll(sep) catch {};

    for (entries) |e| {
        const type_str: []const u8 = switch (e.report_type) {
            .dmarc => "DMARC",
            .tlsrpt => "TLS-RPT",
        };
        const line = std.fmt.bufPrint(&buf, "{s:<8} {s:<25} {s:<30} {s:<17} {s:<20}\n", .{
            type_str,
            truncate(e.org_name, 24),
            truncate(e.report_id, 29),
            truncate(e.date_begin, 16),
            truncate(e.domain, 19),
        }) catch continue;
        stdout_file.writeAll(line) catch {};
    }
    _ = allocator;
}

fn writeJsonList(allocator: std.mem.Allocator, entries: []const reports.store.ReportEntry) !void {
    stdout_file.writeAll("[") catch {};
    for (entries, 0..) |e, i| {
        if (i > 0) stdout_file.writeAll(",") catch {};
        const type_str: []const u8 = switch (e.report_type) {
            .dmarc => "dmarc",
            .tlsrpt => "tlsrpt",
        };
        const json_entry = try std.fmt.allocPrint(allocator, "\n  {{\"type\":\"{s}\",\"org\":\"{s}\",\"id\":\"{s}\",\"date\":\"{s}\",\"domain\":\"{s}\"}}", .{
            type_str, e.org_name, e.report_id, e.date_begin, e.domain,
        });
        defer allocator.free(json_entry);
        stdout_file.writeAll(json_entry) catch {};
    }
    stdout_file.writeAll("\n]\n") catch {};
}

fn showDmarcTable(allocator: std.mem.Allocator, data: []const u8) !void {
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
    }
}

fn showTlsTable(allocator: std.mem.Allocator, data: []const u8) !void {
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

fn truncate(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    return s[0..max];
}

fn printUsage() void {
    stdout_file.writeAll(
        \\Usage: reports <command> [options]
        \\
        \\Commands:
        \\  fetch                        Fetch reports from IMAP
        \\  list [--format] [--domain]   List reports (table|json)
        \\  show <id> [--format]         Show report details (table|json)
        \\  summary [--format] [--domain] Show summary statistics (table|json)
        \\  help                         Show this help
        \\
        \\Options:
        \\  --format <table|json>   Output format (default: table)
        \\  --domain <domain>       Filter by domain
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
