const std = @import("std");
const reports = @import("reports");
const ui = @import("ui.zig");
const data = @import("data.zig");
const enrich = @import("enrich.zig");

const Config = reports.config.Config;
const Store = reports.store.Store;

pub fn cmdShow(allocator: std.mem.Allocator, report_id: []const u8, format: []const u8, do_enrich: bool) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);

    const entries = try data.loadEntries(allocator, &cfg, null);
    defer reports.store.freeReportEntries(allocator, entries);

    for (entries) |entry| {
        const hash_id = data.filenameToHashId(entry.filename);
        if (std.mem.indexOf(u8, hash_id, report_id) != null or
            std.mem.indexOf(u8, entry.report_id, report_id) != null or
            std.mem.indexOf(u8, entry.filename, report_id) != null)
        {
            const st = Store.init(allocator, cfg.data_dir, entry.account_name);
            switch (entry.report_type) {
                .dmarc => {
                    const report_data = try st.loadDmarcReport(entry.filename);
                    defer allocator.free(report_data);

                    if (std.mem.eql(u8, format, "json")) {
                        ui.stdout_file.writeAll(report_data) catch {};
                        ui.stdout_file.writeAll("\n") catch {};
                    } else {
                        try showDmarcTable(allocator, report_data, do_enrich, hash_id);
                    }
                },
                .tlsrpt => {
                    const report_data = try st.loadTlsReport(entry.filename);
                    defer allocator.free(report_data);

                    if (std.mem.eql(u8, format, "json")) {
                        ui.stdout_file.writeAll(report_data) catch {};
                        ui.stdout_file.writeAll("\n") catch {};
                    } else {
                        try showTlsTable(allocator, report_data, do_enrich, hash_id);
                    }
                },
            }
            return;
        }
    }

    ui.stderr_file.writeAll("Report not found: ") catch {};
    ui.stderr_file.writeAll(report_id) catch {};
    ui.stderr_file.writeAll("\n") catch {};
}

pub fn cmdList(allocator: std.mem.Allocator, format: []const u8, domain: ?[]const u8, account: ?[]const u8, report_type: ?[]const u8) !void {
    const cfg = try Config.load(allocator);
    defer cfg.deinit(allocator);

    const entries = try data.loadEntries(allocator, &cfg, account);
    defer reports.store.freeReportEntries(allocator, entries);

    const by_domain = try data.filterByDomain(allocator, entries, domain);
    defer allocator.free(by_domain);

    const filtered = try data.filterByType(allocator, by_domain, report_type);
    defer allocator.free(filtered);

    if (std.mem.eql(u8, format, "json")) {
        try writeJsonList(allocator, cfg.data_dir, filtered);
    } else {
        try writeTableList(allocator, filtered);
    }
}

const RowData = struct {
    source_ip: []const u8,
    count: u64,
    disposition: []const u8,
    from: []const u8,
    dkim_eval: []const u8,
    spf_eval: []const u8,
    ptr_display: []const u8,
    asn_display: []const u8,
    flag: []const u8,
};

const DmarcDetailJson = struct {
    metadata: struct {
        org_name: []const u8 = "",
        report_id: []const u8 = "",
        date_begin: i64 = 0,
        date_end: i64 = 0,
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

fn showDmarcTable(allocator: std.mem.Allocator, report_data: []const u8, do_enrich: bool, hash_id: []const u8) !void {
    const parsed = try std.json.parseFromSlice(DmarcDetailJson, allocator, report_data, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const r = parsed.value;

    var has_problems = false;
    for (r.records) |rec| {
        const dkim_pass = std.mem.eql(u8, rec.dkim_eval, "pass");
        const spf_pass = std.mem.eql(u8, rec.spf_eval, "pass");
        if (!dkim_pass and !spf_pass) {
            has_problems = true;
            break;
        }
    }

    const icon = if (has_problems) ui.fail_red ++ "●" ++ ui.reset else ui.neon_yellow ++ "●" ++ ui.reset;
    ui.stdout_file.writeAll(" ") catch {};
    ui.stdout_file.writeAll(icon) catch {};
    ui.stdout_file.writeAll(" ") catch {};
    ui.stdout_file.writeAll(hash_id) catch {};
    ui.stdout_file.writeAll("\n") catch {};

    var begin_buf: [20]u8 = undefined;
    var end_buf: [20]u8 = undefined;
    const begin_str = data.formatEpoch(&begin_buf, r.metadata.date_begin);
    const end_str = data.formatEpoch(&end_buf, r.metadata.date_end);

    var buf: [256]u8 = undefined;
    ui.stdout_file.writeAll(ui.branch_prefix) catch {};
    const org_line = std.fmt.bufPrint(&buf, "Organization: {s}\n", .{r.metadata.org_name}) catch "";
    ui.stdout_file.writeAll(org_line) catch {};

    const meta_items = [_]struct { label: []const u8, value: []const u8 }{
        .{ .label = "Report ID:    ", .value = r.metadata.report_id },
        .{ .label = "Domain:       ", .value = r.policy.domain },
        .{ .label = "Policy:       ", .value = r.policy.policy },
        .{ .label = "Begin:        ", .value = begin_str },
        .{ .label = "End:          ", .value = end_str },
    };
    for (meta_items) |item| {
        const line = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "{s}{s}\n", .{ item.label, item.value }) catch continue;
        ui.stdout_file.writeAll(line) catch {};
    }
    ui.stdout_file.writeAll("\n") catch {};

    // --- Pass 1: build row data and compute enrichment ---
    var ip_cache = std.StringHashMap(enrich.CachedIpInfo).init(allocator);
    defer {
        var it = ip_cache.valueIterator();
        while (it.next()) |v| v.deinit(allocator);
        ip_cache.deinit();
    }

    var rows: std.ArrayList(RowData) = .empty;
    defer {
        for (rows.items) |row| {
            allocator.free(row.from);
            allocator.free(row.ptr_display);
            allocator.free(row.asn_display);
            allocator.free(row.flag);
        }
        rows.deinit(allocator);
    }

    for (r.records) |rec| {
        const from = enrich.buildFromColumnAlloc(allocator, rec.header_from, rec.envelope_from) catch
            try allocator.dupe(u8, rec.header_from);

        var ptr_display: []const u8 = try allocator.dupe(u8, "");
        var asn_display: []const u8 = try allocator.dupe(u8, "");
        var flag: []const u8 = try allocator.dupe(u8, "");

        if (do_enrich) {
            const cached = enrich.lookupCached(allocator, &ip_cache, rec.source_ip);

            allocator.free(ptr_display);
            ptr_display = if (cached.ptr.len > 0 and !std.mem.eql(u8, cached.ptr, rec.source_ip))
                try allocator.dupe(u8, cached.ptr)
            else
                try allocator.dupe(u8, "-");

            allocator.free(asn_display);
            asn_display = enrich.buildAsnColumn(allocator, cached) catch try allocator.dupe(u8, "-");

            allocator.free(flag);
            flag = ui.countryFlag(allocator, cached.country) catch try allocator.dupe(u8, "-");
        }

        try rows.append(allocator, .{
            .source_ip = rec.source_ip,
            .count = rec.count,
            .disposition = rec.disposition,
            .from = from,
            .dkim_eval = rec.dkim_eval,
            .spf_eval = rec.spf_eval,
            .ptr_display = ptr_display,
            .asn_display = asn_display,
            .flag = flag,
        });
    }

    // --- Pass 2: compute column widths ---
    var w_ip: usize = "SOURCE IP".len;
    var w_ptr: usize = "PTR".len;
    var w_asn: usize = "ASN".len;
    var w_disp: usize = "DISP".len;
    var w_from: usize = "FROM".len;

    for (rows.items) |row| {
        w_ip = @max(w_ip, row.source_ip.len);
        w_disp = @max(w_disp, row.disposition.len);
        w_from = @max(w_from, row.from.len);
        if (do_enrich) {
            w_ptr = @max(w_ptr, row.ptr_display.len);
            w_asn = @max(w_asn, row.asn_display.len);
        }
    }

    w_ip += 1;
    w_disp += 1;
    w_from += 1;
    if (do_enrich) {
        w_ptr += 1;
        w_asn += 1;
    }

    // --- Pass 3: output ---
    const w_cc: usize = 3;
    const w_count: usize = 6;
    const w_dkim: usize = 5;
    const w_spf: usize = 5;

    ui.stdout_file.writeAll(ui.dim) catch {};
    if (do_enrich) {
        try ui.writeTableRow(allocator, &.{
            .{ .val = "SOURCE IP", .width = w_ip },
            .{ .val = "PTR", .width = w_ptr },
            .{ .val = "ASN", .width = w_asn },
            .{ .val = "CC", .width = w_cc },
            .{ .val = "COUNT", .width = w_count },
            .{ .val = "DISP", .width = w_disp },
            .{ .val = "FROM", .width = w_from },
            .{ .val = "DKIM", .width = w_dkim },
            .{ .val = "SPF", .width = w_spf },
        });
        try ui.writeSepRow(allocator, &.{ w_ip, w_ptr, w_asn, w_cc, w_count, w_disp, w_from, w_dkim, w_spf });
    } else {
        try ui.writeTableRow(allocator, &.{
            .{ .val = "SOURCE IP", .width = w_ip },
            .{ .val = "COUNT", .width = w_count },
            .{ .val = "DISP", .width = w_disp },
            .{ .val = "FROM", .width = w_from },
            .{ .val = "DKIM", .width = w_dkim },
            .{ .val = "SPF", .width = w_spf },
        });
        try ui.writeSepRow(allocator, &.{ w_ip, w_count, w_disp, w_from, w_dkim, w_spf });
    }
    ui.stdout_file.writeAll(ui.reset) catch {};

    for (rows.items) |row| {
        var count_buf: [16]u8 = undefined;
        const count_str = std.fmt.bufPrint(&count_buf, "{d}", .{row.count}) catch "0";

        if (do_enrich) {
            try ui.writeTableRow(allocator, &.{
                .{ .val = row.source_ip, .width = w_ip },
                .{ .val = row.ptr_display, .width = w_ptr },
                .{ .val = row.asn_display, .width = w_asn },
                .{ .val = row.flag, .width = w_cc, .is_emoji = true },
                .{ .val = count_str, .width = w_count },
                .{ .val = row.disposition, .width = w_disp },
                .{ .val = row.from, .width = w_from },
                .{ .val = row.dkim_eval, .width = w_dkim, .color = ui.evalColor(row.dkim_eval) },
                .{ .val = row.spf_eval, .width = w_spf, .color = ui.evalColor(row.spf_eval) },
            });
        } else {
            try ui.writeTableRow(allocator, &.{
                .{ .val = row.source_ip, .width = w_ip },
                .{ .val = count_str, .width = w_count },
                .{ .val = row.disposition, .width = w_disp },
                .{ .val = row.from, .width = w_from },
                .{ .val = row.dkim_eval, .width = w_dkim, .color = ui.evalColor(row.dkim_eval) },
                .{ .val = row.spf_eval, .width = w_spf, .color = ui.evalColor(row.spf_eval) },
            });
        }
    }
}

fn showTlsTable(allocator: std.mem.Allocator, report_data: []const u8, do_enrich: bool, hash_id: []const u8) !void {
    const parsed = try std.json.parseFromSlice(TlsDetailJson, allocator, report_data, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const r = parsed.value;

    var has_problems = false;
    for (r.policies) |p| {
        if (p.total_failure > 0) {
            has_problems = true;
            break;
        }
    }

    const icon = if (has_problems) ui.fail_red ++ "●" ++ ui.reset else ui.neon_yellow ++ "●" ++ ui.reset;
    ui.stdout_file.writeAll(" ") catch {};
    ui.stdout_file.writeAll(icon) catch {};
    ui.stdout_file.writeAll(" ") catch {};
    ui.stdout_file.writeAll(hash_id) catch {};
    ui.stdout_file.writeAll("\n") catch {};

    var buf: [512]u8 = undefined;

    ui.stdout_file.writeAll(ui.branch_prefix) catch {};
    const org_line = std.fmt.bufPrint(&buf, "Organization: {s}\n", .{r.organization_name}) catch "";
    ui.stdout_file.writeAll(org_line) catch {};
    const rid_line = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "Report ID:    {s}\n", .{r.report_id}) catch "";
    ui.stdout_file.writeAll(rid_line) catch {};
    ui.stdout_file.writeAll("\n") catch {};

    for (r.policies) |p| {
        const policy_line = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "Policy: {s} ({s})\n", .{ p.policy_domain, p.policy_type }) catch continue;
        ui.stdout_file.writeAll(policy_line) catch {};

        const succ = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "  Successful sessions: {d}\n", .{p.total_successful}) catch continue;
        ui.stdout_file.writeAll(succ) catch {};

        const fail = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "  Failed sessions:     {d}\n", .{p.total_failure}) catch continue;
        ui.stdout_file.writeAll(fail) catch {};

        if (p.failures.len > 0) {
            ui.stdout_file.writeAll("\n" ++ ui.detail_prefix ++ "  Failures:\n") catch {};
            for (p.failures) |f| {
                const fline = std.fmt.bufPrint(&buf, ui.detail_prefix ++ "    {s}: {s} -> {s} ({d} sessions)\n", .{
                    f.result_type, f.sending_mta_ip, f.receiving_mx_hostname, f.failed_session_count,
                }) catch continue;
                ui.stdout_file.writeAll(fline) catch {};

                if (do_enrich and f.sending_mta_ip.len > 0) {
                    const info = reports.ipinfo.lookup(allocator, f.sending_mta_ip);
                    defer info.deinit(allocator);
                    const cached = enrich.CachedIpInfo{
                        .ptr = info.ptr,
                        .asn = info.asn,
                        .asn_org = info.asn_org,
                        .country = info.country,
                    };
                    enrich.writeTlsEnrichLine(&buf, &cached, f.sending_mta_ip);
                }
            }
        }
    }
}

fn writeTableList(allocator: std.mem.Allocator, entries: []const reports.store.ReportEntry) !void {
    var w_id: usize = "ID".len;
    var w_acct: usize = "ACCOUNT".len;
    var w_type: usize = "TYPE".len;
    var w_date: usize = "DATE".len;
    var w_domain: usize = "DOMAIN".len;
    var w_org: usize = "ORGANIZATION".len;
    var w_policy: usize = "POLICY".len;

    for (entries) |e| {
        const hash_id = data.filenameToHashId(e.filename);
        const type_str: []const u8 = switch (e.report_type) {
            .dmarc => "DMARC",
            .tlsrpt => "TLS-RPT",
        };
        w_id = @max(w_id, hash_id.len);
        w_acct = @max(w_acct, e.account_name.len);
        w_type = @max(w_type, type_str.len);
        w_date = @max(w_date, e.date_begin.len);
        w_domain = @max(w_domain, e.domain.len);
        w_org = @max(w_org, e.org_name.len);
        w_policy = @max(w_policy, e.policy.len);
    }

    w_id += 1;
    w_acct += 1;
    w_type += 1;
    w_date += 1;
    w_domain += 1;
    w_org += 1;
    w_policy += 1;

    ui.stdout_file.writeAll(ui.dim) catch {};
    try ui.writeTableRow(allocator, &.{
        .{ .val = "ID", .width = w_id },
        .{ .val = "ACCOUNT", .width = w_acct },
        .{ .val = "TYPE", .width = w_type },
        .{ .val = "DATE", .width = w_date },
        .{ .val = "DOMAIN", .width = w_domain },
        .{ .val = "ORGANIZATION", .width = w_org },
        .{ .val = "POLICY", .width = w_policy },
    });
    try ui.writeSepRow(allocator, &.{ w_id, w_acct, w_type, w_date, w_domain, w_org, w_policy });
    ui.stdout_file.writeAll(ui.reset) catch {};

    for (entries) |e| {
        const type_str: []const u8 = switch (e.report_type) {
            .dmarc => "DMARC",
            .tlsrpt => "TLS-RPT",
        };
        const hash_id = data.filenameToHashId(e.filename);
        try ui.writeTableRow(allocator, &.{
            .{ .val = hash_id, .width = w_id },
            .{ .val = e.account_name, .width = w_acct },
            .{ .val = type_str, .width = w_type },
            .{ .val = e.date_begin, .width = w_date },
            .{ .val = e.domain, .width = w_domain },
            .{ .val = e.org_name, .width = w_org },
            .{ .val = e.policy, .width = w_policy },
        });
    }
}

fn countProblems(alloc: std.mem.Allocator, data_dir: []const u8, entry: reports.store.ReportEntry) u64 {
    const st = Store.init(alloc, data_dir, entry.account_name);
    switch (entry.report_type) {
        .dmarc => {
            const report_data = st.loadDmarcReport(entry.filename) catch return 0;
            defer alloc.free(report_data);
            return reports.stats.countDmarcProblems(alloc, report_data);
        },
        .tlsrpt => {
            const report_data = st.loadTlsReport(entry.filename) catch return 0;
            defer alloc.free(report_data);
            return reports.stats.countTlsProblems(alloc, report_data);
        },
    }
}

fn writeJsonList(alloc: std.mem.Allocator, data_dir: []const u8, entries: []const reports.store.ReportEntry) !void {
    ui.stdout_file.writeAll("[") catch {};
    for (entries, 0..) |e, i| {
        if (i > 0) ui.stdout_file.writeAll(",") catch {};
        const type_str: []const u8 = switch (e.report_type) {
            .dmarc => "dmarc",
            .tlsrpt => "tlsrpt",
        };
        const hash_id = data.filenameToHashId(e.filename);
        const problems = countProblems(alloc, data_dir, e);
        const json_entry = try std.fmt.allocPrint(alloc, "\n  {{\"account\":\"{s}\",\"type\":\"{s}\",\"org\":\"{s}\",\"id\":\"{s}\",\"date\":\"{s}\",\"domain\":\"{s}\",\"policy\":\"{s}\",\"filename\":\"{s}\",\"problems\":{d}}}", .{
            e.account_name, type_str, e.org_name, hash_id, e.date_begin, e.domain, e.policy, e.filename, problems,
        });
        defer alloc.free(json_entry);
        ui.stdout_file.writeAll(json_entry) catch {};
    }
    ui.stdout_file.writeAll("\n]\n") catch {};
}
