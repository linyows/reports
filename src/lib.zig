/// C ABI exports for SwiftUI integration.
/// All functions return JSON strings. Use reports_free_string() to release them.
const std = @import("std");
const reports = @import("reports");

const allocator = std.heap.c_allocator;

export fn reports_init() void {
    reports.imap.globalInit();
}

export fn reports_deinit() void {
    reports.imap.globalCleanup();
}

export fn reports_fetch(config_json: [*:0]const u8) c_int {
    const cfg = reports.config.Config.fromJson(allocator, std.mem.span(config_json)) catch return -1;
    defer cfg.deinit(allocator);

    reports.store.migrateToAccountDirs(cfg.data_dir);
    cfg.ensureDataDir() catch return -1;

    for (cfg.accounts) |acct| {
        if (acct.host.len == 0) continue;

        const client = reports.imap.Client.init(
            allocator,
            acct.host,
            acct.port,
            acct.username,
            acct.password,
            acct.mailbox,
            acct.tls,
        );

        const st = reports.store.Store.init(allocator, cfg.data_dir, acct.name);

        // DMARC
        const dmarc_uids = client.searchDmarcReports() catch continue;
        defer allocator.free(dmarc_uids);

        for (dmarc_uids) |uid| {
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
            }
        }

        // TLS-RPT
        const tls_uids = client.searchTlsReports() catch continue;
        defer allocator.free(tls_uids);

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
            }
        }
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
        const json_entry = std.fmt.allocPrint(allocator, "{{\"account\":\"{s}\",\"type\":\"{s}\",\"org\":\"{s}\",\"id\":\"{s}\",\"date\":\"{s}\",\"domain\":\"{s}\"}}", .{
            e.account_name, type_str, e.org_name, e.report_id, e.date_begin, e.domain,
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

export fn reports_free_string(ptr: ?[*:0]u8) void {
    if (ptr) |p| {
        const len = std.mem.len(p);
        allocator.free(p[0 .. len + 1]);
    }
}
