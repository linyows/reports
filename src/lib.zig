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

const lib_max_fetch_workers = 16;

const LibFetchedMessage = struct {
    uid: u32,
    data: ?[]const u8,
};

const LibFetchWorkerCtx = struct {
    alloc: std.mem.Allocator,
    host: []const u8,
    port: u16,
    username: []const u8,
    password: []const u8,
    mailbox: []const u8,
    tls: bool,
    uids: []const u32,
    results: []LibFetchedMessage,
};

fn libFetchWorker(ctx: *LibFetchWorkerCtx) void {
    var client = reports.imap.Client.init(
        ctx.alloc,
        ctx.host,
        ctx.port,
        ctx.username,
        ctx.password,
        ctx.mailbox,
        ctx.tls,
    );
    client.connect() catch return;
    defer client.deinit();

    for (ctx.uids, 0..) |uid, i| {
        ctx.results[i] = .{
            .uid = uid,
            .data = client.fetchMessage(uid) catch null,
        };
    }
}

export fn reports_fetch(config_json: [*:0]const u8) c_int {
    const cfg = reports.config.Config.fromJson(allocator, std.mem.span(config_json)) catch return -1;
    defer cfg.deinit(allocator);

    reports.store.migrateToAccountDirs(cfg.data_dir);
    cfg.ensureDataDir() catch return -1;

    for (cfg.accounts) |acct| {
        if (acct.host.len == 0) continue;

        // Use a single connection for UID SEARCH
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

        // Collect new UIDs
        var new_uids: std.ArrayList(u32) = .empty;
        for (uids) |uid| {
            if (!fetched_set.contains(uid)) new_uids.append(allocator, uid) catch {};
        }
        const new_uid_slice = new_uids.toOwnedSlice(allocator) catch continue;
        defer allocator.free(new_uid_slice);

        if (new_uid_slice.len == 0) continue;

        // Allocate results
        const all_results = allocator.alloc(LibFetchedMessage, new_uid_slice.len) catch continue;
        defer {
            for (all_results) |r| {
                if (r.data) |d| allocator.free(d);
            }
            allocator.free(all_results);
        }
        for (all_results) |*r| {
            r.* = .{ .uid = 0, .data = null };
        }

        // Spawn worker threads based on CPU cores
        const cpu_count = std.Thread.getCpuCount() catch 2;
        const num_workers = @min(@min(cpu_count, lib_max_fetch_workers), new_uid_slice.len);
        const batch_size = new_uid_slice.len / num_workers;
        const remainder = new_uid_slice.len % num_workers;

        var contexts: [lib_max_fetch_workers]LibFetchWorkerCtx = undefined;
        var threads: [lib_max_fetch_workers]std.Thread = undefined;
        var spawned: usize = 0;

        var offset: usize = 0;
        for (0..num_workers) |i| {
            const this_batch = batch_size + @as(usize, if (i < remainder) 1 else 0);
            contexts[spawned] = .{
                .alloc = allocator,
                .host = acct.host,
                .port = acct.port,
                .username = acct.username,
                .password = acct.password,
                .mailbox = acct.mailbox,
                .tls = acct.tls,
                .uids = new_uid_slice[offset..][0..this_batch],
                .results = all_results[offset..][0..this_batch],
            };
            threads[spawned] = std.Thread.spawn(.{}, libFetchWorker, .{&contexts[spawned]}) catch continue;
            spawned += 1;
            offset += this_batch;
        }

        for (0..spawned) |i| {
            threads[i].join();
        }

        // Process results on main thread
        for (all_results) |r| {
            const raw = r.data orelse continue;

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

                if (reports.mtasts.parseJson(allocator, decompressed)) |report| {
                    defer report.deinit(allocator);
                    st.saveTlsReport(&report) catch continue;
                    saved = true;
                } else |_| {
                    const report = reports.dmarc.parseXml(allocator, decompressed) catch continue;
                    defer report.deinit(allocator);
                    st.saveDmarcReport(&report) catch continue;
                    saved = true;
                }
            }
            if (saved) {
                st.markUidFetched(r.uid);
                fetched_set.put(r.uid, {}) catch {};
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
    const info = reports.ipinfo.lookup(allocator, ip_span);
    defer info.deinit(allocator);

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
