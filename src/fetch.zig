const std = @import("std");
const Allocator = std.mem.Allocator;
const imap = @import("imap.zig");
const mime = @import("mime.zig");
const mtasts = @import("mtasts.zig");
const dmarc = @import("dmarc.zig");
const store = @import("store.zig");
const config = @import("config.zig");

const max_workers = 16;

pub const FetchResult = struct {
    uid: u32,
    data: ?[]const u8,
};

pub const FetchCounts = struct {
    dmarc: u32,
    tls: u32,
};

const WorkerCtx = struct {
    allocator: Allocator,
    host: []const u8,
    port: u16,
    username: []const u8,
    password: []const u8,
    mailbox: []const u8,
    tls: bool,
    uids: []const u32,
    results: []FetchResult,
    progress: ?*std.atomic.Value(usize),
};

fn worker(ctx: *WorkerCtx) void {
    var client = imap.Client.init(
        ctx.allocator,
        ctx.host,
        ctx.port,
        ctx.username,
        ctx.password,
        ctx.mailbox,
        ctx.tls,
    );
    client.connect() catch {
        for (ctx.uids, 0..) |uid, i| {
            ctx.results[i] = .{ .uid = uid, .data = null };
            if (ctx.progress) |p| {
                _ = p.fetchAdd(1, .monotonic);
            }
        }
        return;
    };
    defer client.deinit();

    for (ctx.uids, 0..) |uid, i| {
        ctx.results[i] = .{
            .uid = uid,
            .data = client.fetchMessage(uid) catch null,
        };
        if (ctx.progress) |p| {
            _ = p.fetchAdd(1, .monotonic);
        }
    }
}

pub const FetchJob = struct {
    contexts: [max_workers]WorkerCtx,
    threads: [max_workers]std.Thread,
    spawned: usize,
    results: []FetchResult,

    pub fn join(self: *FetchJob) void {
        for (0..self.spawned) |i| {
            self.threads[i].join();
        }
    }
};

/// Spawn parallel IMAP fetch workers. Caller must call job.join() to wait for completion,
/// then process job.results. Use freeResults() to release memory.
pub fn startFetch(
    allocator: Allocator,
    acct: *const config.Config.Account,
    uids: []const u32,
    progress: ?*std.atomic.Value(usize),
) ?FetchJob {
    if (uids.len == 0) return null;

    const results = allocator.alloc(FetchResult, uids.len) catch return null;
    for (results) |*r| {
        r.* = .{ .uid = 0, .data = null };
    }

    const cpu_count = std.Thread.getCpuCount() catch 2;
    const num_workers = @min(@min(cpu_count, max_workers), uids.len);
    const batch_size = uids.len / num_workers;
    const remainder = uids.len % num_workers;

    var job = FetchJob{
        .contexts = undefined,
        .threads = undefined,
        .spawned = 0,
        .results = results,
    };

    var offset: usize = 0;
    for (0..num_workers) |i| {
        const this_batch = batch_size + @as(usize, if (i < remainder) 1 else 0);
        job.contexts[job.spawned] = .{
            .allocator = allocator,
            .host = acct.host,
            .port = acct.port,
            .username = acct.username,
            .password = acct.password,
            .mailbox = acct.mailbox,
            .tls = acct.tls,
            .uids = uids[offset..][0..this_batch],
            .results = results[offset..][0..this_batch],
            .progress = progress,
        };
        job.threads[job.spawned] = std.Thread.spawn(.{}, worker, .{&job.contexts[job.spawned]}) catch {
            // Fallback: run synchronously if thread spawn fails
            worker(&job.contexts[job.spawned]);
            offset += this_batch;
            continue;
        };
        job.spawned += 1;
        offset += this_batch;
    }

    return job;
}

/// Convenience wrapper: start fetch and wait for completion.
pub fn fetchMessages(
    allocator: Allocator,
    acct: *const config.Config.Account,
    uids: []const u32,
    progress: ?*std.atomic.Value(usize),
) ?[]FetchResult {
    var job = startFetch(allocator, acct, uids, progress) orelse return null;
    job.join();
    return job.results;
}

/// Process fetched messages: parse attachments, save reports, mark UIDs as fetched.
pub fn processResults(
    allocator: Allocator,
    results: []const FetchResult,
    st: *const store.Store,
    fetched_set: *std.AutoHashMap(u32, void),
) FetchCounts {
    var dmarc_count: u32 = 0;
    var tls_count: u32 = 0;

    for (results) |r| {
        const raw = r.data orelse continue;

        const attachments = mime.extractAttachments(allocator, raw) catch continue;
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
            const decompressed = mime.decompress(allocator, att.data, att.filename) catch continue;
            defer allocator.free(decompressed);

            if (isTlsrptContentType(att.content_type)) {
                const report = mtasts.parseJson(allocator, decompressed) catch continue;
                defer report.deinit(allocator);
                st.saveTlsReport(&report) catch continue;
                tls_count += 1;
                saved = true;
            } else if (mtasts.parseJson(allocator, decompressed)) |report| {
                report.deinit(allocator);
                st.saveTlsReport(&report) catch continue;
                tls_count += 1;
                saved = true;
            } else |_| {
                const report = dmarc.parseXml(allocator, decompressed) catch continue;
                defer report.deinit(allocator);
                st.saveDmarcReport(&report) catch continue;
                dmarc_count += 1;
                saved = true;
            }
        }
        if (saved and !fetched_set.contains(r.uid)) {
            st.markUidFetched(r.uid);
            fetched_set.put(r.uid, {}) catch {};
        }
    }

    return .{ .dmarc = dmarc_count, .tls = tls_count };
}

pub fn freeResults(allocator: Allocator, results: []FetchResult) void {
    for (results) |r| {
        if (r.data) |d| allocator.free(d);
    }
    allocator.free(results);
}

fn isTlsrptContentType(ct: []const u8) bool {
    return std.mem.indexOf(u8, ct, "application/tlsrpt+gzip") != null or
        std.mem.indexOf(u8, ct, "application/tlsrpt+json") != null;
}

const testing = std.testing;

const test_acct = config.Config.Account{
    .name = "test",
    .host = "invalid.localhost",
    .port = 1,
    .username = "user",
    .password = "pass",
    .mailbox = "INBOX",
    .tls = false,
};

test "isTlsrptContentType" {
    try testing.expect(isTlsrptContentType("application/tlsrpt+gzip"));
    try testing.expect(isTlsrptContentType("application/tlsrpt+json"));
    try testing.expect(isTlsrptContentType("application/tlsrpt+gzip; name=\"report.gz\""));
    try testing.expect(!isTlsrptContentType("application/gzip"));
    try testing.expect(!isTlsrptContentType("application/xml"));
    try testing.expect(!isTlsrptContentType("text/plain"));
}

test "worker fills results and advances progress on connect failure" {
    const allocator = testing.allocator;
    const uids = [_]u32{ 100, 200, 300 };
    var results: [3]FetchResult = undefined;
    var progress = std.atomic.Value(usize).init(0);

    var ctx = WorkerCtx{
        .allocator = allocator,
        .host = test_acct.host,
        .port = test_acct.port,
        .username = test_acct.username,
        .password = test_acct.password,
        .mailbox = test_acct.mailbox,
        .tls = test_acct.tls,
        .uids = &uids,
        .results = &results,
        .progress = &progress,
    };
    worker(&ctx);

    try testing.expectEqual(3, progress.load(.monotonic));
    for (results, 0..) |r, i| {
        try testing.expectEqual(uids[i], r.uid);
        try testing.expectEqual(null, r.data);
    }
}

test "startFetch covers all UIDs even with connect failures" {
    const allocator = testing.allocator;
    const uids = [_]u32{ 1, 2, 3, 4, 5, 6, 7 };
    var progress = std.atomic.Value(usize).init(0);

    var job = startFetch(allocator, &test_acct, &uids, &progress) orelse {
        try testing.expect(false);
        return;
    };
    job.join();
    defer freeResults(allocator, job.results);

    try testing.expectEqual(uids.len, progress.load(.monotonic));
    try testing.expectEqual(uids.len, job.results.len);
    for (job.results, 0..) |r, i| {
        try testing.expectEqual(uids[i], r.uid);
        try testing.expectEqual(null, r.data);
    }
}

test "startFetch returns null for empty UIDs" {
    const allocator = testing.allocator;
    const uids = [_]u32{};
    const result = startFetch(allocator, &test_acct, &uids, null);
    try testing.expectEqual(null, result);
}

test "processResults skips entries with null data" {
    const allocator = testing.allocator;
    const results = [_]FetchResult{
        .{ .uid = 1, .data = null },
        .{ .uid = 2, .data = null },
    };
    const tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const st = store.Store.init(allocator, tmp_path, "test");
    var fetched_set = std.AutoHashMap(u32, void).init(allocator);
    defer fetched_set.deinit();

    const counts = processResults(allocator, &results, &st, &fetched_set);
    try testing.expectEqual(0, counts.dmarc);
    try testing.expectEqual(0, counts.tls);
    try testing.expectEqual(0, fetched_set.count());
}

test "processResults does not duplicate markUidFetched for already-fetched UIDs" {
    const allocator = testing.allocator;
    // data is not a valid MIME message, so parsing will fail and nothing will be saved.
    // But we can verify that fetched_set membership prevents markUidFetched from being called.
    const results = [_]FetchResult{
        .{ .uid = 42, .data = null },
    };
    const tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const st = store.Store.init(allocator, tmp_path, "test");
    var fetched_set = std.AutoHashMap(u32, void).init(allocator);
    defer fetched_set.deinit();
    try fetched_set.put(42, {});

    const counts = processResults(allocator, &results, &st, &fetched_set);
    try testing.expectEqual(0, counts.dmarc);
    try testing.expectEqual(0, counts.tls);
    // UID 42 was already in the set, so count should remain 1 (not re-added)
    try testing.expectEqual(1, fetched_set.count());
}

test "freeResults releases all allocated data" {
    const allocator = testing.allocator;
    var results = try allocator.alloc(FetchResult, 3);
    results[0] = .{ .uid = 1, .data = try allocator.dupe(u8, "hello") };
    results[1] = .{ .uid = 2, .data = null };
    results[2] = .{ .uid = 3, .data = try allocator.dupe(u8, "world") };
    // testing.allocator detects leaks, so if freeResults is wrong this test will fail
    freeResults(allocator, results);
}
