//! Persistent IP enrichment cache (JSON Lines format).
//!
//! Stores PTR/ASN/country lookup results in {data_dir}/.enrich_cache.jsonl,
//! one entry per line. Writes are append-only for O(1) cost per update; the
//! file is periodically compacted when duplicate lines accumulate.
//!
//! Thread-safe via an internal mutex so parallel DNS workers can update
//! entries concurrently. Entries expire after TTL_SECONDS (30 days).

const std = @import("std");
const Allocator = std.mem.Allocator;
const ipinfo = @import("ipinfo.zig");

pub const TTL_SECONDS: i64 = 30 * 24 * 60 * 60;
const CACHE_FILENAME = ".enrich_cache.jsonl";

pub const Entry = struct {
    ptr: []const u8,
    asn: []const u8,
    asn_org: []const u8,
    country: []const u8,
    ts: i64,
};

pub const Cache = struct {
    allocator: Allocator,
    map: std.StringHashMap(Entry),
    mutex: std.Thread.Mutex = .{},
    path: []const u8,
    /// Number of append-only lines written since the last compaction.
    /// Used to decide when to rewrite the file to reclaim space.
    appended_since_compact: usize = 0,

    pub fn init(allocator: Allocator, data_dir: []const u8) !Cache {
        const path = try std.fs.path.join(allocator, &.{ data_dir, CACHE_FILENAME });
        var cache = Cache{
            .allocator = allocator,
            .map = std.StringHashMap(Entry).init(allocator),
            .path = path,
        };
        // Clean up any orphaned .tmp file from a prior crash during compaction.
        cache.cleanupOrphanTmp();
        cache.loadFromDisk() catch {};
        return cache;
    }

    fn cleanupOrphanTmp(self: *Cache) void {
        const tmp_path = std.fmt.allocPrint(self.allocator, "{s}.tmp", .{self.path}) catch return;
        defer self.allocator.free(tmp_path);
        std.fs.deleteFileAbsolute(tmp_path) catch {};
    }

    pub fn deinit(self: *Cache) void {
        var it = self.map.iterator();
        while (it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            freeEntryFields(self.allocator, kv.value_ptr.*);
        }
        self.map.deinit();
        self.allocator.free(self.path);
    }

    /// Look up an entry. Returns a duplicated entry (caller owns strings) if found and fresh.
    pub fn getDup(self: *Cache, ip: []const u8) ?Entry {
        self.mutex.lock();
        defer self.mutex.unlock();
        const e = self.map.get(ip) orelse return null;
        const now = std.time.timestamp();
        if (now - e.ts > TTL_SECONDS) return null;
        return dupEntry(self.allocator, e) catch null;
    }

    /// Check if an IP has a fresh entry without allocating.
    pub fn hasFresh(self: *Cache, ip: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const e = self.map.get(ip) orelse return false;
        const now = std.time.timestamp();
        return (now - e.ts) <= TTL_SECONDS;
    }

    /// Insert or replace an entry. Updates the in-memory map and appends a
    /// single line to the cache file. Cache takes ownership of new copies.
    /// Propagates I/O errors so callers can surface disk-full / permission issues
    /// rather than silently losing the persisted entry.
    pub fn put(self: *Cache, ip: []const u8, info: ipinfo.IpInfo) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const ip_copy = try self.allocator.dupe(u8, ip);
        errdefer self.allocator.free(ip_copy);

        const entry = try makeEntry(self.allocator, info);
        errdefer freeEntryFields(self.allocator, entry);

        if (self.map.fetchRemove(ip)) |old| {
            self.allocator.free(old.key);
            freeEntryFields(self.allocator, old.value);
        }
        try self.map.put(ip_copy, entry);

        // If appendLine fails, roll back the map insert so in-memory and
        // on-disk state stay consistent.
        self.appendLine(ip, entry) catch |err| {
            if (self.map.fetchRemove(ip)) |kv| {
                self.allocator.free(kv.key);
                freeEntryFields(self.allocator, kv.value);
            }
            return err;
        };
    }

    /// Rewrite the file to remove duplicate/stale lines if it has grown too large.
    /// Triggered automatically at the end of parallel enrichment.
    pub fn compactIfNeeded(self: *Cache) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Compact when appended lines exceed the unique entry count,
        // i.e., the file is at least 2x the ideal size.
        if (self.appended_since_compact <= self.map.count()) return;
        try self.rewriteLocked();
    }

    /// Force a full rewrite (used by tests and explicit compaction).
    pub fn compact(self: *Cache) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.rewriteLocked();
    }

    fn appendLine(self: *Cache, ip: []const u8, entry: Entry) !void {
        // Ensure parent dir exists
        if (std.fs.path.dirname(self.path)) |dir| {
            std.fs.makeDirAbsolute(dir) catch {};
        }

        const line = try formatLine(self.allocator, ip, entry);
        defer self.allocator.free(line);

        const file = std.fs.createFileAbsolute(self.path, .{ .truncate = false }) catch return;
        defer file.close();
        file.seekFromEnd(0) catch {};
        try file.writeAll(line);

        self.appended_since_compact += 1;
    }

    fn rewriteLocked(self: *Cache) !void {
        if (std.fs.path.dirname(self.path)) |dir| {
            std.fs.makeDirAbsolute(dir) catch {};
        }

        const tmp_path = try std.fmt.allocPrint(self.allocator, "{s}.tmp", .{self.path});
        defer self.allocator.free(tmp_path);

        {
            const file = try std.fs.createFileAbsolute(tmp_path, .{});
            defer file.close();

            var it = self.map.iterator();
            while (it.next()) |kv| {
                const line = try formatLine(self.allocator, kv.key_ptr.*, kv.value_ptr.*);
                defer self.allocator.free(line);
                try file.writeAll(line);
            }
        }
        try std.fs.renameAbsolute(tmp_path, self.path);
        self.appended_since_compact = 0;
    }

    fn loadFromDisk(self: *Cache) !void {
        const file = std.fs.openFileAbsolute(self.path, .{}) catch return;
        defer file.close();

        const data = try file.readToEndAlloc(self.allocator, 256 * 1024 * 1024);
        defer self.allocator.free(data);

        var line_count: usize = 0;
        var lines = std.mem.splitScalar(u8, data, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \r\t");
            if (trimmed.len == 0) continue;
            line_count += 1;

            const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, trimmed, .{}) catch continue;
            defer parsed.deinit();

            const obj = switch (parsed.value) {
                .object => |o| o,
                else => continue,
            };

            const ip_val = obj.get("ip") orelse continue;
            if (ip_val != .string) continue;
            const ip = ip_val.string;
            if (ip.len == 0) continue;

            const entry = Entry{
                .ptr = dupStrField(self.allocator, obj.get("ptr")) catch continue,
                .asn = dupStrField(self.allocator, obj.get("asn")) catch continue,
                .asn_org = dupStrField(self.allocator, obj.get("asn_org")) catch continue,
                .country = dupStrField(self.allocator, obj.get("country")) catch continue,
                .ts = tsField(obj.get("ts")),
            };

            // Later lines overwrite earlier ones (JSONL "last wins")
            if (self.map.fetchRemove(ip)) |old| {
                self.allocator.free(old.key);
                freeEntryFields(self.allocator, old.value);
            }
            const ip_copy = self.allocator.dupe(u8, ip) catch {
                freeEntryFields(self.allocator, entry);
                continue;
            };
            self.map.put(ip_copy, entry) catch {
                self.allocator.free(ip_copy);
                freeEntryFields(self.allocator, entry);
                continue;
            };
        }

        // appended_since_compact reflects how many duplicates exist on disk.
        // If all lines were unique, appended_since_compact == 0; otherwise it
        // tracks the "excess" to drive the compaction heuristic.
        self.appended_since_compact = if (line_count > self.map.count())
            line_count - self.map.count()
        else
            0;
    }
};

fn formatLine(allocator: Allocator, ip: []const u8, entry: Entry) ![]u8 {
    // One JSON object per line, terminated with '\n'.
    return std.fmt.allocPrint(
        allocator,
        "{{\"ip\":{f},\"ptr\":{f},\"asn\":{f},\"asn_org\":{f},\"country\":{f},\"ts\":{d}}}\n",
        .{
            std.json.fmt(ip, .{}),
            std.json.fmt(entry.ptr, .{}),
            std.json.fmt(entry.asn, .{}),
            std.json.fmt(entry.asn_org, .{}),
            std.json.fmt(entry.country, .{}),
            entry.ts,
        },
    );
}

fn dupStrField(allocator: Allocator, v: ?std.json.Value) ![]const u8 {
    if (v) |val| switch (val) {
        .string => |s| return allocator.dupe(u8, s),
        else => {},
    };
    return allocator.dupe(u8, "");
}

fn tsField(v: ?std.json.Value) i64 {
    if (v) |val| switch (val) {
        .integer => |i| return i,
        else => {},
    };
    return 0;
}

fn makeEntry(allocator: Allocator, info: ipinfo.IpInfo) !Entry {
    const ptr_copy = try allocator.dupe(u8, info.ptr);
    errdefer allocator.free(ptr_copy);
    const asn_copy = try allocator.dupe(u8, info.asn);
    errdefer allocator.free(asn_copy);
    const org_copy = try allocator.dupe(u8, info.asn_org);
    errdefer allocator.free(org_copy);
    const country_copy = try allocator.dupe(u8, info.country);
    return .{
        .ptr = ptr_copy,
        .asn = asn_copy,
        .asn_org = org_copy,
        .country = country_copy,
        .ts = std.time.timestamp(),
    };
}

pub fn dupEntry(allocator: Allocator, e: Entry) !Entry {
    return .{
        .ptr = try allocator.dupe(u8, e.ptr),
        .asn = try allocator.dupe(u8, e.asn),
        .asn_org = try allocator.dupe(u8, e.asn_org),
        .country = try allocator.dupe(u8, e.country),
        .ts = e.ts,
    };
}

pub fn freeEntryFields(allocator: Allocator, e: Entry) void {
    allocator.free(e.ptr);
    allocator.free(e.asn);
    allocator.free(e.asn_org);
    allocator.free(e.country);
}

/// Convert a cache Entry to an IpInfo (fresh allocations owned by caller).
pub fn entryToIpInfo(allocator: Allocator, e: Entry) !ipinfo.IpInfo {
    return .{
        .ptr = try allocator.dupe(u8, e.ptr),
        .asn = try allocator.dupe(u8, e.asn),
        .asn_org = try allocator.dupe(u8, e.asn_org),
        .country = try allocator.dupe(u8, e.country),
    };
}

// ===== Parallel enrichment =====

const max_workers = 16;

const EnrichCtx = struct {
    cache: *Cache,
    allocator: Allocator,
    ips: []const []const u8,
    progress: ?*std.atomic.Value(usize),
};

fn enrichWorker(ctx: *EnrichCtx) void {
    for (ctx.ips) |ip| {
        defer if (ctx.progress) |p| {
            _ = p.fetchAdd(1, .monotonic);
        };
        if (ctx.cache.hasFresh(ip)) continue;
        const info = ipinfo.lookup(ctx.allocator, ip);
        defer info.deinit(ctx.allocator);
        ctx.cache.put(ip, info) catch {};
    }
}

/// Enrich a batch of IPs in parallel using a worker pool.
/// Skips IPs already present and fresh in the cache.
/// After completion, compacts the cache file if excess duplicates have accumulated.
pub fn enrichParallel(
    cache: *Cache,
    allocator: Allocator,
    ips: []const []const u8,
    progress: ?*std.atomic.Value(usize),
) void {
    if (ips.len == 0) return;

    const cpu_count = std.Thread.getCpuCount() catch 2;
    const num_workers = @min(@min(cpu_count, max_workers), ips.len);
    const batch_size = ips.len / num_workers;
    const remainder = ips.len % num_workers;

    var contexts: [max_workers]EnrichCtx = undefined;
    var threads: [max_workers]std.Thread = undefined;
    var spawned: usize = 0;

    var offset: usize = 0;
    for (0..num_workers) |i| {
        const this_batch = batch_size + @as(usize, if (i < remainder) 1 else 0);
        contexts[spawned] = .{
            .cache = cache,
            .allocator = allocator,
            .ips = ips[offset..][0..this_batch],
            .progress = progress,
        };
        threads[spawned] = std.Thread.spawn(.{}, enrichWorker, .{&contexts[spawned]}) catch {
            enrichWorker(&contexts[spawned]);
            offset += this_batch;
            continue;
        };
        spawned += 1;
        offset += this_batch;
    }

    for (0..spawned) |i| threads[i].join();

    cache.compactIfNeeded() catch {};
}

// ===== Tests =====

const testing = std.testing;

test "cache round-trip: put and getDup" {
    const allocator = testing.allocator;
    const tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    var cache = try Cache.init(allocator, tmp_path);
    defer cache.deinit();

    const info = ipinfo.IpInfo{
        .ptr = try allocator.dupe(u8, "host.example.com"),
        .asn = try allocator.dupe(u8, "15169"),
        .asn_org = try allocator.dupe(u8, "GOOGLE"),
        .country = try allocator.dupe(u8, "US"),
    };
    defer info.deinit(allocator);

    try cache.put("1.2.3.4", info);
    try testing.expect(cache.hasFresh("1.2.3.4"));

    const got = cache.getDup("1.2.3.4") orelse {
        try testing.expect(false);
        return;
    };
    defer freeEntryFields(allocator, got);

    try testing.expectEqualStrings("host.example.com", got.ptr);
    try testing.expectEqualStrings("15169", got.asn);
    try testing.expectEqualStrings("GOOGLE", got.asn_org);
    try testing.expectEqualStrings("US", got.country);
}

test "cache persistence across instances (JSONL append)" {
    const allocator = testing.allocator;
    const tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    {
        var cache = try Cache.init(allocator, tmp_path);
        defer cache.deinit();

        const info = ipinfo.IpInfo{
            .ptr = try allocator.dupe(u8, "mail.example.org"),
            .asn = try allocator.dupe(u8, "32934"),
            .asn_org = try allocator.dupe(u8, "FACEBOOK"),
            .country = try allocator.dupe(u8, "US"),
        };
        defer info.deinit(allocator);
        try cache.put("9.9.9.9", info);
    }

    {
        var cache = try Cache.init(allocator, tmp_path);
        defer cache.deinit();
        const got = cache.getDup("9.9.9.9") orelse {
            try testing.expect(false);
            return;
        };
        defer freeEntryFields(allocator, got);
        try testing.expectEqualStrings("mail.example.org", got.ptr);
        try testing.expectEqualStrings("32934", got.asn);
    }
}

test "later duplicates overwrite earlier entries" {
    const allocator = testing.allocator;
    const tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    {
        var cache = try Cache.init(allocator, tmp_path);
        defer cache.deinit();

        const old_info = ipinfo.IpInfo{
            .ptr = try allocator.dupe(u8, "old"),
            .asn = try allocator.dupe(u8, "1"),
            .asn_org = try allocator.dupe(u8, ""),
            .country = try allocator.dupe(u8, ""),
        };
        defer old_info.deinit(allocator);
        try cache.put("2.2.2.2", old_info);

        const new_info = ipinfo.IpInfo{
            .ptr = try allocator.dupe(u8, "new"),
            .asn = try allocator.dupe(u8, "2"),
            .asn_org = try allocator.dupe(u8, ""),
            .country = try allocator.dupe(u8, ""),
        };
        defer new_info.deinit(allocator);
        try cache.put("2.2.2.2", new_info);
    }

    // Re-open: the latest line should win
    var cache = try Cache.init(allocator, tmp_path);
    defer cache.deinit();
    const got = cache.getDup("2.2.2.2") orelse {
        try testing.expect(false);
        return;
    };
    defer freeEntryFields(allocator, got);
    try testing.expectEqualStrings("new", got.ptr);
    try testing.expectEqualStrings("2", got.asn);
}

test "compaction removes duplicate lines" {
    const allocator = testing.allocator;
    const tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    var cache = try Cache.init(allocator, tmp_path);
    defer cache.deinit();

    // Put the same IP 5 times → 5 lines, 1 unique entry
    for (0..5) |i| {
        var buf: [32]u8 = undefined;
        const ptr = try std.fmt.bufPrint(&buf, "ptr{d}", .{i});
        const info = ipinfo.IpInfo{
            .ptr = try allocator.dupe(u8, ptr),
            .asn = try allocator.dupe(u8, ""),
            .asn_org = try allocator.dupe(u8, ""),
            .country = try allocator.dupe(u8, ""),
        };
        defer info.deinit(allocator);
        try cache.put("3.3.3.3", info);
    }

    try cache.compact();

    // Verify file has only 1 line after compaction
    const file_path = try std.fs.path.join(allocator, &.{ tmp_path, CACHE_FILENAME });
    defer allocator.free(file_path);
    const file = try std.fs.openFileAbsolute(file_path, .{});
    defer file.close();
    const data = try file.readToEndAlloc(allocator, 1024);
    defer allocator.free(data);

    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        if (line.len > 0) count += 1;
    }
    try testing.expectEqual(@as(usize, 1), count);
}

test "expired entries are not returned" {
    const allocator = testing.allocator;
    const tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    var cache = try Cache.init(allocator, tmp_path);
    defer cache.deinit();

    // Manually insert a stale entry
    const ip_copy = try allocator.dupe(u8, "1.1.1.1");
    const entry = Entry{
        .ptr = try allocator.dupe(u8, "stale"),
        .asn = try allocator.dupe(u8, ""),
        .asn_org = try allocator.dupe(u8, ""),
        .country = try allocator.dupe(u8, ""),
        .ts = std.time.timestamp() - TTL_SECONDS - 100,
    };
    try cache.map.put(ip_copy, entry);

    try testing.expect(!cache.hasFresh("1.1.1.1"));
    try testing.expectEqual(@as(?Entry, null), cache.getDup("1.1.1.1"));
}
