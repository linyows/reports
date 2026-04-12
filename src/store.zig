const std = @import("std");
const Allocator = std.mem.Allocator;
const zlug = @import("zlug");
const dmarc = @import("dmarc.zig");
const mtasts = @import("mtasts.zig");

pub const ReportType = enum {
    dmarc,
    tlsrpt,
};

pub const ReportEntry = struct {
    report_type: ReportType,
    account_name: []const u8,
    org_name: []const u8,
    report_id: []const u8,
    date_begin: []const u8,
    date_end: []const u8,
    domain: []const u8,
    policy: []const u8,
    filename: []const u8,
};

pub const Store = struct {
    allocator: Allocator,
    data_dir: []const u8,
    account_name: []const u8,

    pub fn init(allocator: Allocator, data_dir: []const u8, account_name: []const u8) Store {
        return .{ .allocator = allocator, .data_dir = data_dir, .account_name = account_name };
    }

    pub fn saveDmarcReport(self: *const Store, report: *const dmarc.Report) !void {
        const dir = try std.fs.path.join(self.allocator, &.{ self.data_dir, self.account_name, "dmarc" });
        defer self.allocator.free(dir);

        const filename = try hashFilename(self.allocator, report.metadata.org_name, report.metadata.report_id);
        defer self.allocator.free(filename);

        const path = try std.fs.path.join(self.allocator, &.{ dir, filename });
        defer self.allocator.free(path);

        const json = try report.toJson(self.allocator);
        defer self.allocator.free(json);

        const file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();
        try file.writeAll(json);
    }

    pub fn saveTlsReport(self: *const Store, report: *const mtasts.Report) !void {
        const dir = try std.fs.path.join(self.allocator, &.{ self.data_dir, self.account_name, "tlsrpt" });
        defer self.allocator.free(dir);

        const filename = try hashFilename(self.allocator, report.organization_name, report.report_id);
        defer self.allocator.free(filename);

        const path = try std.fs.path.join(self.allocator, &.{ dir, filename });
        defer self.allocator.free(path);

        const json = try report.toJson(self.allocator);
        defer self.allocator.free(json);

        const file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();
        try file.writeAll(json);
    }

    pub fn loadFetchedUids(self: *const Store) !std.AutoHashMap(u32, void) {
        var set = std.AutoHashMap(u32, void).init(self.allocator);

        const path = try std.fs.path.join(self.allocator, &.{ self.data_dir, self.account_name, ".fetched_uids" });
        defer self.allocator.free(path);

        const file = std.fs.openFileAbsolute(path, .{}) catch return set;
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 1 * 1024 * 1024) catch return set;
        defer self.allocator.free(content);

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \r");
            if (trimmed.len == 0) continue;
            const uid = std.fmt.parseInt(u32, trimmed, 10) catch continue;
            set.put(uid, {}) catch continue;
        }

        return set;
    }

    pub fn markUidFetched(self: *const Store, uid: u32) void {
        const path = std.fs.path.join(self.allocator, &.{ self.data_dir, self.account_name, ".fetched_uids" }) catch return;
        defer self.allocator.free(path);

        const file = std.fs.createFileAbsolute(path, .{ .truncate = false }) catch return;
        defer file.close();
        file.seekFromEnd(0) catch {};

        var buf: [16]u8 = undefined;
        const uid_str = std.fmt.bufPrint(&buf, "{d}\n", .{uid}) catch return;
        file.writeAll(uid_str) catch {};
    }

    pub fn listReports(self: *const Store) ![]ReportEntry {
        var entries: std.ArrayList(ReportEntry) = .empty;

        try self.scanDir("dmarc", .dmarc, &entries);
        try self.scanDir("tlsrpt", .tlsrpt, &entries);

        sortByDateDesc(entries.items);

        return entries.toOwnedSlice(self.allocator);
    }

    pub fn loadDmarcReport(self: *const Store, filename: []const u8) ![]const u8 {
        const path = try std.fs.path.join(self.allocator, &.{ self.data_dir, self.account_name, "dmarc", filename });
        defer self.allocator.free(path);

        const file = try std.fs.openFileAbsolute(path, .{});
        defer file.close();
        return file.readToEndAlloc(self.allocator, 10 * 1024 * 1024);
    }

    pub fn loadTlsReport(self: *const Store, filename: []const u8) ![]const u8 {
        const path = try std.fs.path.join(self.allocator, &.{ self.data_dir, self.account_name, "tlsrpt", filename });
        defer self.allocator.free(path);

        const file = try std.fs.openFileAbsolute(path, .{});
        defer file.close();
        return file.readToEndAlloc(self.allocator, 10 * 1024 * 1024);
    }

    fn scanDir(self: *const Store, subdir: []const u8, report_type: ReportType, entries: *std.ArrayList(ReportEntry)) !void {
        const dir_path = try std.fs.path.join(self.allocator, &.{ self.data_dir, self.account_name, subdir });
        defer self.allocator.free(dir_path);

        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch return;
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".json")) continue;

            const data = blk: {
                const file = dir.openFile(entry.name, .{}) catch continue;
                defer file.close();
                break :blk file.readToEndAlloc(self.allocator, 10 * 1024 * 1024) catch continue;
            };
            defer self.allocator.free(data);

            const re = parseEntryFromJson(self.allocator, data, report_type, self.account_name, entry.name) catch continue;
            try entries.append(self.allocator, re);
        }
    }
};

/// List reports across all accounts, sorted by date descending.
pub fn listAllReports(allocator: Allocator, data_dir: []const u8, account_names: []const []const u8) ![]ReportEntry {
    var all: std.ArrayList(ReportEntry) = .empty;

    for (account_names) |name| {
        const st = Store.init(allocator, data_dir, name);
        const entries = try st.listReports();
        defer allocator.free(entries);
        for (entries) |e| {
            try all.append(allocator, e);
        }
    }

    sortByDateDesc(all.items);

    return all.toOwnedSlice(allocator);
}

/// Migrate legacy flat directory layout to per-account layout.
/// Moves {data_dir}/dmarc/ and {data_dir}/tlsrpt/ into {data_dir}/default/.
pub fn migrateToAccountDirs(data_dir: []const u8) void {
    const allocator = std.heap.page_allocator;

    // Check if legacy dmarc/ dir exists at top level
    const legacy_dmarc = std.fs.path.join(allocator, &.{ data_dir, "dmarc" }) catch return;
    defer allocator.free(legacy_dmarc);

    const default_dir = std.fs.path.join(allocator, &.{ data_dir, "default" }) catch return;
    defer allocator.free(default_dir);

    // If default/ already exists or legacy dmarc/ doesn't exist, nothing to do
    std.fs.accessAbsolute(default_dir, .{}) catch {
        // default/ doesn't exist — check if legacy dirs do
        std.fs.accessAbsolute(legacy_dmarc, .{}) catch return;

        // Create default/ and move legacy dirs into it
        std.fs.makeDirAbsolute(default_dir) catch return;

        const target_dmarc = std.fs.path.join(allocator, &.{ default_dir, "dmarc" }) catch return;
        defer allocator.free(target_dmarc);
        std.fs.renameAbsolute(legacy_dmarc, target_dmarc) catch {};

        const legacy_tlsrpt = std.fs.path.join(allocator, &.{ data_dir, "tlsrpt" }) catch return;
        defer allocator.free(legacy_tlsrpt);
        const target_tlsrpt = std.fs.path.join(allocator, &.{ default_dir, "tlsrpt" }) catch return;
        defer allocator.free(target_tlsrpt);
        std.fs.renameAbsolute(legacy_tlsrpt, target_tlsrpt) catch {};

        return;
    };
    // default/ already exists, skip migration
}

pub fn freeReportEntries(allocator: Allocator, entries: []const ReportEntry) void {
    for (entries) |e| {
        allocator.free(e.account_name);
        allocator.free(e.org_name);
        allocator.free(e.report_id);
        allocator.free(e.date_begin);
        allocator.free(e.date_end);
        allocator.free(e.domain);
        allocator.free(e.policy);
        allocator.free(e.filename);
    }
    allocator.free(entries);
}

fn sortByDateDesc(items: []ReportEntry) void {
    std.mem.sortUnstable(ReportEntry, items, {}, struct {
        fn lessThan(_: void, a: ReportEntry, b: ReportEntry) bool {
            return std.mem.order(u8, a.date_begin, b.date_begin) == .gt;
        }
    }.lessThan);
}

fn parseEntryFromJson(allocator: Allocator, data: []const u8, report_type: ReportType, account_name: []const u8, filename: []const u8) !ReportEntry {
    switch (report_type) {
        .dmarc => {
            const parsed = try std.json.parseFromSlice(DmarcJson, allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            const j = parsed.value;

            return .{
                .report_type = .dmarc,
                .account_name = try allocator.dupe(u8, account_name),
                .org_name = try allocator.dupe(u8, j.metadata.org_name),
                .report_id = try allocator.dupe(u8, j.metadata.report_id),
                .date_begin = try formatTimestamp(allocator, j.metadata.date_begin),
                .date_end = try formatTimestamp(allocator, j.metadata.date_end),
                .domain = try allocator.dupe(u8, j.policy.domain),
                .policy = try allocator.dupe(u8, j.policy.policy),
                .filename = try allocator.dupe(u8, filename),
            };
        },
        .tlsrpt => {
            const parsed = try std.json.parseFromSlice(TlsJson, allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            const j = parsed.value;

            return .{
                .report_type = .tlsrpt,
                .account_name = try allocator.dupe(u8, account_name),
                .org_name = try allocator.dupe(u8, j.organization_name),
                .report_id = try allocator.dupe(u8, j.report_id),
                .date_begin = try formatIsoDatetime(allocator, j.start_datetime),
                .date_end = try formatIsoDatetime(allocator, j.end_datetime),
                .domain = try allocator.dupe(u8, if (j.policies.len > 0) j.policies[0].policy_domain else ""),
                .policy = try allocator.dupe(u8, if (j.policies.len > 0) j.policies[0].policy_type else ""),
                .filename = try allocator.dupe(u8, filename),
            };
        },
    }
}

const DmarcJson = struct {
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
};

const TlsJson = struct {
    organization_name: []const u8 = "",
    report_id: []const u8 = "",
    start_datetime: []const u8 = "",
    end_datetime: []const u8 = "",
    policies: []const struct {
        policy_domain: []const u8 = "",
        policy_type: []const u8 = "",
    } = &.{},
};

/// Generate a hash-based filename: {16-char hex}.json
fn hashFilename(allocator: Allocator, org: []const u8, report_id: []const u8) ![]const u8 {
    var hasher = std.hash.Fnv1a_64.init();
    hasher.update(org);
    hasher.update(":");
    hasher.update(report_id);
    const hash = hasher.final();
    return std.fmt.allocPrint(allocator, "{x:0>16}.json", .{hash});
}

fn formatTimestamp(allocator: Allocator, ts: i64) ![]const u8 {
    if (ts == 0) return try allocator.dupe(u8, "");
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = @intCast(ts) };
    const day = epoch.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const daytime = epoch.getDaySeconds();
    return std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}", .{
        year_day.year,
        @intFromEnum(month_day.month),
        month_day.day_index + 1,
        daytime.getHoursIntoDay(),
        daytime.getMinutesIntoHour(),
    });
}

/// Convert ISO 8601 datetime (e.g. "2026-04-10T00:00:00Z") to "YYYY-MM-DD HH:MM".
fn formatIsoDatetime(allocator: Allocator, iso: []const u8) ![]const u8 {
    // Expect at least "YYYY-MM-DDThh:mm"
    if (iso.len >= 16 and iso[10] == 'T') {
        return std.fmt.allocPrint(allocator, "{s} {s}", .{ iso[0..10], iso[11..16] });
    }
    // Already in the right format or unknown — return as-is
    return allocator.dupe(u8, iso);
}

// --- Tests ---

test "slugify org_name for filename" {
    const allocator = std.testing.allocator;

    const s1 = try zlug.slugifyAlloc(allocator, "google.com", .{});
    defer allocator.free(s1);
    try std.testing.expectEqualStrings("google-com", s1);

    const s2 = try zlug.slugifyAlloc(allocator, "Google Inc.", .{});
    defer allocator.free(s2);
    try std.testing.expectEqualStrings("google-inc", s2);

    const s3 = try zlug.slugifyAlloc(allocator, "日本語テスト Corp.", .{});
    defer allocator.free(s3);
    try std.testing.expectEqualStrings("ri-ben-yu-tesuto-corp", s3);
}

test "formatTimestamp formats correctly" {
    const allocator = std.testing.allocator;

    const ts1 = try formatTimestamp(allocator, 1699920000);
    defer allocator.free(ts1);
    try std.testing.expectEqualStrings("2023-11-14 00:00", ts1);

    const ts0 = try formatTimestamp(allocator, 0);
    defer allocator.free(ts0);
    try std.testing.expectEqualStrings("", ts0);
}

test "parseEntryFromJson parses dmarc entry with account" {
    const allocator = std.testing.allocator;
    const json =
        \\{"metadata":{"org_name":"google.com","report_id":"123","date_begin":1700000000,"date_end":1700086400},
        \\"policy":{"domain":"example.com"},"records":[]}
    ;

    const entry = try parseEntryFromJson(allocator, json, .dmarc, "personal", "test.json");
    defer {
        allocator.free(entry.account_name);
        allocator.free(entry.org_name);
        allocator.free(entry.report_id);
        allocator.free(entry.date_begin);
        allocator.free(entry.date_end);
        allocator.free(entry.domain);
        allocator.free(entry.policy);
        allocator.free(entry.filename);
    }

    try std.testing.expectEqualStrings("personal", entry.account_name);
    try std.testing.expectEqualStrings("google.com", entry.org_name);
    try std.testing.expectEqualStrings("example.com", entry.domain);
}

test "listReports sorts by date descending with account dirs" {
    const allocator = std.testing.allocator;

    var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpath(".", &tmp_buf);

    // Create account/dmarc and account/tlsrpt dirs
    try tmp_dir.dir.makePath("myacct/dmarc");
    try tmp_dir.dir.makePath("myacct/tlsrpt");

    const report_old =
        \\{"metadata":{"org_name":"a.com","report_id":"old","date_begin":1600000000,"date_end":1600086400},"policy":{"domain":"d.com"},"records":[]}
    ;
    const report_new =
        \\{"metadata":{"org_name":"b.com","report_id":"new","date_begin":1700000000,"date_end":1700086400},"policy":{"domain":"d.com"},"records":[]}
    ;

    var dmarc_dir = try tmp_dir.dir.openDir("myacct/dmarc", .{});
    defer dmarc_dir.close();

    var f1 = try dmarc_dir.createFile("old.json", .{});
    try f1.writeAll(report_old);
    f1.close();

    var f2 = try dmarc_dir.createFile("new.json", .{});
    try f2.writeAll(report_new);
    f2.close();

    const st = Store.init(allocator, tmp_path, "myacct");
    const entries = try st.listReports();
    defer freeReportEntries(allocator, entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("new", entries[0].report_id);
    try std.testing.expectEqualStrings("old", entries[1].report_id);
    try std.testing.expectEqualStrings("myacct", entries[0].account_name);
}

test "migrateToAccountDirs moves legacy dirs" {
    const allocator = std.testing.allocator;
    _ = allocator;

    const tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp_dir.dir.realpath(".", &tmp_buf);

    // Create legacy layout
    try tmp_dir.dir.makeDir("dmarc");
    try tmp_dir.dir.makeDir("tlsrpt");

    // Write a test file
    var dmarc_dir = try tmp_dir.dir.openDir("dmarc", .{});
    defer dmarc_dir.close();
    var f = try dmarc_dir.createFile("test.json", .{});
    try f.writeAll("{}");
    f.close();

    // Run migration
    migrateToAccountDirs(tmp_path);

    // Verify: default/dmarc/test.json should exist
    const result = tmp_dir.dir.openFile("default/dmarc/test.json", .{});
    try std.testing.expect(result != error.FileNotFound);
    if (result) |file| file.close() else |_| {}

    // Legacy dmarc/ should no longer exist
    const legacy = tmp_dir.dir.openDir("dmarc", .{});
    if (legacy) |*d| {
        var dir = d.*;
        dir.close();
        try std.testing.expect(false); // should not reach here
    } else |_| {}
}
