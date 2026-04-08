const std = @import("std");
const Allocator = std.mem.Allocator;
const dmarc = @import("dmarc.zig");
const mtasts = @import("mtasts.zig");

pub const ReportType = enum {
    dmarc,
    tlsrpt,
};

pub const ReportEntry = struct {
    report_type: ReportType,
    org_name: []const u8,
    report_id: []const u8,
    date_begin: []const u8,
    date_end: []const u8,
    domain: []const u8,
    filename: []const u8,
};

pub const Store = struct {
    allocator: Allocator,
    data_dir: []const u8,

    pub fn init(allocator: Allocator, data_dir: []const u8) Store {
        return .{ .allocator = allocator, .data_dir = data_dir };
    }

    pub fn saveDmarcReport(self: *const Store, report: *const dmarc.Report) !void {
        const dir = try std.fs.path.join(self.allocator, &.{ self.data_dir, "dmarc" });
        defer self.allocator.free(dir);

        const filename = try std.fmt.allocPrint(self.allocator, "{s}_{s}.json", .{
            report.metadata.org_name, report.metadata.report_id,
        });
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
        const dir = try std.fs.path.join(self.allocator, &.{ self.data_dir, "tlsrpt" });
        defer self.allocator.free(dir);

        const filename = try std.fmt.allocPrint(self.allocator, "{s}_{s}.json", .{
            report.organization_name, report.report_id,
        });
        defer self.allocator.free(filename);

        const path = try std.fs.path.join(self.allocator, &.{ dir, filename });
        defer self.allocator.free(path);

        const json = try report.toJson(self.allocator);
        defer self.allocator.free(json);

        const file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();
        try file.writeAll(json);
    }

    pub fn listReports(self: *const Store) ![]ReportEntry {
        var entries: std.ArrayList(ReportEntry) = .empty;

        try self.scanDir("dmarc", .dmarc, &entries);
        try self.scanDir("tlsrpt", .tlsrpt, &entries);

        // Sort by date descending
        std.mem.sortUnstable(ReportEntry, entries.items, {}, struct {
            fn lessThan(_: void, a: ReportEntry, b: ReportEntry) bool {
                return std.mem.order(u8, a.date_begin, b.date_begin) == .gt;
            }
        }.lessThan);

        return entries.toOwnedSlice(self.allocator);
    }

    pub fn loadDmarcReport(self: *const Store, filename: []const u8) ![]const u8 {
        const path = try std.fs.path.join(self.allocator, &.{ self.data_dir, "dmarc", filename });
        defer self.allocator.free(path);

        const file = try std.fs.openFileAbsolute(path, .{});
        defer file.close();
        return file.readToEndAlloc(self.allocator, 10 * 1024 * 1024);
    }

    pub fn loadTlsReport(self: *const Store, filename: []const u8) ![]const u8 {
        const path = try std.fs.path.join(self.allocator, &.{ self.data_dir, "tlsrpt", filename });
        defer self.allocator.free(path);

        const file = try std.fs.openFileAbsolute(path, .{});
        defer file.close();
        return file.readToEndAlloc(self.allocator, 10 * 1024 * 1024);
    }

    fn scanDir(self: *const Store, subdir: []const u8, report_type: ReportType, entries: *std.ArrayList(ReportEntry)) !void {
        const dir_path = try std.fs.path.join(self.allocator, &.{ self.data_dir, subdir });
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

            const re = parseEntryFromJson(self.allocator, data, report_type, entry.name) catch continue;
            try entries.append(self.allocator, re);
        }
    }
};

fn parseEntryFromJson(allocator: Allocator, data: []const u8, report_type: ReportType, filename: []const u8) !ReportEntry {
    switch (report_type) {
        .dmarc => {
            const parsed = try std.json.parseFromSlice(DmarcJson, allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            const j = parsed.value;

            return .{
                .report_type = .dmarc,
                .org_name = try allocator.dupe(u8, j.metadata.org_name),
                .report_id = try allocator.dupe(u8, j.metadata.report_id),
                .date_begin = try formatTimestamp(allocator, j.metadata.date_begin),
                .date_end = try formatTimestamp(allocator, j.metadata.date_end),
                .domain = try allocator.dupe(u8, j.policy.domain),
                .filename = try allocator.dupe(u8, filename),
            };
        },
        .tlsrpt => {
            const parsed = try std.json.parseFromSlice(TlsJson, allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            const j = parsed.value;

            return .{
                .report_type = .tlsrpt,
                .org_name = try allocator.dupe(u8, j.organization_name),
                .report_id = try allocator.dupe(u8, j.report_id),
                .date_begin = try allocator.dupe(u8, j.start_datetime),
                .date_end = try allocator.dupe(u8, j.end_datetime),
                .domain = try allocator.dupe(u8, if (j.policies.len > 0) j.policies[0].policy_domain else ""),
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
    },
};

const TlsJson = struct {
    organization_name: []const u8 = "",
    report_id: []const u8 = "",
    start_datetime: []const u8 = "",
    end_datetime: []const u8 = "",
    policies: []const struct {
        policy_domain: []const u8 = "",
    } = &.{},
};

// --- Tests ---

test "formatTimestamp formats correctly" {
    const allocator = std.testing.allocator;

    // 2023-11-14 00:00 UTC = 1699920000
    const ts1 = try formatTimestamp(allocator, 1699920000);
    defer allocator.free(ts1);
    try std.testing.expectEqualStrings("2023-11-14 00:00", ts1);

    // Zero returns empty string
    const ts0 = try formatTimestamp(allocator, 0);
    defer allocator.free(ts0);
    try std.testing.expectEqualStrings("", ts0);

    // 2024-01-01 12:30 UTC = 1704109800
    const ts2 = try formatTimestamp(allocator, 1704109800);
    defer allocator.free(ts2);
    try std.testing.expectEqualStrings("2024-01-01 12:30", ts2);
}

test "parseEntryFromJson parses dmarc entry" {
    const allocator = std.testing.allocator;
    const json =
        \\{"metadata":{"org_name":"google.com","report_id":"123","date_begin":1700000000,"date_end":1700086400},
        \\"policy":{"domain":"example.com"},"records":[]}
    ;

    const entry = try parseEntryFromJson(allocator, json, .dmarc, "test.json");
    defer {
        allocator.free(entry.org_name);
        allocator.free(entry.report_id);
        allocator.free(entry.date_begin);
        allocator.free(entry.date_end);
        allocator.free(entry.domain);
        allocator.free(entry.filename);
    }

    try std.testing.expectEqualStrings("google.com", entry.org_name);
    try std.testing.expectEqualStrings("123", entry.report_id);
    try std.testing.expectEqualStrings("example.com", entry.domain);
    try std.testing.expectEqualStrings("test.json", entry.filename);
    try std.testing.expect(entry.date_begin.len > 0);
}

test "parseEntryFromJson parses tlsrpt entry" {
    const allocator = std.testing.allocator;
    const json =
        \\{"organization_name":"yahoo.com","report_id":"rpt-1",
        \\"start_datetime":"2024-01-01","end_datetime":"2024-01-02",
        \\"policies":[{"policy_domain":"test.com"}]}
    ;

    const entry = try parseEntryFromJson(allocator, json, .tlsrpt, "tls.json");
    defer {
        allocator.free(entry.org_name);
        allocator.free(entry.report_id);
        allocator.free(entry.date_begin);
        allocator.free(entry.date_end);
        allocator.free(entry.domain);
        allocator.free(entry.filename);
    }

    try std.testing.expectEqualStrings("yahoo.com", entry.org_name);
    try std.testing.expectEqualStrings("rpt-1", entry.report_id);
    try std.testing.expectEqualStrings("test.com", entry.domain);
}

test "listReports sorts by date descending" {
    const allocator = std.testing.allocator;

    // Create temp directory
    var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpath(".", &tmp_buf);

    // Create dmarc and tlsrpt subdirs
    try tmp_dir.dir.makeDir("dmarc");
    try tmp_dir.dir.makeDir("tlsrpt");

    // Write test reports with different dates
    const report_old =
        \\{"metadata":{"org_name":"a.com","report_id":"old","date_begin":1600000000,"date_end":1600086400},"policy":{"domain":"d.com"},"records":[]}
    ;
    const report_new =
        \\{"metadata":{"org_name":"b.com","report_id":"new","date_begin":1700000000,"date_end":1700086400},"policy":{"domain":"d.com"},"records":[]}
    ;
    const report_mid =
        \\{"metadata":{"org_name":"c.com","report_id":"mid","date_begin":1650000000,"date_end":1650086400},"policy":{"domain":"e.com"},"records":[]}
    ;

    var dmarc_dir = try tmp_dir.dir.openDir("dmarc", .{});
    defer dmarc_dir.close();

    var f1 = try dmarc_dir.createFile("old.json", .{});
    try f1.writeAll(report_old);
    f1.close();

    var f2 = try dmarc_dir.createFile("new.json", .{});
    try f2.writeAll(report_new);
    f2.close();

    var f3 = try dmarc_dir.createFile("mid.json", .{});
    try f3.writeAll(report_mid);
    f3.close();

    const st = Store.init(allocator, tmp_path);
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

    try std.testing.expectEqual(@as(usize, 3), entries.len);
    // Should be sorted newest first
    try std.testing.expectEqualStrings("new", entries[0].report_id);
    try std.testing.expectEqualStrings("mid", entries[1].report_id);
    try std.testing.expectEqualStrings("old", entries[2].report_id);
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
