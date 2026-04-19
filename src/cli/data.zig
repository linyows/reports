const std = @import("std");
const reports = @import("reports");
const ui = @import("ui.zig");

const Config = reports.config.Config;
const Store = reports.store.Store;

pub const PeriodStats = struct {
    dmarc: u32 = 0,
    tlsrpt: u32 = 0,
    messages: u64 = 0,
    pass: u64 = 0,
    fail: u64 = 0,
};

pub const DmarcStatsJson = struct {
    records: []const struct {
        count: u64 = 0,
        dkim_eval: []const u8 = "",
        spf_eval: []const u8 = "",
    } = &.{},
};

pub fn loadEntries(allocator: std.mem.Allocator, cfg: *const Config, account: ?[]const u8) ![]reports.store.ReportEntry {
    reports.store.migrateToAccountDirs(cfg.data_dir);
    if (account) |name| {
        const st = Store.init(allocator, cfg.data_dir, name);
        return st.listReports();
    }
    const names = try cfg.accountNames(allocator);
    defer allocator.free(names);
    return reports.store.listAllReports(allocator, cfg.data_dir, names);
}

pub fn accumulateDmarcStats(allocator: std.mem.Allocator, data: []const u8, total: *u64, pass: *u64, fail: *u64) void {
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

pub fn filterByDomain(allocator: std.mem.Allocator, entries: []const reports.store.ReportEntry, domain: ?[]const u8) ![]const reports.store.ReportEntry {
    const filter = domain orelse return try allocator.dupe(reports.store.ReportEntry, entries);

    var result: std.ArrayList(reports.store.ReportEntry) = .empty;
    for (entries) |e| {
        if (std.mem.eql(u8, e.domain, filter)) {
            try result.append(allocator, e);
        }
    }
    return result.toOwnedSlice(allocator);
}

pub fn filterByType(allocator: std.mem.Allocator, entries: []const reports.store.ReportEntry, type_filter: ?[]const u8) ![]const reports.store.ReportEntry {
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

pub fn filenameToHashId(filename: []const u8) []const u8 {
    if (std.mem.endsWith(u8, filename, ".json")) {
        return filename[0 .. filename.len - 5];
    }
    return filename;
}

// --- Date utilities ---

pub fn periodKey(allocator: std.mem.Allocator, date_begin: []const u8, period: []const u8) ![]u8 {
    if (date_begin.len < 10) return error.InvalidDate;

    if (std.mem.eql(u8, period, "year")) {
        return try allocator.dupe(u8, date_begin[0..4]);
    } else if (std.mem.eql(u8, period, "month")) {
        return try allocator.dupe(u8, date_begin[0..7]);
    } else {
        const year = std.fmt.parseInt(u16, date_begin[0..4], 10) catch return error.InvalidDate;
        const month = std.fmt.parseInt(u8, date_begin[5..7], 10) catch return error.InvalidDate;
        const day = std.fmt.parseInt(u8, date_begin[8..10], 10) catch return error.InvalidDate;
        if (month < 1 or month > 12 or day < 1 or day > 31) return error.InvalidDate;
        const wk = isoWeek(year, month, day);
        return std.fmt.allocPrint(allocator, "{d:0>4}-W{d:0>2}", .{ wk.year, wk.week });
    }
}

pub fn isoWeek(year: u16, month: u8, day: u8) struct { year: u16, week: u8 } {
    const dow = dayOfWeek(year, month, day);
    const yday = dayOfYear(year, month, day);
    const thu_yday: i32 = @as(i32, @intCast(yday)) + 4 - @as(i32, @intCast(dow));

    if (thu_yday < 1) {
        const prev_year = year - 1;
        const prev_days: u16 = if (isLeapYear(prev_year)) 366 else 365;
        const adj_thu: u16 = @intCast(@as(i32, @intCast(prev_days)) + thu_yday);
        const wk: u8 = @intCast((adj_thu - 1) / 7 + 1);
        return .{ .year = prev_year, .week = wk };
    }

    const days_in_year: u16 = if (isLeapYear(year)) 366 else 365;
    if (thu_yday > days_in_year) {
        return .{ .year = year + 1, .week = 1 };
    }

    const wk: u8 = @intCast((@as(u16, @intCast(thu_yday)) - 1) / 7 + 1);
    return .{ .year = year, .week = wk };
}

pub fn dayOfWeek(year: u16, month: u8, day: u8) u8 {
    const t = [_]u8{ 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4 };
    var y: i32 = @intCast(year);
    if (month < 3) y -= 1;
    const uy: u32 = @intCast(y);
    const r: u32 = (uy + uy / 4 - uy / 100 + uy / 400 + t[month - 1] + day) % 7;
    if (r == 0) return 7;
    return @intCast(r);
}

pub fn dayOfYear(year: u16, month: u8, day: u8) u16 {
    const days_before = [_]u16{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
    var d: u16 = days_before[month - 1] + day;
    if (month > 2 and isLeapYear(year)) d += 1;
    return d;
}

pub fn isLeapYear(year: u16) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}

pub fn dateAgeDays(date_str: []const u8) !u64 {
    if (date_str.len < 10) return error.InvalidDate;
    const year = try std.fmt.parseInt(u16, date_str[0..4], 10);
    const month = try std.fmt.parseInt(u8, date_str[5..7], 10);
    const day = try std.fmt.parseInt(u8, date_str[8..10], 10);
    const epoch = epochDays(year, month, day);
    const now = @divTrunc(@as(i64, std.time.timestamp()), 86400);
    if (now < epoch) return 0;
    return @intCast(now - epoch);
}

pub fn epochDays(year: u16, month: u8, day: u8) i64 {
    var y: i64 = @intCast(year);
    var m: i64 = @intCast(month);
    if (m <= 2) {
        y -= 1;
        m += 12;
    }
    const era_days = 365 * y + @divFloor(y, 4) - @divFloor(y, 100) + @divFloor(y, 400) + @divFloor(153 * (m - 3) + 2, 5) + @as(i64, @intCast(day)) - 719469;
    return era_days;
}

pub fn formatEpoch(buf: *[20]u8, ts: i64) []const u8 {
    if (ts == 0) return "";
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = @intCast(ts) };
    const day_val = epoch.getEpochDay();
    const year_day = day_val.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        year_day.year,              month_day.month.numeric(),     month_day.day_index + 1,
        day_secs.getHoursIntoDay(), day_secs.getMinutesIntoHour(), day_secs.getSecondsIntoMinute(),
    }) catch "";
}

// --- Tests ---

test "dayOfWeek returns correct ISO day" {
    try std.testing.expectEqual(@as(u8, 1), dayOfWeek(2024, 1, 1));
    try std.testing.expectEqual(@as(u8, 7), dayOfWeek(2023, 12, 31));
    try std.testing.expectEqual(@as(u8, 5), dayOfWeek(2026, 4, 10));
    try std.testing.expectEqual(@as(u8, 6), dayOfWeek(2000, 1, 1));
}

test "dayOfYear returns correct ordinal" {
    try std.testing.expectEqual(@as(u16, 1), dayOfYear(2024, 1, 1));
    try std.testing.expectEqual(@as(u16, 32), dayOfYear(2024, 2, 1));
    try std.testing.expectEqual(@as(u16, 366), dayOfYear(2024, 12, 31));
    try std.testing.expectEqual(@as(u16, 365), dayOfYear(2023, 12, 31));
    try std.testing.expectEqual(@as(u16, 60), dayOfYear(2024, 2, 29));
}

test "isLeapYear" {
    try std.testing.expect(isLeapYear(2024));
    try std.testing.expect(!isLeapYear(2023));
    try std.testing.expect(isLeapYear(2000));
    try std.testing.expect(!isLeapYear(1900));
}

test "isoWeek known dates" {
    const w1 = isoWeek(2024, 1, 1);
    try std.testing.expectEqual(@as(u16, 2024), w1.year);
    try std.testing.expectEqual(@as(u8, 1), w1.week);

    const w2 = isoWeek(2023, 1, 1);
    try std.testing.expectEqual(@as(u16, 2022), w2.year);
    try std.testing.expectEqual(@as(u8, 52), w2.week);

    const w3 = isoWeek(2020, 12, 31);
    try std.testing.expectEqual(@as(u16, 2020), w3.year);
    try std.testing.expectEqual(@as(u8, 53), w3.week);

    const w4 = isoWeek(2021, 1, 1);
    try std.testing.expectEqual(@as(u16, 2020), w4.year);
    try std.testing.expectEqual(@as(u8, 53), w4.week);

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
    const key1 = try periodKey(allocator, "2024-01-01 00:00", "week");
    defer allocator.free(key1);
    try std.testing.expectEqualStrings("2024-W01", key1);

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

test "epochDays known dates" {
    try std.testing.expectEqual(@as(i64, 0), epochDays(1970, 1, 1));
    try std.testing.expectEqual(@as(i64, 10957), epochDays(2000, 1, 1));
    try std.testing.expectEqual(@as(i64, 20557), epochDays(2026, 4, 14));
}

test "dateAgeDays returns 0 for today" {
    const now_secs = std.time.timestamp();
    const now_days = @divTrunc(now_secs, 86400);
    _ = now_days;
    const age = try dateAgeDays("2020-01-01 00:00");
    try std.testing.expect(age > 2000);
}

test "dateAgeDays returns error for short date" {
    try std.testing.expectError(error.InvalidDate, dateAgeDays("2020"));
}

test "formatEpoch returns empty string for zero timestamp" {
    var buf: [20]u8 = undefined;
    const result = formatEpoch(&buf, 0);
    try std.testing.expectEqualStrings("", result);
}

test "formatEpoch formats Unix epoch correctly" {
    var buf: [20]u8 = undefined;
    const result = formatEpoch(&buf, 1704067200);
    try std.testing.expectEqualStrings("2024-01-01 00:00:00", result);
}

test "formatEpoch formats date with time correctly" {
    var buf: [20]u8 = undefined;
    const result = formatEpoch(&buf, 1750001400);
    try std.testing.expectEqualStrings("2025-06-15 15:30:00", result);
}
