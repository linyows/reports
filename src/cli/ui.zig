const std = @import("std");

pub const neon_yellow = "\x1b[38;2;194;255;38m";
pub const warn_yellow = "\x1b[38;2;255;200;0m";
pub const fail_red = "\x1b[38;2;255;51;102m";
pub const dim = "\x1b[2m";
pub const reset = "\x1b[0m";

pub const section_prefix = " " ++ neon_yellow ++ "●" ++ reset ++ " ";
pub const branch_prefix = "   " ++ dim ++ "⎿" ++ reset ++ "  ";
pub const detail_prefix = "      ";

pub const stdout_file = std.fs.File.stdout();
pub const stderr_file = std.fs.File.stderr();

pub const ColSpec = struct {
    val: []const u8,
    width: usize,
    is_emoji: bool = false,
    color: ?[]const u8 = null,
};

pub fn evalColor(val: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, val, "pass")) return neon_yellow;
    if (std.mem.eql(u8, val, "fail")) return fail_red;
    return null;
}

pub fn writeTableRow(allocator: std.mem.Allocator, cols: []const ColSpec) !void {
    for (cols, 0..) |col, i| {
        if (i > 0) stdout_file.writeAll(" ") catch {};

        if (col.is_emoji) {
            stdout_file.writeAll(col.val) catch {};
            const display_w = flagDisplayWidth(col.val);
            if (display_w < col.width) {
                const pad = allocator.alloc(u8, col.width - display_w) catch continue;
                defer allocator.free(pad);
                @memset(pad, ' ');
                stdout_file.writeAll(pad) catch {};
            }
        } else {
            const text = truncate(col.val, col.width);
            if (col.color) |c| stdout_file.writeAll(c) catch {};
            stdout_file.writeAll(text) catch {};
            if (col.color != null) stdout_file.writeAll(reset) catch {};
            if (text.len < col.width) {
                const pad = allocator.alloc(u8, col.width - text.len) catch continue;
                defer allocator.free(pad);
                @memset(pad, ' ');
                stdout_file.writeAll(pad) catch {};
            }
        }
    }
    stdout_file.writeAll("\n") catch {};
}

pub fn writeSepRow(allocator: std.mem.Allocator, widths: []const usize) !void {
    for (widths, 0..) |w, i| {
        if (i > 0) stdout_file.writeAll(" ") catch {};
        const sep = allocator.alloc(u8, w) catch continue;
        defer allocator.free(sep);
        @memset(sep, '-');
        stdout_file.writeAll(sep) catch {};
    }
    stdout_file.writeAll("\n") catch {};
}

pub fn flagDisplayWidth(s: []const u8) usize {
    if (s.len == 0 or std.mem.eql(u8, s, "-")) return s.len;
    if (s.len >= 8) return 2;
    if (s.len >= 4) return 1;
    return s.len;
}

pub fn truncate(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    return s[0..max];
}

/// Convert a 2-letter country code to a flag emoji (Regional Indicator Symbols).
/// "US" → 🇺🇸 (U+1F1FA U+1F1F8), each code point is 4 bytes in UTF-8.
pub fn countryFlag(allocator: std.mem.Allocator, cc: []const u8) ![]const u8 {
    if (cc.len < 2) return try allocator.dupe(u8, "-");

    const c0 = std.ascii.toUpper(cc[0]);
    const c1 = std.ascii.toUpper(cc[1]);
    if (c0 < 'A' or c0 > 'Z' or c1 < 'A' or c1 > 'Z') {
        return try allocator.dupe(u8, "-");
    }

    const ri0: u21 = 0x1F1E6 + @as(u21, c0 - 'A');
    const ri1: u21 = 0x1F1E6 + @as(u21, c1 - 'A');

    var buf0: [4]u8 = undefined;
    var buf1: [4]u8 = undefined;
    const len0: usize = std.unicode.utf8Encode(ri0, &buf0) catch return try allocator.dupe(u8, "-");
    const len1: usize = std.unicode.utf8Encode(ri1, &buf1) catch return try allocator.dupe(u8, "-");
    var result: [8]u8 = undefined;
    @memcpy(result[0..len0], buf0[0..len0]);
    @memcpy(result[len0 .. len0 + len1], buf1[0..len1]);
    return try allocator.dupe(u8, result[0 .. len0 + len1]);
}

// --- Tests ---

test "evalColor returns green for pass" {
    const color = evalColor("pass");
    try std.testing.expect(color != null);
    try std.testing.expectEqualStrings(neon_yellow, color.?);
}

test "evalColor returns red for fail" {
    const color = evalColor("fail");
    try std.testing.expect(color != null);
    try std.testing.expectEqualStrings(fail_red, color.?);
}

test "evalColor returns null for other values" {
    try std.testing.expect(evalColor("none") == null);
    try std.testing.expect(evalColor("") == null);
    try std.testing.expect(evalColor("softfail") == null);
}

test "section_prefix contains colored bullet" {
    try std.testing.expect(std.mem.indexOf(u8, section_prefix, "●") != null);
    try std.testing.expect(std.mem.startsWith(u8, section_prefix, " "));
    try std.testing.expect(std.mem.indexOf(u8, section_prefix, neon_yellow) != null);
}

test "branch_prefix contains dim branch character" {
    try std.testing.expect(std.mem.indexOf(u8, branch_prefix, "⎿") != null);
    try std.testing.expect(std.mem.indexOf(u8, branch_prefix, dim) != null);
    try std.testing.expect(std.mem.indexOf(u8, branch_prefix, reset) != null);
}

test "detail_prefix is six spaces" {
    try std.testing.expectEqualStrings("      ", detail_prefix);
    try std.testing.expectEqual(@as(usize, 6), detail_prefix.len);
}

test "countryFlag converts country code to flag emoji" {
    const allocator = std.testing.allocator;

    const us = try countryFlag(allocator, "US");
    defer allocator.free(us);
    try std.testing.expectEqualStrings("\xf0\x9f\x87\xba\xf0\x9f\x87\xb8", us);

    const jp = try countryFlag(allocator, "JP");
    defer allocator.free(jp);
    try std.testing.expectEqualStrings("\xf0\x9f\x87\xaf\xf0\x9f\x87\xb5", jp);

    const de = try countryFlag(allocator, "de");
    defer allocator.free(de);
    try std.testing.expectEqualStrings("\xf0\x9f\x87\xa9\xf0\x9f\x87\xaa", de);
}

test "countryFlag returns dash for invalid input" {
    const allocator = std.testing.allocator;

    const short = try countryFlag(allocator, "U");
    defer allocator.free(short);
    try std.testing.expectEqualStrings("-", short);

    const empty = try countryFlag(allocator, "");
    defer allocator.free(empty);
    try std.testing.expectEqualStrings("-", empty);
}
