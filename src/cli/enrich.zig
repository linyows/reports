const std = @import("std");
const reports = @import("reports");
const ui = @import("ui.zig");

pub const CachedIpInfo = struct {
    ptr: []const u8,
    asn: []const u8,
    asn_org: []const u8,
    country: []const u8,

    pub fn deinit(self: *const CachedIpInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.ptr);
        allocator.free(self.asn);
        allocator.free(self.asn_org);
        allocator.free(self.country);
    }
};

pub fn lookupCached(allocator: std.mem.Allocator, cache: *std.StringHashMap(CachedIpInfo), ip: []const u8) *const CachedIpInfo {
    if (cache.getPtr(ip)) |existing| return existing;

    const info = reports.ipinfo.lookup(allocator, ip);
    const entry = CachedIpInfo{
        .ptr = info.ptr,
        .asn = info.asn,
        .asn_org = info.asn_org,
        .country = info.country,
    };
    cache.put(ip, entry) catch {
        entry.deinit(allocator);
        const S = struct {
            const empty = CachedIpInfo{ .ptr = "", .asn = "", .asn_org = "", .country = "" };
        };
        return &S.empty;
    };
    return cache.getPtr(ip).?;
}

pub fn writeTlsEnrichLine(buf: *[512]u8, info: *const CachedIpInfo, source_ip: []const u8) void {
    ui.stdout_file.writeAll(ui.dim) catch {};
    ui.stdout_file.writeAll("      \xe2\x86\x92 ") catch {};

    if (info.ptr.len > 0 and !std.mem.eql(u8, info.ptr, source_ip)) {
        ui.stdout_file.writeAll(info.ptr) catch {};
    } else {
        ui.stdout_file.writeAll("(no PTR)") catch {};
    }

    if (info.asn.len > 0) {
        const asn_part = std.fmt.bufPrint(buf, " | AS{s}", .{info.asn}) catch "";
        ui.stdout_file.writeAll(asn_part) catch {};
        if (info.asn_org.len > 0) {
            ui.stdout_file.writeAll(" ") catch {};
            ui.stdout_file.writeAll(info.asn_org) catch {};
        }
    }

    if (info.country.len > 0) {
        ui.stdout_file.writeAll(" | ") catch {};
        ui.stdout_file.writeAll(info.country) catch {};
    }

    ui.stdout_file.writeAll(ui.reset) catch {};
    ui.stdout_file.writeAll("\n") catch {};
}

pub fn buildFromColumnAlloc(allocator: std.mem.Allocator, header_from: []const u8, envelope_from: []const u8) ![]const u8 {
    if (envelope_from.len == 0 or std.mem.eql(u8, envelope_from, header_from)) {
        return try allocator.dupe(u8, header_from);
    }
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ header_from, envelope_from });
}

pub fn buildAsnColumn(allocator: std.mem.Allocator, info: *const CachedIpInfo) ![]const u8 {
    if (info.asn.len == 0) return try allocator.dupe(u8, "-");
    if (info.asn_org.len > 0) {
        return std.fmt.allocPrint(allocator, "AS{s} {s}", .{ info.asn, info.asn_org });
    }
    return std.fmt.allocPrint(allocator, "AS{s}", .{info.asn});
}

// --- Tests ---

test "buildFromColumnAlloc merges header and envelope from" {
    const allocator = std.testing.allocator;

    const same = try buildFromColumnAlloc(allocator, "example.com", "example.com");
    defer allocator.free(same);
    try std.testing.expectEqualStrings("example.com", same);

    const empty_ef = try buildFromColumnAlloc(allocator, "example.com", "");
    defer allocator.free(empty_ef);
    try std.testing.expectEqualStrings("example.com", empty_ef);

    const diff = try buildFromColumnAlloc(allocator, "example.com", "bounce.example.com");
    defer allocator.free(diff);
    try std.testing.expectEqualStrings("example.com/bounce.example.com", diff);
}
