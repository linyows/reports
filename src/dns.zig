const std = @import("std");
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("netdb.h");
    @cInclude("sys/socket.h");
    @cInclude("netinet/in.h");
    @cInclude("arpa/inet.h");
});

pub fn reverseLookup(allocator: Allocator, ip: []const u8) ![]const u8 {
    const ip_z = try allocator.dupeZ(u8, ip);
    defer allocator.free(ip_z);

    // Try IPv4 first, then IPv6
    var sa: c.struct_sockaddr_storage = std.mem.zeroes(c.struct_sockaddr_storage);
    var sa_len: c.socklen_t = 0;

    if (tryParseIpv4(ip_z, &sa, &sa_len)) {
        // ok
    } else if (tryParseIpv6(ip_z, &sa, &sa_len)) {
        // ok
    } else {
        return try allocator.dupe(u8, "");
    }

    var host: [1025]u8 = undefined;
    const rc = c.getnameinfo(
        @ptrCast(&sa),
        sa_len,
        &host,
        host.len,
        null,
        0,
        0,
    );

    if (rc != 0) {
        return try allocator.dupe(u8, "");
    }

    return try allocator.dupe(u8, std.mem.span(@as([*:0]const u8, @ptrCast(&host))));
}

fn tryParseIpv4(ip: [*:0]const u8, sa: *c.struct_sockaddr_storage, len: *c.socklen_t) bool {
    var addr4: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    if (c.inet_pton(c.AF_INET, ip, &addr4.sin_addr) == 1) {
        addr4.sin_family = c.AF_INET;
        const bytes: [*]const u8 = @ptrCast(&addr4);
        const dest: [*]u8 = @ptrCast(sa);
        @memcpy(dest[0..@sizeOf(c.struct_sockaddr_in)], bytes[0..@sizeOf(c.struct_sockaddr_in)]);
        len.* = @sizeOf(c.struct_sockaddr_in);
        return true;
    }
    return false;
}

fn tryParseIpv6(ip: [*:0]const u8, sa: *c.struct_sockaddr_storage, len: *c.socklen_t) bool {
    var addr6: c.struct_sockaddr_in6 = std.mem.zeroes(c.struct_sockaddr_in6);
    if (c.inet_pton(c.AF_INET6, ip, &addr6.sin6_addr) == 1) {
        addr6.sin6_family = c.AF_INET6;
        const bytes: [*]const u8 = @ptrCast(&addr6);
        const dest: [*]u8 = @ptrCast(sa);
        @memcpy(dest[0..@sizeOf(c.struct_sockaddr_in6)], bytes[0..@sizeOf(c.struct_sockaddr_in6)]);
        len.* = @sizeOf(c.struct_sockaddr_in6);
        return true;
    }
    return false;
}
