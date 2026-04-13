const std = @import("std");
const Allocator = std.mem.Allocator;
const dns = @import("dns.zig");

const c = @cImport({
    @cInclude("sys/socket.h");
    @cInclude("netinet/in.h");
    @cInclude("arpa/inet.h");
    @cInclude("unistd.h");
    @cInclude("sys/time.h");
});

pub const IpInfo = struct {
    ptr: []const u8,
    asn: []const u8,
    asn_org: []const u8,
    country: []const u8,

    pub fn deinit(self: *const IpInfo, allocator: Allocator) void {
        allocator.free(self.ptr);
        allocator.free(self.asn);
        allocator.free(self.asn_org);
        allocator.free(self.country);
    }

    pub fn toJson(self: *const IpInfo, allocator: Allocator) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(self.*, .{})});
    }
};

pub fn lookup(allocator: Allocator, ip: []const u8) IpInfo {
    const ptr = dns.reverseLookup(allocator, ip) catch allocator.dupe(u8, "") catch return emptyInfo(allocator);

    if (isPrivateIp(ip)) {
        return .{
            .ptr = ptr,
            .asn = allocator.dupe(u8, "") catch return emptyInfoFree(allocator, ptr),
            .asn_org = allocator.dupe(u8, "") catch return emptyInfoFree(allocator, ptr),
            .country = allocator.dupe(u8, "") catch return emptyInfoFree(allocator, ptr),
        };
    }

    var asn: []const u8 = allocator.dupe(u8, "") catch return emptyInfoFree(allocator, ptr);
    var country: []const u8 = allocator.dupe(u8, "") catch {
        allocator.free(asn);
        return emptyInfoFree(allocator, ptr);
    };
    var asn_org: []const u8 = allocator.dupe(u8, "") catch {
        allocator.free(asn);
        allocator.free(country);
        return emptyInfoFree(allocator, ptr);
    };

    // Team Cymru origin query: <reversed-ip>.origin[6].asn.cymru.com
    if (buildOriginQuery(allocator, ip)) |origin_query| {
        defer allocator.free(origin_query);

        if (queryTxt(allocator, origin_query)) |txt| {
            defer allocator.free(txt);
            if (parseCymruOrigin(allocator, txt)) |parsed| {
                allocator.free(asn);
                asn = parsed.asn;
                allocator.free(country);
                country = parsed.country;
            }
        } else |_| {}
    } else |_| {}

    // ASN org query: AS<number>.asn.cymru.com
    if (asn.len > 0) {
        if (std.fmt.allocPrint(allocator, "AS{s}.asn.cymru.com", .{asn})) |asn_query| {
            defer allocator.free(asn_query);

            if (queryTxt(allocator, asn_query)) |txt| {
                defer allocator.free(txt);
                if (parseCymruAsnOrg(allocator, txt)) |org| {
                    allocator.free(asn_org);
                    asn_org = org;
                }
            } else |_| {}
        } else |_| {}
    }

    return .{
        .ptr = ptr,
        .asn = asn,
        .asn_org = asn_org,
        .country = country,
    };
}

fn allocEmpty(allocator: Allocator) []const u8 {
    return allocator.dupe(u8, "") catch &.{};
}

fn emptyInfo(allocator: Allocator) IpInfo {
    // Use zero-length slices from &.{} as fallback — these point to a valid
    // (but empty) static array. free() on a zero-length slice is a no-op in
    // GeneralPurposeAllocator and c_allocator, so deinit is safe.
    return .{
        .ptr = allocEmpty(allocator),
        .asn = allocEmpty(allocator),
        .asn_org = allocEmpty(allocator),
        .country = allocEmpty(allocator),
    };
}

fn emptyInfoFree(allocator: Allocator, ptr: []const u8) IpInfo {
    allocator.free(ptr);
    return emptyInfo(allocator);
}

// --- Private IP detection ---

pub fn isPrivateIp(ip: []const u8) bool {
    if (std.mem.indexOf(u8, ip, ":") != null) {
        return isPrivateIpv6(ip);
    }
    return isPrivateIpv4(ip);
}

fn isPrivateIpv4(ip: []const u8) bool {
    var parts: [4]u8 = undefined;
    var iter = std.mem.splitScalar(u8, ip, '.');
    var i: usize = 0;
    while (iter.next()) |part| {
        if (i >= 4) return false;
        parts[i] = std.fmt.parseInt(u8, part, 10) catch return false;
        i += 1;
    }
    if (i != 4) return false;

    // 10.0.0.0/8
    if (parts[0] == 10) return true;
    // 172.16.0.0/12
    if (parts[0] == 172 and parts[1] >= 16 and parts[1] <= 31) return true;
    // 192.168.0.0/16
    if (parts[0] == 192 and parts[1] == 168) return true;
    // 127.0.0.0/8
    if (parts[0] == 127) return true;
    // 169.254.0.0/16 (link-local)
    if (parts[0] == 169 and parts[1] == 254) return true;

    return false;
}

fn isPrivateIpv6(ip: []const u8) bool {
    // ::1 loopback
    if (std.mem.eql(u8, ip, "::1")) return true;
    // fe80::/10 link-local
    if (ip.len >= 4) {
        if (std.ascii.toLower(ip[0]) == 'f' and std.ascii.toLower(ip[1]) == 'e' and
            (std.ascii.toLower(ip[2]) == '8' or std.ascii.toLower(ip[2]) == '9' or
                std.ascii.toLower(ip[2]) == 'a' or std.ascii.toLower(ip[2]) == 'b'))
            return true;
    }
    // fc00::/7 unique local
    if (ip.len >= 2) {
        if (std.ascii.toLower(ip[0]) == 'f' and
            (std.ascii.toLower(ip[1]) == 'c' or std.ascii.toLower(ip[1]) == 'd'))
            return true;
    }
    return false;
}

// --- Team Cymru query builders ---

fn buildOriginQuery(allocator: Allocator, ip: []const u8) ![]const u8 {
    if (std.mem.indexOf(u8, ip, ":") != null) {
        return buildIpv6OriginQuery(allocator, ip);
    }
    return buildIpv4OriginQuery(allocator, ip);
}

fn buildIpv4OriginQuery(allocator: Allocator, ip: []const u8) ![]const u8 {
    var parts: [4][]const u8 = undefined;
    var iter = std.mem.splitScalar(u8, ip, '.');
    var i: usize = 0;
    while (iter.next()) |part| {
        if (i >= 4) return error.InvalidIp;
        parts[i] = part;
        i += 1;
    }
    if (i != 4) return error.InvalidIp;

    return std.fmt.allocPrint(allocator, "{s}.{s}.{s}.{s}.origin.asn.cymru.com", .{
        parts[3], parts[2], parts[1], parts[0],
    });
}

fn buildIpv6OriginQuery(allocator: Allocator, ip: []const u8) ![]const u8 {
    // Expand IPv6 to full 32-nibble hex, then reverse nibble-by-nibble
    var expanded: [32]u8 = undefined;
    try expandIpv6(ip, &expanded);

    // Reverse nibbles with dots: "2001..." → "...1.0.0.2"
    var buf: [64]u8 = undefined; // 32 nibbles + 31 dots = 63
    var pos: usize = 0;
    var j: usize = 32;
    while (j > 0) {
        j -= 1;
        buf[pos] = expanded[j];
        pos += 1;
        if (j > 0) {
            buf[pos] = '.';
            pos += 1;
        }
    }

    return std.fmt.allocPrint(allocator, "{s}.origin6.asn.cymru.com", .{buf[0..pos]});
}

fn expandIpv6(ip: []const u8, out: *[32]u8) !void {
    // Parse IPv6 address into 8 groups of 16 bits
    var groups: [8]u16 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
    var group_count: usize = 0;
    var double_colon_pos: ?usize = null;

    var iter = std.mem.splitSequence(u8, ip, ":");
    var idx: usize = 0;
    while (iter.next()) |part| {
        if (part.len == 0) {
            if (double_colon_pos == null) {
                double_colon_pos = idx;
            }
            continue;
        }
        if (idx >= 8) return error.InvalidIpv6;
        groups[idx] = std.fmt.parseInt(u16, part, 16) catch return error.InvalidIpv6;
        idx += 1;
        group_count += 1;
    }

    // If :: was found, shift groups to fill gaps
    if (double_colon_pos) |dcp| {
        const gap = 8 - group_count;
        // Move groups after :: to the end
        var i: usize = 7;
        var src: usize = group_count;
        while (src > dcp) {
            src -= 1;
            groups[i] = groups[src];
            groups[src] = 0;
            i -= 1;
        }
        _ = gap;
    }

    // Convert to hex nibbles
    for (groups, 0..) |g, gi| {
        out[gi * 4 + 0] = hexNibble(@intCast((g >> 12) & 0xf));
        out[gi * 4 + 1] = hexNibble(@intCast((g >> 8) & 0xf));
        out[gi * 4 + 2] = hexNibble(@intCast((g >> 4) & 0xf));
        out[gi * 4 + 3] = hexNibble(@intCast(g & 0xf));
    }
}

fn hexNibble(v: u4) u8 {
    return "0123456789abcdef"[v];
}

// --- Team Cymru response parsers ---

const CymruOrigin = struct {
    asn: []const u8,
    country: []const u8,
};

fn parseCymruOrigin(allocator: Allocator, txt: []const u8) ?CymruOrigin {
    // Format: "23456 | 1.2.3.0/24 | US | arin | 2006-01-01"
    var iter = std.mem.splitSequence(u8, txt, " | ");

    const asn_part = iter.next() orelse return null;
    _ = iter.next(); // prefix — skip
    const country_part = iter.next() orelse return null;

    const asn = allocator.dupe(u8, std.mem.trim(u8, asn_part, " \t\"")) catch return null;
    const country = allocator.dupe(u8, std.mem.trim(u8, country_part, " \t\"")) catch {
        allocator.free(asn);
        return null;
    };

    return .{ .asn = asn, .country = country };
}

fn parseCymruAsnOrg(allocator: Allocator, txt: []const u8) ?[]const u8 {
    // Format: "23456 | US | arin | 2006-01-01 | Google LLC"
    var iter = std.mem.splitSequence(u8, txt, " | ");
    _ = iter.next(); // ASN
    _ = iter.next(); // country
    _ = iter.next(); // RIR
    _ = iter.next(); // date
    const org_part = iter.next() orelse return null;

    const trimmed = std.mem.trim(u8, org_part, " \t\"\n\r");
    // Remove trailing comma variants
    const clean = std.mem.trimRight(u8, trimmed, ",");
    if (clean.len == 0) return null;

    return allocator.dupe(u8, clean) catch null;
}

// --- DNS TXT query via raw UDP ---

fn queryTxt(allocator: Allocator, name: []const u8) ![]const u8 {
    const ns_ip = getNameserver(allocator) catch try allocator.dupe(u8, "8.8.8.8");
    defer allocator.free(ns_ip);

    // Build DNS query packet
    var query_buf: [512]u8 = undefined;
    const query_len = try buildDnsQueryPacket(&query_buf, name);

    // Create UDP socket
    const sock = c.socket(c.AF_INET, c.SOCK_DGRAM, 0);
    if (sock < 0) return error.SocketError;
    defer _ = c.close(sock);

    // Set receive timeout to 3 seconds
    var tv: c.struct_timeval = undefined;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    _ = c.setsockopt(sock, c.SOL_SOCKET, c.SO_RCVTIMEO, @ptrCast(&tv), @sizeOf(c.struct_timeval));

    // Build destination address
    var addr: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    addr.sin_family = c.AF_INET;
    addr.sin_port = std.mem.nativeToBig(u16, 53);

    const ns_z = try allocator.dupeZ(u8, ns_ip);
    defer allocator.free(ns_z);
    if (c.inet_pton(c.AF_INET, ns_z.ptr, &addr.sin_addr) != 1) return error.InvalidNameserver;

    // Send query
    const send_result = c.sendto(
        sock,
        @ptrCast(&query_buf),
        @intCast(query_len),
        0,
        @ptrCast(&addr),
        @sizeOf(c.struct_sockaddr_in),
    );
    if (send_result < 0) return error.SendFailed;

    // Receive response
    var resp_buf: [4096]u8 = undefined;
    const recv_result = c.recvfrom(sock, @ptrCast(&resp_buf), resp_buf.len, 0, null, null);
    if (recv_result < 12) return error.RecvFailed;

    return parseTxtFromResponse(allocator, resp_buf[0..@intCast(recv_result)]);
}

fn buildDnsQueryPacket(buf: *[512]u8, name: []const u8) !usize {
    // Header (12 bytes)
    buf[0] = 0xAB;
    buf[1] = 0xCD; // Transaction ID
    buf[2] = 0x01;
    buf[3] = 0x00; // Flags: RD=1 (recursion desired)
    buf[4] = 0x00;
    buf[5] = 0x01; // QDCOUNT = 1
    buf[6] = 0x00;
    buf[7] = 0x00; // ANCOUNT = 0
    buf[8] = 0x00;
    buf[9] = 0x00; // NSCOUNT = 0
    buf[10] = 0x00;
    buf[11] = 0x00; // ARCOUNT = 0

    // Encode domain name
    var offset: usize = 12;
    var iter = std.mem.splitScalar(u8, name, '.');
    while (iter.next()) |label| {
        if (label.len == 0) continue;
        if (label.len > 63) return error.LabelTooLong;
        if (offset + 1 + label.len >= buf.len) return error.NameTooLong;
        buf[offset] = @intCast(label.len);
        offset += 1;
        @memcpy(buf[offset .. offset + label.len], label);
        offset += label.len;
    }
    buf[offset] = 0; // End of name
    offset += 1;

    // QTYPE = TXT (16)
    buf[offset] = 0x00;
    buf[offset + 1] = 0x10;
    offset += 2;

    // QCLASS = IN (1)
    buf[offset] = 0x00;
    buf[offset + 1] = 0x01;
    offset += 2;

    return offset;
}

fn parseTxtFromResponse(allocator: Allocator, data: []const u8) ![]const u8 {
    if (data.len < 12) return error.ResponseTooShort;

    // Check response flags for errors
    const flags = std.mem.readInt(u16, data[2..4], .big);
    const rcode = flags & 0x0F;
    if (rcode != 0) return error.DnsError;

    const qdcount = std.mem.readInt(u16, data[4..6], .big);
    const ancount = std.mem.readInt(u16, data[6..8], .big);

    if (ancount == 0) return error.NoAnswer;

    // Skip header
    var offset: usize = 12;

    // Skip question section
    for (0..qdcount) |_| {
        offset = try skipDnsName(data, offset);
        offset += 4; // QTYPE + QCLASS
    }

    // Parse first answer
    offset = try skipDnsName(data, offset);

    // TYPE(2) + CLASS(2) + TTL(4)
    if (offset + 10 > data.len) return error.ParseError;
    offset += 8;

    const rdlength = std.mem.readInt(u16, data[offset..][0..2], .big);
    offset += 2;

    if (offset + rdlength > data.len) return error.ParseError;

    // Parse TXT RDATA: concatenate all character-strings
    var txt: std.ArrayList(u8) = .empty;
    errdefer txt.deinit(allocator);
    var rdata_offset: usize = 0;
    while (rdata_offset < rdlength) {
        const txt_len: usize = data[offset + rdata_offset];
        rdata_offset += 1;
        if (rdata_offset + txt_len > rdlength) break;
        try txt.appendSlice(allocator, data[offset + rdata_offset .. offset + rdata_offset + txt_len]);
        rdata_offset += txt_len;
    }

    return txt.toOwnedSlice(allocator);
}

fn skipDnsName(data: []const u8, start: usize) !usize {
    var offset = start;
    while (offset < data.len) {
        const b = data[offset];
        if (b == 0) return offset + 1; // End of name
        if (b & 0xC0 == 0xC0) return offset + 2; // Compression pointer
        offset += 1 + @as(usize, b); // Skip label
    }
    return error.InvalidDnsName;
}

fn getNameserver(allocator: Allocator) ![]const u8 {
    const file = std.fs.openFileAbsolute("/etc/resolv.conf", .{}) catch
        return try allocator.dupe(u8, "8.8.8.8");
    defer file.close();

    const content = file.readToEndAlloc(allocator, 64 * 1024) catch
        return try allocator.dupe(u8, "8.8.8.8");
    defer allocator.free(content);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (std.mem.startsWith(u8, trimmed, "nameserver ")) {
            const ns = std.mem.trim(u8, trimmed["nameserver ".len..], " \t");
            if (ns.len > 0 and std.mem.indexOf(u8, ns, ":") == null) {
                // Only use IPv4 nameservers for our UDP client
                return try allocator.dupe(u8, ns);
            }
        }
    }

    return try allocator.dupe(u8, "8.8.8.8");
}

// --- Tests ---

test "isPrivateIp detects private addresses" {
    try std.testing.expect(isPrivateIp("10.0.0.1"));
    try std.testing.expect(isPrivateIp("10.255.255.255"));
    try std.testing.expect(isPrivateIp("172.16.0.1"));
    try std.testing.expect(isPrivateIp("172.31.255.255"));
    try std.testing.expect(isPrivateIp("192.168.0.1"));
    try std.testing.expect(isPrivateIp("192.168.255.255"));
    try std.testing.expect(isPrivateIp("127.0.0.1"));
    try std.testing.expect(isPrivateIp("169.254.1.1"));
    try std.testing.expect(isPrivateIp("::1"));
    try std.testing.expect(isPrivateIp("fe80::1"));
    try std.testing.expect(isPrivateIp("fc00::1"));
    try std.testing.expect(isPrivateIp("fd12::1"));
}

test "isPrivateIp rejects public addresses" {
    try std.testing.expect(!isPrivateIp("8.8.8.8"));
    try std.testing.expect(!isPrivateIp("1.1.1.1"));
    try std.testing.expect(!isPrivateIp("198.51.100.1"));
    try std.testing.expect(!isPrivateIp("203.0.113.5"));
    try std.testing.expect(!isPrivateIp("172.32.0.1"));
    try std.testing.expect(!isPrivateIp("2001:db8::1"));
}

test "buildIpv4OriginQuery reverses octets" {
    const allocator = std.testing.allocator;
    const q = try buildIpv4OriginQuery(allocator, "198.51.100.1");
    defer allocator.free(q);
    try std.testing.expectEqualStrings("1.100.51.198.origin.asn.cymru.com", q);
}

test "buildIpv6OriginQuery reverses nibbles" {
    const allocator = std.testing.allocator;
    const q = try buildIpv6OriginQuery(allocator, "2001:db8::1");
    defer allocator.free(q);
    try std.testing.expectEqualStrings(
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com",
        q,
    );
}

test "expandIpv6 full address" {
    var out: [32]u8 = undefined;
    try expandIpv6("2001:0db8:0000:0000:0000:0000:0000:0001", &out);
    try std.testing.expectEqualStrings("20010db8000000000000000000000001", &out);
}

test "expandIpv6 abbreviated" {
    var out: [32]u8 = undefined;
    try expandIpv6("2001:db8::1", &out);
    try std.testing.expectEqualStrings("20010db8000000000000000000000001", &out);
}

test "parseCymruOrigin parses response" {
    const allocator = std.testing.allocator;
    const result = parseCymruOrigin(allocator, "15169 | 8.8.8.0/24 | US | arin | 2023-01-01") orelse {
        try std.testing.expect(false);
        return;
    };
    defer allocator.free(result.asn);
    defer allocator.free(result.country);
    try std.testing.expectEqualStrings("15169", result.asn);
    try std.testing.expectEqualStrings("US", result.country);
}

test "parseCymruAsnOrg parses org name" {
    const allocator = std.testing.allocator;
    const org = parseCymruAsnOrg(allocator, "15169 | US | arin | 2000-03-30 | Google LLC, US") orelse {
        try std.testing.expect(false);
        return;
    };
    defer allocator.free(org);
    try std.testing.expectEqualStrings("Google LLC, US", org);
}

test "buildDnsQueryPacket basic" {
    var buf: [512]u8 = undefined;
    const len = try buildDnsQueryPacket(&buf, "example.com");
    // Header (12) + \x07example\x03com\x00 (13) + QTYPE(2) + QCLASS(2) = 29
    try std.testing.expectEqual(@as(usize, 29), len);
    // Verify RD flag
    try std.testing.expectEqual(@as(u8, 0x01), buf[2]);
    // Verify QTYPE = TXT (16)
    try std.testing.expectEqual(@as(u8, 0x10), buf[len - 3]);
}

test "skipDnsName handles normal labels" {
    // \x07example\x03com\x00
    const data = [_]u8{ 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00 };
    const end = try skipDnsName(&data, 0);
    try std.testing.expectEqual(@as(usize, 13), end);
}

test "skipDnsName handles compression pointer" {
    const data = [_]u8{ 0xC0, 0x0C };
    const end = try skipDnsName(&data, 0);
    try std.testing.expectEqual(@as(usize, 2), end);
}

test "getNameserver returns fallback" {
    const allocator = std.testing.allocator;
    // This test just verifies getNameserver doesn't crash
    const ns = getNameserver(allocator) catch try allocator.dupe(u8, "8.8.8.8");
    defer allocator.free(ns);
    try std.testing.expect(ns.len > 0);
}

test "lookup returns empty info for private IPs without network" {
    const allocator = std.testing.allocator;
    const info = lookup(allocator, "10.0.0.1");
    defer info.deinit(allocator);
    // Private IPs should skip Cymru lookup
    try std.testing.expectEqualStrings("", info.asn);
    try std.testing.expectEqualStrings("", info.asn_org);
    try std.testing.expectEqualStrings("", info.country);
}

test "emptyInfo can be safely deinit'd" {
    const allocator = std.testing.allocator;
    const info = emptyInfo(allocator);
    // Must not crash — verifies that zero-length slices are safe to free
    info.deinit(allocator);
}

test "toJson produces valid json" {
    const allocator = std.testing.allocator;
    const info = IpInfo{
        .ptr = try allocator.dupe(u8, "mail.example.com"),
        .asn = try allocator.dupe(u8, "15169"),
        .asn_org = try allocator.dupe(u8, "Google LLC"),
        .country = try allocator.dupe(u8, "US"),
    };
    defer info.deinit(allocator);

    const json = try info.toJson(allocator);
    defer allocator.free(json);

    // Verify it's valid JSON by parsing
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    // Verify field values
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("mail.example.com", obj.get("ptr").?.string);
    try std.testing.expectEqualStrings("15169", obj.get("asn").?.string);
    try std.testing.expectEqualStrings("Google LLC", obj.get("asn_org").?.string);
    try std.testing.expectEqualStrings("US", obj.get("country").?.string);
}

test "toJson escapes special characters" {
    const allocator = std.testing.allocator;
    const info = IpInfo{
        .ptr = try allocator.dupe(u8, "host\"with.quotes"),
        .asn = try allocator.dupe(u8, "123"),
        .asn_org = try allocator.dupe(u8, "Org\\Name"),
        .country = try allocator.dupe(u8, ""),
    };
    defer info.deinit(allocator);

    const json = try info.toJson(allocator);
    defer allocator.free(json);

    // Must be valid JSON even with special chars
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("host\"with.quotes", obj.get("ptr").?.string);
    try std.testing.expectEqualStrings("Org\\Name", obj.get("asn_org").?.string);
}

test "toJson handles empty fields" {
    const allocator = std.testing.allocator;
    const info = IpInfo{
        .ptr = try allocator.dupe(u8, ""),
        .asn = try allocator.dupe(u8, ""),
        .asn_org = try allocator.dupe(u8, ""),
        .country = try allocator.dupe(u8, ""),
    };
    defer info.deinit(allocator);

    const json = try info.toJson(allocator);
    defer allocator.free(json);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("", obj.get("ptr").?.string);
}

test "parseTxtFromResponse parses valid TXT response" {
    const allocator = std.testing.allocator;
    // Construct a minimal DNS response with a TXT record
    var resp: [128]u8 = undefined;
    var pos: usize = 0;

    // Header
    resp[0] = 0xAB;
    resp[1] = 0xCD; // Transaction ID
    resp[2] = 0x81;
    resp[3] = 0x80; // Flags: QR=1, RD=1, RA=1
    resp[4] = 0x00;
    resp[5] = 0x01; // QDCOUNT = 1
    resp[6] = 0x00;
    resp[7] = 0x01; // ANCOUNT = 1
    resp[8] = 0x00;
    resp[9] = 0x00;
    resp[10] = 0x00;
    resp[11] = 0x00;
    pos = 12;

    // Question: \x04test\x03com\x00 QTYPE=TXT QCLASS=IN
    resp[pos] = 0x04;
    @memcpy(resp[pos + 1 .. pos + 5], "test");
    resp[pos + 5] = 0x03;
    @memcpy(resp[pos + 6 .. pos + 9], "com");
    resp[pos + 9] = 0x00;
    pos += 10;
    resp[pos] = 0x00;
    resp[pos + 1] = 0x10; // QTYPE = TXT
    resp[pos + 2] = 0x00;
    resp[pos + 3] = 0x01; // QCLASS = IN
    pos += 4;

    // Answer: compression pointer to question name
    resp[pos] = 0xC0;
    resp[pos + 1] = 0x0C; // pointer to offset 12
    pos += 2;
    resp[pos] = 0x00;
    resp[pos + 1] = 0x10; // TYPE = TXT
    resp[pos + 2] = 0x00;
    resp[pos + 3] = 0x01; // CLASS = IN
    pos += 4;
    resp[pos] = 0x00;
    resp[pos + 1] = 0x00;
    resp[pos + 2] = 0x00;
    resp[pos + 3] = 0x3C; // TTL = 60
    pos += 4;

    // RDATA: TXT "hello world"
    const txt_data = "hello world";
    const rdlength: u16 = @intCast(1 + txt_data.len); // 1 byte length + string
    resp[pos] = @intCast(rdlength >> 8);
    resp[pos + 1] = @intCast(rdlength & 0xFF);
    pos += 2;
    resp[pos] = @intCast(txt_data.len); // character-string length
    pos += 1;
    @memcpy(resp[pos .. pos + txt_data.len], txt_data);
    pos += txt_data.len;

    const result = try parseTxtFromResponse(allocator, resp[0..pos]);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello world", result);
}

test "parseTxtFromResponse rejects NXDOMAIN" {
    // Header with RCODE=3 (NXDOMAIN)
    const resp = [_]u8{
        0xAB, 0xCD, // ID
        0x81, 0x83, // Flags: QR=1, RD=1, RA=1, RCODE=3
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00,
        0x00, 0x00,
        // Question section (minimal)
        0x01, 'x',
        0x00, 0x00,
        0x10, 0x00,
        0x01,
    };
    try std.testing.expectError(error.DnsError, parseTxtFromResponse(std.testing.allocator, &resp));
}

test "parseTxtFromResponse rejects no answers" {
    // Header with ANCOUNT=0 and RCODE=0
    const resp = [_]u8{
        0xAB, 0xCD, // ID
        0x81, 0x80, // Flags: QR=1, RD=1, RA=1, RCODE=0
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00,
        0x00, 0x00,
        0x01, 'x',
        0x00, 0x00,
        0x10, 0x00,
        0x01,
    };
    try std.testing.expectError(error.NoAnswer, parseTxtFromResponse(std.testing.allocator, &resp));
}

test "parseTxtFromResponse rejects truncated response" {
    const resp = [_]u8{ 0xAB, 0xCD, 0x81, 0x80 }; // Only 4 bytes
    try std.testing.expectError(error.ResponseTooShort, parseTxtFromResponse(std.testing.allocator, &resp));
}

test "parseCymruOrigin returns null for incomplete response" {
    const allocator = std.testing.allocator;
    // Only ASN, no prefix or country
    try std.testing.expect(parseCymruOrigin(allocator, "15169") == null);
    // ASN and prefix, but no country
    try std.testing.expect(parseCymruOrigin(allocator, "15169 | 8.8.8.0/24") == null);
}

test "parseCymruAsnOrg returns null for incomplete response" {
    const allocator = std.testing.allocator;
    // Only 3 pipe-separated fields (need 5)
    try std.testing.expect(parseCymruAsnOrg(allocator, "15169 | US | arin") == null);
    // 4 fields, still no org
    try std.testing.expect(parseCymruAsnOrg(allocator, "15169 | US | arin | 2000-01-01") == null);
}

test "parseCymruAsnOrg handles empty org name" {
    const allocator = std.testing.allocator;
    // 5th field is empty
    try std.testing.expect(parseCymruAsnOrg(allocator, "15169 | US | arin | 2000-01-01 | ") == null);
}
