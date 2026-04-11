const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Attachment = struct {
    filename: []const u8,
    content_type: []const u8,
    data: []const u8,
};

/// Extract attachments from a raw MIME email message.
pub fn extractAttachments(allocator: Allocator, raw: []const u8) ![]Attachment {
    var attachments: std.ArrayList(Attachment) = .empty;

    const boundary = findBoundary(raw) orelse {
        if (findBody(raw)) |body| {
            const ct = findHeaderValue(raw, "Content-Type") orelse "";
            if (isReportContentType(ct)) {
                const decoded = try decodeBody(allocator, body, findHeaderValue(raw, "Content-Transfer-Encoding"));
                try attachments.append(allocator, .{
                    .filename = try allocator.dupe(u8, "report"),
                    .content_type = try allocator.dupe(u8, ct),
                    .data = decoded,
                });
            }
        }
        return try attachments.toOwnedSlice(allocator);
    };

    var delim_buf: [256]u8 = undefined;
    const delim = std.fmt.bufPrint(&delim_buf, "--{s}", .{boundary}) catch boundary;
    var parts = std.mem.splitSequence(u8, raw, delim);
    _ = parts.next(); // preamble

    while (parts.next()) |part_raw| {
        const part = std.mem.trimLeft(u8, part_raw, "\r\n");
        if (part.len == 0 or std.mem.startsWith(u8, part, "--")) continue;

        const ct = findHeaderValue(part, "Content-Type") orelse "";
        const cte = findHeaderValue(part, "Content-Transfer-Encoding");
        const cd = findHeaderValue(part, "Content-Disposition");

        if (!isReportContentType(ct) and !isAttachmentDisposition(cd)) continue;

        const body = findBody(part) orelse continue;
        const decoded = try decodeBody(allocator, body, cte);
        const filename = extractFilename(cd) orelse "report";

        try attachments.append(allocator, .{
            .filename = try allocator.dupe(u8, filename),
            .content_type = try allocator.dupe(u8, ct),
            .data = decoded,
        });
    }

    return try attachments.toOwnedSlice(allocator);
}

/// Decompress attachment data (gzip or zip).
pub fn decompress(allocator: Allocator, data: []const u8, filename: []const u8) ![]const u8 {
    if (std.mem.endsWith(u8, filename, ".gz") or std.mem.endsWith(u8, filename, ".gzip")) {
        return decompressGzip(allocator, data);
    } else if (std.mem.endsWith(u8, filename, ".zip")) {
        return decompressZip(allocator, data);
    }

    // Try gzip magic bytes
    if (data.len >= 2 and data[0] == 0x1f and data[1] == 0x8b) {
        return decompressGzip(allocator, data);
    }

    // Try zip magic bytes
    if (data.len >= 4 and data[0] == 0x50 and data[1] == 0x4b and data[2] == 0x03 and data[3] == 0x04) {
        return decompressZip(allocator, data);
    }

    // Assume raw XML/JSON
    return try allocator.dupe(u8, data);
}

const zlib = @cImport({
    @cInclude("zlib.h");
});

fn decompressGzip(allocator: Allocator, data: []const u8) ![]const u8 {
    var stream: zlib.z_stream = std.mem.zeroes(zlib.z_stream);
    stream.next_in = @constCast(data.ptr);
    stream.avail_in = @intCast(data.len);

    // windowBits = 15 + 16 for gzip decoding
    if (zlib.inflateInit2(&stream, 15 + 16) != zlib.Z_OK) return error.ZlibInitFailed;
    defer _ = zlib.inflateEnd(&stream);

    var result: std.ArrayList(u8) = .empty;
    var buf: [8192]u8 = undefined;

    while (true) {
        stream.next_out = &buf;
        stream.avail_out = buf.len;
        const ret = zlib.inflate(&stream, zlib.Z_NO_FLUSH);
        const have = buf.len - stream.avail_out;
        if (have > 0) try result.appendSlice(allocator, buf[0..have]);
        if (ret == zlib.Z_STREAM_END) break;
        if (ret != zlib.Z_OK) {
            result.deinit(allocator);
            return error.ZlibInflateFailed;
        }
    }

    return result.toOwnedSlice(allocator);
}

fn decompressZip(allocator: Allocator, data: []const u8) ![]const u8 {
    // Parse ZIP local file header (PK\x03\x04) to extract the first file
    if (data.len < 30) return error.ZipTooSmall;
    if (!std.mem.eql(u8, data[0..4], &[_]u8{ 'P', 'K', 3, 4 })) return error.ZipBadMagic;

    const compression = std.mem.readInt(u16, data[8..10], .little);
    const compressed_size = std.mem.readInt(u32, data[18..22], .little);
    const uncompressed_size = std.mem.readInt(u32, data[22..26], .little);
    const filename_len = std.mem.readInt(u16, data[26..28], .little);
    const extra_len = std.mem.readInt(u16, data[28..30], .little);

    const file_data_offset: usize = 30 + filename_len + extra_len;
    if (file_data_offset + compressed_size > data.len) return error.ZipTruncated;

    const compressed_data = data[file_data_offset .. file_data_offset + compressed_size];

    if (compression == 0) {
        // Stored (no compression)
        return try allocator.dupe(u8, compressed_data);
    } else if (compression == 8) {
        // Deflate — use zlib with raw inflate (windowBits = -15)
        var stream: zlib.z_stream = std.mem.zeroes(zlib.z_stream);
        stream.next_in = @constCast(compressed_data.ptr);
        stream.avail_in = @intCast(compressed_data.len);

        if (zlib.inflateInit2(&stream, -15) != zlib.Z_OK) return error.ZlibInitFailed;
        defer _ = zlib.inflateEnd(&stream);

        const out = try allocator.alloc(u8, uncompressed_size);
        stream.next_out = out.ptr;
        stream.avail_out = @intCast(out.len);

        const ret = zlib.inflate(&stream, zlib.Z_FINISH);
        if (ret != zlib.Z_STREAM_END) {
            allocator.free(out);
            return error.ZlibInflateFailed;
        }

        return out;
    }

    return error.ZipUnsupportedCompression;
}

fn findBoundary(raw: []const u8) ?[]const u8 {
    const ct_start = std.mem.indexOf(u8, raw, "boundary=") orelse return null;
    const after = raw[ct_start + "boundary=".len ..];
    if (after.len == 0) return null;

    if (after[0] == '"') {
        const end = std.mem.indexOf(u8, after[1..], "\"") orelse return null;
        return after[1 .. end + 1];
    }

    var end: usize = 0;
    while (end < after.len and after[end] != '\r' and after[end] != '\n' and after[end] != ';' and after[end] != ' ') : (end += 1) {}
    return after[0..end];
}

fn findBody(data: []const u8) ?[]const u8 {
    if (std.mem.indexOf(u8, data, "\r\n\r\n")) |pos| return data[pos + 4 ..];
    if (std.mem.indexOf(u8, data, "\n\n")) |pos| return data[pos + 2 ..];
    return null;
}

fn findHeaderValue(data: []const u8, header_name: []const u8) ?[]const u8 {
    const headers_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse
        (std.mem.indexOf(u8, data, "\n\n") orelse return null);

    const headers = data[0..headers_end];
    var lines = std.mem.splitSequence(u8, headers, "\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trimRight(u8, line, "\r");
        if (std.ascii.startsWithIgnoreCase(trimmed, header_name)) {
            const after_name = trimmed[header_name.len..];
            if (after_name.len > 0 and after_name[0] == ':') {
                return std.mem.trim(u8, after_name[1..], " \t");
            }
        }
    }
    return null;
}

fn isReportContentType(ct: []const u8) bool {
    const types = [_][]const u8{
        "application/zip",          "application/gzip",
        "application/x-zip",        "application/x-gzip",
        "application/octet-stream", "text/xml",
        "application/xml",          "application/json",
        "application/tlsrpt+gzip",  "application/tlsrpt+json",
    };
    for (types) |t| {
        if (std.mem.indexOf(u8, ct, t) != null) return true;
    }
    return false;
}

fn isAttachmentDisposition(cd: ?[]const u8) bool {
    const val = cd orelse return false;
    return std.mem.indexOf(u8, val, "attachment") != null;
}

fn extractFilename(cd: ?[]const u8) ?[]const u8 {
    const val = cd orelse return null;
    const pos = std.mem.indexOf(u8, val, "filename=") orelse return null;
    const after = val[pos + "filename=".len ..];
    if (after.len == 0) return null;
    if (after[0] == '"') {
        const end = std.mem.indexOf(u8, after[1..], "\"") orelse return null;
        return after[1 .. end + 1];
    }
    var end: usize = 0;
    while (end < after.len and after[end] != ';' and after[end] != ' ' and after[end] != '\r' and after[end] != '\n') : (end += 1) {}
    return after[0..end];
}

// --- Tests ---

test "findBoundary with quoted boundary" {
    const headers = "Content-Type: multipart/mixed; boundary=\"----=_Part_123\"\r\n\r\nbody";
    try std.testing.expectEqualStrings("----=_Part_123", findBoundary(headers).?);
}

test "findBoundary with unquoted boundary" {
    const headers = "Content-Type: multipart/mixed; boundary=abc123\r\n\r\nbody";
    try std.testing.expectEqualStrings("abc123", findBoundary(headers).?);
}

test "findBoundary returns null for non-multipart" {
    const headers = "Content-Type: application/zip\r\n\r\nbody";
    try std.testing.expectEqual(@as(?[]const u8, null), findBoundary(headers));
}

test "findBody with CRLF" {
    const msg = "Header: value\r\n\r\nThis is body";
    try std.testing.expectEqualStrings("This is body", findBody(msg).?);
}

test "findBody with LF" {
    const msg = "Header: value\n\nThis is body";
    try std.testing.expectEqualStrings("This is body", findBody(msg).?);
}

test "findHeaderValue case insensitive" {
    const msg = "content-type: application/zip\r\nContent-Transfer-Encoding: base64\r\n\r\nbody";
    try std.testing.expectEqualStrings("application/zip", findHeaderValue(msg, "content-type").?);
    try std.testing.expectEqualStrings("base64", findHeaderValue(msg, "Content-Transfer-Encoding").?);
}

test "findHeaderValue returns null for missing header" {
    const msg = "Content-Type: text/plain\r\n\r\nbody";
    try std.testing.expectEqual(@as(?[]const u8, null), findHeaderValue(msg, "X-Custom"));
}

test "isReportContentType" {
    try std.testing.expect(isReportContentType("application/zip"));
    try std.testing.expect(isReportContentType("application/gzip"));
    try std.testing.expect(isReportContentType("application/zip; name=\"report.zip\""));
    try std.testing.expect(isReportContentType("text/xml"));
    try std.testing.expect(isReportContentType("application/tlsrpt+gzip"));
    try std.testing.expect(!isReportContentType("text/plain"));
    try std.testing.expect(!isReportContentType("text/html"));
}

test "isAttachmentDisposition" {
    try std.testing.expect(isAttachmentDisposition("attachment; filename=\"report.zip\""));
    try std.testing.expect(!isAttachmentDisposition("inline"));
    try std.testing.expect(!isAttachmentDisposition(null));
}

test "extractFilename with quotes" {
    try std.testing.expectEqualStrings(
        "google.com!example.com!1700000000!1700086400.zip",
        extractFilename("attachment; filename=\"google.com!example.com!1700000000!1700086400.zip\"").?,
    );
}

test "extractFilename without quotes" {
    try std.testing.expectEqualStrings("report.zip", extractFilename("attachment; filename=report.zip").?);
}

test "extractFilename returns null" {
    try std.testing.expectEqual(@as(?[]const u8, null), extractFilename(null));
    try std.testing.expectEqual(@as(?[]const u8, null), extractFilename("attachment"));
}

test "decodeBody base64" {
    const allocator = std.testing.allocator;
    // "Hello" in base64 is "SGVsbG8="
    const decoded = try decodeBody(allocator, "SGVsbG8=\r\n", "base64");
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("Hello", decoded);
}

test "decodeBody no encoding" {
    const allocator = std.testing.allocator;
    const decoded = try decodeBody(allocator, "  raw content  \r\n", null);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("raw content", decoded);
}

test "decompress raw xml passthrough" {
    const allocator = std.testing.allocator;
    const xml = "<?xml version=\"1.0\"?><feedback></feedback>";
    const result = try decompress(allocator, xml, "report.xml");
    defer allocator.free(result);
    try std.testing.expectEqualStrings(xml, result);
}

test "decompress gzip by magic bytes" {
    const allocator = std.testing.allocator;
    // Create a simple gzip compressed "test" via zlib
    const input = "test data for gzip";
    var zbuf: [256]u8 = undefined;

    var stream: zlib.z_stream = std.mem.zeroes(zlib.z_stream);
    stream.next_in = @constCast(input.ptr);
    stream.avail_in = input.len;
    stream.next_out = &zbuf;
    stream.avail_out = zbuf.len;

    _ = zlib.deflateInit2(&stream, zlib.Z_DEFAULT_COMPRESSION, zlib.Z_DEFLATED, 15 + 16, 8, zlib.Z_DEFAULT_STRATEGY);
    _ = zlib.deflate(&stream, zlib.Z_FINISH);
    const compressed_size = zbuf.len - stream.avail_out;
    _ = zlib.deflateEnd(&stream);

    const result = try decompress(allocator, zbuf[0..compressed_size], "report");
    defer allocator.free(result);
    try std.testing.expectEqualStrings(input, result);
}

test "decompress zip stored" {
    const allocator = std.testing.allocator;
    // Build a minimal ZIP file with stored (no compression) content
    const content = "hello zip";
    const filename = "test.xml";
    var zip_buf: [256]u8 = undefined;
    var pos: usize = 0;

    // Local file header
    @memcpy(zip_buf[pos..][0..4], &[_]u8{ 'P', 'K', 3, 4 });
    pos += 4;
    std.mem.writeInt(u16, zip_buf[pos..][0..2], 20, .little); // version
    pos += 2;
    std.mem.writeInt(u16, zip_buf[pos..][0..2], 0, .little); // flags
    pos += 2;
    std.mem.writeInt(u16, zip_buf[pos..][0..2], 0, .little); // compression: stored
    pos += 2;
    std.mem.writeInt(u16, zip_buf[pos..][0..2], 0, .little); // mod time
    pos += 2;
    std.mem.writeInt(u16, zip_buf[pos..][0..2], 0, .little); // mod date
    pos += 2;
    std.mem.writeInt(u32, zip_buf[pos..][0..4], 0, .little); // crc32
    pos += 4;
    std.mem.writeInt(u32, zip_buf[pos..][0..4], @intCast(content.len), .little); // compressed size
    pos += 4;
    std.mem.writeInt(u32, zip_buf[pos..][0..4], @intCast(content.len), .little); // uncompressed size
    pos += 4;
    std.mem.writeInt(u16, zip_buf[pos..][0..2], @intCast(filename.len), .little); // filename len
    pos += 2;
    std.mem.writeInt(u16, zip_buf[pos..][0..2], 0, .little); // extra len
    pos += 2;
    @memcpy(zip_buf[pos..][0..filename.len], filename);
    pos += filename.len;
    @memcpy(zip_buf[pos..][0..content.len], content);
    pos += content.len;

    const result = try decompress(allocator, zip_buf[0..pos], "report.zip");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello zip", result);
}

test "extractAttachments from single-part email" {
    const allocator = std.testing.allocator;
    const raw =
        "Content-Type: text/xml\r\n" ++
        "Content-Transfer-Encoding: base64\r\n" ++
        "\r\n" ++
        "PD94bWwgdmVyc2lvbj0iMS4wIj8+\r\n";

    const attachments = try extractAttachments(allocator, raw);
    defer {
        for (attachments) |att| {
            allocator.free(att.filename);
            allocator.free(att.content_type);
            allocator.free(att.data);
        }
        allocator.free(attachments);
    }

    try std.testing.expectEqual(@as(usize, 1), attachments.len);
    try std.testing.expectEqualStrings("<?xml version=\"1.0\"?>", attachments[0].data);
}

test "extractAttachments from multipart/report with --boundary" {
    const allocator = std.testing.allocator;
    const raw =
        "Content-Type: multipart/report; boundary=\"abc123\"; report-type=tlsrpt\r\n" ++
        "\r\n" ++
        "--abc123\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "\r\n" ++
        "This is a TLS report.\r\n" ++
        "--abc123\r\n" ++
        "Content-Type: application/tlsrpt+json\r\n" ++
        "\r\n" ++
        "{\"report\": true}\r\n" ++
        "--abc123--\r\n";

    const attachments = try extractAttachments(allocator, raw);
    defer {
        for (attachments) |att| {
            allocator.free(att.filename);
            allocator.free(att.content_type);
            allocator.free(att.data);
        }
        allocator.free(attachments);
    }

    try std.testing.expectEqual(@as(usize, 1), attachments.len);
    try std.testing.expectEqualStrings("application/tlsrpt+json", attachments[0].content_type);
    try std.testing.expectEqualStrings("{\"report\": true}", attachments[0].data);
}

test "extractAttachments from multipart/report with gzip content-type" {
    const allocator = std.testing.allocator;
    const raw =
        "Content-Type: multipart/report; boundary=\"bnd\"; report-type=tlsrpt\r\n" ++
        "\r\n" ++
        "--bnd\r\n" ++
        "Content-Type: application/tlsrpt+gzip; name=\"report.gz\"\r\n" ++
        "Content-Transfer-Encoding: base64\r\n" ++
        "Content-Disposition: attachment; filename=\"report.gz\"\r\n" ++
        "\r\n" ++
        "H4sIAAAAAAAAA6tWKkktLlGyUlAqS8wpTtVRSs7PS8nMS1eqBQBIXVQdGgAAAA==\r\n" ++
        "--bnd--\r\n";

    const attachments = try extractAttachments(allocator, raw);
    defer {
        for (attachments) |att| {
            allocator.free(att.filename);
            allocator.free(att.content_type);
            allocator.free(att.data);
        }
        allocator.free(attachments);
    }

    try std.testing.expectEqual(@as(usize, 1), attachments.len);
    try std.testing.expectEqualStrings("report.gz", attachments[0].filename);
}

test "decodeBody base64 ignores non-base64 characters" {
    const allocator = std.testing.allocator;
    // "hello" in base64 is "aGVsbG8=" with trailing junk
    const body = "aGVsbG8=\r\n--boundary\r\n";
    const decoded = try decodeBody(allocator, body, "base64");
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("hello", decoded);
}

fn decodeBody(allocator: Allocator, body: []const u8, encoding: ?[]const u8) ![]const u8 {
    const enc = encoding orelse return try allocator.dupe(u8, std.mem.trim(u8, body, " \t\r\n"));

    if (std.ascii.indexOfIgnoreCase(enc, "base64") != null) {
        var clean: std.ArrayList(u8) = .empty;
        defer clean.deinit(allocator);
        for (body) |ch| {
            if (std.mem.indexOfScalar(u8, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", ch) != null) {
                try clean.append(allocator, ch);
            }
        }
        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(clean.items) catch return error.Base64DecodeError;
        const decoded = try allocator.alloc(u8, decoded_len);
        std.base64.standard.Decoder.decode(decoded, clean.items) catch return error.Base64DecodeError;
        return decoded;
    }

    return try allocator.dupe(u8, std.mem.trim(u8, body, " \t\r\n"));
}
