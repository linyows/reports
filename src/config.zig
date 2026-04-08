const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Config = struct {
    imap: Imap,
    data_dir: []const u8,
    geoip_db: []const u8,

    pub const Imap = struct {
        host: []const u8,
        port: u16 = 993,
        username: []const u8,
        password: []const u8,
        mailbox: []const u8 = "INBOX",
        tls: bool = true,
    };

    pub fn load(allocator: Allocator) !Config {
        const home = std.posix.getenv("HOME") orelse return error.NoHomeDir;
        const config_path = try std.fs.path.join(allocator, &.{ home, ".config", "reports", "config.json" });
        defer allocator.free(config_path);

        const file = std.fs.openFileAbsolute(config_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return defaultConfig(allocator, home),
            else => return err,
        };
        defer file.close();

        const data = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(data);

        return fromJson(allocator, data);
    }

    pub fn fromJson(allocator: Allocator, data: []const u8) !Config {
        const parsed = try std.json.parseFromSlice(JsonConfig, allocator, data, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        const j = parsed.value;

        const home = std.posix.getenv("HOME") orelse return error.NoHomeDir;

        return .{
            .imap = .{
                .host = try allocator.dupe(u8, j.imap.host),
                .port = j.imap.port,
                .username = try allocator.dupe(u8, j.imap.username),
                .password = try allocator.dupe(u8, j.imap.password),
                .mailbox = try allocator.dupe(u8, j.imap.mailbox),
                .tls = j.imap.tls,
            },
            .data_dir = if (j.data_dir) |d|
                try allocator.dupe(u8, d)
            else
                try std.fs.path.join(allocator, &.{ home, ".local", "share", "reports" }),
            .geoip_db = if (j.geoip_db) |g|
                try allocator.dupe(u8, g)
            else
                try allocator.dupe(u8, ""),
        };
    }

    fn defaultConfig(allocator: Allocator, home: []const u8) !Config {
        return .{
            .imap = .{
                .host = try allocator.dupe(u8, ""),
                .port = 993,
                .username = try allocator.dupe(u8, ""),
                .password = try allocator.dupe(u8, ""),
                .mailbox = try allocator.dupe(u8, "INBOX"),
                .tls = true,
            },
            .data_dir = try std.fs.path.join(allocator, &.{ home, ".local", "share", "reports" }),
            .geoip_db = try allocator.dupe(u8, ""),
        };
    }

    pub fn deinit(self: *const Config, allocator: Allocator) void {
        allocator.free(self.imap.host);
        allocator.free(self.imap.username);
        allocator.free(self.imap.password);
        allocator.free(self.imap.mailbox);
        allocator.free(self.data_dir);
        allocator.free(self.geoip_db);
    }

    pub fn imapUrl(self: *const Config, allocator: Allocator) ![]const u8 {
        const scheme = if (self.imap.tls) "imaps" else "imap";
        return std.fmt.allocPrint(allocator, "{s}://{s}:{d}/{s}", .{
            scheme, self.imap.host, self.imap.port, self.imap.mailbox,
        });
    }

    pub fn ensureDataDir(self: *const Config) !void {
        std.fs.makeDirAbsolute(self.data_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const dmarc_dir = try std.fs.path.join(std.heap.page_allocator, &.{ self.data_dir, "dmarc" });
        defer std.heap.page_allocator.free(dmarc_dir);
        std.fs.makeDirAbsolute(dmarc_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const tlsrpt_dir = try std.fs.path.join(std.heap.page_allocator, &.{ self.data_dir, "tlsrpt" });
        defer std.heap.page_allocator.free(tlsrpt_dir);
        std.fs.makeDirAbsolute(tlsrpt_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
};

// --- Tests ---

test "fromJson parses full config" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "imap": {
        \\    "host": "imap.example.com",
        \\    "port": 993,
        \\    "username": "user@example.com",
        \\    "password": "secret",
        \\    "mailbox": "INBOX",
        \\    "tls": true
        \\  },
        \\  "data_dir": "/tmp/reports-test",
        \\  "geoip_db": "/usr/share/GeoIP/GeoLite2-City.mmdb"
        \\}
    ;

    const cfg = try Config.fromJson(allocator, json);
    defer cfg.deinit(allocator);

    try std.testing.expectEqualStrings("imap.example.com", cfg.imap.host);
    try std.testing.expectEqual(@as(u16, 993), cfg.imap.port);
    try std.testing.expectEqualStrings("user@example.com", cfg.imap.username);
    try std.testing.expectEqualStrings("secret", cfg.imap.password);
    try std.testing.expectEqualStrings("INBOX", cfg.imap.mailbox);
    try std.testing.expect(cfg.imap.tls);
    try std.testing.expectEqualStrings("/tmp/reports-test", cfg.data_dir);
    try std.testing.expectEqualStrings("/usr/share/GeoIP/GeoLite2-City.mmdb", cfg.geoip_db);
}

test "fromJson uses defaults for optional fields" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "imap": {
        \\    "host": "mail.test.com",
        \\    "username": "u",
        \\    "password": "p"
        \\  }
        \\}
    ;

    const cfg = try Config.fromJson(allocator, json);
    defer cfg.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 993), cfg.imap.port);
    try std.testing.expectEqualStrings("INBOX", cfg.imap.mailbox);
    try std.testing.expect(cfg.imap.tls);
    try std.testing.expect(cfg.data_dir.len > 0);
    try std.testing.expectEqualStrings("", cfg.geoip_db);
}

test "imapUrl generates correct url" {
    const allocator = std.testing.allocator;
    const cfg = Config{
        .imap = .{
            .host = "imap.gmail.com",
            .port = 993,
            .username = "u",
            .password = "p",
            .mailbox = "INBOX",
            .tls = true,
        },
        .data_dir = "/tmp",
        .geoip_db = "",
    };

    const url = try cfg.imapUrl(allocator);
    defer allocator.free(url);
    try std.testing.expectEqualStrings("imaps://imap.gmail.com:993/INBOX", url);
}

test "imapUrl with non-tls" {
    const allocator = std.testing.allocator;
    const cfg = Config{
        .imap = .{
            .host = "localhost",
            .port = 143,
            .username = "u",
            .password = "p",
            .mailbox = "dmarc",
            .tls = false,
        },
        .data_dir = "/tmp",
        .geoip_db = "",
    };

    const url = try cfg.imapUrl(allocator);
    defer allocator.free(url);
    try std.testing.expectEqualStrings("imap://localhost:143/dmarc", url);
}

const JsonConfig = struct {
    imap: struct {
        host: []const u8,
        port: u16 = 993,
        username: []const u8,
        password: []const u8,
        mailbox: []const u8 = "INBOX",
        tls: bool = true,
    },
    data_dir: ?[]const u8 = null,
    geoip_db: ?[]const u8 = null,
};
