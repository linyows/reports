const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Config = struct {
    accounts: []const Account,
    data_dir: []const u8,
    geoip_db: []const u8,

    pub const Account = struct {
        name: []const u8,
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

        const data_dir = if (j.data_dir) |d|
            try allocator.dupe(u8, d)
        else
            try std.fs.path.join(allocator, &.{ home, ".local", "share", "reports" });

        const geoip_db = if (j.geoip_db) |g|
            try allocator.dupe(u8, g)
        else
            try allocator.dupe(u8, "");

        // Parse accounts: prefer "accounts" array, fall back to legacy "imap" object
        if (j.accounts) |json_accounts| {
            var accounts = try allocator.alloc(Account, json_accounts.len);
            for (json_accounts, 0..) |ja, i| {
                accounts[i] = .{
                    .name = try allocator.dupe(u8, ja.name),
                    .host = try allocator.dupe(u8, ja.host),
                    .port = ja.port,
                    .username = try allocator.dupe(u8, ja.username),
                    .password = try allocator.dupe(u8, ja.password),
                    .mailbox = try allocator.dupe(u8, ja.mailbox),
                    .tls = ja.tls,
                };
            }
            return .{ .accounts = accounts, .data_dir = data_dir, .geoip_db = geoip_db };
        }

        if (j.imap) |imap| {
            var accounts = try allocator.alloc(Account, 1);
            accounts[0] = .{
                .name = try allocator.dupe(u8, "default"),
                .host = try allocator.dupe(u8, imap.host),
                .port = imap.port,
                .username = try allocator.dupe(u8, imap.username),
                .password = try allocator.dupe(u8, imap.password),
                .mailbox = try allocator.dupe(u8, imap.mailbox),
                .tls = imap.tls,
            };
            return .{ .accounts = accounts, .data_dir = data_dir, .geoip_db = geoip_db };
        }

        // No accounts configured
        const accounts = try allocator.alloc(Account, 0);
        return .{ .accounts = accounts, .data_dir = data_dir, .geoip_db = geoip_db };
    }

    fn defaultConfig(allocator: Allocator, home: []const u8) !Config {
        const accounts = try allocator.alloc(Account, 0);
        return .{
            .accounts = accounts,
            .data_dir = try std.fs.path.join(allocator, &.{ home, ".local", "share", "reports" }),
            .geoip_db = try allocator.dupe(u8, ""),
        };
    }

    pub fn deinit(self: *const Config, allocator: Allocator) void {
        for (self.accounts) |a| {
            allocator.free(a.name);
            allocator.free(a.host);
            allocator.free(a.username);
            allocator.free(a.password);
            allocator.free(a.mailbox);
        }
        allocator.free(self.accounts);
        allocator.free(self.data_dir);
        allocator.free(self.geoip_db);
    }

    pub fn getAccount(self: *const Config, name: []const u8) ?*const Account {
        for (self.accounts) |*a| {
            if (std.mem.eql(u8, a.name, name)) return a;
        }
        return null;
    }

    pub fn accountNames(self: *const Config, allocator: Allocator) ![]const []const u8 {
        var names = try allocator.alloc([]const u8, self.accounts.len);
        for (self.accounts, 0..) |a, i| {
            names[i] = a.name;
        }
        return names;
    }

    pub fn ensureDataDir(self: *const Config) !void {
        makeDirIfNotExists(self.data_dir);
        for (self.accounts) |a| {
            const acct_dir = try std.fs.path.join(std.heap.page_allocator, &.{ self.data_dir, a.name });
            defer std.heap.page_allocator.free(acct_dir);
            makeDirIfNotExists(acct_dir);

            const dmarc_dir = try std.fs.path.join(std.heap.page_allocator, &.{ acct_dir, "dmarc" });
            defer std.heap.page_allocator.free(dmarc_dir);
            makeDirIfNotExists(dmarc_dir);

            const tlsrpt_dir = try std.fs.path.join(std.heap.page_allocator, &.{ acct_dir, "tlsrpt" });
            defer std.heap.page_allocator.free(tlsrpt_dir);
            makeDirIfNotExists(tlsrpt_dir);
        }
    }
};

fn makeDirIfNotExists(path: []const u8) void {
    std.fs.makeDirAbsolute(path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => {},
    };
}

const JsonImapFields = struct {
    host: []const u8,
    port: u16 = 993,
    username: []const u8,
    password: []const u8,
    mailbox: []const u8 = "INBOX",
    tls: bool = true,
};

const JsonAccountFields = struct {
    name: []const u8 = "default",
    host: []const u8,
    port: u16 = 993,
    username: []const u8,
    password: []const u8,
    mailbox: []const u8 = "INBOX",
    tls: bool = true,
};

const JsonConfig = struct {
    accounts: ?[]const JsonAccountFields = null,
    imap: ?JsonImapFields = null,
    data_dir: ?[]const u8 = null,
    geoip_db: ?[]const u8 = null,
};

// --- Tests ---

test "fromJson parses accounts array" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "accounts": [
        \\    { "name": "personal", "host": "imap.gmail.com", "username": "a@gmail.com", "password": "p1", "mailbox": "dmarc" },
        \\    { "name": "work", "host": "imap.work.com", "username": "b@work.com", "password": "p2" }
        \\  ],
        \\  "data_dir": "/tmp/test-reports"
        \\}
    ;

    const cfg = try Config.fromJson(allocator, json);
    defer cfg.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), cfg.accounts.len);
    try std.testing.expectEqualStrings("personal", cfg.accounts[0].name);
    try std.testing.expectEqualStrings("imap.gmail.com", cfg.accounts[0].host);
    try std.testing.expectEqualStrings("dmarc", cfg.accounts[0].mailbox);
    try std.testing.expectEqualStrings("work", cfg.accounts[1].name);
    try std.testing.expectEqualStrings("INBOX", cfg.accounts[1].mailbox);
    try std.testing.expectEqualStrings("/tmp/test-reports", cfg.data_dir);
}

test "fromJson parses legacy imap as default account" {
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
        \\  }
        \\}
    ;

    const cfg = try Config.fromJson(allocator, json);
    defer cfg.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), cfg.accounts.len);
    try std.testing.expectEqualStrings("default", cfg.accounts[0].name);
    try std.testing.expectEqualStrings("imap.example.com", cfg.accounts[0].host);
    try std.testing.expectEqualStrings("user@example.com", cfg.accounts[0].username);
}

test "fromJson with no accounts or imap returns empty" {
    const allocator = std.testing.allocator;
    const json = "{}";

    const cfg = try Config.fromJson(allocator, json);
    defer cfg.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), cfg.accounts.len);
}

test "getAccount finds by name" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "accounts": [
        \\    { "name": "a", "host": "h1", "username": "u1", "password": "p1" },
        \\    { "name": "b", "host": "h2", "username": "u2", "password": "p2" }
        \\  ]
        \\}
    ;

    const cfg = try Config.fromJson(allocator, json);
    defer cfg.deinit(allocator);

    const a = cfg.getAccount("a");
    try std.testing.expect(a != null);
    try std.testing.expectEqualStrings("h1", a.?.host);

    const b = cfg.getAccount("b");
    try std.testing.expect(b != null);
    try std.testing.expectEqualStrings("h2", b.?.host);

    try std.testing.expectEqual(@as(?*const Config.Account, null), cfg.getAccount("nonexistent"));
}

test "fromJson uses defaults for optional fields" {
    const allocator = std.testing.allocator;
    const json =
        \\{ "imap": { "host": "h", "username": "u", "password": "p" } }
    ;

    const cfg = try Config.fromJson(allocator, json);
    defer cfg.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 993), cfg.accounts[0].port);
    try std.testing.expectEqualStrings("INBOX", cfg.accounts[0].mailbox);
    try std.testing.expect(cfg.accounts[0].tls);
    try std.testing.expectEqualStrings("", cfg.geoip_db);
}
