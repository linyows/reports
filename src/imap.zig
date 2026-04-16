const std = @import("std");
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("curl/curl.h");
});

/// Last curl error message (static string from curl_easy_strerror, no need to free).
/// threadlocal to avoid data races when multiple accounts are fetched in parallel.
threadlocal var g_last_curl_error: ?[]const u8 = null;

pub fn lastCurlError() ?[]const u8 {
    return g_last_curl_error;
}

pub const Client = struct {
    allocator: Allocator,
    host: []const u8,
    port: u16,
    username: []const u8,
    password: []const u8,
    mailbox: []const u8,
    tls: bool,
    handle: ?*anyopaque = null,

    pub fn init(allocator: Allocator, host: []const u8, port: u16, username: []const u8, password: []const u8, mailbox: []const u8, tls: bool) Client {
        return .{
            .allocator = allocator,
            .host = host,
            .port = port,
            .username = username,
            .password = password,
            .mailbox = mailbox,
            .tls = tls,
        };
    }

    pub fn connect(self: *Client) !void {
        const h = c.curl_easy_init() orelse return error.CurlInitFailed;

        const username_z = try self.allocator.dupeZ(u8, self.username);
        defer self.allocator.free(username_z);
        _ = c.curl_easy_setopt(h, c.CURLOPT_USERNAME, username_z.ptr);

        const password_z = try self.allocator.dupeZ(u8, self.password);
        defer self.allocator.free(password_z);
        _ = c.curl_easy_setopt(h, c.CURLOPT_PASSWORD, password_z.ptr);

        if (self.tls) {
            _ = c.curl_easy_setopt(h, c.CURLOPT_USE_SSL, @as(c_long, c.CURLUSESSL_ALL));
        }

        _ = c.curl_easy_setopt(h, c.CURLOPT_TIMEOUT, @as(c_long, 120));
        _ = c.curl_easy_setopt(h, c.CURLOPT_CONNECTTIMEOUT, @as(c_long, 15));

        self.handle = h;
    }

    pub fn deinit(self: *Client) void {
        if (self.handle) |h| {
            c.curl_easy_cleanup(h);
            self.handle = null;
        }
    }

    pub fn searchReports(self: *const Client) ![]u32 {
        return self.search("UID SEARCH OR SUBJECT \"Report Domain:\" SUBJECT \"TLS-RPT\"");
    }

    pub fn fetchMessage(self: *const Client, uid: u32) ![]const u8 {
        const scheme: []const u8 = if (self.tls) "imaps" else "imap";
        const url = try std.fmt.allocPrintSentinel(self.allocator, "{s}://{s}:{d}/{s}/;UID={d}", .{
            scheme, self.host, self.port, self.mailbox, uid,
        }, 0);
        defer self.allocator.free(url);
        return self.perform(url.ptr, null);
    }

    fn search(self: *const Client, query: []const u8) ![]u32 {
        const scheme: []const u8 = if (self.tls) "imaps" else "imap";
        const url = try std.fmt.allocPrintSentinel(self.allocator, "{s}://{s}:{d}/{s}", .{
            scheme, self.host, self.port, self.mailbox,
        }, 0);
        defer self.allocator.free(url);

        const query_z = try self.allocator.dupeZ(u8, query);
        defer self.allocator.free(query_z);

        const response = try self.perform(url.ptr, query_z.ptr);
        defer self.allocator.free(response);

        return parseSearchResponse(self.allocator, response);
    }

    fn perform(self: *const Client, url: [*:0]const u8, custom_request: ?[*:0]const u8) ![]const u8 {
        if (self.handle) |h| {
            return self.doPerform(h, url, custom_request, false);
        } else {
            const h = c.curl_easy_init() orelse return error.CurlInitFailed;
            defer c.curl_easy_cleanup(h);
            return self.doPerform(h, url, custom_request, true);
        }
    }

    fn doPerform(self: *const Client, handle: *anyopaque, url: [*:0]const u8, custom_request: ?[*:0]const u8, set_auth: bool) ![]const u8 {
        var response = WriteData{ .allocator = self.allocator };

        _ = c.curl_easy_setopt(handle, c.CURLOPT_URL, url);

        if (set_auth) {
            const username_z = try self.allocator.dupeZ(u8, self.username);
            defer self.allocator.free(username_z);
            _ = c.curl_easy_setopt(handle, c.CURLOPT_USERNAME, username_z.ptr);

            const password_z = try self.allocator.dupeZ(u8, self.password);
            defer self.allocator.free(password_z);
            _ = c.curl_easy_setopt(handle, c.CURLOPT_PASSWORD, password_z.ptr);

            if (self.tls) {
                _ = c.curl_easy_setopt(handle, c.CURLOPT_USE_SSL, @as(c_long, c.CURLUSESSL_ALL));
            }

            _ = c.curl_easy_setopt(handle, c.CURLOPT_TIMEOUT, @as(c_long, 120));
            _ = c.curl_easy_setopt(handle, c.CURLOPT_CONNECTTIMEOUT, @as(c_long, 15));
        }

        if (custom_request) |req| {
            _ = c.curl_easy_setopt(handle, c.CURLOPT_CUSTOMREQUEST, req);
        } else {
            _ = c.curl_easy_setopt(handle, c.CURLOPT_CUSTOMREQUEST, @as([*c]const u8, null));
        }

        _ = c.curl_easy_setopt(handle, c.CURLOPT_WRITEFUNCTION, &writeCallback);
        _ = c.curl_easy_setopt(handle, c.CURLOPT_WRITEDATA, &response);

        const result = c.curl_easy_perform(handle);
        if (result != c.CURLE_OK) {
            const err_msg = c.curl_easy_strerror(result);
            if (err_msg) |msg| {
                const span = std.mem.span(msg);
                std.debug.print("curl error: {s}\n", .{span});
                g_last_curl_error = span;
            }
            if (response.data) |d| self.allocator.free(d);
            return error.CurlPerformFailed;
        }

        return response.data orelse try self.allocator.dupe(u8, "");
    }
};

const WriteData = struct {
    allocator: Allocator,
    data: ?[]u8 = null,
    len: usize = 0,
};

fn writeCallback(ptr: [*c]u8, size: usize, nmemb: usize, userdata: ?*anyopaque) callconv(.c) usize {
    const total = size * nmemb;
    if (total == 0) return 0;
    const wd: *WriteData = @ptrCast(@alignCast(userdata orelse return 0));

    const new_len = wd.len + total;
    if (wd.data) |existing| {
        const new_data = wd.allocator.realloc(existing[0..wd.len], new_len) catch return 0;
        @memcpy(new_data[wd.len..new_len], ptr[0..total]);
        wd.data = new_data;
    } else {
        const new_data = wd.allocator.alloc(u8, new_len) catch return 0;
        @memcpy(new_data[0..total], ptr[0..total]);
        wd.data = new_data;
    }
    wd.len = new_len;
    return total;
}

fn parseSearchResponse(allocator: Allocator, response: []const u8) ![]u32 {
    var uids: std.ArrayList(u32) = .empty;

    var lines = std.mem.splitSequence(u8, response, "\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\n");
        if (std.mem.startsWith(u8, trimmed, "* SEARCH")) {
            var parts = std.mem.splitScalar(u8, trimmed["* SEARCH".len..], ' ');
            while (parts.next()) |part| {
                const num = std.mem.trim(u8, part, " ");
                if (num.len == 0) continue;
                const uid = std.fmt.parseInt(u32, num, 10) catch continue;
                try uids.append(allocator, uid);
            }
        }
    }

    return uids.toOwnedSlice(allocator);
}

pub fn globalInit() void {
    _ = c.curl_global_init(c.CURL_GLOBAL_DEFAULT);
}

pub fn globalCleanup() void {
    c.curl_global_cleanup();
}
