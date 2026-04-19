const std = @import("std");
const build_options = @import("build_options");
const commands = @import("cli/commands.zig");
const show = @import("cli/show.zig");
const ui = @import("cli/ui.zig");

const logo_text = @embedFile("assets/logo.txt");
const desc_text = @embedFile("assets/desc.txt");

pub fn main() !void {
    var gpa_impl: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa_impl.deinit();
    const allocator = gpa_impl.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];
    const account = getOption(args, "--account");
    const format = getOption(args, "--format");
    const domain = getOption(args, "--domain");
    const period = getOption(args, "--period");
    const report_type = getOption(args, "--type");
    const enrich = !hasFlag(args, "--no-enrich");

    if (std.mem.eql(u8, command, "sync")) {
        const refetch = hasFlag(args, "--refetch");
        try commands.cmdFetch(allocator, account, refetch);
        ui.stdout_file.writeAll("\n") catch {};
        try commands.cmdEnrich(allocator);
        ui.stdout_file.writeAll("\n") catch {};
        try commands.cmdAggregate(allocator);
    } else if (std.mem.eql(u8, command, "fetch")) {
        const refetch = hasFlag(args, "--refetch");
        try commands.cmdFetch(allocator, account, refetch);
    } else if (std.mem.eql(u8, command, "enrich")) {
        try commands.cmdEnrich(allocator);
    } else if (std.mem.eql(u8, command, "aggregate")) {
        try commands.cmdAggregate(allocator);
    } else if (std.mem.eql(u8, command, "list")) {
        try show.cmdList(allocator, format orelse "text", domain, account, report_type);
    } else if (std.mem.eql(u8, command, "show")) {
        if (args.len < 3 or std.mem.startsWith(u8, args[2], "--")) {
            ui.stderr_file.writeAll("Usage: reports show <report-id>\n") catch {};
            return;
        }
        try show.cmdShow(allocator, args[2], format orelse "text", enrich);
    } else if (std.mem.eql(u8, command, "dns")) {
        try commands.cmdDns(allocator, domain, format orelse "text");
    } else if (std.mem.eql(u8, command, "domains")) {
        try commands.cmdDomains(allocator, format orelse "text", account);
    } else if (std.mem.eql(u8, command, "summary")) {
        try commands.cmdSummary(allocator, format orelse "text", domain, account, period);
    } else if (std.mem.eql(u8, command, "check")) {
        const threshold = getOption(args, "--threshold");
        const max_age = getOption(args, "--max-age");
        const exit_code = try commands.cmdCheck(allocator, domain, account, format orelse "text", threshold, max_age);
        if (exit_code != 0) std.process.exit(exit_code);
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsage();
    } else if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-v")) {
        printVersion();
    } else {
        ui.stderr_file.writeAll("Unknown command: ") catch {};
        ui.stderr_file.writeAll(command) catch {};
        ui.stderr_file.writeAll("\n") catch {};
        printUsage();
    }
}

fn printVersion() void {
    ui.stdout_file.writeAll("reports version ") catch {};
    ui.stdout_file.writeAll(build_options.version) catch {};
    ui.stdout_file.writeAll("\n") catch {};
}

fn printUsage() void {
    ui.stdout_file.writeAll(ui.neon_yellow) catch {};
    ui.stdout_file.writeAll(logo_text) catch {};
    ui.stdout_file.writeAll(ui.reset) catch {};
    ui.stdout_file.writeAll(ui.dim) catch {};
    ui.stdout_file.writeAll(desc_text) catch {};
    ui.stdout_file.writeAll(ui.reset) catch {};
    ui.stdout_file.writeAll(
        \\
        \\Usage: reports <command> [options]
        \\
        \\Commands:
        \\  sync                         Fetch, enrich, and aggregate (all-in-one)
        \\  fetch                        Fetch reports from IMAP
        \\  enrich                       Enrich source IPs (PTR/ASN/country)
        \\  aggregate                    Rebuild dashboard and mail sources caches
        \\  list                         List reports
        \\  show <id>                    Show report details
        \\  summary                      Show summary statistics
        \\  check                        Check for anomalies (exit 0=OK, 1=WARN, 2=CRIT)
        \\  dns                          Show DNS records (DMARC/SPF/DKIM/MTA-STS/TLS-RPT)
        \\  domains                      List domains
        \\  version                      Show version
        \\  help                         Show this help
        \\
        \\Filters:
        \\  --account <name>      Target specific account (default: all)
        \\  --domain <domain>     Filter by domain
        \\  --type <dmarc|tlsrpt> Filter by report type
        \\
        \\Options:
        \\  --format <text|json>  Output format (default: text)
        \\  --period <week|month|year> Group summary by period
        \\  --threshold <percent> Fail rate threshold for check (default: 0)
        \\  --max-age <days>      Report freshness threshold (default: 7)
        \\  --refetch             Re-fetch all messages (ignore fetched history)
        \\  --no-enrich           Disable IP enrichment (PTR/ASN/country)
        \\
        \\Configuration: ~/.config/reports/config.json
        \\
    ) catch {};
}

fn getOption(args: []const []const u8, name: []const u8) ?[]const u8 {
    for (args, 0..) |arg, i| {
        if (std.mem.eql(u8, arg, name) and i + 1 < args.len) {
            return args[i + 1];
        }
    }
    return null;
}

fn hasFlag(args: []const []const u8, name: []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, name)) return true;
    }
    return false;
}

// Pull in tests from sub-modules so `zig build test` discovers them.
test {
    _ = @import("cli/ui.zig");
    _ = @import("cli/data.zig");
    _ = @import("cli/enrich.zig");
}
