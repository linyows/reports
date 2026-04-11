const std = @import("std");
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("libxml/parser.h");
    @cInclude("libxml/tree.h");
});

pub const Report = struct {
    metadata: Metadata,
    policy: PolicyPublished,
    records: []Record,

    pub const Metadata = struct {
        org_name: []const u8,
        email: []const u8,
        report_id: []const u8,
        date_begin: i64,
        date_end: i64,
    };

    pub const PolicyPublished = struct {
        domain: []const u8,
        adkim: []const u8,
        aspf: []const u8,
        policy: []const u8,
        sub_policy: []const u8,
        pct: u32,
    };

    pub const Record = struct {
        source_ip: []const u8,
        count: u32,
        disposition: []const u8,
        dkim_eval: []const u8,
        spf_eval: []const u8,
        header_from: []const u8,
        envelope_from: []const u8,
        envelope_to: []const u8,
        dkim_results: []AuthResult,
        spf_results: []AuthResult,
    };

    pub const AuthResult = struct {
        domain: []const u8,
        result: []const u8,
        selector: []const u8,
    };

    pub fn deinit(self: *const Report, allocator: Allocator) void {
        allocator.free(self.metadata.org_name);
        allocator.free(self.metadata.email);
        allocator.free(self.metadata.report_id);
        allocator.free(self.policy.domain);
        allocator.free(self.policy.adkim);
        allocator.free(self.policy.aspf);
        allocator.free(self.policy.policy);
        allocator.free(self.policy.sub_policy);
        for (self.records) |rec| {
            allocator.free(rec.source_ip);
            allocator.free(rec.disposition);
            allocator.free(rec.dkim_eval);
            allocator.free(rec.spf_eval);
            allocator.free(rec.header_from);
            allocator.free(rec.envelope_from);
            allocator.free(rec.envelope_to);
            for (rec.dkim_results) |r| {
                allocator.free(r.domain);
                allocator.free(r.result);
                allocator.free(r.selector);
            }
            allocator.free(rec.dkim_results);
            for (rec.spf_results) |r| {
                allocator.free(r.domain);
                allocator.free(r.result);
                allocator.free(r.selector);
            }
            allocator.free(rec.spf_results);
        }
        allocator.free(self.records);
    }

    pub fn toJson(self: *const Report, allocator: Allocator) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(self.*, .{})});
    }
};

pub fn parseXml(allocator: Allocator, data: []const u8) !Report {
    const doc = c.xmlReadMemory(data.ptr, @intCast(data.len), null, null, 0) orelse return error.XmlParseError;
    defer c.xmlFreeDoc(doc);

    const root = c.xmlDocGetRootElement(doc) orelse return error.NoRootElement;

    var metadata: ?Report.Metadata = null;
    var policy: ?Report.PolicyPublished = null;
    var records: std.ArrayList(Report.Record) = .empty;

    var child = firstElement(root.*.children);
    while (child) |node| : (child = nextElement(node.*.next)) {
        if (nameEql(node, "report_metadata")) {
            metadata = try parseMetadata(allocator, node);
        } else if (nameEql(node, "policy_published")) {
            policy = try parsePolicyPublished(allocator, node);
        } else if (nameEql(node, "record")) {
            try records.append(allocator, try parseRecord(allocator, node));
        }
    }

    return .{
        .metadata = metadata orelse return error.MissingMetadata,
        .policy = policy orelse return error.MissingPolicy,
        .records = try records.toOwnedSlice(allocator),
    };
}

fn parseMetadata(allocator: Allocator, node: *c.xmlNode) !Report.Metadata {
    var org_name: []const u8 = "";
    var email: []const u8 = "";
    var report_id: []const u8 = "";
    var date_begin: i64 = 0;
    var date_end: i64 = 0;

    var child = firstElement(node.*.children);
    while (child) |n| : (child = nextElement(n.*.next)) {
        if (nameEql(n, "org_name")) {
            org_name = try textContent(allocator, n);
        } else if (nameEql(n, "email")) {
            email = try textContent(allocator, n);
        } else if (nameEql(n, "report_id")) {
            report_id = try textContent(allocator, n);
        } else if (nameEql(n, "date_range")) {
            var dc = firstElement(n.*.children);
            while (dc) |dn| : (dc = nextElement(dn.*.next)) {
                if (nameEql(dn, "begin")) {
                    const s = try textContent(allocator, dn);
                    defer allocator.free(s);
                    date_begin = std.fmt.parseInt(i64, s, 10) catch 0;
                } else if (nameEql(dn, "end")) {
                    const s = try textContent(allocator, dn);
                    defer allocator.free(s);
                    date_end = std.fmt.parseInt(i64, s, 10) catch 0;
                }
            }
        }
    }

    return .{
        .org_name = org_name,
        .email = email,
        .report_id = report_id,
        .date_begin = date_begin,
        .date_end = date_end,
    };
}

fn parsePolicyPublished(allocator: Allocator, node: *c.xmlNode) !Report.PolicyPublished {
    var domain: []const u8 = "";
    var adkim: []const u8 = "";
    var aspf: []const u8 = "";
    var policy_val: []const u8 = "";
    var sp: []const u8 = "";
    var pct: u32 = 100;

    var child = firstElement(node.*.children);
    while (child) |n| : (child = nextElement(n.*.next)) {
        if (nameEql(n, "domain")) {
            domain = try textContent(allocator, n);
        } else if (nameEql(n, "adkim")) {
            adkim = try textContent(allocator, n);
        } else if (nameEql(n, "aspf")) {
            aspf = try textContent(allocator, n);
        } else if (nameEql(n, "p")) {
            policy_val = try textContent(allocator, n);
        } else if (nameEql(n, "sp")) {
            sp = try textContent(allocator, n);
        } else if (nameEql(n, "pct")) {
            const s = try textContent(allocator, n);
            defer allocator.free(s);
            pct = std.fmt.parseInt(u32, s, 10) catch 100;
        }
    }

    return .{
        .domain = domain,
        .adkim = adkim,
        .aspf = aspf,
        .policy = policy_val,
        .sub_policy = sp,
        .pct = pct,
    };
}

fn parseRecord(allocator: Allocator, node: *c.xmlNode) !Report.Record {
    var source_ip: []const u8 = "";
    var count: u32 = 0;
    var disposition: []const u8 = "";
    var dkim_eval: []const u8 = "";
    var spf_eval: []const u8 = "";
    var header_from: []const u8 = "";
    var envelope_from: []const u8 = "";
    var envelope_to: []const u8 = "";
    var dkim_results: std.ArrayList(Report.AuthResult) = .empty;
    var spf_results: std.ArrayList(Report.AuthResult) = .empty;

    var child = firstElement(node.*.children);
    while (child) |n| : (child = nextElement(n.*.next)) {
        if (nameEql(n, "row")) {
            var rc = firstElement(n.*.children);
            while (rc) |rn| : (rc = nextElement(rn.*.next)) {
                if (nameEql(rn, "source_ip")) {
                    source_ip = try textContent(allocator, rn);
                } else if (nameEql(rn, "count")) {
                    const s = try textContent(allocator, rn);
                    defer allocator.free(s);
                    count = std.fmt.parseInt(u32, s, 10) catch 0;
                } else if (nameEql(rn, "policy_evaluated")) {
                    var pc = firstElement(rn.*.children);
                    while (pc) |pn| : (pc = nextElement(pn.*.next)) {
                        if (nameEql(pn, "disposition")) {
                            disposition = try textContent(allocator, pn);
                        } else if (nameEql(pn, "dkim")) {
                            dkim_eval = try textContent(allocator, pn);
                        } else if (nameEql(pn, "spf")) {
                            spf_eval = try textContent(allocator, pn);
                        }
                    }
                }
            }
        } else if (nameEql(n, "identifiers")) {
            var ic = firstElement(n.*.children);
            while (ic) |in_node| : (ic = nextElement(in_node.*.next)) {
                if (nameEql(in_node, "header_from")) {
                    header_from = try textContent(allocator, in_node);
                } else if (nameEql(in_node, "envelope_from")) {
                    envelope_from = try textContent(allocator, in_node);
                } else if (nameEql(in_node, "envelope_to")) {
                    envelope_to = try textContent(allocator, in_node);
                }
            }
        } else if (nameEql(n, "auth_results")) {
            var ac = firstElement(n.*.children);
            while (ac) |an| : (ac = nextElement(an.*.next)) {
                if (nameEql(an, "dkim")) {
                    try dkim_results.append(allocator, try parseAuthResult(allocator, an));
                } else if (nameEql(an, "spf")) {
                    try spf_results.append(allocator, try parseAuthResult(allocator, an));
                }
            }
        }
    }

    return .{
        .source_ip = source_ip,
        .count = count,
        .disposition = disposition,
        .dkim_eval = dkim_eval,
        .spf_eval = spf_eval,
        .header_from = header_from,
        .envelope_from = envelope_from,
        .envelope_to = envelope_to,
        .dkim_results = try dkim_results.toOwnedSlice(allocator),
        .spf_results = try spf_results.toOwnedSlice(allocator),
    };
}

fn parseAuthResult(allocator: Allocator, node: *c.xmlNode) !Report.AuthResult {
    var domain: []const u8 = "";
    var result: []const u8 = "";
    var selector: []const u8 = "";

    var child = firstElement(node.*.children);
    while (child) |n| : (child = nextElement(n.*.next)) {
        if (nameEql(n, "domain")) {
            domain = try textContent(allocator, n);
        } else if (nameEql(n, "result")) {
            result = try textContent(allocator, n);
        } else if (nameEql(n, "selector")) {
            selector = try textContent(allocator, n);
        }
    }

    return .{
        .domain = domain,
        .result = result,
        .selector = selector,
    };
}

// --- XML helper functions ---

fn firstElement(maybe_node: ?*c.xmlNode) ?*c.xmlNode {
    var cur = maybe_node;
    while (cur) |n| {
        if (n.*.type == c.XML_ELEMENT_NODE) return n;
        cur = n.*.next;
    }
    return null;
}

fn nextElement(maybe_node: ?*c.xmlNode) ?*c.xmlNode {
    var cur = maybe_node;
    while (cur) |n| {
        if (n.*.type == c.XML_ELEMENT_NODE) return n;
        cur = n.*.next;
    }
    return null;
}

fn nameEql(node: *c.xmlNode, name: []const u8) bool {
    const node_name = node.*.name orelse return false;
    return std.mem.eql(u8, std.mem.span(node_name), name);
}

fn textContent(allocator: Allocator, node: *c.xmlNode) ![]const u8 {
    var text_node = node.*.children;
    while (text_node) |tn| {
        if (tn.*.type == c.XML_TEXT_NODE or tn.*.type == c.XML_CDATA_SECTION_NODE) {
            const content = tn.*.content orelse return try allocator.dupe(u8, "");
            return try allocator.dupe(u8, std.mem.span(content));
        }
        text_node = tn.*.next;
    }
    return try allocator.dupe(u8, "");
}

// --- Tests ---


test "parse basic dmarc xml" {
    const allocator = std.testing.allocator;
    const xml_data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<feedback>
        \\  <report_metadata>
        \\    <org_name>google.com</org_name>
        \\    <email>noreply-dmarc-support@google.com</email>
        \\    <report_id>12345678</report_id>
        \\    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
        \\  </report_metadata>
        \\  <policy_published>
        \\    <domain>example.com</domain>
        \\    <adkim>r</adkim>
        \\    <aspf>r</aspf>
        \\    <p>reject</p>
        \\    <sp>none</sp>
        \\    <pct>100</pct>
        \\  </policy_published>
        \\  <record>
        \\    <row>
        \\      <source_ip>198.51.100.1</source_ip>
        \\      <count>5</count>
        \\      <policy_evaluated>
        \\        <disposition>none</disposition>
        \\        <dkim>pass</dkim>
        \\        <spf>pass</spf>
        \\      </policy_evaluated>
        \\    </row>
        \\    <identifiers>
        \\      <header_from>example.com</header_from>
        \\      <envelope_from>bounce.example.com</envelope_from>
        \\      <envelope_to>recipient.com</envelope_to>
        \\    </identifiers>
        \\    <auth_results>
        \\      <dkim><domain>example.com</domain><result>pass</result><selector>s1</selector></dkim>
        \\      <spf><domain>example.com</domain><result>pass</result></spf>
        \\    </auth_results>
        \\  </record>
        \\</feedback>
    ;

    const report = try parseXml(allocator, xml_data);
    defer report.deinit(allocator);

    try std.testing.expectEqualStrings("google.com", report.metadata.org_name);
    try std.testing.expectEqualStrings("noreply-dmarc-support@google.com", report.metadata.email);
    try std.testing.expectEqualStrings("12345678", report.metadata.report_id);
    try std.testing.expectEqual(@as(i64, 1700000000), report.metadata.date_begin);
    try std.testing.expectEqual(@as(i64, 1700086400), report.metadata.date_end);

    try std.testing.expectEqualStrings("example.com", report.policy.domain);
    try std.testing.expectEqualStrings("reject", report.policy.policy);
    try std.testing.expectEqualStrings("none", report.policy.sub_policy);
    try std.testing.expectEqualStrings("r", report.policy.adkim);
    try std.testing.expectEqual(@as(u32, 100), report.policy.pct);

    try std.testing.expectEqual(@as(usize, 1), report.records.len);
    const rec = report.records[0];
    try std.testing.expectEqualStrings("198.51.100.1", rec.source_ip);
    try std.testing.expectEqual(@as(u32, 5), rec.count);
    try std.testing.expectEqualStrings("none", rec.disposition);
    try std.testing.expectEqualStrings("pass", rec.dkim_eval);
    try std.testing.expectEqualStrings("pass", rec.spf_eval);
    try std.testing.expectEqualStrings("example.com", rec.header_from);
    try std.testing.expectEqualStrings("bounce.example.com", rec.envelope_from);
    try std.testing.expectEqualStrings("recipient.com", rec.envelope_to);

    try std.testing.expectEqual(@as(usize, 1), rec.dkim_results.len);
    try std.testing.expectEqualStrings("pass", rec.dkim_results[0].result);
    try std.testing.expectEqualStrings("s1", rec.dkim_results[0].selector);

    try std.testing.expectEqual(@as(usize, 1), rec.spf_results.len);
    try std.testing.expectEqualStrings("pass", rec.spf_results[0].result);
}

test "parse dmarc xml with multiple records" {
    const allocator = std.testing.allocator;
    const xml_data =
        \\<?xml version="1.0"?>
        \\<feedback>
        \\  <report_metadata>
        \\    <org_name>yahoo.com</org_name>
        \\    <email>dmarchelp@yahoo.com</email>
        \\    <report_id>rpt-99</report_id>
        \\    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
        \\  </report_metadata>
        \\  <policy_published>
        \\    <domain>test.org</domain><adkim>s</adkim><aspf>s</aspf>
        \\    <p>quarantine</p><sp>quarantine</sp><pct>50</pct>
        \\  </policy_published>
        \\  <record>
        \\    <row><source_ip>10.0.0.1</source_ip><count>10</count>
        \\      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>pass</spf></policy_evaluated>
        \\    </row>
        \\    <identifiers><header_from>test.org</header_from></identifiers>
        \\    <auth_results><spf><domain>test.org</domain><result>pass</result></spf></auth_results>
        \\  </record>
        \\  <record>
        \\    <row><source_ip>10.0.0.2</source_ip><count>3</count>
        \\      <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
        \\    </row>
        \\    <identifiers><header_from>test.org</header_from></identifiers>
        \\    <auth_results></auth_results>
        \\  </record>
        \\</feedback>
    ;

    const report = try parseXml(allocator, xml_data);
    defer report.deinit(allocator);

    try std.testing.expectEqualStrings("yahoo.com", report.metadata.org_name);
    try std.testing.expectEqualStrings("quarantine", report.policy.policy);
    try std.testing.expectEqual(@as(u32, 50), report.policy.pct);
    try std.testing.expectEqual(@as(usize, 2), report.records.len);
    try std.testing.expectEqual(@as(u32, 10), report.records[0].count);
    try std.testing.expectEqualStrings("quarantine", report.records[0].disposition);
    try std.testing.expectEqual(@as(u32, 3), report.records[1].count);
    try std.testing.expectEqualStrings("reject", report.records[1].disposition);
}

test "parse dmarc xml missing metadata returns error" {
    const allocator = std.testing.allocator;
    const xml_data =
        \\<?xml version="1.0"?><feedback></feedback>
    ;
    try std.testing.expectError(error.MissingMetadata, parseXml(allocator, xml_data));
}

test "parse dmarc xml invalid xml returns error" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.XmlParseError, parseXml(allocator, "not xml at all<<<"));
}

test "toJson produces valid json" {
    const allocator = std.testing.allocator;
    const report = Report{
        .metadata = .{ .org_name = "test.com", .email = "a@b.com", .report_id = "1", .date_begin = 1000, .date_end = 2000 },
        .policy = .{ .domain = "d.com", .adkim = "r", .aspf = "r", .policy = "none", .sub_policy = "none", .pct = 100 },
        .records = &.{},
    };
    const json = try report.toJson(allocator);
    defer allocator.free(json);
    // Should be valid JSON - verify by parsing
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
}
