// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const Transport = enum {
    udp,
    tcp,
};

pub const CandType = enum {
    host,
    srflx,
    prflx,
    relay,
};

pub const Candidate = struct {
    foundation: []const u8,
    component: u8,
    transport: Transport,
    priority: u32,
    address: []const u8,
    port: u16,
    typ: CandType,
    raddr: ?[]const u8 = null,
    rport: ?u16 = null,
};

pub const Error = error{ BadFormat, BufferTooSmall };

pub fn parse(line: []const u8) Error!Candidate {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    const text = if (std.mem.startsWith(u8, trimmed, "candidate:"))
        trimmed["candidate:".len..]
    else
        trimmed;

    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");

    const foundation = tokens.next() orelse return error.BadFormat;
    const component = try parseInt(u8, tokens.next() orelse return error.BadFormat);
    const transport = try parseTransport(tokens.next() orelse return error.BadFormat);
    const priority = try parseInt(u32, tokens.next() orelse return error.BadFormat);
    const address = tokens.next() orelse return error.BadFormat;
    const port = try parseInt(u16, tokens.next() orelse return error.BadFormat);

    if (!std.mem.eql(u8, tokens.next() orelse return error.BadFormat, "typ")) {
        return error.BadFormat;
    }
    const typ = try parseCandType(tokens.next() orelse return error.BadFormat);

    var out = Candidate{
        .foundation = foundation,
        .component = component,
        .transport = transport,
        .priority = priority,
        .address = address,
        .port = port,
        .typ = typ,
    };

    while (tokens.next()) |name| {
        const value = tokens.next() orelse return error.BadFormat;
        if (std.mem.eql(u8, name, "raddr")) {
            out.raddr = value;
        } else if (std.mem.eql(u8, name, "rport")) {
            out.rport = try parseInt(u16, value);
        } else if (std.mem.eql(u8, name, "generation")) {
            _ = try parseInt(u32, value);
        } else if (std.mem.eql(u8, name, "ufrag")) {
            if (value.len == 0) return error.BadFormat;
        } else {
            return error.BadFormat;
        }
    }

    if ((out.raddr == null) != (out.rport == null)) return error.BadFormat;
    return out;
}

pub fn build(c: Candidate, out: []u8) Error![]const u8 {
    if ((c.raddr == null) != (c.rport == null)) return error.BadFormat;

    var used: usize = 0;
    const base = std.fmt.bufPrint(
        out[used..],
        "candidate:{s} {d} {s} {d} {s} {d} typ {s}",
        .{
            c.foundation,
            c.component,
            transportName(c.transport),
            c.priority,
            c.address,
            c.port,
            candTypeName(c.typ),
        },
    ) catch return error.BufferTooSmall;
    used += base.len;

    if (c.raddr) |raddr| {
        const related = std.fmt.bufPrint(out[used..], " raddr {s} rport {d}", .{ raddr, c.rport.? }) catch return error.BufferTooSmall;
        used += related.len;
    }

    return out[0..used];
}

fn parseTransport(value: []const u8) Error!Transport {
    if (std.ascii.eqlIgnoreCase(value, "udp")) return .udp;
    if (std.ascii.eqlIgnoreCase(value, "tcp")) return .tcp;
    return error.BadFormat;
}

fn parseCandType(value: []const u8) Error!CandType {
    if (std.mem.eql(u8, value, "host")) return .host;
    if (std.mem.eql(u8, value, "srflx")) return .srflx;
    if (std.mem.eql(u8, value, "prflx")) return .prflx;
    if (std.mem.eql(u8, value, "relay")) return .relay;
    return error.BadFormat;
}

fn parseInt(comptime T: type, value: []const u8) Error!T {
    if (value.len == 0) return error.BadFormat;
    return std.fmt.parseInt(T, value, 10) catch error.BadFormat;
}

fn transportName(value: Transport) []const u8 {
    return switch (value) {
        .udp => "udp",
        .tcp => "tcp",
    };
}

fn candTypeName(value: CandType) []const u8 {
    return switch (value) {
        .host => "host",
        .srflx => "srflx",
        .prflx => "prflx",
        .relay => "relay",
    };
}

test "parse host candidate" {
    const c = try parse("candidate:842163049 1 UDP 1677729535 192.0.2.172 54400 typ host generation 0 ufrag abc");

    try std.testing.expectEqualStrings("842163049", c.foundation);
    try std.testing.expectEqual(@as(u8, 1), c.component);
    try std.testing.expectEqual(.udp, c.transport);
    try std.testing.expectEqual(@as(u32, 1677729535), c.priority);
    try std.testing.expectEqualStrings("192.0.2.172", c.address);
    try std.testing.expectEqual(@as(u16, 54400), c.port);
    try std.testing.expectEqual(CandType.host, c.typ);
    try std.testing.expect(c.raddr == null);
    try std.testing.expect(c.rport == null);
}

test "parse srflx candidate with related address" {
    const c = try parse("842163049 1 udp 1677729535 203.0.113.1 3478 typ srflx raddr 10.0.0.1 rport 8998");

    try std.testing.expectEqualStrings("842163049", c.foundation);
    try std.testing.expectEqual(@as(u8, 1), c.component);
    try std.testing.expectEqual(.udp, c.transport);
    try std.testing.expectEqual(@as(u32, 1677729535), c.priority);
    try std.testing.expectEqualStrings("203.0.113.1", c.address);
    try std.testing.expectEqual(@as(u16, 3478), c.port);
    try std.testing.expectEqual(CandType.srflx, c.typ);
    try std.testing.expectEqualStrings("10.0.0.1", c.raddr.?);
    try std.testing.expectEqual(@as(u16, 8998), c.rport.?);
}

test "build candidate and parse to equality" {
    const original = Candidate{
        .foundation = "relay1",
        .component = 2,
        .transport = .tcp,
        .priority = 42,
        .address = "2001:db8::1",
        .port = 443,
        .typ = .relay,
        .raddr = "192.0.2.1",
        .rport = 5000,
    };
    var buf: [128]u8 = undefined;

    const text = try build(original, &buf);
    const parsed = try parse(text);

    try std.testing.expectEqualStrings(original.foundation, parsed.foundation);
    try std.testing.expectEqual(original.component, parsed.component);
    try std.testing.expectEqual(original.transport, parsed.transport);
    try std.testing.expectEqual(original.priority, parsed.priority);
    try std.testing.expectEqualStrings(original.address, parsed.address);
    try std.testing.expectEqual(original.port, parsed.port);
    try std.testing.expectEqual(original.typ, parsed.typ);
    try std.testing.expectEqualStrings(original.raddr.?, parsed.raddr.?);
    try std.testing.expectEqual(original.rport.?, parsed.rport.?);
}

test "bad format on missing typ" {
    try std.testing.expectError(error.BadFormat, parse("1 1 udp 100 192.0.2.1 5000 host"));
}

test "tolerate optional candidate prefix" {
    const without_prefix = try parse("1 1 udp 100 192.0.2.1 5000 typ host");
    const with_prefix = try parse("candidate:1 1 udp 100 192.0.2.1 5000 typ host");

    try std.testing.expectEqualStrings(without_prefix.foundation, with_prefix.foundation);
    try std.testing.expectEqual(without_prefix.component, with_prefix.component);
    try std.testing.expectEqual(without_prefix.transport, with_prefix.transport);
    try std.testing.expectEqual(without_prefix.priority, with_prefix.priority);
    try std.testing.expectEqualStrings(without_prefix.address, with_prefix.address);
    try std.testing.expectEqual(without_prefix.port, with_prefix.port);
    try std.testing.expectEqual(without_prefix.typ, with_prefix.typ);
}
