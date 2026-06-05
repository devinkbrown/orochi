//! HAProxy PROXY protocol v1/v2 parsing and building.
//!
//! The module is intentionally standalone and allocation-free. Callers provide
//! complete input slices and output buffers; parsed addresses are stored in
//! fixed-size network-byte-order arrays.
const std = @import("std");

pub const v2_signature = [_]u8{ 0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a };
pub const v2_header_len: usize = 16;
pub const v1_max_line_len: usize = 108;

pub const Family = enum {
    unknown,
    tcp4,
    tcp6,

    pub fn ipLen(self: Family) usize {
        return switch (self) {
            .unknown => 0,
            .tcp4 => 4,
            .tcp6 => 16,
        };
    }
};

pub const Header = struct {
    family: Family = .unknown,
    src_ip: [16]u8 = @splat(0),
    src_port: u16 = 0,
    dst_ip: [16]u8 = @splat(0),
    dst_port: u16 = 0,
    is_local: bool = false,

    pub fn srcBytes(self: *const Header) []const u8 {
        return self.src_ip[0..self.family.ipLen()];
    }

    pub fn dstBytes(self: *const Header) []const u8 {
        return self.dst_ip[0..self.family.ipLen()];
    }
};

pub const Parsed = struct {
    header: Header,
    consumed: usize,
};

pub const ParseError = error{
    InvalidAddress,
    InvalidCommand,
    InvalidFamily,
    InvalidLine,
    InvalidPort,
    InvalidProtocol,
    InvalidSignature,
    InvalidVersion,
    LineTooLong,
    Truncated,
};

pub const BuildError = error{
    InvalidFamily,
    OutputTooSmall,
};

pub fn parse(input: []const u8) ParseError!Parsed {
    if (std.mem.startsWith(u8, input, "PROXY ")) return parseV1(input);
    if (input.len >= v2_signature.len and std.mem.eql(u8, input[0..v2_signature.len], &v2_signature)) {
        return parseV2(input);
    }
    return error.InvalidSignature;
}

pub fn parseV1(input: []const u8) ParseError!Parsed {
    const line_end = findV1LineEnd(input) orelse {
        if (input.len > v1_max_line_len) return error.LineTooLong;
        return error.Truncated;
    };
    if (line_end + 2 > v1_max_line_len) return error.LineTooLong;

    const line = input[0..line_end];
    if (!std.mem.startsWith(u8, line, "PROXY ")) return error.InvalidLine;

    var fields = std.mem.splitScalar(u8, line[6..], ' ');
    const proto = fields.next() orelse return error.InvalidLine;

    if (std.mem.eql(u8, proto, "UNKNOWN")) {
        return .{ .header = .{}, .consumed = line_end + 2 };
    }

    const family: Family = if (std.mem.eql(u8, proto, "TCP4"))
        .tcp4
    else if (std.mem.eql(u8, proto, "TCP6"))
        .tcp6
    else
        return error.InvalidProtocol;

    const src_text = fields.next() orelse return error.InvalidLine;
    const dst_text = fields.next() orelse return error.InvalidLine;
    const src_port_text = fields.next() orelse return error.InvalidLine;
    const dst_port_text = fields.next() orelse return error.InvalidLine;
    if (fields.next() != null) return error.InvalidLine;

    var header = Header{ .family = family };
    try parseIpInto(family, src_text, &header.src_ip);
    try parseIpInto(family, dst_text, &header.dst_ip);
    header.src_port = parsePort(src_port_text) catch return error.InvalidPort;
    header.dst_port = parsePort(dst_port_text) catch return error.InvalidPort;
    return .{ .header = header, .consumed = line_end + 2 };
}

pub fn parseV2(input: []const u8) ParseError!Parsed {
    if (input.len < v2_header_len) {
        if (input.len <= v2_signature.len or !std.mem.eql(u8, input[0..v2_signature.len], &v2_signature)) {
            return error.InvalidSignature;
        }
        return error.Truncated;
    }
    if (!std.mem.eql(u8, input[0..v2_signature.len], &v2_signature)) return error.InvalidSignature;

    const ver_cmd = input[12];
    if ((ver_cmd & 0xf0) != 0x20) return error.InvalidVersion;

    const command = ver_cmd & 0x0f;
    const fam_proto = input[13];
    const payload_len = readU16(input[14..16]);
    const consumed = v2_header_len + @as(usize, payload_len);
    if (input.len < consumed) return error.Truncated;

    if (command == 0x00) {
        return .{ .header = .{ .is_local = true }, .consumed = consumed };
    }
    if (command != 0x01) return error.InvalidCommand;

    const payload = input[v2_header_len..consumed];
    return switch (fam_proto) {
        0x00 => .{ .header = .{}, .consumed = consumed },
        0x11 => parseV2Tcp4(payload, consumed),
        0x21 => parseV2Tcp6(payload, consumed),
        else => error.InvalidFamily,
    };
}

pub fn buildV1(out: []u8, header: Header) BuildError![]u8 {
    if (header.is_local or header.family == .unknown) return copyOut(out, "PROXY UNKNOWN\r\n");

    var src_buf: [39]u8 = undefined;
    var dst_buf: [39]u8 = undefined;
    const src = formatIp(header.family, header.srcBytes(), &src_buf);
    const dst = formatIp(header.family, header.dstBytes(), &dst_buf);
    const proto = switch (header.family) {
        .tcp4 => "TCP4",
        .tcp6 => "TCP6",
        .unknown => unreachable,
    };
    return std.fmt.bufPrint(out, "PROXY {s} {s} {s} {d} {d}\r\n", .{
        proto,
        src,
        dst,
        header.src_port,
        header.dst_port,
    }) catch error.OutputTooSmall;
}

pub fn buildV2(out: []u8, header: Header) BuildError![]u8 {
    const addr_len: usize = switch (header.family) {
        .unknown => 0,
        .tcp4 => 12,
        .tcp6 => 36,
    };
    const total_len = v2_header_len + if (header.is_local) 0 else addr_len;
    if (out.len < total_len) return error.OutputTooSmall;

    @memcpy(out[0..v2_signature.len], &v2_signature);
    out[12] = if (header.is_local) 0x20 else 0x21;
    out[13] = if (header.is_local) 0x00 else switch (header.family) {
        .unknown => 0x00,
        .tcp4 => 0x11,
        .tcp6 => 0x21,
    };
    writeU16(out[14..16], @intCast(total_len - v2_header_len));

    if (header.is_local or header.family == .unknown) return out[0..total_len];

    switch (header.family) {
        .tcp4 => {
            @memcpy(out[16..20], header.src_ip[0..4]);
            @memcpy(out[20..24], header.dst_ip[0..4]);
            writeU16(out[24..26], header.src_port);
            writeU16(out[26..28], header.dst_port);
        },
        .tcp6 => {
            @memcpy(out[16..32], header.src_ip[0..16]);
            @memcpy(out[32..48], header.dst_ip[0..16]);
            writeU16(out[48..50], header.src_port);
            writeU16(out[50..52], header.dst_port);
        },
        .unknown => unreachable,
    }
    return out[0..total_len];
}

fn parseV2Tcp4(payload: []const u8, consumed: usize) ParseError!Parsed {
    if (payload.len != 12) return error.InvalidFamily;
    var header = Header{ .family = .tcp4 };
    @memcpy(header.src_ip[0..4], payload[0..4]);
    @memcpy(header.dst_ip[0..4], payload[4..8]);
    header.src_port = readU16(payload[8..10]);
    header.dst_port = readU16(payload[10..12]);
    return .{ .header = header, .consumed = consumed };
}

fn parseV2Tcp6(payload: []const u8, consumed: usize) ParseError!Parsed {
    if (payload.len != 36) return error.InvalidFamily;
    var header = Header{ .family = .tcp6 };
    @memcpy(header.src_ip[0..16], payload[0..16]);
    @memcpy(header.dst_ip[0..16], payload[16..32]);
    header.src_port = readU16(payload[32..34]);
    header.dst_port = readU16(payload[34..36]);
    return .{ .header = header, .consumed = consumed };
}

fn findV1LineEnd(input: []const u8) ?usize {
    const limit = @min(input.len, v1_max_line_len);
    var i: usize = 0;
    while (i + 1 < limit) : (i += 1) {
        if (input[i] == '\r' and input[i + 1] == '\n') return i;
    }
    return null;
}

fn parseIpInto(family: Family, text: []const u8, out: *[16]u8) ParseError!void {
    out.* = @splat(0);
    switch (family) {
        .tcp4 => {
            const addr = std.Io.net.IpAddress.parseIp4(text, 0) catch return error.InvalidAddress;
            @memcpy(out[0..4], addr.ip4.bytes[0..4]);
        },
        .tcp6 => {
            const addr = std.Io.net.IpAddress.parseIp6(text, 0) catch return error.InvalidAddress;
            @memcpy(out[0..16], addr.ip6.bytes[0..16]);
        },
        .unknown => return error.InvalidFamily,
    }
}

fn parsePort(text: []const u8) !u16 {
    if (text.len == 0) return error.InvalidPort;
    return std.fmt.parseInt(u16, text, 10);
}

fn formatIp(family: Family, bytes: []const u8, out: []u8) []const u8 {
    return switch (family) {
        .tcp4 => std.fmt.bufPrint(out, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] }) catch unreachable,
        .tcp6 => formatIpv6(bytes[0..16], out),
        .unknown => unreachable,
    };
}

fn formatIpv6(bytes: []const u8, out: []u8) []const u8 {
    var pos: usize = 0;
    var group: usize = 0;
    while (group < 8) : (group += 1) {
        if (group != 0) {
            out[pos] = ':';
            pos += 1;
        }
        const word = (@as(u16, bytes[group * 2]) << 8) | bytes[group * 2 + 1];
        const text = std.fmt.bufPrint(out[pos..], "{x}", .{word}) catch unreachable;
        pos += text.len;
    }
    return out[0..pos];
}

fn copyOut(out: []u8, text: []const u8) BuildError![]u8 {
    if (out.len < text.len) return error.OutputTooSmall;
    @memcpy(out[0..text.len], text);
    return out[0..text.len];
}

fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | bytes[1];
}

fn writeU16(bytes: []u8, value: u16) void {
    bytes[0] = @intCast(value >> 8);
    bytes[1] = @intCast(value & 0xff);
}

fn expectHeaderEqual(expected: Header, actual: Header) !void {
    try std.testing.expectEqual(expected.family, actual.family);
    try std.testing.expectEqual(expected.src_port, actual.src_port);
    try std.testing.expectEqual(expected.dst_port, actual.dst_port);
    try std.testing.expectEqual(expected.is_local, actual.is_local);
    try std.testing.expectEqualSlices(u8, expected.srcBytes(), actual.srcBytes());
    try std.testing.expectEqualSlices(u8, expected.dstBytes(), actual.dstBytes());
}

fn ip4(a: u8, b: u8, c: u8, d: u8) [16]u8 {
    var out: [16]u8 = @splat(0);
    out[0] = a;
    out[1] = b;
    out[2] = c;
    out[3] = d;
    return out;
}

fn ip6(bytes: [16]u8) [16]u8 {
    return bytes;
}

test "v1 TCP4 round-trip" {
    const expected = Header{
        .family = .tcp4,
        .src_ip = ip4(192, 0, 2, 10),
        .dst_ip = ip4(198, 51, 100, 20),
        .src_port = 44321,
        .dst_port = 6697,
    };

    var buf: [128]u8 = undefined;
    const built = try buildV1(&buf, expected);
    try std.testing.expectEqualStrings("PROXY TCP4 192.0.2.10 198.51.100.20 44321 6697\r\n", built);

    const parsed = try parseV1(built);
    try std.testing.expectEqual(built.len, parsed.consumed);
    try expectHeaderEqual(expected, parsed.header);
    try expectHeaderEqual(expected, (try parse(built)).header);
}

test "v1 TCP6 round-trip" {
    const expected = Header{
        .family = .tcp6,
        .src_ip = ip6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }),
        .dst_ip = ip6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }),
        .src_port = 12345,
        .dst_port = 443,
    };

    var buf: [160]u8 = undefined;
    const built = try buildV1(&buf, expected);
    try std.testing.expectEqualStrings("PROXY TCP6 2001:db8:0:0:0:0:0:1 2001:db8:0:0:0:0:0:2 12345 443\r\n", built);

    const parsed = try parseV1(built);
    try std.testing.expectEqual(built.len, parsed.consumed);
    try expectHeaderEqual(expected, parsed.header);
}

test "v2 TCP4 round-trip" {
    const expected = Header{
        .family = .tcp4,
        .src_ip = ip4(10, 1, 2, 3),
        .dst_ip = ip4(10, 9, 8, 7),
        .src_port = 50000,
        .dst_port = 6667,
    };

    var buf: [64]u8 = undefined;
    const built = try buildV2(&buf, expected);
    try std.testing.expectEqual(@as(usize, 28), built.len);
    try std.testing.expectEqualSlices(u8, &v2_signature, built[0..12]);
    try std.testing.expectEqual(@as(u8, 0x21), built[12]);
    try std.testing.expectEqual(@as(u8, 0x11), built[13]);
    try std.testing.expectEqual(@as(u16, 12), readU16(built[14..16]));

    const parsed = try parseV2(built);
    try std.testing.expectEqual(built.len, parsed.consumed);
    try expectHeaderEqual(expected, parsed.header);
    try expectHeaderEqual(expected, (try parse(built)).header);
}

test "v2 TCP6 round-trip" {
    const expected = Header{
        .family = .tcp6,
        .src_ip = ip6(.{ 0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5 }),
        .dst_ip = ip6(.{ 0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10 }),
        .src_port = 60000,
        .dst_port = 7000,
    };

    var buf: [80]u8 = undefined;
    const built = try buildV2(&buf, expected);
    try std.testing.expectEqual(@as(usize, 52), built.len);
    try std.testing.expectEqual(@as(u8, 0x21), built[12]);
    try std.testing.expectEqual(@as(u8, 0x21), built[13]);
    try std.testing.expectEqual(@as(u16, 36), readU16(built[14..16]));

    const parsed = try parseV2(built);
    try std.testing.expectEqual(built.len, parsed.consumed);
    try expectHeaderEqual(expected, parsed.header);
}

test "v2 LOCAL command ignores payload" {
    var input: [20]u8 = undefined;
    @memcpy(input[0..12], &v2_signature);
    input[12] = 0x20;
    input[13] = 0x11;
    writeU16(input[14..16], 4);
    input[16..20].* = .{ 1, 2, 3, 4 };

    const parsed = try parseV2(&input);
    try std.testing.expect(parsed.header.is_local);
    try std.testing.expectEqual(Family.unknown, parsed.header.family);
    try std.testing.expectEqual(@as(usize, input.len), parsed.consumed);

    var buf: [16]u8 = undefined;
    const built = try buildV2(&buf, .{ .is_local = true });
    try std.testing.expectEqual(@as(usize, 16), built.len);
    try std.testing.expectEqual(@as(u8, 0x20), built[12]);
    try std.testing.expectEqual(@as(u8, 0x00), built[13]);
    try std.testing.expectEqual(@as(u16, 0), readU16(built[14..16]));
}

test "bad signatures and truncation are rejected" {
    try std.testing.expectError(error.InvalidSignature, parse("BROXY TCP4 1.1.1.1 2.2.2.2 1 2\r\n"));
    try std.testing.expectError(error.Truncated, parse("PROXY TCP4 1.1.1.1 2.2.2.2 1 2"));

    var bad_v2: [16]u8 = undefined;
    @memcpy(bad_v2[0..12], &v2_signature);
    bad_v2[0] = 0;
    bad_v2[12] = 0x21;
    bad_v2[13] = 0x11;
    writeU16(bad_v2[14..16], 0);
    try std.testing.expectError(error.InvalidSignature, parseV2(&bad_v2));

    var truncated_v2: [16]u8 = undefined;
    @memcpy(truncated_v2[0..12], &v2_signature);
    truncated_v2[12] = 0x21;
    truncated_v2[13] = 0x11;
    writeU16(truncated_v2[14..16], 12);
    try std.testing.expectError(error.Truncated, parseV2(&truncated_v2));
}

test "v1 UNKNOWN is accepted and deterministic" {
    const parsed = try parseV1("PROXY UNKNOWN\r\nrest");
    try std.testing.expectEqual(Family.unknown, parsed.header.family);
    try std.testing.expect(!parsed.header.is_local);
    try std.testing.expectEqual(@as(usize, 15), parsed.consumed);

    var buf: [32]u8 = undefined;
    const first = try buildV1(&buf, parsed.header);
    try std.testing.expectEqualStrings("PROXY UNKNOWN\r\n", first);
    const second = try buildV1(&buf, .{ .family = .unknown });
    try std.testing.expectEqualStrings(first, second);
}

test "invalid v1 fields are rejected" {
    try std.testing.expectError(error.InvalidProtocol, parseV1("PROXY UDP4 1.1.1.1 2.2.2.2 1 2\r\n"));
    try std.testing.expectError(error.InvalidAddress, parseV1("PROXY TCP4 2001:db8::1 2.2.2.2 1 2\r\n"));
    try std.testing.expectError(error.InvalidPort, parseV1("PROXY TCP4 1.1.1.1 2.2.2.2 nope 2\r\n"));
    try std.testing.expectError(error.InvalidLine, parseV1("PROXY TCP4 1.1.1.1 2.2.2.2 1 2 extra\r\n"));
}
