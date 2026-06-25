// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! X.509 Name (RDNSequence) DER encoder/parser.
const std = @import("std");

comptime {
    if (@sizeOf(usize) != 8) @compileError("x509_name requires a 64-bit target");
}

pub const Error = error{
    InvalidDer,
    InvalidLength,
    InvalidTag,
    InvalidUtf8,
    LengthOverflow,
    NoSpaceLeft,
    Truncated,
};

pub const Rdn = struct {
    /// DER content octets of the OBJECT IDENTIFIER, without tag/length.
    oid_content: []const u8,
    /// UTF-8 text encoded as a DER UTF8String value.
    value_utf8: []const u8,
};

pub const ParsedRdn = struct {
    /// DER content octets of the OBJECT IDENTIFIER, borrowed from `der`.
    oid: []const u8,
    /// UTF8String content bytes, borrowed from `der`.
    value: []const u8,
};

const tag_oid: u8 = 0x06;
const tag_utf8_string: u8 = 0x0c;
const tag_sequence: u8 = 0x30;
const tag_set: u8 = 0x31;
const common_name_oid = [_]u8{ 0x55, 0x04, 0x03 };

pub fn encodeName(out: []u8, rdns: []const Rdn) Error![]u8 {
    var content_len: usize = 0;
    for (rdns) |rdn| {
        try validateOidContent(rdn.oid_content);
        if (!std.unicode.utf8ValidateSlice(rdn.value_utf8)) return error.InvalidUtf8;
        const attr_content_len = try addLen(
            try tlvSize(rdn.oid_content.len),
            try tlvSize(rdn.value_utf8.len),
        );
        content_len = try addLen(content_len, try tlvSize(try tlvSize(attr_content_len)));
    }

    const total_len = try tlvSize(content_len);
    if (total_len > out.len) return error.NoSpaceLeft;

    var writer = Writer{ .buf = out };
    try writer.header(tag_sequence, content_len);
    for (rdns) |rdn| {
        const attr_content_len = try addLen(
            try tlvSize(rdn.oid_content.len),
            try tlvSize(rdn.value_utf8.len),
        );
        const attr_tlv_len = try tlvSize(attr_content_len);

        try writer.header(tag_set, attr_tlv_len);
        try writer.header(tag_sequence, attr_content_len);
        try writer.tlv(tag_oid, rdn.oid_content);
        try writer.tlv(tag_utf8_string, rdn.value_utf8);
    }

    return out[0..writer.pos];
}

pub fn parseName(der: []const u8, out_rdns: []ParsedRdn) Error![]ParsedRdn {
    var cursor: usize = 0;
    const name = try readTlv(der, &cursor);
    try expectTag(name, tag_sequence);
    if (cursor != der.len) return error.InvalidDer;

    var count: usize = 0;
    var name_cursor: usize = 0;
    while (name_cursor < name.content.len) {
        if (count >= out_rdns.len) return error.NoSpaceLeft;
        out_rdns[count] = try parseSingleValuedRdn(name.content, &name_cursor);
        count += 1;
    }

    return out_rdns[0..count];
}

pub fn commonNameOf(der: []const u8) ?[]const u8 {
    var cursor: usize = 0;
    const name = readTlv(der, &cursor) catch return null;
    expectTag(name, tag_sequence) catch return null;
    if (cursor != der.len) return null;

    var name_cursor: usize = 0;
    while (name_cursor < name.content.len) {
        const rdn = parseSingleValuedRdn(name.content, &name_cursor) catch return null;
        if (std.mem.eql(u8, rdn.oid, common_name_oid[0..])) return rdn.value;
    }
    return null;
}

const Tlv = struct {
    tag: u8,
    content: []const u8,
};

fn parseSingleValuedRdn(input: []const u8, cursor: *usize) Error!ParsedRdn {
    const set = try readTlv(input, cursor);
    try expectTag(set, tag_set);

    var set_cursor: usize = 0;
    const attr = try readTlv(set.content, &set_cursor);
    try expectTag(attr, tag_sequence);
    if (set_cursor != set.content.len) return error.InvalidDer;

    var attr_cursor: usize = 0;
    const oid = try readTlv(attr.content, &attr_cursor);
    try expectTag(oid, tag_oid);
    try validateOidContent(oid.content);

    const value = try readTlv(attr.content, &attr_cursor);
    try expectTag(value, tag_utf8_string);
    if (attr_cursor != attr.content.len) return error.InvalidDer;
    if (!std.unicode.utf8ValidateSlice(value.content)) return error.InvalidUtf8;

    return .{
        .oid = oid.content,
        .value = value.content,
    };
}

fn readTlv(input: []const u8, cursor: *usize) Error!Tlv {
    if (cursor.* > input.len) return error.InvalidDer;
    const start = cursor.*;
    if (input.len - start < 2) return error.Truncated;

    const tag = input[cursor.*];
    cursor.* += 1;
    if (tag & 0x1f == 0x1f) return error.InvalidTag;

    const len = try readLength(input, cursor);
    const content_start = cursor.*;
    if (len > input.len - content_start) return error.Truncated;
    cursor.* += len;

    return .{
        .tag = tag,
        .content = input[content_start..cursor.*],
    };
}

fn readLength(input: []const u8, cursor: *usize) Error!usize {
    if (cursor.* >= input.len) return error.Truncated;

    const first = input[cursor.*];
    cursor.* += 1;
    if (first & 0x80 == 0) return @as(usize, first);

    const count = first & 0x7f;
    if (count == 0) return error.InvalidLength;
    if (count > @sizeOf(usize)) return error.LengthOverflow;
    if (count > input.len - cursor.*) return error.Truncated;
    if (input[cursor.*] == 0) return error.InvalidLength;

    var len: usize = 0;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        len = (len << 8) | input[cursor.*];
        cursor.* += 1;
    }
    if (len < 128) return error.InvalidLength;
    return len;
}

fn expectTag(tlv: Tlv, tag: u8) Error!void {
    if (tlv.tag != tag) return error.InvalidTag;
}

fn validateOidContent(content: []const u8) Error!void {
    if (content.len == 0) return error.InvalidDer;

    var cursor: usize = 0;
    while (cursor < content.len) {
        if (content[cursor] == 0x80) return error.InvalidDer;
        while (true) {
            if (cursor >= content.len) return error.InvalidDer;
            const byte = content[cursor];
            cursor += 1;
            if (byte & 0x80 == 0) break;
        }
    }
}

fn addLen(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.LengthOverflow;
}

fn lenLen(len: usize) Error!usize {
    if (len < 128) return 1;

    var value = len;
    var bytes: usize = 0;
    while (value != 0) {
        bytes += 1;
        value >>= 8;
    }
    if (bytes > @sizeOf(usize)) return error.LengthOverflow;
    return try addLen(1, bytes);
}

fn tlvSize(content_len: usize) Error!usize {
    return try addLen(try addLen(1, try lenLen(content_len)), content_len);
}

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn tlv(self: *Writer, tag: u8, content: []const u8) Error!void {
        try self.header(tag, content.len);
        try self.bytes(content);
    }

    fn header(self: *Writer, tag: u8, content_len: usize) Error!void {
        try self.byte(tag);
        try self.length(content_len);
    }

    fn length(self: *Writer, len: usize) Error!void {
        if (len < 128) {
            try self.byte(@as(u8, @intCast(len)));
            return;
        }

        var value = len;
        var count: usize = 0;
        while (value != 0) {
            count += 1;
            value >>= 8;
        }

        try self.byte(0x80 | @as(u8, @intCast(count)));
        while (count > 0) {
            count -= 1;
            try self.byte(@as(u8, @truncate(len >> @as(u6, @intCast(count * 8)))));
        }
    }

    fn bytes(self: *Writer, input: []const u8) Error!void {
        if (input.len > self.buf.len - self.pos) return error.NoSpaceLeft;
        @memcpy(self.buf[self.pos .. self.pos + input.len], input);
        self.pos += input.len;
    }

    fn byte(self: *Writer, value: u8) Error!void {
        if (self.pos >= self.buf.len) return error.NoSpaceLeft;
        self.buf[self.pos] = value;
        self.pos += 1;
    }
};

test "encodeName writes known DER for a single commonName RDN" {
    // Arrange
    const cn_oid = [_]u8{ 0x55, 0x04, 0x03 };
    const rdns = [_]Rdn{.{
        .oid_content = cn_oid[0..],
        .value_utf8 = "example.com",
    }};
    const expected = [_]u8{
        0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x0b, 'e',  'x',  'a',
        'm',  'p',  'l',  'e',  '.',  'c',  'o',  'm',
    };
    var out: [64]u8 = undefined;

    // Act
    const der = try encodeName(out[0..], rdns[0..]);

    // Assert
    try std.testing.expectEqualSlices(u8, expected[0..], der);
    try std.testing.expectEqualSlices(u8, "example.com", commonNameOf(der).?);
}

test "parseName returns borrowed OID and value slices for multiple RDNs" {
    // Arrange
    const cn_oid = [_]u8{ 0x55, 0x04, 0x03 };
    const org_oid = [_]u8{ 0x55, 0x04, 0x0a };
    const rdns = [_]Rdn{
        .{ .oid_content = org_oid[0..], .value_utf8 = "Example Org" },
        .{ .oid_content = cn_oid[0..], .value_utf8 = "unit.test" },
    };
    var der_buf: [128]u8 = undefined;
    const der = try encodeName(der_buf[0..], rdns[0..]);
    var parsed_buf: [2]ParsedRdn = undefined;

    // Act
    const parsed = try parseName(der, parsed_buf[0..]);

    // Assert
    try std.testing.expectEqual(@as(usize, 2), parsed.len);
    try std.testing.expectEqualSlices(u8, org_oid[0..], parsed[0].oid);
    try std.testing.expectEqualSlices(u8, "Example Org", parsed[0].value);
    try std.testing.expectEqualSlices(u8, cn_oid[0..], parsed[1].oid);
    try std.testing.expectEqualSlices(u8, "unit.test", parsed[1].value);
    try std.testing.expectEqualSlices(u8, "unit.test", commonNameOf(der).?);
}

test "encodeName and parseName handle DER long-form lengths" {
    // Arrange
    const cn_oid = [_]u8{ 0x55, 0x04, 0x03 };
    var long_name: [130]u8 = undefined;
    @memset(long_name[0..], 'a');
    const rdns = [_]Rdn{.{
        .oid_content = cn_oid[0..],
        .value_utf8 = long_name[0..],
    }};
    var der_buf: [160]u8 = undefined;
    var parsed_buf: [1]ParsedRdn = undefined;

    // Act
    const der = try encodeName(der_buf[0..], rdns[0..]);
    const parsed = try parseName(der, parsed_buf[0..]);

    // Assert
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x81, 0x90 }, der[0..3]);
    try std.testing.expectEqual(@as(usize, 1), parsed.len);
    try std.testing.expectEqualSlices(u8, long_name[0..], parsed[0].value);
}

test "parseName rejects truncated DER" {
    // Arrange
    const der = [_]u8{
        0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x0b, 'e',  'x',  'a',
        'm',  'p',  'l',  'e',  '.',  'c',  'o',
    };
    var parsed_buf: [1]ParsedRdn = undefined;

    // Act
    const result = parseName(der[0..], parsed_buf[0..]);

    // Assert
    try std.testing.expectError(error.Truncated, result);
}

test "encodeName reports NoSpaceLeft when caller buffer is too small" {
    // Arrange
    const cn_oid = [_]u8{ 0x55, 0x04, 0x03 };
    const rdns = [_]Rdn{.{
        .oid_content = cn_oid[0..],
        .value_utf8 = "example.com",
    }};
    var out: [8]u8 = undefined;

    // Act
    const result = encodeName(out[0..], rdns[0..]);

    // Assert
    try std.testing.expectError(error.NoSpaceLeft, result);
}

test "parseName reports NoSpaceLeft when output RDN buffer is too small" {
    // Arrange
    const cn_oid = [_]u8{ 0x55, 0x04, 0x03 };
    const org_oid = [_]u8{ 0x55, 0x04, 0x0a };
    const rdns = [_]Rdn{
        .{ .oid_content = org_oid[0..], .value_utf8 = "Example Org" },
        .{ .oid_content = cn_oid[0..], .value_utf8 = "unit.test" },
    };
    var der_buf: [128]u8 = undefined;
    const der = try encodeName(der_buf[0..], rdns[0..]);
    var parsed_buf: [1]ParsedRdn = undefined;

    // Act
    const result = parseName(der, parsed_buf[0..]);

    // Assert
    try std.testing.expectError(error.NoSpaceLeft, result);
}

test "parseName rejects over-sized DER length octet counts" {
    // Arrange
    const der = [_]u8{ 0x30, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var parsed_buf: [1]ParsedRdn = undefined;

    // Act
    const result = parseName(der[0..], parsed_buf[0..]);

    // Assert
    try std.testing.expectError(error.LengthOverflow, result);
}

test "parseName rejects invalid UTF8String bytes" {
    // Arrange
    const der = [_]u8{
        0x30, 0x0a, 0x31, 0x08, 0x30, 0x06, 0x06,
        0x01, 0x55, 0x0c, 0x01, 0xff,
    };
    var parsed_buf: [1]ParsedRdn = undefined;

    // Act
    const result = parseName(der[0..], parsed_buf[0..]);

    // Assert
    try std.testing.expectError(error.InvalidUtf8, result);
    try std.testing.expect(commonNameOf(der[0..]) == null);
}

test "commonNameOf returns null when the name has no commonName RDN" {
    // Arrange
    const org_oid = [_]u8{ 0x55, 0x04, 0x0a };
    const rdns = [_]Rdn{.{
        .oid_content = org_oid[0..],
        .value_utf8 = "Example Org",
    }};
    var der_buf: [64]u8 = undefined;
    const der = try encodeName(der_buf[0..], rdns[0..]);

    // Act
    const cn = commonNameOf(der);

    // Assert
    try std.testing.expect(cn == null);
}
