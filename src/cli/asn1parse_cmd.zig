// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor asn1parse` — DER structure dump using the substrate's strict,
//! bounds-checked walker (src/crypto/x509.zig `DerReader`, which enforces
//! canonical lengths, depth caps, and the 1 MiB ceiling). This module only
//! formats what the reader yields; a malformed input surfaces the reader's
//! typed error, never a crash.

const std = @import("std");
const orochi = @import("orochi");
const common = @import("common.zig");

const x509 = orochi.crypto.x509;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

pub const Options = struct {
    in_path: []const u8 = "-",
    inform: common.Form = .auto,
    /// PEM label to decode when the input is PEM (any label accepted via
    /// decodeFirst when unset).
    label: ?[]const u8 = null,
};

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor asn1parse [-in <path>] [-inform pem|der] [-label <name>]
        \\  -in <path>        input (PEM or DER; default stdin)
        \\  -inform pem|der   force the input encoding (default: auto-detect)
        \\  -label <name>     PEM label to select (default: first block)
        \\
    );
}

pub fn parseArgs(args: []const []const u8) common.Error!Options {
    var opts = Options{};
    var cur = common.ArgCursor{ .args = args };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-in")) {
            opts.in_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-inform")) {
            opts.inform = try common.Form.parse(try cur.value());
        } else if (std.mem.eql(u8, a, "-label")) {
            opts.label = try cur.value();
        } else {
            return error.Usage;
        }
    }
    return opts;
}

fn tagName(tag: u8) []const u8 {
    return switch (tag) {
        0x01 => "BOOLEAN",
        0x02 => "INTEGER",
        0x03 => "BIT STRING",
        0x04 => "OCTET STRING",
        0x05 => "NULL",
        0x06 => "OBJECT",
        0x0c => "UTF8STRING",
        0x13 => "PRINTABLESTRING",
        0x16 => "IA5STRING",
        0x17 => "UTCTIME",
        0x18 => "GENERALIZEDTIME",
        0x30 => "SEQUENCE",
        0x31 => "SET",
        else => if (tag & 0xc0 == 0x80) "cont" else "prim",
    };
}

/// Recursive dump of one DER scope. Depth is bounded by DerReader's own
/// MaxDepth via `child()` — hostile nesting fails typed, not by stack abuse.
pub fn dump(reader: *x509.DerReader, base_offset: usize, depth: usize, out: *Writer) !void {
    while (reader.hasRemaining()) {
        const at = base_offset + reader.offset;
        const tlv = try reader.readTlv();
        try out.print("{d:>6}: d={d} hl={d} l={d:>5} ", .{ at, depth, tlv.header_len, tlv.value.len });
        var pad: usize = 0;
        while (pad < depth) : (pad += 1) try out.writeAll("  ");

        const constructed = tlv.tag & 0x20 != 0;
        if (tlv.tag & 0xc0 == 0x80) {
            try out.print("[{d}]", .{tlv.tag & 0x1f});
        } else {
            try out.writeAll(tagName(tlv.tag));
        }

        if (constructed) {
            try out.writeByte('\n');
            var inner = try reader.child(tlv);
            try dump(&inner, at + tlv.header_len, depth + 1, out);
        } else {
            try out.writeAll("  ");
            if (tlv.tag == x509.Tag.oid) {
                try common.writeOidDotted(out, tlv.value);
            } else {
                try writePreview(out, tlv.value);
            }
            try out.writeByte('\n');
        }
    }
}

/// First bytes of a primitive value: printable text as-is, otherwise hex,
/// truncated with an ellipsis — output is bounded regardless of input size.
fn writePreview(out: *Writer, value: []const u8) !void {
    const limit = 24;
    const shown = value[0..@min(value.len, limit)];
    var printable = shown.len > 0;
    for (shown) |b| {
        if (b < 0x20 or b >= 0x7f) {
            printable = false;
            break;
        }
    }
    if (printable) {
        try out.print(":{s}", .{shown});
    } else {
        try out.writeAll(":");
        try common.writeHex(out, shown);
    }
    if (value.len > limit) try out.writeAll("...");
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    const text = try common.readInput(gpa, io, opts.in_path);
    defer gpa.free(text);

    const der = blk: {
        if (opts.label) |label| break :blk try common.loadDer(gpa, text, label, opts.inform);
        // No label: take the first PEM block whatever its label, else raw DER.
        const looks_pem = std.mem.indexOf(u8, text, "-----BEGIN ") != null;
        const use_pem = switch (opts.inform) {
            .pem => true,
            .der => false,
            .auto => looks_pem,
        };
        if (use_pem) {
            const buf = try gpa.alloc(u8, text.len);
            errdefer gpa.free(buf);
            const first = try orochi.proto.pem.decodeFirst(text, buf);
            const owned = try gpa.dupe(u8, first.der);
            gpa.free(buf);
            break :blk owned;
        }
        break :blk try gpa.dupe(u8, text);
    };
    defer gpa.free(der);

    var reader = x509.DerReader.init(der);
    try dump(&reader, 0, 0, out);
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

test "armorcli asn1parse dumps a nested structure with offsets and OIDs" {
    // SEQUENCE { INTEGER 42, SEQUENCE { OID 1.3.101.112 }, UTF8STRING "hi" }
    const der = [_]u8{
        0x30, 0x0e,
        0x02, 0x01,
        0x2a, 0x30,
        0x05, 0x06,
        0x03, 0x2b,
        0x65, 0x70,
        0x0c, 0x02,
        'h',  'i',
    };
    var aw = Writer.Allocating.init(testing.allocator);
    defer aw.deinit();
    var reader = x509.DerReader.init(&der);
    try dump(&reader, 0, 0, &aw.writer);
    const got = aw.written();

    try testing.expect(std.mem.indexOf(u8, got, "SEQUENCE") != null);
    // 0x2a is printable ('*'), so the preview shows the character form.
    try testing.expect(std.mem.indexOf(u8, got, "INTEGER  :*") != null);
    try testing.expect(std.mem.indexOf(u8, got, "1.3.101.112") != null);
    try testing.expect(std.mem.indexOf(u8, got, ":hi") != null);
    try testing.expect(std.mem.startsWith(u8, got, "     0: d=0"));
}

test "armorcli asn1parse fails closed on malformed DER" {
    var aw = Writer.Allocating.init(testing.allocator);
    defer aw.deinit();

    // Truncated length.
    const truncated = [_]u8{ 0x30, 0x10, 0x02 };
    var r1 = x509.DerReader.init(&truncated);
    try testing.expect(std.meta.isError(dump(&r1, 0, 0, &aw.writer)));

    // Indefinite length is not DER.
    const indefinite = [_]u8{ 0x30, 0x80, 0x00, 0x00 };
    var r2 = x509.DerReader.init(&indefinite);
    try testing.expectError(error.IndefiniteLength, dump(&r2, 0, 0, &aw.writer));

    // Hostile deep nesting hits the substrate depth cap, not the stack.
    var deep: [64]u8 = undefined;
    var i: usize = 0;
    while (i < 31) : (i += 1) {
        deep[i * 2] = 0x30;
        deep[i * 2 + 1] = @intCast(62 - i * 2);
    }
    deep[62] = 0x02;
    deep[63] = 0x00;
    var r3 = x509.DerReader.init(deep[0..64]);
    try testing.expectError(error.OverDepth, dump(&r3, 0, 0, &aw.writer));
}
