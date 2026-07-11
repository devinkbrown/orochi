// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `yoroi rand` — cryptographically-random bytes from the substrate DRBG
//! (src/crypto/random.zig `Drbg`, OS-entropy seeded ChaCha20). Output raw
//! (openssl default), `-hex`, or `-base64`.

const std = @import("std");
const orochi = @import("orochi");
const common = @import("common.zig");

const random = orochi.crypto.random;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

/// Refuse absurd requests before allocating (same posture as input caps).
pub const max_bytes: usize = 1 << 24; // 16 MiB

pub const Encoding = enum { raw, hex, base64 };

pub const Options = struct {
    count: usize = 0,
    encoding: Encoding = .raw,
    out_path: ?[]const u8 = null,
};

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: yoroi rand [-hex|-base64] [-out <path>] <num>
        \\  <num>        number of random bytes to emit (1..16MiB)
        \\  -hex         lowercase hex output
        \\  -base64      standard base64 output
        \\  -out <path>  write there instead of stdout
        \\
    );
}

pub fn parseArgs(args: []const []const u8) common.Error!Options {
    var opts = Options{};
    var have_count = false;
    var cur = common.ArgCursor{ .args = args };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-hex")) {
            opts.encoding = .hex;
        } else if (std.mem.eql(u8, a, "-base64")) {
            opts.encoding = .base64;
        } else if (std.mem.eql(u8, a, "-out")) {
            opts.out_path = try cur.value();
        } else {
            opts.count = std.fmt.parseInt(usize, a, 10) catch return error.Usage;
            have_count = true;
        }
    }
    if (!have_count or opts.count == 0 or opts.count > max_bytes) return error.Usage;
    return opts;
}

/// Fill + encode into `out`. Extracted so tests can drive it directly.
pub fn emit(gpa: Allocator, count: usize, encoding: Encoding, out: *Writer) !void {
    const buf = try gpa.alloc(u8, count);
    defer gpa.free(buf);

    var drbg = try random.Drbg.init();
    defer drbg.deinit();
    try drbg.fillPublic(buf);

    switch (encoding) {
        .raw => try out.writeAll(buf),
        .hex => {
            try common.writeHex(out, buf);
            try out.writeByte('\n');
        },
        .base64 => {
            const enc = std.base64.standard.Encoder;
            const b64 = try gpa.alloc(u8, enc.calcSize(buf.len));
            defer gpa.free(b64);
            try out.writeAll(enc.encode(b64, buf));
            try out.writeByte('\n');
        },
    }
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    if (opts.out_path) |path| {
        var body = Writer.Allocating.init(gpa);
        defer body.deinit();
        try emit(gpa, opts.count, opts.encoding, &body.writer);
        try common.writePublicFile(io, std.Io.Dir.cwd(), path, body.written());
    } else {
        try emit(gpa, opts.count, opts.encoding, out);
    }
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

test "yoroicli rand emits the requested length in each encoding" {
    const gpa = testing.allocator;
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();

    try emit(gpa, 32, .raw, &aw.writer);
    try testing.expectEqual(@as(usize, 32), aw.written().len);

    aw.clearRetainingCapacity();
    try emit(gpa, 32, .hex, &aw.writer);
    try testing.expectEqual(@as(usize, 65), aw.written().len); // 64 hex + newline
    for (aw.written()[0..64]) |c| try testing.expect(std.ascii.isHex(c));

    aw.clearRetainingCapacity();
    try emit(gpa, 30, .base64, &aw.writer);
    try testing.expectEqual(@as(usize, 41), aw.written().len); // ceil(30/3)*4 + newline
}

test "yoroicli rand two draws differ (DRBG is live, not a constant)" {
    const gpa = testing.allocator;
    var a = Writer.Allocating.init(gpa);
    defer a.deinit();
    var b = Writer.Allocating.init(gpa);
    defer b.deinit();
    try emit(gpa, 32, .raw, &a.writer);
    try emit(gpa, 32, .raw, &b.writer);
    try testing.expect(!std.mem.eql(u8, a.written(), b.written()));
}

test "yoroicli rand arg validation" {
    try testing.expectError(error.Usage, parseArgs(&.{}));
    try testing.expectError(error.Usage, parseArgs(&.{"0"}));
    try testing.expectError(error.Usage, parseArgs(&.{"abc"}));
    try testing.expectError(error.Usage, parseArgs(&.{"999999999999"}));
    const opts = try parseArgs(&.{ "-hex", "16" });
    try testing.expectEqual(@as(usize, 16), opts.count);
    try testing.expectEqual(Encoding.hex, opts.encoding);
}
