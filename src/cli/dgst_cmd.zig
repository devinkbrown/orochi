// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor dgst` — SHA-2 digests and HMAC over a file or stdin, backed by
//! src/crypto/hash.zig (`Sha256/384/512`, `Hmac`). The HMAC key is read from a
//! FILE (`-hmac-key <path>`), never from argv, so key bytes can't leak into
//! process listings or shell history; the key buffer is wiped after use.

const std = @import("std");
const orochi = @import("orochi");
const common = @import("common.zig");

const hash = orochi.crypto.hash;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

pub const Options = struct {
    alg: hash.Alg = .sha256,
    in_path: []const u8 = "-",
    hmac_key_path: ?[]const u8 = null,
};

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor dgst [-sha256|-sha384|-sha512] [-hmac-key <path>] [file]
        \\  -sha256/-sha384/-sha512   digest algorithm (default sha256)
        \\  -hmac-key <path>          compute HMAC with the key read from that
        \\                            file (never pass key material on argv);
        \\                            the file bytes are used VERBATIM, incl.
        \\                            any trailing newline
        \\  [file]                    input file; default/"-" reads stdin
        \\
    );
}

pub fn parseArgs(args: []const []const u8) common.Error!Options {
    var opts = Options{};
    var cur = common.ArgCursor{ .args = args };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-sha256")) {
            opts.alg = .sha256;
        } else if (std.mem.eql(u8, a, "-sha384")) {
            opts.alg = .sha384;
        } else if (std.mem.eql(u8, a, "-sha512")) {
            opts.alg = .sha512;
        } else if (std.mem.eql(u8, a, "-hmac-key")) {
            opts.hmac_key_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-hmac")) {
            // openssl puts the HMAC key on argv; we refuse — secrets never
            // ride the command line.
            return error.Usage;
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            return error.Usage;
        } else {
            opts.in_path = a;
        }
    }
    return opts;
}

/// Digest `data` (plain or HMAC) and print the openssl-style line. Pure so
/// tests pin it against published vectors.
pub fn digestLine(alg: hash.Alg, name: []const u8, data: []const u8, hmac_key: ?[]const u8, out: *Writer) !void {
    switch (alg) {
        inline .sha256, .sha384, .sha512 => |comptime_alg| {
            const label = switch (comptime_alg) {
                .sha256 => "SHA256",
                .sha384 => "SHA384",
                .sha512 => "SHA512",
            };
            if (hmac_key) |key| {
                const H = hash.Hmac(comptime_alg);
                const tag = H.create(key, data);
                try out.print("HMAC-{s}({s})= ", .{ label, name });
                try common.writeHex(out, &tag);
            } else {
                const H = hash.Hash(comptime_alg);
                const digest = H.hash(data);
                try out.print("{s}({s})= ", .{ label, name });
                try common.writeHex(out, &digest);
            }
            try out.writeByte('\n');
        },
    }
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    const data = try common.readInput(gpa, io, opts.in_path);
    defer gpa.free(data);

    var key: ?[]u8 = null;
    defer if (key) |k| {
        std.crypto.secureZero(u8, k);
        gpa.free(k);
    };
    if (opts.hmac_key_path) |path| {
        key = try common.readInput(gpa, io, path);
    }

    const display = if (std.mem.eql(u8, opts.in_path, "-")) "stdin" else opts.in_path;
    try digestLine(opts.alg, display, data, key, out);
}

// ===========================================================================
// Tests — independent published vectors (FIPS 180-2 / RFC 4231).
// ===========================================================================

const testing = std.testing;

test "armorcli dgst matches the FIPS 180-2 'abc' vectors" {
    var aw = Writer.Allocating.init(testing.allocator);
    defer aw.deinit();

    try digestLine(.sha256, "stdin", "abc", null, &aw.writer);
    try testing.expectEqualStrings(
        "SHA256(stdin)= ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n",
        aw.written(),
    );

    aw.clearRetainingCapacity();
    try digestLine(.sha512, "stdin", "abc", null, &aw.writer);
    try testing.expectEqualStrings(
        "SHA512(stdin)= ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" ++
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f\n",
        aw.written(),
    );
}

test "armorcli dgst HMAC matches RFC 4231 test case 2" {
    // Key "Jefe", data "what do ya want for nothing?".
    var aw = Writer.Allocating.init(testing.allocator);
    defer aw.deinit();
    try digestLine(.sha256, "f", "what do ya want for nothing?", "Jefe", &aw.writer);
    try testing.expectEqualStrings(
        "HMAC-SHA256(f)= 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843\n",
        aw.written(),
    );
}

test "armorcli dgst refuses -hmac (key on argv)" {
    try testing.expectError(error.Usage, parseArgs(&.{ "-hmac", "sekrit" }));
    const opts = try parseArgs(&.{ "-sha384", "-hmac-key", "key.bin", "input.txt" });
    try testing.expectEqual(hash.Alg.sha384, opts.alg);
    try testing.expectEqualStrings("key.bin", opts.hmac_key_path.?);
    try testing.expectEqualStrings("input.txt", opts.in_path);
}
