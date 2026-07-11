// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Not-yet-implemented `yoroi` verbs, declared so the framework stays
//! extensible and users get a deterministic exit (3) instead of a confusing
//! "unknown command". Each names the substrate piece a future wiring would
//! sit on:
//!   * s_client / s_server — crypto/tls_client.zig + tls_server.zig exist and
//!     are fully tested, but a live socket loop belongs to the daemon reactor;
//!     wiring a standalone one is deliberate follow-up work.
//!   * ocsp — crypto/ocsp.zig parses/verifies responses; the HTTP fetch loop
//!     is daemon-side (ocsp_staple.zig).
//!   * crl — crypto/crl.zig is a parser not yet wired to any live path
//!     (docs/dev/tls-roadmap.md Phase 4 wire-or-cut).
//!   * enc — the substrate exposes AEADs only (aead.zig); there is no
//!     openssl-enc-compatible KDF/format, and inventing one is out of scope.

const std = @import("std");
const common = @import("common.zig");

const Writer = common.Writer;

pub const stubs = [_][]const u8{ "s_client", "s_server", "enc", "ocsp", "crl" };

pub fn isStub(cmd: []const u8) bool {
    for (stubs) |s| {
        if (std.mem.eql(u8, cmd, s)) return true;
    }
    return false;
}

pub fn run(cmd: []const u8, out: *Writer) !void {
    try out.print("yoroi {s}: not yet implemented\n", .{cmd});
    if (std.mem.eql(u8, cmd, "ocsp")) {
        try out.writeAll("  (the substrate parses/verifies OCSP responses; the fetch flow is daemon-side)\n");
    } else if (std.mem.eql(u8, cmd, "crl")) {
        try out.writeAll("  (crypto/crl.zig is a parser awaiting the roadmap Phase 4 wire-or-cut)\n");
    } else if (std.mem.eql(u8, cmd, "enc")) {
        try out.writeAll("  (no openssl-enc-compatible format in the substrate; AEAD-only by design)\n");
    } else {
        try out.writeAll("  (Yoroi TLS client/server exist; a standalone socket loop is follow-up work)\n");
    }
    return error.NotImplemented;
}

const testing = std.testing;

test "yoroicli stubs answer deterministically" {
    try testing.expect(isStub("s_client"));
    try testing.expect(!isStub("x509"));

    var aw = Writer.Allocating.init(testing.allocator);
    defer aw.deinit();
    try testing.expectError(error.NotImplemented, run("crl", &aw.writer));
    try testing.expect(std.mem.indexOf(u8, aw.written(), "not yet implemented") != null);
}
