// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-client TLS resume snapshot — the wire format carried across a Helix
//! UPGRADE so an ESTABLISHED TLS connection keeps decrypting/encrypting on the
//! successor (the socket fd survives execve; this carries the crypto state that
//! pairs with it).
//!
//! One snapshot is sealed into a `.tls_session` capsule per carried TLS client;
//! `fd` is the join key back to the matching `.clients` session snapshot. The
//! payload is the adapter-level `TlsConn.ResumeState` (engine + suite + traffic
//! secrets/keys + record sequence numbers + any buffered partial inbound
//! record), plus the connection's not-yet-flushed outbound wire bytes and the
//! mTLS client-cert fingerprint when one was bound.
//!
//! SECURITY: the encoded bytes contain live traffic secrets. They only ever
//! live inside the sealed memfd arena inherited by the successor process —
//! never on disk.
//!
//! Wire format (all integers little-endian):
//!   [i32 fd]
//!   [u8 engine]      1 = TLS 1.3, 2 = TLS 1.2
//!   [u16 suite]
//!   engine 1: [u8 slen][client_app_secret slen][server_app_secret slen]
//!   engine 2: [u8 klen][client key][u8 ivlen][client iv][server key][server iv]
//!   [u64 app_read_seq][u64 app_write_seq]
//!   [u32 len][pending_recv]   partial inbound TLS record buffered at export
//!   [u32 len][pending_out]    queued outbound wire bytes not yet flushed
//!   [u8 len][certfp]          lowercase-hex SHA-256 of the client leaf, or empty
const std = @import("std");

const tls_conn = @import("../tls_conn.zig");
const tls_server = @import("../../crypto/tls_server.zig");
const tls12_server = @import("../../crypto/tls12_server.zig");

pub const Error = error{ Truncated, TrailingBytes, InvalidFlags, BadCertfp, TooLong, BadEngine, BadLength, UnsupportedVersion };

const engine_tls13: u8 = 1;
const engine_tls12: u8 = 2;

/// Current `.tls_session` capsule schema version whose blob layout `encode`
/// writes. The blob carries no inline version — it rides the capsule header — so
/// this MIRRORS the descriptor in `capsule.zig`; bump both together. v2 makes the
/// trailing kTLS-offload flag bytes mandatory; v1 tolerates them being absent OR
/// present (see `decode`).
pub const schema_version: u16 = 2;

const Secret13 = @FieldType(tls_server.Server.ResumeState, "client_app_secret");
const Keys12 = @FieldType(tls12_server.Server.ResumeState, "keys");
const Key12 = @FieldType(@FieldType(Keys12, "client_write"), "key");
const Iv12 = @FieldType(@FieldType(Keys12, "client_write"), "iv");

/// A plain view of one carried TLS connection. Slices borrow the source
/// (encode input) or the decoded buffer (decode output).
pub const Snapshot = struct {
    /// The client's socket fd (inherited across execve) — joins this TLS state
    /// to its `.clients` session snapshot.
    fd: i32 = -1,
    /// The adapter-level resume state (engine, suite, secrets, seqs, pending
    /// inbound bytes).
    state: tls_conn.TlsConn.ResumeState,
    /// Outbound wire bytes (already TLS records) that were queued but not yet
    /// flushed by the predecessor; the successor re-queues them verbatim so the
    /// client's record sequence stays unbroken.
    pending_out: []const u8 = &.{},
    /// The bound mTLS client-cert fingerprint (lowercase hex), or empty.
    certfp: []const u8 = &.{},
    /// kTLS TX offload (roadmap 3.1): true when the predecessor had offloaded
    /// server→client encryption to the kernel. The kernel TX state rides the
    /// inherited fd across execve, so the successor re-attaches nothing — it just
    /// resumes sending plaintext (RX + the engine's carried secrets/seqs stay
    /// userspace exactly as for a non-offloaded conn).
    tx_offloaded: bool = false,
    /// kTLS RX offload: true when the predecessor had offloaded client→server
    /// decryption. Same path-A carry: the kernel RX state survives execve on the
    /// inherited fd, so the successor re-attaches nothing and just resumes reading
    /// plaintext from `recv()` (routing it past the userspace TLS engine).
    rx_offloaded: bool = false,
};

/// Encode `snap` into a freshly-allocated buffer the caller owns. The result
/// contains key material — wipe or seal it promptly.
pub fn encode(allocator: std.mem.Allocator, snap: Snapshot) (Error || std.mem.Allocator.Error)![]u8 {
    if (snap.pending_out.len > std.math.maxInt(u32)) return error.TooLong;
    if (snap.state.pending_recv.len > std.math.maxInt(u32)) return error.TooLong;
    if (snap.certfp.len > std.math.maxInt(u8)) return error.TooLong;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendInt(&out, allocator, i32, snap.fd);
    switch (snap.state.engine) {
        .tls13 => |s| {
            try out.append(allocator, engine_tls13);
            try appendInt(&out, allocator, u16, s.suite);
            try out.append(allocator, @intCast(s.client_app_secret.len));
            try out.appendSlice(allocator, &s.client_app_secret);
            try out.appendSlice(allocator, &s.server_app_secret);
            try appendInt(&out, allocator, u64, s.app_read_seq);
            try appendInt(&out, allocator, u64, s.app_write_seq);
        },
        .tls12 => |s| {
            try out.append(allocator, engine_tls12);
            try appendInt(&out, allocator, u16, s.suite);
            try out.append(allocator, @intCast(s.keys.client_write.key.len));
            try out.appendSlice(allocator, &s.keys.client_write.key);
            try out.append(allocator, @intCast(s.keys.client_write.iv.len));
            try out.appendSlice(allocator, &s.keys.client_write.iv);
            try out.appendSlice(allocator, &s.keys.server_write.key);
            try out.appendSlice(allocator, &s.keys.server_write.iv);
            try appendInt(&out, allocator, u64, s.app_read_seq);
            try appendInt(&out, allocator, u64, s.app_write_seq);
        },
    }
    try appendInt(&out, allocator, u32, @intCast(snap.state.pending_recv.len));
    try out.appendSlice(allocator, snap.state.pending_recv);
    try appendInt(&out, allocator, u32, @intCast(snap.pending_out.len));
    try out.appendSlice(allocator, snap.pending_out);
    try out.append(allocator, @intCast(snap.certfp.len));
    try out.appendSlice(allocator, snap.certfp);
    // kTLS offload flags (trailing, so an older decoder tolerantly ignores them).
    try out.append(allocator, @intFromBool(snap.tx_offloaded));
    try out.append(allocator, @intFromBool(snap.rx_offloaded));
    return out.toOwnedSlice(allocator);
}

/// Decode a snapshot sealed at capsule `version` (the `.tls_session` capsule
/// header version). Byte-slice fields borrow `bytes`.
///
/// v1 is the value stamped by BOTH a genuine pre-kTLS predecessor (the blob ends
/// at the certfp, with no flag bytes) AND the flag-widened-but-not-yet-version-
/// bumped predecessor (two trailing kTLS-offload flag bytes) — the encoder gained
/// the flags before this version was bumped, so a v1 blob may or may not carry
/// them. The v1 arm therefore tolerates the flags being absent OR present (a
/// present flag must still be canonical). v2 makes both flags mandatory, ending
/// the length ambiguity for every future layout change. Every supported version
/// stays otherwise strict: canonical certfp and exact EOF are required. Any
/// version outside 1..2 is rejected fail-closed.
pub fn decode(bytes: []const u8, version: u16) Error!Snapshot {
    return decodeInternal(bytes, version);
}

/// Decode exactly the current schema (`schema_version`) emitted by `encode`:
/// both kTLS flag bytes mandatory, trailing bytes rejected, and a present
/// certificate fingerprint must be canonical lowercase SHA-256 hex.
pub fn decodeCurrent(bytes: []const u8) Error!Snapshot {
    return decodeInternal(bytes, schema_version);
}

fn decodeInternal(bytes: []const u8, version: u16) Error!Snapshot {
    var r = Reader{ .buf = bytes };
    const fd = try r.int(i32);
    const engine = try r.byte();
    const suite = try r.int(u16);
    var state: tls_conn.TlsConn.ResumeState = switch (engine) {
        engine_tls13 => blk: {
            const slen = try r.byte();
            if (slen != @as(usize, @sizeOf(Secret13))) return error.BadLength;
            var s = tls_server.Server.ResumeState{
                .suite = suite,
                .client_app_secret = undefined,
                .server_app_secret = undefined,
                .app_read_seq = 0,
                .app_write_seq = 0,
            };
            @memcpy(&s.client_app_secret, try r.take(s.client_app_secret.len));
            @memcpy(&s.server_app_secret, try r.take(s.server_app_secret.len));
            s.app_read_seq = try r.int(u64);
            s.app_write_seq = try r.int(u64);
            break :blk .{ .engine = .{ .tls13 = s } };
        },
        engine_tls12 => blk: {
            const klen = try r.byte();
            if (klen != @as(usize, @sizeOf(Key12))) return error.BadLength;
            var s = tls12_server.Server.ResumeState{
                .suite = suite,
                .keys = .{},
                .app_read_seq = 0,
                .app_write_seq = 0,
            };
            @memcpy(&s.keys.client_write.key, try r.take(s.keys.client_write.key.len));
            const ivlen = try r.byte();
            if (ivlen != @as(usize, @sizeOf(Iv12))) return error.BadLength;
            @memcpy(&s.keys.client_write.iv, try r.take(s.keys.client_write.iv.len));
            @memcpy(&s.keys.server_write.key, try r.take(s.keys.server_write.key.len));
            @memcpy(&s.keys.server_write.iv, try r.take(s.keys.server_write.iv.len));
            s.app_read_seq = try r.int(u64);
            s.app_write_seq = try r.int(u64);
            break :blk .{ .engine = .{ .tls12 = s } };
        },
        else => return error.BadEngine,
    };
    state.pending_recv = try r.take(try r.int(u32));
    const pending_out = try r.take(try r.int(u32));
    const certfp = try r.take(try r.byte());
    var tx_offloaded = false;
    var rx_offloaded = false;
    switch (version) {
        1 => {
            // Legacy v1: the two kTLS flag bytes are absent (genuine pre-kTLS) OR
            // present (a flag-widened predecessor that never bumped the version).
            // Tolerate both; a present flag must still be a canonical boolean.
            if (r.pos < r.buf.len) {
                const tx = try r.byte();
                if (tx > 1) return error.InvalidFlags;
                tx_offloaded = tx == 1;
            }
            if (r.pos < r.buf.len) {
                const rx = try r.byte();
                if (rx > 1) return error.InvalidFlags;
                rx_offloaded = rx == 1;
            }
        },
        schema_version => {
            const tx = try r.byte();
            const rx = try r.byte();
            if (tx > 1 or rx > 1) return error.InvalidFlags;
            tx_offloaded = tx == 1;
            rx_offloaded = rx == 1;
        },
        // MAINTENANCE TRAP — a future schema bump that keeps `min_supported = 1`
        // in the capsule descriptor MUST add an explicit arm for EVERY still-
        // accepted version, or that version's TLS sidecars silently drop across
        // the upgrade (the exact field-shift/netsplit class this switch prevents).
        else => return error.UnsupportedVersion,
    }
    if (r.pos != r.buf.len) return error.TrailingBytes;
    if (certfp.len != 0) {
        if (certfp.len != 64) return error.BadCertfp;
        for (certfp) |byte| {
            if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f')))
                return error.BadCertfp;
        }
    }
    return .{ .fd = fd, .state = state, .pending_out = pending_out, .certfp = certfp, .tx_offloaded = tx_offloaded, .rx_offloaded = rx_offloaded };
}

fn appendInt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) std.mem.Allocator.Error!void {
    var le: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &le, value, .little);
    try out.appendSlice(allocator, &le);
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn byte(self: *Reader) Error!u8 {
        if (self.pos + 1 > self.buf.len) return error.Truncated;
        defer self.pos += 1;
        return self.buf[self.pos];
    }
    fn int(self: *Reader, comptime T: type) Error!T {
        if (self.pos + @sizeOf(T) > self.buf.len) return error.Truncated;
        defer self.pos += @sizeOf(T);
        return std.mem.readInt(T, self.buf[self.pos..][0..@sizeOf(T)], .little);
    }
    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.buf.len) return error.Truncated;
        defer self.pos += n;
        return self.buf[self.pos .. self.pos + n];
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "tls13 snapshot round-trips fd, suite, secrets, seqs, pending + certfp" {
    const allocator = testing.allocator;
    var s13 = tls_server.Server.ResumeState{
        .suite = 0x1301,
        .client_app_secret = undefined,
        .server_app_secret = undefined,
        .app_read_seq = 7,
        .app_write_seq = 9,
    };
    for (&s13.client_app_secret, 0..) |*b, i| b.* = @truncate(i);
    for (&s13.server_app_secret, 0..) |*b, i| b.* = @truncate(0x80 + i);

    const bytes = try encode(allocator, .{
        .fd = 42,
        .state = .{ .engine = .{ .tls13 = s13 }, .pending_recv = "\x17\x03\x03" },
        .pending_out = "queued-record",
        .certfp = &repeatBytes("ab", 32),
        .tx_offloaded = true,
        .rx_offloaded = true,
    });
    defer allocator.free(bytes);

    const got = try decode(bytes, schema_version);
    try testing.expectEqual(@as(i32, 42), got.fd);
    const g13 = got.state.engine.tls13;
    try testing.expectEqual(@as(u16, 0x1301), g13.suite);
    try testing.expectEqualSlices(u8, &s13.client_app_secret, &g13.client_app_secret);
    try testing.expectEqualSlices(u8, &s13.server_app_secret, &g13.server_app_secret);
    try testing.expectEqual(@as(u64, 7), g13.app_read_seq);
    try testing.expectEqual(@as(u64, 9), g13.app_write_seq);
    try testing.expectEqualStrings("\x17\x03\x03", got.state.pending_recv);
    try testing.expectEqualStrings("queued-record", got.pending_out);
    try testing.expectEqualStrings(&repeatBytes("ab", 32), got.certfp);
    try testing.expect(got.tx_offloaded);
    try testing.expect(got.rx_offloaded);

    // Cross-version (a): a genuine pre-kTLS v1 blob ends at the certfp with NO
    // flag bytes; the v1 arm decodes it as not-offloaded rather than erroring.
    const v1_no_flags = try decode(bytes[0 .. bytes.len - 2], 1);
    try testing.expect(!v1_no_flags.tx_offloaded);
    try testing.expect(!v1_no_flags.rx_offloaded);

    // Cross-version (b) — the netsplit guard: the CURRENTLY-DEPLOYED predecessor
    // seals the flag-BEARING layout while still stamping v1. Decoding that exact
    // blob as v1 must read the flags (not reject them as trailing bytes), so the
    // next USR2 into a v2 binary adopts the link instead of dropping it.
    const v1_with_flags = try decode(bytes, 1);
    try testing.expect(v1_with_flags.tx_offloaded);
    try testing.expect(v1_with_flags.rx_offloaded);
    try testing.expectEqual(@as(i32, 42), v1_with_flags.fd);
    try testing.expectEqualStrings(&repeatBytes("ab", 32), v1_with_flags.certfp);
}

test "tls12 snapshot round-trips key material and seqs" {
    const allocator = testing.allocator;
    var s12 = tls12_server.Server.ResumeState{
        .suite = 0xc02b,
        .keys = .{},
        .app_read_seq = 3,
        .app_write_seq = 4,
    };
    for (&s12.keys.client_write.key, 0..) |*b, i| b.* = @truncate(i + 1);
    for (&s12.keys.client_write.iv, 0..) |*b, i| b.* = @truncate(i + 2);
    for (&s12.keys.server_write.key, 0..) |*b, i| b.* = @truncate(i + 3);
    for (&s12.keys.server_write.iv, 0..) |*b, i| b.* = @truncate(i + 4);

    const bytes = try encode(allocator, .{
        .fd = 7,
        .state = .{ .engine = .{ .tls12 = s12 } },
    });
    defer allocator.free(bytes);

    const got = try decode(bytes, schema_version);
    try testing.expectEqual(@as(i32, 7), got.fd);
    const g12 = got.state.engine.tls12;
    try testing.expectEqual(@as(u16, 0xc02b), g12.suite);
    try testing.expectEqualSlices(u8, &s12.keys.client_write.key, &g12.keys.client_write.key);
    try testing.expectEqualSlices(u8, &s12.keys.client_write.iv, &g12.keys.client_write.iv);
    try testing.expectEqualSlices(u8, &s12.keys.server_write.key, &g12.keys.server_write.key);
    try testing.expectEqualSlices(u8, &s12.keys.server_write.iv, &g12.keys.server_write.iv);
    try testing.expectEqual(@as(u64, 3), g12.app_read_seq);
    try testing.expectEqual(@as(u64, 4), g12.app_write_seq);
    try testing.expectEqual(@as(usize, 0), got.pending_out.len);
    try testing.expectEqual(@as(usize, 0), got.certfp.len);
}

test "decode rejects truncation, unknown engines, and unknown versions" {
    const allocator = testing.allocator;
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 0, 0 }, schema_version));
    // fd(4) + engine byte 9 = unknown.
    try testing.expectError(error.BadEngine, decode(&[_]u8{ 1, 0, 0, 0, 9, 0x01, 0x13 }, schema_version));
    // A full, valid v2 blob decoded under a too-new (or zero) version reaches the
    // version switch and is rejected fail-closed — a layout this binary cannot
    // parse.
    const s13 = tls_server.Server.ResumeState{
        .suite = 0x1301,
        .client_app_secret = @splat(1),
        .server_app_secret = @splat(2),
        .app_read_seq = 0,
        .app_write_seq = 0,
    };
    const bytes = try encode(allocator, .{ .fd = 5, .state = .{ .engine = .{ .tls13 = s13 } } });
    defer allocator.free(bytes);
    try testing.expectError(error.UnsupportedVersion, decode(bytes, schema_version + 1));
    try testing.expectError(error.UnsupportedVersion, decode(bytes, 0));
}

test "current decode requires canonical flags fingerprint and exact EOF" {
    const allocator = testing.allocator;
    const s13 = tls_server.Server.ResumeState{
        .suite = 0x1301,
        .client_app_secret = @splat(1),
        .server_app_secret = @splat(2),
        .app_read_seq = 1,
        .app_write_seq = 2,
    };
    const bytes = try encode(allocator, .{
        .fd = 17,
        .state = .{ .engine = .{ .tls13 = s13 } },
        .certfp = &repeatBytes("ab", 32),
    });
    defer allocator.free(bytes);
    _ = try decodeCurrent(bytes);
    try testing.expectError(error.Truncated, decodeCurrent(bytes[0 .. bytes.len - 1]));

    const trailing = try allocator.alloc(u8, bytes.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try testing.expectError(error.TrailingBytes, decodeCurrent(trailing));

    const bad_flag = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_flag);
    bad_flag[bad_flag.len - 1] = 2;
    try testing.expectError(error.InvalidFlags, decodeCurrent(bad_flag));

    const bad_certfp = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_certfp);
    bad_certfp[bad_certfp.len - 2 - 64] = 'A';
    try testing.expectError(error.BadCertfp, decodeCurrent(bad_certfp));
}

fn repeatBytes(comptime s: []const u8, comptime n: usize) [s.len * n]u8 {
    var b: [s.len * n]u8 = undefined;
    for (0..n) |i| @memcpy(b[i * s.len ..][0..s.len], s);
    return b;
}
