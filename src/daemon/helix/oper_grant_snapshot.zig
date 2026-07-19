// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Server-wide cross-mesh oper-grant registry carried across a Helix UPGRADE.
//!
//! The daemon's `oper_grants` registry (`proto/oper_cred_share.Registry`) is the
//! CONVERGED record of every verified cross-mesh operator grant — including
//! zero-privilege revocation tombstones and their incarnation replay guard. It
//! is process state: a successor that re-execs with an empty registry forgets
//! which accounts already confer the derived `*` (+Y) prefix, so the peer's
//! post-RESYNC grant re-mint looks like a FALSE oper transition
//! (`had_oper_override=false -> true` in `applyMeshGrant`) and re-broadcasts
//! `MODE #chan +Y <nick>` to every shared channel on every upgrade. Losing the
//! tombstones additionally reopens an incarnation-replay window where a stale
//! pre-revocation grant frame could resurrect revoked authority.
//!
//! This fixed-cap, magic-discriminated checkpoint rides the shared
//! `.mesh_checkpoint` capsule family (header `min_supported = 2`, like the
//! other exact server-wide state pieces). The successor primes its registry
//! from it at the adoption commit edge — BEFORE the io loop can process any
//! peer re-mint — so the re-learn dedups (`had_oper_override=true`, no
//! announce). An arena sealed by a pre-checkpoint predecessor simply lacks the
//! piece and adopts with an empty registry: exactly the pre-fix behavior,
//! mirroring how a pre-v4 `.s2s_link` capsule adopts with an empty roster.
//!
//! Wire format (all integers little-endian):
//!   [magic "OGNT"][u8 version=1]
//!   [u64 mint_incarnation]        the minting node's strictly-increasing
//!                                 grant-incarnation counter high-water mark
//!   [u32 count]                   number of grant records (<= max_grants)
//!   count records:
//!     [u8 alen][account][u64 privilege_bits][u8 clen][class][u8 tlen][title]
//!     [u8 ilen][issuer_node][u64 incarnation][u64 issued_ms][u64 expiry_ms]
//!
//! Short, wrong-magic, unsupported-version, over-count, empty-account,
//! born-expired, duplicate-account, count-mismatched, and trailing payloads all
//! fail closed rather than partially restoring grant authority.

const std = @import("std");

const oper_cred_share = @import("../../proto/oper_cred_share.zig");

pub const Error = error{
    Truncated,
    BadMagic,
    UnsupportedVersion,
    TrailingBytes,
    TooManyGrants,
    InvalidGrant,
};

pub const magic = [_]u8{ 'O', 'G', 'N', 'T' };
pub const version: u8 = 1;

/// Upper bound on carried records: the live registry's own capacity. A
/// predecessor can never hold more, so a larger count is malformed by
/// construction and rejected before any allocation-free walk begins.
pub const max_grants: u32 = oper_cred_share.default_capacity;

const header_len: usize = magic.len + 1 + @sizeOf(u64) + @sizeOf(u32);

/// True when `bytes` carries this checkpoint's discriminator (the shared
/// `.mesh_checkpoint` family is magic-discriminated).
pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

/// A fully-validated checkpoint view. `records` borrows the input buffer;
/// construction (via `decodeCurrent`) has already walked every record
/// fail-closed, so `iterator` is infallible on a held Snapshot.
pub const Snapshot = struct {
    mint_incarnation: u64,
    count: u32,
    records: []const u8,

    pub fn iterator(self: *const Snapshot) Iterator {
        return .{ .r = .{ .buf = self.records }, .remaining = self.count };
    }
};

/// Walk a VALIDATED record region. `next` returns null after `remaining`
/// records. The defensive bound checks inside can only trip on bytes that
/// never went through `decodeCurrent`; they stop the walk (fail closed) rather
/// than read out of bounds.
pub const Iterator = struct {
    r: Reader,
    remaining: u32,

    pub fn next(self: *Iterator) ?oper_cred_share.GrantFields {
        if (self.remaining == 0) return null;
        self.remaining -= 1;
        const account = self.r.shortSlice() orelse return null;
        const privilege_bits = self.r.int(u64) orelse return null;
        const class = self.r.shortSlice() orelse return null;
        const title = self.r.shortSlice() orelse return null;
        const issuer_node = self.r.shortSlice() orelse return null;
        const incarnation = self.r.int(u64) orelse return null;
        const issued_ms = self.r.int(u64) orelse return null;
        const expiry_ms = self.r.int(u64) orelse return null;
        return .{
            .account = account,
            .privilege_bits = privilege_bits,
            .class = class,
            .title = title,
            .issuer_node = issuer_node,
            .incarnation = incarnation,
            .issued_ms = issued_ms,
            .expiry_ms = expiry_ms,
        };
    }
};

/// Encode the registry's grants live at `now_ms` (expired slots are dead — a
/// lookup already returns null for them — so sealing skips them, exactly what
/// `prune` would leave) plus the node's grant-mint incarnation high-water mark.
/// The caller owns the returned buffer. Registry fields are bounded at
/// `oper_cred_share.max_field_len` (255) by construction, so the u8 length
/// prefixes always fit.
pub fn encodeFromRegistry(
    allocator: std.mem.Allocator,
    reg: *const oper_cred_share.Registry,
    now_ms: u64,
    mint_incarnation: u64,
) (Error || std.mem.Allocator.Error)![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, &magic);
    try out.append(allocator, version);
    try appendInt(&out, allocator, u64, mint_incarnation);
    const count_off = out.items.len;
    try appendInt(&out, allocator, u32, 0); // patched below

    var count: u32 = 0;
    var it = reg.liveIterator(now_ms);
    while (it.next()) |g| {
        if (count == max_grants) return error.TooManyGrants;
        if (g.account.len == 0 or g.issued_ms > g.expiry_ms) return error.InvalidGrant;
        try appendShortSlice(&out, allocator, g.account);
        try appendInt(&out, allocator, u64, g.privilege_bits);
        try appendShortSlice(&out, allocator, g.class);
        try appendShortSlice(&out, allocator, g.title);
        try appendShortSlice(&out, allocator, g.issuer_node);
        try appendInt(&out, allocator, u64, g.incarnation);
        try appendInt(&out, allocator, u64, g.issued_ms);
        try appendInt(&out, allocator, u64, g.expiry_ms);
        count += 1;
    }
    std.mem.writeInt(u32, out.items[count_off..][0..4], count, .little);

    // Never SEAL an image the successor would refuse: the same walk decode runs.
    _ = try decodeCurrent(out.items);
    return out.toOwnedSlice(allocator);
}

/// Decode + validate the complete checkpoint fail-closed: exact count, every
/// record well-formed (non-empty account, `issued_ms <= expiry_ms`, no
/// duplicate account — the registry merges by account, so a duplicate is an
/// ambiguous image, not a mergeable one), and no trailing bytes.
pub fn decodeCurrent(bytes: []const u8) Error!Snapshot {
    if (bytes.len < magic.len + 1) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    if (bytes[magic.len] != version) return error.UnsupportedVersion;
    if (bytes.len < header_len) return error.Truncated;

    const mint_incarnation = std.mem.readInt(u64, bytes[magic.len + 1 ..][0..8], .little);
    const count = std.mem.readInt(u32, bytes[header_len - 4 ..][0..4], .little);
    if (count > max_grants) return error.TooManyGrants;

    const records = bytes[header_len..];
    var r = Reader{ .buf = records };
    var starts: [max_grants]usize = undefined;
    var lens: [max_grants]u8 = undefined;
    var seen: u32 = 0;
    while (seen < count) : (seen += 1) {
        const account_start = r.pos + 1;
        const account = r.shortSlice() orelse return error.Truncated;
        if (account.len == 0) return error.InvalidGrant;
        _ = r.int(u64) orelse return error.Truncated; // privilege_bits
        _ = r.shortSlice() orelse return error.Truncated; // class
        _ = r.shortSlice() orelse return error.Truncated; // title
        _ = r.shortSlice() orelse return error.Truncated; // issuer_node
        _ = r.int(u64) orelse return error.Truncated; // incarnation
        const issued_ms = r.int(u64) orelse return error.Truncated;
        const expiry_ms = r.int(u64) orelse return error.Truncated;
        if (issued_ms > expiry_ms) return error.InvalidGrant;
        // Reject a duplicate account (case-insensitive, matching the registry's
        // own findIndex) — an ambiguous image must not half-merge.
        for (starts[0..seen], lens[0..seen]) |prior_start, prior_len| {
            if (std.ascii.eqlIgnoreCase(records[prior_start..][0..prior_len], account))
                return error.InvalidGrant;
        }
        starts[seen] = account_start;
        lens[seen] = @intCast(account.len);
    }
    if (r.pos != records.len) return error.TrailingBytes;

    return .{ .mint_incarnation = mint_incarnation, .count = count, .records = records };
}

/// Relational-validation entry point (`handoff_relations.validateCurrent`).
pub fn validateCheckpoint(bytes: []const u8) Error!void {
    _ = try decodeCurrent(bytes);
}

fn appendInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) std.mem.Allocator.Error!void {
    var le: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &le, value, .little);
    try out.appendSlice(allocator, &le);
}

fn appendShortSlice(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    bytes: []const u8,
) (Error || std.mem.Allocator.Error)!void {
    if (bytes.len > oper_cred_share.max_field_len) return error.InvalidGrant;
    try out.append(allocator, @intCast(bytes.len));
    try out.appendSlice(allocator, bytes);
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn int(self: *Reader, comptime T: type) ?T {
        if (self.buf.len - self.pos < @sizeOf(T)) return null;
        defer self.pos += @sizeOf(T);
        return std.mem.readInt(T, self.buf[self.pos..][0..@sizeOf(T)], .little);
    }

    fn shortSlice(self: *Reader) ?[]const u8 {
        if (self.pos == self.buf.len) return null;
        const n: usize = self.buf[self.pos];
        if (self.buf.len - self.pos - 1 < n) return null;
        defer self.pos += 1 + n;
        return self.buf[self.pos + 1 ..][0..n];
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn sampleGrant() oper_cred_share.GrantFields {
    return .{
        .account = "trev",
        .privilege_bits = 0x0000_0000_0001_0400,
        .class = "netadmin",
        .title = "Network Administrator",
        .issuer_node = "ircx.us",
        .incarnation = 1_700_000_000_123,
        .issued_ms = 1_700_000_000_000,
        .expiry_ms = 1_700_086_400_000,
    };
}

test "oper grant snapshot round-trips grants, tombstones, and the mint incarnation" {
    const allocator = testing.allocator;
    var reg = oper_cred_share.Registry.init();
    _ = reg.upsert(sampleGrant());
    // A zero-privilege revocation tombstone is live state (the incarnation
    // replay guard) and MUST survive the swap.
    _ = reg.upsert(.{
        .account = "revoked_oper",
        .privilege_bits = 0,
        .class = "revoked",
        .title = "",
        .issuer_node = "onyx.local",
        .incarnation = 42,
        .issued_ms = 100,
        .expiry_ms = 1_700_086_400_000,
    });

    const wire = try encodeFromRegistry(allocator, &reg, 1_700_000_500_000, 777);
    defer allocator.free(wire);
    try testing.expect(isCheckpoint(wire));

    const snap = try decodeCurrent(wire);
    try testing.expectEqual(@as(u64, 777), snap.mint_incarnation);
    try testing.expectEqual(@as(u32, 2), snap.count);

    var restored = oper_cred_share.Registry.init();
    var it = snap.iterator();
    var walked: usize = 0;
    while (it.next()) |g| {
        _ = restored.upsert(g);
        walked += 1;
    }
    try testing.expectEqual(@as(usize, 2), walked);
    const got = restored.lookup("trev", 1_700_000_500_000) orelse return error.TestExpectedGrant;
    try testing.expectEqual(sampleGrant().privilege_bits, got.privilege_bits);
    try testing.expectEqualStrings("netadmin", got.class);
    try testing.expectEqualStrings("Network Administrator", got.title);
    try testing.expectEqualStrings("ircx.us", got.issuer_node);
    try testing.expectEqual(sampleGrant().incarnation, got.incarnation);
    const tomb = restored.lookup("revoked_oper", 1_700_000_500_000) orelse return error.TestExpectedGrant;
    try testing.expectEqual(@as(u64, 0), tomb.privilege_bits);
    try testing.expectEqual(@as(u64, 42), tomb.incarnation);
}

test "oper grant snapshot of an empty registry round-trips as an empty image" {
    const allocator = testing.allocator;
    var reg = oper_cred_share.Registry.init();
    const wire = try encodeFromRegistry(allocator, &reg, 3, 55);
    defer allocator.free(wire);
    const snap = try decodeCurrent(wire);
    try testing.expectEqual(@as(u32, 0), snap.count);
    try testing.expectEqual(@as(u64, 55), snap.mint_incarnation);
    var it = snap.iterator();
    try testing.expect(it.next() == null);
}

test "oper grant snapshot sealing skips expired slots (what prune would leave)" {
    const allocator = testing.allocator;
    var reg = oper_cred_share.Registry.init();
    var lapsed = sampleGrant();
    lapsed.account = "lapsed";
    lapsed.expiry_ms = 1_000;
    _ = reg.upsert(sampleGrant());
    _ = reg.upsert(lapsed);

    const wire = try encodeFromRegistry(allocator, &reg, 2_000, 0);
    defer allocator.free(wire);
    const snap = try decodeCurrent(wire);
    try testing.expectEqual(@as(u32, 1), snap.count);
    var it = snap.iterator();
    try testing.expectEqualStrings("trev", it.next().?.account);
    try testing.expect(it.next() == null);
}

test "oper grant snapshot rejects every truncation" {
    const allocator = testing.allocator;
    var reg = oper_cred_share.Registry.init();
    _ = reg.upsert(sampleGrant());
    const wire = try encodeFromRegistry(allocator, &reg, 0, 9);
    defer allocator.free(wire);
    var n: usize = 0;
    while (n < wire.len) : (n += 1) {
        try testing.expectError(error.Truncated, decodeCurrent(wire[0..n]));
    }
}

test "oper grant snapshot rejects bad magic, versions, counts, and trailing bytes" {
    const allocator = testing.allocator;
    var reg = oper_cred_share.Registry.init();
    _ = reg.upsert(sampleGrant());
    const wire = try encodeFromRegistry(allocator, &reg, 0, 9);
    defer allocator.free(wire);

    const bad_magic = try allocator.dupe(u8, wire);
    defer allocator.free(bad_magic);
    bad_magic[0] = 'X';
    try testing.expectError(error.BadMagic, decodeCurrent(bad_magic));
    try testing.expect(!isCheckpoint(bad_magic));

    const too_new = try allocator.dupe(u8, wire);
    defer allocator.free(too_new);
    too_new[magic.len] = version + 1;
    try testing.expectError(error.UnsupportedVersion, decodeCurrent(too_new));

    // Declared count larger than the walked records fails closed (Truncated:
    // the walk runs out of bytes looking for the phantom record).
    const over_count = try allocator.dupe(u8, wire);
    defer allocator.free(over_count);
    std.mem.writeInt(u32, over_count[header_len - 4 ..][0..4], 2, .little);
    try testing.expectError(error.Truncated, decodeCurrent(over_count));

    // Declared count smaller than the emitted records leaves trailing bytes.
    const under_count = try allocator.dupe(u8, wire);
    defer allocator.free(under_count);
    std.mem.writeInt(u32, under_count[header_len - 4 ..][0..4], 0, .little);
    try testing.expectError(error.TrailingBytes, decodeCurrent(under_count));

    // A count beyond the registry capacity is malformed by construction.
    const too_many = try allocator.dupe(u8, wire);
    defer allocator.free(too_many);
    std.mem.writeInt(u32, too_many[header_len - 4 ..][0..4], max_grants + 1, .little);
    try testing.expectError(error.TooManyGrants, decodeCurrent(too_many));

    const trailing = try allocator.alloc(u8, wire.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try testing.expectError(error.TrailingBytes, decodeCurrent(trailing));
}

test "oper grant snapshot rejects empty-account, born-expired, and duplicate-account records" {
    const allocator = testing.allocator;

    // Empty account: build the record by hand (the encoder refuses to seal it).
    var hand: std.ArrayList(u8) = .empty;
    defer hand.deinit(allocator);
    try hand.appendSlice(allocator, &magic);
    try hand.append(allocator, version);
    try appendInt(&hand, allocator, u64, 0); // mint_incarnation
    try appendInt(&hand, allocator, u32, 1); // count
    try hand.append(allocator, 0); // alen = 0
    try appendInt(&hand, allocator, u64, 1); // privilege_bits
    try hand.append(allocator, 0); // clen
    try hand.append(allocator, 0); // tlen
    try hand.append(allocator, 0); // ilen
    try appendInt(&hand, allocator, u64, 1); // incarnation
    try appendInt(&hand, allocator, u64, 1); // issued
    try appendInt(&hand, allocator, u64, 2); // expiry
    try testing.expectError(error.InvalidGrant, decodeCurrent(hand.items));

    // Born-expired (issued > expiry) fails closed.
    var reg = oper_cred_share.Registry.init();
    var born_expired = sampleGrant();
    born_expired.issued_ms = 10;
    born_expired.expiry_ms = 5;
    _ = reg.upsert(born_expired);
    // The registry stores it verbatim; the SEALER refuses the malformed image.
    try testing.expectError(error.InvalidGrant, encodeFromRegistry(allocator, &reg, 0, 0));

    // Duplicate account (case-insensitive) is an ambiguous image.
    var dup: std.ArrayList(u8) = .empty;
    defer dup.deinit(allocator);
    try dup.appendSlice(allocator, &magic);
    try dup.append(allocator, version);
    try appendInt(&dup, allocator, u64, 0);
    try appendInt(&dup, allocator, u32, 2);
    for ([_][]const u8{ "trev", "TREV" }) |account| {
        try dup.append(allocator, @intCast(account.len));
        try dup.appendSlice(allocator, account);
        try appendInt(&dup, allocator, u64, 1);
        try dup.append(allocator, 0);
        try dup.append(allocator, 0);
        try dup.append(allocator, 0);
        try appendInt(&dup, allocator, u64, 1);
        try appendInt(&dup, allocator, u64, 1);
        try appendInt(&dup, allocator, u64, 2);
    }
    try testing.expectError(error.InvalidGrant, decodeCurrent(dup.items));
}

test "oper grant snapshot validateCheckpoint accepts a sealed image" {
    const allocator = testing.allocator;
    var reg = oper_cred_share.Registry.init();
    _ = reg.upsert(sampleGrant());
    const wire = try encodeFromRegistry(allocator, &reg, 0, 1);
    defer allocator.free(wire);
    try validateCheckpoint(wire);
}
