//! TLS 1.3 session-resumption ticket helpers.
//!
//! This module owns only the opaque, local formats used by the clean-room
//! TLS stack:
//!
//! * server tickets are self-contained ChaCha20-Poly1305 sealed blobs carrying
//!   the cipher-suite id, PSK, ticket nonce, and issue time;
//! * client session snapshots are serialized values callers may persist and
//!   later feed to a fresh client.

const std = @import("std");

const Allocator = std.mem.Allocator;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const TicketKey = [ChaCha20Poly1305.key_length]u8;
pub const ticket_nonce_len: usize = 8;
pub const max_hash_len: usize = 48;

const sealed_magic_v1: u8 = 1;
const sealed_magic: u8 = 2;
const stored_magic = [_]u8{ 'O', 'T', 'S', '1' };
const sealed_aad = "orochi tls13 session ticket v1";

pub const Error = error{
    BadTicket,
    BadSession,
    PskTooLarge,
    TicketTooLarge,
    NonceTooLarge,
} || Allocator.Error;

pub const OpenedTicket = struct {
    suite: u16,
    issued_unix_ms: i64,
    ticket_nonce: []const u8,
    psk: []const u8,
    max_early_data_size: u32,
};

pub const StoredSession = struct {
    suite: u16,
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket: []const u8,
    psk: []const u8,
    max_early_data_size: u32 = 0,
};

/// Largest PSK binder this guard retains (SHA-384 digest size).
pub const max_binder_len: usize = max_hash_len;

/// Bounded single-use guard against 0-RTT early-data replay (RFC 8446 §8): it
/// records the PSK binders of accepted 0-RTT attempts and reports a repeat as a
/// replay. A fixed ring of `capacity` recent binders bounds memory; a binder
/// evicted after `capacity` distinct attempts could be replayed, but the ticket
/// lifetime window bounds that exposure further.
///
/// NOT internally synchronized: a caller sharing one guard across threads must
/// serialize `checkAndRecord` (the live daemon would hold a lock around it).
pub const ReplayGuard = struct {
    pub const capacity: usize = 2048;

    entries: [capacity][max_binder_len]u8 = undefined,
    lens: [capacity]u8 = [_]u8{0} ** capacity,
    next: usize = 0,
    wrapped: bool = false,

    /// Returns true when `binder` is fresh (and records it); false when it was
    /// already seen (a replay) or is malformed.
    pub fn checkAndRecord(self: *ReplayGuard, binder: []const u8) bool {
        if (binder.len == 0 or binder.len > max_binder_len) return false;
        const limit = if (self.wrapped) capacity else self.next;
        var i: usize = 0;
        while (i < limit) : (i += 1) {
            if (self.lens[i] == binder.len and
                std.mem.eql(u8, self.entries[i][0..binder.len], binder))
            {
                return false;
            }
        }
        @memcpy(self.entries[self.next][0..binder.len], binder);
        self.lens[self.next] = @intCast(binder.len);
        self.next += 1;
        if (self.next == capacity) {
            self.next = 0;
            self.wrapped = true;
        }
        return true;
    }
};

test "ReplayGuard reports repeats and bounds memory" {
    var g = ReplayGuard{};
    const a = [_]u8{0xAA} ** 32;
    const b = [_]u8{0xBB} ** 48;
    try std.testing.expect(g.checkAndRecord(&a)); // fresh
    try std.testing.expect(!g.checkAndRecord(&a)); // replay
    try std.testing.expect(g.checkAndRecord(&b)); // different
    try std.testing.expect(!g.checkAndRecord(&b)); // replay
    try std.testing.expect(!g.checkAndRecord("")); // malformed
}

/// Seal a server-side ticket blob with a caller-supplied AEAD nonce.
pub fn sealTicket(
    allocator: Allocator,
    key: TicketKey,
    aead_nonce: [ChaCha20Poly1305.nonce_length]u8,
    suite: u16,
    psk: []const u8,
    ticket_nonce: []const u8,
    issued_unix_ms: i64,
    max_early_data_size: u32,
) Error![]u8 {
    if (psk.len > max_hash_len) return error.PskTooLarge;
    if (ticket_nonce.len > std.math.maxInt(u8)) return error.NonceTooLarge;

    var plain = try allocator.alloc(u8, 1 + 2 + 8 + 1 + ticket_nonce.len + 4 + 1 + psk.len);
    defer allocator.free(plain);

    var off: usize = 0;
    plain[off] = sealed_magic;
    off += 1;
    std.mem.writeInt(u16, plain[off..][0..2], suite, .big);
    off += 2;
    std.mem.writeInt(i64, plain[off..][0..8], issued_unix_ms, .big);
    off += 8;
    plain[off] = @intCast(ticket_nonce.len);
    off += 1;
    @memcpy(plain[off..][0..ticket_nonce.len], ticket_nonce);
    off += ticket_nonce.len;
    std.mem.writeInt(u32, plain[off..][0..4], max_early_data_size, .big);
    off += 4;
    plain[off] = @intCast(psk.len);
    off += 1;
    @memcpy(plain[off..][0..psk.len], psk);
    off += psk.len;

    var out = try allocator.alloc(u8, 1 + aead_nonce.len + plain.len + ChaCha20Poly1305.tag_length);
    errdefer allocator.free(out);
    out[0] = sealed_magic;
    @memcpy(out[1..][0..aead_nonce.len], &aead_nonce);
    var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
    ChaCha20Poly1305.encrypt(
        out[1 + aead_nonce.len ..][0..plain.len],
        &tag,
        plain,
        sealed_aad,
        aead_nonce,
        key,
    );
    @memcpy(out[1 + aead_nonce.len + plain.len ..][0..tag.len], &tag);
    return out;
}

/// Open a server-side ticket blob. Returned slices alias `out_plain`.
pub fn openTicket(
    allocator: Allocator,
    key: TicketKey,
    ticket: []const u8,
) Error!struct { plain: []u8, opened: OpenedTicket } {
    if (ticket.len < 1 + ChaCha20Poly1305.nonce_length + ChaCha20Poly1305.tag_length) return error.BadTicket;
    if (ticket[0] != sealed_magic and ticket[0] != sealed_magic_v1) return error.BadTicket;
    const nonce = ticket[1..][0..ChaCha20Poly1305.nonce_length].*;
    const sealed = ticket[1 + ChaCha20Poly1305.nonce_length ..];
    const clen = sealed.len - ChaCha20Poly1305.tag_length;
    const tag = sealed[clen..][0..ChaCha20Poly1305.tag_length].*;
    var plain = try allocator.alloc(u8, clen);
    errdefer allocator.free(plain);
    ChaCha20Poly1305.decrypt(plain, sealed[0..clen], tag, sealed_aad, nonce, key) catch return error.BadTicket;

    var off: usize = 0;
    if (plain.len - off < 1) return error.BadTicket;
    const version = plain[off];
    if (version != sealed_magic and version != sealed_magic_v1) return error.BadTicket;
    off += 1;
    if (plain.len - off < 2 + 8 + 1) return error.BadTicket;
    const suite = std.mem.readInt(u16, plain[off..][0..2], .big);
    off += 2;
    const issued = std.mem.readInt(i64, plain[off..][0..8], .big);
    off += 8;
    const nonce_len = plain[off];
    off += 1;
    if (plain.len - off < nonce_len + 1) return error.BadTicket;
    const ticket_nonce = plain[off .. off + nonce_len];
    off += nonce_len;
    const max_early_data_size = if (version == sealed_magic) blk: {
        if (plain.len - off < 4) return error.BadTicket;
        const limit = std.mem.readInt(u32, plain[off..][0..4], .big);
        off += 4;
        break :blk limit;
    } else 0;
    const psk_len = plain[off];
    off += 1;
    if (psk_len == 0 or psk_len > max_hash_len or plain.len - off != psk_len) return error.BadTicket;
    const psk = plain[off .. off + psk_len];

    return .{
        .plain = plain,
        .opened = .{
            .suite = suite,
            .issued_unix_ms = issued,
            .ticket_nonce = ticket_nonce,
            .psk = psk,
            .max_early_data_size = max_early_data_size,
        },
    };
}

/// Serialize a client-side resumable session snapshot.
pub fn encodeStoredSession(allocator: Allocator, session: StoredSession) Error![]u8 {
    if (session.ticket.len > std.math.maxInt(u16)) return error.TicketTooLarge;
    if (session.psk.len == 0 or session.psk.len > max_hash_len) return error.PskTooLarge;

    var out = try allocator.alloc(u8, stored_magic.len + 2 + 4 + 4 + 2 + session.ticket.len + 4 + 1 + session.psk.len);
    errdefer allocator.free(out);
    var off: usize = 0;
    @memcpy(out[off..][0..stored_magic.len], &stored_magic);
    off += stored_magic.len;
    std.mem.writeInt(u16, out[off..][0..2], session.suite, .big);
    off += 2;
    std.mem.writeInt(u32, out[off..][0..4], session.ticket_lifetime, .big);
    off += 4;
    std.mem.writeInt(u32, out[off..][0..4], session.ticket_age_add, .big);
    off += 4;
    std.mem.writeInt(u16, out[off..][0..2], @intCast(session.ticket.len), .big);
    off += 2;
    @memcpy(out[off..][0..session.ticket.len], session.ticket);
    off += session.ticket.len;
    std.mem.writeInt(u32, out[off..][0..4], session.max_early_data_size, .big);
    off += 4;
    out[off] = @intCast(session.psk.len);
    off += 1;
    @memcpy(out[off..][0..session.psk.len], session.psk);
    off += session.psk.len;
    return out[0..off];
}

/// Decode a serialized client-side resumable session. Returned slices alias `bytes`.
pub fn decodeStoredSession(bytes: []const u8) Error!StoredSession {
    var off: usize = 0;
    if (bytes.len < stored_magic.len or !std.mem.eql(u8, bytes[0..stored_magic.len], &stored_magic)) {
        return error.BadSession;
    }
    off += stored_magic.len;
    if (bytes.len - off < 2 + 4 + 4 + 2) return error.BadSession;
    const suite = std.mem.readInt(u16, bytes[off..][0..2], .big);
    off += 2;
    const lifetime = std.mem.readInt(u32, bytes[off..][0..4], .big);
    off += 4;
    const age_add = std.mem.readInt(u32, bytes[off..][0..4], .big);
    off += 4;
    const ticket_len = std.mem.readInt(u16, bytes[off..][0..2], .big);
    off += 2;
    if (bytes.len - off < ticket_len + 1) return error.BadSession;
    const ticket = bytes[off .. off + ticket_len];
    off += ticket_len;
    var max_early_data_size: u32 = 0;
    const remaining_after_ticket = bytes.len - off;
    if (remaining_after_ticket >= 4 + 1) {
        const candidate_psk_len = bytes[off + 4];
        if (candidate_psk_len != 0 and candidate_psk_len <= max_hash_len and
            remaining_after_ticket == 4 + 1 + @as(usize, candidate_psk_len))
        {
            max_early_data_size = std.mem.readInt(u32, bytes[off..][0..4], .big);
            off += 4;
        }
    }
    const psk_len = bytes[off];
    off += 1;
    if (psk_len == 0 or psk_len > max_hash_len or bytes.len - off != psk_len) return error.BadSession;
    return .{
        .suite = suite,
        .ticket_lifetime = lifetime,
        .ticket_age_add = age_add,
        .ticket = ticket,
        .psk = bytes[off .. off + psk_len],
        .max_early_data_size = max_early_data_size,
    };
}

test "stored client session round-trips" {
    const allocator = std.testing.allocator;
    const encoded = try encodeStoredSession(allocator, .{
        .suite = 0x1301,
        .ticket_lifetime = 86_400,
        .ticket_age_add = 0x1122_3344,
        .ticket = "opaque-ticket",
        .psk = &([_]u8{0xaa} ** 32),
        .max_early_data_size = 4096,
    });
    defer allocator.free(encoded);

    const parsed = try decodeStoredSession(encoded);
    try std.testing.expectEqual(@as(u16, 0x1301), parsed.suite);
    try std.testing.expectEqual(@as(u32, 86_400), parsed.ticket_lifetime);
    try std.testing.expectEqual(@as(u32, 0x1122_3344), parsed.ticket_age_add);
    try std.testing.expectEqualSlices(u8, "opaque-ticket", parsed.ticket);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 32), parsed.psk);
    try std.testing.expectEqual(@as(u32, 4096), parsed.max_early_data_size);
}

test "sealed server ticket opens with the same key" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x11} ** ChaCha20Poly1305.key_length;
    const nonce = [_]u8{0x22} ** ChaCha20Poly1305.nonce_length;
    const psk = [_]u8{0x33} ** 32;
    const ticket = try sealTicket(allocator, key, nonce, 0x1301, &psk, "nonce", 1234, 8192);
    defer allocator.free(ticket);

    const opened = try openTicket(allocator, key, ticket);
    defer allocator.free(opened.plain);
    try std.testing.expectEqual(@as(u16, 0x1301), opened.opened.suite);
    try std.testing.expectEqual(@as(i64, 1234), opened.opened.issued_unix_ms);
    try std.testing.expectEqualSlices(u8, "nonce", opened.opened.ticket_nonce);
    try std.testing.expectEqualSlices(u8, &psk, opened.opened.psk);
    try std.testing.expectEqual(@as(u32, 8192), opened.opened.max_early_data_size);
}
