// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SESSION_REPLICA v2 convergence core.
//!
//! This module deliberately owns no sockets. It defines the signed,
//! self-certifying OFFER/ACK wire objects and the bounded in-memory convergence
//! store driven by the daemon's live S2S capability. The safety rules are
//! intentionally strict:
//!
//!   * authority is keyed by `(token, origin_node)` so simultaneous attachments
//!     coexist; the revision total order only selects a deterministic projection;
//!   * equal revision + equal signed fact is an idempotent duplicate;
//!   * same-origin equal-revision equivocation retains the lexicographically
//!     smaller transcript digest, independent of arrival order;
//!   * lower revisions are stale only within the same origin authority;
//!   * higher revisions supersede only that origin's entry or tombstone;
//!   * every route is bound to the live revision of its authority origin;
//!   * entries, routes, and tombstones have independent hard bounds; no live
//!     authority is evicted merely to admit attacker-controlled input;
//!   * peer removal and time sweeping are allocation-free once state exists.
//!
//! OFFER carries either a complete replica upsert (account, nick, snapshot) or
//! a removal tombstone. ACK carries the receiver's disposition and observed
//! revision. Both objects embed the signing public key, bind every semantic
//! field under a distinct Ed25519 domain, and require the claimed node id to be
//! the self-certified short id of that key. They are safe to forward unchanged
//! across multiple hops.

const std = @import("std");

const sign = @import("../../crypto/sign.zig");
const session_replica_transport = @import("../../proto/session_replica_frame.zig");
const signed_frame = @import("../../substrate/suimyaku/signed_frame.zig");

pub const Token = [16]u8;
pub const NodeId = u64;
pub const Digest = [std.crypto.hash.Blake3.digest_length]u8;

pub const offer_magic = [_]u8{ 'S', 'R', 'O', '2' };
pub const ack_magic = [_]u8{ 'S', 'R', 'A', '2' };
pub const offer_sign_domain = "orochi-session-replica-offer-v2";
pub const ack_sign_domain = "orochi-session-replica-ack-v2";

pub const max_account_len: usize = 128;
pub const max_nick_len: usize = 64;

const revision_wire_len: usize = 8 + 8 + 8;
const signature_wire_len: usize = sign.public_key_len + sign.signature_len;
const offer_fixed_len: usize = offer_magic.len + 1 + @sizeOf(Token) + revision_wire_len + 8 + 8 + 2 + 2 + 4;
const ack_fixed_len: usize = ack_magic.len + 1 + @sizeOf(Token) + revision_wire_len + revision_wire_len + 8 + 8 + 8;
/// Largest snapshot for which every legal max-length account/nick OFFER still
/// fits the secured SESSION_REPLICA transport envelope exactly.
pub const max_snapshot_len: usize = session_replica_transport.max_signed_payload_len -
    offer_fixed_len - signature_wire_len - max_account_len - max_nick_len;

/// A restart-safe, deterministic total-order revision. `epoch` is the durable
/// generation/wall epoch, `sequence` orders writes inside it, and `origin_node`
/// breaks simultaneous cross-node ties without depending on arrival order.
pub const Revision = struct {
    epoch: u64,
    sequence: u64,
    origin_node: NodeId,

    pub fn compare(a: Revision, b: Revision) std.math.Order {
        if (a.epoch < b.epoch) return .lt;
        if (a.epoch > b.epoch) return .gt;
        if (a.sequence < b.sequence) return .lt;
        if (a.sequence > b.sequence) return .gt;
        if (a.origin_node < b.origin_node) return .lt;
        if (a.origin_node > b.origin_node) return .gt;
        return .eq;
    }

    pub fn eql(a: Revision, b: Revision) bool {
        return compare(a, b) == .eq;
    }
};

pub const OfferOperation = enum(u8) {
    upsert = 1,
    remove = 2,
};

/// Unsigned semantic OFFER. `encodeOffer` signs this value and returns the
/// complete owned wire object. Variable fields are borrowed for the call.
pub const Offer = struct {
    operation: OfferOperation,
    token: Token,
    revision: Revision,
    issued_at_ms: i64,
    expires_at_ms: i64,
    account: []const u8 = "",
    nick: []const u8 = "",
    snapshot: []const u8 = "",
};

/// Decoded signed OFFER. Variable fields and `transcript` borrow the input wire.
pub const SignedOffer = struct {
    offer: Offer,
    signer: sign.PublicKey,
    signature: sign.Signature,
    transcript: []const u8,
};

pub const AckStatus = enum(u8) {
    accepted = 1,
    duplicate = 2,
    conflict = 3,
    stale = 4,
    superseded = 5,
    tombstoned = 6,
    capacity = 7,
};

/// Unsigned semantic ACK. `offered_revision` identifies the fact being
/// acknowledged; `observed_revision` reports the receiver's current authority.
pub const Ack = struct {
    status: AckStatus,
    token: Token,
    offered_revision: Revision,
    observed_revision: Revision,
    ack_node: NodeId,
    issued_at_ms: i64,
    expires_at_ms: i64,
};

/// Decoded signed ACK. `transcript` borrows the input wire.
pub const SignedAck = struct {
    ack: Ack,
    signer: sign.PublicKey,
    signature: sign.Signature,
    transcript: []const u8,
};

pub const EncodeError = error{
    InvalidOffer,
    InvalidAck,
    OriginMismatch,
    TooLong,
} || std.mem.Allocator.Error || sign.SignError;

pub const DecodeError = error{
    BadMagic,
    InvalidOffer,
    InvalidAck,
    TooLong,
    TrailingBytes,
    Truncated,
};

pub const VerifyError = error{
    BadSignature,
    OriginMismatch,
    TranscriptMismatch,
};

/// Encode and sign one canonical OFFER. The caller owns the returned bytes.
pub fn encodeOffer(allocator: std.mem.Allocator, offer: Offer, kp: *const sign.KeyPair) EncodeError![]u8 {
    try validateOfferShape(offer);
    if (signed_frame.originShortId(kp.public_key) != offer.revision.origin_node) return error.OriginMismatch;

    const transcript_len = offer_fixed_len + offer.account.len + offer.nick.len + offer.snapshot.len;
    const total_len = transcript_len + signature_wire_len;
    var out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);

    var writer = Writer{ .bytes = out };
    writer.writeBytes(&offer_magic);
    writer.writeByte(@intFromEnum(offer.operation));
    writer.writeBytes(&offer.token);
    writer.writeRevision(offer.revision);
    writer.writeI64(offer.issued_at_ms);
    writer.writeI64(offer.expires_at_ms);
    writer.writeU16(@intCast(offer.account.len));
    writer.writeU16(@intCast(offer.nick.len));
    writer.writeU32(@intCast(offer.snapshot.len));
    writer.writeBytes(offer.account);
    writer.writeBytes(offer.nick);
    writer.writeBytes(offer.snapshot);
    std.debug.assert(writer.pos == transcript_len);

    const signature = try kp.signCtx(offer_sign_domain, out[0..transcript_len]);
    writer.writeBytes(&kp.public_key);
    writer.writeBytes(&signature);
    std.debug.assert(writer.pos == out.len);
    return out;
}

/// Strictly decode one canonical signed OFFER. Returned slices borrow `bytes`.
pub fn decodeOffer(bytes: []const u8) DecodeError!SignedOffer {
    var reader = Reader{ .bytes = bytes };
    const offer = try readOffer(&reader);
    const transcript_end = reader.pos;
    const signer = (try reader.take(sign.public_key_len))[0..sign.public_key_len].*;
    const signature = (try reader.take(sign.signature_len))[0..sign.signature_len].*;
    if (reader.pos != bytes.len) return error.TrailingBytes;

    return .{
        .offer = offer,
        .signer = signer,
        .signature = signature,
        .transcript = bytes[0..transcript_end],
    };
}

fn readOffer(reader: *Reader) DecodeError!Offer {
    if (!std.mem.eql(u8, try reader.take(offer_magic.len), &offer_magic)) return error.BadMagic;
    const operation: OfferOperation = switch (try reader.readByte()) {
        1 => .upsert,
        2 => .remove,
        else => return error.InvalidOffer,
    };
    const token = (try reader.take(@sizeOf(Token)))[0..@sizeOf(Token)].*;
    const revision = try reader.readRevision();
    const issued_at_ms = try reader.readI64();
    const expires_at_ms = try reader.readI64();
    const account_len = try reader.readU16();
    const nick_len = try reader.readU16();
    const snapshot_len = try reader.readU32();
    if (account_len > max_account_len or nick_len > max_nick_len or snapshot_len > max_snapshot_len) return error.TooLong;
    const account = try reader.take(account_len);
    const nick = try reader.take(nick_len);
    const snapshot = try reader.take(snapshot_len);
    const offer = Offer{
        .operation = operation,
        .token = token,
        .revision = revision,
        .issued_at_ms = issued_at_ms,
        .expires_at_ms = expires_at_ms,
        .account = account,
        .nick = nick,
        .snapshot = snapshot,
    };
    validateOfferShape(offer) catch return error.InvalidOffer;
    return offer;
}

pub fn verifyOffer(signed: SignedOffer) VerifyError!void {
    var reader = Reader{ .bytes = signed.transcript };
    const projected = readOffer(&reader) catch return error.TranscriptMismatch;
    if (reader.pos != signed.transcript.len or !offerEql(projected, signed.offer)) return error.TranscriptMismatch;
    if (signed_frame.originShortId(signed.signer) != signed.offer.revision.origin_node) return error.OriginMismatch;
    const valid = sign.verifyCtx(offer_sign_domain, signed.transcript, signed.signature, signed.signer) catch false;
    if (!valid) return error.BadSignature;
}

/// Encode and sign one canonical ACK. The caller owns the returned bytes.
pub fn encodeAck(allocator: std.mem.Allocator, ack: Ack, kp: *const sign.KeyPair) EncodeError![]u8 {
    try validateAckShape(ack);
    if (signed_frame.originShortId(kp.public_key) != ack.ack_node) return error.OriginMismatch;

    const transcript_len = ack_fixed_len;
    var out = try allocator.alloc(u8, transcript_len + signature_wire_len);
    errdefer allocator.free(out);
    var writer = Writer{ .bytes = out };
    writer.writeBytes(&ack_magic);
    writer.writeByte(@intFromEnum(ack.status));
    writer.writeBytes(&ack.token);
    writer.writeRevision(ack.offered_revision);
    writer.writeRevision(ack.observed_revision);
    writer.writeU64(ack.ack_node);
    writer.writeI64(ack.issued_at_ms);
    writer.writeI64(ack.expires_at_ms);
    std.debug.assert(writer.pos == transcript_len);

    const signature = try kp.signCtx(ack_sign_domain, out[0..transcript_len]);
    writer.writeBytes(&kp.public_key);
    writer.writeBytes(&signature);
    std.debug.assert(writer.pos == out.len);
    return out;
}

/// Strictly decode one canonical signed ACK. Returned transcript borrows bytes.
pub fn decodeAck(bytes: []const u8) DecodeError!SignedAck {
    var reader = Reader{ .bytes = bytes };
    const ack = try readAck(&reader);
    const transcript_end = reader.pos;
    const signer = (try reader.take(sign.public_key_len))[0..sign.public_key_len].*;
    const signature = (try reader.take(sign.signature_len))[0..sign.signature_len].*;
    if (reader.pos != bytes.len) return error.TrailingBytes;

    return .{
        .ack = ack,
        .signer = signer,
        .signature = signature,
        .transcript = bytes[0..transcript_end],
    };
}

fn readAck(reader: *Reader) DecodeError!Ack {
    if (!std.mem.eql(u8, try reader.take(ack_magic.len), &ack_magic)) return error.BadMagic;
    const status: AckStatus = switch (try reader.readByte()) {
        1 => .accepted,
        2 => .duplicate,
        3 => .conflict,
        4 => .stale,
        5 => .superseded,
        6 => .tombstoned,
        7 => .capacity,
        else => return error.InvalidAck,
    };
    const token = (try reader.take(@sizeOf(Token)))[0..@sizeOf(Token)].*;
    const offered_revision = try reader.readRevision();
    const observed_revision = try reader.readRevision();
    const ack_node = try reader.readU64();
    const issued_at_ms = try reader.readI64();
    const expires_at_ms = try reader.readI64();
    const ack = Ack{
        .status = status,
        .token = token,
        .offered_revision = offered_revision,
        .observed_revision = observed_revision,
        .ack_node = ack_node,
        .issued_at_ms = issued_at_ms,
        .expires_at_ms = expires_at_ms,
    };
    validateAckShape(ack) catch return error.InvalidAck;
    return ack;
}

pub fn verifyAck(signed: SignedAck) VerifyError!void {
    var reader = Reader{ .bytes = signed.transcript };
    const projected = readAck(&reader) catch return error.TranscriptMismatch;
    if (reader.pos != signed.transcript.len or !ackEql(projected, signed.ack)) return error.TranscriptMismatch;
    if (signed_frame.originShortId(signed.signer) != signed.ack.ack_node) return error.OriginMismatch;
    const valid = sign.verifyCtx(ack_sign_domain, signed.transcript, signed.signature, signed.signer) catch false;
    if (!valid) return error.BadSignature;
}

fn validateOfferShape(offer: Offer) error{ InvalidOffer, TooLong }!void {
    if (offer.revision.origin_node == 0) return error.InvalidOffer;
    if (offer.issued_at_ms < 0 or offer.expires_at_ms < offer.issued_at_ms) return error.InvalidOffer;
    if (offer.account.len > max_account_len or offer.nick.len > max_nick_len or offer.snapshot.len > max_snapshot_len) return error.TooLong;
    switch (offer.operation) {
        .upsert => {
            if (offer.account.len == 0 or offer.nick.len == 0 or offer.snapshot.len == 0) return error.InvalidOffer;
        },
        .remove => {
            if (offer.account.len != 0 or offer.nick.len != 0 or offer.snapshot.len != 0) return error.InvalidOffer;
        },
    }
}

fn validateAckShape(ack: Ack) error{InvalidAck}!void {
    if (ack.ack_node == 0 or ack.offered_revision.origin_node == 0 or ack.observed_revision.origin_node == 0) return error.InvalidAck;
    if (ack.offered_revision.origin_node != ack.observed_revision.origin_node) return error.InvalidAck;
    if (ack.issued_at_ms < 0 or ack.expires_at_ms < ack.issued_at_ms) return error.InvalidAck;
}

pub const ApplyDisposition = enum {
    inserted,
    duplicate,
    conflict,
    conflict_replaced,
    quarantined,
    stale,
    superseded,
    tombstoned,

    pub fn ackStatus(self: ApplyDisposition) AckStatus {
        return switch (self) {
            .inserted => .accepted,
            .duplicate => .duplicate,
            .conflict => .conflict,
            .conflict_replaced => .conflict,
            .quarantined => .conflict,
            .stale => .stale,
            .superseded => .superseded,
            .tombstoned => .tombstoned,
        };
    }
};

pub const ApplyResult = struct {
    disposition: ApplyDisposition,
    current_revision: Revision,
};

pub const RouteDisposition = enum {
    inserted,
    refreshed,
    ignored,
    stale,
};

/// ACKs are authenticated receipt metadata only. They never create an active
/// route because v2 ACKs carry no path vector with which to prevent loops.
pub const AckDisposition = enum {
    accepted,
    ignored,
    stale,
};

pub const ApplyError = VerifyError || error{
    EntryFull,
    Expired,
    IdentityConflict,
    InvalidLifetime,
    InvalidOffer,
    QuarantineFull,
    RouteFull,
    TombstoneFull,
} || std.mem.Allocator.Error;

pub const AckApplyError = VerifyError || error{
    Expired,
    InvalidLifetime,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    entries: std.AutoHashMapUnmanaged(OriginKey, Entry) = .empty,
    routes: std.AutoHashMapUnmanaged(RouteKey, RouteValue) = .empty,
    tombstones: std.AutoHashMapUnmanaged(OriginKey, Tombstone) = .empty,
    quarantines: std.AutoHashMapUnmanaged(Token, Quarantine) = .empty,

    pub const Config = struct {
        max_entries: usize = 4096,
        max_routes: usize = 16_384,
        max_tombstones: usize = 4096,
        max_quarantines: usize = 1024,
        max_offer_lifetime_ms: u64 = 24 * 60 * 60 * 1000,
        max_future_skew_ms: u64 = 5 * 60 * 1000,
        route_ttl_ms: u64 = 15 * 60 * 1000,
        tombstone_ttl_ms: u64 = 24 * 60 * 60 * 1000,
        max_account_bytes: usize = max_account_len,
        max_nick_bytes: usize = max_nick_len,
        max_snapshot_bytes: usize = max_snapshot_len,
    };

    pub const Entry = struct {
        /// Exact canonical signed OFFER, owned by the Store. Variable semantic
        /// slices below borrow this stable heap allocation.
        wire: []const u8,
        account: []const u8,
        nick: []const u8,
        snapshot: []const u8,
        revision: Revision,
        issued_at_ms: i64,
        expires_at_ms: i64,
        updated_at_ms: i64,
        digest: Digest,
        /// First ingress selected for this exact authority revision. Reflected
        /// duplicates cannot add alternate parents; a newer revision reselects.
        ingress_peer: ?NodeId,
        /// Allocation-free deny marker used if full quarantine evidence cannot
        /// be installed under allocator or quarantine-capacity pressure.
        quarantine_until_ms: ?i64,
    };

    /// The authority scope for one attachment. One bearer token may have
    /// several simultaneous origin entries, but an origin has at most one live
    /// entry or tombstone for that token.
    pub const OriginKey = struct {
        token: Token,
        origin_node: NodeId,
    };

    pub const Route = struct {
        /// Anti-entropy provenance only: this is the first peer from which the
        /// signed authority fact was learned, not proof of live reachability.
        token: Token,
        destination: NodeId,
        next_hop: NodeId,
        revision: Revision,
        last_seen_ms: i64,
    };

    const RouteKey = struct {
        token: Token,
        destination: NodeId,
        next_hop: NodeId,
    };

    const RouteValue = struct {
        revision: Revision,
        last_seen_ms: i64,
    };

    pub const Tombstone = struct {
        /// Exact canonical signed REVOKE, owned by the Store.
        wire: []const u8,
        revision: Revision,
        removed_at_ms: i64,
        offer_expires_at_ms: i64,
        digest: Digest,
        /// Binds a removed origin to the token's account identity while replay
        /// protection is active. Unknown-token removals have no identity yet.
        identity_digest: ?Digest,
        quarantine_until_ms: ?i64,
    };

    pub const Quarantine = struct {
        first_wire: []const u8,
        second_wire: []const u8,
        expires_at_ms: i64,
        detected_at_ms: i64,
    };

    pub const RetainedKind = enum {
        offer,
        revoke,
    };

    /// Borrowed retransmission view. `wire` stays valid until the corresponding
    /// Store origin is superseded, swept, or the Store is deinitialized.
    pub const RetainedObject = struct {
        kind: RetainedKind,
        token: Token,
        origin_node: NodeId,
        revision: Revision,
        expires_at_ms: i64,
        wire: []const u8,
    };

    pub const SweepResult = struct {
        entries: usize = 0,
        routes: usize = 0,
        tombstones: usize = 0,
        quarantines: usize = 0,
    };

    pub fn init(allocator: std.mem.Allocator) Store {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) Store {
        return .{ .allocator = allocator, .cfg = cfg };
    }

    pub fn deinit(self: *Store) void {
        var it = self.entries.valueIterator();
        while (it.next()) |entry| freeEntry(self.allocator, entry.*);
        var tombstone_it = self.tombstones.valueIterator();
        while (tombstone_it.next()) |tombstone| freeTombstone(self.allocator, tombstone.*);
        var quarantine_it = self.quarantines.valueIterator();
        while (quarantine_it.next()) |quarantine| freeQuarantine(self.allocator, quarantine.*);
        self.entries.deinit(self.allocator);
        self.routes.deinit(self.allocator);
        self.tombstones.deinit(self.allocator);
        self.quarantines.deinit(self.allocator);
        self.* = undefined;
    }

    /// Verify and converge a signed OFFER learned through `via_peer`. Zero means
    /// locally seeded state and deliberately creates no route.
    pub fn applySignedOffer(self: *Store, signed: SignedOffer, via_peer: NodeId, now_ms: i64) ApplyError!ApplyResult {
        try verifyOffer(signed);
        const offer = signed.offer;
        try self.validateOfferForStore(offer, now_ms);
        const digest = digestBytes(signed.transcript);
        return self.applyVerifiedOffer(signed, digest, via_peer, now_ms);
    }

    /// Verify a signed ACK as receipt metadata. No route is installed: ACK v2
    /// has no path vector, so treating its ingress as reachability can form a
    /// loop when the receipt is forwarded or reflected.
    pub fn applySignedAck(self: *Store, signed: SignedAck, via_peer: NodeId, now_ms: i64) AckApplyError!AckDisposition {
        try verifyAck(signed);
        const ack = signed.ack;
        try validateLifetime(ack.issued_at_ms, ack.expires_at_ms, now_ms, self.cfg.max_offer_lifetime_ms, self.cfg.max_future_skew_ms);
        if (via_peer == 0) return .ignored;
        switch (ack.status) {
            .accepted, .duplicate, .superseded => {},
            .conflict, .stale, .tombstoned, .capacity => return .ignored,
        }
        if (ack.offered_revision.origin_node != ack.observed_revision.origin_node) return .stale;
        if (!ack.offered_revision.eql(ack.observed_revision)) return .stale;
        const origin = ack.observed_revision.origin_node;
        const current = self.getOrigin(ack.token, origin) orelse return .stale;
        if (!current.revision.eql(ack.observed_revision)) return .stale;
        return .accepted;
    }

    /// Return the live fact asserted by exactly one origin. Token comparison is
    /// constant-time; the public lookup deliberately does not use hash equality.
    pub fn getOrigin(self: *const Store, token: Token, origin_node: NodeId) ?*const Entry {
        if (self.isQuarantined(token)) return null;
        var it = @constCast(&self.entries).iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) return slot.value_ptr;
        }
        return null;
    }

    /// Deterministic current identity projection for callers that need one
    /// representative. Concurrent origins remain stored and addressable.
    pub fn bestIdentity(self: *const Store, token: Token) ?*const Entry {
        if (self.isQuarantined(token)) return null;
        var best: ?*const Entry = null;
        var it = @constCast(&self.entries).iterator();
        while (it.next()) |slot| {
            if (!tokenEql(slot.key_ptr.token, token)) continue;
            if (best == null or slot.value_ptr.revision.compare(best.?.revision) == .gt) best = slot.value_ptr;
        }
        return best;
    }

    /// Deterministic representative restricted to signed facts that remain
    /// live at `now_ms`; safe for hot paths between periodic sweeps.
    pub fn bestLiveIdentity(self: *const Store, token: Token, now_ms: i64) ?*const Entry {
        if (self.isQuarantined(token)) return null;
        var best: ?*const Entry = null;
        var it = @constCast(&self.entries).iterator();
        while (it.next()) |slot| {
            if (!tokenEql(slot.key_ptr.token, token) or now_ms > slot.value_ptr.expires_at_ms) continue;
            if (best == null or slot.value_ptr.revision.compare(best.?.revision) == .gt) best = slot.value_ptr;
        }
        return best;
    }

    pub const LiveIdentity = struct {
        token: Token,
        entry: *const Entry,
    };

    /// Allocation-free exact lookup for a detached origin/nick projection.
    /// Nick comparison is byte-exact; callers apply protocol casemapping before
    /// this boundary. Null means no live match and `error.Ambiguous` means that
    /// a token cannot be selected safely.
    pub fn uniqueLiveOriginNick(self: *const Store, origin_node: NodeId, nick: []const u8, now_ms: i64) error{Ambiguous}!?LiveIdentity {
        var match: ?LiveIdentity = null;
        var it = @constCast(&self.entries).iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node != origin_node or now_ms > slot.value_ptr.expires_at_ms) continue;
            // Full quarantine removes token entries; the embedded marker is the
            // allocation-failure fallback and must be checked directly here.
            if (slot.value_ptr.quarantine_until_ms != null) continue;
            if (!std.mem.eql(u8, slot.value_ptr.nick, nick)) continue;
            if (match != null) return error.Ambiguous;
            match = .{ .token = slot.key_ptr.token, .entry = slot.value_ptr };
        }
        return match;
    }

    /// Compatibility alias for the deterministic representative.
    pub fn get(self: *const Store, token: Token) ?*const Entry {
        return self.bestIdentity(token);
    }

    pub fn getOriginTombstone(self: *const Store, token: Token, origin_node: NodeId) ?Tombstone {
        var it = @constCast(&self.tombstones).iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) return slot.value_ptr.*;
        }
        return null;
    }

    /// Compatibility projection selecting the highest tombstone revision.
    pub fn getTombstone(self: *const Store, token: Token) ?Tombstone {
        var best: ?Tombstone = null;
        var it = @constCast(&self.tombstones).iterator();
        while (it.next()) |slot| {
            if (!tokenEql(slot.key_ptr.token, token)) continue;
            if (best == null or slot.value_ptr.revision.compare(best.?.revision) == .gt) best = slot.value_ptr.*;
        }
        return best;
    }

    pub fn entryCount(self: *const Store) usize {
        return self.entries.count();
    }

    pub fn routeCount(self: *const Store) usize {
        return self.routes.count();
    }

    pub fn tombstoneCount(self: *const Store) usize {
        return self.tombstones.count();
    }

    pub fn quarantineCount(self: *const Store) usize {
        return self.quarantines.count();
    }

    pub fn isQuarantined(self: *const Store, token: Token) bool {
        var quarantine_it = @constCast(&self.quarantines).keyIterator();
        while (quarantine_it.next()) |stored| {
            if (tokenEql(stored.*, token)) return true;
        }
        var entry_it = @constCast(&self.entries).iterator();
        while (entry_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null and tokenEql(slot.key_ptr.token, token)) return true;
        }
        var tombstone_it = @constCast(&self.tombstones).iterator();
        while (tombstone_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null and tokenEql(slot.key_ptr.token, token)) return true;
        }
        return false;
    }

    pub fn retainedCount(self: *const Store, now_ms: i64) usize {
        var count: usize = 0;
        var quarantine_it = @constCast(&self.quarantines).valueIterator();
        while (quarantine_it.next()) |quarantine| {
            if (now_ms <= quarantine.expires_at_ms) count += 2;
        }
        var entry_it = @constCast(&self.entries).valueIterator();
        while (entry_it.next()) |entry| {
            if (entry.quarantine_until_ms == null and now_ms <= entry.expires_at_ms) count += 1;
        }
        var tombstone_it = @constCast(&self.tombstones).valueIterator();
        while (tombstone_it.next()) |tombstone| {
            if (tombstone.quarantine_until_ms == null and now_ms <= tombstone.offer_expires_at_ms) count += 1;
        }
        return count;
    }

    /// Copy bounded borrowed views of every nonexpired current signed object.
    /// Ordering is unspecified; compare the result with `retainedCount` to
    /// detect truncation. Callers forward each `wire` byte-for-byte unchanged.
    pub fn retainedObjectsInto(self: *const Store, now_ms: i64, out: []RetainedObject) usize {
        return self.retainedObjectsRange(now_ms, 0, out);
    }

    /// Bounded pagination over the same unspecified but mutation-stable map
    /// iteration used by `retainedObjectsInto`. Callers must restart at zero if
    /// the Store mutates between pages.
    pub fn retainedObjectsRange(self: *const Store, now_ms: i64, skip: usize, out: []RetainedObject) usize {
        var count: usize = 0;
        var seen: usize = 0;
        var quarantine_it = @constCast(&self.quarantines).valueIterator();
        while (quarantine_it.next()) |quarantine| {
            if (now_ms > quarantine.expires_at_ms) continue;
            const wires = [_][]const u8{ quarantine.first_wire, quarantine.second_wire };
            for (wires) |wire| {
                if (seen < skip) {
                    seen += 1;
                    continue;
                }
                if (count == out.len) return count;
                out[count] = retainedObjectFromWire(wire);
                count += 1;
            }
        }
        var entry_it = @constCast(&self.entries).iterator();
        while (entry_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null or now_ms > slot.value_ptr.expires_at_ms) continue;
            if (seen < skip) {
                seen += 1;
                continue;
            }
            if (count == out.len) return count;
            out[count] = .{
                .kind = .offer,
                .token = slot.key_ptr.token,
                .origin_node = slot.key_ptr.origin_node,
                .revision = slot.value_ptr.revision,
                .expires_at_ms = slot.value_ptr.expires_at_ms,
                .wire = slot.value_ptr.wire,
            };
            count += 1;
        }
        var tombstone_it = @constCast(&self.tombstones).iterator();
        while (tombstone_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null or now_ms > slot.value_ptr.offer_expires_at_ms) continue;
            if (seen < skip) {
                seen += 1;
                continue;
            }
            if (count == out.len) return count;
            out[count] = .{
                .kind = .revoke,
                .token = slot.key_ptr.token,
                .origin_node = slot.key_ptr.origin_node,
                .revision = slot.value_ptr.revision,
                .expires_at_ms = slot.value_ptr.offer_expires_at_ms,
                .wire = slot.value_ptr.wire,
            };
            count += 1;
        }
        return count;
    }

    pub fn originCountForToken(self: *const Store, token: Token) usize {
        var count: usize = 0;
        var it = @constCast(&self.entries).keyIterator();
        while (it.next()) |key| {
            if (tokenEql(key.token, token)) count += 1;
        }
        return count;
    }

    /// Test for any or one exact anti-entropy parent of an authority origin.
    pub fn hasReplicaParent(self: *const Store, token: Token, origin_node: NodeId, parent_peer: ?NodeId) bool {
        if (self.isQuarantined(token)) return false;
        var it = @constCast(&self.routes).keyIterator();
        while (it.next()) |key| {
            if (!tokenEql(key.token, token) or key.destination != origin_node) continue;
            if (parent_peer == null or key.next_hop == parent_peer.?) return true;
        }
        return false;
    }

    /// Compatibility name. This reports provenance, never live reachability.
    pub fn hasOriginRoute(self: *const Store, token: Token, origin_node: NodeId, next_hop: ?NodeId) bool {
        return self.hasReplicaParent(token, origin_node, next_hop);
    }

    pub fn hasRoute(self: *const Store, token: Token, destination: NodeId, next_hop: NodeId) bool {
        return self.hasOriginRoute(token, destination, next_hop);
    }

    /// Allocation-free check for any OFFER provenance learned through one peer.
    /// ACKs never populate this table and callers must not infer reachability.
    pub fn hasReplicaParentVia(self: *const Store, token: Token, parent_peer: NodeId) bool {
        if (self.isQuarantined(token)) return false;
        var it = @constCast(&self.routes).keyIterator();
        while (it.next()) |key| {
            if (key.next_hop == parent_peer and tokenEql(key.token, token)) return true;
        }
        return false;
    }

    /// Compatibility name. This reports provenance, never live reachability.
    pub fn hasAuthorityRouteVia(self: *const Store, token: Token, next_hop: NodeId) bool {
        return self.hasReplicaParentVia(token, next_hop);
    }

    /// Copy matching routes into `out`. Returns the number copied; callers can
    /// compare with `routeCountForToken` to detect truncation.
    pub fn routesInto(self: *const Store, token: Token, out: []Route) usize {
        if (self.isQuarantined(token)) return 0;
        var n: usize = 0;
        var it = @constCast(&self.routes).iterator();
        while (it.next()) |slot| {
            if (!tokenEql(slot.key_ptr.token, token)) continue;
            if (n == out.len) break;
            out[n] = .{
                .token = slot.key_ptr.token,
                .destination = slot.key_ptr.destination,
                .next_hop = slot.key_ptr.next_hop,
                .revision = slot.value_ptr.revision,
                .last_seen_ms = slot.value_ptr.last_seen_ms,
            };
            n += 1;
        }
        return n;
    }

    pub fn routeCountForToken(self: *const Store, token: Token) usize {
        var n: usize = 0;
        var it = @constCast(&self.routes).keyIterator();
        while (it.next()) |key| {
            if (tokenEql(key.token, token)) n += 1;
        }
        return n;
    }

    pub fn routeCountForOrigin(self: *const Store, token: Token, origin_node: NodeId) usize {
        var n: usize = 0;
        var it = @constCast(&self.routes).iterator();
        while (it.next()) |slot| {
            if (slot.value_ptr.revision.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) n += 1;
        }
        return n;
    }

    /// Remove every provenance parent equal to `peer`. Allocation-free and safe
    /// under pressure; retained signed objects remain available for resync.
    pub fn removePeer(self: *Store, peer: NodeId) usize {
        var removed: usize = 0;
        while (true) {
            var victim: ?RouteKey = null;
            var it = self.routes.keyIterator();
            while (it.next()) |key| {
                if (key.next_hop == peer) {
                    victim = key.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.routes.remove(key)) removed += 1;
        }
        return removed;
    }

    /// Sweep expired signed state, stale/expired routes, and mature tombstones.
    /// Tombstones are retained until BOTH their configured TTL and the signed
    /// remove offer's expiry pass, preventing replay resurrection.
    pub fn sweep(self: *Store, now_ms: i64) SweepResult {
        var result = SweepResult{};
        while (true) {
            var victim: ?Token = null;
            var it = self.quarantines.iterator();
            while (it.next()) |slot| {
                if (now_ms > slot.value_ptr.expires_at_ms) {
                    victim = slot.key_ptr.*;
                    break;
                }
            }
            const token = victim orelse break;
            if (self.quarantines.fetchRemove(token)) |removed| {
                freeQuarantine(self.allocator, removed.value);
                result.quarantines += 1;
            }
        }

        while (true) {
            var victim: ?OriginKey = null;
            var it = self.entries.iterator();
            while (it.next()) |slot| {
                if (now_ms > slot.value_ptr.expires_at_ms) {
                    victim = slot.key_ptr.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.entries.fetchRemove(key)) |removed| {
                freeEntry(self.allocator, removed.value);
                result.entries += 1;
                result.routes += self.removeRoutesForOrigin(key.token, key.origin_node);
            }
        }

        while (true) {
            var victim: ?RouteKey = null;
            var it = self.routes.iterator();
            while (it.next()) |slot| {
                const age = nonNegativeAge(now_ms, slot.value_ptr.last_seen_ms);
                const current = self.getOrigin(slot.key_ptr.token, slot.value_ptr.revision.origin_node);
                const invalid_revision = if (current) |entry| !entry.revision.eql(slot.value_ptr.revision) else true;
                if (invalid_revision or age >= self.cfg.route_ttl_ms) {
                    victim = slot.key_ptr.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.routes.remove(key)) result.routes += 1;
        }

        while (true) {
            var victim: ?OriginKey = null;
            var it = self.tombstones.iterator();
            while (it.next()) |slot| {
                const age = nonNegativeAge(now_ms, slot.value_ptr.removed_at_ms);
                if (age >= self.cfg.tombstone_ttl_ms and now_ms > slot.value_ptr.offer_expires_at_ms) {
                    victim = slot.key_ptr.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.tombstones.fetchRemove(key)) |removed| {
                freeTombstone(self.allocator, removed.value);
                result.tombstones += 1;
            }
        }

        var entry_it = self.entries.valueIterator();
        while (entry_it.next()) |entry| {
            if (entry.quarantine_until_ms) |until_ms| {
                if (now_ms > until_ms) entry.quarantine_until_ms = null;
            }
        }
        var tombstone_it = self.tombstones.valueIterator();
        while (tombstone_it.next()) |tombstone| {
            if (tombstone.quarantine_until_ms) |until_ms| {
                if (now_ms > until_ms) tombstone.quarantine_until_ms = null;
            }
        }
        return result;
    }

    fn validateOfferForStore(self: *const Store, offer: Offer, now_ms: i64) ApplyError!void {
        validateOfferShape(offer) catch return error.InvalidOffer;
        if (offer.account.len > self.cfg.max_account_bytes or offer.nick.len > self.cfg.max_nick_bytes or offer.snapshot.len > self.cfg.max_snapshot_bytes) return error.InvalidOffer;
        try validateLifetime(offer.issued_at_ms, offer.expires_at_ms, now_ms, self.cfg.max_offer_lifetime_ms, self.cfg.max_future_skew_ms);
    }

    fn applyVerifiedOffer(self: *Store, signed: SignedOffer, digest: Digest, via_peer: NodeId, now_ms: i64) ApplyError!ApplyResult {
        const offer = signed.offer;
        if (self.hasFullQuarantine(offer.token)) return .{ .disposition = .quarantined, .current_revision = offer.revision };
        if (offer.operation == .upsert) {
            if (self.findIdentityConflict(offer.token, offer.account, now_ms)) |conflict| {
                if (conflict.wire) |wire| {
                    try self.installQuarantine(signed, wire, conflict.expires_at_ms, now_ms);
                } else {
                    self.markTokenDenied(offer.token, @min(conflict.expires_at_ms, offer.expires_at_ms));
                }
                return .{ .disposition = .quarantined, .current_revision = offer.revision };
            }
            if (self.hasDenyMarker(offer.token)) return .{ .disposition = .quarantined, .current_revision = offer.revision };
        } else if (self.hasDenyMarker(offer.token)) {
            return .{ .disposition = .quarantined, .current_revision = offer.revision };
        }

        const origin = offer.revision.origin_node;
        const entry = self.getOriginMutable(offer.token, origin);
        const tombstone = self.getOriginTombstoneMutable(offer.token, origin);
        std.debug.assert(entry == null or tombstone == null);

        const current_revision: ?Revision = if (entry) |value| value.revision else if (tombstone) |value| value.revision else null;
        if (current_revision) |current| {
            switch (offer.revision.compare(current)) {
                .lt => return .{ .disposition = .stale, .current_revision = current },
                .eq => {
                    const current_digest = if (entry) |value| value.digest else tombstone.?.digest;
                    if (!std.crypto.timing_safe.eql(Digest, current_digest, digest)) {
                        if (std.mem.order(u8, &digest, &current_digest) == .lt) {
                            switch (offer.operation) {
                                .upsert => try self.installUpsert(signed, digest, via_peer, now_ms),
                                .remove => try self.installTombstone(signed, digest, now_ms),
                            }
                            return .{ .disposition = .conflict_replaced, .current_revision = current };
                        }
                        return .{ .disposition = .conflict, .current_revision = current };
                    }
                    if (offer.operation == .upsert and entry != null) {
                        // The first ingress is pinned for this exact revision.
                        // A reflected duplicate from another peer must not form
                        // an alternate path back toward the first parent.
                        const same_ingress = if (entry.?.ingress_peer) |peer| peer == via_peer else via_peer == 0;
                        if (same_ingress) {
                            if (via_peer != 0) _ = try self.recordRoute(offer.token, offer.revision.origin_node, via_peer, offer.revision, now_ms);
                            entry.?.updated_at_ms = now_ms;
                        }
                    }
                    return .{ .disposition = .duplicate, .current_revision = current };
                },
                .gt => {},
            }
        }

        const disposition: ApplyDisposition = if (current_revision == null)
            if (offer.operation == .remove) .tombstoned else .inserted
        else
            .superseded;

        switch (offer.operation) {
            .upsert => try self.installUpsert(signed, digest, via_peer, now_ms),
            .remove => try self.installTombstone(signed, digest, now_ms),
        }
        return .{ .disposition = disposition, .current_revision = offer.revision };
    }

    fn installUpsert(self: *Store, signed: SignedOffer, digest: Digest, via_peer: NodeId, now_ms: i64) ApplyError!void {
        const offer = signed.offer;
        const key = OriginKey{ .token = offer.token, .origin_node = offer.revision.origin_node };
        const replacing_entry = self.getOriginMutable(offer.token, offer.revision.origin_node) != null;
        if (!replacing_entry and self.entries.count() >= self.cfg.max_entries) return error.EntryFull;

        const route_key = RouteKey{ .token = offer.token, .destination = offer.revision.origin_node, .next_hop = via_peer };
        const removable_routes = self.routeCountForOrigin(offer.token, offer.revision.origin_node);
        const wants_route = via_peer != 0;
        if (wants_route and self.routes.count() - removable_routes >= self.cfg.max_routes) return error.RouteFull;

        const wire = try ownSignedOffer(self.allocator, signed);
        errdefer self.allocator.free(wire);
        const owned = decodeOffer(wire) catch unreachable;

        if (!replacing_entry) try self.entries.ensureUnusedCapacity(self.allocator, 1);
        if (wants_route and removable_routes == 0) try self.routes.ensureUnusedCapacity(self.allocator, 1);

        if (self.getOriginMutable(offer.token, offer.revision.origin_node)) |old| {
            freeEntry(self.allocator, old.*);
            old.* = .{
                .wire = wire,
                .account = owned.offer.account,
                .nick = owned.offer.nick,
                .snapshot = owned.offer.snapshot,
                .revision = offer.revision,
                .issued_at_ms = offer.issued_at_ms,
                .expires_at_ms = offer.expires_at_ms,
                .updated_at_ms = now_ms,
                .digest = digest,
                .ingress_peer = if (via_peer == 0) null else via_peer,
                .quarantine_until_ms = null,
            };
        } else {
            self.entries.putAssumeCapacityNoClobber(key, .{
                .wire = wire,
                .account = owned.offer.account,
                .nick = owned.offer.nick,
                .snapshot = owned.offer.snapshot,
                .revision = offer.revision,
                .issued_at_ms = offer.issued_at_ms,
                .expires_at_ms = offer.expires_at_ms,
                .updated_at_ms = now_ms,
                .digest = digest,
                .ingress_peer = if (via_peer == 0) null else via_peer,
                .quarantine_until_ms = null,
            });
        }
        if (self.tombstones.fetchRemove(key)) |removed| freeTombstone(self.allocator, removed.value);
        _ = self.removeRoutesForOrigin(offer.token, offer.revision.origin_node);
        if (via_peer != 0) self.putRouteAssumeCapacity(route_key, offer.revision, now_ms);
    }

    fn installTombstone(self: *Store, signed: SignedOffer, digest: Digest, now_ms: i64) ApplyError!void {
        const offer = signed.offer;
        const key = OriginKey{ .token = offer.token, .origin_node = offer.revision.origin_node };
        const existing_tombstone = self.getOriginTombstoneMutable(offer.token, offer.revision.origin_node);
        const replacing = existing_tombstone != null;
        if (!replacing and self.tombstones.count() >= self.cfg.max_tombstones) return error.TombstoneFull;

        const wire = try ownSignedOffer(self.allocator, signed);
        errdefer self.allocator.free(wire);
        if (!replacing) try self.tombstones.ensureUnusedCapacity(self.allocator, 1);

        const identity_digest = if (existing_tombstone) |old|
            old.identity_digest orelse self.identityDigestForToken(offer.token)
        else if (self.getOriginMutable(offer.token, offer.revision.origin_node)) |entry|
            digestBytes(entry.account)
        else
            self.identityDigestForToken(offer.token);

        if (self.entries.fetchRemove(key)) |removed| freeEntry(self.allocator, removed.value);
        _ = self.removeRoutesForOrigin(offer.token, offer.revision.origin_node);
        const value = Tombstone{
            .wire = wire,
            .revision = offer.revision,
            .removed_at_ms = now_ms,
            .offer_expires_at_ms = offer.expires_at_ms,
            .digest = digest,
            .identity_digest = identity_digest,
            .quarantine_until_ms = null,
        };
        if (self.getOriginTombstoneMutable(offer.token, offer.revision.origin_node)) |old| {
            freeTombstone(self.allocator, old.*);
            old.* = value;
        } else {
            self.tombstones.putAssumeCapacityNoClobber(key, value);
        }
    }

    fn recordRoute(self: *Store, token: Token, destination: NodeId, next_hop: NodeId, revision: Revision, now_ms: i64) (error{RouteFull} || std.mem.Allocator.Error)!RouteDisposition {
        const current = self.getOrigin(token, revision.origin_node) orelse return .stale;
        if (!current.revision.eql(revision)) return .stale;
        const key = RouteKey{ .token = token, .destination = destination, .next_hop = next_hop };
        if (self.routes.getPtr(key)) |route| {
            if (revision.compare(route.revision) == .lt) return .stale;
            route.revision = revision;
            route.last_seen_ms = now_ms;
            return .refreshed;
        }
        if (self.routes.count() >= self.cfg.max_routes) return error.RouteFull;
        try self.routes.ensureUnusedCapacity(self.allocator, 1);
        self.putRouteAssumeCapacity(key, revision, now_ms);
        return .inserted;
    }

    fn putRouteAssumeCapacity(self: *Store, key: RouteKey, revision: Revision, now_ms: i64) void {
        if (self.routes.getPtr(key)) |route| {
            route.* = .{ .revision = revision, .last_seen_ms = now_ms };
        } else {
            self.routes.putAssumeCapacityNoClobber(key, .{ .revision = revision, .last_seen_ms = now_ms });
        }
    }

    fn removeRoutesForOrigin(self: *Store, token: Token, origin_node: NodeId) usize {
        var removed: usize = 0;
        while (true) {
            var victim: ?RouteKey = null;
            var it = self.routes.iterator();
            while (it.next()) |slot| {
                if (slot.value_ptr.revision.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) {
                    victim = slot.key_ptr.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.routes.remove(key)) removed += 1;
        }
        return removed;
    }

    fn getOriginMutable(self: *Store, token: Token, origin_node: NodeId) ?*Entry {
        var it = self.entries.iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) return slot.value_ptr;
        }
        return null;
    }

    fn getOriginTombstoneMutable(self: *Store, token: Token, origin_node: NodeId) ?*Tombstone {
        var it = self.tombstones.iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) return slot.value_ptr;
        }
        return null;
    }

    fn identityDigestForToken(self: *const Store, token: Token) ?Digest {
        var entry_it = @constCast(&self.entries).iterator();
        while (entry_it.next()) |slot| {
            if (tokenEql(slot.key_ptr.token, token)) return digestBytes(slot.value_ptr.account);
        }
        var tombstone_it = @constCast(&self.tombstones).iterator();
        while (tombstone_it.next()) |slot| {
            if (tokenEql(slot.key_ptr.token, token) and slot.value_ptr.identity_digest != null) return slot.value_ptr.identity_digest.?;
        }
        return null;
    }

    const IdentityConflictEvidence = struct {
        wire: ?[]const u8,
        expires_at_ms: i64,
    };

    fn findIdentityConflict(self: *const Store, token: Token, account: []const u8, now_ms: i64) ?IdentityConflictEvidence {
        const account_digest = digestBytes(account);
        var entry_it = @constCast(&self.entries).iterator();
        while (entry_it.next()) |slot| {
            if (!tokenEql(slot.key_ptr.token, token)) continue;
            if (now_ms > slot.value_ptr.expires_at_ms) continue;
            if (!std.mem.eql(u8, slot.value_ptr.account, account)) return .{
                .wire = slot.value_ptr.wire,
                .expires_at_ms = slot.value_ptr.expires_at_ms,
            };
        }
        var tombstone_it = @constCast(&self.tombstones).iterator();
        while (tombstone_it.next()) |slot| {
            if (!tokenEql(slot.key_ptr.token, token)) continue;
            if (now_ms > slot.value_ptr.offer_expires_at_ms) continue;
            const bound = slot.value_ptr.identity_digest orelse continue;
            if (!std.crypto.timing_safe.eql(Digest, bound, account_digest)) return .{
                // REVOKE v2 carries no account field, so a tombstone can deny
                // locally but cannot supply portable account-conflict evidence.
                .wire = null,
                .expires_at_ms = slot.value_ptr.offer_expires_at_ms,
            };
        }
        return null;
    }

    fn hasFullQuarantine(self: *const Store, token: Token) bool {
        var it = @constCast(&self.quarantines).keyIterator();
        while (it.next()) |stored| {
            if (tokenEql(stored.*, token)) return true;
        }
        return false;
    }

    fn hasDenyMarker(self: *const Store, token: Token) bool {
        var entry_it = @constCast(&self.entries).iterator();
        while (entry_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null and tokenEql(slot.key_ptr.token, token)) return true;
        }
        var tombstone_it = @constCast(&self.tombstones).iterator();
        while (tombstone_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null and tokenEql(slot.key_ptr.token, token)) return true;
        }
        return false;
    }

    fn installQuarantine(self: *Store, incoming: SignedOffer, existing_wire: []const u8, existing_expires_at_ms: i64, now_ms: i64) ApplyError!void {
        const until_ms = @min(existing_expires_at_ms, incoming.offer.expires_at_ms);
        if (self.quarantines.count() >= self.cfg.max_quarantines) {
            self.markTokenDenied(incoming.offer.token, until_ms);
            return error.QuarantineFull;
        }

        const existing_copy = self.allocator.dupe(u8, existing_wire) catch |err| {
            self.markTokenDenied(incoming.offer.token, until_ms);
            return err;
        };
        errdefer self.allocator.free(existing_copy);
        const incoming_copy = ownSignedOffer(self.allocator, incoming) catch |err| {
            self.markTokenDenied(incoming.offer.token, until_ms);
            return err;
        };
        errdefer self.allocator.free(incoming_copy);
        self.quarantines.ensureUnusedCapacity(self.allocator, 1) catch |err| {
            self.markTokenDenied(incoming.offer.token, until_ms);
            return err;
        };

        const existing_signed = decodeOffer(existing_copy) catch unreachable;
        const existing_digest = digestBytes(existing_signed.transcript);
        const incoming_digest = digestBytes(incoming.transcript);
        const existing_first = std.mem.order(u8, &existing_digest, &incoming_digest) == .lt;
        const quarantine = Quarantine{
            .first_wire = if (existing_first) existing_copy else incoming_copy,
            .second_wire = if (existing_first) incoming_copy else existing_copy,
            .expires_at_ms = until_ms,
            .detected_at_ms = now_ms,
        };
        self.removeStateForToken(incoming.offer.token);
        self.quarantines.putAssumeCapacityNoClobber(incoming.offer.token, quarantine);
    }

    fn markTokenDenied(self: *Store, token: Token, until_ms: i64) void {
        var entry_it = self.entries.iterator();
        while (entry_it.next()) |slot| {
            if (tokenEql(slot.key_ptr.token, token)) slot.value_ptr.quarantine_until_ms = until_ms;
        }
        var tombstone_it = self.tombstones.iterator();
        while (tombstone_it.next()) |slot| {
            if (tokenEql(slot.key_ptr.token, token)) slot.value_ptr.quarantine_until_ms = until_ms;
        }
        _ = self.removeRoutesForToken(token);
    }

    fn removeStateForToken(self: *Store, token: Token) void {
        while (true) {
            var victim: ?OriginKey = null;
            var it = self.entries.keyIterator();
            while (it.next()) |key| {
                if (tokenEql(key.token, token)) {
                    victim = key.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.entries.fetchRemove(key)) |removed| freeEntry(self.allocator, removed.value);
        }
        while (true) {
            var victim: ?OriginKey = null;
            var it = self.tombstones.keyIterator();
            while (it.next()) |key| {
                if (tokenEql(key.token, token)) {
                    victim = key.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.tombstones.fetchRemove(key)) |removed| freeTombstone(self.allocator, removed.value);
        }
        _ = self.removeRoutesForToken(token);
    }

    fn removeRoutesForToken(self: *Store, token: Token) usize {
        var removed: usize = 0;
        while (true) {
            var victim: ?RouteKey = null;
            var it = self.routes.keyIterator();
            while (it.next()) |key| {
                if (tokenEql(key.token, token)) {
                    victim = key.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.routes.remove(key)) removed += 1;
        }
        return removed;
    }
};

fn validateLifetime(issued_at_ms: i64, expires_at_ms: i64, now_ms: i64, max_lifetime_ms: u64, max_future_skew_ms: u64) error{ Expired, InvalidLifetime }!void {
    if (issued_at_ms < 0 or expires_at_ms < issued_at_ms) return error.InvalidLifetime;
    const lifetime: i128 = @as(i128, expires_at_ms) - @as(i128, issued_at_ms);
    if (lifetime > max_lifetime_ms) return error.InvalidLifetime;
    const future_delta: i128 = @as(i128, issued_at_ms) - @as(i128, now_ms);
    if (future_delta > max_future_skew_ms) return error.InvalidLifetime;
    if (now_ms > expires_at_ms) return error.Expired;
}

fn freeEntry(allocator: std.mem.Allocator, entry: Store.Entry) void {
    allocator.free(entry.wire);
}

fn freeTombstone(allocator: std.mem.Allocator, tombstone: Store.Tombstone) void {
    allocator.free(tombstone.wire);
}

fn freeQuarantine(allocator: std.mem.Allocator, quarantine: Store.Quarantine) void {
    allocator.free(quarantine.first_wire);
    allocator.free(quarantine.second_wire);
}

fn ownSignedOffer(allocator: std.mem.Allocator, signed: SignedOffer) std.mem.Allocator.Error![]u8 {
    const wire = try allocator.alloc(u8, signed.transcript.len + signature_wire_len);
    @memcpy(wire[0..signed.transcript.len], signed.transcript);
    @memcpy(wire[signed.transcript.len..][0..sign.public_key_len], &signed.signer);
    @memcpy(wire[signed.transcript.len + sign.public_key_len ..], &signed.signature);
    return wire;
}

fn retainedObjectFromWire(wire: []const u8) Store.RetainedObject {
    const signed = decodeOffer(wire) catch unreachable;
    return .{
        .kind = if (signed.offer.operation == .upsert) .offer else .revoke,
        .token = signed.offer.token,
        .origin_node = signed.offer.revision.origin_node,
        .revision = signed.offer.revision,
        .expires_at_ms = signed.offer.expires_at_ms,
        .wire = wire,
    };
}

fn tokenEql(a: Token, b: Token) bool {
    // A replica token is the reusable bearer credential. Even internal
    // equality checks must not reintroduce an early-exit timing oracle at an
    // apply/lookup boundary.
    return std.crypto.timing_safe.eql(Token, a, b);
}

fn offerEql(a: Offer, b: Offer) bool {
    return a.operation == b.operation and
        tokenEql(a.token, b.token) and
        a.revision.eql(b.revision) and
        a.issued_at_ms == b.issued_at_ms and
        a.expires_at_ms == b.expires_at_ms and
        std.mem.eql(u8, a.account, b.account) and
        std.mem.eql(u8, a.nick, b.nick) and
        std.mem.eql(u8, a.snapshot, b.snapshot);
}

fn ackEql(a: Ack, b: Ack) bool {
    return a.status == b.status and
        tokenEql(a.token, b.token) and
        a.offered_revision.eql(b.offered_revision) and
        a.observed_revision.eql(b.observed_revision) and
        a.ack_node == b.ack_node and
        a.issued_at_ms == b.issued_at_ms and
        a.expires_at_ms == b.expires_at_ms;
}

fn digestBytes(bytes: []const u8) Digest {
    var digest: Digest = undefined;
    std.crypto.hash.Blake3.hash(bytes, &digest, .{});
    return digest;
}

fn nonNegativeAge(now_ms: i64, then_ms: i64) u64 {
    if (now_ms <= then_ms) return 0;
    const age: i128 = @as(i128, now_ms) - @as(i128, then_ms);
    return @intCast(age);
}

const Writer = struct {
    bytes: []u8,
    pos: usize = 0,

    fn writeByte(self: *Writer, value: u8) void {
        self.bytes[self.pos] = value;
        self.pos += 1;
    }

    fn writeBytes(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.pos .. self.pos + value.len], value);
        self.pos += value.len;
    }

    fn writeU16(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.pos..][0..2], value, .big);
        self.pos += 2;
    }

    fn writeU32(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.pos..][0..4], value, .big);
        self.pos += 4;
    }

    fn writeU64(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .big);
        self.pos += 8;
    }

    fn writeI64(self: *Writer, value: i64) void {
        std.mem.writeInt(i64, self.bytes[self.pos..][0..8], value, .big);
        self.pos += 8;
    }

    fn writeRevision(self: *Writer, revision: Revision) void {
        self.writeU64(revision.epoch);
        self.writeU64(revision.sequence);
        self.writeU64(revision.origin_node);
    }
};

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(self: *Reader, len: usize) DecodeError![]const u8 {
        if (len > self.bytes.len -| self.pos) return error.Truncated;
        const result = self.bytes[self.pos .. self.pos + len];
        self.pos += len;
        return result;
    }

    fn readByte(self: *Reader) DecodeError!u8 {
        return (try self.take(1))[0];
    }

    fn readU16(self: *Reader) DecodeError!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .big);
    }

    fn readU32(self: *Reader) DecodeError!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .big);
    }

    fn readU64(self: *Reader) DecodeError!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .big);
    }

    fn readI64(self: *Reader) DecodeError!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .big);
    }

    fn readRevision(self: *Reader) DecodeError!Revision {
        return .{
            .epoch = try self.readU64(),
            .sequence = try self.readU64(),
            .origin_node = try self.readU64(),
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testKey(seed: u8) !sign.KeyPair {
    return sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(seed)));
}

fn revisionFor(kp: *const sign.KeyPair, epoch: u64, sequence: u64) Revision {
    return .{ .epoch = epoch, .sequence = sequence, .origin_node = signed_frame.originShortId(kp.public_key) };
}

fn testToken(byte: u8) Token {
    var result: Token = @splat(0);
    result[15] = byte;
    return result;
}

fn upsertOffer(kp: *const sign.KeyPair, tok: Token, epoch: u64, sequence: u64, snapshot: []const u8) Offer {
    return .{
        .operation = .upsert,
        .token = tok,
        .revision = revisionFor(kp, epoch, sequence),
        .issued_at_ms = 100,
        .expires_at_ms = 10_000,
        .account = "alice",
        .nick = "Alice",
        .snapshot = snapshot,
    };
}

fn removeOffer(kp: *const sign.KeyPair, tok: Token, epoch: u64, sequence: u64) Offer {
    return .{
        .operation = .remove,
        .token = tok,
        .revision = revisionFor(kp, epoch, sequence),
        .issued_at_ms = 100,
        .expires_at_ms = 10_000,
    };
}

fn signedOffer(allocator: std.mem.Allocator, offer: Offer, kp: *const sign.KeyPair) !struct { wire: []u8, decoded: SignedOffer } {
    const wire = try encodeOffer(allocator, offer, kp);
    return .{ .wire = wire, .decoded = try decodeOffer(wire) };
}

fn nextTestPermutation(values: []u8) bool {
    if (values.len < 2) return false;
    var pivot = values.len - 1;
    while (pivot > 0 and values[pivot - 1] >= values[pivot]) pivot -= 1;
    if (pivot == 0) return false;
    const left = pivot - 1;
    var successor = values.len - 1;
    while (values[successor] <= values[left]) successor -= 1;
    std.mem.swap(u8, &values[left], &values[successor]);
    var lo = pivot;
    var hi = values.len - 1;
    while (lo < hi) {
        std.mem.swap(u8, &values[lo], &values[hi]);
        lo += 1;
        hi -= 1;
    }
    return true;
}

test "session replica revision comparison is a deterministic total order" {
    const values = [_]Revision{
        .{ .epoch = 1, .sequence = 1, .origin_node = 1 },
        .{ .epoch = 1, .sequence = 1, .origin_node = 2 },
        .{ .epoch = 1, .sequence = 2, .origin_node = 1 },
        .{ .epoch = 2, .sequence = 0, .origin_node = 1 },
    };
    for (values, 0..) |left, i| {
        try testing.expectEqual(std.math.Order.eq, left.compare(left));
        for (values, 0..) |right, j| {
            const expected: std.math.Order = if (i < j) .lt else if (i > j) .gt else .eq;
            try testing.expectEqual(expected, left.compare(right));
        }
    }
    for (values, 0..) |a, i| for (values, 0..) |_, j| for (values, 0..) |c, k| {
        if (i < j and j < k) try testing.expect(a.compare(c) == .lt);
    };
}

test "session replica signed OFFER upsert round-trips and verifies" {
    var kp = try testKey(0x11);
    defer kp.deinit();
    const original = upsertOffer(&kp, testToken(1), 7, 9, "snapshot-v1");
    const wire = try encodeOffer(testing.allocator, original, &kp);
    defer testing.allocator.free(wire);
    const decoded = try decodeOffer(wire);
    try verifyOffer(decoded);
    try testing.expectEqual(OfferOperation.upsert, decoded.offer.operation);
    try testing.expectEqualStrings("alice", decoded.offer.account);
    try testing.expectEqualStrings("Alice", decoded.offer.nick);
    try testing.expectEqualStrings("snapshot-v1", decoded.offer.snapshot);
    try testing.expect(decoded.offer.revision.eql(original.revision));
    var forged_projection = decoded;
    forged_projection.offer.nick = "Mallory";
    try testing.expectError(error.TranscriptMismatch, verifyOffer(forged_projection));
}

test "session replica maximum OFFER fits transport exactly and boundary plus one rejects" {
    var kp = try testKey(0x10);
    defer kp.deinit();
    const account: [max_account_len]u8 = @splat('a');
    const nick: [max_nick_len]u8 = @splat('n');
    const snapshot = try testing.allocator.alloc(u8, max_snapshot_len + 1);
    defer testing.allocator.free(snapshot);
    @memset(snapshot, 's');
    const offer = Offer{
        .operation = .upsert,
        .token = testToken(41),
        .revision = revisionFor(&kp, 1, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 200,
        .account = &account,
        .nick = &nick,
        .snapshot = snapshot[0..max_snapshot_len],
    };
    const signed_wire = try encodeOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(signed_wire);
    try testing.expectEqual(session_replica_transport.max_signed_payload_len, signed_wire.len);
    const transport_buf = try testing.allocator.alloc(u8, session_replica_transport.header_len + signed_wire.len);
    defer testing.allocator.free(transport_buf);
    const transport_wire = try session_replica_transport.encode(.offer, signed_wire, transport_buf);
    const framed = try session_replica_transport.decode(.offer, transport_wire);
    try testing.expectEqualSlices(u8, signed_wire, framed.signed_payload);
    try verifyOffer(try decodeOffer(framed.signed_payload));

    var oversized = offer;
    oversized.snapshot = snapshot;
    try testing.expectError(error.TooLong, encodeOffer(testing.allocator, oversized, &kp));
}

test "session replica signed OFFER remove round-trips and canonical shape is enforced" {
    var kp = try testKey(0x12);
    defer kp.deinit();
    const wire = try encodeOffer(testing.allocator, removeOffer(&kp, testToken(2), 1, 2), &kp);
    defer testing.allocator.free(wire);
    const decoded = try decodeOffer(wire);
    try verifyOffer(decoded);
    try testing.expectEqual(OfferOperation.remove, decoded.offer.operation);
    try testing.expectEqual(@as(usize, 0), decoded.offer.snapshot.len);

    var invalid = removeOffer(&kp, testToken(2), 1, 3);
    invalid.account = "alice";
    try testing.expectError(error.InvalidOffer, encodeOffer(testing.allocator, invalid, &kp));
}

test "session replica OFFER rejects signer-origin mismatch tampering truncation and trailing bytes" {
    var kp = try testKey(0x21);
    defer kp.deinit();
    var other = try testKey(0x22);
    defer other.deinit();
    const original = upsertOffer(&kp, testToken(3), 1, 1, "state");
    try testing.expectError(error.OriginMismatch, encodeOffer(testing.allocator, original, &other));

    const wire = try encodeOffer(testing.allocator, original, &kp);
    defer testing.allocator.free(wire);
    var tampered = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(tampered);
    tampered[offer_fixed_len] ^= 1;
    try testing.expectError(error.BadSignature, verifyOffer(try decodeOffer(tampered)));
    try testing.expectError(error.Truncated, decodeOffer(wire[0 .. wire.len - 1]));
    const trailing = try std.mem.concat(testing.allocator, u8, &.{ wire, "x" });
    defer testing.allocator.free(trailing);
    try testing.expectError(error.TrailingBytes, decodeOffer(trailing));
    tampered[0] = 'X';
    try testing.expectError(error.BadMagic, decodeOffer(tampered));
}

test "session replica OFFER decode rejects invalid operation and oversized declared fields" {
    var kp = try testKey(0x23);
    defer kp.deinit();
    const wire = try encodeOffer(testing.allocator, upsertOffer(&kp, testToken(4), 1, 1, "state"), &kp);
    defer testing.allocator.free(wire);
    var changed = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(changed);
    changed[offer_magic.len] = 0xff;
    try testing.expectError(error.InvalidOffer, decodeOffer(changed));
    changed[offer_magic.len] = @intFromEnum(OfferOperation.upsert);
    const account_len_offset = offer_magic.len + 1 + @sizeOf(Token) + revision_wire_len + 8 + 8;
    std.mem.writeInt(u16, changed[account_len_offset..][0..2], @intCast(max_account_len + 1), .big);
    try testing.expectError(error.TooLong, decodeOffer(changed));
}

test "session replica signed ACK round-trips verifies and rejects tampering" {
    var offer_kp = try testKey(0x31);
    defer offer_kp.deinit();
    var ack_kp = try testKey(0x32);
    defer ack_kp.deinit();
    const rev = revisionFor(&offer_kp, 3, 4);
    const ack = Ack{
        .status = .accepted,
        .token = testToken(5),
        .offered_revision = rev,
        .observed_revision = rev,
        .ack_node = signed_frame.originShortId(ack_kp.public_key),
        .issued_at_ms = 200,
        .expires_at_ms = 500,
    };
    const wire = try encodeAck(testing.allocator, ack, &ack_kp);
    defer testing.allocator.free(wire);
    const decoded = try decodeAck(wire);
    try verifyAck(decoded);
    try testing.expectEqual(AckStatus.accepted, decoded.ack.status);
    try testing.expectEqual(ack.ack_node, decoded.ack.ack_node);
    var forged_projection = decoded;
    forged_projection.ack.status = .duplicate;
    try testing.expectError(error.TranscriptMismatch, verifyAck(forged_projection));

    var tampered = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(tampered);
    tampered[ack_magic.len] = @intFromEnum(AckStatus.stale);
    try testing.expectError(error.BadSignature, verifyAck(try decodeAck(tampered)));
    tampered[ack_magic.len] = 0xff;
    try testing.expectError(error.InvalidAck, decodeAck(tampered));
    try testing.expectError(error.Truncated, decodeAck(wire[0 .. wire.len - 1]));
}

test "session replica ACK signer must self-certify ack node and wire has no trailing tolerance" {
    var kp = try testKey(0x33);
    defer kp.deinit();
    var origin = try testKey(0x34);
    defer origin.deinit();
    const rev = revisionFor(&origin, 1, 1);
    var ack = Ack{
        .status = .duplicate,
        .token = testToken(6),
        .offered_revision = rev,
        .observed_revision = rev,
        .ack_node = 7,
        .issued_at_ms = 1,
        .expires_at_ms = 2,
    };
    try testing.expectError(error.OriginMismatch, encodeAck(testing.allocator, ack, &kp));
    ack.ack_node = signed_frame.originShortId(kp.public_key);
    ack.observed_revision.origin_node +%= 1;
    try testing.expectError(error.InvalidAck, encodeAck(testing.allocator, ack, &kp));
    ack.observed_revision = ack.offered_revision;
    const wire = try encodeAck(testing.allocator, ack, &kp);
    defer testing.allocator.free(wire);

    var cross_origin = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(cross_origin);
    const observed_origin_offset = ack_magic.len + 1 + @sizeOf(Token) + revision_wire_len + 16;
    std.mem.writeInt(u64, cross_origin[observed_origin_offset..][0..8], ack.offered_revision.origin_node +% 1, .big);
    try testing.expectError(error.InvalidAck, decodeAck(cross_origin));

    const trailing = try std.mem.concat(testing.allocator, u8, &.{ wire, "x" });
    defer testing.allocator.free(trailing);
    try testing.expectError(error.TrailingBytes, decodeAck(trailing));
}

test "session replica every single-byte OFFER and ACK corruption fails closed" {
    var origin = try testKey(0x35);
    defer origin.deinit();
    var receiver = try testKey(0x36);
    defer receiver.deinit();
    const tok = testToken(35);
    const offer_wire = try encodeOffer(testing.allocator, upsertOffer(&origin, tok, 1, 1, "corruption-target"), &origin);
    defer testing.allocator.free(offer_wire);
    var corrupted_offer = try testing.allocator.dupe(u8, offer_wire);
    defer testing.allocator.free(corrupted_offer);
    for (corrupted_offer, 0..) |_, index| {
        corrupted_offer[index] ^= 1;
        const decoded = decodeOffer(corrupted_offer) catch {
            corrupted_offer[index] ^= 1;
            continue;
        };
        verifyOffer(decoded) catch {
            corrupted_offer[index] ^= 1;
            continue;
        };
        corrupted_offer[index] ^= 1;
        return error.TestUnexpectedResult;
    }

    const revision = revisionFor(&origin, 1, 1);
    const ack_wire = try encodeAck(testing.allocator, .{
        .status = .accepted,
        .token = tok,
        .offered_revision = revision,
        .observed_revision = revision,
        .ack_node = signed_frame.originShortId(receiver.public_key),
        .issued_at_ms = 100,
        .expires_at_ms = 200,
    }, &receiver);
    defer testing.allocator.free(ack_wire);
    var corrupted_ack = try testing.allocator.dupe(u8, ack_wire);
    defer testing.allocator.free(corrupted_ack);
    for (corrupted_ack, 0..) |_, index| {
        corrupted_ack[index] ^= 1;
        const decoded = decodeAck(corrupted_ack) catch {
            corrupted_ack[index] ^= 1;
            continue;
        };
        verifyAck(decoded) catch {
            corrupted_ack[index] ^= 1;
            continue;
        };
        corrupted_ack[index] ^= 1;
        return error.TestUnexpectedResult;
    }
}

test "session replica store distinguishes duplicate conflict stale and supersede without mutation leaks" {
    var kp = try testKey(0x41);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(7);

    const first = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "v1"), &kp);
    defer testing.allocator.free(first.wire);
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOffer(first.decoded, 10, 150)).disposition);
    try testing.expectEqualStrings("v1", store.get(tok).?.snapshot);
    try testing.expect(store.hasRoute(tok, first.decoded.offer.revision.origin_node, 10));

    try testing.expectEqual(ApplyDisposition.duplicate, (try store.applySignedOffer(first.decoded, 11, 160)).disposition);
    try testing.expectEqual(@as(usize, 1), store.routeCount());
    try testing.expect(!store.hasRoute(tok, first.decoded.offer.revision.origin_node, 11));

    const conflict = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "evil-same-revision"), &kp);
    defer testing.allocator.free(conflict.wire);
    const conflict_result = try store.applySignedOffer(conflict.decoded, 12, 170);
    try testing.expect(conflict_result.disposition == .conflict or conflict_result.disposition == .conflict_replaced);
    const conflict_digest = digestBytes(conflict.decoded.transcript);
    const first_digest = digestBytes(first.decoded.transcript);
    const expected_snapshot: []const u8 = if (std.mem.order(u8, &conflict_digest, &first_digest) == .lt)
        "evil-same-revision"
    else
        "v1";
    try testing.expectEqualStrings(expected_snapshot, store.get(tok).?.snapshot);
    try testing.expectEqual(@as(usize, 1), store.routeCount());

    const stale = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 0, "old"), &kp);
    defer testing.allocator.free(stale.wire);
    try testing.expectEqual(ApplyDisposition.stale, (try store.applySignedOffer(stale.decoded, 13, 180)).disposition);
    try testing.expectEqualStrings(expected_snapshot, store.get(tok).?.snapshot);

    const newer = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 2, "v2"), &kp);
    defer testing.allocator.free(newer.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(newer.decoded, 14, 190)).disposition);
    try testing.expectEqualStrings("v2", store.get(tok).?.snapshot);
    try testing.expectEqual(@as(usize, 1), store.routeCountForToken(tok));
    try testing.expect(store.hasRoute(tok, newer.decoded.offer.revision.origin_node, 14));
}

test "session replica cross-node equal-clock origins coexist and best identity is deterministic" {
    var low = try testKey(0x42);
    defer low.deinit();
    var high = try testKey(0x43);
    defer high.deinit();
    if (signed_frame.originShortId(low.public_key) > signed_frame.originShortId(high.public_key)) std.mem.swap(sign.KeyPair, &low, &high);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(8);
    const a = try signedOffer(testing.allocator, upsertOffer(&low, tok, 9, 9, "low"), &low);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, upsertOffer(&high, tok, 9, 9, "high"), &high);
    defer testing.allocator.free(b.wire);
    _ = try store.applySignedOffer(a.decoded, 1, 200);
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOffer(b.decoded, 2, 201)).disposition);
    try testing.expectEqual(@as(usize, 2), store.originCountForToken(tok));
    try testing.expectEqualStrings("low", store.getOrigin(tok, a.decoded.offer.revision.origin_node).?.snapshot);
    try testing.expectEqualStrings("high", store.getOrigin(tok, b.decoded.offer.revision.origin_node).?.snapshot);
    try testing.expectEqualStrings("high", store.get(tok).?.snapshot);
    try testing.expectEqual(ApplyDisposition.duplicate, (try store.applySignedOffer(a.decoded, 1, 202)).disposition);
}

test "session replica A B C attachments preserve independent origins paths and removal" {
    var a_key = try testKey(0x45);
    defer a_key.deinit();
    var b_key = try testKey(0x46);
    defer b_key.deinit();
    var c_key = try testKey(0x47);
    defer c_key.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();

    const tok = testToken(23);
    const a_node = signed_frame.originShortId(a_key.public_key);
    const b_node = signed_frame.originShortId(b_key.public_key);
    const c_node = signed_frame.originShortId(c_key.public_key);
    const a = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 10, 1, "A-state"), &a_key);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, upsertOffer(&b_key, tok, 10, 2, "B-state"), &b_key);
    defer testing.allocator.free(b.wire);
    const c = try signedOffer(testing.allocator, upsertOffer(&c_key, tok, 10, 3, "C-state"), &c_key);
    defer testing.allocator.free(c.wire);

    // A reflected through C cannot replace or augment the first parent B.
    _ = try store.applySignedOffer(a.decoded, b_node, 200);
    _ = try store.applySignedOffer(a.decoded, c_node, 201);
    _ = try store.applySignedOffer(b.decoded, c_node, 202);
    _ = try store.applySignedOffer(c.decoded, b_node, 203);
    try testing.expectEqual(@as(usize, 3), store.originCountForToken(tok));
    try testing.expect(store.hasOriginRoute(tok, a_node, b_node));
    try testing.expect(!store.hasOriginRoute(tok, a_node, c_node));
    try testing.expect(store.hasOriginRoute(tok, b_node, c_node));
    try testing.expect(store.hasOriginRoute(tok, c_node, b_node));

    var routes: [8]Store.Route = undefined;
    try testing.expectEqual(@as(usize, 3), store.routesInto(tok, &routes));
    for (routes[0..3]) |route| {
        const origin = store.getOrigin(tok, route.revision.origin_node) orelse return error.TestUnexpectedResult;
        try testing.expect(origin.revision.eql(route.revision));
    }

    const b_new = try signedOffer(testing.allocator, upsertOffer(&b_key, tok, 10, 5, "B-state-2"), &b_key);
    defer testing.allocator.free(b_new.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(b_new.decoded, a_node, 203)).disposition);
    try testing.expect(!store.hasOriginRoute(tok, b_node, c_node));
    try testing.expect(store.hasOriginRoute(tok, b_node, a_node));
    try testing.expect(store.hasOriginRoute(tok, a_node, b_node));
    try testing.expect(!store.hasOriginRoute(tok, a_node, c_node));
    try testing.expect(store.hasOriginRoute(tok, c_node, b_node));

    const remove_c = try signedOffer(testing.allocator, removeOffer(&c_key, tok, 10, 4), &c_key);
    defer testing.allocator.free(remove_c.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(remove_c.decoded, b_node, 204)).disposition);
    try testing.expectEqual(@as(usize, 2), store.originCountForToken(tok));
    try testing.expect(store.getOrigin(tok, c_node) == null);
    try testing.expect(store.getOriginTombstone(tok, c_node) != null);
    try testing.expect(store.hasOriginRoute(tok, a_node, b_node));
    try testing.expect(!store.hasOriginRoute(tok, a_node, c_node));
    try testing.expect(store.hasOriginRoute(tok, b_node, a_node));
    try testing.expect(!store.hasOriginRoute(tok, c_node, null));
    try testing.expectEqualStrings("A-state", store.getOrigin(tok, a_node).?.snapshot);
    try testing.expectEqualStrings("B-state-2", store.getOrigin(tok, b_node).?.snapshot);
}

test "session replica retained canonical wire replays OFFER and REVOKE after origin loss" {
    var a_key = try testKey(0x4b);
    defer a_key.deinit();
    const tok = testToken(28);
    const a_node = signed_frame.originShortId(a_key.public_key);
    const offer = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 4, 1, "offline-A"), &a_key);
    defer testing.allocator.free(offer.wire);

    var at_b = Store.init(testing.allocator);
    defer at_b.deinit();
    _ = try at_b.applySignedOffer(offer.decoded, a_node, 200);
    try testing.expectEqual(@as(usize, 1), at_b.retainedCount(200));
    var retained: [1]Store.RetainedObject = undefined;
    try testing.expectEqual(@as(usize, 1), at_b.retainedObjectsInto(200, &retained));
    try testing.expectEqual(Store.RetainedKind.offer, retained[0].kind);
    try testing.expectEqualSlices(u8, offer.wire, retained[0].wire);
    try testing.expect(offer.wire.ptr != retained[0].wire.ptr);
    try testing.expectEqual(@as(usize, 1), at_b.removePeer(a_node));
    try testing.expect(!at_b.hasReplicaParent(tok, a_node, a_node));
    try testing.expectEqual(@as(usize, 1), at_b.retainedCount(200));

    // A is no longer available; newly connected C learns the exact signed fact
    // from B without B possessing A's signing key.
    var at_c = Store.init(testing.allocator);
    defer at_c.deinit();
    try testing.expectEqual(ApplyDisposition.inserted, (try at_c.applySignedOffer(try decodeOffer(retained[0].wire), 0xb0, 201)).disposition);
    try testing.expectEqualStrings("offline-A", at_c.getOrigin(tok, a_node).?.snapshot);
    // C records only that B supplied the cache object; this is not evidence
    // that B or A is presently reachable for live message relay.
    try testing.expect(at_c.hasReplicaParent(tok, a_node, 0xb0));

    const revoke = try signedOffer(testing.allocator, removeOffer(&a_key, tok, 4, 2), &a_key);
    defer testing.allocator.free(revoke.wire);
    _ = try at_b.applySignedOffer(revoke.decoded, 0xb0, 202);
    try testing.expectEqual(@as(usize, 1), at_b.retainedCount(202));
    try testing.expectEqual(@as(usize, 1), at_b.retainedObjectsInto(202, &retained));
    try testing.expectEqual(Store.RetainedKind.revoke, retained[0].kind);
    try testing.expectEqualSlices(u8, revoke.wire, retained[0].wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try at_c.applySignedOffer(try decodeOffer(retained[0].wire), 0xb0, 203)).disposition);
    try testing.expect(at_c.getOrigin(tok, a_node) == null);
    try testing.expect(at_c.getOriginTombstone(tok, a_node) != null);
    try testing.expectEqual(@as(usize, 0), at_b.retainedCount(10_001));
}

test "session replica retained enumeration is bounded across concurrent origins" {
    var a_key = try testKey(0x4c);
    defer a_key.deinit();
    var b_key = try testKey(0x4d);
    defer b_key.deinit();
    const tok = testToken(29);
    const a = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 1, 1, "A"), &a_key);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, upsertOffer(&b_key, tok, 1, 2, "B"), &b_key);
    defer testing.allocator.free(b.wire);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    _ = try store.applySignedOffer(a.decoded, 1, 200);
    _ = try store.applySignedOffer(b.decoded, 2, 201);
    try testing.expectEqual(@as(usize, 2), store.retainedCount(201));
    var one: [1]Store.RetainedObject = undefined;
    try testing.expectEqual(@as(usize, 1), store.retainedObjectsInto(201, &one));
    try verifyOffer(try decodeOffer(one[0].wire));
    var second: [1]Store.RetainedObject = undefined;
    try testing.expectEqual(@as(usize, 1), store.retainedObjectsRange(201, 1, &second));
    try verifyOffer(try decodeOffer(second[0].wire));
    try testing.expect(one[0].origin_node != second[0].origin_node);
}

test "session replica nick revisions evolve until account conflict quarantines the token" {
    var a_key = try testKey(0x48);
    defer a_key.deinit();
    var b_key = try testKey(0x49);
    defer b_key.deinit();
    var c_key = try testKey(0x4a);
    defer c_key.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();

    const tok = testToken(24);
    var a_offer = upsertOffer(&a_key, tok, 1, 1, "A-1");
    a_offer.nick = "Alice-A";
    const a = try signedOffer(testing.allocator, a_offer, &a_key);
    defer testing.allocator.free(a.wire);
    var b_offer = upsertOffer(&b_key, tok, 1, 2, "B-1");
    b_offer.nick = "Alice-B";
    const b = try signedOffer(testing.allocator, b_offer, &b_key);
    defer testing.allocator.free(b.wire);
    _ = try store.applySignedOffer(a.decoded, 11, 200);
    _ = try store.applySignedOffer(b.decoded, 12, 201);
    try testing.expectEqualStrings("Alice-B", store.bestIdentity(tok).?.nick);

    var a_new_offer = upsertOffer(&a_key, tok, 1, 3, "A-2");
    a_new_offer.nick = "Alice-A2";
    const a_new = try signedOffer(testing.allocator, a_new_offer, &a_key);
    defer testing.allocator.free(a_new.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(a_new.decoded, 13, 202)).disposition);
    try testing.expectEqualStrings("Alice-A2", store.bestIdentity(tok).?.nick);
    try testing.expectEqualStrings("Alice-B", store.getOrigin(tok, b.decoded.offer.revision.origin_node).?.nick);

    var incompatible = upsertOffer(&c_key, tok, 9, 9, "evil");
    incompatible.account = "mallory";
    const evil = try signedOffer(testing.allocator, incompatible, &c_key);
    defer testing.allocator.free(evil.wire);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOffer(evil.decoded, 14, 203)).disposition);
    try testing.expect(store.isQuarantined(tok));
    try testing.expectEqual(@as(usize, 0), store.originCountForToken(tok));
    try testing.expectEqual(@as(usize, 1), store.quarantineCount());
    try testing.expect(store.bestIdentity(tok) == null);
    try testing.expect(!store.hasOriginRoute(tok, evil.decoded.offer.revision.origin_node, null));

    const remove_a = try signedOffer(testing.allocator, removeOffer(&a_key, tok, 2, 1), &a_key);
    defer testing.allocator.free(remove_a.wire);
    const remove_b = try signedOffer(testing.allocator, removeOffer(&b_key, tok, 2, 1), &b_key);
    defer testing.allocator.free(remove_b.wire);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOffer(remove_a.decoded, 0, 204)).disposition);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOffer(remove_b.decoded, 0, 205)).disposition);
    try testing.expect(store.bestIdentity(tok) == null);
    try testing.expectEqual(@as(usize, 2), store.retainedCount(206));
    try testing.expectEqual(@as(usize, 0), store.sweep(10_000).quarantines);
    try testing.expectEqual(@as(usize, 1), store.sweep(10_001).quarantines);
    try testing.expect(!store.isQuarantined(tok));
}

test "session replica cross-origin account permutations converge on portable quarantine evidence" {
    var alice_key = try testKey(0x55);
    defer alice_key.deinit();
    var mallory_key = try testKey(0x56);
    defer mallory_key.deinit();
    const tok = testToken(36);
    const alice = try signedOffer(testing.allocator, upsertOffer(&alice_key, tok, 1, 1, "alice-state"), &alice_key);
    defer testing.allocator.free(alice.wire);
    var mallory_offer = upsertOffer(&mallory_key, tok, 9, 9, "mallory-state");
    mallory_offer.account = "mallory";
    const mallory = try signedOffer(testing.allocator, mallory_offer, &mallory_key);
    defer testing.allocator.free(mallory.wire);

    var alice_first = Store.init(testing.allocator);
    defer alice_first.deinit();
    var mallory_first = Store.init(testing.allocator);
    defer mallory_first.deinit();
    _ = try alice_first.applySignedOffer(alice.decoded, 91, 200);
    try testing.expectEqual(ApplyDisposition.quarantined, (try alice_first.applySignedOffer(mallory.decoded, 92, 201)).disposition);
    _ = try mallory_first.applySignedOffer(mallory.decoded, 92, 200);
    try testing.expectEqual(ApplyDisposition.quarantined, (try mallory_first.applySignedOffer(alice.decoded, 91, 201)).disposition);
    try testing.expect(alice_first.isQuarantined(tok));
    try testing.expect(mallory_first.isQuarantined(tok));
    try testing.expect(alice_first.bestIdentity(tok) == null);
    try testing.expect(mallory_first.bestIdentity(tok) == null);
    try testing.expectEqual(@as(usize, 0), alice_first.routeCountForToken(tok));
    try testing.expectEqual(@as(usize, 0), mallory_first.routeCountForToken(tok));

    var first_evidence: [2]Store.RetainedObject = undefined;
    var second_evidence: [2]Store.RetainedObject = undefined;
    try testing.expectEqual(@as(usize, 2), alice_first.retainedObjectsInto(201, &first_evidence));
    try testing.expectEqual(@as(usize, 2), mallory_first.retainedObjectsInto(201, &second_evidence));
    try testing.expectEqualSlices(u8, first_evidence[0].wire, second_evidence[0].wire);
    try testing.expectEqualSlices(u8, first_evidence[1].wire, second_evidence[1].wire);

    var replay = Store.init(testing.allocator);
    defer replay.deinit();
    _ = try replay.applySignedOffer(try decodeOffer(first_evidence[0].wire), 93, 202);
    try testing.expectEqual(ApplyDisposition.quarantined, (try replay.applySignedOffer(try decodeOffer(first_evidence[1].wire), 93, 203)).disposition);
    try testing.expect(replay.isQuarantined(tok));
    try testing.expect(replay.bestIdentity(tok) == null);

    var capped = Store.initWithConfig(testing.allocator, .{ .max_quarantines = 0 });
    defer capped.deinit();
    _ = try capped.applySignedOffer(alice.decoded, 91, 200);
    try testing.expectError(error.QuarantineFull, capped.applySignedOffer(mallory.decoded, 92, 201));
    try testing.expect(capped.isQuarantined(tok));
    try testing.expect(capped.bestIdentity(tok) == null);
    try testing.expectEqual(@as(usize, 0), capped.routeCountForToken(tok));
    try testing.expectEqual(@as(usize, 0), capped.quarantineCount());
}

test "session replica all lifecycle arrival permutations converge after a higher revision" {
    var kp = try testKey(0x4e);
    defer kp.deinit();
    const tok = testToken(31);
    const stale = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 0, "stale"), &kp);
    defer testing.allocator.free(stale.wire);
    const live = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "live"), &kp);
    defer testing.allocator.free(live.wire);
    const conflict = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "equivocation"), &kp);
    defer testing.allocator.free(conflict.wire);
    const removed = try signedOffer(testing.allocator, removeOffer(&kp, tok, 1, 2), &kp);
    defer testing.allocator.free(removed.wire);
    const resurrected = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 3, "resurrected"), &kp);
    defer testing.allocator.free(resurrected.wire);
    const Event = struct { signed: SignedOffer, via: NodeId };
    const events = [_]Event{
        .{ .signed = stale.decoded, .via = 10 },
        .{ .signed = live.decoded, .via = 11 },
        .{ .signed = live.decoded, .via = 12 },
        .{ .signed = conflict.decoded, .via = 13 },
        .{ .signed = removed.decoded, .via = 14 },
        .{ .signed = resurrected.decoded, .via = 15 },
    };
    var order = [_]u8{ 0, 1, 2, 3, 4, 5 };
    var permutations: usize = 0;
    while (true) {
        var store = Store.init(testing.allocator);
        defer store.deinit();
        for (order) |event_index| {
            const event = events[event_index];
            _ = try store.applySignedOffer(event.signed, event.via, 500);
        }
        const current = store.getOrigin(tok, resurrected.decoded.offer.revision.origin_node).?;
        try testing.expect(current.revision.eql(resurrected.decoded.offer.revision));
        try testing.expectEqualStrings("resurrected", current.snapshot);
        try testing.expectEqual(@as(?NodeId, 15), current.ingress_peer);
        try testing.expect(store.getOriginTombstone(tok, current.revision.origin_node) == null);
        try testing.expect(store.hasOriginRoute(tok, current.revision.origin_node, 15));
        try testing.expectEqual(@as(usize, 1), store.routeCountForOrigin(tok, current.revision.origin_node));
        var retained: [1]Store.RetainedObject = undefined;
        try testing.expectEqual(@as(usize, 1), store.retainedObjectsInto(500, &retained));
        try testing.expectEqualSlices(u8, resurrected.wire, retained[0].wire);
        permutations += 1;
        if (!nextTestPermutation(&order)) break;
    }
    try testing.expectEqual(@as(usize, 720), permutations);
}

test "session replica all A B C authority permutations converge independently" {
    var a_key = try testKey(0x4f);
    defer a_key.deinit();
    var b_key = try testKey(0x50);
    defer b_key.deinit();
    var c_key = try testKey(0x53);
    defer c_key.deinit();
    const tok = testToken(32);
    const a1 = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 2, 1, "A-1"), &a_key);
    defer testing.allocator.free(a1.wire);
    const a2 = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 2, 2, "A-2"), &a_key);
    defer testing.allocator.free(a2.wire);
    const b1 = try signedOffer(testing.allocator, upsertOffer(&b_key, tok, 2, 1, "B-1"), &b_key);
    defer testing.allocator.free(b1.wire);
    const b2 = try signedOffer(testing.allocator, upsertOffer(&b_key, tok, 2, 2, "B-2"), &b_key);
    defer testing.allocator.free(b2.wire);
    const c1 = try signedOffer(testing.allocator, upsertOffer(&c_key, tok, 2, 1, "C-1"), &c_key);
    defer testing.allocator.free(c1.wire);
    const c2 = try signedOffer(testing.allocator, removeOffer(&c_key, tok, 2, 2), &c_key);
    defer testing.allocator.free(c2.wire);
    const Event = struct { signed: SignedOffer, via: NodeId };
    const events = [_]Event{
        .{ .signed = a1.decoded, .via = 21 },
        .{ .signed = a2.decoded, .via = 22 },
        .{ .signed = b1.decoded, .via = 31 },
        .{ .signed = b2.decoded, .via = 32 },
        .{ .signed = c1.decoded, .via = 41 },
        .{ .signed = c2.decoded, .via = 42 },
    };
    var order = [_]u8{ 0, 1, 2, 3, 4, 5 };
    var permutations: usize = 0;
    while (true) {
        var store = Store.init(testing.allocator);
        defer store.deinit();
        for (order) |event_index| {
            const event = events[event_index];
            _ = try store.applySignedOffer(event.signed, event.via, 500);
        }
        try testing.expectEqual(@as(usize, 2), store.originCountForToken(tok));
        try testing.expectEqualStrings("A-2", store.getOrigin(tok, a2.decoded.offer.revision.origin_node).?.snapshot);
        try testing.expectEqualStrings("B-2", store.getOrigin(tok, b2.decoded.offer.revision.origin_node).?.snapshot);
        try testing.expect(store.getOrigin(tok, c2.decoded.offer.revision.origin_node) == null);
        try testing.expect(store.getOriginTombstone(tok, c2.decoded.offer.revision.origin_node) != null);
        try testing.expect(store.hasOriginRoute(tok, a2.decoded.offer.revision.origin_node, 22));
        try testing.expect(store.hasOriginRoute(tok, b2.decoded.offer.revision.origin_node, 32));
        try testing.expect(!store.hasOriginRoute(tok, c2.decoded.offer.revision.origin_node, null));
        try testing.expectEqual(@as(usize, 3), store.retainedCount(500));
        const expected_best = if (a2.decoded.offer.revision.compare(b2.decoded.offer.revision) == .gt)
            a2.decoded.offer.revision
        else
            b2.decoded.offer.revision;
        try testing.expect(store.bestIdentity(tok).?.revision.eql(expected_best));
        permutations += 1;
        if (!nextTestPermutation(&order)) break;
    }
    try testing.expectEqual(@as(usize, 720), permutations);
}

test "session replica remove creates a bounded tombstone blocks replay and yields to a newer upsert" {
    var kp = try testKey(0x51);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(9);
    const live = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "live"), &kp);
    defer testing.allocator.free(live.wire);
    const remove = try signedOffer(testing.allocator, removeOffer(&kp, tok, 1, 2), &kp);
    defer testing.allocator.free(remove.wire);
    _ = try store.applySignedOffer(live.decoded, 10, 200);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(remove.decoded, 10, 210)).disposition);
    try testing.expect(store.get(tok) == null);
    try testing.expect(store.getTombstone(tok) != null);
    try testing.expectEqual(@as(usize, 0), store.routeCountForToken(tok));
    try testing.expectEqual(ApplyDisposition.stale, (try store.applySignedOffer(live.decoded, 11, 220)).disposition);
    try testing.expectEqual(ApplyDisposition.duplicate, (try store.applySignedOffer(remove.decoded, 11, 230)).disposition);

    const resurrect = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 3, "new-live"), &kp);
    defer testing.allocator.free(resurrect.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(resurrect.decoded, 12, 240)).disposition);
    try testing.expect(store.getTombstone(tok) == null);
    try testing.expectEqualStrings("new-live", store.get(tok).?.snapshot);
}

test "session replica same revision remove versus upsert picks deterministic digest" {
    var kp = try testKey(0x52);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(10);
    const live = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 2, 2, "live"), &kp);
    defer testing.allocator.free(live.wire);
    const remove = try signedOffer(testing.allocator, removeOffer(&kp, tok, 2, 2), &kp);
    defer testing.allocator.free(remove.wire);
    _ = try store.applySignedOffer(live.decoded, 1, 200);
    const result = try store.applySignedOffer(remove.decoded, 1, 201);
    const remove_digest = digestBytes(remove.decoded.transcript);
    const live_digest = digestBytes(live.decoded.transcript);
    const remove_wins = std.mem.order(u8, &remove_digest, &live_digest) == .lt;
    try testing.expectEqual(if (remove_wins) ApplyDisposition.conflict_replaced else ApplyDisposition.conflict, result.disposition);
    if (remove_wins) {
        try testing.expect(store.get(tok) == null);
        try testing.expect(store.getTombstone(tok) != null);
    } else {
        try testing.expectEqualStrings("live", store.get(tok).?.snapshot);
    }
}

test "session replica equivocation permutations retain the same canonical winner" {
    var kp = try testKey(0x54);
    defer kp.deinit();
    const tok = testToken(33);
    const x = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 3, 3, "X"), &kp);
    defer testing.allocator.free(x.wire);
    const y = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 3, 3, "Y"), &kp);
    defer testing.allocator.free(y.wire);
    const x_digest = digestBytes(x.decoded.transcript);
    const y_digest = digestBytes(y.decoded.transcript);
    const winner = if (std.mem.order(u8, &x_digest, &y_digest) == .lt) x else y;

    var xy = Store.init(testing.allocator);
    defer xy.deinit();
    var yx = Store.init(testing.allocator);
    defer yx.deinit();
    _ = try xy.applySignedOffer(x.decoded, 71, 200);
    _ = try xy.applySignedOffer(y.decoded, 72, 201);
    _ = try yx.applySignedOffer(y.decoded, 72, 200);
    _ = try yx.applySignedOffer(x.decoded, 71, 201);
    try testing.expectEqualStrings(winner.decoded.offer.snapshot, xy.get(tok).?.snapshot);
    try testing.expectEqualStrings(winner.decoded.offer.snapshot, yx.get(tok).?.snapshot);
    var xy_retained: [1]Store.RetainedObject = undefined;
    var yx_retained: [1]Store.RetainedObject = undefined;
    _ = xy.retainedObjectsInto(201, &xy_retained);
    _ = yx.retainedObjectsInto(201, &yx_retained);
    try testing.expectEqualSlices(u8, winner.wire, xy_retained[0].wire);
    try testing.expectEqualSlices(u8, winner.wire, yx_retained[0].wire);

    const revoke = try signedOffer(testing.allocator, removeOffer(&kp, tok, 3, 3), &kp);
    defer testing.allocator.free(revoke.wire);
    const revoke_digest = digestBytes(revoke.decoded.transcript);
    const upsert_wins = std.mem.order(u8, &x_digest, &revoke_digest) == .lt;
    var upsert_remove = Store.init(testing.allocator);
    defer upsert_remove.deinit();
    var remove_upsert = Store.init(testing.allocator);
    defer remove_upsert.deinit();
    _ = try upsert_remove.applySignedOffer(x.decoded, 73, 200);
    _ = try upsert_remove.applySignedOffer(revoke.decoded, 73, 201);
    _ = try remove_upsert.applySignedOffer(revoke.decoded, 73, 200);
    _ = try remove_upsert.applySignedOffer(x.decoded, 73, 201);
    try testing.expectEqual(upsert_wins, upsert_remove.get(tok) != null);
    try testing.expectEqual(upsert_wins, remove_upsert.get(tok) != null);
    _ = upsert_remove.retainedObjectsInto(201, &xy_retained);
    _ = remove_upsert.retainedObjectsInto(201, &yx_retained);
    const mixed_winner_wire = if (upsert_wins) x.wire else revoke.wire;
    try testing.expectEqualSlices(u8, mixed_winner_wire, xy_retained[0].wire);
    try testing.expectEqualSlices(u8, mixed_winner_wire, yx_retained[0].wire);

    const higher = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 3, 4, "resolved"), &kp);
    defer testing.allocator.free(higher.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try upsert_remove.applySignedOffer(higher.decoded, 74, 202)).disposition);
    try testing.expectEqual(ApplyDisposition.superseded, (try remove_upsert.applySignedOffer(higher.decoded, 74, 202)).disposition);
    try testing.expectEqualStrings("resolved", upsert_remove.get(tok).?.snapshot);
    try testing.expectEqualStrings("resolved", remove_upsert.get(tok).?.snapshot);
}

test "session replica entry route and tombstone bounds fail closed" {
    var kp = try testKey(0x61);
    defer kp.deinit();
    var entries = Store.initWithConfig(testing.allocator, .{ .max_entries = 1, .max_routes = 4, .max_tombstones = 4 });
    defer entries.deinit();
    const a = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(11), 1, 1, "a"), &kp);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(12), 1, 1, "b"), &kp);
    defer testing.allocator.free(b.wire);
    _ = try entries.applySignedOffer(a.decoded, 1, 200);
    try testing.expectError(error.EntryFull, entries.applySignedOffer(b.decoded, 2, 200));
    try testing.expectEqual(@as(usize, 1), entries.entryCount());
    try testing.expect(entries.get(testToken(11)) != null);

    var routes = Store.initWithConfig(testing.allocator, .{ .max_entries = 2, .max_routes = 1, .max_tombstones = 2 });
    defer routes.deinit();
    _ = try routes.applySignedOffer(a.decoded, 1, 200);
    const updated_before_full = routes.get(testToken(11)).?.updated_at_ms;
    try testing.expectError(error.RouteFull, routes.applySignedOffer(b.decoded, 2, 201));
    try testing.expectEqual(@as(usize, 1), routes.routeCount());
    try testing.expectEqual(updated_before_full, routes.get(testToken(11)).?.updated_at_ms);
    try testing.expect(routes.get(testToken(12)) == null);

    var tombs = Store.initWithConfig(testing.allocator, .{ .max_entries = 2, .max_routes = 2, .max_tombstones = 1 });
    defer tombs.deinit();
    const r1 = try signedOffer(testing.allocator, removeOffer(&kp, testToken(13), 1, 1), &kp);
    defer testing.allocator.free(r1.wire);
    const r2 = try signedOffer(testing.allocator, removeOffer(&kp, testToken(14), 1, 1), &kp);
    defer testing.allocator.free(r2.wire);
    _ = try tombs.applySignedOffer(r1.decoded, 0, 200);
    try testing.expectError(error.TombstoneFull, tombs.applySignedOffer(r2.decoded, 0, 201));
    try testing.expectEqual(@as(usize, 1), tombs.tombstoneCount());

    var other_origin = try testKey(0x63);
    defer other_origin.deinit();
    var origins = Store.initWithConfig(testing.allocator, .{ .max_entries = 1, .max_routes = 4, .max_tombstones = 4 });
    defer origins.deinit();
    const same_token_other_origin = try signedOffer(testing.allocator, upsertOffer(&other_origin, testToken(11), 1, 1, "other"), &other_origin);
    defer testing.allocator.free(same_token_other_origin.wire);
    _ = try origins.applySignedOffer(a.decoded, 1, 200);
    try testing.expectError(error.EntryFull, origins.applySignedOffer(same_token_other_origin.decoded, 2, 201));
    try testing.expectEqual(@as(usize, 1), origins.originCountForToken(testToken(11)));
    try testing.expect(origins.getOrigin(testToken(11), a.decoded.offer.revision.origin_node) != null);
    try testing.expect(origins.getOrigin(testToken(11), same_token_other_origin.decoded.offer.revision.origin_node) == null);
}

test "session replica store rejects expired overlong and far-future offers without mutation" {
    var kp = try testKey(0x62);
    defer kp.deinit();
    var store = Store.initWithConfig(testing.allocator, .{ .max_offer_lifetime_ms = 100, .max_future_skew_ms = 100 });
    defer store.deinit();
    var expired_offer = upsertOffer(&kp, testToken(15), 1, 1, "x");
    expired_offer.issued_at_ms = 0;
    expired_offer.expires_at_ms = 10;
    const expired = try signedOffer(testing.allocator, expired_offer, &kp);
    defer testing.allocator.free(expired.wire);
    try testing.expectError(error.Expired, store.applySignedOffer(expired.decoded, 1, 11));
    var long_offer = upsertOffer(&kp, testToken(15), 1, 2, "x");
    long_offer.issued_at_ms = 0;
    long_offer.expires_at_ms = 101;
    const too_long = try signedOffer(testing.allocator, long_offer, &kp);
    defer testing.allocator.free(too_long.wire);
    try testing.expectError(error.InvalidLifetime, store.applySignedOffer(too_long.decoded, 1, 1));
    var extreme_offer = upsertOffer(&kp, testToken(15), 1, 3, "x");
    extreme_offer.issued_at_ms = 0;
    extreme_offer.expires_at_ms = std.math.maxInt(i64);
    const extreme = try signedOffer(testing.allocator, extreme_offer, &kp);
    defer testing.allocator.free(extreme.wire);
    try testing.expectError(error.InvalidLifetime, store.applySignedOffer(extreme.decoded, 1, 1));

    var future_offer = upsertOffer(&kp, testToken(15), 1, 4, "future");
    future_offer.issued_at_ms = 32_503_680_000_000;
    future_offer.expires_at_ms = future_offer.issued_at_ms + 100;
    const future = try signedOffer(testing.allocator, future_offer, &kp);
    defer testing.allocator.free(future.wire);
    try testing.expectError(error.InvalidLifetime, store.applySignedOffer(future.decoded, 1, 200));
    try testing.expectEqual(@as(usize, 0), store.entryCount());

    var boundary_offer = upsertOffer(&kp, testToken(15), 1, 5, "boundary");
    boundary_offer.issued_at_ms = 300;
    boundary_offer.expires_at_ms = 400;
    const boundary = try signedOffer(testing.allocator, boundary_offer, &kp);
    defer testing.allocator.free(boundary.wire);
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOffer(boundary.decoded, 0, 200)).disposition);
}

test "session replica signed ACK is authenticated receipt metadata and never a route" {
    var origin = try testKey(0x71);
    defer origin.deinit();
    var receiver = try testKey(0x72);
    defer receiver.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(16);
    const offer = try signedOffer(testing.allocator, upsertOffer(&origin, tok, 1, 1, "state"), &origin);
    defer testing.allocator.free(offer.wire);
    _ = try store.applySignedOffer(offer.decoded, 0, 200);
    const ack = Ack{
        .status = .accepted,
        .token = tok,
        .offered_revision = offer.decoded.offer.revision,
        .observed_revision = offer.decoded.offer.revision,
        .ack_node = signed_frame.originShortId(receiver.public_key),
        .issued_at_ms = 200,
        .expires_at_ms = 300,
    };
    const ack_wire = try encodeAck(testing.allocator, ack, &receiver);
    defer testing.allocator.free(ack_wire);
    try testing.expectEqual(AckDisposition.accepted, try store.applySignedAck(try decodeAck(ack_wire), 99, 210));
    try testing.expect(!store.hasOriginRoute(tok, offer.decoded.offer.revision.origin_node, 99));
    try testing.expectEqual(@as(usize, 0), store.routeCount());
    try testing.expectEqual(AckDisposition.accepted, try store.applySignedAck(try decodeAck(ack_wire), 99, 220));

    var stale_ack = ack;
    stale_ack.status = .stale;
    const stale_wire = try encodeAck(testing.allocator, stale_ack, &receiver);
    defer testing.allocator.free(stale_wire);
    try testing.expectEqual(AckDisposition.ignored, try store.applySignedAck(try decodeAck(stale_wire), 100, 220));
    try testing.expectEqual(@as(usize, 0), store.routeCount());
}

test "session replica ACK ignores route capacity and rejects expiry and revision mismatch" {
    var origin = try testKey(0x73);
    defer origin.deinit();
    var receiver = try testKey(0x74);
    defer receiver.deinit();
    var store = Store.initWithConfig(testing.allocator, .{ .max_routes = 0, .max_future_skew_ms = 100 });
    defer store.deinit();
    const tok = testToken(17);
    const offer = try signedOffer(testing.allocator, upsertOffer(&origin, tok, 1, 2, "state"), &origin);
    defer testing.allocator.free(offer.wire);
    _ = try store.applySignedOffer(offer.decoded, 0, 200);
    var ack = Ack{
        .status = .accepted,
        .token = tok,
        .offered_revision = offer.decoded.offer.revision,
        .observed_revision = offer.decoded.offer.revision,
        .ack_node = signed_frame.originShortId(receiver.public_key),
        .issued_at_ms = 200,
        .expires_at_ms = 300,
    };
    const wire = try encodeAck(testing.allocator, ack, &receiver);
    defer testing.allocator.free(wire);
    try testing.expectEqual(AckDisposition.accepted, try store.applySignedAck(try decodeAck(wire), 5, 210));
    try testing.expectEqual(@as(usize, 0), store.routeCount());
    try testing.expectError(error.Expired, store.applySignedAck(try decodeAck(wire), 5, 301));
    ack.observed_revision.sequence += 1;
    const mismatch = try encodeAck(testing.allocator, ack, &receiver);
    defer testing.allocator.free(mismatch);
    try testing.expectEqual(AckDisposition.stale, try store.applySignedAck(try decodeAck(mismatch), 5, 210));

    var future_ack = ack;
    future_ack.observed_revision = future_ack.offered_revision;
    future_ack.issued_at_ms = 32_503_680_000_000;
    future_ack.expires_at_ms = future_ack.issued_at_ms + 100;
    const future = try encodeAck(testing.allocator, future_ack, &receiver);
    defer testing.allocator.free(future);
    try testing.expectError(error.InvalidLifetime, store.applySignedAck(try decodeAck(future), 5, 210));

    var boundary_ack = ack;
    boundary_ack.observed_revision = boundary_ack.offered_revision;
    boundary_ack.issued_at_ms = 310;
    boundary_ack.expires_at_ms = 310;
    const boundary = try encodeAck(testing.allocator, boundary_ack, &receiver);
    defer testing.allocator.free(boundary);
    try testing.expectEqual(AckDisposition.accepted, try store.applySignedAck(try decodeAck(boundary), 5, 210));
}

test "session replica line and triangle reflections never create OFFER or ACK route loops" {
    var a_key = try testKey(0x75);
    defer a_key.deinit();
    var c_key = try testKey(0x76);
    defer c_key.deinit();
    const tok = testToken(27);
    const a_node = signed_frame.originShortId(a_key.public_key);
    const b_node: NodeId = 0xb0;
    const c_node = signed_frame.originShortId(c_key.public_key);
    const first = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 1, 1, "A-1"), &a_key);
    defer testing.allocator.free(first.wire);

    var at_b = Store.init(testing.allocator);
    defer at_b.deinit();
    var at_c = Store.init(testing.allocator);
    defer at_c.deinit();
    _ = try at_b.applySignedOffer(first.decoded, a_node, 200);
    _ = try at_c.applySignedOffer(first.decoded, b_node, 201);

    // C reflects through the triangle to B, and A reaches C directly later.
    // Both nodes keep their causally first parent for this exact revision.
    try testing.expectEqual(ApplyDisposition.duplicate, (try at_b.applySignedOffer(first.decoded, c_node, 202)).disposition);
    try testing.expectEqual(ApplyDisposition.duplicate, (try at_c.applySignedOffer(first.decoded, a_node, 203)).disposition);
    try testing.expect(at_b.hasOriginRoute(tok, a_node, a_node));
    try testing.expect(!at_b.hasOriginRoute(tok, a_node, c_node));
    try testing.expect(at_c.hasOriginRoute(tok, a_node, b_node));
    try testing.expect(!at_c.hasOriginRoute(tok, a_node, a_node));

    const ack = Ack{
        .status = .accepted,
        .token = tok,
        .offered_revision = first.decoded.offer.revision,
        .observed_revision = first.decoded.offer.revision,
        .ack_node = c_node,
        .issued_at_ms = 200,
        .expires_at_ms = 500,
    };
    const ack_wire = try encodeAck(testing.allocator, ack, &c_key);
    defer testing.allocator.free(ack_wire);
    try testing.expectEqual(AckDisposition.accepted, try at_b.applySignedAck(try decodeAck(ack_wire), c_node, 204));
    try testing.expectEqual(@as(usize, 1), at_b.routeCount());
    try testing.expect(!at_b.hasOriginRoute(tok, a_node, c_node));

    // Losing the selected parent cannot silently reparent an old signed fact.
    try testing.expectEqual(@as(usize, 1), at_c.removePeer(b_node));
    try testing.expectEqual(ApplyDisposition.duplicate, (try at_c.applySignedOffer(first.decoded, a_node, 205)).disposition);
    try testing.expectEqual(@as(usize, 0), at_c.routeCount());
    const newer = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 1, 2, "A-2"), &a_key);
    defer testing.allocator.free(newer.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try at_c.applySignedOffer(newer.decoded, a_node, 206)).disposition);
    try testing.expect(at_c.hasOriginRoute(tok, a_node, a_node));
}

test "session replica peer loss drops the pinned route and old revision cannot reparent" {
    var kp = try testKey(0x81);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(18);
    const offer = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "state"), &kp);
    defer testing.allocator.free(offer.wire);
    _ = try store.applySignedOffer(offer.decoded, 10, 200);
    _ = try store.applySignedOffer(offer.decoded, 11, 201);
    try testing.expectEqual(@as(usize, 1), store.routeCount());
    try testing.expectEqual(@as(usize, 1), store.removePeer(10));
    try testing.expect(!store.hasRoute(tok, offer.decoded.offer.revision.origin_node, 10));
    try testing.expect(!store.hasRoute(tok, offer.decoded.offer.revision.origin_node, 11));
    try testing.expectEqual(ApplyDisposition.duplicate, (try store.applySignedOffer(offer.decoded, 11, 202)).disposition);
    try testing.expectEqual(@as(usize, 0), store.routeCount());
    try testing.expectEqual(@as(usize, 0), store.removePeer(77));
}

test "session replica sweep expires entries routes and tombstones at their exact boundaries" {
    var kp = try testKey(0x82);
    defer kp.deinit();
    var store = Store.initWithConfig(testing.allocator, .{
        .route_ttl_ms = 50,
        .tombstone_ttl_ms = 100,
        .max_offer_lifetime_ms = 20_000,
    });
    defer store.deinit();

    var live_offer = upsertOffer(&kp, testToken(19), 1, 1, "live");
    live_offer.expires_at_ms = 250;
    const live = try signedOffer(testing.allocator, live_offer, &kp);
    defer testing.allocator.free(live.wire);
    _ = try store.applySignedOffer(live.decoded, 10, 200);
    const at_route_boundary = store.sweep(250);
    try testing.expectEqual(@as(usize, 0), at_route_boundary.entries);
    try testing.expectEqual(@as(usize, 1), at_route_boundary.routes);
    try testing.expect(store.get(testToken(19)) != null);
    const after_entry_expiry = store.sweep(251);
    try testing.expectEqual(@as(usize, 1), after_entry_expiry.entries);

    var removed_offer = removeOffer(&kp, testToken(20), 1, 2);
    removed_offer.expires_at_ms = 400;
    const removed = try signedOffer(testing.allocator, removed_offer, &kp);
    defer testing.allocator.free(removed.wire);
    _ = try store.applySignedOffer(removed.decoded, 0, 300);
    try testing.expectEqual(@as(usize, 0), store.sweep(400).tombstones);
    try testing.expectEqual(@as(usize, 1), store.tombstoneCount());
    try testing.expectEqual(@as(usize, 1), store.sweep(401).tombstones);
}

test "session replica sweep removes only the expired origin and its paths" {
    var a_key = try testKey(0x85);
    defer a_key.deinit();
    var b_key = try testKey(0x86);
    defer b_key.deinit();
    var store = Store.initWithConfig(testing.allocator, .{
        .route_ttl_ms = 10_000,
        .max_offer_lifetime_ms = 10_000,
    });
    defer store.deinit();
    const tok = testToken(25);
    var a_offer = upsertOffer(&a_key, tok, 1, 1, "A");
    a_offer.expires_at_ms = 250;
    var b_offer = upsertOffer(&b_key, tok, 1, 2, "B");
    b_offer.expires_at_ms = 500;
    const a = try signedOffer(testing.allocator, a_offer, &a_key);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, b_offer, &b_key);
    defer testing.allocator.free(b.wire);
    _ = try store.applySignedOffer(a.decoded, 41, 200);
    _ = try store.applySignedOffer(a.decoded, 42, 201);
    _ = try store.applySignedOffer(b.decoded, 43, 202);

    const swept = store.sweep(251);
    try testing.expectEqual(@as(usize, 1), swept.entries);
    try testing.expectEqual(@as(usize, 1), swept.routes);
    try testing.expect(store.getOrigin(tok, a.decoded.offer.revision.origin_node) == null);
    try testing.expect(!store.hasOriginRoute(tok, a.decoded.offer.revision.origin_node, null));
    try testing.expect(store.getOrigin(tok, b.decoded.offer.revision.origin_node) != null);
    try testing.expect(store.hasOriginRoute(tok, b.decoded.offer.revision.origin_node, 43));
    try testing.expectEqual(@as(usize, 1), store.routeCountForToken(tok));
}

test "session replica routesInto reports bounded route values" {
    var kp = try testKey(0x83);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(21);
    const offer = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 2, 3, "state"), &kp);
    defer testing.allocator.free(offer.wire);
    _ = try store.applySignedOffer(offer.decoded, 10, 200);
    _ = try store.applySignedOffer(offer.decoded, 11, 201);
    var one: [1]Store.Route = undefined;
    try testing.expectEqual(@as(usize, 1), store.routesInto(tok, &one));
    try testing.expect(one[0].revision.eql(offer.decoded.offer.revision));
    try testing.expectEqual(@as(usize, 1), store.routeCountForToken(tok));
}

test "session replica insertion is leak-clean at every allocation failure" {
    var kp = try testKey(0x84);
    defer kp.deinit();
    const offer = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(22), 4, 5, "state"), &kp);
    defer testing.allocator.free(offer.wire);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, signed: SignedOffer) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            const result = try store.applySignedOffer(signed, 10, 200);
            try testing.expectEqual(ApplyDisposition.inserted, result.disposition);
            try testing.expectEqualStrings("state", store.get(signed.offer.token).?.snapshot);
            try testing.expectEqual(@as(usize, 1), store.routeCount());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{offer.decoded});
}

test "session replica concurrent origin insertion is transactional at every allocation failure" {
    var a_key = try testKey(0x87);
    defer a_key.deinit();
    var b_key = try testKey(0x88);
    defer b_key.deinit();
    const tok = testToken(26);
    const a = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 1, 1, "A"), &a_key);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, upsertOffer(&b_key, tok, 1, 2, "B"), &b_key);
    defer testing.allocator.free(b.wire);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, first: SignedOffer, second: SignedOffer) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.applySignedOffer(first, 51, 200);
            _ = try store.applySignedOffer(second, 52, 201);
            try testing.expectEqual(@as(usize, 2), store.originCountForToken(first.offer.token));
            try testing.expect(store.getOrigin(first.offer.token, first.offer.revision.origin_node) != null);
            try testing.expect(store.getOrigin(second.offer.token, second.offer.revision.origin_node) != null);
            try testing.expectEqual(@as(usize, 2), store.routeCountForToken(first.offer.token));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ a.decoded, b.decoded });
}

test "session replica hot lookups cover max origins without allocation and filter expiry" {
    var a_key = try testKey(0x8b);
    defer a_key.deinit();
    var b_key = try testKey(0x8c);
    defer b_key.deinit();
    var c_key = try testKey(0x8d);
    defer c_key.deinit();
    var d_key = try testKey(0x8e);
    defer d_key.deinit();
    const tok = testToken(37);
    var a_offer = upsertOffer(&a_key, tok, 1, 1, "A");
    a_offer.expires_at_ms = 500;
    var b_offer = upsertOffer(&b_key, tok, 9, 9, "B");
    b_offer.expires_at_ms = 250;
    const a = try signedOffer(testing.allocator, a_offer, &a_key);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, b_offer, &b_key);
    defer testing.allocator.free(b.wire);
    const c = try signedOffer(testing.allocator, upsertOffer(&c_key, tok, 1, 2, "C"), &c_key);
    defer testing.allocator.free(c.wire);
    const d = try signedOffer(testing.allocator, upsertOffer(&d_key, tok, 1, 3, "D"), &d_key);
    defer testing.allocator.free(d.wire);
    var store = Store.initWithConfig(testing.allocator, .{ .max_entries = 3, .max_routes = 3 });
    defer store.deinit();
    _ = try store.applySignedOffer(a.decoded, 101, 200);
    _ = try store.applySignedOffer(b.decoded, 102, 200);
    _ = try store.applySignedOffer(c.decoded, 103, 200);
    try testing.expectError(error.EntryFull, store.applySignedOffer(d.decoded, 104, 200));
    try testing.expect(store.hasAuthorityRouteVia(tok, 101));
    try testing.expect(store.hasAuthorityRouteVia(tok, 102));
    try testing.expect(store.hasAuthorityRouteVia(tok, 103));
    try testing.expect(!store.hasAuthorityRouteVia(tok, 104));
    try testing.expectEqualStrings("B", store.bestIdentity(tok).?.snapshot);
    try testing.expectEqualStrings("C", store.bestLiveIdentity(tok, 300).?.snapshot);
}

test "session replica unique origin nick lookup is live ambiguity and quarantine safe" {
    var origin_key = try testKey(0x91);
    defer origin_key.deinit();
    var conflicting_key = try testKey(0x92);
    defer conflicting_key.deinit();
    const origin_node = signed_frame.originShortId(origin_key.public_key);
    const first_token = testToken(39);
    const second_token = testToken(40);
    var first_offer = upsertOffer(&origin_key, first_token, 1, 1, "first");
    first_offer.expires_at_ms = 500;
    const first = try signedOffer(testing.allocator, first_offer, &origin_key);
    defer testing.allocator.free(first.wire);
    var second_offer = upsertOffer(&origin_key, second_token, 1, 2, "second");
    second_offer.expires_at_ms = 250;
    const second = try signedOffer(testing.allocator, second_offer, &origin_key);
    defer testing.allocator.free(second.wire);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    _ = try store.applySignedOffer(first.decoded, 121, 200);
    _ = try store.applySignedOffer(second.decoded, 122, 200);
    try testing.expectError(error.Ambiguous, store.uniqueLiveOriginNick(origin_node, "Alice", 200));
    try testing.expect((try store.uniqueLiveOriginNick(origin_node, "alice", 300)) == null);
    const unique = (try store.uniqueLiveOriginNick(origin_node, "Alice", 300)).?;
    try testing.expect(tokenEql(first_token, unique.token));
    try testing.expectEqualStrings("first", unique.entry.snapshot);

    var conflicting_offer = upsertOffer(&conflicting_key, first_token, 9, 9, "conflict");
    conflicting_offer.account = "mallory";
    const conflicting = try signedOffer(testing.allocator, conflicting_offer, &conflicting_key);
    defer testing.allocator.free(conflicting.wire);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOffer(conflicting.decoded, 123, 301)).disposition);
    try testing.expect((try store.uniqueLiveOriginNick(origin_node, "Alice", 301)) == null);
}

test "session replica retained REVOKE replacement is transactional at every allocation failure" {
    var kp = try testKey(0x89);
    defer kp.deinit();
    const tok = testToken(30);
    const offer = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "live"), &kp);
    defer testing.allocator.free(offer.wire);
    const revoke = try signedOffer(testing.allocator, removeOffer(&kp, tok, 1, 2), &kp);
    defer testing.allocator.free(revoke.wire);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, live: SignedOffer, removed: SignedOffer) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.applySignedOffer(live, 61, 200);
            _ = try store.applySignedOffer(removed, 61, 201);
            try testing.expect(store.getOrigin(live.offer.token, live.offer.revision.origin_node) == null);
            try testing.expect(store.getOriginTombstone(live.offer.token, live.offer.revision.origin_node) != null);
            var retained: [1]Store.RetainedObject = undefined;
            try testing.expectEqual(@as(usize, 1), store.retainedObjectsInto(201, &retained));
            try testing.expectEqual(Store.RetainedKind.revoke, retained[0].kind);
            try verifyOffer(try decodeOffer(retained[0].wire));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ offer.decoded, revoke.decoded });
}

test "session replica deterministic equivocation replacement is transactional at every allocation failure" {
    var kp = try testKey(0x8a);
    defer kp.deinit();
    const tok = testToken(34);
    const x = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "X"), &kp);
    defer testing.allocator.free(x.wire);
    const y = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "Y"), &kp);
    defer testing.allocator.free(y.wire);
    const x_digest = digestBytes(x.decoded.transcript);
    const y_digest = digestBytes(y.decoded.transcript);
    const winner = if (std.mem.order(u8, &x_digest, &y_digest) == .lt) x.decoded else y.decoded;
    const loser = if (std.mem.order(u8, &x_digest, &y_digest) == .lt) y.decoded else x.decoded;

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, losing: SignedOffer, winning: SignedOffer) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.applySignedOffer(losing, 81, 200);
            try testing.expectEqual(ApplyDisposition.conflict_replaced, (try store.applySignedOffer(winning, 82, 201)).disposition);
            try testing.expectEqualStrings(winning.offer.snapshot, store.get(winning.offer.token).?.snapshot);
            var retained: [1]Store.RetainedObject = undefined;
            _ = store.retainedObjectsInto(201, &retained);
            try testing.expectEqualSlices(u8, winning.transcript, (try decodeOffer(retained[0].wire)).transcript);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ loser, winner });
}

test "session replica account quarantine is fail-closed at every allocation failure" {
    var alice_key = try testKey(0x8f);
    defer alice_key.deinit();
    var mallory_key = try testKey(0x90);
    defer mallory_key.deinit();
    const tok = testToken(38);
    const alice = try signedOffer(testing.allocator, upsertOffer(&alice_key, tok, 1, 1, "Alice"), &alice_key);
    defer testing.allocator.free(alice.wire);
    var mallory_offer = upsertOffer(&mallory_key, tok, 1, 1, "Mallory");
    mallory_offer.account = "mallory";
    const mallory = try signedOffer(testing.allocator, mallory_offer, &mallory_key);
    defer testing.allocator.free(mallory.wire);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, first: SignedOffer, conflicting: SignedOffer) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.applySignedOffer(first, 111, 200);
            const result = store.applySignedOffer(conflicting, 112, 201) catch |err| {
                if (err == error.OutOfMemory) {
                    try testing.expect(store.isQuarantined(first.offer.token));
                    try testing.expect(store.bestIdentity(first.offer.token) == null);
                    try testing.expectEqual(@as(usize, 0), store.routeCountForToken(first.offer.token));
                }
                return err;
            };
            try testing.expectEqual(ApplyDisposition.quarantined, result.disposition);
            try testing.expect(store.isQuarantined(first.offer.token));
            try testing.expect(store.bestIdentity(first.offer.token) == null);
            try testing.expectEqual(@as(usize, 2), store.retainedCount(201));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ alice.decoded, mallory.decoded });
}
