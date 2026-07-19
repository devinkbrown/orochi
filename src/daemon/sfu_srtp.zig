// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SFU-side SRTP/SRTCP crypto hub for the DTLS-SRTP media leg (RFC 3711 / 5764).
//!
//! Increment 1 terminates DTLS per peer (Onyx Server is always the DTLS *server*) and
//! exposes each peer's exported SRTP keying material read-only. This hub turns
//! that material into a *live* SFU crypto context: it decrypts a DTLS-SRTP peer's
//! inbound media under that peer's own key and re-encrypts the recovered
//! plaintext, per recipient, under each recipient's DISTINCT key — so a
//! selective-forwarding unit can relay between peers that do not share a key.
//!
//! Plaintext RTP/RTCP is the SFU's common currency: group-key/SDES and native
//! legs already forward plaintext on this UDP plane, so the DTLS crypto engages
//! ONLY on DTLS legs. When no address is a DTLS-SRTP peer the forwarding path is
//! byte-identical to the pre-DTLS relay.
//!
//! Nonce discipline (the security core). SRTP's AES-CM keystream is
//! `f(key, ssrc, index)`; encrypting two DIFFERENT plaintexts under the same
//! (key, ssrc, index) is a two-time-pad that leaks media. To make that
//! impossible by construction:
//!   * Inbound decrypt state is keyed per **(source peer, ssrc)** with its own
//!     rollover counter + replay window — one peer can never poison another's
//!     ROC (a cross-peer availability attack) nor bypass replay.
//!   * Outbound re-encrypt state is keyed per **(recipient peer, ssrc)** and
//!     carries its OWN replay window: an index already encrypted to a recipient
//!     is NEVER encrypted again (the packet is dropped), so the outbound nonce
//!     cannot repeat regardless of inbound eviction, SSRC spoofing, or replay.
//!   * The reuse-critical outbound state is tied to the recipient's KEY lifetime:
//!     a peer context is evicted only when its DTLS session is gone or its key
//!     changed (a re-handshake ⇒ a fresh key, so resetting the window is safe).
//!     It is NEVER LRU-recycled while its key is live — an over-full table fails
//!     closed (drops the new stream) rather than resetting a live window.
//!   * SSRC ownership is bound to the first authenticated source; a DTLS peer
//!     that spoofs an SSRC owned by another source is rejected.
//!
//! Fail-closed everywhere: auth failure, replay, an unclaimable SSRC, a full
//! table, or 48-bit index exhaustion all DROP (return null) — never forward
//! unauthenticated or nonce-reusing bytes. The owning media pump is the SOLE
//! thread that touches the hub; there is no internal synchronisation.
const std = @import("std");
const srtp = @import("../proto/srtp.zig");
const srtcp = @import("../proto/srtcp.zig");
const dtls_srtp = @import("../proto/dtls_srtp.zig");
const dtls_server = @import("../proto/dtls12_server.zig");
const ice = @import("../proto/ice.zig");

pub const TransportAddress = ice.TransportAddress;
pub const ExportedKeys = dtls_srtp.ExportedKeys;

/// Per-recipient SRTP overhead the pump must reserve on egress buffers.
pub const rtp_overhead: usize = srtp.auth_tag_len;
/// Per-recipient SRTCP overhead (index word + auth tag) on egress buffers.
pub const rtcp_overhead: usize = srtcp.index_len + srtcp.auth_tag_len;

/// Max simultaneous DTLS-SRTP peers with live crypto contexts. Must be >= the
/// DTLS terminator's session cap so a peer with a LIVE key is never evicted —
/// evicting it would reset its reuse-critical outbound replay windows. An
/// over-full hub fails closed on new peers instead of recycling a live one.
pub const max_peers: usize = dtls_server.default_max_sessions;
comptime {
    std.debug.assert(max_peers >= dtls_server.default_max_sessions);
}

/// Inbound (source) SSRC streams tracked per peer. A source rarely publishes
/// more than a couple; excess is LRU-recycled (safe — inbound eviction cannot
/// cause outbound nonce reuse, which the per-recipient window guards).
pub const max_in_streams: usize = 8;
/// Outbound (recipient) SSRC streams tracked per peer — one per source SSRC the
/// recipient receives. Fail-closed when full (never recycled: recycling would
/// reset a reuse-critical replay window). Sized to the SFU fan-out cap
/// (`media_transport.max_forward` = 64); a recipient fed by more distinct SSRCs
/// than this (a very large multi-stream call) drops the excess streams to it —
/// an availability limit, never a nonce-safety compromise.
pub const max_out_streams: usize = 64;
/// SSRC → owning source bindings (integrity: reject cross-source SSRC spoofing).
pub const max_owners: usize = 256;

/// 64-index anti-replay window (RFC 3711 §3.3.2), over the 48-bit SRTP index.
const replay_window: u64 = 64;

/// Per-stream rollover-counter + anti-replay state (RFC 3711 §3.3.1 / App. A).
/// Used for BOTH an inbound source stream (guards decrypt replay) and an
/// outbound recipient stream (guards against re-encrypting a repeated index).
const StreamCtx = struct {
    ssrc: u32 = 0,
    active: bool = false,
    last_use: u64 = 0,
    roc: u32 = 0,
    s_l: u16 = 0,
    seen: bool = false,
    replay_top: u64 = 0,
    replay_bits: u64 = 0,

    fn reset(self: *StreamCtx, ssrc: u32, now: u64) void {
        self.* = .{ .ssrc = ssrc, .active = true, .last_use = now };
    }
};

const GuessedIndex = struct { index: u64, roc: u32 };

/// Per-peer crypto context. Inbound = client-write keys (decrypt packets FROM
/// this peer, the DTLS client); outbound = server-write keys (encrypt packets TO
/// this peer). Only evicted on session-gone / key-change, never LRU-recycled.
const PeerCtx = struct {
    addr: TransportAddress = .{},
    active: bool = false,
    last_use: u64 = 0,
    /// Exported keying material, retained to detect a re-handshake (key change).
    material: ExportedKeys = std.mem.zeroes(ExportedKeys),
    inbound: srtp.SessionKeys = std.mem.zeroes(srtp.SessionKeys),
    outbound: srtp.SessionKeys = std.mem.zeroes(srtp.SessionKeys),
    /// Monotonic SRTCP egress index (per recipient). Strictly increasing, never
    /// reset for a live key ⇒ the (ssrc, index) SRTCP nonce never repeats.
    /// u32 so 31-bit exhaustion fails closed rather than wrapping into reuse.
    srtcp_out_index: u32 = 0,
    in_streams: [max_in_streams]StreamCtx = @splat(.{}),
    out_streams: [max_out_streams]StreamCtx = @splat(.{}),

    fn wipe(self: *PeerCtx) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.material));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.inbound));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.outbound));
        self.* = .{};
    }
};

/// SSRC → owning source address (first authenticated writer wins).
const OwnerEntry = struct {
    ssrc: u32 = 0,
    addr: TransportAddress = .{},
    active: bool = false,
    last_use: u64 = 0,
};

pub const SfuSrtp = struct {
    allocator: std.mem.Allocator,
    /// Lazily allocated (on first established peer) so DTLS-off servers pay
    /// nothing; freed by `wipe`.
    peers: []PeerCtx = &.{},
    owners: [max_owners]OwnerEntry = @splat(.{}),
    clock: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) SfuSrtp {
        return .{ .allocator = allocator };
    }

    fn tick(self: *SfuSrtp) u64 {
        self.clock +%= 1;
        return self.clock;
    }

    fn ensurePeers(self: *SfuSrtp) bool {
        if (self.peers.len != 0) return true;
        const p = self.allocator.alloc(PeerCtx, max_peers) catch return false;
        for (p) |*e| e.* = .{};
        self.peers = p;
        return true;
    }

    // -- peer table --------------------------------------------------------

    fn findPeer(self: *SfuSrtp, addr: TransportAddress) ?*PeerCtx {
        for (self.peers) |*p| {
            if (p.active and p.addr.eql(addr)) return p;
        }
        return null;
    }

    fn materialEql(a: *const ExportedKeys, b: *const ExportedKeys) bool {
        return std.mem.eql(u8, std.mem.asBytes(a), std.mem.asBytes(b));
    }

    /// Install (idempotently) the live SRTP contexts for a DTLS-SRTP peer.
    /// Returns false when the table is full of live peers (fail closed — the
    /// caller drops that leg rather than recycling a live context). A changed
    /// key (re-handshake at the same address) reinstalls with a fresh key and
    /// fresh — safely reset — replay windows.
    pub fn noteEstablished(self: *SfuSrtp, addr: TransportAddress, exported: ExportedKeys) bool {
        if (!self.ensurePeers()) return false;
        if (self.findPeer(addr)) |p| {
            if (materialEql(&p.material, &exported)) {
                p.last_use = self.tick();
                return true;
            }
            self.releaseOwnedBy(addr); // old streams retired with the old key
            p.wipe();
            self.installPeer(p, addr, exported);
            return true;
        }
        // New peer: use only a FREE slot — never recycle a live one.
        for (self.peers) |*p| {
            if (!p.active) {
                self.installPeer(p, addr, exported);
                return true;
            }
        }
        return false; // full of live peers ⇒ fail closed
    }

    fn installPeer(self: *SfuSrtp, p: *PeerCtx, addr: TransportAddress, exported: ExportedKeys) void {
        p.addr = addr;
        p.material = exported;
        p.inbound = srtp.deriveSessionKeys(exported.clientMaster(), exported.clientSalt());
        p.outbound = srtp.deriveSessionKeys(exported.serverMaster(), exported.serverSalt());
        p.srtcp_out_index = 0;
        for (&p.in_streams) |*s| s.* = .{};
        for (&p.out_streams) |*s| s.* = .{};
        p.active = true;
        p.last_use = self.tick();
    }

    /// Whether a live crypto context exists for `addr`.
    pub fn peerActive(self: *SfuSrtp, addr: TransportAddress) bool {
        return self.findPeer(addr) != null;
    }

    /// Drop a peer's crypto context (secure-zeroing its keys) and release its
    /// SSRC ownerships. Safe for an unknown address.
    pub fn evict(self: *SfuSrtp, addr: TransportAddress) void {
        self.releaseOwnedBy(addr);
        if (self.findPeer(addr)) |p| p.wipe();
    }

    // -- SSRC ownership ----------------------------------------------------

    /// Whether `ssrc` is currently owned by a source OTHER than `addr`.
    fn ssrcOwnedByOther(self: *SfuSrtp, ssrc: u32, addr: TransportAddress) bool {
        for (&self.owners) |*o| {
            if (o.active and o.ssrc == ssrc) return !o.addr.eql(addr);
        }
        return false;
    }

    /// Bind `ssrc` to `addr` (first authenticated writer wins; refreshes LRU).
    fn claimSsrc(self: *SfuSrtp, ssrc: u32, addr: TransportAddress) void {
        for (&self.owners) |*o| {
            if (o.active and o.ssrc == ssrc) {
                o.addr = addr;
                o.last_use = self.tick();
                return;
            }
        }
        var slot: *OwnerEntry = &self.owners[0];
        for (&self.owners) |*o| {
            if (!o.active) {
                slot = o;
                break;
            }
            if (o.last_use < slot.last_use) slot = o;
        }
        slot.* = .{ .ssrc = ssrc, .addr = addr, .active = true, .last_use = self.tick() };
    }

    fn releaseOwnedBy(self: *SfuSrtp, addr: TransportAddress) void {
        for (&self.owners) |*o| {
            if (o.active and o.addr.eql(addr)) o.* = .{};
        }
    }

    // -- per-peer stream slots ---------------------------------------------

    /// Inbound source stream for `ssrc` (LRU-recycled when full — safe).
    fn inStream(self: *SfuSrtp, p: *PeerCtx, ssrc: u32) *StreamCtx {
        const now = self.tick();
        for (&p.in_streams) |*s| {
            if (s.active and s.ssrc == ssrc) {
                s.last_use = now;
                return s;
            }
        }
        var lru: *StreamCtx = &p.in_streams[0];
        for (&p.in_streams) |*s| {
            if (!s.active) {
                lru = s;
                break;
            }
            if (s.last_use < lru.last_use) lru = s;
        }
        lru.reset(ssrc, now);
        return lru;
    }

    /// Outbound recipient stream for `ssrc`. Fail-closed when full: NEVER
    /// recycles a live stream (that would reset its reuse-critical window).
    fn outStream(self: *SfuSrtp, p: *PeerCtx, ssrc: u32) ?*StreamCtx {
        const now = self.tick();
        for (&p.out_streams) |*s| {
            if (s.active and s.ssrc == ssrc) {
                s.last_use = now;
                return s;
            }
        }
        for (&p.out_streams) |*s| {
            if (!s.active) {
                s.reset(ssrc, now);
                return s;
            }
        }
        return null; // full ⇒ fail closed
    }

    // -- SRTP packet index (RFC 3711 §3.3.1 / Appendix A) ------------------

    /// Estimate the 48-bit SRTP index for a received `seq` WITHOUT committing,
    /// so a packet that fails a later check cannot advance the ROC.
    fn guess(s: *const StreamCtx, seq: u16) GuessedIndex {
        if (!s.seen) return .{ .index = seq, .roc = 0 };
        const s_l: i64 = s.s_l;
        const sq: i64 = seq;
        var v: i64 = s.roc;
        if (s.s_l < 0x8000) {
            if (sq - s_l > 0x8000) v = @as(i64, s.roc) - 1;
        } else {
            if (s_l - sq > 0x8000) v = @as(i64, s.roc) + 1;
        }
        if (v < 0) v = 0; // pre-start reorder guard (ROC 0 has no predecessor)
        const roc: u32 = @intCast(v & 0xFFFF_FFFF);
        return .{ .index = (@as(u64, roc) << 16) | seq, .roc = roc };
    }

    /// Advance ROC / highest-sequence after an ACCEPTED (authenticated or
    /// successfully-encrypted) packet.
    fn commit(s: *StreamCtx, g: GuessedIndex, seq: u16) void {
        if (!s.seen) {
            s.seen = true;
            s.roc = g.roc;
            s.s_l = seq;
        } else if (g.roc == s.roc) {
            if (seq > s.s_l) s.s_l = seq;
        } else if (g.roc == s.roc +% 1) {
            s.roc = g.roc;
            s.s_l = seq;
        }
        markSeen(s, g.index);
    }

    fn isSeen(s: *const StreamCtx, index: u64) bool {
        if (!s.seen) return false;
        if (index > s.replay_top) return false;
        const diff = s.replay_top - index;
        if (diff >= replay_window) return true; // outside the window ⇒ too old
        return (s.replay_bits >> @intCast(diff)) & 1 == 1;
    }

    fn markSeen(s: *StreamCtx, index: u64) void {
        if (index > s.replay_top) {
            const shift = index - s.replay_top;
            s.replay_bits = if (shift >= 64) 0 else s.replay_bits << @intCast(shift);
            s.replay_bits |= 1; // bit 0 tracks the new top
            s.replay_top = index;
        } else {
            const diff = s.replay_top - index;
            if (diff < 64) s.replay_bits |= (@as(u64, 1) << @intCast(diff));
        }
    }

    // -- inbound (decrypt from a DTLS-SRTP peer) ---------------------------

    /// Decrypt an inbound SRTP packet from DTLS-SRTP peer `addr` into `out`.
    /// Null (⇒ DROP) if the peer is unknown, the SSRC is owned by another
    /// source, the packet is replayed, or the auth tag fails. ROC/replay and
    /// SSRC ownership advance ONLY after successful authentication.
    ///
    /// The SSRC and sequence are read from the packet's OWN (cleartext) RTP
    /// header — the SAME bytes `srtp.unprotect` builds the AES-CM nonce from — so
    /// the replay-window key and the decryption nonce can never diverge.
    pub fn unprotectRtp(self: *SfuSrtp, addr: TransportAddress, packet: []const u8, out: []u8) ?[]const u8 {
        if (packet.len < srtp.rtp_header_len) return null;
        const ssrc = std.mem.readInt(u32, packet[8..12], .big);
        const seq = std.mem.readInt(u16, packet[2..4], .big);
        const p = self.findPeer(addr) orelse return null;
        if (self.ssrcOwnedByOther(ssrc, addr)) return null; // reject SSRC spoofing
        const s = self.inStream(p, ssrc);
        const g = guess(s, seq);
        if (isSeen(s, g.index)) return null; // replay
        const plain = srtp.unprotect(p.inbound, g.roc, packet, out) catch return null;
        self.claimSsrc(ssrc, addr);
        commit(s, g, seq);
        p.last_use = self.tick();
        return plain;
    }

    /// Decrypt an inbound SRTCP packet from DTLS-SRTP peer `addr` into `out`
    /// (the SRTCP index rides in the packet). Null ⇒ unknown peer or auth
    /// failure (⇒ DROP).
    pub fn unprotectRtcp(self: *SfuSrtp, addr: TransportAddress, packet: []const u8, out: []u8) ?[]const u8 {
        const p = self.findPeer(addr) orelse return null;
        const plain = srtcp.unprotect(p.inbound, packet, out) catch return null;
        p.last_use = self.tick();
        return plain;
    }

    // -- outbound (re-encrypt to a DTLS-SRTP peer) -------------------------

    /// Re-encrypt plaintext RTP for DTLS-SRTP recipient `addr` under its own
    /// outbound key. The per-(recipient, ssrc) replay window guarantees the
    /// (ssrc, index) nonce is NEVER used twice for this recipient — a repeated
    /// index is refused (null). Null ⇒ unknown recipient, out-of-slots (fail
    /// closed), nonce already used, or a protect error.
    ///
    /// The SSRC and sequence are read from `plain`'s OWN RTP header — the SAME
    /// bytes `srtp.protect` builds the AES-CM nonce from — so the replay-window
    /// key and the encryption nonce can NEVER diverge. This is what keeps the
    /// retransmit (NACK) path safe: the caller cannot pass a mismatched SSRC that
    /// would advance a different window than the nonce actually uses.
    pub fn protectRtp(self: *SfuSrtp, addr: TransportAddress, plain: []const u8, out: []u8) ?[]const u8 {
        if (plain.len < srtp.rtp_header_len) return null;
        const ssrc = std.mem.readInt(u32, plain[8..12], .big);
        const seq = std.mem.readInt(u16, plain[2..4], .big);
        const p = self.findPeer(addr) orelse return null;
        const s = self.outStream(p, ssrc) orelse return null;
        const g = guess(s, seq);
        if (isSeen(s, g.index)) return null; // nonce already used ⇒ refuse (no two-time-pad)
        const wire = srtp.protect(p.outbound, g.roc, plain, out) catch return null;
        commit(s, g, seq);
        p.last_use = self.tick();
        return wire;
    }

    /// Re-encrypt plaintext RTCP for DTLS-SRTP recipient `addr` under its own
    /// outbound key with the next monotonic SRTCP index. Null ⇒ unknown
    /// recipient, 31-bit index exhaustion (fail closed — never a reused nonce),
    /// or a protect error.
    pub fn protectRtcp(self: *SfuSrtp, addr: TransportAddress, plain: []const u8, out: []u8) ?[]const u8 {
        const p = self.findPeer(addr) orelse return null;
        const idx = p.srtcp_out_index;
        if (idx > std.math.maxInt(u31)) return null; // exhausted
        const wire = srtcp.protect(p.outbound, @intCast(idx), plain, out) catch return null;
        p.srtcp_out_index = idx + 1;
        p.last_use = self.tick();
        return wire;
    }

    /// Snapshot the addresses of every live peer context into `out` (for the
    /// pump to reconcile against the terminator and evict departed peers).
    /// Returns how many were written.
    pub fn activePeerAddrs(self: *SfuSrtp, out: []TransportAddress) usize {
        var n: usize = 0;
        for (self.peers) |*p| {
            if (!p.active) continue;
            if (n >= out.len) break;
            out[n] = p.addr;
            n += 1;
        }
        return n;
    }

    /// Secure-zero every live key, free the peer table, and reset all state
    /// (call on teardown, with the pump stopped).
    pub fn wipe(self: *SfuSrtp) void {
        for (self.peers) |*p| {
            std.crypto.secureZero(u8, std.mem.asBytes(&p.material));
            std.crypto.secureZero(u8, std.mem.asBytes(&p.inbound));
            std.crypto.secureZero(u8, std.mem.asBytes(&p.outbound));
        }
        if (self.peers.len != 0) self.allocator.free(self.peers);
        self.peers = &.{};
        self.owners = @splat(.{});
        self.clock = 0;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn mkAddr(last: u8) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, last }, 5000 + @as(u16, last)) catch unreachable;
}

/// Synthetic per-peer exported keying material (as if from a distinct DTLS
/// handshake): client-write and server-write differ, and each peer differs.
fn mkKeys(seed: u8) ExportedKeys {
    var e: ExportedKeys = undefined;
    for (&e.client, 0..) |*b, i| b.* = @intCast((i *% 7 +% seed) & 0xff);
    for (&e.server, 0..) |*b, i| b.* = @intCast((i *% 13 +% seed +% 128) & 0xff);
    return e;
}

/// A minimal RTP packet: V2, PT96, given seq/ssrc, then `payload`.
fn rtpPacket(seq: u16, ssrc: u32, payload: []const u8, out: []u8) []const u8 {
    out[0] = 0x80;
    out[1] = 0x60;
    std.mem.writeInt(u16, out[2..4], seq, .big);
    std.mem.writeInt(u32, out[4..8], 0x0000_0064, .big); // timestamp
    std.mem.writeInt(u32, out[8..12], ssrc, .big);
    @memcpy(out[12..][0..payload.len], payload);
    return out[0 .. 12 + payload.len];
}

test "SFU forward: source decrypted, re-encrypted to two peers under distinct keys" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const kA = mkKeys(1);
    const kB = mkKeys(2);
    const kC = mkKeys(3);
    const aA = mkAddr(1);
    const aB = mkAddr(2);
    const aC = mkAddr(3);
    try testing.expect(hub.noteEstablished(aA, kA));
    try testing.expect(hub.noteEstablished(aB, kB));
    try testing.expect(hub.noteEstablished(aC, kC));

    const ssrc: u32 = 0xCAFE_BABE;
    const seq: u16 = 0x2a;
    var rtp_buf: [64]u8 = undefined;
    const rtp = rtpPacket(seq, ssrc, "voice-frame", &rtp_buf);

    // A (the DTLS client) protects its egress with the client-write context.
    const a_in = srtp.deriveSessionKeys(kA.clientMaster(), kA.clientSalt());
    var wire_buf: [128]u8 = undefined;
    const wireA = try srtp.protect(a_in, 0, rtp, &wire_buf);

    // Hub decrypts A's inbound, recovering the plaintext RTP verbatim.
    var plain_buf: [128]u8 = undefined;
    const canonical = hub.unprotectRtp(aA, wireA, &plain_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, rtp, canonical);

    // Re-encrypt to B and C under each recipient's OWN outbound key.
    var toB_buf: [128]u8 = undefined;
    var toC_buf: [128]u8 = undefined;
    const toB = hub.protectRtp(aB, canonical, &toB_buf) orelse return error.TestUnexpectedResult;
    const toC = hub.protectRtp(aC, canonical, &toC_buf) orelse return error.TestUnexpectedResult;
    try testing.expect(!std.mem.eql(u8, toB, toC));

    // B recovers the frame with B's server-write context; C with C's.
    const b_out = srtp.deriveSessionKeys(kB.serverMaster(), kB.serverSalt());
    const c_out = srtp.deriveSessionKeys(kC.serverMaster(), kC.serverSalt());
    var rec: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, rtp, try srtp.unprotect(b_out, 0, toB, &rec));
    try testing.expectEqualSlices(u8, rtp, try srtp.unprotect(c_out, 0, toC, &rec));

    // A's keys can open neither B's packet.
    const a_out = srtp.deriveSessionKeys(kA.serverMaster(), kA.serverSalt());
    try testing.expectError(error.AuthFailed, srtp.unprotect(a_in, 0, toB, &rec));
    try testing.expectError(error.AuthFailed, srtp.unprotect(a_out, 0, toB, &rec));
}

test "SFU bridge: group-key<->DTLS-SRTP both directions carry intelligible media" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const kD = mkKeys(9);
    const aD = mkAddr(4); // the DTLS-SRTP peer
    try testing.expect(hub.noteEstablished(aD, kD));

    // (1) group-key/plaintext source -> DTLS-SRTP recipient. No inbound context
    // is needed; the outbound stream tracks the ROC from the forwarded seq.
    const p_ssrc: u32 = 0x1111_2222;
    const p_seq: u16 = 100;
    var g_buf: [64]u8 = undefined;
    const g_rtp = rtpPacket(p_seq, p_ssrc, "from-group-key", &g_buf);
    var enc_buf: [128]u8 = undefined;
    const to_dtls = hub.protectRtp(aD, g_rtp, &enc_buf) orelse return error.TestUnexpectedResult;
    const d_out = srtp.deriveSessionKeys(kD.serverMaster(), kD.serverSalt());
    var rec: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, g_rtp, try srtp.unprotect(d_out, 0, to_dtls, &rec));

    // (2) DTLS-SRTP source -> group-key recipient (receives the plaintext).
    const d_ssrc: u32 = 0x3333_4444;
    const d_seq: u16 = 55;
    var d_buf: [64]u8 = undefined;
    const d_rtp = rtpPacket(d_seq, d_ssrc, "from-dtls-peer", &d_buf);
    const d_in = srtp.deriveSessionKeys(kD.clientMaster(), kD.clientSalt());
    var wire_buf: [128]u8 = undefined;
    const d_wire = try srtp.protect(d_in, 0, d_rtp, &wire_buf);
    var plain_buf: [128]u8 = undefined;
    const canonical = hub.unprotectRtp(aD, d_wire, &plain_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, d_rtp, canonical);
}

test "SFU SRTCP: inbound decrypt then per-recipient re-encrypt round-trips" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const kA = mkKeys(5);
    const kB = mkKeys(6);
    const aA = mkAddr(7);
    const aB = mkAddr(8);
    try testing.expect(hub.noteEstablished(aA, kA));
    try testing.expect(hub.noteEstablished(aB, kB));

    const rtcp = [_]u8{ 0x80, 0xC8, 0x00, 0x06, 0xCA, 0xFE, 0xBA, 0xBE } ++ "sr-report-body!!".*;
    const a_in = srtp.deriveSessionKeys(kA.clientMaster(), kA.clientSalt());
    var wire_buf: [128]u8 = undefined;
    const a_wire = try srtcp.protect(a_in, 7, &rtcp, &wire_buf);

    var plain_buf: [128]u8 = undefined;
    const canonical = hub.unprotectRtcp(aA, a_wire, &plain_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &rtcp, canonical);

    var enc_buf: [128]u8 = undefined;
    const to_b = hub.protectRtcp(aB, canonical, &enc_buf) orelse return error.TestUnexpectedResult;
    const b_out = srtp.deriveSessionKeys(kB.serverMaster(), kB.serverSalt());
    var rec: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, &rtcp, try srtcp.unprotect(b_out, to_b, &rec));

    // Monotonic SRTCP index: a second egress packet uses a fresh index word.
    var enc_buf2: [128]u8 = undefined;
    const to_b2 = hub.protectRtcp(aB, canonical, &enc_buf2) orelse return error.TestUnexpectedResult;
    try testing.expect(!std.mem.eql(u8, to_b, to_b2));
}

test "SFU fail-closed: tampered and replayed inbound packets are dropped" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const kA = mkKeys(4);
    const aA = mkAddr(9);
    try testing.expect(hub.noteEstablished(aA, kA));

    const ssrc: u32 = 0xDEAD_BEEF;
    const seq: u16 = 7;
    var rtp_buf: [64]u8 = undefined;
    const rtp = rtpPacket(seq, ssrc, "secret", &rtp_buf);
    const a_in = srtp.deriveSessionKeys(kA.clientMaster(), kA.clientSalt());
    var wire_buf: [128]u8 = undefined;
    const wireA = try srtp.protect(a_in, 0, rtp, &wire_buf);

    // Tampered ciphertext ⇒ auth failure ⇒ drop. The ROC must NOT move.
    var tampered: [128]u8 = undefined;
    @memcpy(tampered[0..wireA.len], wireA);
    tampered[12] ^= 0x01;
    var out: [128]u8 = undefined;
    try testing.expect(hub.unprotectRtp(aA, tampered[0..wireA.len], &out) == null);

    // The genuine packet still decrypts (forgery did not desync).
    try testing.expectEqualSlices(u8, rtp, hub.unprotectRtp(aA, wireA, &out) orelse return error.TestUnexpectedResult);

    // Replay of the same authenticated packet ⇒ dropped.
    var out2: [128]u8 = undefined;
    try testing.expect(hub.unprotectRtp(aA, wireA, &out2) == null);

    // A fresh higher sequence is still accepted.
    var next_buf: [64]u8 = undefined;
    const next = rtpPacket(seq + 1, ssrc, "secret", &next_buf);
    var nwire_buf: [128]u8 = undefined;
    const nwire = try srtp.protect(a_in, 0, next, &nwire_buf);
    try testing.expect(hub.unprotectRtp(aA, nwire, &out2) != null);
}

test "SFU nonce safety: colliding SSRC from a second source never reuses a recipient nonce" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const kV = mkKeys(11); // legitimate source of the SSRC
    const kW = mkKeys(12); // attacker, spoofs the same SSRC
    const kR = mkKeys(13); // recipient (the victim of any two-time-pad)
    const aV = mkAddr(21);
    const aW = mkAddr(22);
    const aR = mkAddr(23);
    try testing.expect(hub.noteEstablished(aV, kV));
    try testing.expect(hub.noteEstablished(aW, kW));
    try testing.expect(hub.noteEstablished(aR, kR));

    const ssrc: u32 = 0x5151_5151;
    const seq: u16 = 100;

    // V sends P1 at (ssrc, seq); it is forwarded (re-encrypted) to R.
    var v_buf: [64]u8 = undefined;
    const v_rtp = rtpPacket(seq, ssrc, "victim-P1", &v_buf);
    const v_in = srtp.deriveSessionKeys(kV.clientMaster(), kV.clientSalt());
    var v_wire_buf: [128]u8 = undefined;
    const v_wire = try srtp.protect(v_in, 0, v_rtp, &v_wire_buf);
    var v_plain: [128]u8 = undefined;
    const v_canon = hub.unprotectRtp(aV, v_wire, &v_plain) orelse return error.TestUnexpectedResult;
    var toR1_buf: [128]u8 = undefined;
    const toR1 = hub.protectRtp(aR, v_canon, &toR1_buf) orelse return error.TestUnexpectedResult;
    var toR1_copy: [128]u8 = undefined;
    @memcpy(toR1_copy[0..toR1.len], toR1);

    // W (authenticated) spoofs the SAME SSRC. It is REJECTED at ingress by the
    // ownership binding — V owns the SSRC.
    var w_buf: [64]u8 = undefined;
    const w_rtp = rtpPacket(seq, ssrc, "attack-P2", &w_buf);
    const w_in = srtp.deriveSessionKeys(kW.clientMaster(), kW.clientSalt());
    var w_wire_buf: [128]u8 = undefined;
    const w_wire = try srtp.protect(w_in, 0, w_rtp, &w_wire_buf);
    var w_plain: [128]u8 = undefined;
    try testing.expect(hub.unprotectRtp(aW, w_wire, &w_plain) == null);

    // Belt-and-suspenders: even if a different-plaintext frame reached the
    // outbound stage at the same (ssrc, seq), the per-recipient replay window
    // refuses to re-encrypt the already-used index (no two-time-pad).
    var attack_plain: [64]u8 = undefined;
    const attack_rtp = rtpPacket(seq, ssrc, "attack-P2", &attack_plain);
    var toR2_buf: [128]u8 = undefined;
    try testing.expect(hub.protectRtp(aR, attack_rtp, &toR2_buf) == null);

    // R still decrypts V's genuine P1 with R's server-write key.
    const r_out = srtp.deriveSessionKeys(kR.serverMaster(), kR.serverSalt());
    var r_rec: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, v_rtp, try srtp.unprotect(r_out, 0, toR1_copy[0..toR1.len], &r_rec));
}

test "SFU no cross-peer ROC poisoning: per-source inbound streams stay independent" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const kV = mkKeys(31);
    const kW = mkKeys(32);
    const aV = mkAddr(24);
    const aW = mkAddr(25);
    try testing.expect(hub.noteEstablished(aV, kV));
    try testing.expect(hub.noteEstablished(aW, kW));

    // W drives ITS OWN (W, ssrc) stream to a high sequence.
    const w_ssrc: u32 = 0x9999_0000;
    const w_in = srtp.deriveSessionKeys(kW.clientMaster(), kW.clientSalt());
    var w_buf: [64]u8 = undefined;
    const w_rtp = rtpPacket(60000, w_ssrc, "w-data", &w_buf);
    var w_wire_buf: [128]u8 = undefined;
    const w_wire = try srtp.protect(w_in, 0, w_rtp, &w_wire_buf);
    var w_plain: [128]u8 = undefined;
    try testing.expect(hub.unprotectRtp(aW, w_wire, &w_plain) != null);

    // V uses a DIFFERENT ssrc at a LOW sequence. Because inbound state is keyed
    // per (source, ssrc), V's stream is fully independent of W's high sequence:
    // V decrypts correctly at ROC 0 (no cross-peer poisoning / blackhole).
    const v_ssrc: u32 = 0x9999_0001;
    const v_in = srtp.deriveSessionKeys(kV.clientMaster(), kV.clientSalt());
    var v_buf: [64]u8 = undefined;
    const v_rtp = rtpPacket(201, v_ssrc, "v-data", &v_buf);
    var v_wire_buf: [128]u8 = undefined;
    const v_wire = try srtp.protect(v_in, 0, v_rtp, &v_wire_buf);
    var v_plain: [128]u8 = undefined;
    const got = hub.unprotectRtp(aV, v_wire, &v_plain) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, v_rtp, got);
}

test "SFU lifecycle: re-handshake at same address re-keys; evict wipes; full table fails closed" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const a1 = mkAddr(30);
    const k1 = mkKeys(1);
    const k2 = mkKeys(2);
    try testing.expect(hub.noteEstablished(a1, k1));
    // Re-handshake at the SAME address with NEW keys ⇒ context re-keyed.
    try testing.expect(hub.noteEstablished(a1, k2));

    const ssrc: u32 = 0x0BADF00D;
    const seq: u16 = 5;
    var rtp_buf: [64]u8 = undefined;
    const rtp = rtpPacket(seq, ssrc, "hello", &rtp_buf);
    // Egress now uses k2's server-write key.
    var enc_buf: [128]u8 = undefined;
    const wire = hub.protectRtp(a1, rtp, &enc_buf) orelse return error.TestUnexpectedResult;
    const k2_out = srtp.deriveSessionKeys(k2.serverMaster(), k2.serverSalt());
    var rec: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, rtp, try srtp.unprotect(k2_out, 0, wire, &rec));
    // k1's key can no longer open it.
    const k1_out = srtp.deriveSessionKeys(k1.serverMaster(), k1.serverSalt());
    try testing.expectError(error.AuthFailed, srtp.unprotect(k1_out, 0, wire, &rec));

    hub.evict(a1);
    try testing.expect(!hub.peerActive(a1));

    // Fill the table with live peers, then a new peer fails closed (never
    // recycles a live context).
    var i: usize = 0;
    while (i < max_peers) : (i += 1) {
        const ok = hub.noteEstablished(TransportAddress.fromBytes(&[_]u8{ 10, 0, @intCast(i >> 8), @intCast(i & 0xff) }, 6000) catch unreachable, mkKeys(@intCast(i & 0xff)));
        try testing.expect(ok);
    }
    try testing.expect(!hub.noteEstablished(mkAddr(200), mkKeys(7)));
}

test "SFU NACK-safety: the outbound replay window is keyed by the packet header, not a caller id" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();
    const kR = mkKeys(41);
    const aR = mkAddr(50);
    try testing.expect(hub.noteEstablished(aR, kR));

    const z: u32 = 0xABCD_EF01;
    const x: u32 = 0x1234_5678;

    // Forward header (ssrc=Z, seq=51, P1) to R → encrypted; R's Z-window uses 51.
    var p1_buf: [64]u8 = undefined;
    const p1 = rtpPacket(51, z, "P1", &p1_buf);
    var e1: [128]u8 = undefined;
    try testing.expect(hub.protectRtp(aR, p1, &e1) != null);

    // The exact NACK divergence: a DIFFERENT plaintext with the SAME header
    // (ssrc=Z, seq=51) — as a seq-keyed retransmit cache could hand back for a
    // NACK nominally about a different SSRC — is REFUSED (Z-window used 51). The
    // window follows the packet's OWN header, so it can never disagree with the
    // AES-CM nonce ⇒ no two-time-pad.
    var p2_buf: [64]u8 = undefined;
    const p2 = rtpPacket(51, z, "P2-different", &p2_buf);
    var e2: [128]u8 = undefined;
    try testing.expect(hub.protectRtp(aR, p2, &e2) == null);

    // A packet with a DIFFERENT header SSRC (X) at the same seq is an
    // independent SRTP stream to R ⇒ allowed.
    var px_buf: [64]u8 = undefined;
    const px = rtpPacket(51, x, "X-stream", &px_buf);
    var ex: [128]u8 = undefined;
    try testing.expect(hub.protectRtp(aR, px, &ex) != null);
}

test "SFU byte-identical intent: unknown (non-DTLS) address yields null crypto" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();
    const unknown = mkAddr(40);
    var out: [64]u8 = undefined;
    const zeros40: [40]u8 = @splat(0);
    const zeros12: [12]u8 = @splat(0);
    try testing.expect(hub.unprotectRtp(unknown, &zeros40, &out) == null);
    try testing.expect(hub.protectRtp(unknown, &zeros12, &out) == null);
    try testing.expect(hub.unprotectRtcp(unknown, &zeros40, &out) == null);
    try testing.expect(hub.protectRtcp(unknown, &zeros12, &out) == null);
}
