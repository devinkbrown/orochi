// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Framed secured S2S link: the live-path Tsumugi handshake over a byte stream.
//!
//! `tsumugi_session` drives the AKE message-at-a-time; on a real TCP stream the
//! TOFU preamble, M1, and M2 must be delimited so they survive coalescing and
//! splitting. This adapter length-prefixes ONLY those three handshake messages
//! (u32 LE length + payload, reassembled through an inbound buffer). Those three
//! messages — the prekey preamble plus M1/M2 — ARE the handshake and travel in
//! plaintext (their own contents are already AKE-protected).
//!
//! Once the AKE establishes, the inner `S2sLink` CRDT stream is NOT trusted to
//! the wire raw: every byte is wrapped in an AEAD record layer keyed on the
//! Tsumugi `Established` directional keys (`send_key`/`recv_key`) so the entire
//! post-handshake MESSAGE/MEMBERSHIP/MODE/TOPIC/NICK stream is confidential and
//! tamper-evident on secured mesh links. See `record_*` constants for the wire
//! format. The inner link's own `s2s_frame` decoder still frames the *plaintext*
//! CRDT messages inside each record, so there is no semantic double-framing — the
//! AEAD layer only secures the byte stream the inner decoder consumes.
//!
//! TOFU bootstrap (decision: trust-on-first-use): the responder announces its
//! signed prekey as the preamble; the initiator verifies the signature + validity
//! window and adopts the node id (optionally pinned via `expected_remote`), then
//! runs Noise-IK. Identity keypairs/prekeys are borrowed — keep them alive.
const std = @import("std");

const node_identity = @import("node_identity.zig");
const tsumugi_session = @import("../crypto/tsumugi_session.zig");
const hs = @import("../crypto/tsumugi_handshake.zig");
const node_short_id = @import("../crypto/node_short_id.zig");
const s2s_link = @import("s2s_link.zig");
const s2s_peer = @import("../substrate/suimyaku/s2s_peer.zig");
const partition_detector = @import("../substrate/suimyaku/partition_detector.zig");
const entity_prop_event = @import("../proto/entity_prop_event.zig");

pub const Role = tsumugi_session.Role;

/// Bound on a single buffered handshake message (prekey ~1.3KB, M1/M2 a few KB).
const max_handshake_msg: u32 = 64 * 1024;
pub const max_expected_remotes: usize = 16;

// --- Post-AKE AEAD record layer -------------------------------------------
//
// Wire format of one secured record (little-endian), emitted back-to-back:
//
//   [u32 len][ciphertext (len - tag_len bytes)][Poly1305 tag (tag_len bytes)]
//
// `len` counts the ciphertext+tag that follow the 4-byte length prefix (i.e.
// `plaintext_len + record_tag_len`). The ciphertext is the inner CRDT bytes
// sealed with the session `send_key` and a per-record nonce derived from the
// base `send_nonce` plus a strictly-incrementing 64-bit record counter (one
// record per `drainInner` chunk). The peer parses the length prefix, opens the
// record with `recv_key` + the matching counter, and feeds the recovered
// plaintext to the inner link. A tag/length failure drops the link.

const RecordChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const record_len_prefix: usize = 4;
const record_tag_len: usize = RecordChaCha.tag_length;

/// Upper bound on a single inbound record's `len` field. A drained inner chunk
/// is at most one CRDT frame batch; cap generously but finitely so a desync or
/// hostile peer can't make us buffer unboundedly.
const max_record_len: u32 = 16 * 1024 * 1024;

/// AAD bound into every record: the record counter as 8 LE bytes. This binds the
/// ordinal into the tag so a reordered/replayed record cannot validate against a
/// different position even if an attacker rewrote the length prefix.
fn recordAad(counter: u64) [8]u8 {
    var aad: [8]u8 = undefined;
    std.mem.writeInt(u64, &aad, counter, .little);
    return aad;
}

/// Named errors this adapter raises (it also surfaces handshake, allocation, and
/// inner-link errors; the methods use `anyerror` to carry the union).
pub const HandshakeError = error{ HandshakeTooLarge, PrekeyRejected, UnexpectedRemote };

pub const Options = struct {
    allocator: std.mem.Allocator,
    role: Role,
    /// Borrowed local identity (provides the static + KEM keys and realm).
    identity: *const node_identity.NodeIdentity,
    /// This node's signed prekey (build via `identity.signedPrekey(...)`).
    local_prekey: hs.SignedPrekey,
    cfg: hs.Config,
    rng: std.Io,
    server_name: []const u8,
    /// Human description of THIS node, gossiped to the peer in the CRDT handshake
    /// so remote WHOIS (312) names the right per-server description. Empty = none.
    description: []const u8 = "",
    local_epoch_ms: u64 = 1000,
    channel_name: []const u8 = "#suimyaku",
    /// Optional trust pin: require the peer's node id to equal this. Null = TOFU.
    expected_remote: ?[20]u8 = null,
    /// Optional trust pins: require the peer's node id to match one entry. Empty
    /// keeps TOFU. Copied into the link at init.
    expected_remotes: []const [20]u8 = &.{},
    /// Optional node-signing-key allowlist. Empty keeps TOFU. Borrowed; caller
    /// must keep it alive for the link lifetime.
    trusted_node_keys: []const [32]u8 = &.{},
};

const Phase = enum { await_prekey, ake, established };

pub const SecuredLink = struct {
    allocator: std.mem.Allocator,
    role: Role,
    identity: *const node_identity.NodeIdentity,
    local_prekey: hs.SignedPrekey,
    cfg: hs.Config,
    rng: std.Io,
    expected_remotes: [max_expected_remotes][20]u8 = undefined,
    expected_remote_count: usize = 0,
    trusted_node_keys: []const [32]u8 = &.{},
    server_name: []const u8,
    description: []const u8,
    local_epoch_ms: u64,
    channel_name: []const u8,

    phase: Phase,
    session: ?tsumugi_session.Session = null,
    inner: ?*s2s_link.S2sLink = null,
    /// Borrowed local-world nick predicate for cross-namespace NICK collision
    /// resolution, retained so it survives the lazy `inner` stand-up (the inner
    /// S2sLink does not exist until the AKE completes). Re-applied to `inner` on
    /// creation. Null until the daemon installs it.
    local_nicks: ?s2s_link.S2sLink.LocalNickResolver = null,
    inbuf: std.ArrayList(u8) = .empty,
    out: std.ArrayList(u8) = .empty,
    feed_seq: u64 = 0,
    /// Post-AKE AEAD record counters (per direction). Strictly incremented for
    /// every record so no (key, nonce) pair is ever reused.
    send_counter: u64 = 0,
    recv_counter: u64 = 0,
    /// Reassembly buffer for inbound secured records: the transport delivers a
    /// byte stream, so partial records carry across `feedInner` calls here.
    rec_inbuf: std.ArrayList(u8) = .empty,

    /// Initialize. The responder immediately queues its prekey preamble and stands
    /// up its session; the initiator waits for the responder's preamble.
    pub fn init(opts: Options) anyerror!SecuredLink {
        var expected: [max_expected_remotes][20]u8 = undefined;
        var expected_count: usize = 0;
        if (opts.expected_remote) |pin| {
            expected[expected_count] = pin;
            expected_count += 1;
        }
        for (opts.expected_remotes) |pin| {
            if (expected_count == expected.len) break;
            expected[expected_count] = pin;
            expected_count += 1;
        }
        var self = SecuredLink{
            .allocator = opts.allocator,
            .role = opts.role,
            .identity = opts.identity,
            .local_prekey = opts.local_prekey,
            .cfg = opts.cfg,
            .rng = opts.rng,
            .expected_remotes = expected,
            .expected_remote_count = expected_count,
            .trusted_node_keys = opts.trusted_node_keys,
            .server_name = opts.server_name,
            .description = opts.description,
            .local_epoch_ms = opts.local_epoch_ms,
            .channel_name = opts.channel_name,
            .phase = if (opts.role == .responder) .ake else .await_prekey,
        };
        if (opts.role == .responder) {
            self.session = tsumugi_session.Session.initResponder(
                opts.allocator,
                &opts.identity.sign_kp,
                opts.local_prekey,
                &opts.identity.kem_kp.secret_key,
                opts.cfg,
            );
            // Preamble: announce our signed prekey so the initiator can run IK.
            const wire = try hs.encodeSignedPrekey(opts.allocator, &opts.local_prekey);
            defer opts.allocator.free(wire);
            try self.writeFramed(wire);
        }
        return self;
    }

    pub fn deinit(self: *SecuredLink) void {
        if (self.session) |*s| s.deinit();
        if (self.inner) |l| {
            l.deinit();
            self.allocator.destroy(l);
        }
        self.inbuf.deinit(self.allocator);
        self.out.deinit(self.allocator);
        self.rec_inbuf.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn outbound(self: *const SecuredLink) []const u8 {
        return self.out.items;
    }
    pub fn clearOutbound(self: *SecuredLink) void {
        self.out.clearRetainingCapacity();
    }
    pub fn established(self: *const SecuredLink) bool {
        return if (self.inner) |l| l.established() else false;
    }
    /// Install (or clear) the borrowed local-world nick predicate for
    /// cross-namespace NICK collision resolution. Retained across the lazy inner
    /// stand-up and applied immediately when `inner` already exists.
    pub fn setLocalNickResolver(self: *SecuredLink, resolver: ?s2s_link.S2sLink.LocalNickResolver) void {
        self.local_nicks = resolver;
        if (self.inner) |l| l.setLocalNickResolver(resolver);
    }
    pub fn peerShortId(self: *const SecuredLink) ?u64 {
        return if (self.session) |s| s.peerShortId() else null;
    }
    /// The peer's node id as a `u64` (the authenticated session short id),
    /// matching the plaintext link's `remoteNodeId` shape so generic mesh code
    /// (e.g. network-wide clone aggregation) can key uniformly on either leg.
    pub fn remoteNodeId(self: *const SecuredLink) ?u64 {
        return self.peerShortId();
    }
    pub fn peerNodeId(self: *const SecuredLink) ?[20]u8 {
        return if (self.session) |s| s.peerNodeId() else null;
    }

    /// The peer's authenticated raw Ed25519 signing public key (null before the
    /// AKE establishes). Verifies peer-signed cross-mesh operator grants.
    pub fn peerNodeKey(self: *const SecuredLink) ?[32]u8 {
        return if (self.session) |s| s.peerNodeKey() else null;
    }

    fn trustRootAllows(self: *const SecuredLink, key: [32]u8) bool {
        if (self.trusted_node_keys.len == 0) return true;
        for (self.trusted_node_keys) |trusted| {
            if (std.mem.eql(u8, trusted[0..], key[0..])) return true;
        }
        return false;
    }

    pub fn channelMembers(self: *const SecuredLink, channel: []const u8) []const s2s_peer.MemberInfo {
        return if (self.inner) |l| l.channelMembers(channel) else &.{};
    }

    pub fn remoteName(self: *const SecuredLink) []const u8 {
        return if (self.inner) |l| l.remoteName() else "";
    }

    /// Which node (if known) owns `nick`, per this peer's route table.
    pub fn routeNickNode(self: *const SecuredLink, nick: []const u8) ?u64 {
        return if (self.inner) |l| l.routeNickNode(nick) else null;
    }

    /// Find `nick` in this peer's converged remote channel rosters (ASCII
    /// case-insensitive). Borrowed; valid until the next membership mutation.
    pub fn findRemoteMember(self: *const SecuredLink, nick: []const u8) ?s2s_peer.MemberInfo {
        return if (self.inner) |l| l.findRemoteMember(nick) else null;
    }

    /// Server name registered for `node` (handshake or gossiped registry).
    pub fn nodeName(self: *const SecuredLink, node: u64) ?[]const u8 {
        return if (self.inner) |l| l.nodeName(node) else null;
    }

    /// Server description registered for `node`, or null when unknown/empty.
    pub fn nodeDescription(self: *const SecuredLink, node: u64) ?[]const u8 {
        return if (self.inner) |l| l.nodeDescription(node) else null;
    }

    /// Announce a local member to the peer over the secured CRDT link (no-op until
    /// established), carrying the member's real username/realname/visible-host.
    /// Outbound bytes accumulate in `out`.
    pub fn sendMembership(self: *SecuredLink, channel: []const u8, nick: []const u8, status: u4, hlc: u64, present: bool, ident: s2s_peer.MemberIdentity, setter: []const u8) anyerror!void {
        const link = self.inner orelse return;
        try link.sendMembership(channel, nick, status, hlc, present, ident, setter);
        try self.drainInner();
    }

    /// Announce aggregate local boolean MODE flags for `channel` over the
    /// secured CRDT link (no-op until established). Outbound bytes accumulate in
    /// `out`.
    pub fn sendChannelModeFlags(self: *SecuredLink, channel: []const u8, flags: u16, hlc: u64) anyerror!void {
        const link = self.inner orelse return;
        try link.sendChannelModeFlags(channel, flags, hlc);
        try self.drainInner();
    }

    /// Announce a full local parameter/IRCX channel-state snapshot over the
    /// secured CRDT link. Outbound bytes accumulate in `out`.
    pub fn sendChannelModeState(self: *SecuredLink, ev: s2s_link.ChannelModeStateEvent) anyerror!void {
        const link = self.inner orelse return;
        try link.sendChannelModeState(ev);
        try self.drainInner();
    }

    /// Announce a local IRCX channel PROP set/delete (or re-broadcast a remote
    /// one) over the secured CRDT link. Outbound bytes accumulate in `out`.
    /// `origin` carries the ORIGINAL author's node id + self-contained multi-hop
    /// origin signature (see `S2sLink.sendChannelProp`).
    pub fn sendChannelProp(
        self: *SecuredLink,
        channel: []const u8,
        key: []const u8,
        value: []const u8,
        owner: []const u8,
        hlc: u64,
        present: bool,
        origin: s2s_peer.S2sPeer.PropOrigin,
    ) anyerror!void {
        const link = self.inner orelse return;
        try link.sendChannelProp(channel, key, value, owner, hlc, present, origin);
        try self.drainInner();
    }

    /// Announce a local IRCX user/member PROP set/delete (or re-broadcast a remote
    /// one) over the secured CRDT link via ENTITY_PROP. Outbound bytes accumulate
    /// in `out`. `origin` carries the ORIGINAL author's node id + self-contained
    /// multi-hop origin signature (see `S2sLink.sendEntityProp`).
    pub fn sendEntityProp(
        self: *SecuredLink,
        kind: entity_prop_event.EntityKind,
        entity: []const u8,
        key: []const u8,
        value: []const u8,
        owner: []const u8,
        hlc: u64,
        present: bool,
        origin: s2s_peer.S2sPeer.PropOrigin,
    ) anyerror!void {
        const link = self.inner orelse return;
        try link.sendEntityProp(kind, entity, key, value, owner, hlc, present, origin);
        try self.drainInner();
    }

    /// Announce a local channel topic change over the secured CRDT link.
    pub fn sendTopic(
        self: *SecuredLink,
        channel: []const u8,
        topic: []const u8,
        setter: []const u8,
        set_at: i64,
        hlc: u64,
        present: bool,
    ) anyerror!void {
        const link = self.inner orelse return;
        try link.sendTopic(channel, topic, setter, set_at, hlc, present);
        try self.drainInner();
    }

    /// Announce a local user's nick change over the secured CRDT link.
    pub fn sendNickChange(
        self: *SecuredLink,
        old_nick: []const u8,
        new_nick: []const u8,
        ident: s2s_peer.MemberIdentity,
        hlc: u64,
    ) anyerror!void {
        const link = self.inner orelse return;
        try link.sendNickChange(old_nick, new_nick, ident, hlc);
        try self.drainInner();
    }

    /// Drain remote channel topic changes for the daemon to apply + emit.
    pub fn takeTopicChanges(self: *SecuredLink) anyerror![]s2s_peer.S2sPeer.TopicDelta {
        const link = self.inner orelse return &.{};
        return link.takeTopicChanges();
    }

    /// Drain remote user nick changes for the daemon to surface as NICK lines.
    pub fn takeNickChanges(self: *SecuredLink) anyerror![]s2s_peer.S2sPeer.NickDelta {
        const link = self.inner orelse return &.{};
        return link.takeNickChanges();
    }

    /// Forward a cross-node user message over the secured CRDT link.
    pub fn sendMessage(self: *SecuredLink, msg: s2s_link.RelayMessage) anyerror!void {
        const link = self.inner orelse return;
        try link.sendMessage(msg);
        try self.drainInner();
    }

    /// Drain inbound cross-node messages decoded by the inner link. Caller owns
    /// the slice + each Owned (deinit each, free the slice).
    pub fn takeInbound(self: *SecuredLink) anyerror![]s2s_peer.InboundMessage {
        const link = self.inner orelse return &.{};
        return link.takeInbound();
    }

    /// Drain remote channel membership changes (JOIN/PART) for the daemon to
    /// surface to local members. Caller owns the slice + each delta's strings.
    pub fn takeMembershipChanges(self: *SecuredLink) anyerror![]s2s_peer.S2sPeer.MembershipDelta {
        const link = self.inner orelse return &.{};
        return link.takeMembershipChanges();
    }

    /// Drain remote channel MODE flag changes for the daemon to apply and
    /// surface to local members. Caller owns the slice + each delta's string.
    pub fn takeChannelModeFlagChanges(self: *SecuredLink) anyerror![]s2s_peer.S2sPeer.ChannelModeFlagsDelta {
        const link = self.inner orelse return &.{};
        return link.takeChannelModeFlagChanges();
    }

    /// Drain remote parameter/IRCX channel-state snapshots for daemon-side apply.
    pub fn takeChannelModeStateChanges(self: *SecuredLink) anyerror![]s2s_peer.S2sPeer.ChannelModeStateDelta {
        const link = self.inner orelse return &.{};
        return link.takeChannelModeStateChanges();
    }

    /// Drain remote direct-owned frames rejected for origin/peer mismatch.
    pub fn takeRejectedOriginFrames(self: *SecuredLink) u64 {
        const link = self.inner orelse return 0;
        return link.takeRejectedOriginFrames();
    }

    /// Announce a local channel list-mode (+b/+e/+I) change over the secured
    /// link. Outbound bytes accumulate in `out`.
    pub fn sendChannelList(
        self: *SecuredLink,
        channel: []const u8,
        kind: s2s_peer.S2sPeer.ChannelListDelta.Kind,
        mask: []const u8,
        setter: []const u8,
        set_at: i64,
        hlc: u64,
        present: bool,
    ) anyerror!void {
        const link = self.inner orelse return;
        try link.sendChannelList(channel, kind, mask, setter, set_at, hlc, present);
        try self.drainInner();
    }

    /// Drain remote channel list-mode changes decoded by the inner link.
    pub fn takeChannelListChanges(self: *SecuredLink) anyerror![]s2s_peer.S2sPeer.ChannelListDelta {
        const link = self.inner orelse return &.{};
        return link.takeChannelListChanges();
    }

    /// Drain remote channel PROP changes for daemon-side LWW apply.
    pub fn takeChannelPropChanges(self: *SecuredLink) anyerror![]s2s_peer.S2sPeer.ChannelPropDelta {
        const link = self.inner orelse return &.{};
        return link.takeChannelPropChanges();
    }

    /// Drain remote user/member PROP changes (ENTITY_PROP) for daemon-side LWW
    /// apply.
    pub fn takeEntityPropChanges(self: *SecuredLink) anyerror![]s2s_peer.S2sPeer.EntityPropDelta {
        const link = self.inner orelse return &.{};
        return link.takeEntityPropChanges();
    }

    /// Forward a signed cross-mesh operator grant to the peer over the secured
    /// CRDT link (no-op until established). Outbound bytes accumulate in `out`.
    pub fn sendOperGrant(self: *SecuredLink, signed: []const u8) anyerror!void {
        const link = self.inner orelse return;
        try link.sendOperGrant(signed);
        try self.drainInner();
    }

    /// Drain queued inbound oper-grant payloads decoded by the inner link. Caller
    /// owns + frees each slice and the outer slice. Verify each against
    /// `peerNodeKey()` before trusting it.
    pub fn takeOperGrants(self: *SecuredLink) anyerror![][]u8 {
        const link = self.inner orelse return &.{};
        return link.takeOperGrants();
    }

    /// Ship a live-session migration capsule (`migration_relay` frame bytes) to
    /// the peer over the secured CRDT link (no-op until established). The capsule
    /// carries sensitive session state, so it only rides the authenticated,
    /// encrypted leg — never the plaintext S2S path.
    pub fn sendSessionMigrate(self: *SecuredLink, frame_bytes: []const u8) anyerror!void {
        const link = self.inner orelse return;
        try link.sendSessionMigrate(frame_bytes);
        try self.drainInner();
    }

    /// Drain queued inbound session-migration capsules decoded by the inner link.
    /// Caller owns + frees each raw frame-bytes slice and the outer slice; each is
    /// verified+decoded by `MigrationTarget.accept` before any state is restored.
    pub fn takeSessionMigrations(self: *SecuredLink) anyerror![][]u8 {
        const link = self.inner orelse return &.{};
        return link.takeSessionMigrations();
    }

    /// Emit a CLONE_COUNT batch over the encrypted leg, then flush ciphertext.
    pub fn sendCloneCounts(self: *SecuredLink, payload: []const u8) anyerror!void {
        const link = self.inner orelse return;
        try link.sendCloneCounts(payload);
        try self.drainInner();
    }

    /// Drain queued inbound CLONE_COUNT payloads decoded by the inner link.
    pub fn takeCloneCounts(self: *SecuredLink) anyerror![][]u8 {
        const link = self.inner orelse return &.{};
        return link.takeCloneCounts();
    }

    /// Emit a signed OPER_EVENT over the encrypted leg, then flush ciphertext.
    pub fn sendOperEvent(self: *SecuredLink, category: u6, severity: u8, origin_server: []const u8, message: []const u8) anyerror!void {
        const link = self.inner orelse return;
        try link.sendOperEvent(category, severity, origin_server, message);
        try self.drainInner();
    }

    /// Drain queued inbound OPER_EVENT payloads decoded by the inner link.
    pub fn takeOperEvents(self: *SecuredLink) anyerror![][]u8 {
        const link = self.inner orelse return &.{};
        return link.takeOperEvents();
    }

    /// Emit a signed OBSERVE_EVENT over the encrypted leg, then flush ciphertext.
    pub fn sendObserveEvent(self: *SecuredLink, action: u8, origin_server: []const u8, nick: []const u8, user: []const u8, host: []const u8, account: ?[]const u8, detail: []const u8) anyerror!void {
        const link = self.inner orelse return;
        try link.sendObserveEvent(action, origin_server, nick, user, host, account, detail);
        try self.drainInner();
    }

    /// Drain queued inbound OBSERVE_EVENT payloads decoded by the inner link.
    pub fn takeObserveEvents(self: *SecuredLink) anyerror![][]u8 {
        const link = self.inner orelse return &.{};
        return link.takeObserveEvents();
    }

    pub fn sendKill(self: *SecuredLink, origin_server: []const u8, killer: []const u8, target: []const u8, reason: []const u8) anyerror!void {
        const link = self.inner orelse return;
        try link.sendKill(origin_server, killer, target, reason);
        try self.drainInner();
    }

    /// Drain queued inbound KILL payloads decoded by the inner link.
    pub fn takeKills(self: *SecuredLink) anyerror![][]u8 {
        const link = self.inner orelse return &.{};
        return link.takeKills();
    }

    /// Copy this peer's known-server topology into `out` for partition analysis
    /// (empty until the inner CRDT link is established).
    pub fn collectTopology(self: *const SecuredLink, out: []partition_detector.TopoNode) usize {
        const link = self.inner orelse return 0;
        return link.collectTopology(out);
    }

    fn writeFramed(self: *SecuredLink, payload: []const u8) anyerror!void {
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u32, &hdr, @intCast(payload.len), .little);
        try self.out.appendSlice(self.allocator, &hdr);
        try self.out.appendSlice(self.allocator, payload);
    }

    /// Feed inbound stream bytes. Handshake messages are length-deframed; once
    /// established, bytes are deframed as AEAD records, decrypted, and fed to the
    /// inner CRDT link (see the record-layer constants for the wire format).
    pub fn feed(self: *SecuredLink, bytes: []const u8, now_ms: u64) anyerror!void {
        if (self.phase == .established) {
            try self.feedInner(bytes, now_ms);
            return;
        }
        try self.inbuf.appendSlice(self.allocator, bytes);
        try self.drainHandshake(now_ms);
    }

    fn drainHandshake(self: *SecuredLink, now_ms: u64) anyerror!void {
        while (self.phase != .established) {
            if (self.inbuf.items.len < 4) return;
            const len = std.mem.readInt(u32, self.inbuf.items[0..4], .little);
            if (len > max_handshake_msg) return error.HandshakeTooLarge;
            if (self.inbuf.items.len < 4 + len) return; // wait for the rest
            const msg = self.inbuf.items[4 .. 4 + len];
            try self.processHandshake(msg, now_ms);
            // Consume the framed message.
            const consumed = 4 + len;
            const rest = self.inbuf.items.len - consumed;
            std.mem.copyForwards(u8, self.inbuf.items[0..rest], self.inbuf.items[consumed..]);
            self.inbuf.shrinkRetainingCapacity(rest);
        }
        // Established: any trailing bytes are the start of the secured record
        // stream — route them through feedInner so they buffer + decrypt.
        if (self.inbuf.items.len != 0) {
            const tail = try self.allocator.dupe(u8, self.inbuf.items);
            defer self.allocator.free(tail);
            self.inbuf.clearRetainingCapacity();
            try self.feedInner(tail, now_ms);
        }
    }

    fn processHandshake(self: *SecuredLink, msg: []const u8, now_ms: u64) anyerror!void {
        switch (self.phase) {
            .await_prekey => {
                // Initiator: verify + adopt the responder's announced prekey (TOFU).
                const remote_prekey = hs.decodeSignedPrekey(msg) catch return error.PrekeyRejected;
                remote_prekey.verify(self.cfg.now_ms) catch return error.PrekeyRejected;
                if (!self.allowsExpectedRemote(remote_prekey.node_id)) return error.UnexpectedRemote;
                if (!self.trustRootAllows(remote_prekey.node_key)) return error.PrekeyRejected;
                self.session = tsumugi_session.Session.initInitiator(
                    self.allocator,
                    &self.identity.sign_kp,
                    self.local_prekey,
                    &self.identity.kem_kp.secret_key,
                    remote_prekey,
                    self.cfg,
                );
                const m1 = try self.session.?.open(self.rng);
                defer self.allocator.free(m1);
                try self.writeFramed(m1);
                self.phase = .ake;
            },
            .ake => {
                if (try self.session.?.feed(msg, self.rng)) |reply| {
                    defer self.allocator.free(reply);
                    try self.writeFramed(reply);
                }
                if (self.session.?.isEstablished()) {
                    if (self.session.?.peerNodeId()) |peer| {
                        if (!self.allowsExpectedRemote(peer)) return error.UnexpectedRemote;
                    }
                    try self.beginCrdt(now_ms);
                }
            },
            .established => unreachable,
        }
    }

    fn allowsExpectedRemote(self: *const SecuredLink, node_id: [20]u8) bool {
        if (self.expected_remote_count == 0) return true;
        for (self.expected_remotes[0..self.expected_remote_count]) |pin| {
            if (std.mem.eql(u8, &pin, &node_id)) return true;
        }
        return false;
    }

    fn beginCrdt(self: *SecuredLink, now_ms: u64) anyerror!void {
        if (self.peerNodeKey()) |key| {
            if (!self.trustRootAllows(key)) return error.PrekeyRejected;
        }
        const peer_short = self.session.?.peerShortId().?;
        const link = try self.allocator.create(s2s_link.S2sLink);
        errdefer self.allocator.destroy(link);
        try link.init(.{
            .allocator = self.allocator,
            .local_node_id = node_short_id.shortId(self.identity.node_id),
            .remote_node_id = peer_short,
            .local_epoch_ms = self.local_epoch_ms,
            .server_name = self.server_name,
            .description = self.description,
            .channel_name = self.channel_name,
            .now_ms = now_ms,
            // End-to-end frame signing: hand the inner peer this node's signing
            // key so direct-owned state frames carry a self-certifying origin
            // proof. `local_node_id` above is derived from the SAME identity, so
            // the receiver's `originShortId(pubkey) == origin_node` invariant
            // holds. The inner peer takes an independent copy and wipes it on
            // deinit; `self.identity.sign_kp` is unaffected.
            .signing_key = self.identity.sign_kp,
        });
        if (self.local_nicks) |resolver| link.setLocalNickResolver(resolver);
        self.inner = link;
        self.phase = .established;
        if (self.role == .initiator) {
            try link.start(now_ms);
            try self.drainInner();
        }
    }

    /// The established Tsumugi keys (present once `phase == .established`). The
    /// inner link is only created alongside establishment, so this never returns
    /// null on the post-AKE paths that call it.
    fn establishedKeys(self: *const SecuredLink) *const hs.Established {
        return self.session.?.established().?;
    }

    /// Inbound: append the transport bytes to the record reassembly buffer, then
    /// open every complete length-prefixed AEAD record and feed the recovered
    /// plaintext to the inner CRDT link. Leftover partial-record bytes stay
    /// buffered for the next call. A tag/length failure returns an error so the
    /// caller drops the link (no corrupt plaintext is ever delivered).
    fn feedInner(self: *SecuredLink, bytes: []const u8, now_ms: u64) anyerror!void {
        try self.rec_inbuf.appendSlice(self.allocator, bytes);
        try self.drainRecords(now_ms);
        try self.drainInner();
    }

    fn drainRecords(self: *SecuredLink, now_ms: u64) anyerror!void {
        const link = self.inner.?;
        const keys = self.establishedKeys();
        var consumed: usize = 0;
        while (true) {
            const buf = self.rec_inbuf.items[consumed..];
            if (buf.len < record_len_prefix) break;
            const body_len = std.mem.readInt(u32, buf[0..4], .little);
            if (body_len > max_record_len) return error.HandshakeTooLarge;
            if (body_len < record_tag_len) return error.AuthFailed; // malformed: no room for a tag, can never authenticate
            const total = record_len_prefix + body_len;
            if (buf.len < total) break; // wait for the rest of this record
            const body = buf[record_len_prefix..total];
            const ct = body[0 .. body.len - record_tag_len];
            const tag = body[body.len - record_tag_len ..][0..record_tag_len].*;

            const aad = recordAad(self.recv_counter);
            const pt = try self.allocator.alloc(u8, ct.len);
            defer self.allocator.free(pt);
            // AEAD-open: a tamper/desync surfaces as error.AuthFailed, which we
            // propagate so the link is dropped before any plaintext is fed in.
            try keys.openRecord(self.recv_counter, &aad, ct, tag, pt);
            self.recv_counter +%= 1;

            self.feed_seq +%= 1;
            try link.feed(pt, now_ms, self.feed_seq);
            consumed += total;
        }
        if (consumed != 0) {
            const rest = self.rec_inbuf.items.len - consumed;
            std.mem.copyForwards(u8, self.rec_inbuf.items[0..rest], self.rec_inbuf.items[consumed..]);
            self.rec_inbuf.shrinkRetainingCapacity(rest);
        }
    }

    /// Outbound: take the inner link's pending plaintext and emit it as ONE
    /// length-prefixed AEAD record (sealed with `send_key` + the next record
    /// counter), appended to `self.out`. Each drained chunk becomes its own
    /// record; the counter advances so nonces never repeat.
    fn drainInner(self: *SecuredLink) anyerror!void {
        const link = self.inner.?;
        const o = link.outbound();
        if (o.len == 0) return;
        try self.sealRecordTo(o);
        link.clearOutbound();
    }

    /// Seal `pt` into one record (`[u32 len][ct][tag]`) and append to `self.out`.
    fn sealRecordTo(self: *SecuredLink, pt: []const u8) anyerror!void {
        const keys = self.establishedKeys();
        const body_len = pt.len + record_tag_len;
        std.debug.assert(body_len <= max_record_len);

        const start = self.out.items.len;
        try self.out.resize(self.allocator, start + record_len_prefix + body_len);
        const rec = self.out.items[start..];
        std.mem.writeInt(u32, rec[0..4], @intCast(body_len), .little);

        const aad = recordAad(self.send_counter);
        keys.sealRecord(self.send_counter, &aad, pt, rec[record_len_prefix..]);
        self.send_counter +%= 1;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const DeterministicIo = struct {
    s: u64,
    fn io(self: *DeterministicIo) std.Io {
        return .{ .userdata = self, .vtable = &vtable };
    }
    fn random(userdata: ?*anyopaque, buffer: []u8) void {
        var self: *DeterministicIo = @ptrCast(@alignCast(userdata.?));
        for (buffer) |*b| {
            self.s = self.s *% 6364136223846793005 +% 1442695040888963407;
            b.* = @truncate(self.s >> 56);
        }
    }
    const vtable: std.Io.VTable = blk: {
        var vt = std.Io.failing.vtable.*;
        vt.random = random;
        break :blk vt;
    };
};

fn cfgFor(realm: [32]u8, mesh_pass: []const u8) hs.Config {
    return .{ .realm = realm, .supported_bands = 0b1111, .supported_features = 0b1, .mesh_pass = mesh_pass, .now_ms = 20 };
}

/// Pump two links, optionally splitting each transfer into 1-byte feeds to prove
/// the handshake framing survives arbitrary TCP fragmentation.
fn pump(a: *SecuredLink, b: *SecuredLink, split: bool) !void {
    var now: u64 = 1;
    var rounds: usize = 0;
    while (rounds < 64) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try testing.allocator.dupe(u8, a_out);
        defer testing.allocator.free(a_copy);
        const b_copy = try testing.allocator.dupe(u8, b_out);
        defer testing.allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try feedMaybeSplit(b, a_copy, now, split);
        if (b_copy.len != 0) try feedMaybeSplit(a, b_copy, now, split);
        now += 1;
    }
}

fn feedMaybeSplit(link: *SecuredLink, bytes: []const u8, now: u64, split: bool) !void {
    if (!split) {
        try link.feed(bytes, now);
        return;
    }
    for (bytes) |byte| try link.feed(&[_]u8{byte}, now);
}

fn runScenario(split: bool) !void {
    var ida = try node_identity.fromSeed([_]u8{0x11} ** 32, "local");
    defer ida.deinit();
    var idb = try node_identity.fromSeed([_]u8{0x22} ** 32, "local");
    defer idb.deinit();
    const pre_a = try ida.signedPrekey(1, 10, 1000, 0b1111, 0b1);
    const pre_b = try idb.signedPrekey(2, 10, 1000, 0b1111, 0b1);

    var rng = DeterministicIo{ .s = 0xABCDEF };

    var a = try SecuredLink.init(.{
        .allocator = testing.allocator,
        .role = .initiator,
        .identity = &ida,
        .local_prekey = pre_a,
        .cfg = cfgFor(ida.realm, "mp"),
        .rng = rng.io(),
        .server_name = "a.orochi",
    });
    defer a.deinit();
    var b = try SecuredLink.init(.{
        .allocator = testing.allocator,
        .role = .responder,
        .identity = &idb,
        .local_prekey = pre_b,
        .cfg = cfgFor(idb.realm, ""),
        .rng = rng.io(),
        .server_name = "b.orochi",
    });
    defer b.deinit();

    try pump(&a, &b, split);

    try testing.expect(a.established());
    try testing.expect(b.established());
    // TOFU: each side adopted the other's bridged identity.
    try testing.expectEqual(idb.shortId(), a.peerShortId().?);
    try testing.expectEqual(ida.shortId(), b.peerShortId().?);
    // Each side recovered the peer's authenticated raw Ed25519 sign key — the
    // key cross-mesh oper grants are verified against.
    try testing.expectEqualSlices(u8, &idb.sign_kp.public_key, &a.peerNodeKey().?);
    try testing.expectEqualSlices(u8, &ida.sign_kp.public_key, &b.peerNodeKey().?);
}

test "secured link: TOFU preamble + IK handshake + CRDT over a whole-buffer stream" {
    try runScenario(false);
}

test "secured link survives 1-byte fragmentation of every handshake message" {
    try runScenario(true);
}

/// Fully-built initiator/responder pair sharing the test allocator. Drives the
/// AKE to establishment so data-path tests start from a secured link.
const EstablishedPair = struct {
    ida: node_identity.NodeIdentity,
    idb: node_identity.NodeIdentity,
    a: SecuredLink,
    b: SecuredLink,

    fn init() !EstablishedPair {
        var ida = try node_identity.fromSeed([_]u8{0x11} ** 32, "local");
        errdefer ida.deinit();
        var idb = try node_identity.fromSeed([_]u8{0x22} ** 32, "local");
        errdefer idb.deinit();
        const pre_a = try ida.signedPrekey(1, 10, 1000, 0b1111, 0b1);
        const pre_b = try idb.signedPrekey(2, 10, 1000, 0b1111, 0b1);
        var rng = DeterministicIo{ .s = 0x5151 };
        var a = try SecuredLink.init(.{
            .allocator = testing.allocator,
            .role = .initiator,
            .identity = &ida,
            .local_prekey = pre_a,
            .cfg = cfgFor(ida.realm, "mp"),
            .rng = rng.io(),
            .server_name = "a.orochi",
        });
        errdefer a.deinit();
        var b = try SecuredLink.init(.{
            .allocator = testing.allocator,
            .role = .responder,
            .identity = &idb,
            .local_prekey = pre_b,
            .cfg = cfgFor(idb.realm, ""),
            .rng = rng.io(),
            .server_name = "b.orochi",
        });
        errdefer b.deinit();
        try pump(&a, &b, false);
        return .{ .ida = ida, .idb = idb, .a = a, .b = b };
    }

    fn deinit(self: *EstablishedPair) void {
        self.a.deinit();
        self.b.deinit();
        self.ida.deinit();
        self.idb.deinit();
    }
};

test "post-handshake bytes on the wire are ciphertext, not inner plaintext" {
    var p = try EstablishedPair.init();
    defer p.deinit();
    try testing.expect(p.a.established());
    try testing.expect(p.b.established());

    // Both sides have drained the establishment exchange; start clean.
    p.a.clearOutbound();
    p.b.clearOutbound();

    // Snapshot the inner link's plaintext for this membership announcement, then
    // produce the secured wire bytes for the same announcement.
    const ident = s2s_peer.MemberIdentity{ .username = "u", .realname = "real name", .host = "h.example" };
    try p.a.inner.?.sendMembership("#suimyaku", "alice", 0, 100, true, ident, "");
    const plaintext = try testing.allocator.dupe(u8, p.a.inner.?.outbound());
    defer testing.allocator.free(plaintext);
    try testing.expect(plaintext.len != 0);

    try p.a.drainInner(); // seals the pending inner bytes into one record
    const wire = p.a.outbound();
    // Framed record is longer than the plaintext (4-byte len + tag) and does not
    // contain the plaintext verbatim.
    try testing.expect(wire.len == plaintext.len + 4 + 16);
    try testing.expect(std.mem.indexOf(u8, wire, plaintext) == null);
}

test "a single flipped bit in a transit record fails decryption" {
    var p = try EstablishedPair.init();
    defer p.deinit();
    p.a.clearOutbound();
    p.b.clearOutbound();

    const ident = s2s_peer.MemberIdentity{ .username = "u", .realname = "r", .host = "h" };
    try p.a.sendMembership("#suimyaku", "bob", 0, 200, true, ident, "");
    const record = try testing.allocator.dupe(u8, p.a.outbound());
    defer testing.allocator.free(record);
    try testing.expect(record.len > 4 + 16);
    p.a.clearOutbound();

    // Flip a bit in the ciphertext body (past the 4-byte length prefix).
    record[record.len - 1] ^= 1;
    // The tamper must surface as an AEAD auth failure, not silent plaintext.
    try testing.expectError(error.AuthFailed, p.b.feed(record, 99));
}

test "a CRDT membership frame round-trips end-to-end over the secured record layer" {
    var p = try EstablishedPair.init();
    defer p.deinit();
    p.a.clearOutbound();
    p.b.clearOutbound();

    const ident = s2s_peer.MemberIdentity{ .username = "ann", .realname = "Ann Real", .host = "host.a" };
    try p.a.sendMembership("#suimyaku", "ann", 0, 300, true, ident, "");

    // Pump the secured record(s) A->B (and any B->A acks) to convergence.
    try pump(&p.a, &p.b, false);

    const changes = try p.b.takeMembershipChanges();
    defer {
        for (changes) |*c| c.deinit(testing.allocator);
        testing.allocator.free(changes);
    }
    var saw_ann = false;
    for (changes) |c| {
        if (std.mem.eql(u8, c.nick, "ann")) saw_ann = true;
    }
    try testing.expect(saw_ann);
}

test "a trust-pin mismatch rejects the peer prekey" {
    var ida = try node_identity.fromSeed([_]u8{0x11} ** 32, "local");
    defer ida.deinit();
    var idb = try node_identity.fromSeed([_]u8{0x22} ** 32, "local");
    defer idb.deinit();
    const pre_a = try ida.signedPrekey(1, 10, 1000, 0b1111, 0b1);
    const pre_b = try idb.signedPrekey(2, 10, 1000, 0b1111, 0b1);
    var rng = DeterministicIo{ .s = 1 };

    // Initiator pins a WRONG expected remote id.
    var a = try SecuredLink.init(.{
        .allocator = testing.allocator,
        .role = .initiator,
        .identity = &ida,
        .local_prekey = pre_a,
        .cfg = cfgFor(ida.realm, "mp"),
        .rng = rng.io(),
        .server_name = "a.orochi",
        .expected_remote = [_]u8{0xFF} ** 20,
    });
    defer a.deinit();
    var b = try SecuredLink.init(.{
        .allocator = testing.allocator,
        .role = .responder,
        .identity = &idb,
        .local_prekey = pre_b,
        .cfg = cfgFor(idb.realm, ""),
        .rng = rng.io(),
        .server_name = "b.orochi",
    });
    defer b.deinit();

    // Feed B's preamble to A -> A rejects on the pin mismatch.
    const preamble = try testing.allocator.dupe(u8, b.outbound());
    defer testing.allocator.free(preamble);
    try testing.expectError(error.UnexpectedRemote, a.feed(preamble, 1));
}
