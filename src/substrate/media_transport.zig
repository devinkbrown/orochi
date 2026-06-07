//! SFU media-transport control plane: the per-call registry that ties each
//! call participant to its ICE credentials and (once a connectivity check
//! succeeds) its bound remote UDP media address, and computes the RTP forward
//! set for the selective-forwarding unit.
//!
//! This is the transport plane's control core — pure and socket-free, so it is
//! fully testable on its own. The live UDP socket (a later layer) drives it:
//! it allocates an endpoint per `MEDIA OFFER`, looks endpoints up by ICE ufrag
//! when a STUN binding arrives, binds the peer address on a successful check,
//! and asks `forwardTargets` where to relay each inbound RTP packet.
//!
//! Credentials follow ICE (RFC 8445 §5.3): a ufrag/pwd pair the server offers
//! per participant. The inbound STUN USERNAME is `<server-ufrag>:<peer-ufrag>`,
//! so a binding is demultiplexed back to a participant by its server ufrag.
const std = @import("std");
const ice = @import("../proto/ice.zig");
const stun = @import("../proto/stun.zig");

pub const ufrag_len: usize = 8;
pub const pwd_len: usize = 24;
/// Max SFU forward fan-out considered per inbound packet (call size cap).
pub const max_forward: usize = 64;

pub const TransportAddress = ice.TransportAddress;

/// One participant's media-transport state within a call.
pub const Endpoint = struct {
    /// ICE credentials the server offers this participant (RFC 8445 §5.3).
    ufrag: [ufrag_len]u8,
    pwd: [pwd_len]u8,
    /// The peer's bound media address, set once a connectivity check succeeds.
    /// Null means ICE has not completed; the SFU skips it as a forward target.
    remote: ?TransportAddress = null,
    /// The RTP SSRC the participant publishes (learned from its first packet).
    ssrc: u32 = 0,
    /// Media packets/bytes received from this participant and relayed onward.
    rx_packets: u64 = 0,
    rx_bytes: u64 = 0,

    pub fn ufragSlice(self: *const Endpoint) []const u8 {
        return self.ufrag[0..];
    }
    pub fn pwdSlice(self: *const Endpoint) []const u8 {
        return self.pwd[0..];
    }
    pub fn connected(self: *const Endpoint) bool {
        return self.remote != null;
    }
};

const ufrag_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Canonical 18-byte key for an address index: ip(16) ++ port(2, big-endian).
/// The IP is always 16 fully-initialized bytes (IPv4 lives in the first 4),
/// so byte-array hashing is well-defined.
const AddrKey = [18]u8;

fn addrKey(a: TransportAddress) AddrKey {
    var k: AddrKey = undefined;
    @memcpy(k[0..16], &a.ip);
    std.mem.writeInt(u16, k[16..18], a.port, .big);
    return k;
}

pub const MediaTransport = struct {
    allocator: std.mem.Allocator,
    /// Composite "channel\x00participant" -> Endpoint.
    endpoints: std.StringHashMapUnmanaged(Endpoint) = .empty,
    /// Server ufrag -> composite key, for STUN binding demultiplexing.
    by_ufrag: std.StringHashMapUnmanaged([]const u8) = .empty,
    /// Bound peer address -> composite key, for routing inbound RTP by source.
    by_addr: std.AutoHashMapUnmanaged(AddrKey, []const u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) MediaTransport {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MediaTransport) void {
        var it = self.endpoints.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.endpoints.deinit(self.allocator);
        self.by_ufrag.deinit(self.allocator);
        self.by_addr.deinit(self.allocator);
        self.* = undefined;
    }

    fn compositeKey(buf: []u8, channel: []const u8, participant: []const u8) ?[]const u8 {
        if (channel.len + 1 + participant.len > buf.len) return null;
        @memcpy(buf[0..channel.len], channel);
        buf[channel.len] = 0;
        @memcpy(buf[channel.len + 1 ..][0..participant.len], participant);
        return buf[0 .. channel.len + 1 + participant.len];
    }

    fn fillCreds(rng: std.Random, ufrag: []u8, pwd: []u8) void {
        for (ufrag) |*c| c.* = ufrag_alphabet[rng.uintLessThan(usize, ufrag_alphabet.len)];
        for (pwd) |*c| c.* = ufrag_alphabet[rng.uintLessThan(usize, ufrag_alphabet.len)];
    }

    /// Allocate (or re-credential) the endpoint for `participant` in `channel`,
    /// generating a fresh ICE ufrag/pwd from `rng`. Returns a pointer to the
    /// stored endpoint. Re-allocating an existing participant rotates creds and
    /// clears any prior remote binding.
    pub fn allocate(
        self: *MediaTransport,
        channel: []const u8,
        participant: []const u8,
        rng: std.Random,
    ) !*Endpoint {
        var kb: [256]u8 = undefined;
        const k = compositeKey(&kb, channel, participant) orelse return error.NameTooLong;

        var ep = Endpoint{ .ufrag = undefined, .pwd = undefined };
        fillCreds(rng, &ep.ufrag, &ep.pwd);

        const gop = try self.endpoints.getOrPut(self.allocator, k);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, k) catch |e| {
                _ = self.endpoints.remove(k);
                return e;
            };
        } else {
            // Rotating creds: drop the stale ufrag index entry.
            _ = self.by_ufrag.remove(gop.value_ptr.ufragSlice());
        }
        gop.value_ptr.* = ep;
        // Index the (stable) stored ufrag slice back to the owned key.
        self.by_ufrag.put(self.allocator, gop.value_ptr.ufragSlice(), gop.key_ptr.*) catch {};
        return gop.value_ptr;
    }

    pub fn get(self: *MediaTransport, channel: []const u8, participant: []const u8) ?*Endpoint {
        var kb: [256]u8 = undefined;
        const k = compositeKey(&kb, channel, participant) orelse return null;
        return self.endpoints.getPtr(k);
    }

    /// Resolve a participant endpoint from the server ufrag carried in a STUN
    /// binding's USERNAME (`<server-ufrag>:<peer-ufrag>`).
    pub fn byServerUfrag(self: *MediaTransport, server_ufrag: []const u8) ?*Endpoint {
        const key = self.by_ufrag.get(server_ufrag) orelse return null;
        return self.endpoints.getPtr(key);
    }

    /// Bind the peer's media address after a successful connectivity check, and
    /// (re)index it for RTP source routing.
    pub fn bindRemote(self: *MediaTransport, channel: []const u8, participant: []const u8, addr: TransportAddress) bool {
        var kb: [256]u8 = undefined;
        const k = compositeKey(&kb, channel, participant) orelse return false;
        const owned = self.endpoints.getKey(k) orelse return false;
        const ep = self.endpoints.getPtr(k).?;
        self.rebindAddr(ep, owned, addr);
        return true;
    }

    /// Point `ep.remote` at `addr`, refreshing the by_addr index from any prior
    /// binding to the (stable, owned) `owned_key`.
    fn rebindAddr(self: *MediaTransport, ep: *Endpoint, owned_key: []const u8, addr: TransportAddress) void {
        if (ep.remote) |old| _ = self.by_addr.remove(addrKey(old));
        ep.remote = addr;
        self.by_addr.put(self.allocator, addrKey(addr), owned_key) catch {};
    }

    /// Record the SSRC a participant publishes (best-effort; first packet wins
    /// unless overwritten).
    pub fn setSsrc(self: *MediaTransport, channel: []const u8, participant: []const u8, ssrc: u32) void {
        if (self.get(channel, participant)) |ep| ep.ssrc = ssrc;
    }

    /// Fill `out` with the bound remote addresses of every *other* connected
    /// participant in `channel` (the SFU forward set for a packet originating
    /// from `from`). Returns how many were written.
    pub fn forwardTargets(
        self: *MediaTransport,
        channel: []const u8,
        from: []const u8,
        out: []TransportAddress,
    ) usize {
        var n: usize = 0;
        var it = self.endpoints.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const sep = std.mem.indexOfScalar(u8, key, 0) orelse continue;
            if (!std.mem.eql(u8, key[0..sep], channel)) continue;
            if (std.mem.eql(u8, key[sep + 1 ..], from)) continue; // don't echo to sender
            const remote = entry.value_ptr.remote orelse continue;
            if (n >= out.len) break;
            out[n] = remote;
            n += 1;
        }
        return n;
    }

    /// Convert an ICE transport address into a STUN address (null if the IP
    /// length is neither 4 nor 16 octets).
    fn toStunAddress(a: TransportAddress) ?stun.Address {
        return switch (a.ip_len) {
            4 => .{ .ipv4 = .{ .ip = a.ip[0..4].*, .port = a.port } },
            16 => .{ .ipv6 = .{ .ip = a.ip[0..16].*, .port = a.port } },
            else => null,
        };
    }

    /// Process an inbound STUN binding request that arrived from `source` on the
    /// media socket. The request is demultiplexed to a participant via the
    /// server ufrag in its USERNAME (`<server-ufrag>:<peer-ufrag>`), its
    /// MESSAGE-INTEGRITY is verified against that endpoint's password, and on
    /// success the source is bound as the peer's media address and a binding
    /// success response (XOR-MAPPED-ADDRESS = source, MESSAGE-INTEGRITY,
    /// FINGERPRINT) is returned for the caller to send back. Returns null when
    /// the datagram is not an authenticated binding for a known endpoint (the
    /// caller drops it). The returned slice is owned by `allocator`.
    pub fn handleStunBinding(
        self: *MediaTransport,
        allocator: std.mem.Allocator,
        datagram: []const u8,
        source: TransportAddress,
    ) !?[]u8 {
        var msg = stun.decode(allocator, datagram) catch return null;
        defer msg.deinit(allocator);
        if (msg.typ != .binding_request) return null;

        // Pull the USERNAME and isolate the server ufrag (before the ':').
        var username: ?[]const u8 = null;
        for (msg.attributes) |attr| {
            if (attr == .username) username = attr.username;
        }
        const user = username orelse return null;
        const colon = std.mem.indexOfScalar(u8, user, ':') orelse user.len;
        const server_ufrag = user[0..colon];

        const owned_key = self.by_ufrag.get(server_ufrag) orelse return null;
        const ep = self.endpoints.getPtr(owned_key) orelse return null;
        // Short-term credential check (RFC 8445 §7.3): the peer keys its request
        // with the server's advertised password.
        const ok = stun.verifyMessageIntegrity(datagram, ep.pwdSlice()) catch return null;
        if (!ok) return null;

        self.rebindAddr(ep, owned_key, source); // connectivity confirmed → bind + index

        const mapped = toStunAddress(source) orelse return null;
        return try stun.buildBindingSuccessResponse(allocator, msg.transaction_id, .{
            .xor_mapped_address = mapped,
            .integrity_key = ep.pwdSlice(),
            .fingerprint = true,
        });
    }

    /// Route an inbound RTP/RTCP datagram by its UDP `source`: resolve the
    /// sending participant via the address index, meter it (`bytes_len`), then
    /// fill `out` with the bound remotes of every *other* connected participant
    /// in the same call (the SFU relay set). Returns 0 if the source is not a
    /// known bound endpoint.
    pub fn forwardFromSource(self: *MediaTransport, source: TransportAddress, bytes_len: usize, out: []TransportAddress) usize {
        const key = self.by_addr.get(addrKey(source)) orelse return 0;
        if (self.endpoints.getPtr(key)) |ep| {
            ep.rx_packets += 1;
            ep.rx_bytes += bytes_len;
        }
        const sep = std.mem.indexOfScalar(u8, key, 0) orelse return 0;
        return self.forwardTargets(key[0..sep], key[sep + 1 ..], out);
    }

    /// Per-participant transport stats snapshot (copied out so callers need not
    /// hold a lock while formatting).
    pub const ParticipantStat = struct {
        name_buf: [64]u8 = undefined,
        name_len: usize = 0,
        connected: bool = false,
        rx_packets: u64 = 0,
        rx_bytes: u64 = 0,

        pub fn name(self: *const ParticipantStat) []const u8 {
            return self.name_buf[0..self.name_len];
        }
    };

    /// Fill `out` with a stats snapshot for each participant in `channel`.
    pub fn statsForChannel(self: *MediaTransport, channel: []const u8, out: []ParticipantStat) usize {
        var n: usize = 0;
        var it = self.endpoints.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const sep = std.mem.indexOfScalar(u8, key, 0) orelse continue;
            if (!std.mem.eql(u8, key[0..sep], channel)) continue;
            if (n >= out.len) break;
            const who = key[sep + 1 ..];
            var s = ParticipantStat{
                .connected = entry.value_ptr.connected(),
                .rx_packets = entry.value_ptr.rx_packets,
                .rx_bytes = entry.value_ptr.rx_bytes,
            };
            const len = @min(who.len, s.name_buf.len);
            @memcpy(s.name_buf[0..len], who[0..len]);
            s.name_len = len;
            out[n] = s;
            n += 1;
        }
        return n;
    }

    /// Drop a participant's endpoint (on MEDIA LEAVE / disconnect).
    pub fn remove(self: *MediaTransport, channel: []const u8, participant: []const u8) void {
        var kb: [256]u8 = undefined;
        const k = compositeKey(&kb, channel, participant) orelse return;
        if (self.endpoints.fetchRemove(k)) |kv| {
            _ = self.by_ufrag.remove(kv.value.ufragSlice());
            if (kv.value.remote) |addr| _ = self.by_addr.remove(addrKey(addr));
            self.allocator.free(kv.key);
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testAddr(last_octet: u8, port: u16) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 192, 168, 0, last_octet }, port) catch unreachable;
}

test "allocate issues distinct creds and indexes by ufrag" {
    var prng = std.Random.DefaultPrng.init(0x1234);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();

    const a = try mt.allocate("#call", "alice", prng.random());
    try testing.expectEqual(@as(usize, ufrag_len), a.ufragSlice().len);
    try testing.expectEqual(@as(usize, pwd_len), a.pwdSlice().len);
    try testing.expect(!a.connected());

    const a_ufrag = a.ufrag; // copy before more inserts (pointer may move)
    _ = try mt.allocate("#call", "bob", prng.random());

    // The server ufrag demuxes back to the right participant.
    const found = mt.byServerUfrag(&a_ufrag) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &a_ufrag, found.ufragSlice());
}

test "forwardTargets returns other connected peers only" {
    var prng = std.Random.DefaultPrng.init(7);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    _ = try mt.allocate("#c", "alice", prng.random());
    _ = try mt.allocate("#c", "bob", prng.random());
    _ = try mt.allocate("#c", "carol", prng.random());
    _ = try mt.allocate("#other", "dave", prng.random());

    // No one is connected yet -> empty forward set.
    var out: [8]TransportAddress = undefined;
    try testing.expectEqual(@as(usize, 0), mt.forwardTargets("#c", "alice", &out));

    try testing.expect(mt.bindRemote("#c", "bob", testAddr(2, 5002)));
    try testing.expect(mt.bindRemote("#c", "carol", testAddr(3, 5003)));
    try testing.expect(mt.bindRemote("#other", "dave", testAddr(9, 5009)));

    // alice's packet forwards to bob+carol (connected, same channel), not dave.
    const n = mt.forwardTargets("#c", "alice", &out);
    try testing.expectEqual(@as(usize, 2), n);
    for (out[0..n]) |addr| try testing.expect(addr.port == 5002 or addr.port == 5003);
}

test "handleStunBinding authenticates, binds the peer, and answers" {
    var prng = std.Random.DefaultPrng.init(0xfeed);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    const ep = try mt.allocate("#c", "alice", prng.random());
    const ufrag = ep.ufrag;
    const pwd = ep.pwd;

    // Client builds a binding request: USERNAME=<server>:<peer>, keyed by pwd.
    var user_buf: [ufrag_len + 6]u8 = undefined;
    const user = std.fmt.bufPrint(&user_buf, "{s}:peer", .{ufrag[0..]}) catch unreachable;
    const tx: stun.TransactionId = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const req = try stun.buildBindingRequest(testing.allocator, tx, .{
        .username = user,
        .integrity_key = pwd[0..],
        .fingerprint = true,
    });
    defer testing.allocator.free(req);

    const src = testAddr(7, 50007);
    const resp = (try mt.handleStunBinding(testing.allocator, req, src)) orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(resp);

    // Peer address is now bound, and it is the SFU forward target for others.
    try testing.expect(mt.get("#c", "alice").?.connected());
    try testing.expectEqual(@as(u16, 50007), mt.get("#c", "alice").?.remote.?.port);

    // The response is a success with a verifiable MESSAGE-INTEGRITY.
    var decoded = try stun.decode(testing.allocator, resp);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(stun.MessageType.binding_success_response, decoded.typ);
    try testing.expect(try stun.verifyMessageIntegrity(resp, pwd[0..]));
}

test "handleStunBinding rejects bad integrity and unknown ufrag" {
    var prng = std.Random.DefaultPrng.init(0xabcd);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    const ep = try mt.allocate("#c", "alice", prng.random());
    const ufrag = ep.ufrag;

    const tx: stun.TransactionId = .{ 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9 };
    var user_buf: [ufrag_len + 6]u8 = undefined;
    const user = std.fmt.bufPrint(&user_buf, "{s}:peer", .{ufrag[0..]}) catch unreachable;

    // Wrong password -> integrity fails -> dropped (null), no binding.
    const bad = try stun.buildBindingRequest(testing.allocator, tx, .{
        .username = user,
        .integrity_key = "wrong-password",
        .fingerprint = true,
    });
    defer testing.allocator.free(bad);
    try testing.expect((try mt.handleStunBinding(testing.allocator, bad, testAddr(1, 1))) == null);
    try testing.expect(!mt.get("#c", "alice").?.connected());

    // Unknown ufrag -> dropped.
    const unknown = try stun.buildBindingRequest(testing.allocator, tx, .{
        .username = "ZZZZZZZZ:peer",
        .integrity_key = "whatever",
        .fingerprint = true,
    });
    defer testing.allocator.free(unknown);
    try testing.expect((try mt.handleStunBinding(testing.allocator, unknown, testAddr(1, 1))) == null);
}

test "forwardFromSource routes an RTP packet to the other peers" {
    var prng = std.Random.DefaultPrng.init(0x5151);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    _ = try mt.allocate("#c", "alice", prng.random());
    _ = try mt.allocate("#c", "bob", prng.random());
    _ = try mt.allocate("#c", "carol", prng.random());

    const alice_addr = testAddr(1, 5001);
    try testing.expect(mt.bindRemote("#c", "alice", alice_addr));
    try testing.expect(mt.bindRemote("#c", "bob", testAddr(2, 5002)));
    try testing.expect(mt.bindRemote("#c", "carol", testAddr(3, 5003)));

    // A packet from alice's bound address forwards to bob+carol, not alice.
    var out: [8]TransportAddress = undefined;
    const n = mt.forwardFromSource(alice_addr, 100, &out);
    try testing.expectEqual(@as(usize, 2), n);
    for (out[0..n]) |a| try testing.expect(a.port == 5002 or a.port == 5003);

    // An unknown source routes nowhere.
    try testing.expectEqual(@as(usize, 0), mt.forwardFromSource(testAddr(9, 9999), 100, &out));

    // After alice leaves, her address no longer resolves.
    mt.remove("#c", "alice");
    try testing.expectEqual(@as(usize, 0), mt.forwardFromSource(alice_addr, 100, &out));
}

test "remove drops the endpoint and its ufrag index" {
    var prng = std.Random.DefaultPrng.init(99);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    const ep = try mt.allocate("#c", "alice", prng.random());
    const ufrag = ep.ufrag;
    try testing.expect(mt.byServerUfrag(&ufrag) != null);
    mt.remove("#c", "alice");
    try testing.expect(mt.get("#c", "alice") == null);
    try testing.expect(mt.byServerUfrag(&ufrag) == null);
}
