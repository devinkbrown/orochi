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

pub const ufrag_len: usize = 8;
pub const pwd_len: usize = 24;

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

pub const MediaTransport = struct {
    allocator: std.mem.Allocator,
    /// Composite "channel\x00participant" -> Endpoint.
    endpoints: std.StringHashMapUnmanaged(Endpoint) = .empty,
    /// Server ufrag -> composite key, for STUN binding demultiplexing.
    by_ufrag: std.StringHashMapUnmanaged([]const u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) MediaTransport {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MediaTransport) void {
        var it = self.endpoints.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.endpoints.deinit(self.allocator);
        self.by_ufrag.deinit(self.allocator);
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

    /// Bind the peer's media address after a successful connectivity check.
    pub fn bindRemote(self: *MediaTransport, channel: []const u8, participant: []const u8, addr: TransportAddress) bool {
        const ep = self.get(channel, participant) orelse return false;
        ep.remote = addr;
        return true;
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

    /// Drop a participant's endpoint (on MEDIA LEAVE / disconnect).
    pub fn remove(self: *MediaTransport, channel: []const u8, participant: []const u8) void {
        var kb: [256]u8 = undefined;
        const k = compositeKey(&kb, channel, participant) orelse return;
        if (self.endpoints.fetchRemove(k)) |kv| {
            _ = self.by_ufrag.remove(kv.value.ufragSlice());
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
