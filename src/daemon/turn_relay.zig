//! TURN relay allocation model for Orochi's media relay plane.
//!
//! This module is deliberately socket-free. The daemon owns UDP/TCP sockets,
//! STUN authentication, and packet I/O; this file only tracks allocation state,
//! permissions, channel bindings, relayed-port lookup, lifetime expiry, and the
//! small ChannelData envelope used on the data path.

const std = @import("std");

pub const min_channel: u16 = 0x4000;
pub const max_channel: u16 = 0x7fff;

pub const Error = std.mem.Allocator.Error || error{
    AllocationExists,
    AllocationLimit,
    RelayedPortInUse,
    UnknownAllocation,
    InvalidChannel,
    BufferTooSmall,
    PayloadTooLarge,
    TruncatedFrame,
    UnsupportedFraming,
};

pub const IpFamily = enum(u8) {
    v4 = 4,
    v6 = 6,
};

pub const PeerIp = struct {
    family: IpFamily,
    bytes: [16]u8,

    pub fn v4(octets: [4]u8) PeerIp {
        var bytes: [16]u8 = .{0} ** 16;
        @memcpy(bytes[0..4], &octets);
        return .{ .family = .v4, .bytes = bytes };
    }

    pub fn v6(bytes: [16]u8) PeerIp {
        return .{ .family = .v6, .bytes = bytes };
    }
};

pub const Peer = struct {
    ip: PeerIp,
    port: u16,

    pub fn v4(octets: [4]u8, port: u16) Peer {
        return .{ .ip = PeerIp.v4(octets), .port = port };
    }

    pub fn v6(bytes: [16]u8, port: u16) Peer {
        return .{ .ip = PeerIp.v6(bytes), .port = port };
    }
};

pub const RelayedAddress = struct {
    port: u16,
};

pub const ChannelData = struct {
    channel: u16,
    payload: []const u8,
    consumed: usize,
};

pub const IndicationKind = enum {
    send,
    data,
};

pub const Indication = struct {
    kind: IndicationKind,
    peer: Peer,
    payload: []const u8,
};

pub const Allocation = struct {
    client_key: []const u8,
    relayed_port: u16,
    expires_at_ms: u64,
    permissions: std.StringHashMapUnmanaged(void) = .empty,
    channels: std.AutoHashMapUnmanaged(u16, Peer) = .empty,

    fn init(client_key: []const u8, lifetime_ms: u64, relayed_port: u16) Allocation {
        return .{
            .client_key = client_key,
            .relayed_port = relayed_port,
            .expires_at_ms = lifetime_ms,
        };
    }

    fn deinit(self: *Allocation, allocator: std.mem.Allocator) void {
        var pit = self.permissions.keyIterator();
        while (pit.next()) |key_ptr| allocator.free(key_ptr.*);
        self.permissions.deinit(allocator);
        self.channels.deinit(allocator);
        self.* = undefined;
    }

    pub fn refresh(self: *Allocation, lifetime_ms: u64) void {
        self.expires_at_ms = lifetime_ms;
    }

    pub fn addPermission(
        self: *Allocation,
        allocator: std.mem.Allocator,
        peer_ip: PeerIp,
    ) std.mem.Allocator.Error!void {
        var raw: [peer_ip_key_len]u8 = undefined;
        const key = peerIpKey(&raw, peer_ip);
        const owned = try allocator.dupe(u8, key);
        errdefer allocator.free(owned);

        const gop = try self.permissions.getOrPut(allocator, owned);
        if (gop.found_existing) {
            allocator.free(owned);
            return;
        }
        gop.value_ptr.* = {};
    }

    pub fn hasPermission(self: *const Allocation, peer_ip: PeerIp) bool {
        var raw: [peer_ip_key_len]u8 = undefined;
        return self.permissions.contains(peerIpKey(&raw, peer_ip));
    }

    pub fn canRelayTo(self: *const Allocation, peer: Peer) bool {
        return self.hasPermission(peer.ip);
    }

    pub fn channelBind(
        self: *Allocation,
        allocator: std.mem.Allocator,
        channel_num: u16,
        peer: Peer,
    ) Error!void {
        if (!validChannel(channel_num)) return error.InvalidChannel;
        try self.channels.put(allocator, channel_num, peer);
    }

    pub fn channelPeer(self: *const Allocation, channel_num: u16) ?Peer {
        if (!validChannel(channel_num)) return null;
        return self.channels.get(channel_num);
    }
};

pub const AllocationTable = struct {
    max_allocations: usize,
    allocations: std.StringHashMapUnmanaged(Allocation) = .empty,
    relayed_ports: std.AutoHashMapUnmanaged(u16, []const u8) = .empty,

    pub fn init(max_allocations: usize) AllocationTable {
        return .{ .max_allocations = max_allocations };
    }

    pub fn deinit(self: *AllocationTable, allocator: std.mem.Allocator) void {
        var it = self.allocations.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(allocator);
            allocator.free(entry.key_ptr.*);
        }
        self.allocations.deinit(allocator);
        self.relayed_ports.deinit(allocator);
        self.* = undefined;
    }

    pub fn allocate(
        self: *AllocationTable,
        allocator: std.mem.Allocator,
        client_key: []const u8,
        lifetime_ms: u64,
        relayed_port: u16,
    ) Error!*Allocation {
        if (self.allocations.contains(client_key)) return error.AllocationExists;
        if (self.relayed_ports.contains(relayed_port)) return error.RelayedPortInUse;
        if (self.allocations.count() >= self.max_allocations) return error.AllocationLimit;

        const owned_key = try allocator.dupe(u8, client_key);
        errdefer allocator.free(owned_key);

        var inserted_allocation = false;
        errdefer {
            if (inserted_allocation) _ = self.allocations.remove(owned_key);
        }

        const gop = try self.allocations.getOrPut(allocator, owned_key);
        if (gop.found_existing) return error.AllocationExists;
        inserted_allocation = true;
        gop.value_ptr.* = Allocation.init(owned_key, lifetime_ms, relayed_port);

        try self.relayed_ports.put(allocator, relayed_port, owned_key);
        return gop.value_ptr;
    }

    pub fn refresh(self: *AllocationTable, client_key: []const u8, lifetime_ms: u64) Error!*Allocation {
        const allocation = self.allocations.getPtr(client_key) orelse return error.UnknownAllocation;
        allocation.refresh(lifetime_ms);
        return allocation;
    }

    pub fn addPermission(
        self: *AllocationTable,
        allocator: std.mem.Allocator,
        client_key: []const u8,
        peer_ip: PeerIp,
    ) Error!void {
        const allocation = self.allocations.getPtr(client_key) orelse return error.UnknownAllocation;
        try allocation.addPermission(allocator, peer_ip);
    }

    pub fn checkPermission(self: *const AllocationTable, client_key: []const u8, peer_ip: PeerIp) bool {
        const allocation = self.allocations.get(client_key) orelse return false;
        return allocation.hasPermission(peer_ip);
    }

    pub fn channelBind(
        self: *AllocationTable,
        allocator: std.mem.Allocator,
        client_key: []const u8,
        channel_num: u16,
        peer: Peer,
    ) Error!void {
        const allocation = self.allocations.getPtr(client_key) orelse return error.UnknownAllocation;
        try allocation.channelBind(allocator, channel_num, peer);
    }

    pub fn channelPeer(self: *const AllocationTable, client_key: []const u8, channel_num: u16) ?Peer {
        const allocation = self.allocations.get(client_key) orelse return null;
        return allocation.channelPeer(channel_num);
    }

    pub fn lookupRelayedPort(self: *AllocationTable, relayed_port: u16) ?*Allocation {
        const client_key = self.relayed_ports.get(relayed_port) orelse return null;
        return self.allocations.getPtr(client_key);
    }

    pub fn lookupRelayedAddress(self: *AllocationTable, addr: RelayedAddress) ?*Allocation {
        return self.lookupRelayedPort(addr.port);
    }

    pub fn expire(self: *AllocationTable, allocator: std.mem.Allocator, now_ms: u64) usize {
        var doomed: std.ArrayListUnmanaged([]const u8) = .empty;
        defer doomed.deinit(allocator);

        var it = self.allocations.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expires_at_ms <= now_ms) {
                doomed.append(allocator, entry.key_ptr.*) catch break;
            }
        }

        var removed: usize = 0;
        for (doomed.items) |client_key| {
            if (self.removeAllocation(allocator, client_key)) removed += 1;
        }
        return removed;
    }

    pub fn count(self: *const AllocationTable) usize {
        return self.allocations.count();
    }

    fn removeAllocation(
        self: *AllocationTable,
        allocator: std.mem.Allocator,
        client_key: []const u8,
    ) bool {
        if (self.allocations.fetchRemove(client_key)) |removed| {
            _ = self.relayed_ports.remove(removed.value.relayed_port);
            var allocation = removed.value;
            allocation.deinit(allocator);
            allocator.free(removed.key);
            return true;
        }
        return false;
    }
};

pub fn encodeChannelData(out: []u8, channel: u16, payload: []const u8) Error!usize {
    if (!validChannel(channel)) return error.InvalidChannel;
    if (payload.len > std.math.maxInt(u16)) return error.PayloadTooLarge;
    if (out.len < 4 + payload.len) return error.BufferTooSmall;

    writeU16(out[0..2], channel);
    writeU16(out[2..4], @intCast(payload.len));
    @memcpy(out[4..][0..payload.len], payload);
    return 4 + payload.len;
}

pub fn parseChannelData(bytes: []const u8) Error!ChannelData {
    if (bytes.len < 4) return error.TruncatedFrame;
    const channel = readU16(bytes[0..2]);
    if (!validChannel(channel)) return error.InvalidChannel;
    const payload_len = readU16(bytes[2..4]);
    const end = 4 + @as(usize, payload_len);
    if (bytes.len < end) return error.TruncatedFrame;
    return .{ .channel = channel, .payload = bytes[4..end], .consumed = end };
}

pub fn makeSendIndication(peer: Peer, payload: []const u8) Indication {
    return .{ .kind = .send, .peer = peer, .payload = payload };
}

pub fn makeDataIndication(peer: Peer, payload: []const u8) Indication {
    return .{ .kind = .data, .peer = peer, .payload = payload };
}

pub fn encodeIndication(_: []u8, indication: Indication) Error!usize {
    return switch (indication.kind) {
        .send => error.UnsupportedFraming,
        .data => error.UnsupportedFraming,
    };
}

const peer_ip_key_len: usize = 17;

fn peerIpKey(out: *[peer_ip_key_len]u8, peer_ip: PeerIp) []const u8 {
    out[0] = @intFromEnum(peer_ip.family);
    @memcpy(out[1..], &peer_ip.bytes);
    return out[0..];
}

fn validChannel(channel: u16) bool {
    return channel >= min_channel and channel <= max_channel;
}

fn writeU16(out: []u8, value: u16) void {
    out[0] = @intCast(value >> 8);
    out[1] = @intCast(value & 0xff);
}

fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}

test "allocate refresh lookup and expire" {
    const allocator = std.testing.allocator;
    var table = AllocationTable.init(2);
    defer table.deinit(allocator);

    const a = try table.allocate(allocator, "client-a", 100, 49152);
    try std.testing.expectEqual(@as(u16, 49152), a.relayed_port);
    try std.testing.expect(table.lookupRelayedAddress(.{ .port = 49152 }) != null);

    _ = try table.refresh("client-a", 250);
    try std.testing.expectEqual(@as(u64, 250), table.lookupRelayedPort(49152).?.expires_at_ms);
    try std.testing.expectEqual(@as(usize, 0), table.expire(allocator, 249));
    try std.testing.expectEqual(@as(usize, 1), table.expire(allocator, 250));
    try std.testing.expectEqual(@as(usize, 0), table.count());
    try std.testing.expect(table.lookupRelayedPort(49152) == null);
}

test "bounded allocations and relayed port collision" {
    const allocator = std.testing.allocator;
    var table = AllocationTable.init(1);
    defer table.deinit(allocator);

    _ = try table.allocate(allocator, "client-a", 100, 50000);
    try std.testing.expectError(error.AllocationLimit, table.allocate(allocator, "client-b", 100, 50001));
    try std.testing.expectError(error.AllocationExists, table.allocate(allocator, "client-a", 100, 50002));
    try std.testing.expectError(error.RelayedPortInUse, table.allocate(allocator, "client-c", 100, 50000));
}

test "permission gating" {
    const allocator = std.testing.allocator;
    var table = AllocationTable.init(4);
    defer table.deinit(allocator);

    _ = try table.allocate(allocator, "client-a", 1000, 51000);
    const allowed = PeerIp.v4(.{ 203, 0, 113, 10 });
    const denied = PeerIp.v4(.{ 203, 0, 113, 11 });

    try std.testing.expect(!table.checkPermission("client-a", allowed));
    try table.addPermission(allocator, "client-a", allowed);
    try std.testing.expect(table.checkPermission("client-a", allowed));
    try std.testing.expect(!table.checkPermission("client-a", denied));
    try std.testing.expect(table.lookupRelayedPort(51000).?.canRelayTo(Peer.v4(.{ 203, 0, 113, 10 }, 4000)));
}

test "channel bind and channeldata round trip" {
    const allocator = std.testing.allocator;
    var table = AllocationTable.init(4);
    defer table.deinit(allocator);

    _ = try table.allocate(allocator, "client-a", 1000, 52000);
    const peer = Peer.v4(.{ 198, 51, 100, 7 }, 3478);
    try table.channelBind(allocator, "client-a", min_channel, peer);
    try std.testing.expectEqual(peer, table.channelPeer("client-a", min_channel).?);
    try std.testing.expectError(error.InvalidChannel, table.channelBind(allocator, "client-a", 0x3000, peer));

    var buf: [64]u8 = undefined;
    const written = try encodeChannelData(&buf, min_channel, "media");
    const parsed = try parseChannelData(buf[0..written]);
    try std.testing.expectEqual(min_channel, parsed.channel);
    try std.testing.expectEqual(@as(usize, written), parsed.consumed);
    try std.testing.expectEqualSlices(u8, "media", parsed.payload);
}

test "lifetime expiry removes nested permissions and channels" {
    const allocator = std.testing.allocator;
    var table = AllocationTable.init(4);
    defer table.deinit(allocator);

    _ = try table.allocate(allocator, "soon", 10, 53000);
    _ = try table.allocate(allocator, "later", 20, 53001);
    try table.addPermission(allocator, "soon", PeerIp.v4(.{ 192, 0, 2, 1 }));
    try table.channelBind(allocator, "soon", 0x4001, Peer.v4(.{ 192, 0, 2, 1 }, 5004));

    try std.testing.expectEqual(@as(usize, 1), table.expire(allocator, 10));
    try std.testing.expect(table.lookupRelayedPort(53000) == null);
    try std.testing.expect(table.lookupRelayedPort(53001) != null);
    try std.testing.expectEqual(@as(usize, 1), table.expire(allocator, 20));
}
