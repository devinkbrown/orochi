//! MTU fragmentation and reassembly for opaque native media payloads.
//!
//! This layer is codec-agnostic: it splits and rebuilds payload bytes without
//! inspecting or decoding them.

const std = @import("std");

pub const header_len: usize = 9;

pub const Error = error{
    BufferTooSmall,
    Truncated,
    TooManyFragments,
    Incomplete,
    Mismatch,
};

const last_flag: u8 = 0x01;

pub fn fragmentCount(payload_len: usize, max_fragment_payload: usize) usize {
    if (payload_len == 0) return 1;
    if (max_fragment_payload == 0) return 0;
    return (payload_len + max_fragment_payload - 1) / max_fragment_payload;
}

pub fn fragment(
    frame_id: u32,
    payload: []const u8,
    max_fragment_payload: usize,
    out: []u8,
) Error![]const u8 {
    if (max_fragment_payload == 0 and payload.len != 0) return error.BufferTooSmall;

    const count = fragmentCount(payload.len, max_fragment_payload);
    if (count > std.math.maxInt(u16)) return error.TooManyFragments;

    const needed = header_len * count + payload.len;
    if (out.len < needed) return error.BufferTooSmall;

    var written: usize = 0;
    var offset: usize = 0;
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const remaining = payload.len - offset;
        const chunk_len = if (index + 1 == count)
            remaining
        else
            @min(max_fragment_payload, remaining);
        const end = offset + chunk_len;

        std.mem.writeInt(u32, out[written..][0..4], frame_id, .big);
        std.mem.writeInt(u16, out[written + 4 ..][0..2], @intCast(index), .big);
        std.mem.writeInt(u16, out[written + 6 ..][0..2], @intCast(count), .big);
        out[written + 8] = if (index + 1 == count) last_flag else 0;
        written += header_len;

        @memcpy(out[written .. written + chunk_len], payload[offset..end]);
        written += chunk_len;
        offset = end;
    }

    return out[0..written];
}

pub const Reassembler = struct {
    allocator: std.mem.Allocator,
    frame_id: ?u32 = null,
    frag_count: u16 = 0,
    fragments: []Fragment = &.{},
    received: []bool = &.{},
    received_count: usize = 0,
    total_len: usize = 0,
    completed: ?[]u8 = null,

    const Self = @This();

    const Fragment = struct {
        bytes: []u8 = &.{},
    };

    const Header = struct {
        frame_id: u32,
        frag_index: u16,
        frag_count: u16,
        flags: u8,
        payload: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{ .allocator = allocator };
    }

    pub fn push(self: *Self, datagram: []const u8) Error!?[]const u8 {
        self.releaseCompleted();

        const h = try parse(datagram);
        if (h.frag_count == 0) return error.Mismatch;
        if (h.frag_index >= h.frag_count) return error.Mismatch;
        if (((h.flags & last_flag) != 0) != (h.frag_index + 1 == h.frag_count)) {
            return error.Mismatch;
        }

        if (self.frame_id == null or self.frame_id.? != h.frame_id) {
            self.resetInFlight();
            try self.startFrame(h.frame_id, h.frag_count);
        } else if (self.frag_count != h.frag_count) {
            return error.Mismatch;
        }

        const idx: usize = h.frag_index;
        if (self.received[idx]) return null;

        const owned = self.allocator.dupe(u8, h.payload) catch return error.BufferTooSmall;
        self.fragments[idx].bytes = owned;
        self.received[idx] = true;
        self.received_count += 1;
        self.total_len += owned.len;

        if (self.received_count != self.frag_count) return null;

        const out = self.allocator.alloc(u8, self.total_len) catch return error.BufferTooSmall;
        var pos: usize = 0;
        for (self.fragments) |frag| {
            @memcpy(out[pos .. pos + frag.bytes.len], frag.bytes);
            pos += frag.bytes.len;
        }

        self.resetInFlight();
        self.completed = out;
        return out;
    }

    pub fn reset(self: *Self) void {
        self.releaseCompleted();
        self.resetInFlight();
    }

    pub fn deinit(self: *Self) void {
        self.reset();
        self.* = .{ .allocator = self.allocator };
    }

    fn startFrame(self: *Self, frame_id: u32, frag_count: u16) Error!void {
        const count: usize = frag_count;
        self.fragments = self.allocator.alloc(Fragment, count) catch return error.BufferTooSmall;
        self.received = self.allocator.alloc(bool, count) catch {
            self.allocator.free(self.fragments);
            self.fragments = &.{};
            return error.BufferTooSmall;
        };
        @memset(self.fragments, .{});
        @memset(self.received, false);
        self.frame_id = frame_id;
        self.frag_count = frag_count;
    }

    fn resetInFlight(self: *Self) void {
        for (self.fragments) |frag| {
            self.allocator.free(frag.bytes);
        }
        if (self.fragments.len != 0) self.allocator.free(self.fragments);
        if (self.received.len != 0) self.allocator.free(self.received);

        self.frame_id = null;
        self.frag_count = 0;
        self.fragments = &.{};
        self.received = &.{};
        self.received_count = 0;
        self.total_len = 0;
    }

    fn releaseCompleted(self: *Self) void {
        if (self.completed) |payload| {
            self.allocator.free(payload);
            self.completed = null;
        }
    }

    fn parse(datagram: []const u8) Error!Header {
        if (datagram.len < header_len) return error.Truncated;
        return .{
            .frame_id = std.mem.readInt(u32, datagram[0..4], .big),
            .frag_index = std.mem.readInt(u16, datagram[4..6], .big),
            .frag_count = std.mem.readInt(u16, datagram[6..8], .big),
            .flags = datagram[8],
            .payload = datagram[header_len..],
        };
    }
};

test "fragment count rounds up and keeps empty payload representable" {
    try std.testing.expectEqual(@as(usize, 4), fragmentCount(1000, 300));
    try std.testing.expectEqual(@as(usize, 1), fragmentCount(0, 300));
    try std.testing.expectEqual(@as(usize, 0), fragmentCount(1000, 0));
}

test "fragment then reassemble out of order" {
    var payload: [1000]u8 = undefined;
    for (&payload, 0..) |*byte, i| {
        byte.* = @intCast(i % 251);
    }

    const count = fragmentCount(payload.len, 300);
    try std.testing.expect(count >= 4);

    var encoded: [1200]u8 = undefined;
    const written = try fragment(0xAABBCCDD, &payload, 300, &encoded);

    const lengths = [_]usize{ 300, 300, 300, 100 };
    var datagrams: [4][]const u8 = undefined;
    var pos: usize = 0;
    for (&datagrams, lengths) |*datagram, payload_len| {
        datagram.* = written[pos .. pos + header_len + payload_len];
        pos += header_len + payload_len;
    }
    try std.testing.expectEqual(written.len, pos);

    var r = Reassembler.init(std.testing.allocator);
    defer r.deinit();

    try std.testing.expect(try r.push(datagrams[2]) == null);
    try std.testing.expect(try r.push(datagrams[0]) == null);
    try std.testing.expect(try r.push(datagrams[2]) == null);
    try std.testing.expect(try r.push(datagrams[3]) == null);

    const rebuilt = try r.push(datagrams[1]) orelse return error.Incomplete;
    try std.testing.expectEqualSlices(u8, &payload, rebuilt);
}

test "truncated datagram is rejected" {
    var r = Reassembler.init(std.testing.allocator);
    defer r.deinit();

    try std.testing.expectError(error.Truncated, r.push(&[_]u8{ 1, 2, 3 }));
}
