// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native kagura negative-ack helpers for Suimyaku media frames.
//!
//! This module keys retransmission and gap tracking by `kagura_frame`
//! `sequence` values: u32 frame sequence numbers that wrap at 2^32. It is
//! self-contained and std-only so it can be tested in isolation:
//!
//!     zig test src/substrate/kagura_nack.zig

const std = @import("std");

const Allocator = std.mem.Allocator;
const seq_modulus: i64 = 1 << 32;

pub const RetransmitBuffer = struct {
    allocator: Allocator,
    capacity: usize,
    packets: std.ArrayList(StoredPacket) = .empty,
    newest_ext_seq: ?i64 = null,

    pub fn init(allocator: Allocator, capacity: usize) RetransmitBuffer {
        return .{
            .allocator = allocator,
            .capacity = capacity,
        };
    }

    pub fn deinit(self: *RetransmitBuffer) void {
        for (self.packets.items) |packet| {
            self.allocator.free(packet.bytes);
        }
        self.packets.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn onSent(self: *RetransmitBuffer, seq: u32, bytes: []const u8) Allocator.Error!void {
        if (self.capacity == 0) return;

        const ext_seq = if (self.newest_ext_seq) |newest| extendSeq(seq, newest) else @as(i64, seq);
        self.newest_ext_seq = maxOptionalI64(self.newest_ext_seq, ext_seq);

        const copied = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copied);

        if (self.findExt(ext_seq)) |index| {
            self.allocator.free(self.packets.items[index].bytes);
            self.packets.items[index].bytes = copied;
            return;
        }

        var index: usize = 0;
        while (index < self.packets.items.len and self.packets.items[index].ext_seq < ext_seq) : (index += 1) {}
        try self.packets.insert(self.allocator, index, .{
            .seq = seq,
            .ext_seq = ext_seq,
            .bytes = copied,
        });

        while (self.packets.items.len > self.capacity) {
            const old = self.packets.orderedRemove(0);
            self.allocator.free(old.bytes);
        }
    }

    pub fn lookup(self: RetransmitBuffer, seq: u32) ?[]const u8 {
        var index = self.packets.items.len;
        while (index > 0) {
            index -= 1;
            const packet = self.packets.items[index];
            if (packet.seq == seq) return packet.bytes;
        }
        return null;
    }

    pub fn len(self: RetransmitBuffer) usize {
        return self.packets.items.len;
    }

    fn findExt(self: RetransmitBuffer, ext_seq: i64) ?usize {
        for (self.packets.items, 0..) |packet, index| {
            if (packet.ext_seq == ext_seq) return index;
        }
        return null;
    }
};

pub const GapTracker = struct {
    allocator: Allocator,
    received: std.AutoHashMap(i64, void),
    missing_ext: std.ArrayList(i64) = .empty,
    highest_ext_seq: ?i64 = null,

    pub fn init(allocator: Allocator) GapTracker {
        return .{
            .allocator = allocator,
            .received = std.AutoHashMap(i64, void).init(allocator),
        };
    }

    pub fn deinit(self: *GapTracker) void {
        self.received.deinit();
        self.missing_ext.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn onReceived(self: *GapTracker, seq: u32) Allocator.Error!void {
        const ext_seq = if (self.highest_ext_seq) |highest| extendSeq(seq, highest) else @as(i64, seq);

        try self.received.put(ext_seq, {});
        self.removeMissing(ext_seq);

        if (self.highest_ext_seq) |highest| {
            if (ext_seq > highest) {
                var missing_seq = highest + 1;
                while (missing_seq < ext_seq) : (missing_seq += 1) {
                    if (!self.received.contains(missing_seq)) {
                        try self.missing_ext.append(self.allocator, missing_seq);
                    }
                }
                self.highest_ext_seq = ext_seq;
            }
        } else {
            self.highest_ext_seq = ext_seq;
        }
    }

    pub fn missing(self: *const GapTracker, out: []u32) usize {
        const count = @min(out.len, self.missing_ext.items.len);
        for (self.missing_ext.items[0..count], 0..) |ext_seq, index| {
            out[index] = seqFromExt(ext_seq);
        }
        return count;
    }

    fn removeMissing(self: *GapTracker, ext_seq: i64) void {
        for (self.missing_ext.items, 0..) |missing_ext, index| {
            if (missing_ext == ext_seq) {
                _ = self.missing_ext.orderedRemove(index);
                return;
            }
        }
    }
};

const StoredPacket = struct {
    seq: u32,
    ext_seq: i64,
    bytes: []u8,
};

fn extendSeq(seq: u32, reference: i64) i64 {
    const base_cycle = @divFloor(reference, seq_modulus);
    var best = @as(i64, seq) + base_cycle * seq_modulus;
    var best_distance = absI64(best - reference);

    const candidates = [_]i64{
        best - seq_modulus,
        best + seq_modulus,
    };
    for (candidates) |candidate| {
        const distance = absI64(candidate - reference);
        if (distance < best_distance or (distance == best_distance and candidate > best)) {
            best = candidate;
            best_distance = distance;
        }
    }
    return best;
}

fn seqFromExt(ext_seq: i64) u32 {
    const wrapped = @mod(ext_seq, seq_modulus);
    return @intCast(wrapped);
}

fn absI64(value: i64) i64 {
    return if (value < 0) -value else value;
}

fn maxOptionalI64(current: ?i64, value: i64) ?i64 {
    if (current) |existing| return @max(existing, value);
    return value;
}

test "retransmit buffer stores and looks up packets" {
    const allocator = std.testing.allocator;
    var buffer = RetransmitBuffer.init(allocator, 3);
    defer buffer.deinit();

    try buffer.onSent(10, "frame10");
    try buffer.onSent(11, "frame11");

    try std.testing.expectEqual(@as(usize, 2), buffer.len());
    try std.testing.expectEqualSlices(u8, "frame10", buffer.lookup(10).?);
    try std.testing.expectEqualSlices(u8, "frame11", buffer.lookup(11).?);
    try std.testing.expectEqual(@as(?[]const u8, null), buffer.lookup(12));
}

test "retransmit buffer evicts beyond capacity and misses after eviction" {
    const allocator = std.testing.allocator;
    var buffer = RetransmitBuffer.init(allocator, 2);
    defer buffer.deinit();

    try buffer.onSent(7, "pkt7");
    try buffer.onSent(8, "pkt8");
    try buffer.onSent(9, "pkt9");

    try std.testing.expectEqual(@as(usize, 2), buffer.len());
    try std.testing.expectEqual(@as(?[]const u8, null), buffer.lookup(7));
    try std.testing.expectEqualSlices(u8, "pkt8", buffer.lookup(8).?);
    try std.testing.expectEqualSlices(u8, "pkt9", buffer.lookup(9).?);
}

test "retransmit buffer replaces duplicate sequence" {
    const allocator = std.testing.allocator;
    var buffer = RetransmitBuffer.init(allocator, 2);
    defer buffer.deinit();

    try buffer.onSent(42, "old");
    try buffer.onSent(42, "new");

    try std.testing.expectEqual(@as(usize, 1), buffer.len());
    try std.testing.expectEqualSlices(u8, "new", buffer.lookup(42).?);
}

test "gap tracker detects and clears a gap" {
    const allocator = std.testing.allocator;
    var tracker = GapTracker.init(allocator);
    defer tracker.deinit();

    try tracker.onReceived(100);
    try tracker.onReceived(104);

    var out: [8]u32 = undefined;
    var count = tracker.missing(&out);
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 101, 102, 103 }, out[0..count]);

    try tracker.onReceived(102);

    count = tracker.missing(&out);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 101, 103 }, out[0..count]);
}

test "gap tracker handles u32 wrap without spurious gaps" {
    const allocator = std.testing.allocator;
    var tracker = GapTracker.init(allocator);
    defer tracker.deinit();

    try tracker.onReceived(0xffff_fffe);
    try tracker.onReceived(0xffff_ffff);
    try tracker.onReceived(0);
    try tracker.onReceived(1);

    var out: [8]u32 = undefined;
    const count = tracker.missing(&out);
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "gap tracker detects missing packets across u32 wrap" {
    const allocator = std.testing.allocator;
    var tracker = GapTracker.init(allocator);
    defer tracker.deinit();

    try tracker.onReceived(0xffff_fffe);
    try tracker.onReceived(1);

    var out: [8]u32 = undefined;
    const count = tracker.missing(&out);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 0xffff_ffff, 0 }, out[0..count]);
}

test "gap tracker does not treat u16-sized rollover as u32 wrap" {
    const allocator = std.testing.allocator;
    var tracker = GapTracker.init(allocator);
    defer tracker.deinit();

    try tracker.onReceived(65534);
    try tracker.onReceived(1);

    var out: [8]u32 = undefined;
    const count = tracker.missing(&out);
    try std.testing.expectEqual(@as(usize, 0), count);
}
