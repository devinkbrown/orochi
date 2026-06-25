// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RTP Generic NACK helpers and a bounded sender retransmit buffer.
//!
//! Generic NACK is the RTP Feedback Control Information format from RFC 4585:
//! every four-byte block contains a Packet ID (PID) and a 16-bit bitmask of
//! the following packets (BLP). This module is self-contained and std-only so
//! it can be tested in isolation:
//!
//!     zig test src/substrate/rtp_nack.zig

const std = @import("std");

const Allocator = std.mem.Allocator;
const seq_modulus: i64 = 1 << 16;

pub const NackError = error{
    InvalidFciLength,
};

pub const NackBlock = struct {
    pid: u16,
    blp: u16 = 0,

    pub fn contains(self: NackBlock, seq: u16) bool {
        if (seq == self.pid) return true;
        const delta = seqDistanceForward(self.pid, seq);
        if (delta == 0 or delta > 16) return false;
        const bit: u4 = @intCast(delta - 1);
        return (self.blp & (@as(u16, 1) << bit)) != 0;
    }

    pub fn missingCount(self: NackBlock) usize {
        return 1 + @popCount(self.blp);
    }
};

pub const Receiver = struct {
    allocator: Allocator,
    received: std.AutoHashMap(i64, void),
    missing: std.AutoHashMap(i64, void),
    max_ext_seq: ?i64 = null,
    blocks: std.ArrayList(NackBlock) = .empty,
    ext_scratch: std.ArrayList(i64) = .empty,
    fci_scratch: std.ArrayList(u8) = .empty,

    pub fn init(allocator: Allocator) Receiver {
        return .{
            .allocator = allocator,
            .received = std.AutoHashMap(i64, void).init(allocator),
            .missing = std.AutoHashMap(i64, void).init(allocator),
        };
    }

    pub fn deinit(self: *Receiver) void {
        self.received.deinit();
        self.missing.deinit();
        self.blocks.deinit(self.allocator);
        self.ext_scratch.deinit(self.allocator);
        self.fci_scratch.deinit(self.allocator);
        self.* = undefined;
    }

    /// Records a received RTP sequence number and returns the current Generic
    /// NACK blocks for packets missing up to the highest packet seen.
    pub fn onReceived(self: *Receiver, seq: u16) Allocator.Error![]const NackBlock {
        const ext_seq = if (self.max_ext_seq) |max| extendSeq(seq, max) else @as(i64, seq);
        try self.received.put(ext_seq, {});
        _ = self.missing.remove(ext_seq);

        if (self.max_ext_seq) |max| {
            if (ext_seq > max) {
                var missing_seq = max + 1;
                while (missing_seq < ext_seq) : (missing_seq += 1) {
                    if (!self.received.contains(missing_seq)) {
                        try self.missing.put(missing_seq, {});
                    }
                }
                self.max_ext_seq = ext_seq;
            }
        } else {
            self.max_ext_seq = ext_seq;
        }

        return self.currentNacks();
    }

    pub fn currentNacks(self: *Receiver) Allocator.Error![]const NackBlock {
        self.ext_scratch.clearRetainingCapacity();
        var iter = self.missing.keyIterator();
        while (iter.next()) |seq| {
            try self.ext_scratch.append(self.allocator, seq.*);
        }
        std.mem.sort(i64, self.ext_scratch.items, {}, std.sort.asc(i64));
        return buildBlocksFromExt(self.allocator, self.ext_scratch.items, &self.blocks);
    }

    pub fn currentFci(self: *Receiver) Allocator.Error![]const u8 {
        const nacks = try self.currentNacks();
        self.fci_scratch.clearRetainingCapacity();
        try appendNackFci(self.allocator, &self.fci_scratch, nacks);
        return self.fci_scratch.items;
    }
};

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

    pub fn onSent(self: *RetransmitBuffer, seq: u16, bytes: []const u8) Allocator.Error!void {
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

    pub fn lookup(self: RetransmitBuffer, seq: u16) ?[]const u8 {
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

const StoredPacket = struct {
    seq: u16,
    ext_seq: i64,
    bytes: []u8,
};

pub fn buildNackBlocks(allocator: Allocator, missing_seqs: []const u16) Allocator.Error![]NackBlock {
    var ext: std.ArrayList(i64) = .empty;
    defer ext.deinit(allocator);

    try ext.ensureTotalCapacity(allocator, missing_seqs.len);
    for (missing_seqs, 0..) |seq, index| {
        const ext_seq = if (index == 0) @as(i64, seq) else extendSeq(seq, ext.items[index - 1]);
        ext.appendAssumeCapacity(ext_seq);
    }
    std.mem.sort(i64, ext.items, {}, std.sort.asc(i64));

    var blocks: std.ArrayList(NackBlock) = .empty;
    errdefer blocks.deinit(allocator);
    _ = try buildBlocksFromExt(allocator, ext.items, &blocks);
    return blocks.toOwnedSlice(allocator);
}

pub fn encodeNackFci(allocator: Allocator, blocks: []const NackBlock) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendNackFci(allocator, &out, blocks);
    return out.toOwnedSlice(allocator);
}

pub fn parseNackFci(allocator: Allocator, fci: []const u8) (Allocator.Error || NackError)![]u16 {
    if (fci.len % 4 != 0) return error.InvalidFciLength;

    var out: std.ArrayList(u16) = .empty;
    errdefer out.deinit(allocator);

    var offset: usize = 0;
    while (offset < fci.len) : (offset += 4) {
        const block = NackBlock{
            .pid = readU16(fci[offset .. offset + 2]),
            .blp = readU16(fci[offset + 2 .. offset + 4]),
        };
        try out.append(allocator, block.pid);
        var bit: u5 = 0;
        while (bit < 16) : (bit += 1) {
            if ((block.blp & (@as(u16, 1) << @as(u4, @intCast(bit)))) != 0) {
                try out.append(allocator, wrapAdd(block.pid, @as(u16, bit) + 1));
            }
        }
    }

    return out.toOwnedSlice(allocator);
}

fn buildBlocksFromExt(
    allocator: Allocator,
    missing_ext: []const i64,
    blocks: *std.ArrayList(NackBlock),
) Allocator.Error![]const NackBlock {
    blocks.clearRetainingCapacity();
    if (missing_ext.len == 0) return blocks.items;

    var index: usize = 0;
    while (index < missing_ext.len) {
        const pid_ext = missing_ext[index];
        var block = NackBlock{ .pid = seqFromExt(pid_ext), .blp = 0 };
        index += 1;

        while (index < missing_ext.len) {
            const delta = missing_ext[index] - pid_ext;
            if (delta == 0) {
                index += 1;
                continue;
            }
            if (delta < 1 or delta > 16) break;
            const bit: u4 = @intCast(delta - 1);
            block.blp |= @as(u16, 1) << bit;
            index += 1;
        }

        try blocks.append(allocator, block);
    }

    return blocks.items;
}

fn appendNackFci(allocator: Allocator, out: *std.ArrayList(u8), blocks: []const NackBlock) Allocator.Error!void {
    try out.ensureUnusedCapacity(allocator, blocks.len * 4);
    for (blocks) |block| {
        var bytes: [4]u8 = undefined;
        writeU16(bytes[0..2], block.pid);
        writeU16(bytes[2..4], block.blp);
        out.appendSliceAssumeCapacity(&bytes);
    }
}

fn extendSeq(seq: u16, reference: i64) i64 {
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

fn seqFromExt(ext_seq: i64) u16 {
    const wrapped = @mod(ext_seq, seq_modulus);
    return @intCast(wrapped);
}

fn wrapAdd(seq: u16, delta: u16) u16 {
    return @intCast((@as(u32, seq) + @as(u32, delta)) & 0xffff);
}

fn seqDistanceForward(from: u16, to: u16) u16 {
    return @intCast((@as(u32, to) -% @as(u32, from)) & 0xffff);
}

fn readU16(bytes: []const u8) u16 {
    std.debug.assert(bytes.len == 2);
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}

fn writeU16(bytes: []u8, value: u16) void {
    std.debug.assert(bytes.len == 2);
    bytes[0] = @intCast(value >> 8);
    bytes[1] = @intCast(value & 0xff);
}

fn absI64(value: i64) i64 {
    return if (value < 0) -value else value;
}

fn maxOptionalI64(current: ?i64, value: i64) ?i64 {
    if (current) |existing| return @max(existing, value);
    return value;
}

test "gap detection produces one PID plus BLP block" {
    const allocator = std.testing.allocator;
    var receiver = Receiver.init(allocator);
    defer receiver.deinit();

    try std.testing.expectEqual(@as(usize, 0), (try receiver.onReceived(100)).len);
    const blocks = try receiver.onReceived(104);

    try std.testing.expectEqual(@as(usize, 1), blocks.len);
    try std.testing.expectEqual(@as(u16, 101), blocks[0].pid);
    try std.testing.expectEqual(@as(u16, 0b0000_0000_0000_0011), blocks[0].blp);
    try std.testing.expect(blocks[0].contains(101));
    try std.testing.expect(blocks[0].contains(102));
    try std.testing.expect(blocks[0].contains(103));
    try std.testing.expect(!blocks[0].contains(104));
}

test "gap detection spanning more than 17 packets produces multiple FCI blocks" {
    const allocator = std.testing.allocator;
    var receiver = Receiver.init(allocator);
    defer receiver.deinit();

    _ = try receiver.onReceived(1000);
    const blocks = try receiver.onReceived(1022);

    try std.testing.expectEqual(@as(usize, 2), blocks.len);
    try std.testing.expectEqual(@as(u16, 1001), blocks[0].pid);
    try std.testing.expectEqual(@as(u16, 0xffff), blocks[0].blp);
    try std.testing.expectEqual(@as(u16, 1018), blocks[1].pid);
    try std.testing.expectEqual(@as(u16, 0b0000_0000_0000_0111), blocks[1].blp);
}

test "encode and parse Generic NACK FCI deterministically" {
    const allocator = std.testing.allocator;
    const missing = [_]u16{ 10, 11, 12, 30, 31, 65535, 0 };

    const blocks = try buildNackBlocks(allocator, &missing);
    defer allocator.free(blocks);
    try std.testing.expectEqual(@as(usize, 2), blocks.len);

    const fci = try encodeNackFci(allocator, blocks);
    defer allocator.free(fci);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xff, 0xff, 0x1c, 0x01,
        0x00, 0x1e, 0x00, 0x01,
    }, fci);

    const parsed = try parseNackFci(allocator, fci);
    defer allocator.free(parsed);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 65535, 0, 10, 11, 12, 30, 31 }, parsed);
}

test "parse rejects malformed FCI length" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidFciLength, parseNackFci(allocator, &[_]u8{ 1, 2, 3 }));
}

test "retransmit buffer returns stored packets and evicts beyond capacity" {
    const allocator = std.testing.allocator;
    var buffer = RetransmitBuffer.init(allocator, 3);
    defer buffer.deinit();

    try buffer.onSent(7, "pkt7");
    try buffer.onSent(8, "pkt8");
    try buffer.onSent(9, "pkt9");
    try std.testing.expectEqualSlices(u8, "pkt8", buffer.lookup(8).?);

    try buffer.onSent(10, "pkt10");
    try std.testing.expectEqual(@as(usize, 3), buffer.len());
    try std.testing.expectEqual(@as(?[]const u8, null), buffer.lookup(7));
    try std.testing.expectEqualSlices(u8, "pkt10", buffer.lookup(10).?);
}

test "retransmit buffer replaces duplicate extended sequence packet" {
    const allocator = std.testing.allocator;
    var buffer = RetransmitBuffer.init(allocator, 2);
    defer buffer.deinit();

    try buffer.onSent(42, "old");
    try buffer.onSent(42, "new");
    try std.testing.expectEqual(@as(usize, 1), buffer.len());
    try std.testing.expectEqualSlices(u8, "new", buffer.lookup(42).?);
}

test "sequence wrap gaps and retransmit lookup are deterministic" {
    const allocator = std.testing.allocator;
    var receiver = Receiver.init(allocator);
    defer receiver.deinit();

    _ = try receiver.onReceived(65534);
    const blocks = try receiver.onReceived(1);
    try std.testing.expectEqual(@as(usize, 1), blocks.len);
    try std.testing.expectEqual(@as(u16, 65535), blocks[0].pid);
    try std.testing.expectEqual(@as(u16, 0x0001), blocks[0].blp);

    const fci = try receiver.currentFci();
    const parsed = try parseNackFci(allocator, fci);
    defer allocator.free(parsed);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 65535, 0 }, parsed);

    var buffer = RetransmitBuffer.init(allocator, 2);
    defer buffer.deinit();
    try buffer.onSent(65535, "last");
    try buffer.onSent(0, "zero");
    try buffer.onSent(1, "one");
    try std.testing.expectEqual(@as(?[]const u8, null), buffer.lookup(65535));
    try std.testing.expectEqualSlices(u8, "zero", buffer.lookup(0).?);
    try std.testing.expectEqualSlices(u8, "one", buffer.lookup(1).?);
}
