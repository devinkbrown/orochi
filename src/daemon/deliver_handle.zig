// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pooled outbound delivery buffers for cross-shard handoff.
//!
//! A reactor may need to deliver IRC bytes to a client pinned to another shard.
//! The sender cannot borrow or mutate the target reactor's send queue directly,
//! so it copies the bytes into a pooled `DeliverBuf` and sends a small POD
//! `DeliverMsg` through the shard mailbox. The target reactor drains the bytes
//! under its own ownership and releases the buffer back to the pool.

const std = @import("std");
const client = @import("client.zig");

pub const ClientId = client.ClientId;

pub const max_bytes: usize = 4096;
const invalid_index: u32 = std.math.maxInt(u32);

pub const DeliverBuf = struct {
    data: [max_bytes]u8 = @splat(0),
    len: usize = 0,
    refs: std.atomic.Value(usize) = .init(0),
    next_free: std.atomic.Value(u32) = .init(invalid_index),
};

/// A POD handoff record carried over a shard mailbox: the target client and the
/// pooled buffer holding its bytes. Plain (not `packed`) — it crosses threads by
/// value through `BoundedMpmc`, which cannot store a bit-packed raw pointer.
pub const DeliverMsg = struct {
    to: ClientId,
    buf: *DeliverBuf,
    /// Set by cross-shard administrative closes (KILL/CLOSE): the owning
    /// reactor appends this buffer, arms send, then marks the connection closing
    /// so the normal send-drain path tears it down.
    close_after: bool = false,
    close_reason: []const u8 = "Client quit",
    /// Cross-shard oper-event fan-out: when non-null, `to` is ignored and the
    /// owning reactor delivers `buf` to every one of ITS OWN clients subscribed to
    /// this Event-Spine category (raw `u6` to avoid importing event_spine into the
    /// handle layer; the server casts to/from `EventCategory`). Keeps cross-reactor
    /// client iteration on each reactor's own thread.
    broadcast_category: ?u6 = null,
    /// Event severity (raw ordinal of `EventSeverity`) carried alongside
    /// `broadcast_category` so the receiving reactor applies each subscriber's
    /// minimum-severity filter identically to the publishing reactor. Only
    /// meaningful when `broadcast_category != null`.
    broadcast_severity: u8 = 0,
    /// Cross-shard oper-event subject (inline POD copy): the event's subject text,
    /// carried alongside `broadcast_category` so the receiving reactor can apply
    /// each local subscriber's per-category subject glob exactly as the publishing
    /// reactor does. `broadcast_subject_len == 0` means the empty/wildcard subject
    /// (match-all). Capped at `broadcast_subject_max`; longer subjects are
    /// truncated for filtering (the displayed bytes in `buf` are untruncated).
    broadcast_subject: [broadcast_subject_max]u8 = @splat(0),
    broadcast_subject_len: u16 = 0,
    /// Cross-shard oper-event ORIGIN server name (inline POD copy): the server the
    /// event was raised on, so a network-wide event fanned to other shards renders
    /// `:<origin> EVENT …` with the originating node — not the local one. Empty
    /// (`broadcast_origin_len == 0`) means "use the local server name" (the case
    /// for a locally-raised event). Capped at `broadcast_origin_max`.
    broadcast_origin: [broadcast_origin_max]u8 = @splat(0),
    broadcast_origin_len: u16 = 0,
    /// Cross-shard OBSERVE fan-out: when true, `buf` holds an encoded
    /// `observe_event` payload (action + origin + structured subject), and the
    /// owning reactor decodes it, matches its OWN clients' standing OBSERVE filters,
    /// and pushes a per-watcher `EVENT … OBSERVE` line. Distinct from the
    /// `broadcast_category` Event-Spine path (different subscription model). `to` is
    /// ignored. Keeps cross-reactor client iteration on each reactor's own thread.
    broadcast_observe: bool = false,

    /// The carried subject slice (empty when none was set).
    pub fn broadcastSubject(self: *const DeliverMsg) []const u8 {
        return self.broadcast_subject[0..self.broadcast_subject_len];
    }

    /// The carried origin server name (empty when none was set => local server).
    pub fn broadcastOrigin(self: *const DeliverMsg) []const u8 {
        return self.broadcast_origin[0..self.broadcast_origin_len];
    }
};

/// Inline cap for the cross-shard oper-event subject filter copy. Subjects longer
/// than this are truncated for the per-category glob check only.
pub const broadcast_subject_max: usize = 256;

/// Inline cap for the cross-shard oper-event origin server name copy.
pub const broadcast_origin_max: usize = 128;

pub fn DeliverPool(comptime slots: usize) type {
    comptime {
        std.debug.assert(slots > 0);
        std.debug.assert(slots < invalid_index);
    }

    return struct {
        const Self = @This();
        const Head = std.atomic.Value(u64);

        bufs: [slots]DeliverBuf = initBufs(),
        head: Head = .init(packHead(0, 0)),

        pub fn init() Self {
            return .{};
        }

        pub fn acquire(self: *Self, bytes_in: []const u8) ?*DeliverBuf {
            if (bytes_in.len > max_bytes) return null;

            const buf = self.popFree() orelse return null;
            @memcpy(buf.data[0..bytes_in.len], bytes_in);
            buf.len = bytes_in.len;
            buf.refs.store(1, .release);
            return buf;
        }

        pub fn retain(_: *Self, buf: *DeliverBuf) void {
            const old = buf.refs.fetchAdd(1, .acquire);
            std.debug.assert(old > 0);
        }

        pub fn release(self: *Self, buf: *DeliverBuf) void {
            const old = buf.refs.fetchSub(1, .release);
            std.debug.assert(old > 0);
            if (old != 1) return;

            _ = buf.refs.load(.acquire);
            buf.len = 0;
            self.pushFree(buf);
        }

        pub fn bytes(_: *Self, buf: *const DeliverBuf) []const u8 {
            return buf.data[0..buf.len];
        }

        fn popFree(self: *Self) ?*DeliverBuf {
            var current = self.head.load(.acquire);
            while (true) {
                const index = headIndex(current);
                if (index == invalid_index) return null;

                const buf = &self.bufs[index];
                const next = buf.next_free.load(.acquire);
                const desired = packHead(headTag(current) +% 1, next);
                if (self.head.cmpxchgWeak(current, desired, .acquire, .monotonic)) |actual| {
                    current = actual;
                    continue;
                }

                buf.next_free.store(invalid_index, .release);
                return buf;
            }
        }

        fn pushFree(self: *Self, buf: *DeliverBuf) void {
            const index = self.indexOf(buf);
            var current = self.head.load(.acquire);
            while (true) {
                buf.next_free.store(headIndex(current), .release);
                const desired = packHead(headTag(current) +% 1, index);
                if (self.head.cmpxchgWeak(current, desired, .release, .monotonic)) |actual| {
                    current = actual;
                    continue;
                }
                return;
            }
        }

        fn indexOf(self: *Self, buf: *const DeliverBuf) u32 {
            const base = @intFromPtr(&self.bufs[0]);
            const ptr = @intFromPtr(buf);
            const offset = ptr - base;
            std.debug.assert(offset % @sizeOf(DeliverBuf) == 0);
            const index = offset / @sizeOf(DeliverBuf);
            std.debug.assert(index < slots);
            return @intCast(index);
        }

        fn freeCount(self: *Self) usize {
            var count: usize = 0;
            var index = headIndex(self.head.load(.acquire));
            while (index != invalid_index) : (index = self.bufs[index].next_free.load(.acquire)) {
                count += 1;
                std.debug.assert(count <= slots);
            }
            return count;
        }

        fn initBufs() [slots]DeliverBuf {
            var bufs: [slots]DeliverBuf = undefined;
            for (&bufs, 0..) |*buf, i| {
                buf.* = .{
                    .data = @as([max_bytes]u8, @splat(0)),
                    .len = 0,
                    .refs = .init(0),
                    .next_free = .init(if (i + 1 == slots) invalid_index else @as(u32, @intCast(i + 1))),
                };
            }
            return bufs;
        }
    };
}

fn packHead(tag: u32, index: u32) u64 {
    return (@as(u64, tag) << 32) | @as(u64, index);
}

fn headTag(head: u64) u32 {
    return @intCast(head >> 32);
}

fn headIndex(head: u64) u32 {
    return @intCast(head & 0xffff_ffff);
}

test "DeliverPool acquire copies bytes and release reuses a free slot" {
    var pool = DeliverPool(2).init();

    const first = pool.acquire("PRIVMSG #zig :hello\r\n") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("PRIVMSG #zig :hello\r\n", pool.bytes(first));
    pool.release(first);

    const second = pool.acquire("PING :1\r\n") orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(first, second);
    try std.testing.expectEqualStrings("PING :1\r\n", pool.bytes(second));
    pool.release(second);
    try std.testing.expectEqual(@as(usize, 2), pool.freeCount());
}

test "DeliverPool returns null when exhausted or bytes are too long" {
    var pool = DeliverPool(1).init();
    const too_long = @as([(max_bytes + 1)]u8, @splat('x'));
    try std.testing.expectEqual(@as(?*DeliverBuf, null), pool.acquire(&too_long));

    const buf = pool.acquire("one") orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(?*DeliverBuf, null), pool.acquire("two"));
    pool.release(buf);
    try std.testing.expectEqual(@as(usize, 1), pool.freeCount());
}

test "DeliverPool retain release frees only at zero" {
    var pool = DeliverPool(1).init();
    const buf = pool.acquire("NOTICE * :hi\r\n") orelse return error.TestExpectedEqual;
    pool.retain(buf);

    pool.release(buf);
    try std.testing.expectEqual(@as(usize, 0), pool.freeCount());
    try std.testing.expectEqualStrings("NOTICE * :hi\r\n", pool.bytes(buf));

    pool.release(buf);
    try std.testing.expectEqual(@as(usize, 1), pool.freeCount());
}

test "DeliverPool threaded acquire release stress leaves every slot free" {
    const producers = 8;
    const iters = 4000;
    const Pool = DeliverPool(64);

    const Context = struct {
        pool: Pool = Pool.init(),

        fn producer(ctx: *@This(), producer_id: usize) void {
            var line: [64]u8 = undefined;
            for (0..iters) |i| {
                const msg = std.fmt.bufPrint(&line, ":{d} PRIVMSG #stress :{d}\r\n", .{ producer_id, i }) catch unreachable;
                while (true) {
                    if (ctx.pool.acquire(msg)) |buf| {
                        std.debug.assert(std.mem.eql(u8, ctx.pool.bytes(buf), msg));
                        ctx.pool.release(buf);
                        break;
                    }
                    std.Thread.yield() catch {};
                }
            }
        }
    };

    var ctx: Context = .{};
    var threads: [producers]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |thread| thread.join();

    for (&threads, 0..) |*thread, producer_id| {
        thread.* = std.Thread.spawn(.{}, Context.producer, .{ &ctx, producer_id }) catch {
            return error.SkipZigTest;
        };
        spawned += 1;
    }

    for (&threads) |thread| thread.join();
    try std.testing.expectEqual(@as(usize, 64), ctx.pool.freeCount());
}
