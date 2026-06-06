//! Wire framing for DNS-over-TLS (RFC 7858) and DNS-over-TCP (RFC 1035 §4.2.2).
//!
//! Both transports prefix each DNS message with a two-octet, big-endian length
//! field giving the size of the message that immediately follows. This module
//! implements *only* that framing/deframing layer: it has no sockets, no TLS,
//! no clock, and no randomness. The TLS transport is a separate future layer
//! that feeds decrypted record bytes into the `Deframer` here.
//!
//! Because TLS records do not align to DNS message boundaries, the deframer is
//! a streaming reassembler: callers `push` arbitrary byte chunks and then pull
//! complete messages one at a time with `next`.
const std = @import("std");

/// Size of the big-endian length prefix that precedes every DNS message.
pub const prefix_len: usize = 2;

/// Largest DNS message a 16-bit length prefix can describe.
pub const max_message_len: usize = std.math.maxInt(u16);

const endian = .big;

pub const FrameError = error{
    /// The destination buffer cannot hold the prefix plus message.
    NoSpaceLeft,
    /// The message exceeds what a 16-bit length prefix can represent.
    MessageTooLong,
};

/// Total framed size (prefix + message) for a message of `msg_len` bytes.
///
/// Asserts `msg_len <= max_message_len`; use `frame` for the checked path.
pub fn framedLen(msg_len: usize) usize {
    std.debug.assert(msg_len <= max_message_len);
    return prefix_len + msg_len;
}

/// Write a two-octet big-endian length prefix followed by `msg` into `out`.
///
/// Returns the populated prefix-of-`out` slice on success.
/// Errors:
///   * `error.MessageTooLong` if `msg` exceeds `max_message_len`.
///   * `error.NoSpaceLeft` if `out` is smaller than `framedLen(msg.len)`.
pub fn frame(msg: []const u8, out: []u8) FrameError![]const u8 {
    if (msg.len > max_message_len) return error.MessageTooLong;

    const total = prefix_len + msg.len;
    if (out.len < total) return error.NoSpaceLeft;

    std.mem.writeInt(u16, out[0..prefix_len], @intCast(msg.len), endian);
    @memcpy(out[prefix_len..total], msg);
    return out[0..total];
}

/// Streaming deframer over an allocator-backed, growable buffer.
///
/// Buffer ownership: the `Deframer` owns its internal accumulation buffer,
/// allocated and freed via the allocator supplied to `init`/`deinit`. Callers
/// hand it raw bytes with `push` (copied into the buffer) and retrieve complete
/// messages with `next`.
///
/// Slice lifetime: the slice returned by `next` points *into* the internal
/// buffer and stays valid only until the following mutating call (`push`,
/// `next`, `reset`, or `deinit`). Copy it out if it must outlive that.
///
/// Consumed bytes are compacted out of the front of the buffer after each
/// message is yielded, so steady-state memory stays bounded by the largest
/// in-flight frame rather than the total bytes ever pushed.
pub const Deframer = struct {
    allocator: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,
    /// Bytes at the front of `buf` already yielded by `next`. They are physically
    /// compacted out on the following `push`, so a slice returned by `next` stays
    /// valid until the next mutating call.
    consumed: usize = 0,

    pub fn init(allocator: std.mem.Allocator) Deframer {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Deframer) void {
        self.buf.deinit(self.allocator);
        self.* = undefined;
    }

    /// Drop all buffered bytes while retaining the underlying capacity.
    pub fn reset(self: *Deframer) void {
        self.buf.clearRetainingCapacity();
        self.consumed = 0;
    }

    /// Number of unread bytes currently buffered (excludes already-yielded data).
    pub fn buffered(self: *const Deframer) usize {
        return self.buf.items.len - self.consumed;
    }

    /// True when no unread bytes remain (clean message boundary at EOF).
    pub fn isEmpty(self: *const Deframer) bool {
        return self.buffered() == 0;
    }

    /// Append a chunk of transport bytes. Chunks may split or combine DNS
    /// messages arbitrarily; the deframer reassembles them.
    pub fn push(self: *Deframer, bytes: []const u8) std.mem.Allocator.Error!void {
        self.compact();
        try self.buf.appendSlice(self.allocator, bytes);
    }

    /// Yield the next complete DNS message, or null if one is not yet fully
    /// buffered (partial prefix or partial body).
    ///
    /// The returned slice aliases the internal buffer; see the struct docs for
    /// its lifetime.
    pub fn next(self: *Deframer) ?[]const u8 {
        const window = self.buf.items[self.consumed..];
        if (window.len < prefix_len) return null;

        const msg_len: usize = std.mem.readInt(u16, window[0..prefix_len], endian);
        const total = prefix_len + msg_len;
        if (window.len < total) return null;

        const msg = window[prefix_len..total];
        self.consumed += total;
        return msg;
    }

    /// Shift unread bytes to the front of the buffer and drop consumed bytes,
    /// keeping steady-state memory bounded by the largest in-flight frame.
    fn compact(self: *Deframer) void {
        if (self.consumed == 0) return;
        const remaining = self.buf.items.len - self.consumed;
        if (remaining != 0) {
            std.mem.copyForwards(u8, self.buf.items[0..remaining], self.buf.items[self.consumed..]);
        }
        self.buf.shrinkRetainingCapacity(remaining);
        self.consumed = 0;
    }
};

const testing = std.testing;

test "frame round-trips a message" {
    // Arrange
    const msg = "dns-query-bytes";
    var out: [prefix_len + msg.len]u8 = undefined;

    // Act
    const framed = try frame(msg, &out);

    // Assert
    try testing.expectEqual(framedLen(msg.len), framed.len);
    try testing.expectEqual(@as(u16, msg.len), std.mem.readInt(u16, framed[0..prefix_len], endian));
    try testing.expectEqualSlices(u8, msg, framed[prefix_len..]);
}

test "frame rejects message longer than 65535 bytes" {
    // Arrange
    const allocator = testing.allocator;
    const oversized = try allocator.alloc(u8, max_message_len + 1);
    defer allocator.free(oversized);
    var out: [16]u8 = undefined;

    // Act / Assert
    try testing.expectError(error.MessageTooLong, frame(oversized, &out));
}

test "frame rejects output buffer too small for prefix plus message" {
    // Arrange
    const msg = "too-big-for-out";
    var out: [prefix_len + msg.len - 1]u8 = undefined;

    // Act / Assert
    try testing.expectError(error.NoSpaceLeft, frame(msg, &out));
}

test "framedLen adds the two-octet prefix" {
    // Arrange / Act / Assert
    try testing.expectEqual(@as(usize, 2), framedLen(0));
    try testing.expectEqual(@as(usize, 7), framedLen(5));
    try testing.expectEqual(@as(usize, prefix_len + max_message_len), framedLen(max_message_len));
}

test "Deframer reassembles a message split across two pushes" {
    // Arrange
    const allocator = testing.allocator;
    const msg = "split-across-pushes";
    var out: [prefix_len + msg.len]u8 = undefined;
    const framed = try frame(msg, &out);

    var deframer = Deframer.init(allocator);
    defer deframer.deinit();

    // Act: feed prefix + part of the body, then the rest.
    try deframer.push(framed[0 .. prefix_len + 4]);
    try testing.expectEqual(@as(?[]const u8, null), deframer.next());
    try deframer.push(framed[prefix_len + 4 ..]);

    // Assert
    const got = deframer.next().?;
    try testing.expectEqualSlices(u8, msg, got);
    try testing.expectEqual(@as(?[]const u8, null), deframer.next());
    try testing.expect(deframer.isEmpty());
}

test "Deframer yields two messages from one combined push" {
    // Arrange
    const allocator = testing.allocator;
    const first = "first-message";
    const second = "second-longer-message";
    var combined: [prefix_len + first.len + prefix_len + second.len]u8 = undefined;
    const a = try frame(first, combined[0..]);
    _ = try frame(second, combined[a.len..]);

    var deframer = Deframer.init(allocator);
    defer deframer.deinit();

    // Act
    try deframer.push(&combined);

    // Assert
    try testing.expectEqualSlices(u8, first, deframer.next().?);
    try testing.expectEqualSlices(u8, second, deframer.next().?);
    try testing.expectEqual(@as(?[]const u8, null), deframer.next());
    try testing.expect(deframer.isEmpty());
}

test "Deframer reassembles a one-byte-at-a-time drip feed" {
    // Arrange
    const allocator = testing.allocator;
    const msg = "drip-fed-message";
    var out: [prefix_len + msg.len]u8 = undefined;
    const framed = try frame(msg, &out);

    var deframer = Deframer.init(allocator);
    defer deframer.deinit();

    // Act: feed one byte per push; only the final byte completes the message.
    var got: ?[]const u8 = null;
    for (framed, 0..) |byte, i| {
        try deframer.push(&[_]u8{byte});
        const out_msg = deframer.next();
        if (i + 1 < framed.len) {
            try testing.expectEqual(@as(?[]const u8, null), out_msg);
        } else {
            got = out_msg;
        }
    }

    // Assert
    try testing.expectEqualSlices(u8, msg, got.?);
    try testing.expect(deframer.isEmpty());
}

test "Deframer handles a partial length prefix then completion" {
    // Arrange
    const allocator = testing.allocator;
    const msg = "prefix-then-rest";
    var out: [prefix_len + msg.len]u8 = undefined;
    const framed = try frame(msg, &out);

    var deframer = Deframer.init(allocator);
    defer deframer.deinit();

    // Act: only the first prefix octet arrives first.
    try deframer.push(framed[0..1]);
    try testing.expectEqual(@as(?[]const u8, null), deframer.next());
    try testing.expectEqual(@as(usize, 1), deframer.buffered());

    // Second prefix octet arrives; body still missing.
    try deframer.push(framed[1..2]);
    try testing.expectEqual(@as(?[]const u8, null), deframer.next());

    // Body arrives.
    try deframer.push(framed[2..]);

    // Assert
    try testing.expectEqualSlices(u8, msg, deframer.next().?);
    try testing.expect(deframer.isEmpty());
}

test "Deframer round-trips an empty (zero-length) message" {
    // Arrange
    const allocator = testing.allocator;
    var out: [prefix_len]u8 = undefined;
    const framed = try frame("", &out);

    var deframer = Deframer.init(allocator);
    defer deframer.deinit();

    // Act
    try deframer.push(framed);

    // Assert
    const got = deframer.next().?;
    try testing.expectEqual(@as(usize, 0), got.len);
    try testing.expect(deframer.isEmpty());
}

test "Deframer reset discards buffered partial bytes without leaking" {
    // Arrange
    const allocator = testing.allocator;
    const msg = "buffered-then-reset";
    var out: [prefix_len + msg.len]u8 = undefined;
    const framed = try frame(msg, &out);

    var deframer = Deframer.init(allocator);
    defer deframer.deinit();

    // Act
    try deframer.push(framed[0 .. framed.len - 1]);
    try testing.expectEqual(@as(?[]const u8, null), deframer.next());
    deframer.reset();

    // Assert
    try testing.expect(deframer.isEmpty());
    try testing.expectEqual(@as(?[]const u8, null), deframer.next());
}
