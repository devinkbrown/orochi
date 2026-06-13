//! Helix conduit: arbitrary-fd + payload transfer over a SEQPACKET unix socket.
//!
//! Builds on the SCM_RIGHTS batch primitives in `handoff.zig` to move any number
//! of descriptors (well past the 253-fd-per-message kernel cap) together with a
//! single contiguous payload. The old daemon uses this to hand every live client
//! socket and the serialized capsule to its execve'd successor.
//!
//! Wire framing (all multi-byte integers big-endian):
//!
//!   1. Header message (no fds, its own SEQPACKET datagram):
//!        magic   : u32  ("HXCD")
//!        fd_count: u32  total number of descriptors to follow
//!        pay_len : u32  total payload byte length
//!        batches : u32  number of fd batches that will follow
//!   2. `batches` fd-batch messages, each carrying up to
//!      `max_fds_per_message` descriptors and a contiguous slice of the payload.
//!      Batch `i` carries payload bytes for that batch only; concatenating the
//!      payload slices of all batches in order reconstructs the whole payload.
//!
//! Splitting the payload across batches lets the receiver size each recv buffer
//! exactly and verify the totals deterministically. Linux syscall paths are
//! gated at runtime, matching `handoff.zig`.

const std = @import("std");
const builtin = @import("builtin");

const handoff = @import("handoff.zig");

const linux = std.os.linux;
const Allocator = std.mem.Allocator;

pub const Error = handoff.Error || std.mem.Allocator.Error || error{Protocol};

const magic: u32 = 0x48584344; // "HXCD"
const header_len: usize = 16;

/// Even payload split across the fd batches. The last batch absorbs any
/// remainder so the slices always sum back to `payload_len`.
fn batchPayloadRange(payload_len: usize, batch_count: usize, batch_index: usize) struct { start: usize, end: usize } {
    if (batch_count == 0) return .{ .start = 0, .end = 0 };
    const base = payload_len / batch_count;
    const rem = payload_len % batch_count;
    // Earlier batches each take one extra byte until the remainder is consumed.
    const start = base * batch_index + @min(batch_index, rem);
    const this = base + @as(usize, if (batch_index < rem) 1 else 0);
    return .{ .start = start, .end = start + this };
}

fn writeU32Be(buf: []u8, value: u32) void {
    std.mem.writeInt(u32, buf[0..4], value, .big);
}

fn readU32Be(buf: []const u8) u32 {
    return std.mem.readInt(u32, buf[0..4], .big);
}

/// Send a fixed header datagram with no descriptors attached.
fn sendHeader(socket_fd: handoff.Fd, fd_count: u32, payload_len: u32, batches: u32) Error!void {
    if (builtin.os.tag != .linux) return error.Unsupported;

    var hdr: [header_len]u8 = undefined;
    writeU32Be(hdr[0..4], magic);
    writeU32Be(hdr[4..8], fd_count);
    writeU32Be(hdr[8..12], payload_len);
    writeU32Be(hdr[12..16], batches);

    var iov = std.posix.iovec_const{ .base = &hdr, .len = hdr.len };
    const msg = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    while (true) {
        const rc = linux.sendmsg(socket_fd, &msg, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => return error.SendFailed,
        }
    }
}

const ParsedHeader = struct { fd_count: u32, payload_len: u32, batches: u32 };

/// Receive and validate the header datagram.
fn recvHeader(socket_fd: handoff.Fd) Error!ParsedHeader {
    if (builtin.os.tag != .linux) return error.Unsupported;

    var hdr: [header_len]u8 = undefined;
    var iov = std.posix.iovec{ .base = &hdr, .len = hdr.len };
    var msg = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const n = blk: while (true) {
        const rc = linux.recvmsg(socket_fd, &msg, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => break :blk @as(usize, @intCast(rc)),
            .INTR => continue,
            else => return error.RecvFailed,
        }
    };

    if (n != header_len) return error.Protocol;
    if (readU32Be(hdr[0..4]) != magic) return error.Protocol;
    return .{
        .fd_count = readU32Be(hdr[4..8]),
        .payload_len = readU32Be(hdr[8..12]),
        .batches = readU32Be(hdr[12..16]),
    };
}

/// Send `fds` and `payload` over `socket_fd`. The header datagram is sent first,
/// then the descriptors are streamed in batches, each carrying its slice of the
/// payload.
pub fn send(socket_fd: handoff.Fd, fds: []const handoff.Fd, payload: []const u8) Error!void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    if (fds.len > std.math.maxInt(u32)) return error.TooManyFds;
    if (payload.len > std.math.maxInt(u32)) return error.Protocol;

    const batch_count = handoff.fdBatchCount(fds.len);
    try sendHeader(
        socket_fd,
        @intCast(fds.len),
        @intCast(payload.len),
        @intCast(batch_count),
    );

    if (batch_count == 0) return;

    var batch_index: usize = 0;
    var fd_offset: usize = 0;
    while (batch_index < batch_count) : (batch_index += 1) {
        const take = handoff.batchLen(fds.len, batch_index);
        const range = batchPayloadRange(payload.len, batch_count, batch_index);
        try handoff.sendFdBatch(
            socket_fd,
            fds[fd_offset .. fd_offset + take],
            payload[range.start..range.end],
        );
        fd_offset += take;
    }
}

pub const Received = struct {
    fds: []handoff.Fd,
    payload: []u8,

    pub fn deinit(self: *Received, allocator: Allocator) void {
        allocator.free(self.fds);
        allocator.free(self.payload);
        self.* = .{ .fds = &.{}, .payload = &.{} };
    }
};

/// Receive a full transfer: read the header, then loop `recvFdBatch` until all
/// descriptors and the whole payload have arrived. Returns `error.Protocol` on
/// any count or length mismatch.
pub fn recv(allocator: Allocator, socket_fd: handoff.Fd) Error!Received {
    if (builtin.os.tag != .linux) return error.Unsupported;

    const head = try recvHeader(socket_fd);

    const fds = try allocator.alloc(handoff.Fd, head.fd_count);
    errdefer allocator.free(fds);
    const payload = try allocator.alloc(u8, head.payload_len);
    errdefer allocator.free(payload);

    if (head.fd_count == 0) {
        if (head.batches != 0 or head.payload_len != 0) return error.Protocol;
        return .{ .fds = fds, .payload = payload };
    }

    if (handoff.fdBatchCount(head.fd_count) != head.batches) return error.Protocol;

    var fd_offset: usize = 0;
    errdefer for (fds[0..fd_offset]) |fd| {
        _ = linux.close(fd);
    };
    var payload_offset: usize = 0;
    var batch_index: usize = 0;
    while (batch_index < head.batches) : (batch_index += 1) {
        const expected_fds = handoff.batchLen(head.fd_count, batch_index);
        const range = batchPayloadRange(head.payload_len, head.batches, batch_index);
        const expected_payload = range.end - range.start;

        var batch = try handoff.recvFdBatch(allocator, socket_fd, @max(1, expected_payload));
        defer batch.deinit(allocator);

        if (batch.fds.len != expected_fds) {
            for (batch.fds) |fd| _ = linux.close(fd);
            return error.Protocol;
        }
        // A zero-length payload slice is sent as a single padding byte by the
        // underlying primitive; tolerate that case explicitly.
        const got_payload = if (expected_payload == 0) 0 else batch.bytes.len;
        if (got_payload != expected_payload) {
            for (batch.fds) |fd| _ = linux.close(fd);
            return error.Protocol;
        }

        @memcpy(fds[fd_offset .. fd_offset + batch.fds.len], batch.fds);
        if (expected_payload != 0) {
            @memcpy(payload[payload_offset .. payload_offset + expected_payload], batch.bytes[0..expected_payload]);
        }

        fd_offset += batch.fds.len;
        payload_offset += expected_payload;
    }

    if (fd_offset != head.fd_count or payload_offset != head.payload_len) return error.Protocol;

    return .{ .fds = fds, .payload = payload };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "batchPayloadRange covers the whole payload with no gaps or overlaps" {
    const cases = [_]struct { len: usize, batches: usize }{
        .{ .len = 0, .batches = 0 },
        .{ .len = 0, .batches = 3 },
        .{ .len = 10, .batches = 1 },
        .{ .len = 10, .batches = 3 },
        .{ .len = 333, .batches = 2 },
        .{ .len = 257, .batches = 7 },
    };
    for (cases) |c| {
        var prev_end: usize = 0;
        var total: usize = 0;
        var i: usize = 0;
        while (i < c.batches) : (i += 1) {
            const r = batchPayloadRange(c.len, c.batches, i);
            try std.testing.expectEqual(prev_end, r.start);
            try std.testing.expect(r.end >= r.start);
            prev_end = r.end;
            total += r.end - r.start;
        }
        if (c.batches != 0) try std.testing.expectEqual(c.len, total);
    }
}

test "conduit moves >253 fds plus a multi-hundred-byte payload" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var sockets = try handoff.socketPair();
    defer sockets.close();

    // Open /dev/null and dup it many times to force multiple SCM_RIGHTS batches.
    const base_fd: handoff.Fd = blk: {
        const rc = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => break :blk @intCast(rc),
            else => return error.SkipZigTest,
        }
    };
    defer _ = linux.close(base_fd);

    const fd_total: usize = 300; // > max_fds_per_message (253) -> 2 batches
    var duped: std.ArrayList(handoff.Fd) = .empty;
    defer {
        for (duped.items) |fd| _ = linux.close(fd);
        duped.deinit(allocator);
    }
    try duped.ensureTotalCapacity(allocator, fd_total);

    var n: usize = 0;
    while (n < fd_total) : (n += 1) {
        const rc = linux.dup(base_fd);
        switch (linux.errno(rc)) {
            .SUCCESS => try duped.append(allocator, @intCast(rc)),
            else => return error.RecvFailed,
        }
    }

    // A few hundred bytes of deterministic payload.
    var payload: [400]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i & 0xff);

    const SendCtx = struct {
        sock: handoff.Fd,
        fds: []const handoff.Fd,
        pay: []const u8,
        result: Error!void = undefined,

        fn run(ctx: *@This()) void {
            ctx.result = send(ctx.sock, ctx.fds, ctx.pay);
        }
    };

    var ctx = SendCtx{ .sock = sockets.supervisor, .fds = duped.items, .pay = payload[0..] };
    const thread = try std.Thread.spawn(.{}, SendCtx.run, .{&ctx});

    var received = try recv(allocator, sockets.worker);
    defer {
        for (received.fds) |fd| _ = linux.close(fd);
        received.deinit(allocator);
    }

    thread.join();
    try ctx.result;

    try std.testing.expectEqual(fd_total, received.fds.len);
    try std.testing.expectEqualSlices(u8, payload[0..], received.payload);
}
