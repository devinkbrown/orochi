// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux Helix handoff transport: sealed memfd arena and SCM_RIGHTS fd passing.
//!
//! The supervisor and workers exchange state through one sealed memfd and pass
//! client/listener descriptors over an AF_UNIX SOCK_SEQPACKET control socket.
//! Linux syscall paths are gated at runtime; non-Linux targets compile and
//! return `error.Unsupported`.

const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const linux = std.os.linux;

pub const max_fds_per_message: usize = 253;

const f_add_seals: i32 = 1033;
const f_seal_seal: u32 = 0x0001;
const f_seal_shrink: u32 = 0x0002;
const f_seal_grow: u32 = 0x0004;
const f_seal_write: u32 = 0x0008;
const scm_rights: i32 = 0x01;
const msg_ctrunc: u32 = 0x08;

pub const Error = error{
    Unsupported,
    MemfdCreateFailed,
    WriteFailed,
    SealFailed,
    SocketPairFailed,
    SendFailed,
    RecvFailed,
    EmptyFdBatch,
    ControlTruncated,
    MissingRights,
    TooManyFds,
} || Allocator.Error;

pub const Fd = linux.fd_t;

pub const Arena = struct {
    fd: Fd = -1,
    size: usize = 0,
    sealed: bool = false,

    pub fn create(name: []const u8) Error!Arena {
        if (builtin.os.tag != .linux) return error.Unsupported;
        var zname: [64]u8 = undefined;
        const len = @min(name.len, zname.len - 1);
        @memcpy(zname[0..len], name[0..len]);
        zname[len] = 0;

        const rc = linux.memfd_create(@ptrCast(&zname), linux.MFD.CLOEXEC | linux.MFD.ALLOW_SEALING);
        switch (linux.errno(rc)) {
            .SUCCESS => return .{ .fd = @intCast(rc) },
            else => return error.MemfdCreateFailed,
        }
    }

    pub fn writeAll(self: *Arena, bytes: []const u8) Error!void {
        if (builtin.os.tag != .linux) return error.Unsupported;
        if (self.sealed) return error.SealFailed;
        var written: usize = 0;
        while (written < bytes.len) {
            const rc = linux.write(self.fd, bytes.ptr + written, bytes.len - written);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    const n: usize = @intCast(rc);
                    if (n == 0) return error.WriteFailed;
                    written += n;
                },
                .INTR => continue,
                else => return error.WriteFailed,
            }
        }
        self.size += written;
    }

    pub fn seal(self: *Arena) Error!void {
        if (builtin.os.tag != .linux) return error.Unsupported;
        const seals = f_seal_seal | f_seal_shrink | f_seal_grow | f_seal_write;
        const rc = linux.fcntl(self.fd, f_add_seals, seals);
        switch (linux.errno(rc)) {
            .SUCCESS => self.sealed = true,
            else => return error.SealFailed,
        }
    }

    pub fn close(self: *Arena) void {
        if (builtin.os.tag == .linux and self.fd >= 0) {
            _ = linux.close(self.fd);
        }
        self.* = .{};
    }
};

pub const SocketPair = struct {
    supervisor: Fd,
    worker: Fd,

    pub fn close(self: *SocketPair) void {
        if (builtin.os.tag == .linux) {
            if (self.supervisor >= 0) _ = linux.close(self.supervisor);
            if (self.worker >= 0) _ = linux.close(self.worker);
        }
        self.* = .{ .supervisor = -1, .worker = -1 };
    }
};

pub fn socketPair() Error!SocketPair {
    if (builtin.os.tag != .linux) return error.Unsupported;
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &fds);
    switch (linux.errno(rc)) {
        .SUCCESS => return .{ .supervisor = fds[0], .worker = fds[1] },
        else => return error.SocketPairFailed,
    }
}

pub fn fdBatchCount(fd_count: usize) usize {
    if (fd_count == 0) return 0;
    return (fd_count + max_fds_per_message - 1) / max_fds_per_message;
}

pub fn batchLen(fd_count: usize, batch_index: usize) usize {
    const start = batch_index * max_fds_per_message;
    if (start >= fd_count) return 0;
    return @min(max_fds_per_message, fd_count - start);
}

pub fn sendFdBatches(socket_fd: Fd, fds: []const Fd, payload: []const u8) Error!usize {
    if (builtin.os.tag != .linux) return error.Unsupported;
    if (fds.len == 0) return error.EmptyFdBatch;

    var sent_batches: usize = 0;
    var index: usize = 0;
    while (index < fds.len) {
        const take = @min(max_fds_per_message, fds.len - index);
        try sendFdBatch(socket_fd, fds[index .. index + take], payload);
        sent_batches += 1;
        index += take;
    }
    return sent_batches;
}

pub fn sendFdBatch(socket_fd: Fd, fds: []const Fd, payload: []const u8) Error!void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    if (fds.len == 0) return error.EmptyFdBatch;
    if (fds.len > max_fds_per_message) return error.TooManyFds;

    var empty_payload = [_]u8{0};
    const body = if (payload.len == 0) empty_payload[0..] else payload;
    var iov = std.posix.iovec_const{ .base = body.ptr, .len = body.len };

    var control: [controlSpace(max_fds_per_message)]u8 align(@alignOf(linux.cmsghdr)) = undefined;
    @memset(&control, 0);
    const fd_bytes = std.mem.sliceAsBytes(fds);
    const used = controlSpace(fds.len);
    const hdr: *linux.cmsghdr = @ptrCast(&control);
    hdr.* = .{
        .len = controlLen(fd_bytes.len),
        .level = linux.SOL.SOCKET,
        .type = scm_rights,
    };
    @memcpy(control[alignCmsg(@sizeOf(linux.cmsghdr)) .. alignCmsg(@sizeOf(linux.cmsghdr)) + fd_bytes.len], fd_bytes);

    const msg = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = &control,
        .controllen = used,
        .flags = 0,
    };

    const rc = linux.sendmsg(socket_fd, &msg, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .INTR => return try sendFdBatch(socket_fd, fds, payload),
        else => return error.SendFailed,
    }
}

pub const ReceivedBatch = struct {
    bytes: []u8,
    fds: []Fd,

    pub fn deinit(self: *ReceivedBatch, allocator: Allocator) void {
        allocator.free(self.bytes);
        allocator.free(self.fds);
        self.* = .{ .bytes = &.{}, .fds = &.{} };
    }
};

pub fn recvFdBatch(allocator: Allocator, socket_fd: Fd, max_payload: usize) Error!ReceivedBatch {
    if (builtin.os.tag != .linux) return error.Unsupported;

    const body = try allocator.alloc(u8, @max(1, max_payload));
    errdefer allocator.free(body);

    var iov = std.posix.iovec{ .base = body.ptr, .len = body.len };
    var control: [controlSpace(max_fds_per_message)]u8 align(@alignOf(linux.cmsghdr)) = undefined;
    @memset(&control, 0);

    var msg = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };

    const rc = linux.recvmsg(socket_fd, &msg, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .INTR => return recvFdBatch(allocator, socket_fd, max_payload),
        else => return error.RecvFailed,
    }
    const body_len: usize = @intCast(rc);
    if ((msg.flags & msg_ctrunc) != 0) return error.ControlTruncated;

    const hdr: *linux.cmsghdr = @ptrCast(&control);
    if (hdr.level != linux.SOL.SOCKET or hdr.type != scm_rights) return error.MissingRights;
    if (hdr.len < controlLen(0)) return error.MissingRights;

    const fd_bytes_len = hdr.len - controlLen(0);
    if (fd_bytes_len % @sizeOf(Fd) != 0) return error.MissingRights;
    const fd_count = fd_bytes_len / @sizeOf(Fd);
    if (fd_count > max_fds_per_message) return error.TooManyFds;

    const fds = try allocator.alloc(Fd, fd_count);
    errdefer allocator.free(fds);
    const data_start = alignCmsg(@sizeOf(linux.cmsghdr));
    const source = control[data_start .. data_start + fd_bytes_len];
    @memcpy(std.mem.sliceAsBytes(fds), source);

    return .{
        .bytes = try allocator.realloc(body, body_len),
        .fds = fds,
    };
}

fn alignCmsg(len: usize) usize {
    return std.mem.alignForward(usize, len, @sizeOf(usize));
}

fn controlLen(data_len: usize) usize {
    return alignCmsg(@sizeOf(linux.cmsghdr)) + data_len;
}

fn controlSpace(fd_count: usize) usize {
    return alignCmsg(@sizeOf(linux.cmsghdr)) + alignCmsg(fd_count * @sizeOf(Fd));
}

test "SCM_RIGHTS batches respect the 253 fd kernel limit" {
    try std.testing.expectEqual(@as(usize, 0), fdBatchCount(0));
    try std.testing.expectEqual(@as(usize, 1), fdBatchCount(1));
    try std.testing.expectEqual(@as(usize, 1), fdBatchCount(max_fds_per_message));
    try std.testing.expectEqual(@as(usize, 2), fdBatchCount(max_fds_per_message + 1));
    try std.testing.expectEqual(max_fds_per_message, batchLen(300, 0));
    try std.testing.expectEqual(@as(usize, 47), batchLen(300, 1));
}

test "control message sizing is aligned and monotonic" {
    const zero = controlSpace(0);
    const one = controlSpace(1);
    const many = controlSpace(max_fds_per_message);
    try std.testing.expect(zero >= @sizeOf(linux.cmsghdr));
    try std.testing.expect(one > zero);
    try std.testing.expect(many > one);
    try std.testing.expectEqual(@as(usize, 0), zero % @sizeOf(usize));
}

test "linux socketpair can pass a memfd descriptor" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var sockets = try socketPair();
    defer sockets.close();

    var arena = try Arena.create("helix-test");
    defer arena.close();
    try arena.writeAll("capsule");
    try arena.seal();

    const fds = [_]Fd{arena.fd};
    try std.testing.expectEqual(@as(usize, 1), try sendFdBatches(sockets.supervisor, &fds, "arena"));

    var recv = try recvFdBatch(allocator, sockets.worker, 16);
    defer {
        for (recv.fds) |fd| _ = linux.close(fd);
        recv.deinit(allocator);
    }

    try std.testing.expect(std.mem.eql(u8, recv.bytes, "arena"));
    try std.testing.expectEqual(@as(usize, 1), recv.fds.len);
}
