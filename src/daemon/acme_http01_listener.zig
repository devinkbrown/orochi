//! Loopback HTTP-01 challenge listener.
//!
//! Binds `127.0.0.1:<port>` and serves ACME challenge responses from a shared
//! `TokenStore` (see [acme_http01_server]) on a background thread, so the
//! blocking issuance driver (see [acme_runner]) can run concurrently while the
//! CA validates the challenge.
//!
//! Deployment (per the chosen rollout): nginx on the live box proxies
//! `/.well-known/acme-challenge/` to this loopback port — the public site keeps
//! serving everything else. This listener never binds a public interface.

const std = @import("std");

const http01 = @import("acme_http01_server.zig");

const linux = std.os.linux;
const posix = std.posix;

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("acme_http01_listener requires a 64-bit target");
}

pub const ListenerError = error{
    SocketUnavailable,
    BindFailed,
    ListenFailed,
    AddrLookupFailed,
};

/// Max request bytes read per connection (a challenge GET is tiny).
const max_request: usize = 8 * 1024;
/// Max response bytes (status line + headers + key authorization).
const max_response: usize = 4 * 1024;

pub const ChallengeServer = struct {
    store: *http01.TokenStore,
    listen_fd: linux.fd_t,
    port: u16,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = .{ .raw = false },

    /// Bind `127.0.0.1:port` (use port 0 for an ephemeral port) and start
    /// listening. No thread is running yet; call `spawn`. The returned value must
    /// live at a stable address for the thread's lifetime.
    pub fn init(store: *http01.TokenStore, port: u16) ListenerError!ChallengeServer {
        const fd = try socketTcp();
        errdefer closeFd(fd);

        var yes: u32 = 1;
        _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes), @sizeOf(u32));

        var addr = linux.sockaddr.in{
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, 0x7f00_0001), // 127.0.0.1
        };
        if (posix.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
            return error.BindFailed;
        if (posix.errno(linux.listen(fd, 16)) != .SUCCESS)
            return error.ListenFailed;

        // Receive timeout so a blocked accept4 wakes periodically to re-check the
        // stop flag. Closing the listener from another thread does NOT reliably
        // wake accept4, so this poll is how shutdown actually terminates.
        const tv = linux.timeval{ .sec = 0, .usec = 250 * 1000 };
        _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));

        return .{ .store = store, .listen_fd = fd, .port = try boundPort(fd) };
    }

    /// Spawn the background accept loop.
    pub fn spawn(self: *ChallengeServer) std.Thread.SpawnError!void {
        self.thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
    }

    /// Signal stop, unblock the accept loop by closing the listener, and join.
    pub fn shutdown(self: *ChallengeServer) void {
        self.stop_flag.store(true, .release);
        closeFd(self.listen_fd); // unblocks a blocking accept4 with EBADF
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn acceptLoop(self: *ChallengeServer) void {
        while (!self.stop_flag.load(.acquire)) {
            const rc = linux.accept4(self.listen_fd, null, null, posix.SOCK.CLOEXEC);
            switch (posix.errno(rc)) {
                .SUCCESS => self.serveConn(@intCast(rc)),
                .AGAIN, .INTR, .CONNABORTED => continue, // timeout/interrupt: re-check stop flag
                else => return, // listener closed (shutdown) or fatal: exit thread
            }
        }
    }

    fn serveConn(self: *ChallengeServer, fd: linux.fd_t) void {
        defer closeFd(fd);
        // Accepted sockets do not inherit the listener's timeout; cap the read so a
        // silent/slow client cannot stall the single-threaded accept loop.
        const tv = linux.timeval{ .sec = 5, .usec = 0 };
        _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
        var req_buf: [max_request]u8 = undefined;
        const rc = linux.read(fd, &req_buf, req_buf.len);
        if (posix.errno(rc) != .SUCCESS) return;
        const n: usize = @intCast(rc);
        if (n == 0) return;

        var resp_buf: [max_response]u8 = undefined;
        const resp = http01.handleRequest(self.store, req_buf[0..n], &resp_buf) catch return;
        writeAll(fd, resp);
    }
};

// ---------------------------------------------------------------------------
// Low-level helpers (raw linux syscalls)
// ---------------------------------------------------------------------------

fn socketTcp() ListenerError!linux.fd_t {
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SocketUnavailable,
    };
}

fn boundPort(fd: linux.fd_t) ListenerError!u16 {
    var storage: posix.sockaddr.storage = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(linux.getsockname(fd, @ptrCast(&storage), &len)) != .SUCCESS)
        return error.AddrLookupFailed;
    const a: *const linux.sockaddr.in = @ptrCast(@alignCast(&storage));
    return std.mem.bigToNative(u16, a.port);
}

fn closeFd(fd: linux.fd_t) void {
    _ = linux.close(fd);
}

fn writeAll(fd: linux.fd_t, bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        if (posix.errno(rc) != .SUCCESS) return;
        off += @intCast(rc);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ChallengeServer serves a stored token over loopback" {
    const allocator = std.testing.allocator;
    var store = http01.TokenStore.init(allocator);
    defer store.deinit();
    try store.put("tok_AZ09-test", "tok_AZ09-test.thumb");

    var server = try ChallengeServer.init(&store, 0);
    try server.spawn();
    defer server.shutdown();

    // Connect a client to the ephemeral loopback port and request the token.
    const cfd = try socketTcp();
    defer closeFd(cfd);
    var addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, server.port),
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
    };
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(linux.connect(cfd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))));

    const req = "GET /.well-known/acme-challenge/tok_AZ09-test HTTP/1.1\r\nHost: x\r\n\r\n";
    writeAll(cfd, req);

    var buf: [512]u8 = undefined;
    const rc = linux.read(cfd, &buf, buf.len);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
    const got = buf[0..@intCast(rc)];
    try std.testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, got, "\r\n\r\ntok_AZ09-test.thumb"));
}

test "ChallengeServer returns 404 for unknown token" {
    const allocator = std.testing.allocator;
    var store = http01.TokenStore.init(allocator);
    defer store.deinit();

    var server = try ChallengeServer.init(&store, 0);
    try server.spawn();
    defer server.shutdown();

    const cfd = try socketTcp();
    defer closeFd(cfd);
    var addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, server.port),
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
    };
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(linux.connect(cfd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))));

    writeAll(cfd, "GET /.well-known/acme-challenge/nope HTTP/1.1\r\n\r\n");
    var buf: [512]u8 = undefined;
    const rc = linux.read(cfd, &buf, buf.len);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
    try std.testing.expect(std.mem.startsWith(u8, buf[0..@intCast(rc)], "HTTP/1.1 404 Not Found\r\n"));
}

test {
    std.testing.refAllDecls(@This());
}
