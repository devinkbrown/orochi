// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Threaded plaintext HTTP listener for Discord-compatible incoming webhooks.
//!
//! Mirrors `metrics_http.zig`: a standalone, loopback-by-default HTTP/1.1
//! accept loop on its own thread. It NEVER touches reactor-owned connection
//! state — it only (a) verifies a presented token against the shared
//! `WebhookStore` (constant-time), (b) rate-limits, (c) parses + sanitises the
//! Discord JSON body, and (d) hands a fully-scrubbed `PendingPost` to the owning
//! reactor through a `PostSink` (which enqueues + wakes). The reactor performs
//! the actual channel fan-out on-thread.
//!
//! Responses use Discord-shaped status codes:
//!   204 success · 400 bad payload · 401 bad token · 404 unknown id ·
//!   405 wrong method · 413 too large · 429 rate-limited (+ `Retry-After`).
//!
//! TLS is intentionally out of scope: front this listener with a reverse proxy
//! (nginx/Caddy) that terminates HTTPS and forwards to the configured loopback
//! port, exactly as an operator already does for the `/metrics` endpoint.

const std = @import("std");

const linux = std.os.linux;
const posix = std.posix;

const webhook = @import("webhook.zig");
const webhook_render = @import("webhook_render.zig");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("webhook_http requires a 64-bit target");
}

/// Absolute ceiling on a request body, independent of the (smaller) configured
/// cap. Sizes the connection read buffer; a declared/actual body beyond the
/// configured cap yields 413 well before this.
pub const max_body_hard: usize = 64 * 1024;
/// Scratch reserved for the request line + headers.
pub const max_header: usize = 4 * 1024;
/// JSON parse arena size (fixed, on the connection stack). Bounded work: the
/// body is already ≤ the configured cap. Exhaustion → 400 (fail-closed).
pub const json_scratch: usize = 256 * 1024;

pub const default_listen_backlog: u31 = 16;
pub const default_accept_poll_ms: u32 = 250;
pub const default_conn_read_timeout_sec: u32 = 5;

/// Loopback `127.0.0.1` in host byte order (the secure default bind).
pub const loopback_addr: u32 = 0x7f00_0001;

pub const ListenerError = error{
    SocketUnavailable,
    BindFailed,
    ListenFailed,
    AddrLookupFailed,
};

/// Handler tunables (validation limits + rate policy).
pub const HandlerConfig = struct {
    /// Max request-body bytes accepted before answering 413.
    max_body: usize = 8 * 1024,
    /// Per-webhook token-bucket rate policy.
    rate: webhook.RateConfig = .{},
    /// `Retry-After` (seconds) returned when the reactor post queue is full.
    busy_retry_after: u32 = 1,
};

// ---------------------------------------------------------------------------
// Pure request handling (unit-testable, no sockets)
// ---------------------------------------------------------------------------

/// Handle one fully-read HTTP request. Writes a complete HTTP/1.1 response into
/// `out` and returns the slice written. On a validated post it fills a
/// `PendingPost` and offers it to `sink`; a full queue yields 429. `allocator`
/// backs only the transient JSON parse tree.
pub fn handleRequest(
    store: *webhook.WebhookStore,
    sink: webhook.PostSink,
    cfg: HandlerConfig,
    allocator: std.mem.Allocator,
    request_bytes: []const u8,
    now_ms: i64,
    out: []u8,
) error{NoSpaceLeft}![]const u8 {
    // --- Request line ---------------------------------------------------
    const head_end = std.mem.indexOf(u8, request_bytes, "\r\n\r\n") orelse
        return writeSimple(out, "400 Bad Request", "bad request\n", null);
    const line_end = std.mem.indexOfScalar(u8, request_bytes, '\n') orelse
        return writeSimple(out, "400 Bad Request", "bad request\n", null);
    var line = request_bytes[0..line_end];
    if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];

    const sp1 = std.mem.indexOfScalar(u8, line, ' ') orelse
        return writeSimple(out, "400 Bad Request", "bad request\n", null);
    const method = line[0..sp1];
    const after = line[sp1 + 1 ..];
    const sp2 = std.mem.indexOfScalar(u8, after, ' ') orelse
        return writeSimple(out, "400 Bad Request", "bad request\n", null);
    const target = after[0..sp2];

    // --- Route (POST /api/webhooks/<id>/<token>) ------------------------
    const parsed_target = webhook.parseTarget(target) orelse
        return writeSimple(out, "404 Not Found", "unknown webhook\n", null);
    if (!std.mem.eql(u8, method, "POST"))
        return writeSimple(out, "405 Method Not Allowed", "method not allowed\n", null);

    // --- Body size gate -------------------------------------------------
    const headers = request_bytes[0..head_end];
    const body = request_bytes[head_end + 4 ..];
    const declared = contentLength(headers);
    const effective_len = declared orelse body.len;
    if (effective_len > cfg.max_body)
        return writeSimple(out, "413 Payload Too Large", "payload too large\n", null);
    // If a length was declared, honour exactly that many body bytes (a client
    // may pipeline; we never read past the declared body).
    const body_slice = if (declared) |d| body[0..@min(d, body.len)] else body;
    if (declared) |d| {
        if (d > body_slice.len)
            return writeSimple(out, "400 Bad Request", "truncated body\n", null);
    }

    // --- Token verification (constant-time) + rate limit ----------------
    var resolved: webhook.Resolved = .{};
    const vr = store.verify(parsed_target.id, parsed_target.token, now_ms, cfg.rate, &resolved);
    switch (vr.status) {
        .not_found => return writeSimple(out, "404 Not Found", "unknown webhook\n", null),
        .bad_token => return writeSimple(out, "401 Unauthorized", "invalid token\n", null),
        .rate_limited => return writeSimple(out, "429 Too Many Requests", "rate limited\n", vr.retry_after_sec),
        .ok => {},
    }

    // --- Render (fail-closed on hostile / empty JSON) -------------------
    var post: webhook.PendingPost = .{};
    post.setChannel(resolved.channel());
    webhook_render.render(allocator, body_slice, resolved.name(), &post) catch |e| switch (e) {
        error.BadJson => return writeSimple(out, "400 Bad Request", "invalid payload\n", null),
        error.EmptyPayload => return writeSimple(out, "400 Bad Request", "empty payload\n", null),
    };

    // --- Hand off to the reactor ----------------------------------------
    if (!sink.tryPost(&post))
        return writeSimple(out, "429 Too Many Requests", "server busy\n", cfg.busy_retry_after);

    // 204 No Content: success, no body (Discord's success code).
    const resp = std.fmt.bufPrint(out, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n", .{}) catch
        return error.NoSpaceLeft;
    return resp;
}

/// Parse a `Content-Length` header value from the header block (case-insensitive
/// key). Returns null if absent or unparseable.
fn contentLength(headers: []const u8) ?usize {
    var it = std.mem.splitSequence(u8, headers, "\r\n");
    while (it.next()) |h| {
        const colon = std.mem.indexOfScalar(u8, h, ':') orelse continue;
        const key = std.mem.trim(u8, h[0..colon], " ");
        if (!std.ascii.eqlIgnoreCase(key, "content-length")) continue;
        const val = std.mem.trim(u8, h[colon + 1 ..], " \t");
        return std.fmt.parseInt(usize, val, 10) catch null;
    }
    return null;
}

/// A small fixed-body response (all non-204 outcomes). When `retry_after` is
/// set, a `Retry-After` header is included (429).
fn writeSimple(out: []u8, status: []const u8, body: []const u8, retry_after: ?u32) error{NoSpaceLeft}![]const u8 {
    const header = if (retry_after) |ra|
        std.fmt.bufPrint(
            out,
            "HTTP/1.1 {s}\r\nContent-Type: text/plain; charset=utf-8\r\nRetry-After: {d}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
            .{ status, ra, body.len },
        ) catch return error.NoSpaceLeft
    else
        std.fmt.bufPrint(
            out,
            "HTTP/1.1 {s}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
            .{ status, body.len },
        ) catch return error.NoSpaceLeft;
    if (out.len - header.len < body.len) return error.NoSpaceLeft;
    @memcpy(out[header.len .. header.len + body.len], body);
    return out[0 .. header.len + body.len];
}

// ---------------------------------------------------------------------------
// Threaded loopback listener
// ---------------------------------------------------------------------------

pub const Config = struct {
    listen_backlog: u31 = default_listen_backlog,
    accept_poll_ms: u32 = default_accept_poll_ms,
    conn_read_timeout_sec: u32 = default_conn_read_timeout_sec,
    bind_addr: u32 = loopback_addr,
    handler: HandlerConfig = .{},
};

pub const WebhookServer = struct {
    store: *webhook.WebhookStore,
    sink: webhook.PostSink,
    handler: HandlerConfig,
    listen_fd: linux.fd_t,
    port: u16,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = .{ .raw = false },
    conn_read_timeout_sec: u32 = default_conn_read_timeout_sec,

    /// Bind `<addr>:port` (port 0 = ephemeral). No thread runs yet; call `spawn`.
    /// The returned value must live at a stable address for the thread's life.
    pub fn init(
        store: *webhook.WebhookStore,
        sink: webhook.PostSink,
        port: u16,
        config: Config,
    ) ListenerError!WebhookServer {
        const fd = try socketTcp();
        errdefer closeFd(fd);

        var yes: u32 = 1;
        _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes), @sizeOf(u32));

        var addr = linux.sockaddr.in{
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, config.bind_addr),
        };
        if (posix.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
            return error.BindFailed;
        if (posix.errno(linux.listen(fd, config.listen_backlog)) != .SUCCESS)
            return error.ListenFailed;

        const tv = linux.timeval{
            .sec = @intCast(config.accept_poll_ms / 1000),
            .usec = @intCast((config.accept_poll_ms % 1000) * 1000),
        };
        _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));

        return .{
            .store = store,
            .sink = sink,
            .handler = config.handler,
            .listen_fd = fd,
            .port = try boundPort(fd),
            .conn_read_timeout_sec = config.conn_read_timeout_sec,
        };
    }

    pub fn spawn(self: *WebhookServer) std.Thread.SpawnError!void {
        self.thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
    }

    pub fn shutdown(self: *WebhookServer) void {
        self.stop_flag.store(true, .release);
        closeFd(self.listen_fd); // unblocks a blocking accept4 with EBADF
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn acceptLoop(self: *WebhookServer) void {
        while (!self.stop_flag.load(.acquire)) {
            const rc = linux.accept4(self.listen_fd, null, null, posix.SOCK.CLOEXEC);
            switch (posix.errno(rc)) {
                .SUCCESS => self.serveConn(@intCast(rc)),
                .AGAIN, .INTR, .CONNABORTED => continue,
                else => return,
            }
        }
    }

    fn serveConn(self: *WebhookServer, fd: linux.fd_t) void {
        defer closeFd(fd);
        const tv = linux.timeval{ .sec = @intCast(self.conn_read_timeout_sec), .usec = 0 };
        _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));

        // Read request headers + body (bounded). The read loop stops once the
        // full declared body is present, the buffer fills, or the socket idles.
        var req_buf: [max_header + max_body_hard]u8 = undefined;
        const n = readRequest(fd, &req_buf, self.handler.max_body) orelse return;
        if (n == 0) return;

        var scratch: [json_scratch]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&scratch);

        var resp_buf: [1024]u8 = undefined;
        const now_ms = @import("../substrate/platform.zig").monotonicMillis();
        const resp = handleRequest(
            self.store,
            self.sink,
            self.handler,
            fba.allocator(),
            req_buf[0..n],
            now_ms,
            &resp_buf,
        ) catch return;
        writeAll(fd, resp);
    }
};

/// Read a full HTTP request (headers + declared body) into `buf`. Returns the
/// byte count, or null on read error before any bytes. Stops early once the
/// declared `Content-Length` body is complete so a keep-alive-less client that
/// leaves the socket open does not stall the loop for the whole read timeout.
fn readRequest(fd: linux.fd_t, buf: []u8, max_body: usize) ?usize {
    var total: usize = 0;
    var header_end: ?usize = null;
    var need: ?usize = null; // total bytes required once headers are parsed
    while (total < buf.len) {
        const rc = linux.read(fd, buf[total..].ptr, buf.len - total);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return if (total == 0) null else total,
        }
        const got: usize = @intCast(rc);
        if (got == 0) break; // peer closed
        total += got;

        if (header_end == null) {
            if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n")) |he| {
                header_end = he;
                const clen = contentLength(buf[0..he]) orelse 0;
                // Stop reading at most one byte past the configured cap: a body
                // declared larger than `max_body` is a guaranteed 413, so there is
                // no reason to slurp the whole (possibly 64 KiB) declared payload.
                const wanted = @min(clen, max_body + 1);
                need = he + 4 + wanted;
            }
        }
        if (need) |req| {
            if (total >= req) break; // full request (or the cap+1) in hand
        }
    }
    return total;
}

// ---------------------------------------------------------------------------
// Low-level helpers (raw linux syscalls), mirroring metrics_http.zig
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
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(linux.getsockname(fd, @ptrCast(&storage), &slen)) != .SUCCESS)
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

const testing = std.testing;

/// A test sink that records the last post and can be forced to reject (full).
const RecordingSink = struct {
    got: ?webhook.PendingPost = null,
    accept: bool = true,

    fn submit(ctx: *anyopaque, post: *const webhook.PendingPost) bool {
        const self: *RecordingSink = @ptrCast(@alignCast(ctx));
        if (!self.accept) return false;
        self.got = post.*;
        return true;
    }

    fn sink(self: *RecordingSink) webhook.PostSink {
        return .{ .ctx = self, .submit = submit };
    }
};

fn seed(store: *webhook.WebhookStore) webhook.Credentials {
    const idm: [webhook.id_bytes]u8 = @splat(0xAB);
    const tkm: [webhook.token_bytes]u8 = @splat(0xCD);
    return store.create("#alerts", "hook", "op", 0, 0, .{}, idm, tkm) catch unreachable;
}

fn buildRequest(buf: []u8, id: []const u8, token: []const u8, body: []const u8) []const u8 {
    return std.fmt.bufPrint(
        buf,
        "POST /api/webhooks/{s}/{s} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
        .{ id, token, body.len, body },
    ) catch unreachable;
}

test "handleRequest returns 204 and enqueues a post on a valid request" {
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};

    var reqbuf: [512]u8 = undefined;
    const req = buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"hi\"}");

    var out: [1024]u8 = undefined;
    const resp = try handleRequest(&store, rec.sink(), .{}, testing.allocator, req, 0, &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 204 No Content\r\n"));
    try testing.expect(rec.got != null);
    try testing.expectEqualStrings("#alerts", rec.got.?.channel());
    try testing.expectEqualStrings("hi", rec.got.?.body());
}

test "handleRequest 404 for unknown id, 401 for bad token" {
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};

    var reqbuf: [512]u8 = undefined;
    var out: [1024]u8 = undefined;

    var unknown: [webhook.id_hex_len]u8 = @splat('0');
    const r404 = try handleRequest(&store, rec.sink(), .{}, testing.allocator, buildRequest(&reqbuf, &unknown, &creds.token, "{\"content\":\"x\"}"), 0, &out);
    try testing.expect(std.mem.startsWith(u8, r404, "HTTP/1.1 404 Not Found\r\n"));

    const r401 = try handleRequest(&store, rec.sink(), .{}, testing.allocator, buildRequest(&reqbuf, &creds.id, "wrongtoken", "{\"content\":\"x\"}"), 0, &out);
    try testing.expect(std.mem.startsWith(u8, r401, "HTTP/1.1 401 Unauthorized\r\n"));
    // Neither error posted anything.
    try testing.expect(rec.got == null);
}

test "handleRequest 400 for bad JSON and empty payload" {
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};
    var reqbuf: [512]u8 = undefined;
    var out: [1024]u8 = undefined;

    const bad = try handleRequest(&store, rec.sink(), .{}, testing.allocator, buildRequest(&reqbuf, &creds.id, &creds.token, "not json"), 0, &out);
    try testing.expect(std.mem.startsWith(u8, bad, "HTTP/1.1 400 Bad Request\r\n"));

    const empty = try handleRequest(&store, rec.sink(), .{}, testing.allocator, buildRequest(&reqbuf, &creds.id, &creds.token, "{}"), 0, &out);
    try testing.expect(std.mem.startsWith(u8, empty, "HTTP/1.1 400 Bad Request\r\n"));
}

test "handleRequest 405 for a non-POST method on a valid webhook path" {
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};
    var out: [1024]u8 = undefined;
    var reqbuf: [512]u8 = undefined;
    const req = std.fmt.bufPrint(&reqbuf, "GET /api/webhooks/{s}/{s} HTTP/1.1\r\nHost: x\r\n\r\n", .{ creds.id, creds.token }) catch unreachable;
    const resp = try handleRequest(&store, rec.sink(), .{}, testing.allocator, req, 0, &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 405 Method Not Allowed\r\n"));
}

test "handleRequest 413 when the declared body exceeds the cap" {
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};
    var out: [1024]u8 = undefined;
    var reqbuf: [512]u8 = undefined;
    // Declare a huge Content-Length with a tiny cap.
    const req = std.fmt.bufPrint(&reqbuf, "POST /api/webhooks/{s}/{s} HTTP/1.1\r\nContent-Length: 99999\r\n\r\n{{}}", .{ creds.id, creds.token }) catch unreachable;
    const resp = try handleRequest(&store, rec.sink(), .{ .max_body = 16 }, testing.allocator, req, 0, &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 413 Payload Too Large\r\n"));
}

test "handleRequest 429 with Retry-After when rate limited" {
    var store = webhook.WebhookStore.init();
    const idm: [webhook.id_bytes]u8 = @splat(1);
    const tkm: [webhook.token_bytes]u8 = @splat(2);
    const creds = try store.create("#c", "h", "o", 0, 0, .{ .per_min = 60, .burst = 1 }, idm, tkm);
    var rec = RecordingSink{};
    const cfg = HandlerConfig{ .rate = .{ .per_min = 60, .burst = 1 } };
    var reqbuf: [512]u8 = undefined;
    var out: [1024]u8 = undefined;

    // First succeeds.
    _ = try handleRequest(&store, rec.sink(), cfg, testing.allocator, buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"a\"}"), 0, &out);
    // Second within the same instant → 429 + Retry-After.
    const limited = try handleRequest(&store, rec.sink(), cfg, testing.allocator, buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"b\"}"), 0, &out);
    try testing.expect(std.mem.startsWith(u8, limited, "HTTP/1.1 429 Too Many Requests\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, limited, 1, "Retry-After: "));
}

test "handleRequest 429 server busy when the sink is full" {
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{ .accept = false };
    var reqbuf: [512]u8 = undefined;
    var out: [1024]u8 = undefined;
    const resp = try handleRequest(&store, rec.sink(), .{}, testing.allocator, buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"x\"}"), 0, &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 429 Too Many Requests\r\n"));
}

test "contentLength parses case-insensitively" {
    try testing.expectEqual(@as(?usize, 42), contentLength("Host: x\r\ncontent-length: 42\r\nX: y"));
    try testing.expectEqual(@as(?usize, 7), contentLength("CONTENT-LENGTH:7"));
    try testing.expectEqual(@as(?usize, null), contentLength("Host: x"));
}

test "WebhookServer serves a POST over loopback and enqueues a post" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};

    var server = WebhookServer.init(&store, rec.sink(), 0, .{}) catch return error.SkipZigTest;
    try server.spawn();
    defer server.shutdown();

    const cfd = try socketTcp();
    defer closeFd(cfd);
    var addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, server.port),
        .addr = std.mem.nativeToBig(u32, loopback_addr),
    };
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(linux.connect(cfd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))));

    var reqbuf: [512]u8 = undefined;
    const req = buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"loop\"}");
    writeAll(cfd, req);

    var buf: [512]u8 = undefined;
    const rc = linux.read(cfd, &buf, buf.len);
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
    const got = buf[0..@intCast(rc)];
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 204 No Content\r\n"));

    // The post reached the sink (poll briefly for the accept-loop thread).
    var tries: usize = 0;
    while (rec.got == null and tries < 1000) : (tries += 1) std.Thread.yield() catch {};
    try testing.expect(rec.got != null);
    try testing.expectEqualStrings("loop", rec.got.?.body());
}

test {
    testing.refAllDecls(@This());
}
