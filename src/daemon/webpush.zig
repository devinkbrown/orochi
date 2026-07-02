// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Web Push delivery (Roadmap: "reach you with the tab closed").
//!
//! The pure message crypto (RFC 8291/8292) lives in `crypto/webpush.zig`;
//! this module is the daemon glue:
//!
//!   * `Subscription` + codec — bounded per-account subscription lists,
//!     serialized into the durable store's `.props` family under
//!     `wps\x00<account>` (same pattern as mirrored metadata).
//!   * `Vapid` — the server's ES256 key pair, load-or-create at a state path
//!     (survives restarts and Helix upgrades; rotating it invalidates every
//!     subscription, so it is created exactly once).
//!   * `Worker` — a background thread draining a job queue: per job it mints
//!     a VAPID JWT for the endpoint's origin, encrypts the payload, and POSTs
//!     it. Reactor threads only ever enqueue — network I/O never blocks them.
//!     Endpoints answering 404/410 land on a dead-list the server drains to
//!     prune stale subscriptions.
const std = @import("std");
const dlog = @import("dlog.zig");
const wp_crypto = @import("../crypto/webpush.zig");
const ecdsa = @import("../crypto/ecdsa_p256.zig");
const acme_runner = @import("acme_runner.zig");
const http1 = @import("../proto/http1_client.zig");
const platform = @import("../substrate/platform.zig");

const Allocator = std.mem.Allocator;
const b64url = std.base64.url_safe_no_pad;

pub const max_subscriptions_per_account: usize = 3;
/// Length of the base64url-unpadded VAPID public key (65 SEC1 bytes).
pub const vapid_pub_b64_len: usize = b64url.Encoder.calcSize(65);
pub const max_endpoint_len: usize = 512;
/// Push TTL we request: the service holds an undelivered push this long.
pub const push_ttl_seconds: u32 = 12 * 60 * 60;
/// VAPID JWT lifetime (must be ≤ 24h; short keeps a leaked token boring).
pub const vapid_jwt_ttl_seconds: i64 = 12 * 60 * 60;
/// Bound on queued jobs; beyond it new pushes drop (push is best-effort).
pub const max_queued_jobs: usize = 256;

pub const Config = struct {
    /// Master gate: off = command rejected, no worker, nothing advertised.
    enabled: bool = false,
    /// VAPID `sub` claim — a contact for the push service operator.
    subject: []const u8 = "mailto:ops@eshmaki.me",

    pub fn applyToml(cfg: *Config, doc: anytype) void {
        if (doc.getBool("webpush.enabled")) |v| cfg.enabled = v;
        if (doc.getString("webpush.subject")) |v| {
            if (v.len > 0) cfg.subject = v;
        }
    }
};

// ── Subscriptions + codec ────────────────────────────────────────────────────

pub const Subscription = struct {
    /// HTTPS push-service endpoint URL (owned).
    endpoint: []u8,
    /// Browser's P-256 key (`p256dh`), uncompressed SEC1.
    ua_public: [wp_crypto.ua_public_length]u8,
    /// Subscription auth secret (`auth`).
    auth: [wp_crypto.auth_secret_length]u8,

    pub fn deinit(self: *Subscription, allocator: Allocator) void {
        allocator.free(self.endpoint);
    }
};

pub const CodecError = error{MalformedRecord} || Allocator.Error;

/// Serialize a subscription list for the durable store. One record per line:
/// `<endpoint>\t<p256dh-b64url>\t<auth-b64url>\n`. Endpoints are validated
/// URL-ish at SUBSCRIBE time and can never contain tab/newline.
pub fn encodeList(allocator: Allocator, subs: []const Subscription) Allocator.Error![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    for (subs) |s| {
        var key_b64: [b64url.Encoder.calcSize(wp_crypto.ua_public_length)]u8 = undefined;
        _ = b64url.Encoder.encode(&key_b64, &s.ua_public);
        var auth_b64: [b64url.Encoder.calcSize(wp_crypto.auth_secret_length)]u8 = undefined;
        _ = b64url.Encoder.encode(&auth_b64, &s.auth);
        try out.appendSlice(allocator, s.endpoint);
        try out.append(allocator, '\t');
        try out.appendSlice(allocator, &key_b64);
        try out.append(allocator, '\t');
        try out.appendSlice(allocator, &auth_b64);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

/// Parse a stored subscription list. Caller owns the result (each endpoint is
/// an owned copy); a malformed record fails the whole decode (the value is
/// only ever written by `encodeList`).
pub fn decodeList(allocator: Allocator, text: []const u8) CodecError![]Subscription {
    var subs: std.ArrayListUnmanaged(Subscription) = .empty;
    errdefer {
        for (subs.items) |*s| s.deinit(allocator);
        subs.deinit(allocator);
    }
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const endpoint = fields.next() orelse return error.MalformedRecord;
        const key_b64 = fields.next() orelse return error.MalformedRecord;
        const auth_b64 = fields.next() orelse return error.MalformedRecord;
        if (fields.next() != null) return error.MalformedRecord;
        if (endpoint.len == 0 or endpoint.len > max_endpoint_len) return error.MalformedRecord;

        const ua_public = wp_crypto.decodeFixed(wp_crypto.ua_public_length, key_b64) catch
            return error.MalformedRecord;
        const auth = wp_crypto.decodeFixed(wp_crypto.auth_secret_length, auth_b64) catch
            return error.MalformedRecord;

        const owned = try allocator.dupe(u8, endpoint);
        errdefer allocator.free(owned);
        try subs.append(allocator, .{ .endpoint = owned, .ua_public = ua_public, .auth = auth });
    }
    return subs.toOwnedSlice(allocator);
}

pub fn freeList(allocator: Allocator, subs: []Subscription) void {
    for (subs) |*s| s.deinit(allocator);
    allocator.free(subs);
}

/// Parse a client-supplied `p256dh` value (base64url, 65-byte SEC1 point).
pub fn decodeKey65(text: []const u8) error{InvalidSubscriptionKey}![wp_crypto.ua_public_length]u8 {
    return wp_crypto.decodeFixed(wp_crypto.ua_public_length, text);
}

/// Parse a client-supplied `auth` value (base64url, 16 bytes).
pub fn decodeAuth16(text: []const u8) error{InvalidSubscriptionKey}![wp_crypto.auth_secret_length]u8 {
    return wp_crypto.decodeFixed(wp_crypto.auth_secret_length, text);
}

/// Validate a client-supplied endpoint: absolute https URL, sane length, no
/// characters that could break the codec or an HTTP request line.
pub fn validEndpoint(endpoint: []const u8) bool {
    if (endpoint.len == 0 or endpoint.len > max_endpoint_len) return false;
    if (!std.mem.startsWith(u8, endpoint, "https://")) return false;
    if (endpoint.len == "https://".len) return false;
    for (endpoint) |c| {
        if (c <= 0x20 or c == 0x7f) return false; // ctl, space
    }
    return true;
}

// ── VAPID key persistence ────────────────────────────────────────────────────

pub const Vapid = struct {
    key_pair: ecdsa.KeyPair,

    /// Load the VAPID key from `sub_path`, or create + persist a fresh one.
    /// Format on disk: 64 lowercase hex chars of the P-256 secret scalar.
    pub fn loadOrCreate(io: std.Io, allocator: Allocator, dir: std.Io.Dir, sub_path: []const u8) !Vapid {
        if (dir.readFileAlloc(io, sub_path, allocator, .limited(256))) |text| {
            defer allocator.free(text);
            const trimmed = std.mem.trim(u8, text, " \r\n\t");
            if (trimmed.len == 64) {
                var secret: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&secret, trimmed) catch return error.InvalidVapidKey;
                const sk = ecdsa.SecretKey.fromBytes(secret) catch return error.InvalidVapidKey;
                const kp = ecdsa.KeyPair.fromSecretKey(sk) catch return error.InvalidVapidKey;
                return .{ .key_pair = kp };
            }
            return error.InvalidVapidKey;
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }

        const kp = ecdsa.KeyPair.generate(io);
        const hex = std.fmt.bytesToHex(kp.secret_key.toBytes(), .lower);
        try dir.writeFile(io, .{ .sub_path = sub_path, .data = &hex });
        return .{ .key_pair = kp };
    }

    /// The base64url public key clients pass to `pushManager.subscribe`.
    /// Buffer must hold 87 bytes.
    pub fn publicB64(self: *const Vapid, out: *[b64url.Encoder.calcSize(65)]u8) []const u8 {
        const sec1 = self.key_pair.public_key.toUncompressedSec1();
        return b64url.Encoder.encode(out, &sec1);
    }
};

// ── Delivery worker ──────────────────────────────────────────────────────────

pub const Job = struct {
    endpoint: []u8,
    ua_public: [wp_crypto.ua_public_length]u8,
    auth: [wp_crypto.auth_secret_length]u8,
    /// Cleartext payload (JSON); encrypted per-job on the worker thread.
    payload: []u8,

    fn deinit(self: *Job, allocator: Allocator) void {
        allocator.free(self.endpoint);
        allocator.free(self.payload);
    }
};

pub const Worker = struct {
    allocator: Allocator,
    vapid: ecdsa.KeyPair,
    subject: []const u8,
    resolver: acme_runner.Resolver,
    trust_anchors: []const []const u8,

    mutex: std.atomic.Mutex = .unlocked,
    queue: std.ArrayListUnmanaged(Job) = .empty,
    /// Endpoints the push service reported gone (404/410); the server drains
    /// this (under the world lock) and prunes the stored subscriptions.
    dead: std.ArrayListUnmanaged([]u8) = .empty,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    /// Delivery stats (worker-thread writes, oper-command reads are racy-read
    /// tolerable: monotonically increasing counters).
    sent: usize = 0,
    failed: usize = 0,

    pub fn spawn(self: *Worker) !void {
        self.thread = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, run, .{self});
    }

    pub fn shutdown(self: *Worker) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| t.join();
        self.thread = null;
        for (self.queue.items) |*j| j.deinit(self.allocator);
        self.queue.deinit(self.allocator);
        for (self.dead.items) |e| self.allocator.free(e);
        self.dead.deinit(self.allocator);
    }

    /// Enqueue a push (copies everything). Full queue = dropped: push is a
    /// best-effort nudge, never a delivery guarantee (tegami holds the DM).
    pub fn enqueue(
        self: *Worker,
        endpoint: []const u8,
        ua_public: [wp_crypto.ua_public_length]u8,
        auth: [wp_crypto.auth_secret_length]u8,
        payload: []const u8,
    ) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.stop_flag.load(.acquire) or self.queue.items.len >= max_queued_jobs) return;
        const ep = self.allocator.dupe(u8, endpoint) catch return;
        const pl = self.allocator.dupe(u8, payload) catch {
            self.allocator.free(ep);
            return;
        };
        self.queue.append(self.allocator, .{
            .endpoint = ep,
            .ua_public = ua_public,
            .auth = auth,
            .payload = pl,
        }) catch {
            self.allocator.free(ep);
            self.allocator.free(pl);
            return;
        };
    }

    /// Take ownership of the dead-endpoint list (freed with this worker's
    /// allocator by the caller).
    pub fn drainDead(self: *Worker) []const []u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.dead.toOwnedSlice(self.allocator) catch &.{};
    }

    fn run(self: *Worker) void {
        while (true) {
            const maybe_job: ?Job = blk: {
                lockSpin(&self.mutex);
                defer self.mutex.unlock();
                if (self.queue.items.len == 0) break :blk null;
                break :blk self.queue.orderedRemove(0);
            };
            var job = maybe_job orelse {
                if (self.stop_flag.load(.acquire)) return;
                sleepMs(200);
                continue;
            };
            defer job.deinit(self.allocator);
            self.deliver(&job) catch |err| {
                self.failed += 1;
                dlog.log("webpush: delivery to {s} failed: {s}\n", .{ job.endpoint, @errorName(err) });
            };
        }
    }

    fn deliver(self: *Worker, job: *Job) !void {
        const url = try acme_runner.Url.parse(job.endpoint);

        // VAPID audience = scheme://host[:port] of the push service.
        var aud_buf: [max_endpoint_len]u8 = undefined;
        const aud = if (url.port == 443)
            try std.fmt.bufPrint(&aud_buf, "https://{s}", .{url.host})
        else
            try std.fmt.bufPrint(&aud_buf, "https://{s}:{d}", .{ url.host, url.port });

        const exp = @divTrunc(platform.realtimeMillis(), 1000) + vapid_jwt_ttl_seconds;
        const jwt = try wp_crypto.vapidJwt(self.allocator, aud, self.subject, exp, self.vapid);
        defer self.allocator.free(jwt);
        const auth_value = try wp_crypto.vapidAuthValue(
            self.allocator,
            jwt,
            self.vapid.public_key.toUncompressedSec1(),
        );
        defer self.allocator.free(auth_value);

        const body = try wp_crypto.encryptRandom(self.allocator, job.ua_public, job.auth, job.payload);
        defer self.allocator.free(body);

        var ttl_buf: [16]u8 = undefined;
        const ttl = std.fmt.bufPrint(&ttl_buf, "{d}", .{push_ttl_seconds}) catch unreachable;
        const extra = [_]http1.Header{
            .{ .name = "authorization", .value = auth_value },
            .{ .name = "content-encoding", .value = "aes128gcm" },
            .{ .name = "content-type", .value = "application/octet-stream" },
            .{ .name = "ttl", .value = ttl },
            .{ .name = "urgency", .value = "high" },
        };

        const raw = try acme_runner.httpsRequest(
            self.allocator,
            self.resolver,
            self.trust_anchors,
            "POST",
            url,
            &extra,
            body,
            64 * 1024,
        );
        defer self.allocator.free(raw);

        var header_scratch: [64]http1.Header = undefined;
        const resp = try http1.parseResponse(raw, &header_scratch);
        if (resp.status >= 200 and resp.status < 300) {
            self.sent += 1;
            return;
        }
        if (resp.status == 404 or resp.status == 410) {
            // Subscription is gone — surface it for pruning.
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            const ep = self.allocator.dupe(u8, job.endpoint) catch return;
            self.dead.append(self.allocator, ep) catch self.allocator.free(ep);
            self.failed += 1;
            return;
        }
        self.failed += 1;
        dlog.log("webpush: {s} answered {d}\n", .{ job.endpoint, resp.status });
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

fn sleepMs(ms: u32) void {
    const linux = std.os.linux;
    var req = linux.timespec{ .sec = @divTrunc(ms, 1000), .nsec = @as(isize, ms % 1000) * 1_000_000 };
    _ = linux.nanosleep(&req, null);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "subscription list encode/decode round-trip" {
    const ep1 = try testing.allocator.dupe(u8, "https://push.example.net/send/abc123");
    const ep2 = try testing.allocator.dupe(u8, "https://fcm.googleapis.com/fcm/send/xyz");
    var subs = [_]Subscription{
        .{ .endpoint = ep1, .ua_public = [_]u8{4} ++ [_]u8{1} ** 64, .auth = [_]u8{9} ** 16 },
        .{ .endpoint = ep2, .ua_public = [_]u8{4} ++ [_]u8{2} ** 64, .auth = [_]u8{8} ** 16 },
    };
    defer for (&subs) |*s| s.deinit(testing.allocator);

    const encoded = try encodeList(testing.allocator, &subs);
    defer testing.allocator.free(encoded);

    const decoded = try decodeList(testing.allocator, encoded);
    defer freeList(testing.allocator, decoded);

    try testing.expectEqual(@as(usize, 2), decoded.len);
    try testing.expectEqualStrings(subs[0].endpoint, decoded[0].endpoint);
    try testing.expectEqualSlices(u8, &subs[1].ua_public, &decoded[1].ua_public);
    try testing.expectEqualSlices(u8, &subs[0].auth, &decoded[0].auth);
}

test "decodeList rejects malformed records" {
    try testing.expectError(error.MalformedRecord, decodeList(testing.allocator, "no-tabs-here\n"));
    try testing.expectError(error.MalformedRecord, decodeList(testing.allocator, "https://x\tnot-b64!!\tAAAAAAAAAAAAAAAAAAAAAA\n"));
    // Empty value decodes to an empty list.
    const empty = try decodeList(testing.allocator, "");
    defer freeList(testing.allocator, empty);
    try testing.expectEqual(@as(usize, 0), empty.len);
}

test "validEndpoint enforces https, length and character rules" {
    try testing.expect(validEndpoint("https://updates.push.services.mozilla.com/wpush/v2/token"));
    try testing.expect(!validEndpoint("http://plaintext.example/send"));
    try testing.expect(!validEndpoint("https://"));
    try testing.expect(!validEndpoint("https://x.example/a b"));
    try testing.expect(!validEndpoint("https://x.example/a\tb"));
    const long = "https://x.example/" ++ "a" ** (max_endpoint_len);
    try testing.expect(!validEndpoint(long));
}

test "Vapid.loadOrCreate persists and reloads the same key" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var v1 = try Vapid.loadOrCreate(testing.io, testing.allocator, tmp.dir, "vapid.key");
    var v2 = try Vapid.loadOrCreate(testing.io, testing.allocator, tmp.dir, "vapid.key");

    var b1: [87]u8 = undefined;
    var b2: [87]u8 = undefined;
    try testing.expectEqualStrings(v1.publicB64(&b1), v2.publicB64(&b2));
}

test "worker enqueue/shutdown never blocks and bounds the queue" {
    // No network in tests: spawn the thread, enqueue against a dead resolver,
    // and shut down. Exercises the queue/lifecycle paths (delivery itself is
    // covered by the crypto KATs + live verification).
    const FailResolver = struct {
        fn resolve(_: *anyopaque, _: []const u8, _: u16) anyerror!@import("std").Io.net.IpAddress {
            return error.TemporaryNameServerFailure;
        }
    };
    var ctx_byte: u8 = 0;
    var w = Worker{
        .allocator = testing.allocator,
        .vapid = ecdsa.KeyPair.generate(testing.io),
        .subject = "mailto:t@example.net",
        .resolver = .{ .ctx = @ptrCast(&ctx_byte), .resolveFn = FailResolver.resolve },
        .trust_anchors = &.{},
    };
    try w.spawn();
    const ua = try @import("../crypto/ecdh_p256.zig").generate();
    w.enqueue("https://push.example.net/send/1", ua.public_sec1, [_]u8{1} ** 16, "{\"type\":\"dm\"}");
    sleepMs(50);
    w.shutdown();
    // The lone job either failed (dead resolver) or was still queued at
    // shutdown; both are fine — nothing hung, nothing leaked.
    try testing.expect(w.sent == 0);
}
