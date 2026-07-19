// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-daemon OCSP-staple fetch/verify/cache/refresh scheduler.
//!
//! Mirrors `acme_renewal.Service`: a dedicated OS thread that never touches live
//! TLS listener state. Each cycle it re-reads the leaf + issuer from the
//! configured cert file, builds an OCSP request for the leaf's AIA responder URL,
//! POSTs it over the off-reactor blocking `http_fetch` transport, verifies +
//! freshness-gates the response with `ocsp.isStapleServable`, and — only on a
//! good, in-window, issuer-signed response — hands the raw DER to the server via
//! `publishOcspStaple`, which reactor 0 swaps into `config.tls_ocsp_staple`.
//!
//! Failure is non-fatal and non-destructive: on any fetch/verify/freshness error
//! the previously published staple keeps serving until it actually expires (the
//! server never clears a good staple on our behalf). A `revoked` response for our
//! own leaf is logged CRITICAL and never stapled.

const std = @import("std");
const dlog = @import("dlog.zig");
const linux = std.os.linux;

const config_format = @import("config_format.zig");
const http_fetch = @import("http_fetch.zig");
const http1 = @import("../proto/http1_client.zig");
const ocsp = @import("../crypto/ocsp.zig");
const platform = @import("../substrate/platform.zig");
const server_mod = @import("server.zig");
const tls_certs = @import("tls_certs.zig");
const x509 = @import("../crypto/x509.zig");

const wake_poll_ms: u64 = 1000;
const ocsp_request_content_type = "application/ocsp-request";
/// DER serials are <= 20 bytes (RFC 5280 §4.1.2.2) plus a possible sign octet.
const max_serial_len = 24;

/// Tunables for the fetch scheduler. `main.zig` populates these from the
/// `[ocsp]` config section; defaults are safe for a Let's Encrypt-style leaf.
pub const Options = struct {
    /// How often the worker wakes to check whether a (re)fetch is due. The actual
    /// responder is only contacted when the cached staple is stale or missing.
    check_interval_ms: u64 = 15 * 60 * 1000,
    /// Never re-contact the responder more often than this after a success.
    min_refresh_seconds: i64 = 5 * 60,
    /// Re-contact the responder at least this often even if nextUpdate is distant.
    max_refresh_seconds: i64 = 24 * 60 * 60,
    /// Clock-skew tolerance applied to thisUpdate/nextUpdate freshness checks.
    skew_seconds: i64 = ocsp.default_staple_skew_seconds,
    connect_timeout_ms: u31 = 5000,
    recv_timeout_ms: u31 = 10000,
    max_response_bytes: usize = 64 * 1024,
};

/// Seconds until the next responder contact for a staple valid over
/// `[this_update, next_update)`, evaluated at `now`. Standard stapling practice
/// refreshes at the halfway point; the result is clamped to `[min_s, max_s]` so a
/// long-lived response is still re-checked and a near-expiry one is not hammered.
pub fn refreshDelaySeconds(
    this_update: i64,
    next_update: i64,
    now: i64,
    min_s: i64,
    max_s: i64,
) i64 {
    const halfway = this_update + @divTrunc(next_update - this_update, 2);
    const delay = halfway - now;
    return std.math.clamp(delay, min_s, max_s);
}

/// Retry delay after `failures` consecutive responder-fetch failures: exponential
/// backoff starting at `min_s` and doubling each additional failure, clamped to
/// `max_s`. `failures == 0/1` yields `min_s`. Keeps a down responder from being
/// hammered every check interval while still recovering within `max_s`.
pub fn backoffSeconds(failures: u32, min_s: i64, max_s: i64) i64 {
    var delay = min_s;
    var n: u32 = 1;
    while (n < failures and delay < max_s) : (n += 1) {
        // Guard against i64 overflow on an absurd `max_s`; we clamp anyway.
        if (delay > @divTrunc(std.math.maxInt(i64), 2)) {
            delay = max_s;
            break;
        }
        delay *= 2;
    }
    return std.math.clamp(delay, min_s, max_s);
}

/// Extract the DER OCSPResponse body from a complete HTTP response, or null if
/// the status is not 200 or the body is empty. `http_response` is decoded in
/// place (chunked/Content-Length framing); the returned slice aliases it.
pub fn extractOcspBody(http_response: []u8) ?[]const u8 {
    var header_storage: [32]http1.Header = undefined;
    const resp = http1.parseResponse(http_response, &header_storage) catch return null;
    if (resp.status != 200) return null;
    if (resp.body.len == 0) return null;
    return resp.body;
}

pub const Service = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server: *server_mod.Server,
    tls: *const config_format.Config.Tls,
    opts: Options,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    // Bookkeeping so a fresh, still-valid staple isn't re-fetched every wake.
    last_serial: [max_serial_len]u8 = undefined,
    last_serial_len: usize = 0,
    next_refresh_unix: i64 = 0,
    // Exponential-backoff state so a down responder isn't re-contacted every check
    // interval. Reset on a successful publish or a leaf-serial change.
    fail_count: u32 = 0,
    next_retry_unix: i64 = 0,
    // One-shot log gates for persistent skip conditions (avoid per-wake spam).
    warned_no_issuer: bool = false,
    warned_no_aia: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        server: *server_mod.Server,
        tls: *const config_format.Config.Tls,
        opts: Options,
    ) Service {
        return .{
            .allocator = allocator,
            .io = io,
            .server = server,
            .tls = tls,
            .opts = opts,
        };
    }

    pub fn start(self: *Service) void {
        if (self.thread != null) return;
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, worker, .{self}) catch |err| {
            dlog.log("onyx-server: ocsp stapler start failed ({s}); stapling disabled\n", .{@errorName(err)});
            return;
        };
        dlog.log("onyx-server: ocsp staple scheduler enabled (check interval {d}ms)\n", .{self.opts.check_interval_ms});
    }

    pub fn stop(self: *Service) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn worker(self: *Service) void {
        // Fetch promptly at startup, then on the check interval.
        self.checkOnce();
        while (!self.stop_flag.load(.acquire)) {
            if (!sleepInterruptible(self.opts.check_interval_ms, &self.stop_flag)) break;
            self.checkOnce();
        }
    }

    fn checkOnce(self: *Service) void {
        const cert_path = self.tls.cert_path orelse return;

        const chain = tls_certs.loadCertChain(self.allocator, self.io, cert_path) catch |err| {
            dlog.log("onyx-server: ocsp staple skipped: cannot read cert file {s} ({s})\n", .{ cert_path, @errorName(err) });
            return;
        };
        defer {
            for (chain) |der| self.allocator.free(der);
            self.allocator.free(chain);
        }
        if (chain.len < 2) {
            if (!self.warned_no_issuer) {
                dlog.log("onyx-server: ocsp staple disabled: cert file {s} has no issuer cert (need fullchain)\n", .{cert_path});
                self.warned_no_issuer = true;
            }
            return;
        }
        self.warned_no_issuer = false;

        const leaf = x509.parse(chain[0]) catch |err| {
            dlog.log("onyx-server: ocsp staple skipped: cannot parse leaf cert ({s})\n", .{@errorName(err)});
            return;
        };
        const issuer = x509.parse(chain[1]) catch |err| {
            dlog.log("onyx-server: ocsp staple skipped: cannot parse issuer cert ({s})\n", .{@errorName(err)});
            return;
        };
        if (leaf.aia_ocsp_url.len == 0) {
            if (!self.warned_no_aia) {
                dlog.log("onyx-server: ocsp staple disabled: leaf has no AIA OCSP responder URL\n", .{});
                self.warned_no_aia = true;
            }
            return;
        }
        self.warned_no_aia = false;

        const now = @divTrunc(platform.realtimeMillis(), 1000);

        // A cert rotation (new serial vs the last published one) deserves a fresh
        // attempt, not the backoff accumulated against the previous leaf.
        if (self.last_serial_len != 0 and
            !std.mem.eql(u8, self.last_serial[0..self.last_serial_len], leaf.serial_der))
        {
            self.fail_count = 0;
            self.next_retry_unix = 0;
        }

        // A still-valid staple for this exact serial doesn't need re-fetching yet.
        if (self.hasFreshStapleFor(leaf.serial_der, now)) return;
        // Back off after consecutive failures instead of re-hammering a down
        // responder every check interval.
        if (now < self.next_retry_unix) return;

        if (!self.fetchAndPublish(leaf, issuer, now)) self.noteFetchFailure(now);
    }

    /// Record a failed fetch and schedule the next attempt with exponential
    /// backoff (`backoffSeconds`). Bounded so the counter can't wrap.
    fn noteFetchFailure(self: *Service, now: i64) void {
        if (self.fail_count < std.math.maxInt(u32)) self.fail_count += 1;
        const delay = backoffSeconds(self.fail_count, self.opts.min_refresh_seconds, self.opts.max_refresh_seconds);
        self.next_retry_unix = now + delay;
        dlog.log("onyx-server: ocsp fetch retry backing off {d}s after {d} consecutive failure(s)\n", .{ delay, self.fail_count });
    }

    /// Returns true when a fresh, servable staple was published; false on any
    /// failure (so the caller can apply backoff).
    fn fetchAndPublish(self: *Service, leaf: x509.Certificate, issuer: x509.Certificate, now: i64) bool {
        const req = ocsp.buildRequestForCerts(self.allocator, leaf, issuer) catch |err| {
            dlog.log("onyx-server: ocsp staple skipped: cannot build request ({s})\n", .{@errorName(err)});
            return false;
        };
        defer self.allocator.free(req);

        const url = http_fetch.parseUrl(leaf.aia_ocsp_url) catch {
            dlog.log("onyx-server: ocsp staple skipped: malformed AIA URL\n", .{});
            return false;
        };
        // The OCSPResponse is signature-verified against the issuer below, so the
        // responder's transport authentication is not load-bearing — skip cert
        // verification for the (rare) HTTPS responder to avoid a trust-anchor loop.
        const http_resp = http_fetch.post(self.allocator, url, ocsp_request_content_type, req, .{
            .insecure_skip_verify = true,
            .connect_timeout_ms = self.opts.connect_timeout_ms,
            .recv_timeout_ms = self.opts.recv_timeout_ms,
            .max_response_bytes = self.opts.max_response_bytes,
        }) catch |err| {
            dlog.log("onyx-server: ocsp fetch failed ({s}); keeping current staple\n", .{@errorName(err)});
            return false;
        };
        defer self.allocator.free(http_resp);

        const der = extractOcspBody(http_resp) orelse {
            dlog.log("onyx-server: ocsp fetch: responder returned no usable OCSPResponse body\n", .{});
            return false;
        };

        // Surface a revocation of our OWN leaf loudly; never staple it. Trust the
        // revoked verdict only if the response is actually issuer-signed — the
        // transport runs with cert verification off (the response signature is the
        // real authenticator), so an unsigned injected "revoked" must not forge a
        // CRITICAL alert.
        if (ocsp.parse(der)) |parsed| {
            // Chain-aware: honor a revoked verdict signed by an issuer-authorized
            // delegated responder too (the common CA setup), not just a directly
            // issuer-signed one — otherwise a real revocation could be missed.
            if (ocsp.verifyResponseSignatureWithChain(parsed, issuer.spki_der, now)) {
                if (ocsp.statusForSerial(parsed, leaf.serial_der)) |status| {
                    if (status == .revoked) {
                        dlog.log("onyx-server: CRITICAL ocsp responder reports THIS server's certificate REVOKED — not stapling\n", .{});
                        return false;
                    }
                }
            }
        } else |_| {}

        if (!ocsp.isStapleServable(der, issuer.spki_der, leaf.serial_der, now, self.opts.skew_seconds)) {
            dlog.log("onyx-server: ocsp response not servable (bad sig/status/freshness); keeping current staple\n", .{});
            return false;
        }

        const owned = self.allocator.dupe(u8, der) catch {
            dlog.log("onyx-server: ocsp staple skipped: out of memory copying response\n", .{});
            return false;
        };
        self.server.publishOcspStaple(owned);
        self.recordPublished(der, leaf.serial_der, now);
        return true;
    }

    /// True when the last published staple covers `serial` and it is not yet time
    /// to refresh — lets the worker wake frequently without hammering responders.
    fn hasFreshStapleFor(self: *Service, serial: []const u8, now: i64) bool {
        if (self.last_serial_len == 0) return false;
        if (!std.mem.eql(u8, self.last_serial[0..self.last_serial_len], serial)) return false;
        return now < self.next_refresh_unix;
    }

    /// Record the serial + schedule the next responder contact from the freshly
    /// published response's thisUpdate/nextUpdate (falls back to min interval).
    fn recordPublished(self: *Service, der: []const u8, serial: []const u8, now: i64) void {
        // A successful publish clears the failure backoff.
        self.fail_count = 0;
        self.next_retry_unix = 0;
        if (serial.len <= max_serial_len) {
            @memcpy(self.last_serial[0..serial.len], serial);
            self.last_serial_len = serial.len;
        } else {
            self.last_serial_len = 0; // unexpectedly long serial: always re-fetch
        }

        var delay = self.opts.min_refresh_seconds;
        if (ocsp.parse(der)) |parsed| {
            if (ocsp.singleForSerial(parsed, serial)) |single| {
                if (single.next_update) |next_bytes| {
                    const this_e = x509.generalizedTimeToEpoch(single.this_update) catch now;
                    const next_e = x509.generalizedTimeToEpoch(next_bytes) catch (now + self.opts.min_refresh_seconds);
                    delay = refreshDelaySeconds(this_e, next_e, now, self.opts.min_refresh_seconds, self.opts.max_refresh_seconds);
                }
            }
        } else |_| {}
        self.next_refresh_unix = now + delay;
        dlog.log("onyx-server: ocsp staple published ({d} bytes); next refresh in {d}s\n", .{ der.len, delay });
    }
};

fn sleepInterruptible(total_ms: u64, stop_flag: *std.atomic.Value(bool)) bool {
    var remaining = total_ms;
    while (remaining > 0) {
        if (stop_flag.load(.acquire)) return false;
        const chunk = @min(remaining, wake_poll_ms);
        sleepMs(@intCast(chunk));
        remaining -= chunk;
    }
    return !stop_flag.load(.acquire);
}

fn sleepMs(ms: u32) void {
    var req = linux.timespec{ .sec = @divTrunc(ms, 1000), .nsec = @as(isize, ms % 1000) * 1_000_000 };
    _ = linux.nanosleep(&req, null);
}

test "refreshDelaySeconds halves the validity window, clamped" {
    const this_u: i64 = 1_700_000_000;
    const next_u: i64 = this_u + 4000; // 4000s window, halfway at +2000

    // Fetched at thisUpdate: refresh in ~half the window.
    try std.testing.expectEqual(@as(i64, 2000), refreshDelaySeconds(this_u, next_u, this_u, 60, 86_400));

    // Past the halfway point clamps up to the minimum, never negative.
    try std.testing.expectEqual(@as(i64, 60), refreshDelaySeconds(this_u, next_u, this_u + 3000, 60, 86_400));

    // A very long window clamps down to the daily ceiling.
    const long_next = this_u + 30 * 24 * 60 * 60;
    try std.testing.expectEqual(@as(i64, 86_400), refreshDelaySeconds(this_u, long_next, this_u, 60, 86_400));
}

test "backoffSeconds doubles per failure, clamped to [min,max]" {
    // 0/1 failures → the minimum.
    try std.testing.expectEqual(@as(i64, 300), backoffSeconds(0, 300, 86_400));
    try std.testing.expectEqual(@as(i64, 300), backoffSeconds(1, 300, 86_400));
    // Then doubles each additional failure.
    try std.testing.expectEqual(@as(i64, 600), backoffSeconds(2, 300, 86_400));
    try std.testing.expectEqual(@as(i64, 1200), backoffSeconds(3, 300, 86_400));
    try std.testing.expectEqual(@as(i64, 2400), backoffSeconds(4, 300, 86_400));
    // Clamps to max once the doubling would exceed it, and stays there.
    try std.testing.expectEqual(@as(i64, 86_400), backoffSeconds(20, 300, 86_400));
    try std.testing.expectEqual(@as(i64, 86_400), backoffSeconds(std.math.maxInt(u32), 300, 86_400));
    // A tiny window never returns below min even for 1 failure.
    try std.testing.expectEqual(@as(i64, 300), backoffSeconds(1, 300, 300));
}

test "extractOcspBody returns body only for a 200 with content" {
    const allocator = std.testing.allocator;

    {
        const raw = try allocator.dupe(u8, "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: 5\r\n\r\n\x30\x03\x0a\x01\x00");
        defer allocator.free(raw);
        const body = extractOcspBody(raw).?;
        try std.testing.expectEqualSlices(u8, "\x30\x03\x0a\x01\x00", body);
    }
    {
        const raw = try allocator.dupe(u8, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\n\r\nbad");
        defer allocator.free(raw);
        try std.testing.expect(extractOcspBody(raw) == null);
    }
    {
        const raw = try allocator.dupe(u8, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        defer allocator.free(raw);
        try std.testing.expect(extractOcspBody(raw) == null);
    }
}

test {
    std.testing.refAllDecls(@This());
}
