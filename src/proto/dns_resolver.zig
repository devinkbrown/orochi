//! Async DNS resolver core — the transaction multiplexer that sits between the
//! pure wire codec (`dns.zig`) and a live datagram transport (io_uring UDP, the
//! simulation reactor, or a test harness).
//!
//! This module performs NO I/O. It owns the parts that are awkward to get right
//! and easy to get wrong:
//!   * 16-bit transaction-id allocation that never collides with an in-flight id,
//!   * a pending-request table keyed by that id,
//!   * matching an inbound datagram back to the request that asked for it,
//!   * timeout expiry of unanswered requests, and
//!   * a TTL cache so repeat lookups skip the wire entirely.
//!
//! The caller drives it at the edges:
//!   1. `resolvePtr` / `resolveHost` -> either a cached answer or wire bytes to
//!      transmit (a pending entry is registered for the latter).
//!   2. feed every inbound datagram to `onResponse` -> an optional `Resolved`.
//!   3. call `sweep` periodically -> timed-out requests reported as failures.
//!
//! `caller` is an opaque `u64` the daemon uses to tie an answer back to whatever
//! asked (e.g. a packed client token). Because answers can arrive after the
//! asker is gone, the wiring layer MUST re-validate `caller` against live state
//! before applying a result — exactly like an io_uring completion re-validates a
//! generational slot.

const std = @import("std");
const dns = @import("dns.zig");
const secure_fns = @import("secure_fns.zig");

/// The question types this resolver can issue and parse (mirrors the subset the
/// `dns.zig` codec supports). TXT/SRV are intentionally absent until the codec
/// grows them.
pub const QueryKind = enum { ptr, a, aaaa };

/// The shape of a completed lookup.
pub const ResultKind = enum {
    /// A PTR lookup produced a hostname (see `Resolved.name`).
    ptr,
    /// An A/AAAA lookup produced one or more addresses (see `Resolved.addresses`).
    addrs,
    /// The name does not exist (NXDOMAIN) or no matching records were returned.
    nxdomain,
    /// The resolver/server failed, or the request timed out with no answer.
    failure,
};

/// A completed lookup, with inline fixed storage so it never borrows from the
/// transient parse buffer that produced it.
pub const Resolved = struct {
    caller: u64,
    query: QueryKind,
    kind: ResultKind,
    name_buf: [dns.max_domain_text_len]u8 = undefined,
    name_len: usize = 0,
    addrs: [dns.max_cache_addrs]dns.Address = undefined,
    addrs_len: usize = 0,

    /// The resolved hostname for a `.ptr` result (empty otherwise).
    pub fn name(self: *const Resolved) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    /// The resolved addresses for an `.addrs` result (empty otherwise).
    pub fn addresses(self: *const Resolved) []const dns.Address {
        return self.addrs[0..self.addrs_len];
    }
};

/// The outcome of an issue request.
pub const Outcome = union(enum) {
    /// Served from cache; no datagram needs to be sent.
    cached: Resolved,
    /// A query was encoded into the caller's buffer and a pending entry was
    /// registered. Transmit these bytes; the answer arrives via `onResponse`.
    sent: []const u8,
};

pub const Options = struct {
    /// How long an unanswered request lives before `sweep` reports it failed.
    timeout_ms: i64 = 5_000,
    /// TTL floor applied to cached answers whose record TTL is below it, so a
    /// hostile/buggy server can't force constant re-querying. Seconds.
    min_ttl_seconds: u32 = 30,
    /// TTL ceiling applied to cached answers. Seconds.
    max_ttl_seconds: u32 = 3600,
};

pub const ResolverError = std.mem.Allocator.Error || dns.EncodeError || error{
    /// Every one of the 65 535 usable transaction ids is currently in flight.
    NoFreeTransactionId,
};

/// One in-flight request awaiting a matching response.
const Pending = struct {
    caller: u64,
    query: QueryKind,
    deadline_ms: i64,
    /// The address questioned by a PTR request (used to key the PTR cache on
    /// answer). Undefined for forward lookups.
    address: dns.Address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
    /// The questioned hostname for a forward lookup (used to key the host cache
    /// on answer). Empty for PTR requests.
    name_buf: [dns.max_domain_text_len]u8 = undefined,
    name_len: usize = 0,
};

/// Max answer records parsed from a single response. RRsets larger than this are
/// truncated to the first N — ample for host/reverse lookups.
const max_answers = 8;

pub const Resolver = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    cache: dns.Cache,
    pending: std.AutoHashMapUnmanaged(u16, Pending) = .empty,
    options: Options,

    pub fn init(allocator: std.mem.Allocator, options: Options) Self {
        return .{
            .allocator = allocator,
            .cache = dns.Cache.init(allocator),
            .options = options,
        };
    }

    pub fn deinit(self: *Self) void {
        self.pending.deinit(self.allocator);
        self.cache.deinit();
        self.* = undefined;
    }

    /// Number of requests currently awaiting a response.
    pub fn inFlight(self: *const Self) usize {
        return self.pending.count();
    }

    /// Resolve the hostname for `address` (reverse DNS). Returns a cached answer
    /// when known, otherwise encodes a PTR query into `out` and registers it.
    pub fn resolvePtr(
        self: *Self,
        caller: u64,
        address: dns.Address,
        now_ms: i64,
        out: []u8,
    ) ResolverError!Outcome {
        if (self.cache.getPtr(now_ms, address)) |host| {
            var r = Resolved{ .caller = caller, .query = .ptr, .kind = .ptr };
            r.name_len = @min(host.len, r.name_buf.len);
            @memcpy(r.name_buf[0..r.name_len], host[0..r.name_len]);
            return .{ .cached = r };
        }

        const id = try self.allocId();
        const wire = try dns.encodePtrQuery(out, id, address);
        try self.pending.put(self.allocator, id, .{
            .caller = caller,
            .query = .ptr,
            .deadline_ms = now_ms + self.options.timeout_ms,
            .address = address,
        });
        return .{ .sent = wire };
    }

    /// Resolve the addresses for `host` (forward DNS). `qtype` selects A or AAAA.
    pub fn resolveHost(
        self: *Self,
        caller: u64,
        host: []const u8,
        qtype: QueryKind,
        now_ms: i64,
        out: []u8,
    ) ResolverError!Outcome {
        std.debug.assert(qtype != .ptr);
        if (self.cache.getHost(now_ms, host)) |entry| {
            var r = Resolved{ .caller = caller, .query = qtype, .kind = .addrs };
            r.addrs_len = entry.addrs_len;
            for (entry.addressSlice(), 0..) |a, i| r.addrs[i] = a;
            return .{ .cached = r };
        }

        const id = try self.allocId();
        const rtype: dns.RecordType = if (qtype == .a) .a else .aaaa;
        const wire = try dns.encodeQuery(out, id, host, rtype);
        var entry = Pending{
            .caller = caller,
            .query = qtype,
            .deadline_ms = now_ms + self.options.timeout_ms,
        };
        entry.name_len = @min(host.len, entry.name_buf.len);
        @memcpy(entry.name_buf[0..entry.name_len], host[0..entry.name_len]);
        try self.pending.put(self.allocator, id, entry);
        return .{ .sent = wire };
    }

    /// Feed one inbound datagram. Returns the completed lookup when the response
    /// matches an in-flight request, or null for stale/unsolicited/garbage
    /// packets (which are ignored, never fatal).
    pub fn onResponse(self: *Self, datagram: []const u8, now_ms: i64) ?Resolved {
        const msg = dns.parseMessage(1, max_answers, datagram) catch return null;
        if (!msg.header.isResponse()) return null;

        const removed = self.pending.fetchRemove(msg.header.id) orelse return null;
        const p = removed.value;

        var r = Resolved{ .caller = p.caller, .query = p.query, .kind = .failure };

        if (msg.header.rcode() != 0) {
            r.kind = if (msg.header.rcode() == 3) .nxdomain else .failure;
            return r;
        }

        switch (p.query) {
            .ptr => {
                for (msg.answerSlice()) |rr| {
                    if (rr.rr_type != .ptr) continue;
                    const host = rr.data.ptr.slice();
                    r.kind = .ptr;
                    r.name_len = @min(host.len, r.name_buf.len);
                    @memcpy(r.name_buf[0..r.name_len], host[0..r.name_len]);
                    self.cache.putPtr(now_ms, p.address, r.name(), self.clampTtl(rr.ttl)) catch {};
                    return r;
                }
                r.kind = .nxdomain;
            },
            .a, .aaaa => {
                const want: dns.RecordType = if (p.query == .a) .a else .aaaa;
                var n: usize = 0;
                for (msg.answerSlice()) |rr| {
                    if (rr.rr_type != want or n >= r.addrs.len) continue;
                    r.addrs[n] = switch (rr.data) {
                        .a => |b| .{ .ipv4 = b },
                        .aaaa => |b| .{ .ipv6 = b },
                        .ptr => continue,
                    };
                    n += 1;
                }
                r.addrs_len = n;
                if (n == 0) {
                    r.kind = .nxdomain;
                } else {
                    r.kind = .addrs;
                    const host = p.name_buf[0..p.name_len];
                    self.cache.putHost(now_ms, host, r.addresses(), self.clampTtl(0)) catch {};
                }
            },
        }
        return r;
    }

    /// Report and drop every request whose deadline has passed. Fills `out` with
    /// `.failure` results (one per timed-out request) and returns how many. When
    /// `out` is smaller than the number of expirations, the remainder stay
    /// pending and are reported on the next sweep.
    pub fn sweep(self: *Self, now_ms: i64, out: []Resolved) usize {
        var n: usize = 0;
        var expired: [64]u16 = undefined;
        var ecount: usize = 0;
        var it = self.pending.iterator();
        while (it.next()) |entry| {
            if (now_ms < entry.value_ptr.deadline_ms) continue;
            if (n >= out.len or ecount >= expired.len) break;
            out[n] = .{ .caller = entry.value_ptr.caller, .query = entry.value_ptr.query, .kind = .failure };
            expired[ecount] = entry.key_ptr.*;
            n += 1;
            ecount += 1;
        }
        for (expired[0..ecount]) |id| _ = self.pending.remove(id);
        return n;
    }

    /// Drop any in-flight requests issued for `caller` (e.g. the asking client
    /// disconnected). Late responses for them then match nothing and are ignored.
    pub fn cancelCaller(self: *Self, caller: u64) void {
        var doomed: [64]u16 = undefined;
        var count: usize = 0;
        var it = self.pending.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.caller != caller) continue;
            if (count >= doomed.len) break;
            doomed[count] = entry.key_ptr.*;
            count += 1;
        }
        for (doomed[0..count]) |id| _ = self.pending.remove(id);
    }

    fn clampTtl(self: *const Self, ttl: u32) u32 {
        return std.math.clamp(ttl, self.options.min_ttl_seconds, self.options.max_ttl_seconds);
    }

    /// Allocate an unpredictable transaction id that no in-flight request is
    /// using. The id is drawn from a CSPRNG (not a counter) so an off-path
    /// attacker cannot guess it — forged responses with the wrong id are
    /// rejected. Collisions with an in-flight id are re-drawn; the bounded loop
    /// surfaces a full table as `NoFreeTransactionId` rather than spinning.
    fn allocId(self: *Self) ResolverError!u16 {
        const max_attempts: usize = 4 * (@as(usize, std.math.maxInt(u16)) + 1);
        var attempts: usize = 0;
        while (attempts < max_attempts) : (attempts += 1) {
            const candidate: u16 = @truncate(secure_fns.randomU64());
            if (candidate == 0) continue; // keep ids non-zero
            if (!self.pending.contains(candidate)) return candidate;
        }
        return error.NoFreeTransactionId;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Build a minimal PTR response for `id` answering `host` with `ttl`.
fn buildPtrResponse(out: []u8, id: u16, address: dns.Address, host: []const u8, ttl: u32) []const u8 {
    var name_buf: [dns.max_domain_text_len]u8 = undefined;
    const qname = dns.reverseName(&name_buf, address) catch unreachable;
    const answer = dns.Answer{
        .name = qname,
        .rr_type = .ptr,
        .ttl = ttl,
        .data = .{ .ptr = host },
    };
    const question = dns.Query{ .name = qname, .qtype = .ptr };
    return dns.encodeMessage(out, .{
        .id = id,
        .response = true,
        .recursion_available = true,
        .questions = (&question)[0..1],
        .answers = (&answer)[0..1],
    }) catch unreachable;
}

test "resolvePtr issues a query then onResponse completes and caches it" {
    var r = Resolver.init(testing.allocator, .{});
    defer r.deinit();

    const addr = dns.Address{ .ipv4 = .{ 198, 51, 100, 7 } };
    var qbuf: [dns.max_message_len]u8 = undefined;

    // First lookup: a query is emitted and one request is in flight.
    const out1 = try r.resolvePtr(42, addr, 1_000, &qbuf);
    try testing.expect(out1 == .sent);
    try testing.expectEqual(@as(usize, 1), r.inFlight());

    // The emitted query id is what the server echoes back.
    const parsed = try dns.parseMessage(1, 0, out1.sent);
    const id = parsed.header.id;

    var rbuf: [dns.max_message_len]u8 = undefined;
    const resp = buildPtrResponse(&rbuf, id, addr, "host.example.org", 600);
    const done = r.onResponse(resp, 1_010).?;

    try testing.expectEqual(@as(u64, 42), done.caller);
    try testing.expectEqual(ResultKind.ptr, done.kind);
    try testing.expectEqualStrings("host.example.org", done.name());
    try testing.expectEqual(@as(usize, 0), r.inFlight());

    // Second lookup for the same address is served from cache (no wire bytes).
    const out2 = try r.resolvePtr(99, addr, 1_020, &qbuf);
    try testing.expect(out2 == .cached);
    try testing.expectEqualStrings("host.example.org", out2.cached.name());
    try testing.expectEqual(@as(usize, 0), r.inFlight());
}

test "onResponse ignores an unmatched transaction id" {
    var r = Resolver.init(testing.allocator, .{});
    defer r.deinit();
    const addr = dns.Address{ .ipv4 = .{ 10, 0, 0, 1 } };
    var rbuf: [dns.max_message_len]u8 = undefined;
    // No request was issued, so any response matches nothing.
    const resp = buildPtrResponse(&rbuf, 7, addr, "ghost.example", 60);
    try testing.expect(r.onResponse(resp, 5) == null);
}

test "NXDOMAIN rcode produces a negative result" {
    var r = Resolver.init(testing.allocator, .{});
    defer r.deinit();
    const addr = dns.Address{ .ipv4 = .{ 203, 0, 113, 9 } };
    var qbuf: [dns.max_message_len]u8 = undefined;
    const out = try r.resolvePtr(1, addr, 0, &qbuf);
    const id = (try dns.parseMessage(1, 0, out.sent)).header.id;

    var name_buf: [dns.max_domain_text_len]u8 = undefined;
    const qname = try dns.reverseName(&name_buf, addr);
    const question = dns.Query{ .name = qname, .qtype = .ptr };
    var rbuf: [dns.max_message_len]u8 = undefined;
    const resp = try dns.encodeMessage(&rbuf, .{
        .id = id,
        .response = true,
        .rcode = 3,
        .questions = (&question)[0..1],
    });
    const done = r.onResponse(resp, 1).?;
    try testing.expectEqual(ResultKind.nxdomain, done.kind);
}

test "resolveHost returns addresses and caches the host" {
    var r = Resolver.init(testing.allocator, .{});
    defer r.deinit();
    var qbuf: [dns.max_message_len]u8 = undefined;
    const out = try r.resolveHost(5, "mail.example.net", .a, 0, &qbuf);
    try testing.expect(out == .sent);
    const id = (try dns.parseMessage(1, 0, out.sent)).header.id;

    const a1 = dns.Answer{ .name = "mail.example.net", .rr_type = .a, .ttl = 300, .data = .{ .a = .{ 192, 0, 2, 1 } } };
    const a2 = dns.Answer{ .name = "mail.example.net", .rr_type = .a, .ttl = 300, .data = .{ .a = .{ 192, 0, 2, 2 } } };
    const answers = [_]dns.Answer{ a1, a2 };
    const question = dns.Query{ .name = "mail.example.net", .qtype = .a };
    var rbuf: [dns.max_message_len]u8 = undefined;
    const resp = try dns.encodeMessage(&rbuf, .{
        .id = id,
        .response = true,
        .questions = (&question)[0..1],
        .answers = &answers,
    });
    const done = r.onResponse(resp, 10).?;
    try testing.expectEqual(ResultKind.addrs, done.kind);
    try testing.expectEqual(@as(usize, 2), done.addresses().len);
    try testing.expectEqual(dns.Address{ .ipv4 = .{ 192, 0, 2, 1 } }, done.addresses()[0]);

    // Cached now.
    const out2 = try r.resolveHost(6, "mail.example.net", .a, 20, &qbuf);
    try testing.expect(out2 == .cached);
    try testing.expectEqual(@as(usize, 2), out2.cached.addresses().len);
}

test "sweep reports and drops timed-out requests" {
    var r = Resolver.init(testing.allocator, .{ .timeout_ms = 100 });
    defer r.deinit();
    const addr = dns.Address{ .ipv4 = .{ 192, 0, 2, 50 } };
    var qbuf: [dns.max_message_len]u8 = undefined;
    _ = try r.resolvePtr(77, addr, 0, &qbuf);
    try testing.expectEqual(@as(usize, 1), r.inFlight());

    var results: [4]Resolved = undefined;
    // Before the deadline: nothing expires.
    try testing.expectEqual(@as(usize, 0), r.sweep(50, &results));
    // After the deadline: the request is reported failed and dropped.
    const n = r.sweep(150, &results);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u64, 77), results[0].caller);
    try testing.expectEqual(ResultKind.failure, results[0].kind);
    try testing.expectEqual(@as(usize, 0), r.inFlight());
}

test "cancelCaller drops only that caller's in-flight requests" {
    var r = Resolver.init(testing.allocator, .{});
    defer r.deinit();
    var qbuf: [dns.max_message_len]u8 = undefined;
    _ = try r.resolvePtr(1, .{ .ipv4 = .{ 1, 1, 1, 1 } }, 0, &qbuf);
    _ = try r.resolvePtr(1, .{ .ipv4 = .{ 2, 2, 2, 2 } }, 0, &qbuf);
    _ = try r.resolvePtr(2, .{ .ipv4 = .{ 3, 3, 3, 3 } }, 0, &qbuf);
    try testing.expectEqual(@as(usize, 3), r.inFlight());

    r.cancelCaller(1);
    try testing.expectEqual(@as(usize, 1), r.inFlight());
}

test "allocId skips ids that are still in flight" {
    var r = Resolver.init(testing.allocator, .{});
    defer r.deinit();
    var qbuf: [dns.max_message_len]u8 = undefined;

    // Issue several without answering; every emitted id must be distinct.
    var seen = std.AutoHashMap(u16, void).init(testing.allocator);
    defer seen.deinit();
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        const out = try r.resolvePtr(@intCast(i), .{ .ipv4 = .{ 0, 0, 0, @intCast(i) } }, 0, &qbuf);
        const id = (try dns.parseMessage(1, 0, out.sent)).header.id;
        try testing.expect(!seen.contains(id));
        try seen.put(id, {});
    }
    try testing.expectEqual(@as(usize, 16), r.inFlight());
}
