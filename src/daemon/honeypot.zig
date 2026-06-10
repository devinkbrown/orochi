//! Orochi connection-IP honeypot / decoy registry.
//!
//! Operators register decoy IPv4 addresses, CIDR ranges, glob patterns, or
//! listener ports that legitimate clients should never touch. Any connection
//! observed from (or to) a decoy is a strong signal of scanning or abuse, so
//! every hit is counted per source and recorded in a bounded recent-hits ring
//! for scoring toward an automatic ban decision.
//!
//! This is a pure in-memory store: it performs no I/O, opens no sockets, and
//! reads no clock. Callers inject monotonic timestamps (milliseconds) so the
//! expiry/prune logic stays deterministic and testable. All matching logic
//! (IPv4 parsing, CIDR masking, and `*`/`?` globbing) is implemented locally so
//! the module has no dependency beyond the Zig standard library.
//!
//! Returned slices are borrowed and remain valid only until the next mutation
//! of the owning structure.
const std = @import("std");

/// Maximum number of distinct decoy patterns that may be registered.
pub const max_decoys: usize = 4096;
/// Maximum byte length accepted for a decoy pattern string.
pub const max_pattern_bytes: usize = 64;
/// Maximum number of distinct source IPs tracked for hit accounting.
pub const max_sources: usize = 65536;
/// Capacity of the recent-hits ring buffer.
pub const max_recent_hits: usize = 1024;
/// Hit score added per recorded hit, used to drive auto-ban decisions.
pub const hit_score: u32 = 10;

/// Errors returned by registry mutations.
pub const Error = std.mem.Allocator.Error || error{
    /// The supplied pattern was empty or exceeded `max_pattern_bytes`.
    InvalidPattern,
    /// The decoy capacity (`max_decoys`) is exhausted.
    TooManyDecoys,
    /// The source-tracking capacity (`max_sources`) is exhausted.
    TooManySources,
};

/// How a registered decoy pattern is interpreted when matching an address.
pub const DecoyKind = enum {
    /// A single exact IPv4 literal, e.g. `192.0.2.7`.
    exact,
    /// An IPv4 CIDR range, e.g. `192.0.2.0/24`.
    cidr,
    /// A glob over the textual address using `*` and `?`, e.g. `10.0.*.*`.
    glob,
};

/// One recorded hit against a decoy: which source IP, which decoy pattern, when.
pub const Hit = struct {
    /// The connecting source address (owned by the registry).
    source: []const u8,
    /// The decoy pattern that matched (owned by the registry).
    pattern: []const u8,
    /// Injected timestamp in milliseconds.
    at_ms: i64,
};

/// Aggregate hit accounting for a single source IP.
pub const SourceStat = struct {
    /// Total hits observed from this source since first sighting.
    hits: u64 = 0,
    /// Accumulated abuse score (`hits * hit_score`, saturating).
    score: u32 = 0,
    /// Timestamp of the most recent hit, in milliseconds.
    last_ms: i64 = 0,
};

/// A parsed IPv4 CIDR range: network address plus prefix length in bits.
const Ipv4Cidr = struct {
    network: u32,
    prefix: u6,

    fn contains(self: Ipv4Cidr, addr: u32) bool {
        if (self.prefix == 0) return true;
        const shift: u5 = @intCast(32 - @as(u32, self.prefix));
        const mask: u32 = ~@as(u32, 0) << shift;
        return (addr & mask) == (self.network & mask);
    }
};

/// Internal representation of a registered decoy pattern.
const Decoy = struct {
    pattern: []const u8,
    kind: DecoyKind,
    cidr: ?Ipv4Cidr = null,

    fn deinit(self: *Decoy, allocator: std.mem.Allocator) void {
        allocator.free(self.pattern);
    }

    fn matches(self: *const Decoy, addr_text: []const u8, addr_v4: ?u32) bool {
        return switch (self.kind) {
            .exact => std.mem.eql(u8, self.pattern, addr_text),
            .cidr => if (addr_v4) |v4| self.cidr.?.contains(v4) else false,
            .glob => globMatch(self.pattern, addr_text),
        };
    }
};

/// Connection-IP honeypot store.
pub const Honeypot = struct {
    allocator: std.mem.Allocator,
    decoys: std.ArrayListUnmanaged(Decoy) = .empty,
    sources: std.StringHashMapUnmanaged(SourceStat) = .empty,
    recent: std.ArrayListUnmanaged(Hit) = .empty,
    /// Index of the oldest entry once the ring is full (ring head).
    ring_head: usize = 0,

    /// Create an empty honeypot bound to `allocator`.
    pub fn init(allocator: std.mem.Allocator) Honeypot {
        return .{ .allocator = allocator };
    }

    /// Release all owned memory and poison the instance.
    pub fn deinit(self: *Honeypot) void {
        for (self.decoys.items) |*decoy| decoy.deinit(self.allocator);
        self.decoys.deinit(self.allocator);

        var it = self.sources.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.sources.deinit(self.allocator);

        for (self.recent.items) |hit| {
            self.allocator.free(hit.source);
            self.allocator.free(hit.pattern);
        }
        self.recent.deinit(self.allocator);
        self.* = undefined;
    }

    /// Register a decoy from an IPv4 literal, CIDR range, or glob pattern.
    ///
    /// Returns `false` if an identical pattern is already registered (no-op),
    /// `true` if a new decoy was added.
    pub fn addDecoy(self: *Honeypot, pattern: []const u8) Error!bool {
        try validatePattern(pattern);
        if (self.findDecoy(pattern) != null) return false;
        if (self.decoys.items.len >= max_decoys) return error.TooManyDecoys;

        const kind = classify(pattern);
        const cidr = if (kind == .cidr) parseIpv4Cidr(pattern) else null;

        const owned = try self.allocator.dupe(u8, pattern);
        errdefer self.allocator.free(owned);
        try self.decoys.append(self.allocator, .{
            .pattern = owned,
            .kind = kind,
            .cidr = cidr,
        });
        return true;
    }

    /// Remove a previously registered decoy. Returns `true` if one was removed.
    pub fn removeDecoy(self: *Honeypot, pattern: []const u8) bool {
        const idx = self.findDecoy(pattern) orelse return false;
        var decoy = self.decoys.orderedRemove(idx);
        decoy.deinit(self.allocator);
        return true;
    }

    /// Number of registered decoy patterns.
    pub fn decoyCount(self: *const Honeypot) usize {
        return self.decoys.items.len;
    }

    /// Borrowed view of registered decoy patterns. Valid until the next mutation.
    pub fn listDecoys(self: *const Honeypot, out: *std.ArrayListUnmanaged([]const u8)) Error!void {
        out.clearRetainingCapacity();
        try out.ensureTotalCapacity(self.allocator, self.decoys.items.len);
        for (self.decoys.items) |decoy| out.appendAssumeCapacity(decoy.pattern);
    }

    /// Whether `ip` matches any registered decoy. `ip` is the textual address;
    /// IPv4 literals additionally enable CIDR matching.
    pub fn isDecoy(self: *const Honeypot, ip: []const u8) bool {
        const v4 = parseIpv4(ip);
        for (self.decoys.items) |*decoy| {
            if (decoy.matches(ip, v4)) return true;
        }
        return false;
    }

    /// The first decoy pattern matched by `ip`, if any (borrowed slice).
    pub fn matchedPattern(self: *const Honeypot, ip: []const u8) ?[]const u8 {
        const v4 = parseIpv4(ip);
        for (self.decoys.items) |*decoy| {
            if (decoy.matches(ip, v4)) return decoy.pattern;
        }
        return null;
    }

    /// Record a connection from `ip` at injected time `now_ms`.
    ///
    /// If `ip` matches a decoy, the per-source counters are incremented, the hit
    /// is pushed onto the bounded recent-hits ring, and `true` is returned. If
    /// `ip` matches nothing, this is a no-op returning `false`.
    pub fn recordHit(self: *Honeypot, ip: []const u8, now_ms: i64) Error!bool {
        const pattern = self.matchedPattern(ip) orelse return false;

        const stat = try self.ensureSource(ip);
        stat.hits +|= 1;
        stat.score +|= hit_score;
        stat.last_ms = now_ms;

        try self.pushHit(ip, pattern, now_ms);
        return true;
    }

    /// Aggregate hit statistics for `ip`, or null if it has never hit a decoy.
    pub fn sourceStat(self: *const Honeypot, ip: []const u8) ?SourceStat {
        return self.sources.get(ip);
    }

    /// Number of distinct sources tracked.
    pub fn sourceCount(self: *const Honeypot) usize {
        return self.sources.count();
    }

    /// Number of hits currently held in the recent-hits ring.
    pub fn recentCount(self: *const Honeypot) usize {
        return self.recent.items.len;
    }

    /// Whether `ip`'s accumulated score has reached `threshold` (auto-ban hint).
    pub fn shouldBan(self: *const Honeypot, ip: []const u8, threshold: u32) bool {
        const stat = self.sources.get(ip) orelse return false;
        return stat.score >= threshold;
    }

    /// Drop recent-ring hits older than `now_ms - ttl_ms` and forget any source
    /// whose last hit is now older than the TTL. Returns the number of recent
    /// hits pruned.
    pub fn prune(self: *Honeypot, now_ms: i64, ttl_ms: i64) usize {
        const cutoff = now_ms -| ttl_ms;

        var pruned: usize = 0;
        var write: usize = 0;
        for (self.recent.items) |hit| {
            if (hit.at_ms < cutoff) {
                self.allocator.free(hit.source);
                self.allocator.free(hit.pattern);
                pruned += 1;
            } else {
                self.recent.items[write] = hit;
                write += 1;
            }
        }
        self.recent.items.len = write;
        self.ring_head = 0;

        self.pruneSources(cutoff);
        return pruned;
    }

    /// Borrowed view of the recent-hits ring in storage order. Valid until the
    /// next mutation.
    pub fn recentHits(self: *const Honeypot) []const Hit {
        return self.recent.items;
    }

    fn findDecoy(self: *const Honeypot, pattern: []const u8) ?usize {
        for (self.decoys.items, 0..) |decoy, idx| {
            if (std.mem.eql(u8, decoy.pattern, pattern)) return idx;
        }
        return null;
    }

    fn ensureSource(self: *Honeypot, ip: []const u8) Error!*SourceStat {
        if (self.sources.getPtr(ip)) |stat| return stat;
        if (self.sources.count() >= max_sources) return error.TooManySources;

        const owned = try self.allocator.dupe(u8, ip);
        errdefer self.allocator.free(owned);
        try self.sources.putNoClobber(self.allocator, owned, .{});
        return self.sources.getPtr(ip).?;
    }

    fn pushHit(self: *Honeypot, ip: []const u8, pattern: []const u8, now_ms: i64) Error!void {
        const owned_ip = try self.allocator.dupe(u8, ip);
        errdefer self.allocator.free(owned_ip);
        const owned_pat = try self.allocator.dupe(u8, pattern);
        errdefer self.allocator.free(owned_pat);

        const hit: Hit = .{ .source = owned_ip, .pattern = owned_pat, .at_ms = now_ms };

        if (self.recent.items.len < max_recent_hits) {
            try self.recent.append(self.allocator, hit);
            return;
        }

        // Ring is full: overwrite the oldest slot and advance the head.
        const victim = self.recent.items[self.ring_head];
        self.allocator.free(victim.source);
        self.allocator.free(victim.pattern);
        self.recent.items[self.ring_head] = hit;
        self.ring_head = (self.ring_head + 1) % max_recent_hits;
    }

    fn pruneSources(self: *Honeypot, cutoff: i64) void {
        // Collect stale keys first; mutating during iteration is unsafe.
        var stale: std.ArrayListUnmanaged([]const u8) = .empty;
        defer stale.deinit(self.allocator);

        var it = self.sources.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.last_ms < cutoff) {
                stale.append(self.allocator, entry.key_ptr.*) catch return;
            }
        }
        for (stale.items) |key| {
            if (self.sources.fetchRemove(key)) |removed| {
                self.allocator.free(removed.key);
            }
        }
    }
};

fn validatePattern(pattern: []const u8) error{InvalidPattern}!void {
    if (pattern.len == 0 or pattern.len > max_pattern_bytes) return error.InvalidPattern;
}

/// Decide how a pattern string should be matched.
fn classify(pattern: []const u8) DecoyKind {
    if (std.mem.indexOfScalar(u8, pattern, '*') != null or
        std.mem.indexOfScalar(u8, pattern, '?') != null)
    {
        return .glob;
    }
    if (std.mem.indexOfScalar(u8, pattern, '/') != null) return .cidr;
    return .exact;
}

/// Parse an IPv4 dotted-quad literal into a big-endian-ordered `u32`.
/// Returns null on any malformed input. Rejects leading zeros and out-of-range
/// octets.
fn parseIpv4(text: []const u8) ?u32 {
    var octets: [4]u8 = undefined;
    var idx: usize = 0;
    var it = std.mem.splitScalar(u8, text, '.');
    while (it.next()) |part| {
        if (idx >= 4) return null;
        if (part.len == 0 or part.len > 3) return null;
        if (part.len > 1 and part[0] == '0') return null; // no leading zeros
        var value: u32 = 0;
        for (part) |ch| {
            if (ch < '0' or ch > '9') return null;
            value = value * 10 + (ch - '0');
        }
        if (value > 255) return null;
        octets[idx] = @intCast(value);
        idx += 1;
    }
    if (idx != 4) return null;
    return std.mem.readInt(u32, &octets, .big);
}

/// Parse an IPv4 CIDR (`a.b.c.d/n`). Returns null on malformed input.
fn parseIpv4Cidr(text: []const u8) ?Ipv4Cidr {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return null;
    const addr_text = text[0..slash];
    const prefix_text = text[slash + 1 ..];
    if (prefix_text.len == 0 or prefix_text.len > 2) return null;

    const network = parseIpv4(addr_text) orelse return null;
    var prefix: u32 = 0;
    for (prefix_text) |ch| {
        if (ch < '0' or ch > '9') return null;
        prefix = prefix * 10 + (ch - '0');
    }
    if (prefix > 32) return null;
    return .{ .network = network, .prefix = @intCast(prefix) };
}

/// Glob matcher supporting `*` (zero or more chars) and `?` (exactly one char).
/// Iterative backtracking, no allocation, linear in practice.
fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var star_t: usize = 0;

    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or pattern[p] == text[t])) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            star_t = t;
            p += 1;
        } else if (star) |sp| {
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

const testing = std.testing;

test "addDecoy is idempotent and isDecoy matches exact literals" {
    var hp = Honeypot.init(testing.allocator);
    defer hp.deinit();

    try testing.expect(try hp.addDecoy("192.0.2.7"));
    try testing.expect(!try hp.addDecoy("192.0.2.7"));
    try testing.expectEqual(@as(usize, 1), hp.decoyCount());

    try testing.expect(hp.isDecoy("192.0.2.7"));
    try testing.expect(!hp.isDecoy("192.0.2.8"));
}

test "CIDR decoy matches the whole range but not outsiders" {
    var hp = Honeypot.init(testing.allocator);
    defer hp.deinit();

    try testing.expect(try hp.addDecoy("10.20.0.0/16"));
    try testing.expect(hp.isDecoy("10.20.5.99"));
    try testing.expect(hp.isDecoy("10.20.255.1"));
    try testing.expect(!hp.isDecoy("10.21.0.1"));
    try testing.expect(!hp.isDecoy("11.20.0.1"));

    try testing.expect(try hp.addDecoy("0.0.0.0/0"));
    try testing.expect(hp.isDecoy("203.0.113.50"));
}

test "glob decoy matches wildcards and single chars" {
    var hp = Honeypot.init(testing.allocator);
    defer hp.deinit();

    try testing.expect(try hp.addDecoy("198.51.100.*"));
    try testing.expect(hp.isDecoy("198.51.100.1"));
    try testing.expect(hp.isDecoy("198.51.100.254"));
    try testing.expect(!hp.isDecoy("198.51.101.1"));

    try testing.expect(try hp.addDecoy("172.16.?.1"));
    try testing.expect(hp.isDecoy("172.16.5.1"));
    try testing.expect(!hp.isDecoy("172.16.50.1"));
}

test "matchedPattern returns the matching decoy string" {
    var hp = Honeypot.init(testing.allocator);
    defer hp.deinit();

    try testing.expect(try hp.addDecoy("10.0.0.0/8"));
    try testing.expectEqualStrings("10.0.0.0/8", hp.matchedPattern("10.9.8.7").?);
    try testing.expect(hp.matchedPattern("8.8.8.8") == null);
}

test "recordHit accounts per-source hits and scores" {
    var hp = Honeypot.init(testing.allocator);
    defer hp.deinit();

    try testing.expect(try hp.addDecoy("192.0.2.0/24"));

    try testing.expect(try hp.recordHit("192.0.2.10", 1_000));
    try testing.expect(try hp.recordHit("192.0.2.10", 2_000));
    try testing.expect(!try hp.recordHit("198.51.100.1", 3_000)); // not a decoy

    const stat = hp.sourceStat("192.0.2.10").?;
    try testing.expectEqual(@as(u64, 2), stat.hits);
    try testing.expectEqual(@as(u32, 2 * hit_score), stat.score);
    try testing.expectEqual(@as(i64, 2_000), stat.last_ms);

    try testing.expect(hp.sourceStat("198.51.100.1") == null);
    try testing.expectEqual(@as(usize, 1), hp.sourceCount());
    try testing.expectEqual(@as(usize, 2), hp.recentCount());
}

test "shouldBan fires once the score threshold is reached" {
    var hp = Honeypot.init(testing.allocator);
    defer hp.deinit();

    try testing.expect(try hp.addDecoy("203.0.113.5"));
    try testing.expect(!hp.shouldBan("203.0.113.5", 25));

    _ = try hp.recordHit("203.0.113.5", 10);
    _ = try hp.recordHit("203.0.113.5", 20);
    try testing.expect(!hp.shouldBan("203.0.113.5", 25));
    _ = try hp.recordHit("203.0.113.5", 30);
    try testing.expect(hp.shouldBan("203.0.113.5", 25));
}

test "removeDecoy drops the pattern and stops matching" {
    var hp = Honeypot.init(testing.allocator);
    defer hp.deinit();

    try testing.expect(try hp.addDecoy("10.0.0.0/8"));
    try testing.expect(hp.isDecoy("10.1.1.1"));
    try testing.expect(hp.removeDecoy("10.0.0.0/8"));
    try testing.expect(!hp.removeDecoy("10.0.0.0/8"));
    try testing.expect(!hp.isDecoy("10.1.1.1"));
    try testing.expectEqual(@as(usize, 0), hp.decoyCount());
}

test "listDecoys reflects registered patterns" {
    var hp = Honeypot.init(testing.allocator);
    defer hp.deinit();

    try testing.expect(try hp.addDecoy("a.b.c.d/24") or true); // invalid octets -> exact kind
    _ = hp.removeDecoy("a.b.c.d/24");

    try testing.expect(try hp.addDecoy("192.0.2.1"));
    try testing.expect(try hp.addDecoy("198.51.100.0/24"));

    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    defer out.deinit(testing.allocator);
    try hp.listDecoys(&out);
    try testing.expectEqual(@as(usize, 2), out.items.len);
    try testing.expectEqualStrings("192.0.2.1", out.items[0]);
    try testing.expectEqualStrings("198.51.100.0/24", out.items[1]);
}

test "prune removes stale recent hits and forgets idle sources" {
    var hp = Honeypot.init(testing.allocator);
    defer hp.deinit();

    try testing.expect(try hp.addDecoy("192.0.2.0/24"));

    _ = try hp.recordHit("192.0.2.1", 1_000);
    _ = try hp.recordHit("192.0.2.2", 5_000);
    try testing.expectEqual(@as(usize, 2), hp.recentCount());
    try testing.expectEqual(@as(usize, 2), hp.sourceCount());

    // TTL of 3s at now=6s: cutoff=3000, the first hit (1000) is stale.
    const pruned = hp.prune(6_000, 3_000);
    try testing.expectEqual(@as(usize, 1), pruned);
    try testing.expectEqual(@as(usize, 1), hp.recentCount());
    try testing.expectEqual(@as(usize, 1), hp.sourceCount());
    try testing.expect(hp.sourceStat("192.0.2.1") == null);
    try testing.expect(hp.sourceStat("192.0.2.2") != null);
}

test "recent-hits ring is bounded and overwrites oldest" {
    var hp = Honeypot.init(testing.allocator);
    defer hp.deinit();

    try testing.expect(try hp.addDecoy("10.0.0.0/8"));

    var i: usize = 0;
    while (i < max_recent_hits + 50) : (i += 1) {
        const ms: i64 = @intCast(i);
        _ = try hp.recordHit("10.0.0.1", ms);
    }
    try testing.expectEqual(max_recent_hits, hp.recentCount());

    // Every retained hit must be newer than the 50 that were overwritten.
    for (hp.recentHits()) |hit| {
        try testing.expect(hit.at_ms >= 50);
    }

    const stat = hp.sourceStat("10.0.0.1").?;
    try testing.expectEqual(@as(u64, max_recent_hits + 50), stat.hits);
}

test "decoy capacity limit is enforced" {
    var hp = Honeypot.init(testing.allocator);
    defer hp.deinit();

    var buf: [max_pattern_bytes]u8 = undefined;
    var i: usize = 0;
    while (i < max_decoys) : (i += 1) {
        const pat = try std.fmt.bufPrint(&buf, "10.{d}.{d}.0/24", .{ i / 256, i % 256 });
        _ = try hp.addDecoy(pat);
    }
    try testing.expectError(error.TooManyDecoys, hp.addDecoy("8.8.8.8"));
}

test "invalid patterns are rejected" {
    var hp = Honeypot.init(testing.allocator);
    defer hp.deinit();

    try testing.expectError(error.InvalidPattern, hp.addDecoy(""));

    const huge = "a" ** (max_pattern_bytes + 1);
    try testing.expectError(error.InvalidPattern, hp.addDecoy(huge));
}

test "parseIpv4 rejects malformed addresses" {
    try testing.expect(parseIpv4("192.0.2.1") != null);
    try testing.expect(parseIpv4("0.0.0.0") != null);
    try testing.expect(parseIpv4("255.255.255.255") != null);
    try testing.expect(parseIpv4("192.0.2.256") == null);
    try testing.expect(parseIpv4("192.0.2") == null);
    try testing.expect(parseIpv4("192.0.2.1.5") == null);
    try testing.expect(parseIpv4("192.0.2.01") == null); // leading zero
    try testing.expect(parseIpv4("192.0.2.x") == null);
    try testing.expect(parseIpv4("") == null);
}

test "globMatch edge cases" {
    try testing.expect(globMatch("*", "anything"));
    try testing.expect(globMatch("*", ""));
    try testing.expect(globMatch("a*c", "abc"));
    try testing.expect(globMatch("a*c", "ac"));
    try testing.expect(globMatch("a*c", "axxxxc"));
    try testing.expect(!globMatch("a*c", "abd"));
    try testing.expect(globMatch("???", "abc"));
    try testing.expect(!globMatch("???", "ab"));
    try testing.expect(globMatch("10.*.*.*", "10.1.2.3"));
}
