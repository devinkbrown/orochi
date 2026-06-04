//! Pure client TLS certificate fingerprint support.
//!
//! Callers supply already-derived SHA-256 certificate fingerprints as lowercase
//! hex strings. This module does no socket work, TLS parsing, or allocation in
//! its store and builders.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const ClientId = u64;
pub const fingerprint_len: usize = 64;
pub const Fingerprint = [fingerprint_len]u8;
pub const whois_certfp_numeric = numeric.Numeric.RPL_WHOISCERTFP;

pub const CertFpError = error{
    InvalidFingerprint,
    StoreFull,
    OutputTooSmall,
};

/// Fixed-capacity, allocation-free CERTFP store keyed by client id.
pub fn CertFpStore(comptime max_clients: usize) type {
    if (max_clients == 0) @compileError("CertFpStore requires at least one client slot");

    return struct {
        entries: [max_clients]Entry = [_]Entry{Entry{}} ** max_clients,
        count: usize = 0,

        const Self = @This();

        const Entry = struct {
            client: ClientId = 0,
            active: bool = false,
            fingerprint: Fingerprint = [_]u8{0} ** fingerprint_len,

            fn slice(self: *const Entry) []const u8 {
                return self.fingerprint[0..];
            }
        };

        pub fn init() Self {
            return .{};
        }

        /// Set or replace the lowercase SHA-256 hex fingerprint for `client`.
        pub fn set(self: *Self, client: ClientId, fp: []const u8) CertFpError!void {
            try validateFingerprint(fp);

            const entry = try self.entryFor(client);
            @memcpy(entry.fingerprint[0..], fp);
            entry.active = true;
        }

        /// Return the stored fingerprint for `client`, if present.
        pub fn get(self: *const Self, client: ClientId) ?[]const u8 {
            for (self.entries[0..self.count]) |*entry| {
                if (entry.active and entry.client == client) return entry.slice();
            }
            return null;
        }

        /// Clear `client` and return whether a fingerprint was present.
        pub fn clear(self: *Self, client: ClientId) bool {
            for (self.entries[0..self.count], 0..) |*entry, index| {
                if (!entry.active or entry.client != client) continue;

                self.count -= 1;
                if (index != self.count) {
                    self.entries[index] = self.entries[self.count];
                }
                self.entries[self.count] = Entry{};
                return true;
            }
            return false;
        }

        fn entryFor(self: *Self, client: ClientId) CertFpError!*Entry {
            for (self.entries[0..self.count]) |*entry| {
                if (entry.active and entry.client == client) return entry;
            }
            if (self.count >= max_clients) return error.StoreFull;

            const index = self.count;
            self.count += 1;
            self.entries[index] = .{ .client = client, .active = true };
            return &self.entries[index];
        }
    };
}

/// Build the RPL_WHOISCERTFP (276) body: `<nick> :has client certificate fingerprint <fp>`.
pub fn buildWhoisCertfp(out: []u8, nick: []const u8, fp: []const u8) CertFpError![]const u8 {
    try validateFingerprint(fp);

    const needed = whoisCertfpBodyLen(nick);
    if (out.len < needed) return error.OutputTooSmall;

    var cursor: usize = 0;
    @memcpy(out[cursor .. cursor + nick.len], nick);
    cursor += nick.len;
    @memcpy(out[cursor .. cursor + whois_certfp_trailing_prefix.len], whois_certfp_trailing_prefix);
    cursor += whois_certfp_trailing_prefix.len;
    @memcpy(out[cursor .. cursor + fp.len], fp);
    cursor += fp.len;
    return out[0..cursor];
}

pub fn whoisCertfpBodyLen(nick: []const u8) usize {
    return nick.len + whois_certfp_trailing_prefix.len + fingerprint_len;
}

/// Validate one caller-supplied lowercase SHA-256 hex fingerprint.
pub fn validateFingerprint(fp: []const u8) CertFpError!void {
    if (fp.len != fingerprint_len) return error.InvalidFingerprint;
    for (fp) |ch| {
        if (!isLowerHex(ch)) return error.InvalidFingerprint;
    }
}

/// Timing-safe equality for validated lowercase SHA-256 hex fingerprints.
pub fn fingerprintEqual(a: []const u8, b: []const u8) bool {
    if (a.len != fingerprint_len or b.len != fingerprint_len) return false;

    var left: Fingerprint = undefined;
    var right: Fingerprint = undefined;
    @memcpy(left[0..], a);
    @memcpy(right[0..], b);
    return std.crypto.timing_safe.eql(Fingerprint, left, right);
}

fn isLowerHex(ch: u8) bool {
    return switch (ch) {
        '0'...'9', 'a'...'f' => true,
        else => false,
    };
}

const whois_certfp_trailing_prefix = " :has client certificate fingerprint ";

test "set/get/clear round-trip" {
    const allocator = std.testing.allocator;
    const scratch = try allocator.alloc(u8, fingerprint_len);
    defer allocator.free(scratch);
    @memset(scratch, 'a');

    var store = CertFpStore(2).init();
    try store.set(42, scratch);

    const stored = store.get(42) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings(scratch, stored);
    try std.testing.expectEqual(@as(usize, 1), store.count);

    try store.set(42, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    try std.testing.expectEqualStrings(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        store.get(42).?,
    );
    try std.testing.expect(store.clear(42));
    try std.testing.expect(store.get(42) == null);
    try std.testing.expectEqual(@as(usize, 0), store.count);
    try std.testing.expect(!store.clear(42));
}

test "reject non-hex and wrong-length fingerprints" {
    var store = CertFpStore(1).init();

    try std.testing.expectError(error.InvalidFingerprint, validateFingerprint(""));
    try std.testing.expectError(
        error.InvalidFingerprint,
        validateFingerprint("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"),
    );
    try std.testing.expectError(
        error.InvalidFingerprint,
        validateFingerprint("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"),
    );
    try std.testing.expectError(
        error.InvalidFingerprint,
        validateFingerprint("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"),
    );
    try std.testing.expectError(
        error.InvalidFingerprint,
        store.set(1, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"),
    );
}

test "276 body exact bytes" {
    const allocator = std.testing.allocator;
    const fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const nick = "alice";
    const out = try allocator.alloc(u8, whoisCertfpBodyLen(nick));
    defer allocator.free(out);

    var code_buf: [3]u8 = undefined;
    try std.testing.expectEqual(@as(u16, 276), numeric.code(whois_certfp_numeric));
    try std.testing.expectEqualStrings("276", numeric.formatCode(whois_certfp_numeric, &code_buf));

    const body = try buildWhoisCertfp(out, nick, fp);
    try std.testing.expectEqualStrings(
        "alice :has client certificate fingerprint 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        body,
    );
}

test "timing_safe match true/false" {
    const a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const b = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const c = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab";

    try std.testing.expect(fingerprintEqual(a, b));
    try std.testing.expect(!fingerprintEqual(a, c));
    try std.testing.expect(!fingerprintEqual(a, "short"));
}

test {
    std.testing.refAllDecls(@This());
}
