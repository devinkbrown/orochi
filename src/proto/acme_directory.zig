//! ACME directory resource parser (RFC 8555 §7.1.1).
//!
//! The directory is the entry point of an ACME server: a JSON object that maps
//! well-known resource names to absolute endpoint URLs. A client fetches it
//! once and uses the returned URLs for every subsequent operation.
//!
//! This module is pure: it depends only on `std` and `std.json`. It performs no
//! network, clock, or RNG access — the caller is responsible for fetching the
//! JSON bytes over the wire and handing them here for parsing.
//!
//! Ownership: `parse` takes an allocator and returns a `Directory` whose URL
//! slices are heap-owned copies of the parsed values. The caller MUST call
//! `Directory.deinit(allocator)` with the same allocator to release them.

const std = @import("std");

/// Parsed ACME directory. URL slices are owned by the allocator passed to
/// `parse`; release them with `deinit`.
pub const Directory = struct {
    /// `newNonce` — endpoint issuing fresh anti-replay nonces.
    new_nonce: []const u8,
    /// `newAccount` — endpoint creating/looking-up accounts.
    new_account: []const u8,
    /// `newOrder` — endpoint creating certificate orders.
    new_order: []const u8,
    /// `revokeCert` — endpoint revoking issued certificates.
    revoke_cert: []const u8,
    /// `keyChange` — endpoint rotating an account key.
    key_change: []const u8,
    /// `meta.termsOfService` — optional ToS URL the client may surface to users.
    terms_of_service: ?[]const u8,

    /// Free all owned URL slices. Safe to call exactly once with the same
    /// allocator that was passed to `parse`.
    pub fn deinit(self: *Directory, allocator: std.mem.Allocator) void {
        allocator.free(self.new_nonce);
        allocator.free(self.new_account);
        allocator.free(self.new_order);
        allocator.free(self.revoke_cert);
        allocator.free(self.key_change);
        if (self.terms_of_service) |tos| allocator.free(tos);
        self.* = undefined;
    }
};

pub const ParseError = error{
    /// Input was not valid JSON, or the root was not a JSON object.
    InvalidJson,
    /// A required endpoint key was absent or not a JSON string.
    MissingField,
    /// Allocator could not satisfy a request.
    OutOfMemory,
};

/// Required top-level keys in the order they appear in the struct.
const RequiredKey = enum {
    new_nonce,
    new_account,
    new_order,
    revoke_cert,
    key_change,

    /// JSON key name for this field.
    fn jsonName(self: RequiredKey) []const u8 {
        return switch (self) {
            .new_nonce => "newNonce",
            .new_account => "newAccount",
            .new_order => "newOrder",
            .revoke_cert => "revokeCert",
            .key_change => "keyChange",
        };
    }
};

/// Fetch a required string field from the root object, erroring if absent or of
/// the wrong type.
fn requireString(obj: std.json.ObjectMap, key: RequiredKey) ParseError![]const u8 {
    const value = obj.get(key.jsonName()) orelse return error.MissingField;
    return switch (value) {
        .string => |s| s,
        else => error.MissingField,
    };
}

/// Read the optional `meta.termsOfService` string. Returns null when `meta` is
/// absent, is not an object, lacks `termsOfService`, or that value is not a
/// string — all tolerated per spec.
fn optionalTermsOfService(obj: std.json.ObjectMap) ?[]const u8 {
    const meta = obj.get("meta") orelse return null;
    switch (meta) {
        .object => |meta_obj| {
            const tos = meta_obj.get("termsOfService") orelse return null;
            return switch (tos) {
                .string => |s| s,
                else => null,
            };
        },
        else => return null,
    }
}

/// Parse an ACME directory JSON resource into an owned `Directory`.
///
/// Required keys (`newNonce`, `newAccount`, `newOrder`, `revokeCert`,
/// `keyChange`) must each be present as JSON strings or `error.MissingField` is
/// returned. The optional `meta.termsOfService` is tolerated when absent.
///
/// On success the returned slices are heap-owned; call `Directory.deinit`.
pub fn parse(allocator: std.mem.Allocator, json_bytes: []const u8) ParseError!Directory {
    var parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        json_bytes,
        .{},
    ) catch return error.InvalidJson;
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidJson;
    const obj = parsed.value.object;

    // Borrow string views from the parsed tree first; only allocate owned
    // copies once every required field is confirmed present, so a missing
    // field never leaks a partial allocation.
    const new_nonce_v = try requireString(obj, .new_nonce);
    const new_account_v = try requireString(obj, .new_account);
    const new_order_v = try requireString(obj, .new_order);
    const revoke_cert_v = try requireString(obj, .revoke_cert);
    const key_change_v = try requireString(obj, .key_change);
    const tos_v = optionalTermsOfService(obj);

    // Track owned copies so we can unwind cleanly on a mid-way OOM.
    var owned: [5][]const u8 = undefined;
    var n_owned: usize = 0;
    errdefer for (owned[0..n_owned]) |s| allocator.free(s);

    const new_nonce = try allocator.dupe(u8, new_nonce_v);
    owned[n_owned] = new_nonce;
    n_owned += 1;

    const new_account = try allocator.dupe(u8, new_account_v);
    owned[n_owned] = new_account;
    n_owned += 1;

    const new_order = try allocator.dupe(u8, new_order_v);
    owned[n_owned] = new_order;
    n_owned += 1;

    const revoke_cert = try allocator.dupe(u8, revoke_cert_v);
    owned[n_owned] = revoke_cert;
    n_owned += 1;

    const key_change = try allocator.dupe(u8, key_change_v);
    owned[n_owned] = key_change;
    n_owned += 1;

    const terms_of_service: ?[]const u8 = if (tos_v) |tos|
        try allocator.dupe(u8, tos)
    else
        null;

    return .{
        .new_nonce = new_nonce,
        .new_account = new_account,
        .new_order = new_order,
        .revoke_cert = revoke_cert,
        .key_change = key_change,
        .terms_of_service = terms_of_service,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Realistic Let's Encrypt-style directory resource.
const fixture_full =
    \\{
    \\  "newNonce": "https://acme-v02.api.example.org/acme/new-nonce",
    \\  "newAccount": "https://acme-v02.api.example.org/acme/new-acct",
    \\  "newOrder": "https://acme-v02.api.example.org/acme/new-order",
    \\  "revokeCert": "https://acme-v02.api.example.org/acme/revoke-cert",
    \\  "keyChange": "https://acme-v02.api.example.org/acme/key-change",
    \\  "renewalInfo": "https://acme-v02.api.example.org/acme/renewal-info",
    \\  "meta": {
    \\    "termsOfService": "https://example.org/acme/terms/v1",
    \\    "website": "https://example.org",
    \\    "caaIdentities": ["example.org"]
    \\  }
    \\}
;

test "parses a full directory into owned endpoint URLs" {
    // Arrange
    const allocator = std.testing.allocator;

    // Act
    var dir = try parse(allocator, fixture_full);
    defer dir.deinit(allocator);

    // Assert
    try std.testing.expectEqualStrings(
        "https://acme-v02.api.example.org/acme/new-nonce",
        dir.new_nonce,
    );
    try std.testing.expectEqualStrings(
        "https://acme-v02.api.example.org/acme/new-acct",
        dir.new_account,
    );
    try std.testing.expectEqualStrings(
        "https://acme-v02.api.example.org/acme/new-order",
        dir.new_order,
    );
    try std.testing.expectEqualStrings(
        "https://acme-v02.api.example.org/acme/revoke-cert",
        dir.revoke_cert,
    );
    try std.testing.expectEqualStrings(
        "https://acme-v02.api.example.org/acme/key-change",
        dir.key_change,
    );
    try std.testing.expect(dir.terms_of_service != null);
    try std.testing.expectEqualStrings(
        "https://example.org/acme/terms/v1",
        dir.terms_of_service.?,
    );
}

test "tolerates a missing meta object" {
    // Arrange
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "newNonce": "https://ca.example/nonce",
        \\  "newAccount": "https://ca.example/acct",
        \\  "newOrder": "https://ca.example/order",
        \\  "revokeCert": "https://ca.example/revoke",
        \\  "keyChange": "https://ca.example/keychange"
        \\}
    ;

    // Act
    var dir = try parse(allocator, json);
    defer dir.deinit(allocator);

    // Assert
    try std.testing.expectEqual(@as(?[]const u8, null), dir.terms_of_service);
    try std.testing.expectEqualStrings("https://ca.example/order", dir.new_order);
}

test "tolerates meta present without termsOfService" {
    // Arrange
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "newNonce": "https://ca.example/nonce",
        \\  "newAccount": "https://ca.example/acct",
        \\  "newOrder": "https://ca.example/order",
        \\  "revokeCert": "https://ca.example/revoke",
        \\  "keyChange": "https://ca.example/keychange",
        \\  "meta": { "website": "https://ca.example" }
        \\}
    ;

    // Act
    var dir = try parse(allocator, json);
    defer dir.deinit(allocator);

    // Assert
    try std.testing.expectEqual(@as(?[]const u8, null), dir.terms_of_service);
}

test "errors when a required field is missing" {
    // Arrange — newOrder omitted.
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "newNonce": "https://ca.example/nonce",
        \\  "newAccount": "https://ca.example/acct",
        \\  "revokeCert": "https://ca.example/revoke",
        \\  "keyChange": "https://ca.example/keychange"
        \\}
    ;

    // Act / Assert
    try std.testing.expectError(error.MissingField, parse(allocator, json));
}

test "errors when a required field has the wrong type" {
    // Arrange — newNonce is a number, not a string.
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "newNonce": 42,
        \\  "newAccount": "https://ca.example/acct",
        \\  "newOrder": "https://ca.example/order",
        \\  "revokeCert": "https://ca.example/revoke",
        \\  "keyChange": "https://ca.example/keychange"
        \\}
    ;

    // Act / Assert
    try std.testing.expectError(error.MissingField, parse(allocator, json));
}

test "errors on malformed JSON" {
    // Arrange
    const allocator = std.testing.allocator;

    // Act / Assert
    try std.testing.expectError(error.InvalidJson, parse(allocator, "{ not json"));
}

test "errors when root is not an object" {
    // Arrange
    const allocator = std.testing.allocator;

    // Act / Assert
    try std.testing.expectError(error.InvalidJson, parse(allocator, "[1,2,3]"));
}
