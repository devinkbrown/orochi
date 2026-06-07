//! ACME (RFC 8555) order, authorization, and challenge JSON codecs.
//!
//! Parsers take an allocator and return owned structs. All string slices inside
//! parsed results are deep-copied and must be released with `deinit`.
//! Builders write JSON into caller-owned buffers and allocate no memory.

const std = @import("std");
const base64url = @import("base64url.zig");

const Allocator = std.mem.Allocator;

comptime {
    if (@sizeOf(usize) != 8) @compileError("acme_order.zig supports 64-bit targets only");
}

pub const ParseError = error{
    InvalidJson,
    ExpectedObject,
    MissingField,
    InvalidField,
    InvalidStatus,
    OutOfMemory,
};

pub const BuildError = error{NoSpaceLeft};

pub const Status = enum {
    pending,
    ready,
    processing,
    valid,
    invalid,
    deactivated,
    expired,
    revoked,

    pub fn jsonName(self: Status) []const u8 {
        return switch (self) {
            .pending => "pending",
            .ready => "ready",
            .processing => "processing",
            .valid => "valid",
            .invalid => "invalid",
            .deactivated => "deactivated",
            .expired => "expired",
            .revoked => "revoked",
        };
    }
};

pub const Identifier = struct {
    allocator: Allocator,
    type: []u8,
    value: []u8,

    pub fn deinit(self: *Identifier) void {
        self.allocator.free(self.type);
        self.allocator.free(self.value);
        self.* = undefined;
    }
};

pub const Challenge = struct {
    allocator: Allocator,
    type: []u8,
    url: []u8,
    token: []u8,
    status: Status,

    pub fn deinit(self: *Challenge) void {
        self.allocator.free(self.type);
        self.allocator.free(self.url);
        self.allocator.free(self.token);
        self.* = undefined;
    }
};

pub const Authorization = struct {
    allocator: Allocator,
    status: Status,
    identifier: Identifier,
    challenges: []Challenge,

    pub fn deinit(self: *Authorization) void {
        self.identifier.deinit();
        for (self.challenges) |*challenge| challenge.deinit();
        self.allocator.free(self.challenges);
        self.* = undefined;
    }
};

pub const Order = struct {
    allocator: Allocator,
    status: Status,
    expires: ?[]u8,
    identifiers: []Identifier,
    authorizations: [][]u8,
    finalize: []u8,
    certificate: ?[]u8,

    pub fn deinit(self: *Order) void {
        if (self.expires) |expires| self.allocator.free(expires);
        for (self.identifiers) |*identifier| identifier.deinit();
        self.allocator.free(self.identifiers);
        for (self.authorizations) |url| self.allocator.free(url);
        self.allocator.free(self.authorizations);
        self.allocator.free(self.finalize);
        if (self.certificate) |certificate| self.allocator.free(certificate);
        self.* = undefined;
    }
};

pub fn parseOrder(allocator: Allocator, json_text: []const u8) ParseError!Order {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch return error.InvalidJson;
    defer parsed.deinit();
    if (parsed.value != .object) return error.ExpectedObject;

    const obj = parsed.value.object;
    const status = try parseStatusField(obj, "status");
    const expires = try optionalDupStringField(allocator, obj, "expires");
    errdefer if (expires) |value| allocator.free(value);
    const identifiers = try parseIdentifierArray(allocator, obj.get("identifiers") orelse return error.MissingField);
    errdefer freeIdentifiers(allocator, identifiers);
    const authorizations = try parseStringArray(allocator, obj.get("authorizations") orelse return error.MissingField);
    errdefer freeStringArray(allocator, authorizations);
    const finalize = try dupStringField(allocator, obj, "finalize");
    errdefer allocator.free(finalize);
    const certificate = try optionalDupStringField(allocator, obj, "certificate");
    errdefer if (certificate) |value| allocator.free(value);

    return .{
        .allocator = allocator,
        .status = status,
        .expires = expires,
        .identifiers = identifiers,
        .authorizations = authorizations,
        .finalize = finalize,
        .certificate = certificate,
    };
}

pub fn parseAuthorization(allocator: Allocator, json_text: []const u8) ParseError!Authorization {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch return error.InvalidJson;
    defer parsed.deinit();
    if (parsed.value != .object) return error.ExpectedObject;
    return parseAuthorizationValue(allocator, parsed.value);
}

pub fn parseChallenge(allocator: Allocator, json_text: []const u8) ParseError!Challenge {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch return error.InvalidJson;
    defer parsed.deinit();
    if (parsed.value != .object) return error.ExpectedObject;
    return parseChallengeValue(allocator, parsed.value);
}

pub fn findChallenge(authz: Authorization, challenge_type: []const u8) ?*const Challenge {
    for (authz.challenges) |*challenge| {
        if (std.mem.eql(u8, challenge.type, challenge_type)) return challenge;
    }
    return null;
}

pub fn buildNewOrder(out: []u8, domains: []const []const u8) BuildError![]const u8 {
    var writer = std.Io.Writer.fixed(out);
    try writeAll(&writer, "{\"identifiers\":[");
    for (domains, 0..) |domain, i| {
        if (i != 0) try writeAll(&writer, ",");
        try writeAll(&writer, "{\"type\":\"dns\",\"value\":");
        try writeJsonString(&writer, domain);
        try writeAll(&writer, "}");
    }
    try writeAll(&writer, "]}");
    return writer.buffered();
}

pub fn buildFinalize(out: []u8, csr_der: []const u8) BuildError![]const u8 {
    const prefix = "{\"csr\":\"";
    const suffix = "\"}";
    const enc_len = base64url.encodedLen(csr_der.len);
    const need = prefix.len + enc_len + suffix.len;
    if (out.len < need) return error.NoSpaceLeft;
    @memcpy(out[0..prefix.len], prefix);
    _ = base64url.encode(out[prefix.len .. prefix.len + enc_len], csr_der) catch return error.NoSpaceLeft;
    @memcpy(out[prefix.len + enc_len .. need], suffix);
    return out[0..need];
}

fn parseAuthorizationValue(allocator: Allocator, value: std.json.Value) ParseError!Authorization {
    if (value != .object) return error.InvalidField;
    const obj = value.object;
    const status = try parseStatusField(obj, "status");
    var identifier = try parseIdentifierValue(allocator, obj.get("identifier") orelse return error.MissingField);
    errdefer identifier.deinit();
    const challenges = try parseChallengeArray(allocator, obj.get("challenges") orelse return error.MissingField);
    errdefer freeChallenges(allocator, challenges);
    return .{
        .allocator = allocator,
        .status = status,
        .identifier = identifier,
        .challenges = challenges,
    };
}

fn parseIdentifierValue(allocator: Allocator, value: std.json.Value) ParseError!Identifier {
    if (value != .object) return error.InvalidField;
    const obj = value.object;
    const typ = try dupStringField(allocator, obj, "type");
    errdefer allocator.free(typ);
    const ident_value = try dupStringField(allocator, obj, "value");
    return .{ .allocator = allocator, .type = typ, .value = ident_value };
}

fn parseChallengeValue(allocator: Allocator, value: std.json.Value) ParseError!Challenge {
    if (value != .object) return error.InvalidField;
    const obj = value.object;
    const typ = try dupStringField(allocator, obj, "type");
    errdefer allocator.free(typ);
    const url = try dupStringField(allocator, obj, "url");
    errdefer allocator.free(url);
    // Not every challenge type carries a token (e.g. dns-persist-01 uses
    // issuer-domain-names). Only http-01/dns-01 — which we select — need one, so
    // tolerate its absence with an empty string rather than rejecting the authz.
    const token = (try optionalDupStringField(allocator, obj, "token")) orelse try allocator.dupe(u8, "");
    errdefer allocator.free(token);
    const status = try parseStatusField(obj, "status");
    return .{ .allocator = allocator, .type = typ, .url = url, .token = token, .status = status };
}

fn parseIdentifierArray(allocator: Allocator, value: std.json.Value) ParseError![]Identifier {
    if (value != .array) return error.InvalidField;
    const items = value.array.items;
    var identifiers = try allocator.alloc(Identifier, items.len);
    var initialized: usize = 0;
    errdefer {
        for (identifiers[0..initialized]) |*identifier| identifier.deinit();
        allocator.free(identifiers);
    }
    for (items) |item| {
        identifiers[initialized] = try parseIdentifierValue(allocator, item);
        initialized += 1;
    }
    return identifiers;
}

fn parseChallengeArray(allocator: Allocator, value: std.json.Value) ParseError![]Challenge {
    if (value != .array) return error.InvalidField;
    const items = value.array.items;
    var challenges = try allocator.alloc(Challenge, items.len);
    var initialized: usize = 0;
    errdefer {
        for (challenges[0..initialized]) |*challenge| challenge.deinit();
        allocator.free(challenges);
    }
    for (items) |item| {
        challenges[initialized] = try parseChallengeValue(allocator, item);
        initialized += 1;
    }
    return challenges;
}

fn parseStringArray(allocator: Allocator, value: std.json.Value) ParseError![][]u8 {
    if (value != .array) return error.InvalidField;
    const items = value.array.items;
    var strings = try allocator.alloc([]u8, items.len);
    var initialized: usize = 0;
    errdefer freeStringArray(allocator, strings[0..initialized]);
    for (items) |item| {
        if (item != .string) return error.InvalidField;
        strings[initialized] = try allocator.dupe(u8, item.string);
        initialized += 1;
    }
    return strings;
}

fn freeIdentifiers(allocator: Allocator, identifiers: []Identifier) void {
    for (identifiers) |*identifier| identifier.deinit();
    allocator.free(identifiers);
}

fn freeChallenges(allocator: Allocator, challenges: []Challenge) void {
    for (challenges) |*challenge| challenge.deinit();
    allocator.free(challenges);
}

fn freeStringArray(allocator: Allocator, strings: [][]u8) void {
    for (strings) |string| allocator.free(string);
    allocator.free(strings);
}

fn parseStatusField(obj: std.json.ObjectMap, name: []const u8) ParseError!Status {
    const value = obj.get(name) orelse return error.MissingField;
    if (value != .string) return error.InvalidField;
    return parseStatus(value.string);
}

fn parseStatus(text: []const u8) ParseError!Status {
    if (std.mem.eql(u8, text, "pending")) return .pending;
    if (std.mem.eql(u8, text, "ready")) return .ready;
    if (std.mem.eql(u8, text, "processing")) return .processing;
    if (std.mem.eql(u8, text, "valid")) return .valid;
    if (std.mem.eql(u8, text, "invalid")) return .invalid;
    if (std.mem.eql(u8, text, "deactivated")) return .deactivated;
    if (std.mem.eql(u8, text, "expired")) return .expired;
    if (std.mem.eql(u8, text, "revoked")) return .revoked;
    return error.InvalidStatus;
}

fn dupStringField(allocator: Allocator, obj: std.json.ObjectMap, name: []const u8) ParseError![]u8 {
    const value = obj.get(name) orelse return error.MissingField;
    if (value != .string) return error.InvalidField;
    return allocator.dupe(u8, value.string);
}

fn optionalDupStringField(allocator: Allocator, obj: std.json.ObjectMap, name: []const u8) ParseError!?[]u8 {
    const value = obj.get(name) orelse return null;
    if (value != .string) return error.InvalidField;
    return @as(?[]u8, try allocator.dupe(u8, value.string));
}

fn writeAll(writer: *std.Io.Writer, bytes: []const u8) BuildError!void {
    writer.writeAll(bytes) catch return error.NoSpaceLeft;
}

fn writeJsonString(writer: *std.Io.Writer, value: []const u8) BuildError!void {
    std.json.Stringify.value(value, .{}, writer) catch return error.NoSpaceLeft;
}

test "parse order copies ACME fields and deinit releases owned memory" {
    // Arrange
    const allocator = std.testing.allocator;
    const fixture =
        \\{
        \\  "status":"ready",
        \\  "expires":"2026-06-08T12:00:00Z",
        \\  "identifiers":[
        \\    {"type":"dns","value":"example.com"},
        \\    {"type":"dns","value":"www.example.com"}
        \\  ],
        \\  "authorizations":[
        \\    "https://ca.example/acme/authz/1",
        \\    "https://ca.example/acme/authz/2"
        \\  ],
        \\  "finalize":"https://ca.example/acme/order/1/finalize",
        \\  "certificate":"https://ca.example/acme/cert/1"
        \\}
    ;

    // Act
    var order = try parseOrder(allocator, fixture);
    defer order.deinit();

    // Assert
    try std.testing.expectEqual(Status.ready, order.status);
    try std.testing.expectEqualStrings("2026-06-08T12:00:00Z", order.expires.?);
    try std.testing.expectEqual(@as(usize, 2), order.identifiers.len);
    try std.testing.expectEqualStrings("dns", order.identifiers[0].type);
    try std.testing.expectEqualStrings("www.example.com", order.identifiers[1].value);
    try std.testing.expectEqualStrings("https://ca.example/acme/authz/2", order.authorizations[1]);
    try std.testing.expectEqualStrings("https://ca.example/acme/order/1/finalize", order.finalize);
    try std.testing.expectEqualStrings("https://ca.example/acme/cert/1", order.certificate.?);
}

test "parse authorization copies identifier challenges and findChallenge selects by type" {
    // Arrange
    const allocator = std.testing.allocator;
    const fixture =
        \\{
        \\  "status":"pending",
        \\  "identifier":{"type":"dns","value":"example.com"},
        \\  "challenges":[
        \\    {"type":"http-01","url":"https://ca.example/chal/1","token":"tok-http","status":"pending"},
        \\    {"type":"dns-01","url":"https://ca.example/chal/2","token":"tok-dns","status":"valid"}
        \\  ]
        \\}
    ;

    // Act
    var authz = try parseAuthorization(allocator, fixture);
    defer authz.deinit();
    const found = findChallenge(authz, "dns-01").?;

    // Assert
    try std.testing.expectEqual(Status.pending, authz.status);
    try std.testing.expectEqualStrings("example.com", authz.identifier.value);
    try std.testing.expectEqual(Status.valid, found.status);
    try std.testing.expectEqualStrings("tok-dns", found.token);
    try std.testing.expect(findChallenge(authz, "tls-alpn-01") == null);
}

test "parse challenge accepts realistic challenge object" {
    // Arrange
    const allocator = std.testing.allocator;
    const fixture =
        \\{"type":"tls-alpn-01","url":"https://ca.example/chal/3","token":"abc_123","status":"processing"}
    ;

    // Act
    var challenge = try parseChallenge(allocator, fixture);
    defer challenge.deinit();

    // Assert
    try std.testing.expectEqualStrings("tls-alpn-01", challenge.type);
    try std.testing.expectEqualStrings("https://ca.example/chal/3", challenge.url);
    try std.testing.expectEqualStrings("abc_123", challenge.token);
    try std.testing.expectEqual(Status.processing, challenge.status);
}

test "build newOrder emits parseable identifiers payload" {
    // Arrange
    var out: [256]u8 = undefined;
    const domains = [_][]const u8{ "example.com", "www.example.com" };

    // Act
    const json_text = try buildNewOrder(&out, &domains);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_text, .{});
    defer parsed.deinit();

    // Assert
    const identifiers = parsed.value.object.get("identifiers").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), identifiers.len);
    try std.testing.expectEqualStrings("dns", identifiers[0].object.get("type").?.string);
    try std.testing.expectEqualStrings("www.example.com", identifiers[1].object.get("value").?.string);
}

test "build finalize base64url encodes CSR DER and round-trips" {
    // Arrange
    var out: [128]u8 = undefined;
    var decoded: [8]u8 = undefined;
    const csr_der = [_]u8{ 0x30, 0x82, 0x01, 0x0a };

    // Act
    const json_text = try buildFinalize(&out, &csr_der);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_text, .{});
    defer parsed.deinit();
    const csr = parsed.value.object.get("csr").?.string;
    const round_trip = try base64url.decode(&decoded, csr);

    // Assert
    try std.testing.expectEqualStrings("MIIBCg", csr);
    try std.testing.expectEqualSlices(u8, &csr_der, round_trip);
}

test "parsers reject missing required fields and unknown statuses" {
    // Arrange
    const allocator = std.testing.allocator;
    const missing_finalize =
        \\{"status":"ready","identifiers":[],"authorizations":[]}
    ;
    const bad_status =
        \\{"type":"http-01","url":"https://ca.example/chal/1","token":"tok","status":"done"}
    ;

    // Act / Assert
    try std.testing.expectError(error.MissingField, parseOrder(allocator, missing_finalize));
    try std.testing.expectError(error.InvalidStatus, parseChallenge(allocator, bad_status));
}

test "builders return NoSpaceLeft for undersized buffers" {
    // Arrange
    var tiny_order: [8]u8 = undefined;
    var tiny_finalize: [8]u8 = undefined;
    const domains = [_][]const u8{"example.com"};
    const csr_der = [_]u8{ 0x30, 0x82, 0x01, 0x0a };

    // Act / Assert
    try std.testing.expectError(error.NoSpaceLeft, buildNewOrder(&tiny_order, &domains));
    try std.testing.expectError(error.NoSpaceLeft, buildFinalize(&tiny_finalize, &csr_der));
}
