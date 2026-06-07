//! ACME account JSON codecs for RFC 8555 section 7.3.
//!
//! The ACME account URL is not part of the account JSON object. Servers return
//! it in the HTTP Location header, and later JWS requests use it as the `kid`.
//! `parseAccount` leaves `Account.kid` as null; callers should fill it from the
//! Location header when that header is available. The field is borrowed and is
//! not freed by `Account.deinit`.

const std = @import("std");

comptime {
    if (@sizeOf(usize) != 8) @compileError("acme_account requires a 64-bit target");
}

pub const BuildError = error{
    NoSpaceLeft,
};

pub const ParseError = error{
    OutOfMemory,
    InvalidJson,
    InvalidAccount,
    MissingStatus,
    InvalidStatus,
    InvalidContact,
    InvalidOrders,
};

pub const Status = enum {
    valid,
    deactivated,
    revoked,

    pub fn parse(raw: []const u8) ?Status {
        if (std.mem.eql(u8, raw, "valid")) return .valid;
        if (std.mem.eql(u8, raw, "deactivated")) return .deactivated;
        if (std.mem.eql(u8, raw, "revoked")) return .revoked;
        return null;
    }

    pub fn jsonName(self: Status) []const u8 {
        return switch (self) {
            .valid => "valid",
            .deactivated => "deactivated",
            .revoked => "revoked",
        };
    }
};

pub const Account = struct {
    /// Borrowed ACME account URL from the HTTP Location header; not JSON-owned.
    kid: ?[]const u8 = null,
    status: Status,
    contact: ?[]const []const u8 = null,
    orders: ?[]const u8 = null,

    pub fn deinit(self: *Account, allocator: std.mem.Allocator) void {
        if (self.contact) |items| {
            for (items) |item| allocator.free(item);
            allocator.free(items);
        }
        if (self.orders) |orders| allocator.free(orders);
        self.* = undefined;
    }
};

pub fn buildNewAccount(
    out: []u8,
    contacts: []const []const u8,
    tos_agreed: bool,
) BuildError![]const u8 {
    var writer = std.Io.Writer.fixed(out);
    return buildNewAccountWithWriter(&writer, contacts, tos_agreed) catch |err| switch (err) {
        error.WriteFailed => error.NoSpaceLeft,
    };
}

fn buildNewAccountWithWriter(
    writer: *std.Io.Writer,
    contacts: []const []const u8,
    tos_agreed: bool,
) std.Io.Writer.Error![]const u8 {
    var json: std.json.Stringify = .{ .writer = writer };

    try json.beginObject();
    try json.objectField("termsOfServiceAgreed");
    try json.write(tos_agreed);
    try json.objectField("contact");
    try json.beginArray();
    for (contacts) |contact| try json.write(contact);
    try json.endArray();
    try json.endObject();

    return writer.buffered();
}

pub fn parseAccount(allocator: std.mem.Allocator, bytes: []const u8) ParseError!Account {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidAccount;
    const object = parsed.value.object;

    const status_value = object.get("status") orelse return error.MissingStatus;
    if (status_value != .string) return error.InvalidStatus;
    const status = Status.parse(status_value.string) orelse return error.InvalidStatus;

    var account = Account{ .status = status };
    errdefer account.deinit(allocator);

    if (object.get("contact")) |contact_value| {
        if (contact_value != .array) return error.InvalidContact;
        account.contact = try dupeStringArray(allocator, contact_value.array.items);
    }

    if (object.get("orders")) |orders_value| {
        if (orders_value != .string) return error.InvalidOrders;
        account.orders = try allocator.dupe(u8, orders_value.string);
    }

    return account;
}

fn dupeStringArray(
    allocator: std.mem.Allocator,
    values: []const std.json.Value,
) ParseError![]const []const u8 {
    const items = try allocator.alloc([]const u8, values.len);
    var used: usize = 0;
    errdefer {
        for (items[0..used]) |item| allocator.free(item);
        allocator.free(items);
    }

    for (values) |value| {
        if (value != .string) return error.InvalidContact;
        items[used] = try allocator.dupe(u8, value.string);
        used += 1;
    }

    return items;
}

test "buildNewAccount writes terms agreement and mailto contacts" {
    // Arrange.
    var out: [160]u8 = undefined;
    const contacts = [_][]const u8{
        "mailto:admin@example.com",
        "mailto:ops+acme@example.net",
    };

    // Act.
    const json = try buildNewAccount(&out, &contacts, true);

    // Assert.
    try std.testing.expectEqualStrings(
        "{\"termsOfServiceAgreed\":true,\"contact\":[\"mailto:admin@example.com\",\"mailto:ops+acme@example.net\"]}",
        json,
    );
}

test "buildNewAccount keeps an empty contact array when no contacts are supplied" {
    // Arrange.
    var out: [80]u8 = undefined;
    const contacts = [_][]const u8{};

    // Act.
    const json = try buildNewAccount(&out, &contacts, false);

    // Assert.
    try std.testing.expectEqualStrings(
        "{\"termsOfServiceAgreed\":false,\"contact\":[]}",
        json,
    );
}

test "buildNewAccount reports NoSpaceLeft for undersized output buffers" {
    // Arrange.
    var out: [12]u8 = undefined;
    const contacts = [_][]const u8{"mailto:admin@example.com"};

    // Act.
    const result = buildNewAccount(&out, &contacts, true);

    // Assert.
    try std.testing.expectError(error.NoSpaceLeft, result);
}

test "buildNewAccount output parses back to the expected JSON fields" {
    // Arrange.
    const allocator = std.testing.allocator;
    var out: [128]u8 = undefined;
    const contacts = [_][]const u8{"mailto:admin@example.com"};

    // Act.
    const json = try buildNewAccount(&out, &contacts, true);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    // Assert.
    try std.testing.expect(parsed.value == .object);
    const object = parsed.value.object;
    try std.testing.expectEqual(true, object.get("termsOfServiceAgreed").?.bool);
    try std.testing.expectEqualStrings(
        "mailto:admin@example.com",
        object.get("contact").?.array.items[0].string,
    );
}

test "parseAccount copies status contact orders and leaves kid for Location header" {
    // Arrange.
    const allocator = std.testing.allocator;
    const fixture =
        \\{
        \\  "status": "valid",
        \\  "contact": [
        \\    "mailto:admin@example.com",
        \\    "mailto:ops@example.net"
        \\  ],
        \\  "orders": "https://ca.example/acme/acct/42/orders"
        \\}
    ;

    // Act.
    var account = try parseAccount(allocator, fixture);
    defer account.deinit(allocator);
    account.kid = "https://ca.example/acme/acct/42";

    // Assert.
    try std.testing.expectEqual(Status.valid, account.status);
    try std.testing.expectEqualStrings("https://ca.example/acme/acct/42", account.kid.?);
    try std.testing.expectEqual(@as(usize, 2), account.contact.?.len);
    try std.testing.expectEqualStrings("mailto:admin@example.com", account.contact.?[0]);
    try std.testing.expectEqualStrings("mailto:ops@example.net", account.contact.?[1]);
    try std.testing.expectEqualStrings("https://ca.example/acme/acct/42/orders", account.orders.?);
}

test "parseAccount accepts missing optional contact and orders fields" {
    // Arrange.
    const allocator = std.testing.allocator;
    const fixture = "{\"status\":\"deactivated\"}";

    // Act.
    var account = try parseAccount(allocator, fixture);
    defer account.deinit(allocator);

    // Assert.
    try std.testing.expectEqual(Status.deactivated, account.status);
    try std.testing.expectEqual(@as(?[]const []const u8, null), account.contact);
    try std.testing.expectEqual(@as(?[]const u8, null), account.orders);
    try std.testing.expectEqual(@as(?[]const u8, null), account.kid);
}

test "parseAccount preserves present empty contact array" {
    // Arrange.
    const allocator = std.testing.allocator;
    const fixture = "{\"status\":\"revoked\",\"contact\":[]}";

    // Act.
    var account = try parseAccount(allocator, fixture);
    defer account.deinit(allocator);

    // Assert.
    try std.testing.expectEqual(Status.revoked, account.status);
    try std.testing.expect(account.contact != null);
    try std.testing.expectEqual(@as(usize, 0), account.contact.?.len);
}

test "parseAccount rejects non-object JSON" {
    // Arrange.
    const allocator = std.testing.allocator;
    const fixture = "[]";

    // Act.
    const result = parseAccount(allocator, fixture);

    // Assert.
    try std.testing.expectError(error.InvalidAccount, result);
}

test "parseAccount rejects missing status" {
    // Arrange.
    const allocator = std.testing.allocator;
    const fixture = "{\"contact\":[\"mailto:admin@example.com\"]}";

    // Act.
    const result = parseAccount(allocator, fixture);

    // Assert.
    try std.testing.expectError(error.MissingStatus, result);
}

test "parseAccount rejects unknown status" {
    // Arrange.
    const allocator = std.testing.allocator;
    const fixture = "{\"status\":\"pending\"}";

    // Act.
    const result = parseAccount(allocator, fixture);

    // Assert.
    try std.testing.expectError(error.InvalidStatus, result);
}

test "parseAccount rejects contact arrays with non-string entries without leaking" {
    // Arrange.
    const allocator = std.testing.allocator;
    const fixture = "{\"status\":\"valid\",\"contact\":[\"mailto:admin@example.com\",7]}";

    // Act.
    const result = parseAccount(allocator, fixture);

    // Assert.
    try std.testing.expectError(error.InvalidContact, result);
}

test "parseAccount rejects non-string orders" {
    // Arrange.
    const allocator = std.testing.allocator;
    const fixture = "{\"status\":\"valid\",\"orders\":42}";

    // Act.
    const result = parseAccount(allocator, fixture);

    // Assert.
    try std.testing.expectError(error.InvalidOrders, result);
}

test "parseAccount rejects malformed JSON" {
    // Arrange.
    const allocator = std.testing.allocator;
    const fixture = "{\"status\":\"valid\"";

    // Act.
    const result = parseAccount(allocator, fixture);

    // Assert.
    try std.testing.expectError(error.InvalidJson, result);
}
