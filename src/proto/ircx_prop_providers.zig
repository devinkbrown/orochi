// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure property-provider registry for computed IRCX properties.
//!
//! Providers in this module read only the injected `Snapshot`. They do not
//! allocate, do not reach into live daemon state, and return slices that either
//! point at snapshot data or at caller-owned output storage.
const std = @import("std");

/// Object scope for a computed property provider.
pub const PropScope = enum {
    channel,
    user,
};

/// Value returned by a computed property provider.
pub const PropValue = union(enum) {
    /// Borrowed UTF-8 text.
    text: []const u8,
    /// Signed integer value, typically a timestamp.
    number: i64,
    /// Boolean property value.
    boolean: bool,
    /// Borrowed list of borrowed UTF-8 text values.
    list: []const []const u8,
};

/// Errors returned by property-provider lookup and rendering.
pub const ProviderError = error{
    UnknownProperty,
    OutputTooSmall,
};

/// Borrowed immutable state used by property providers.
pub const Snapshot = struct {
    /// Account name attached to a user object, or null when unauthenticated.
    account_name: ?[]const u8 = null,
    /// Rendered membership entries for a user object.
    member_of: []const []const u8 = &.{},
    /// Timestamp associated with the object's join event.
    join_time: ?i64 = null,
    /// Timestamp associated with the object's part event.
    part_time: ?i64 = null,
    /// Operator key attached to a channel object.
    op_key: ?[]const u8 = null,
    /// Owner key attached to a channel object.
    owner_key: ?[]const u8 = null,
    /// Channel creation timestamp.
    creation_time: ?i64 = null,
    /// Nick or account name that last set the channel topic.
    topic_setter: ?[]const u8 = null,
    /// Channel display name (the canonical channel id, e.g. `#zig`).
    channel_name: ?[]const u8 = null,
    /// Current channel topic text.
    topic: ?[]const u8 = null,
    /// Channel subject (short descriptor distinct from TOPIC).
    subject: ?[]const u8 = null,
    /// Channel language tag (e.g. `en`, `de`).
    language: ?[]const u8 = null,
    /// Host key attached to a channel object (write-only secret, never read out).
    host_key: ?[]const u8 = null,
    /// Member key attached to a channel object (mirrors +k; secret).
    member_key: ?[]const u8 = null,
    /// Live channel member count.
    member_count: ?u64 = null,
    /// Channel member limit (mirrors +l); null when unset.
    member_limit: ?u64 = null,
    /// Channel registration state used by the `registered` provider.
    registered: ?bool = null,
    /// Display name used by the user profile provider.
    profile_display_name: ?[]const u8 = null,
    /// Real name used by the user profile provider.
    profile_real_name: ?[]const u8 = null,
    /// Title used by the user profile provider.
    profile_title: ?[]const u8 = null,
    /// Location used by the user profile provider.
    profile_location: ?[]const u8 = null,
    /// Free-form note used by the user profile provider.
    profile_note: ?[]const u8 = null,
    /// Website URL used by the user profile provider.
    profile_url: ?[]const u8 = null,
    /// Gender identity used by the user profile provider.
    profile_gender: ?[]const u8 = null,
    /// Avatar/picture URL used by the user profile provider.
    profile_picture: ?[]const u8 = null,
    /// Short biography used by the user profile provider.
    profile_bio: ?[]const u8 = null,
    /// Contact email used by the user profile provider.
    profile_email: ?[]const u8 = null,
    /// GeoIP country code exposed by the user GeoIP providers.
    geo_country: ?[]const u8 = null,
    /// GeoIP region/subdivision exposed by the user GeoIP providers.
    geo_region: ?[]const u8 = null,
    /// GeoIP city exposed by the user GeoIP providers.
    geo_city: ?[]const u8 = null,
    /// GeoIP ASN exposed by the user GeoIP providers.
    geo_asn: ?u32 = null,
    /// GeoIP ASN organization exposed by the user GeoIP providers.
    geo_asorg: ?[]const u8 = null,
};

/// Function type implemented by each computed property provider.
pub const ProviderFn = *const fn (ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue;

/// Named property-provider descriptor.
pub const Provider = struct {
    /// Canonical lower-case property name.
    name: []const u8,
    /// Object scope this provider applies to.
    scope: PropScope,
    /// Pure provider implementation.
    read: ProviderFn,
    /// True for write-only secret keys (OWNERKEY/HOSTKEY/MEMBERKEY/OPKEY) that the
    /// IRCX draft marks "never readable"; callers must not emit these to clients.
    secret: bool = false,
};

/// Registry of known computed property providers.
pub const ProviderRegistry = struct {
    /// Provider table searched by lookup and query methods.
    providers: []const Provider,

    /// Create a registry containing the built-in provider table.
    pub fn init() ProviderRegistry {
        return .{ .providers = &builtin_providers };
    }

    /// Release registry-owned resources.
    pub fn deinit(self: *ProviderRegistry) void {
        self.* = undefined;
    }

    /// Find a provider by case-insensitive property name.
    pub fn lookup(self: *const ProviderRegistry, name: []const u8) ?Provider {
        for (self.providers) |provider| {
            if (std.ascii.eqlIgnoreCase(provider.name, name)) return provider;
        }
        return null;
    }

    /// Copy providers matching `scope` into `buf` and return the filled prefix.
    pub fn listForScope(self: *const ProviderRegistry, scope: PropScope, buf: []Provider) []Provider {
        var count: usize = 0;
        for (self.providers) |provider| {
            if (provider.scope != scope) continue;
            if (count == buf.len) return buf[0..count];
            buf[count] = provider;
            count += 1;
        }
        return buf[0..count];
    }

    /// Evaluate a provider by case-insensitive property name.
    pub fn query(
        self: *const ProviderRegistry,
        name: []const u8,
        ctx: *const Snapshot,
        buf: []u8,
    ) ProviderError!PropValue {
        const provider = self.lookup(name) orelse return error.UnknownProperty;
        return provider.read(ctx, buf);
    }
};

const builtin_providers = [_]Provider{
    .{ .name = "account", .scope = .user, .read = readAccount },
    .{ .name = "member_of", .scope = .user, .read = readMemberOf },
    .{ .name = "onjoin", .scope = .channel, .read = readOnJoin },
    .{ .name = "onpart", .scope = .channel, .read = readOnPart },
    .{ .name = "opkey", .scope = .channel, .read = readOpKey, .secret = true },
    .{ .name = "ownerkey", .scope = .channel, .read = readOwnerKey, .secret = true },
    .{ .name = "user_profile", .scope = .user, .read = readUserProfile },
    .{ .name = "country", .scope = .user, .read = readGeoCountry },
    .{ .name = "region", .scope = .user, .read = readGeoRegion },
    .{ .name = "city", .scope = .user, .read = readGeoCity },
    .{ .name = "asn", .scope = .user, .read = readGeoAsn },
    .{ .name = "asorg", .scope = .user, .read = readGeoAsOrg },
    .{ .name = "creation_time", .scope = .channel, .read = readCreationTime },
    .{ .name = "topic_setter", .scope = .channel, .read = readTopicSetter },
    .{ .name = "name", .scope = .channel, .read = readChannelName },
    .{ .name = "topic", .scope = .channel, .read = readTopic },
    .{ .name = "subject", .scope = .channel, .read = readSubject },
    .{ .name = "language", .scope = .channel, .read = readLanguage },
    .{ .name = "hostkey", .scope = .channel, .read = readHostKey, .secret = true },
    .{ .name = "memberkey", .scope = .channel, .read = readMemberKey, .secret = true },
    .{ .name = "membercount", .scope = .channel, .read = readMemberCount },
    .{ .name = "memberlimit", .scope = .channel, .read = readMemberLimit },
    .{ .name = "registered", .scope = .channel, .read = readRegistered },
};

fn readAccount(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.account_name orelse "" };
}

fn readMemberOf(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .list = ctx.member_of };
}

fn readOnJoin(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .number = ctx.join_time orelse 0 };
}

fn readOnPart(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .number = ctx.part_time orelse 0 };
}

fn readOpKey(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.op_key orelse "" };
}

fn readOwnerKey(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.owner_key orelse "" };
}

fn readCreationTime(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .number = ctx.creation_time orelse 0 };
}

fn readTopicSetter(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.topic_setter orelse "" };
}

fn readChannelName(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.channel_name orelse "" };
}

fn readTopic(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.topic orelse "" };
}

fn readSubject(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.subject orelse "" };
}

fn readLanguage(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.language orelse "" };
}

fn readHostKey(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.host_key orelse "" };
}

fn readMemberKey(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.member_key orelse "" };
}

fn readMemberCount(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .number = @intCast(ctx.member_count orelse 0) };
}

fn readMemberLimit(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .number = @intCast(ctx.member_limit orelse 0) };
}

fn readRegistered(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .boolean = ctx.registered orelse false };
}

fn readUserProfile(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    var writer = BufferWriter.init(out_buf);
    var first = true;

    try appendProfileField(&writer, &first, "display", ctx.profile_display_name);
    try appendProfileField(&writer, &first, "real", ctx.profile_real_name);
    try appendProfileField(&writer, &first, "title", ctx.profile_title);
    try appendProfileField(&writer, &first, "location", ctx.profile_location);
    try appendProfileField(&writer, &first, "note", ctx.profile_note);
    try appendProfileField(&writer, &first, "url", ctx.profile_url);
    try appendProfileField(&writer, &first, "gender", ctx.profile_gender);
    try appendProfileField(&writer, &first, "picture", ctx.profile_picture);
    try appendProfileField(&writer, &first, "bio", ctx.profile_bio);
    try appendProfileField(&writer, &first, "email", ctx.profile_email);

    return .{ .text = writer.slice() };
}

fn readGeoCountry(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.geo_country orelse "" };
}

fn readGeoRegion(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.geo_region orelse "" };
}

fn readGeoCity(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.geo_city orelse "" };
}

fn readGeoAsn(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    const asn = ctx.geo_asn orelse return .{ .text = "" };
    return .{ .text = std.fmt.bufPrint(out_buf, "{d}", .{asn}) catch return error.OutputTooSmall };
}

fn readGeoAsOrg(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    _ = out_buf;
    return .{ .text = ctx.geo_asorg orelse "" };
}

fn appendProfileField(
    writer: *BufferWriter,
    first: *bool,
    key: []const u8,
    value: ?[]const u8,
) ProviderError!void {
    const text = value orelse return;
    if (text.len == 0) return;
    if (!first.*) try writer.append(";");
    first.* = false;
    try writer.append(key);
    try writer.append("=");
    try writer.append(text);
}

const BufferWriter = struct {
    out: []u8,
    len: usize = 0,

    fn init(out: []u8) BufferWriter {
        return .{ .out = out };
    }

    fn slice(self: *const BufferWriter) []const u8 {
        return self.out[0..self.len];
    }

    fn append(self: *BufferWriter, bytes: []const u8) ProviderError!void {
        if (bytes.len > self.out.len - self.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }
};

fn expectText(value: PropValue, expected: []const u8) !void {
    switch (value) {
        .text => |actual| try std.testing.expectEqualStrings(expected, actual),
        .number, .boolean, .list => return error.UnexpectedValueKind,
    }
}

fn expectNumber(value: PropValue, expected: i64) !void {
    switch (value) {
        .number => |actual| try std.testing.expectEqual(expected, actual),
        .text, .boolean, .list => return error.UnexpectedValueKind,
    }
}

fn expectBoolean(value: PropValue, expected: bool) !void {
    switch (value) {
        .boolean => |actual| try std.testing.expectEqual(expected, actual),
        .text, .number, .list => return error.UnexpectedValueKind,
    }
}

fn expectList(value: PropValue, expected: []const []const u8) !void {
    switch (value) {
        .list => |actual| {
            try std.testing.expectEqual(expected.len, actual.len);
            for (expected, actual) |expected_item, actual_item| {
                try std.testing.expectEqualStrings(expected_item, actual_item);
            }
        },
        .text, .number, .boolean => return error.UnexpectedValueKind,
    }
}

test "account provider returns the snapshot account name" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 1);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const snapshot = Snapshot{ .account_name = "alice" };

    // Act
    const value = try registry.query("account", &snapshot, out);

    // Assert
    try expectText(value, "alice");
}

test "member_of provider returns the borrowed membership list" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 1);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const memberships = [_][]const u8{ "#ops:owner", "#help:voice", "#chat:member" };
    const snapshot = Snapshot{ .member_of = &memberships };

    // Act
    const value = try registry.query("member_of", &snapshot, out);

    // Assert
    try expectList(value, &memberships);
}

test "onjoin provider returns the join timestamp or zero" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 1);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const with_join = Snapshot{ .join_time = 1_735_689_600 };
    const without_join = Snapshot{};

    // Act
    const present = try registry.query("onjoin", &with_join, out);
    const absent = try registry.query("onjoin", &without_join, out);

    // Assert
    try expectNumber(present, 1_735_689_600);
    try expectNumber(absent, 0);
}

test "onpart provider returns the part timestamp or zero" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 1);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const with_part = Snapshot{ .part_time = 1_735_693_200 };
    const without_part = Snapshot{};

    // Act
    const present = try registry.query("onpart", &with_part, out);
    const absent = try registry.query("onpart", &without_part, out);

    // Assert
    try expectNumber(present, 1_735_693_200);
    try expectNumber(absent, 0);
}

test "opkey provider returns the channel operator key" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 1);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const snapshot = Snapshot{ .op_key = "op-secret" };

    // Act
    const value = try registry.query("opkey", &snapshot, out);

    // Assert
    try expectText(value, "op-secret");
}

test "ownerkey provider returns the channel owner key" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 1);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const snapshot = Snapshot{ .owner_key = "owner-secret" };

    // Act
    const value = try registry.query("ownerkey", &snapshot, out);

    // Assert
    try expectText(value, "owner-secret");
}

test "user_profile provider builds a deterministic profile string" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 128);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const snapshot = Snapshot{
        .profile_display_name = "Alice",
        .profile_real_name = "Alice Example",
        .profile_title = "Operator",
        .profile_location = "Berlin",
        .profile_note = "Available",
    };

    // Act
    const value = try registry.query("user_profile", &snapshot, out);

    // Assert
    try expectText(value, "display=Alice;real=Alice Example;title=Operator;location=Berlin;note=Available");
}

test "user_profile provider skips missing and empty fields" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 64);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const snapshot = Snapshot{
        .profile_display_name = "Alice",
        .profile_title = "",
        .profile_note = "Ready",
    };

    // Act
    const value = try registry.query("user_profile", &snapshot, out);

    // Assert
    try expectText(value, "display=Alice;note=Ready");
}

test "user_profile provider includes extended profile fields" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 256);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const snapshot = Snapshot{
        .profile_url = "https://example.test/alice",
        .profile_gender = "nonbinary",
        .profile_picture = "https://example.test/a.png",
        .profile_bio = "Orochi operator",
        .profile_email = "alice@example.test",
    };

    // Act
    const value = try registry.query("user_profile", &snapshot, out);

    // Assert
    try expectText(value, "url=https://example.test/alice;gender=nonbinary;picture=https://example.test/a.png;bio=Orochi operator;email=alice@example.test");
}

test "user_profile provider reports small caller buffers" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 8);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const snapshot = Snapshot{ .profile_display_name = "Alice" };

    // Act
    const result = registry.query("user_profile", &snapshot, out);

    // Assert
    try std.testing.expectError(error.OutputTooSmall, result);
}

test "user GeoIP providers return snapshot values or empty strings" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 32);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const snapshot = Snapshot{
        .geo_country = "DE",
        .geo_region = "Berlin",
        .geo_city = "Berlin",
        .geo_asn = 64512,
        .geo_asorg = "Example Net",
    };
    const empty = Snapshot{};

    // Act / Assert
    try expectText(try registry.query("COUNTRY", &snapshot, out), "DE");
    try expectText(try registry.query("REGION", &snapshot, out), "Berlin");
    try expectText(try registry.query("CITY", &snapshot, out), "Berlin");
    try expectText(try registry.query("ASN", &snapshot, out), "64512");
    try expectText(try registry.query("ASORG", &snapshot, out), "Example Net");

    try expectText(try registry.query("COUNTRY", &empty, out), "");
    try expectText(try registry.query("REGION", &empty, out), "");
    try expectText(try registry.query("CITY", &empty, out), "");
    try expectText(try registry.query("ASN", &empty, out), "");
    try expectText(try registry.query("ASORG", &empty, out), "");
}

test "user ASN provider reports small caller buffers" {
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const snapshot = Snapshot{ .geo_asn = 64512 };
    var out: [2]u8 = undefined;

    try std.testing.expectError(error.OutputTooSmall, registry.query("ASN", &snapshot, &out));
}

test "creation_time provider returns the channel creation timestamp" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 1);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const snapshot = Snapshot{ .creation_time = 1_735_600_000 };

    // Act
    const value = try registry.query("creation_time", &snapshot, out);

    // Assert
    try expectNumber(value, 1_735_600_000);
}

test "topic_setter provider returns the borrowed setter name" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 1);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const snapshot = Snapshot{ .topic_setter = "carol" };

    // Act
    const value = try registry.query("topic_setter", &snapshot, out);

    // Assert
    try expectText(value, "carol");
}

test "channel string providers return snapshot text or empty" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 1);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();

    const snapshot = Snapshot{
        .channel_name = "#zig",
        .topic = "Zig IRCX",
        .subject = "dev",
        .language = "en",
        .host_key = "host-secret",
        .member_key = "member-secret",
    };

    try expectText(try registry.query("name", &snapshot, out), "#zig");
    try expectText(try registry.query("topic", &snapshot, out), "Zig IRCX");
    try expectText(try registry.query("subject", &snapshot, out), "dev");
    try expectText(try registry.query("language", &snapshot, out), "en");
    try expectText(try registry.query("hostkey", &snapshot, out), "host-secret");
    try expectText(try registry.query("memberkey", &snapshot, out), "member-secret");

    const empty = Snapshot{};
    try expectText(try registry.query("topic", &empty, out), "");
}

test "channel numeric and boolean providers" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 1);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();

    const snapshot = Snapshot{
        .member_count = 42,
        .member_limit = 100,
        .registered = true,
    };

    try expectNumber(try registry.query("membercount", &snapshot, out), 42);
    try expectNumber(try registry.query("memberlimit", &snapshot, out), 100);
    try expectBoolean(try registry.query("registered", &snapshot, out), true);

    const unset = Snapshot{};
    try expectNumber(try registry.query("membercount", &unset, out), 0);
    try expectNumber(try registry.query("memberlimit", &unset, out), 0);
    try expectBoolean(try registry.query("registered", &unset, out), false);
}

test "secret key providers are flagged so callers never emit them" {
    var registry = ProviderRegistry.init();
    defer registry.deinit();

    try std.testing.expect(registry.lookup("ownerkey").?.secret);
    try std.testing.expect(registry.lookup("opkey").?.secret);
    try std.testing.expect(registry.lookup("hostkey").?.secret);
    try std.testing.expect(registry.lookup("memberkey").?.secret);

    try std.testing.expect(!registry.lookup("topic").?.secret);
    try std.testing.expect(!registry.lookup("name").?.secret);
    try std.testing.expect(!registry.lookup("account").?.secret);
}

test "lookup is case-insensitive and returns provider descriptors" {
    // Arrange
    var registry = ProviderRegistry.init();
    defer registry.deinit();

    // Act
    const provider = registry.lookup("UsEr_PrOfIlE").?;

    // Assert
    try std.testing.expectEqualStrings("user_profile", provider.name);
    try std.testing.expectEqual(PropScope.user, provider.scope);
}

test "query returns UnknownProperty for an unknown name" {
    const allocator = std.testing.allocator;

    // Arrange
    const out = try allocator.alloc(u8, 1);
    defer allocator.free(out);
    var registry = ProviderRegistry.init();
    defer registry.deinit();
    const snapshot = Snapshot{};

    // Act
    const result = registry.query("missing_property", &snapshot, out);

    // Assert
    try std.testing.expectError(error.UnknownProperty, result);
}

test "listForScope filters user and channel providers" {
    const allocator = std.testing.allocator;

    // Arrange
    const user_buf = try allocator.alloc(Provider, builtin_providers.len);
    defer allocator.free(user_buf);
    const channel_buf = try allocator.alloc(Provider, builtin_providers.len);
    defer allocator.free(channel_buf);
    var registry = ProviderRegistry.init();
    defer registry.deinit();

    // Act
    const users = registry.listForScope(.user, user_buf);
    const channels = registry.listForScope(.channel, channel_buf);

    // Assert
    try std.testing.expectEqual(@as(usize, 8), users.len);
    try std.testing.expectEqual(@as(usize, 15), channels.len);
    try std.testing.expectEqualStrings("account", users[0].name);
    try std.testing.expectEqualStrings("member_of", users[1].name);
    try std.testing.expectEqualStrings("user_profile", users[2].name);
    try std.testing.expectEqualStrings("country", users[3].name);
    try std.testing.expectEqualStrings("region", users[4].name);
    try std.testing.expectEqualStrings("city", users[5].name);
    try std.testing.expectEqualStrings("asn", users[6].name);
    try std.testing.expectEqualStrings("asorg", users[7].name);
    try std.testing.expectEqualStrings("onjoin", channels[0].name);
    try std.testing.expectEqualStrings("topic_setter", channels[5].name);
    try std.testing.expectEqualStrings("name", channels[6].name);
}

test "listForScope truncates to caller capacity without allocating" {
    const allocator = std.testing.allocator;

    // Arrange
    const channel_buf = try allocator.alloc(Provider, 2);
    defer allocator.free(channel_buf);
    var registry = ProviderRegistry.init();
    defer registry.deinit();

    // Act
    const channels = registry.listForScope(.channel, channel_buf);

    // Assert
    try std.testing.expectEqual(@as(usize, 2), channels.len);
    try std.testing.expectEqualStrings("onjoin", channels[0].name);
    try std.testing.expectEqualStrings("onpart", channels[1].name);
}
