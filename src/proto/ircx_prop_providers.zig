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
    .{ .name = "opkey", .scope = .channel, .read = readOpKey },
    .{ .name = "ownerkey", .scope = .channel, .read = readOwnerKey },
    .{ .name = "user_profile", .scope = .user, .read = readUserProfile },
    .{ .name = "creation_time", .scope = .channel, .read = readCreationTime },
    .{ .name = "topic_setter", .scope = .channel, .read = readTopicSetter },
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

fn readUserProfile(ctx: *const Snapshot, out_buf: []u8) ProviderError!PropValue {
    var writer = BufferWriter.init(out_buf);
    var first = true;

    try appendProfileField(&writer, &first, "display", ctx.profile_display_name);
    try appendProfileField(&writer, &first, "real", ctx.profile_real_name);
    try appendProfileField(&writer, &first, "title", ctx.profile_title);
    try appendProfileField(&writer, &first, "location", ctx.profile_location);
    try appendProfileField(&writer, &first, "note", ctx.profile_note);

    return .{ .text = writer.slice() };
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
    const user_buf = try allocator.alloc(Provider, 9);
    defer allocator.free(user_buf);
    const channel_buf = try allocator.alloc(Provider, 9);
    defer allocator.free(channel_buf);
    var registry = ProviderRegistry.init();
    defer registry.deinit();

    // Act
    const users = registry.listForScope(.user, user_buf);
    const channels = registry.listForScope(.channel, channel_buf);

    // Assert
    try std.testing.expectEqual(@as(usize, 3), users.len);
    try std.testing.expectEqual(@as(usize, 6), channels.len);
    try std.testing.expectEqualStrings("account", users[0].name);
    try std.testing.expectEqualStrings("member_of", users[1].name);
    try std.testing.expectEqualStrings("user_profile", users[2].name);
    try std.testing.expectEqualStrings("onjoin", channels[0].name);
    try std.testing.expectEqualStrings("topic_setter", channels[5].name);
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
