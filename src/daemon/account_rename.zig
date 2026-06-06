//! Pure account rename planning.
//!
//! This module validates a requested account name, asks caller-owned storage
//! whether the destination exists, and returns an owned plan describing the
//! old-to-new account transition. It performs no daemon I/O and mutates no
//! backing account store.

const std = @import("std");

comptime {
    if (@sizeOf(usize) != 8) @compileError("account rename planning is 64-bit only");
}

/// IRC numeric hints a caller may use when translating rename failures.
pub const RenameNumeric = enum(u16) {
    ERR_ERRONEUSNICKNAME = 432,
    ERR_NICKNAMEINUSE = 433,
    ERR_NEEDMOREPARAMS = 461,
    RPL_LOGGEDIN = 900,

    /// Returns the wire numeric value.
    pub fn value(self: RenameNumeric) u16 {
        return @intFromEnum(self);
    }

    /// Maps a planning error to the closest numeric, when a numeric is useful.
    pub fn fromError(err: RenameError) ?RenameNumeric {
        return switch (err) {
            error.InvalidCurrentName,
            error.CurrentNameTooLong,
            error.InvalidNewName,
            error.NewNameTooLong,
            => .ERR_ERRONEUSNICKNAME,
            error.SameName => .ERR_NEEDMOREPARAMS,
            error.AccountExists => .ERR_NICKNAMEINUSE,
            error.OutOfMemory => null,
        };
    }
};

/// Runtime validation limits for account rename planning.
pub const Params = struct {
    /// Maximum bytes accepted for an account name.
    max_account_bytes: usize = 32,
};

/// Errors returned while validating and planning an account rename.
pub const RenameError = std.mem.Allocator.Error || error{
    InvalidCurrentName,
    CurrentNameTooLong,
    InvalidNewName,
    NewNameTooLong,
    SameName,
    AccountExists,
};

/// Metadata copied unchanged from the old account into a rename plan.
pub const AccountMetadata = struct {
    /// Creation timestamp in milliseconds, owned by the backing store.
    created_ms: u64 = 0,
    /// Last metadata update timestamp in milliseconds.
    updated_ms: u64 = 0,
    /// Caller-defined account flags.
    flags: u64 = 0,
    /// True when the account has completed contact verification.
    verified: bool = false,
};

/// Borrowed account state supplied by the caller.
pub const AccountSnapshot = struct {
    /// Current account name.
    name: []const u8,
    /// Metadata that must survive the rename unchanged.
    metadata: AccountMetadata = .{},
};

/// Callback adapter used to query whether an account name already exists.
pub const AccountLookup = struct {
    /// Caller-owned context pointer passed to `exists_fn`.
    ptr: *anyopaque,
    /// Returns true when `name` is already present in caller-owned storage.
    exists_fn: *const fn (ptr: *anyopaque, name: []const u8) RenameError!bool,

    /// Checks whether an account name is already present.
    pub fn exists(self: AccountLookup, name: []const u8) RenameError!bool {
        return self.exists_fn(self.ptr, name);
    }
};

/// Owned rename plan returned by `Planner.plan`.
pub const RenamePlan = struct {
    allocator: std.mem.Allocator,
    old_name: []const u8,
    new_name: []const u8,
    metadata: AccountMetadata,

    /// Frees owned plan storage and invalidates the plan.
    pub fn deinit(self: *RenamePlan) void {
        self.allocator.free(self.old_name);
        self.allocator.free(self.new_name);
        self.* = undefined;
    }

    /// Returns a borrowed view of the source account before the rename.
    pub fn original(self: *const RenamePlan) AccountSnapshot {
        return .{ .name = self.old_name, .metadata = self.metadata };
    }

    /// Returns a borrowed view of the account after the rename.
    pub fn renamed(self: *const RenamePlan) AccountSnapshot {
        return .{ .name = self.new_name, .metadata = self.metadata };
    }
};

/// Pure account rename planner.
pub const Planner = struct {
    allocator: std.mem.Allocator,
    params: Params,
    lookup: AccountLookup,

    /// Creates a planner using caller-owned lookup state.
    pub fn init(allocator: std.mem.Allocator, params: Params, lookup: AccountLookup) Planner {
        return .{
            .allocator = allocator,
            .params = params,
            .lookup = lookup,
        };
    }

    /// Invalidates the planner. The lookup context remains caller-owned.
    pub fn deinit(self: *Planner) void {
        self.* = undefined;
    }

    /// Validates `new_name`, checks for destination collisions, and returns a plan.
    pub fn plan(self: *const Planner, current: AccountSnapshot, new_name: []const u8) RenameError!RenamePlan {
        try validateCurrentNameWith(self.params, current.name);
        try validateNewNameWith(self.params, new_name);
        if (std.ascii.eqlIgnoreCase(current.name, new_name)) return error.SameName;
        if (try self.lookup.exists(new_name)) return error.AccountExists;

        const owned_old = try self.allocator.dupe(u8, current.name);
        errdefer self.allocator.free(owned_old);
        const owned_new = try self.allocator.dupe(u8, new_name);
        errdefer self.allocator.free(owned_new);

        return .{
            .allocator = self.allocator,
            .old_name = owned_old,
            .new_name = owned_new,
            .metadata = current.metadata,
        };
    }
};

/// Validates an existing account name using default limits.
pub fn validateCurrentName(name: []const u8) RenameError!void {
    return validateCurrentNameWith(.{}, name);
}

/// Validates a requested new account name using default limits.
pub fn validateNewName(name: []const u8) RenameError!void {
    return validateNewNameWith(.{}, name);
}

/// Validates an existing account name using caller-selected limits.
pub fn validateCurrentNameWith(params: Params, name: []const u8) RenameError!void {
    return validateName(params, name, .current);
}

/// Validates a requested new account name using caller-selected limits.
pub fn validateNewNameWith(params: Params, name: []const u8) RenameError!void {
    return validateName(params, name, .new);
}

const NameRole = enum {
    current,
    new,
};

fn validateName(params: Params, name: []const u8, role: NameRole) RenameError!void {
    if (name.len == 0) {
        return switch (role) {
            .current => error.InvalidCurrentName,
            .new => error.InvalidNewName,
        };
    }
    if (name.len > params.max_account_bytes) {
        return switch (role) {
            .current => error.CurrentNameTooLong,
            .new => error.NewNameTooLong,
        };
    }

    for (name) |byte| {
        if (!isAccountNameByte(byte)) {
            return switch (role) {
                .current => error.InvalidCurrentName,
                .new => error.InvalidNewName,
            };
        }
    }
}

fn isAccountNameByte(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or
        (byte >= 'A' and byte <= 'Z') or
        (byte >= '0' and byte <= '9') or
        byte == '_' or byte == '-' or byte == '.';
}

const testing = std.testing;

const MockLookup = struct {
    allocator: std.mem.Allocator,
    names: std.StringHashMap(void),

    fn init(allocator: std.mem.Allocator) MockLookup {
        return .{
            .allocator = allocator,
            .names = std.StringHashMap(void).init(allocator),
        };
    }

    fn deinit(self: *MockLookup) void {
        var it = self.names.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.names.deinit();
        self.* = undefined;
    }

    fn add(self: *MockLookup, name: []const u8) !void {
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        try self.names.putNoClobber(owned, {});
    }

    fn lookup(self: *MockLookup) AccountLookup {
        return .{ .ptr = self, .exists_fn = exists };
    }

    fn exists(ptr: *anyopaque, name: []const u8) RenameError!bool {
        const self: *MockLookup = @ptrCast(@alignCast(ptr));
        var it = self.names.iterator();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, name)) return true;
        }
        return false;
    }
};

test "plan validates destination, checks lookup, and preserves metadata" {
    // Arrange.
    var lookup = MockLookup.init(testing.allocator);
    defer lookup.deinit();
    try lookup.add("reserved");

    var planner = Planner.init(testing.allocator, .{}, lookup.lookup());
    defer planner.deinit();

    const current = AccountSnapshot{
        .name = "alice",
        .metadata = .{
            .created_ms = 100,
            .updated_ms = 200,
            .flags = 0x42,
            .verified = true,
        },
    };

    // Act.
    var plan_item = try planner.plan(current, "alice.v2");
    defer plan_item.deinit();

    // Assert.
    try testing.expectEqualStrings("alice", plan_item.old_name);
    try testing.expectEqualStrings("alice.v2", plan_item.new_name);
    try testing.expectEqual(current.metadata.created_ms, plan_item.metadata.created_ms);
    try testing.expectEqual(current.metadata.updated_ms, plan_item.metadata.updated_ms);
    try testing.expectEqual(current.metadata.flags, plan_item.metadata.flags);
    try testing.expectEqual(current.metadata.verified, plan_item.metadata.verified);
}

test "plan owns old and new names independent of input buffers" {
    // Arrange.
    var lookup = MockLookup.init(testing.allocator);
    defer lookup.deinit();

    var planner = Planner.init(testing.allocator, .{}, lookup.lookup());
    defer planner.deinit();

    var old_buf = [_]u8{ 'A', 'l', 'i', 'c', 'e' };
    var new_buf = [_]u8{ 'B', 'o', 'b' };
    const current = AccountSnapshot{ .name = old_buf[0..] };

    // Act.
    var plan_item = try planner.plan(current, new_buf[0..]);
    defer plan_item.deinit();
    old_buf[0] = 'x';
    new_buf[0] = 'y';

    // Assert.
    try testing.expectEqualStrings("Alice", plan_item.original().name);
    try testing.expectEqualStrings("Bob", plan_item.renamed().name);
}

test "existing destination is rejected case-insensitively" {
    // Arrange.
    var lookup = MockLookup.init(testing.allocator);
    defer lookup.deinit();
    try lookup.add("Target");

    var planner = Planner.init(testing.allocator, .{}, lookup.lookup());
    defer planner.deinit();

    // Act and assert.
    try testing.expectError(
        error.AccountExists,
        planner.plan(.{ .name = "source" }, "target"),
    );
}

test "same account name is rejected before lookup collision handling" {
    // Arrange.
    var lookup = MockLookup.init(testing.allocator);
    defer lookup.deinit();
    try lookup.add("alice");

    var planner = Planner.init(testing.allocator, .{}, lookup.lookup());
    defer planner.deinit();

    // Act and assert.
    try testing.expectError(
        error.SameName,
        planner.plan(.{ .name = "Alice" }, "alice"),
    );
}

test "current and new account validation report precise errors" {
    // Arrange.
    var lookup = MockLookup.init(testing.allocator);
    defer lookup.deinit();

    var planner = Planner.init(testing.allocator, .{ .max_account_bytes = 5 }, lookup.lookup());
    defer planner.deinit();

    // Act and assert.
    try testing.expectError(error.InvalidCurrentName, planner.plan(.{ .name = "" }, "bob"));
    try testing.expectError(error.InvalidCurrentName, planner.plan(.{ .name = "a b" }, "bob"));
    try testing.expectError(error.CurrentNameTooLong, planner.plan(.{ .name = "toolong" }, "bob"));
    try testing.expectError(error.InvalidNewName, planner.plan(.{ .name = "alice" }, ""));
    try testing.expectError(error.InvalidNewName, planner.plan(.{ .name = "alice" }, "a:b"));
    try testing.expectError(error.NewNameTooLong, planner.plan(.{ .name = "alice" }, "charlie"));
}

test "numeric mapping covers planner errors" {
    // Arrange.
    const invalid = RenameNumeric.fromError(error.InvalidNewName);
    const too_long = RenameNumeric.fromError(error.NewNameTooLong);
    const same = RenameNumeric.fromError(error.SameName);
    const exists = RenameNumeric.fromError(error.AccountExists);
    const oom = RenameNumeric.fromError(error.OutOfMemory);

    // Act and assert.
    try testing.expectEqual(RenameNumeric.ERR_ERRONEUSNICKNAME, invalid.?);
    try testing.expectEqual(RenameNumeric.ERR_ERRONEUSNICKNAME, too_long.?);
    try testing.expectEqual(@as(u16, 461), same.?.value());
    try testing.expectEqual(RenameNumeric.ERR_NICKNAMEINUSE, exists.?);
    try testing.expect(oom == null);
}
