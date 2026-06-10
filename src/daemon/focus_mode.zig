//! Focus Mode for the Orochi IRC daemon.
//!
//! Each account can toggle a personal "focus" state. While focused, the
//! account's client is expected to suppress message notifications, except
//! for messages originating from accounts on a per-account allowlist.
//!
//! Storage model:
//!   account name -> FocusState { on, allow: set of account names }
//!
//! The allowlist is a string set (StringHashMap with void values). All keys
//! (account names and allowlist entries) are owned copies, duplicated on
//! insertion and freed on removal / deinit. Pure std only; 64-bit clean.

const std = @import("std");

/// Per-account focus state: whether focus is engaged plus the set of
/// account names allowed to break through while focused.
const FocusState = struct {
    on: bool,
    allow: std.StringHashMap(void),

    fn init(allocator: std.mem.Allocator) FocusState {
        return .{ .on = false, .allow = std.StringHashMap(void).init(allocator) };
    }

    /// Free every owned key in the allowlist, then the set itself.
    fn deinit(self: *FocusState) void {
        var it = self.allow.iterator();
        while (it.next()) |entry| {
            self.allow.allocator.free(entry.key_ptr.*);
        }
        self.allow.deinit();
    }
};

/// Tracks focus toggles and allowlists across accounts.
pub const FocusMode = struct {
    allocator: std.mem.Allocator,
    states: std.StringHashMap(FocusState),

    pub fn init(allocator: std.mem.Allocator) FocusMode {
        return .{
            .allocator = allocator,
            .states = std.StringHashMap(FocusState).init(allocator),
        };
    }

    /// Release all owned account keys, allowlist entries, and the maps.
    pub fn deinit(self: *FocusMode) void {
        var it = self.states.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        self.states.deinit();
    }

    /// Look up (or lazily create) the state record for an account. The
    /// returned pointer is owned by the map; the account key is duplicated
    /// only when a new record is created.
    fn ensure(self: *FocusMode, account: []const u8) !*FocusState {
        const gop = try self.states.getOrPut(account);
        if (!gop.found_existing) {
            const key_copy = self.allocator.dupe(u8, account) catch |err| {
                // Roll back the tentative slot so we never leave a dangling
                // key pointing at caller-owned memory.
                _ = self.states.remove(account);
                return err;
            };
            gop.key_ptr.* = key_copy;
            gop.value_ptr.* = FocusState.init(self.allocator);
        }
        return gop.value_ptr;
    }

    /// Engage focus for an account (creating its record if needed).
    pub fn enable(self: *FocusMode, account: []const u8) !void {
        const state = try self.ensure(account);
        state.on = true;
    }

    /// Disengage focus for an account. Returns true if the account had a
    /// record and was previously focused; false otherwise. The record and
    /// its allowlist are retained so allow entries survive a toggle.
    pub fn disable(self: *FocusMode, account: []const u8) bool {
        const state = self.states.getPtr(account) orelse return false;
        const was_on = state.on;
        state.on = false;
        return was_on;
    }

    /// Report whether focus is currently engaged for an account.
    pub fn isOn(self: *FocusMode, account: []const u8) bool {
        const state = self.states.getPtr(account) orelse return false;
        return state.on;
    }

    /// Add `who` to `account`'s breakthrough allowlist. Returns true if a
    /// new entry was added, false if it was already present.
    pub fn allow(self: *FocusMode, account: []const u8, who: []const u8) !bool {
        const state = try self.ensure(account);
        if (state.allow.contains(who)) return false;
        const who_copy = try self.allocator.dupe(u8, who);
        errdefer self.allocator.free(who_copy);
        try state.allow.put(who_copy, {});
        return true;
    }

    /// Report whether `who` is on `account`'s breakthrough allowlist.
    pub fn allows(self: *FocusMode, account: []const u8, who: []const u8) bool {
        const state = self.states.getPtr(account) orelse return false;
        return state.allow.contains(who);
    }

    /// Drop an account's entire record (focus flag + allowlist), freeing all
    /// owned memory. Returns true if a record existed and was removed.
    pub fn clear(self: *FocusMode, account: []const u8) bool {
        const entry = self.states.fetchRemove(account) orelse return false;
        self.allocator.free(entry.key);
        var value = entry.value;
        value.deinit();
        return true;
    }
};

test "enable / disable / isOn toggling" {
    var fm = FocusMode.init(std.testing.allocator);
    defer fm.deinit();

    try std.testing.expect(!fm.isOn("kappa"));
    try std.testing.expect(!fm.disable("kappa")); // no record yet

    try fm.enable("kappa");
    try std.testing.expect(fm.isOn("kappa"));

    try std.testing.expect(fm.disable("kappa")); // was on
    try std.testing.expect(!fm.isOn("kappa"));
    try std.testing.expect(!fm.disable("kappa")); // already off
}

test "allow / allows allowlist semantics" {
    var fm = FocusMode.init(std.testing.allocator);
    defer fm.deinit();

    try std.testing.expect(!fm.allows("kappa", "tengu"));

    try std.testing.expect(try fm.allow("kappa", "tengu")); // newly added
    try std.testing.expect(fm.allows("kappa", "tengu"));
    try std.testing.expect(!try fm.allow("kappa", "tengu")); // duplicate

    try std.testing.expect(try fm.allow("kappa", "oni"));
    try std.testing.expect(fm.allows("kappa", "oni"));
    try std.testing.expect(!fm.allows("kappa", "yuki")); // never added
}

test "clear removes record and frees allowlist" {
    var fm = FocusMode.init(std.testing.allocator);
    defer fm.deinit();

    try fm.enable("kappa");
    _ = try fm.allow("kappa", "tengu");
    _ = try fm.allow("kappa", "oni");

    try std.testing.expect(fm.clear("kappa")); // removed
    try std.testing.expect(!fm.clear("kappa")); // gone now

    try std.testing.expect(!fm.isOn("kappa"));
    try std.testing.expect(!fm.allows("kappa", "tengu"));
}

test "focus state and allowlist are independent across accounts" {
    var fm = FocusMode.init(std.testing.allocator);
    defer fm.deinit();

    try fm.enable("kappa");
    _ = try fm.allow("kappa", "tengu");

    // Second account untouched by first.
    try std.testing.expect(!fm.isOn("oni"));
    try std.testing.expect(!fm.allows("oni", "tengu"));

    // Allow survives a disable toggle on the same account.
    try std.testing.expect(fm.disable("kappa"));
    try std.testing.expect(fm.allows("kappa", "tengu"));

    // 64-bit sanity: usize is 8 bytes on the target.
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(usize));
}
