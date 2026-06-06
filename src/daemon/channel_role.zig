//! ChannelRole — custom per-(channel, member) role labels for the Mizuchi daemon.
//!
//! Each (channel, member) pair maps to an owned label string of at most
//! `max_label_len` bytes. Keys are encoded as "channel\x00member" so that
//! all entries belonging to a single channel share the byte prefix
//! "channel\x00", enabling fast channel-wide clearing.

const std = @import("std");

/// Separator byte joining a channel and member into a composite key.
/// NUL never appears in a valid channel or member name, so it is an
/// unambiguous delimiter.
const key_sep: u8 = 0x00;

/// Maximum permitted label length, in bytes.
pub const max_label_len: usize = 32;

/// Error set surfaced by mutating operations.
pub const RoleError = error{
    /// The supplied label exceeds `max_label_len`.
    LabelTooLong,
} || std.mem.Allocator.Error;

pub const ChannelRole = struct {
    allocator: std.mem.Allocator,
    table: std.StringHashMapUnmanaged([]u8),

    const Self = @This();

    /// Create an empty role table backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .table = .empty,
        };
    }

    /// Release every owned key and value, then the table itself.
    pub fn deinit(self: *Self) void {
        var it = self.table.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.table.deinit(self.allocator);
        self.* = undefined;
    }

    /// Build the composite "channel\x00member" key into a freshly allocated buffer.
    fn makeKey(self: *Self, channel: []const u8, member: []const u8) ![]u8 {
        const buf = try self.allocator.alloc(u8, channel.len + 1 + member.len);
        @memcpy(buf[0..channel.len], channel);
        buf[channel.len] = key_sep;
        @memcpy(buf[channel.len + 1 ..], member);
        return buf;
    }

    /// Assign `label` to (channel, member), overwriting any prior label.
    /// The label is duplicated; the caller retains ownership of its slices.
    pub fn setRole(
        self: *Self,
        channel: []const u8,
        member: []const u8,
        label: []const u8,
    ) RoleError!void {
        if (label.len > max_label_len) return RoleError.LabelTooLong;

        const key = try self.makeKey(channel, member);
        errdefer self.allocator.free(key);

        const value = try self.allocator.dupe(u8, label);
        errdefer self.allocator.free(value);

        const gop = try self.table.getOrPut(self.allocator, key);
        if (gop.found_existing) {
            // Existing entry already owns an equivalent key; drop the new one
            // and replace the stale value in place.
            self.allocator.free(key);
            self.allocator.free(gop.value_ptr.*);
            gop.value_ptr.* = value;
        } else {
            gop.value_ptr.* = value;
        }
    }

    /// Return the label for (channel, member), or null if none is set.
    /// The returned slice is owned by the table and valid until mutated.
    pub fn getRole(self: *Self, channel: []const u8, member: []const u8) ?[]const u8 {
        var stack_buf: [256]u8 = undefined;
        const needed = channel.len + 1 + member.len;

        if (needed <= stack_buf.len) {
            @memcpy(stack_buf[0..channel.len], channel);
            stack_buf[channel.len] = key_sep;
            @memcpy(stack_buf[channel.len + 1 .. needed], member);
            return self.table.get(stack_buf[0..needed]);
        }

        // Oversized key: fall back to a heap probe key.
        const key = self.makeKey(channel, member) catch return null;
        defer self.allocator.free(key);
        return self.table.get(key);
    }

    /// Remove the entry for (channel, member). Returns true if one existed.
    pub fn clearMember(self: *Self, channel: []const u8, member: []const u8) bool {
        var stack_buf: [256]u8 = undefined;
        const needed = channel.len + 1 + member.len;

        const probe: []const u8 = blk: {
            if (needed <= stack_buf.len) {
                @memcpy(stack_buf[0..channel.len], channel);
                stack_buf[channel.len] = key_sep;
                @memcpy(stack_buf[channel.len + 1 .. needed], member);
                break :blk stack_buf[0..needed];
            }
            break :blk self.makeKey(channel, member) catch return false;
        };
        const heap_probe = needed > stack_buf.len;
        defer if (heap_probe) self.allocator.free(probe);

        if (self.table.fetchRemove(probe)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }

    /// Remove every entry belonging to `channel`. Returns the count removed.
    pub fn clearChannel(self: *Self, channel: []const u8) usize {
        // Compose the "channel\x00" prefix on the stack when it fits.
        var stack_buf: [256]u8 = undefined;
        const prefix_len = channel.len + 1;

        var heap_prefix: ?[]u8 = null;
        defer if (heap_prefix) |p| self.allocator.free(p);

        const prefix: []const u8 = blk: {
            if (prefix_len <= stack_buf.len) {
                @memcpy(stack_buf[0..channel.len], channel);
                stack_buf[channel.len] = key_sep;
                break :blk stack_buf[0..prefix_len];
            }
            const p = self.allocator.alloc(u8, prefix_len) catch return 0;
            @memcpy(p[0..channel.len], channel);
            p[channel.len] = key_sep;
            heap_prefix = p;
            break :blk p;
        };

        var removed: usize = 0;
        var it = self.table.iterator();
        while (it.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, prefix)) {
                const key = entry.key_ptr.*;
                const value = entry.value_ptr.*;
                // removeByPtr keeps the iterator valid for continued traversal.
                self.table.removeByPtr(entry.key_ptr);
                self.allocator.free(key);
                self.allocator.free(value);
                removed += 1;
            }
        }
        return removed;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "set, get, and overwrite a role label" {
    const allocator = std.testing.allocator;
    var roles = ChannelRole.init(allocator);
    defer roles.deinit();

    try std.testing.expect(roles.getRole("#dragon", "kai") == null);

    try roles.setRole("#dragon", "kai", "navigator");
    try std.testing.expectEqualStrings("navigator", roles.getRole("#dragon", "kai").?);

    // Overwrite replaces the value without leaking the old one.
    try roles.setRole("#dragon", "kai", "captain");
    try std.testing.expectEqualStrings("captain", roles.getRole("#dragon", "kai").?);

    // A label of exactly max_label_len is accepted; one byte longer is rejected.
    const ok_label = "x" ** max_label_len;
    try roles.setRole("#dragon", "kai", ok_label);
    try std.testing.expectEqualStrings(ok_label, roles.getRole("#dragon", "kai").?);

    const long_label = "x" ** (max_label_len + 1);
    try std.testing.expectError(RoleError.LabelTooLong, roles.setRole("#dragon", "kai", long_label));
}

test "clearMember removes one entry and reports presence" {
    const allocator = std.testing.allocator;
    var roles = ChannelRole.init(allocator);
    defer roles.deinit();

    try roles.setRole("#river", "mizu", "guide");
    try roles.setRole("#river", "tsuchi", "scout");

    try std.testing.expect(roles.clearMember("#river", "mizu"));
    try std.testing.expect(roles.getRole("#river", "mizu") == null);

    // The sibling entry is untouched.
    try std.testing.expectEqualStrings("scout", roles.getRole("#river", "tsuchi").?);

    // Clearing an absent member returns false.
    try std.testing.expect(!roles.clearMember("#river", "mizu"));
    try std.testing.expect(!roles.clearMember("#nowhere", "ghost"));
}

test "clearChannel removes only the target channel's entries" {
    const allocator = std.testing.allocator;
    var roles = ChannelRole.init(allocator);
    defer roles.deinit();

    try roles.setRole("#alpha", "one", "a1");
    try roles.setRole("#alpha", "two", "a2");
    try roles.setRole("#alpha", "three", "a3");
    try roles.setRole("#beta", "one", "b1");
    try roles.setRole("#beta", "two", "b2");

    // A channel whose name is a prefix of another must not match falsely:
    // "#alpha\x00" should not match a key like "#alphaX\x00...".
    try roles.setRole("#alphaX", "one", "ax1");

    const removed = roles.clearChannel("#alpha");
    try std.testing.expectEqual(@as(usize, 3), removed);

    try std.testing.expect(roles.getRole("#alpha", "one") == null);
    try std.testing.expect(roles.getRole("#alpha", "two") == null);
    try std.testing.expect(roles.getRole("#alpha", "three") == null);

    // Other channels are fully preserved.
    try std.testing.expectEqualStrings("b1", roles.getRole("#beta", "one").?);
    try std.testing.expectEqualStrings("b2", roles.getRole("#beta", "two").?);
    try std.testing.expectEqualStrings("ax1", roles.getRole("#alphaX", "one").?);

    // Clearing an empty/absent channel returns 0.
    try std.testing.expectEqual(@as(usize, 0), roles.clearChannel("#missing"));
}
