//! Per-(account, channel) mention-mute registry for the Mizuchi IRC daemon.
//!
//! A `MentionMute` records which (account, channel) pairs have suppressed
//! mention notifications. Each pair is stored as a single composite key of the
//! form `account ++ "\x00" ++ channel` in a presence set. The NUL separator is
//! never valid inside an account name or channel name, so the encoding is
//! unambiguous.

const std = @import("std");

/// Byte that separates the account part from the channel part inside a
/// composite key. NUL is forbidden in IRC names, so it cannot collide.
const key_separator: u8 = 0;

pub const MentionMute = struct {
    allocator: std.mem.Allocator,
    /// Presence set: key = owned composite key, value = void.
    set: std.StringHashMapUnmanaged(void),

    pub fn init(allocator: std.mem.Allocator) MentionMute {
        return .{
            .allocator = allocator,
            .set = .{},
        };
    }

    /// Release every owned key and the backing table.
    pub fn deinit(self: *MentionMute) void {
        var it = self.set.keyIterator();
        while (it.next()) |key_ptr| {
            self.allocator.free(key_ptr.*);
        }
        self.set.deinit(self.allocator);
        self.* = undefined;
    }

    /// Allocate a composite key `account ++ NUL ++ channel`. Caller owns it.
    fn makeKey(self: *MentionMute, account: []const u8, channel: []const u8) ![]u8 {
        const total = account.len + 1 + channel.len;
        const buf = try self.allocator.alloc(u8, total);
        @memcpy(buf[0..account.len], account);
        buf[account.len] = key_separator;
        @memcpy(buf[account.len + 1 ..], channel);
        return buf;
    }

    /// Mark (account, channel) as muted. Idempotent: muting an already-muted
    /// pair leaves the set unchanged and frees the temporary key.
    pub fn mute(self: *MentionMute, account: []const u8, channel: []const u8) !void {
        const key = try self.makeKey(account, channel);
        errdefer self.allocator.free(key);

        const gop = try self.set.getOrPut(self.allocator, key);
        if (gop.found_existing) {
            // Already present; the existing owned key stays, drop this one.
            self.allocator.free(key);
            return;
        }
        gop.value_ptr.* = {};
    }

    /// Remove the mute for (account, channel). Returns true if a mute was
    /// actually removed, false if the pair was not muted.
    pub fn unmute(self: *MentionMute, account: []const u8, channel: []const u8) bool {
        const probe = self.makeKey(account, channel) catch return false;
        defer self.allocator.free(probe);

        if (self.set.fetchRemove(probe)) |removed| {
            self.allocator.free(removed.key);
            return true;
        }
        return false;
    }

    /// Report whether (account, channel) is currently muted.
    pub fn isMuted(self: *MentionMute, account: []const u8, channel: []const u8) bool {
        const probe = self.makeKey(account, channel) catch return false;
        defer self.allocator.free(probe);
        return self.set.contains(probe);
    }

    /// Remove every mute belonging to `account` across all channels. Returns
    /// the number of mutes removed.
    pub fn clearAccount(self: *MentionMute, account: []const u8) usize {
        // Collect matching keys first; mutating the map while iterating its
        // own key storage is unsafe.
        var doomed: std.ArrayListUnmanaged([]const u8) = .empty;
        defer doomed.deinit(self.allocator);

        var it = self.set.keyIterator();
        while (it.next()) |key_ptr| {
            const key = key_ptr.*;
            if (keyMatchesAccount(key, account)) {
                doomed.append(self.allocator, key) catch {
                    // Out of memory while collecting; remove what we can below.
                    break;
                };
            }
        }

        var removed_count: usize = 0;
        for (doomed.items) |key| {
            if (self.set.fetchRemove(key)) |removed| {
                self.allocator.free(removed.key);
                removed_count += 1;
            }
        }
        return removed_count;
    }
};

/// True when `key` has the form `account ++ NUL ++ <anything>`.
fn keyMatchesAccount(key: []const u8, account: []const u8) bool {
    if (key.len <= account.len) return false;
    if (key[account.len] != key_separator) return false;
    return std.mem.eql(u8, key[0..account.len], account);
}

test "mute then isMuted reports muted only for that pair" {
    var mm = MentionMute.init(std.testing.allocator);
    defer mm.deinit();

    try mm.mute("alice", "#zig");

    try std.testing.expect(mm.isMuted("alice", "#zig"));
    try std.testing.expect(!mm.isMuted("alice", "#rust"));
    try std.testing.expect(!mm.isMuted("bob", "#zig"));
}

test "mute is idempotent and does not leak duplicate keys" {
    var mm = MentionMute.init(std.testing.allocator);
    defer mm.deinit();

    try mm.mute("carol", "#general");
    try mm.mute("carol", "#general");
    try mm.mute("carol", "#general");

    try std.testing.expectEqual(@as(usize, 1), mm.set.count());
    try std.testing.expect(mm.isMuted("carol", "#general"));
}

test "unmute removes only the targeted pair and reports correctly" {
    var mm = MentionMute.init(std.testing.allocator);
    defer mm.deinit();

    try mm.mute("dave", "#a");
    try mm.mute("dave", "#b");

    try std.testing.expect(mm.unmute("dave", "#a"));
    try std.testing.expect(!mm.isMuted("dave", "#a"));
    try std.testing.expect(mm.isMuted("dave", "#b"));

    // Unmuting something not present returns false.
    try std.testing.expect(!mm.unmute("dave", "#a"));
    try std.testing.expect(!mm.unmute("nobody", "#x"));
}

test "clearAccount removes all of an account's mutes and counts them" {
    var mm = MentionMute.init(std.testing.allocator);
    defer mm.deinit();

    try mm.mute("erin", "#one");
    try mm.mute("erin", "#two");
    try mm.mute("erin", "#three");
    try mm.mute("frank", "#one");

    const cleared = mm.clearAccount("erin");
    try std.testing.expectEqual(@as(usize, 3), cleared);

    try std.testing.expect(!mm.isMuted("erin", "#one"));
    try std.testing.expect(!mm.isMuted("erin", "#two"));
    try std.testing.expect(!mm.isMuted("erin", "#three"));
    // Frank, who shares a channel name, is untouched.
    try std.testing.expect(mm.isMuted("frank", "#one"));

    // Clearing again finds nothing.
    try std.testing.expectEqual(@as(usize, 0), mm.clearAccount("erin"));
}

test "account prefix collision does not over-match in clearAccount" {
    var mm = MentionMute.init(std.testing.allocator);
    defer mm.deinit();

    // "al" is a prefix of "alice"; the NUL separator must prevent a match.
    try mm.mute("al", "#x");
    try mm.mute("alice", "#x");

    const cleared = mm.clearAccount("al");
    try std.testing.expectEqual(@as(usize, 1), cleared);
    try std.testing.expect(!mm.isMuted("al", "#x"));
    try std.testing.expect(mm.isMuted("alice", "#x"));
}
