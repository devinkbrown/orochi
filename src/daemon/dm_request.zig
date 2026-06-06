//! dm_request.zig — first-contact direct-message requests from strangers.
//!
//! When an unknown party tries to open a direct conversation with a user, the
//! attempt is parked here as a pending request until the recipient explicitly
//! accepts or declines it. Each recipient owns a bounded list of requests; the
//! oldest entry is evicted once the cap is reached so a hostile sender cannot
//! grow memory without limit.
//!
//! Pure-Zig, standalone: imports only `std`.

const std = @import("std");

/// Maximum pending requests held per recipient. The oldest request is dropped
/// when a new one arrives past this limit.
pub const max_per_recipient: usize = 100;

/// Maximum number of bytes retained from a request preview. Longer previews are
/// truncated on a byte boundary before storage.
pub const max_preview_len: usize = 200;

/// A single parked first-contact request awaiting a decision.
pub const Req = struct {
    /// Identity of the sender. Owned by the store.
    from: []u8,
    /// Truncated copy of the opening message. Owned by the store.
    preview: []u8,
    /// Wall-clock time the request was filed, in milliseconds.
    at_ms: i64,
};

/// Per-recipient store of pending direct-message requests.
pub const DmRequest = struct {
    allocator: std.mem.Allocator,
    /// recipient identity -> owned list of owned requests.
    table: std.StringHashMapUnmanaged(std.ArrayListUnmanaged(Req)),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .table = .{},
        };
    }

    /// Release every recipient bucket, every request, and all key strings.
    pub fn deinit(self: *Self) void {
        var it = self.table.iterator();
        while (it.next()) |entry| {
            freeBucket(self.allocator, entry.value_ptr);
            self.allocator.free(entry.key_ptr.*);
        }
        self.table.deinit(self.allocator);
        self.* = undefined;
    }

    /// File a first-contact request for `recipient` originating from `from`.
    ///
    /// `from` and `preview` are copied; the caller retains ownership of its own
    /// buffers. `preview` is truncated to `max_preview_len`. Returns the number
    /// of pending requests for the recipient after filing.
    pub fn file(
        self: *Self,
        recipient: []const u8,
        from: []const u8,
        preview: []const u8,
        now: i64,
    ) !usize {
        const bucket = try self.bucketFor(recipient);

        const from_copy = try self.allocator.dupe(u8, from);
        errdefer self.allocator.free(from_copy);

        const clipped = if (preview.len > max_preview_len)
            preview[0..max_preview_len]
        else
            preview;
        const preview_copy = try self.allocator.dupe(u8, clipped);
        errdefer self.allocator.free(preview_copy);

        // Drop the oldest request to honour the per-recipient cap.
        if (bucket.items.len >= max_per_recipient) {
            const evicted = bucket.orderedRemove(0);
            self.allocator.free(evicted.from);
            self.allocator.free(evicted.preview);
        }

        try bucket.append(self.allocator, .{
            .from = from_copy,
            .preview = preview_copy,
            .at_ms = now,
        });

        return bucket.items.len;
    }

    /// Accept the request from `from` to `recipient`, removing it from the
    /// pending list. Returns true if a matching request existed.
    pub fn accept(self: *Self, recipient: []const u8, from: []const u8) bool {
        return self.removeMatch(recipient, from);
    }

    /// Decline the request from `from` to `recipient`, removing it from the
    /// pending list. Returns true if a matching request existed.
    pub fn decline(self: *Self, recipient: []const u8, from: []const u8) bool {
        return self.removeMatch(recipient, from);
    }

    /// View the pending requests for `recipient`. The slice is valid until the
    /// next mutating call for this recipient. Empty when none are pending.
    pub fn pending(self: *Self, recipient: []const u8) []const Req {
        const bucket = self.table.getPtr(recipient) orelse return &[_]Req{};
        return bucket.items;
    }

    // --- internals ---

    fn bucketFor(self: *Self, recipient: []const u8) !*std.ArrayListUnmanaged(Req) {
        if (self.table.getPtr(recipient)) |existing| return existing;

        const key = try self.allocator.dupe(u8, recipient);
        errdefer self.allocator.free(key);

        try self.table.put(self.allocator, key, .empty);
        return self.table.getPtr(key).?;
    }

    fn removeMatch(self: *Self, recipient: []const u8, from: []const u8) bool {
        const bucket = self.table.getPtr(recipient) orelse return false;
        var i: usize = 0;
        while (i < bucket.items.len) : (i += 1) {
            if (std.mem.eql(u8, bucket.items[i].from, from)) {
                const removed = bucket.orderedRemove(i);
                self.allocator.free(removed.from);
                self.allocator.free(removed.preview);
                return true;
            }
        }
        return false;
    }

    fn freeBucket(allocator: std.mem.Allocator, bucket: *std.ArrayListUnmanaged(Req)) void {
        for (bucket.items) |req| {
            allocator.free(req.from);
            allocator.free(req.preview);
        }
        bucket.deinit(allocator);
    }
};

test "file then pending reflects stored request" {
    var store = DmRequest.init(std.testing.allocator);
    defer store.deinit();

    const count = try store.file("alice", "stranger", "hi there", 1_000);
    try std.testing.expectEqual(@as(usize, 1), count);

    const list = store.pending("alice");
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectEqualStrings("stranger", list[0].from);
    try std.testing.expectEqualStrings("hi there", list[0].preview);
    try std.testing.expectEqual(@as(i64, 1_000), list[0].at_ms);

    // Unknown recipient yields an empty view.
    try std.testing.expectEqual(@as(usize, 0), store.pending("bob").len);
}

test "accept and decline remove the matching request" {
    var store = DmRequest.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.file("alice", "carol", "ping", 1);
    _ = try store.file("alice", "dave", "yo", 2);
    try std.testing.expectEqual(@as(usize, 2), store.pending("alice").len);

    try std.testing.expect(store.accept("alice", "carol"));
    try std.testing.expectEqual(@as(usize, 1), store.pending("alice").len);
    try std.testing.expectEqualStrings("dave", store.pending("alice")[0].from);

    try std.testing.expect(store.decline("alice", "dave"));
    try std.testing.expectEqual(@as(usize, 0), store.pending("alice").len);

    // No match left, and unknown recipient.
    try std.testing.expect(!store.accept("alice", "dave"));
    try std.testing.expect(!store.decline("nobody", "dave"));
}

test "preview is truncated and cap evicts oldest" {
    var store = DmRequest.init(std.testing.allocator);
    defer store.deinit();

    const long = "x" ** (max_preview_len + 50);
    _ = try store.file("zed", "spammer", long, 7);
    try std.testing.expectEqual(max_preview_len, store.pending("zed")[0].preview.len);

    var buf: [16]u8 = undefined;
    var n: usize = 0;
    while (n < max_per_recipient + 10) : (n += 1) {
        const who = std.fmt.bufPrint(&buf, "u{d}", .{n}) catch unreachable;
        const total = try store.file("eve", who, "knock", @intCast(n));
        try std.testing.expect(total <= max_per_recipient);
    }
    try std.testing.expectEqual(max_per_recipient, store.pending("eve").len);
    // Oldest survivors were evicted; the first remaining is past index 0.
    try std.testing.expect(!std.mem.eql(u8, store.pending("eve")[0].from, "u0"));
}
