//! STS preload-list model for hostnames that are committed to TLS-only access.
//!
//! This module owns only the in-memory preload model. It does not perform
//! network I/O, command dispatch, certificate checks, or persistence.
const std = @import("std");

/// Maximum canonical DNS hostname length accepted by the preload list.
pub const MAX_HOST_LEN: usize = 255;

/// Default maximum number of preloaded hostnames in a list.
pub const DEFAULT_MAX_ENTRIES: usize = 4096;

/// Smallest accepted preload duration in seconds.
pub const MIN_DURATION_SECONDS: u64 = 1;

/// Preload-list sizing limits.
pub const Params = struct {
    /// Maximum number of hostname entries stored at once.
    max_entries: usize = DEFAULT_MAX_ENTRIES,
    /// Maximum canonical hostname bytes accepted per entry.
    max_host_bytes: usize = MAX_HOST_LEN,
};

/// Errors returned by preload-list validation and storage operations.
pub const PreloadError = std.mem.Allocator.Error || error{
    InvalidDuration,
    InvalidHost,
    HostTooLong,
    OutputTooSmall,
    PreloadFull,
    PreloadNotFound,
};

/// Activity state for a preload entry at a caller-provided time.
pub const EntryState = enum(u1) {
    active,
    expired,
};

/// Borrowed view of a preload entry.
pub const EntryView = struct {
    /// Canonical lowercase hostname without a trailing root dot.
    host: []const u8,
    /// Original committed duration in seconds.
    duration_seconds: u64,
    /// Caller-provided timestamp used when the entry was added.
    added_seconds: u64,
    /// Caller-provided timestamp after which the entry is expired.
    expires_seconds: u64,

    /// Return whether this entry is active at `now_seconds`.
    pub fn state(self: EntryView, now_seconds: u64) EntryState {
        return if (now_seconds < self.expires_seconds) .active else .expired;
    }

    /// Return the remaining active duration in seconds.
    pub fn remainingSeconds(self: EntryView, now_seconds: u64) u64 {
        if (now_seconds >= self.expires_seconds) return 0;
        return self.expires_seconds - now_seconds;
    }
};

/// A hostname preload list with owned canonical keys.
pub fn PreloadList(comptime params: Params) type {
    comptime {
        if (params.max_entries == 0) @compileError("STS preload list needs entry storage");
        if (params.max_host_bytes == 0) @compileError("STS preload hostnames need byte storage");
        if (params.max_host_bytes > MAX_HOST_LEN) @compileError("STS preload hostnames exceed DNS hostname length");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        hosts: std.StringHashMap(Entry),
        count: usize = 0,

        const Entry = struct {
            duration_seconds: u64,
            added_seconds: u64,
            expires_seconds: u64,

            fn view(self: Entry, host: []const u8) EntryView {
                return .{
                    .host = host,
                    .duration_seconds = self.duration_seconds,
                    .added_seconds = self.added_seconds,
                    .expires_seconds = self.expires_seconds,
                };
            }
        };

        /// Initialize an empty preload list.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .hosts = std.StringHashMap(Entry).init(allocator),
            };
        }

        /// Free all owned hostname keys and map storage.
        pub fn deinit(self: *Self) void {
            self.clear();
            self.hosts.deinit();
            self.* = undefined;
        }

        /// Remove every preload entry while retaining hash-map capacity.
        pub fn clear(self: *Self) void {
            var it = self.hosts.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
            }
            self.hosts.clearRetainingCapacity();
            self.count = 0;
        }

        /// Add a hostname or refresh an existing hostname with a new duration.
        pub fn add(
            self: *Self,
            host: []const u8,
            duration_seconds: u64,
            now_seconds: u64,
        ) PreloadError!void {
            var host_buf: [params.max_host_bytes]u8 = undefined;
            const normalized = try normalizeHostWith(params, host, &host_buf);
            const entry = Entry{
                .duration_seconds = duration_seconds,
                .added_seconds = now_seconds,
                .expires_seconds = try expiresAt(now_seconds, duration_seconds),
            };

            if (self.hosts.getPtr(normalized)) |existing| {
                existing.* = entry;
                return;
            }
            if (self.count >= params.max_entries) return error.PreloadFull;

            const owned_key = try self.allocator.dupe(u8, normalized);
            errdefer self.allocator.free(owned_key);
            try self.hosts.putNoClobber(owned_key, entry);
            self.count += 1;
        }

        /// Remove a hostname from the preload list.
        pub fn remove(self: *Self, host: []const u8) PreloadError!void {
            var host_buf: [params.max_host_bytes]u8 = undefined;
            const normalized = try normalizeHostWith(params, host, &host_buf);
            const removed = self.hosts.fetchRemove(normalized) orelse return error.PreloadNotFound;
            self.allocator.free(removed.key);
            self.count -= 1;
        }

        /// Return true when `host` has an active TLS-only preload entry.
        pub fn contains(self: *const Self, host: []const u8, now_seconds: u64) PreloadError!bool {
            return (try self.get(host, now_seconds)) != null;
        }

        /// Return an active borrowed entry view, or null if missing or expired.
        pub fn get(self: *const Self, host: []const u8, now_seconds: u64) PreloadError!?EntryView {
            var host_buf: [params.max_host_bytes]u8 = undefined;
            const normalized = try normalizeHostWith(params, host, &host_buf);
            const entry = self.hosts.getEntry(normalized) orelse return null;
            const view = entry.value_ptr.view(entry.key_ptr.*);
            if (view.state(now_seconds) == .expired) return null;
            return view;
        }

        /// Write active preload entries into `out` and return the written slice.
        pub fn list(self: *const Self, now_seconds: u64, out: []EntryView) PreloadError![]const EntryView {
            var index: usize = 0;
            var it = self.hosts.iterator();
            while (it.next()) |entry| {
                const view = entry.value_ptr.view(entry.key_ptr.*);
                switch (view.state(now_seconds)) {
                    .active => {
                        if (index >= out.len) return error.OutputTooSmall;
                        out[index] = view;
                        index += 1;
                    },
                    .expired => {},
                }
            }
            return out[0..index];
        }

        /// Remove all entries that are expired at `now_seconds`.
        pub fn pruneExpired(self: *Self, now_seconds: u64) void {
            var keys: [32][]const u8 = undefined;
            while (true) {
                var key_count: usize = 0;
                var it = self.hosts.iterator();
                while (it.next()) |entry| {
                    const view = entry.value_ptr.view(entry.key_ptr.*);
                    switch (view.state(now_seconds)) {
                        .active => {},
                        .expired => {
                            keys[key_count] = entry.key_ptr.*;
                            key_count += 1;
                            if (key_count == keys.len) break;
                        },
                    }
                }
                if (key_count == 0) break;

                for (keys[0..key_count]) |key| {
                    _ = self.hosts.remove(key);
                    self.allocator.free(key);
                    self.count -= 1;
                }
            }
        }

        /// Return the number of stored entries, including unpruned expired ones.
        pub fn len(self: *const Self) usize {
            return self.count;
        }
    };
}

/// Default STS preload-list type.
pub const DefaultPreloadList = PreloadList(.{});

/// Validate and lowercase a hostname into caller-provided storage.
pub fn normalizeHost(host: []const u8, out: *[MAX_HOST_LEN]u8) PreloadError![]const u8 {
    return normalizeHostWith(.{}, host, out);
}

fn normalizeHostWith(comptime params: Params, host: []const u8, out: *[params.max_host_bytes]u8) PreloadError![]const u8 {
    if (host.len == 0) return error.InvalidHost;

    const canonical_len = if (host[host.len - 1] == '.') host.len - 1 else host.len;
    if (canonical_len == 0) return error.InvalidHost;
    if (canonical_len > params.max_host_bytes) return error.HostTooLong;

    var label_len: usize = 0;
    var previous: u8 = 0;
    for (host[0..canonical_len], 0..) |byte, index| {
        const lower = std.ascii.toLower(byte);
        switch (lower) {
            'a'...'z', '0'...'9' => {
                label_len += 1;
                if (label_len > 63) return error.InvalidHost;
                out[index] = lower;
            },
            '-' => {
                if (label_len == 0) return error.InvalidHost;
                label_len += 1;
                if (label_len > 63) return error.InvalidHost;
                out[index] = lower;
            },
            '.' => {
                if (label_len == 0 or previous == '-') return error.InvalidHost;
                label_len = 0;
                out[index] = lower;
            },
            else => return error.InvalidHost,
        }
        previous = lower;
    }

    if (label_len == 0 or previous == '-') return error.InvalidHost;
    return out[0..canonical_len];
}

fn expiresAt(now_seconds: u64, duration_seconds: u64) PreloadError!u64 {
    if (duration_seconds < MIN_DURATION_SECONDS) return error.InvalidDuration;
    if (now_seconds > std.math.maxInt(u64) - duration_seconds) return error.InvalidDuration;
    return now_seconds + duration_seconds;
}

fn expectListed(host: []const u8, entries: []const EntryView) !EntryView {
    for (entries) |entry| {
        if (std.mem.eql(u8, host, entry.host)) return entry;
    }
    return error.PreloadNotFound;
}

test "add normalizes hostname and refreshes existing duration" {
    // Arrange.
    var list = DefaultPreloadList.init(std.testing.allocator);
    defer list.deinit();

    // Act.
    try list.add("IRC.Example.NET.", 60, 100);
    try list.add("irc.example.net", 120, 130);
    const entry = (try list.get("IRC.EXAMPLE.NET", 131)).?;

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("irc.example.net", entry.host);
    try std.testing.expectEqual(@as(u64, 120), entry.duration_seconds);
    try std.testing.expectEqual(@as(u64, 130), entry.added_seconds);
    try std.testing.expectEqual(@as(u64, 250), entry.expires_seconds);
    try std.testing.expectEqual(@as(u64, 119), entry.remainingSeconds(131));
}

test "contains treats expired entries as inactive until pruned" {
    // Arrange.
    var list = DefaultPreloadList.init(std.testing.allocator);
    defer list.deinit();

    // Act.
    try list.add("secure.example", 10, 20);

    // Assert.
    try std.testing.expect(try list.contains("SECURE.EXAMPLE", 29));
    try std.testing.expect(!try list.contains("secure.example", 30));
    try std.testing.expectEqual(@as(usize, 1), list.len());

    // Act.
    list.pruneExpired(30);

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "remove deletes owned key and reports missing host" {
    // Arrange.
    var list = DefaultPreloadList.init(std.testing.allocator);
    defer list.deinit();
    try list.add("remove.example", 300, 1);

    // Act.
    try list.remove("REMOVE.EXAMPLE.");

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), list.len());
    try std.testing.expect(!try list.contains("remove.example", 2));
    try std.testing.expectError(error.PreloadNotFound, list.remove("remove.example"));
}

test "list returns active borrowed entries with durations" {
    // Arrange.
    var list = DefaultPreloadList.init(std.testing.allocator);
    defer list.deinit();
    try list.add("a.example", 50, 100);
    try list.add("b.example", 10, 100);
    try list.add("c.example", 70, 100);

    // Act.
    var out: [2]EntryView = undefined;
    const entries = try list.list(120, &out);

    // Assert.
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    const a = try expectListed("a.example", entries);
    const c = try expectListed("c.example", entries);
    try std.testing.expectEqual(@as(u64, 30), a.remainingSeconds(120));
    try std.testing.expectEqual(@as(u64, 50), c.remainingSeconds(120));
    try std.testing.expectError(error.OutputTooSmall, list.list(99, &out));
}

test "validation rejects malformed hostnames and durations" {
    // Arrange.
    var list = DefaultPreloadList.init(std.testing.allocator);
    defer list.deinit();
    var host_buf: [MAX_HOST_LEN]u8 = undefined;

    // Act and assert.
    try std.testing.expectError(error.InvalidHost, list.add("", 60, 0));
    try std.testing.expectError(error.InvalidHost, list.add(".example", 60, 0));
    try std.testing.expectError(error.InvalidHost, list.add("bad..example", 60, 0));
    try std.testing.expectError(error.InvalidHost, list.add("-bad.example", 60, 0));
    try std.testing.expectError(error.InvalidHost, list.add("bad-.example", 60, 0));
    try std.testing.expectError(error.InvalidHost, list.add("bad_example", 60, 0));
    try std.testing.expectError(error.InvalidDuration, list.add("valid.example", 0, 0));
    try std.testing.expectError(error.InvalidDuration, list.add("valid.example", 1, std.math.maxInt(u64)));

    const normalized = try normalizeHost("MiXeD.Example.", &host_buf);
    try std.testing.expectEqualStrings("mixed.example", normalized);
}

test "capacity limit applies only to new canonical hosts" {
    // Arrange.
    const SmallList = PreloadList(.{ .max_entries = 1, .max_host_bytes = MAX_HOST_LEN });
    var list = SmallList.init(std.testing.allocator);
    defer list.deinit();

    // Act.
    try list.add("one.example", 60, 0);
    try list.add("ONE.EXAMPLE", 120, 1);

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectError(error.PreloadFull, list.add("two.example", 60, 0));
}

test "clear releases all entries and permits reuse" {
    // Arrange.
    var list = DefaultPreloadList.init(std.testing.allocator);
    defer list.deinit();
    try list.add("one.example", 60, 0);
    try list.add("two.example", 60, 0);

    // Act.
    list.clear();
    try list.add("three.example", 90, 10);

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expect(try list.contains("three.example", 11));
    try std.testing.expect(!try list.contains("one.example", 11));
}
