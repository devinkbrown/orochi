//! Per-channel idle auto-kick policy evaluation.
const std = @import("std");

/// Tunable limits for channel threshold storage and evaluation inputs.
pub const Params = struct {
    /// Maximum number of channels that may have an idle threshold configured.
    max_channels: usize = 4096,
    /// Maximum channel name length accepted by the policy.
    max_channel_len: usize = 128,
    /// Maximum member identifier length accepted in evaluation snapshots.
    max_member_len: usize = 128,
};

/// Errors returned by idle-kick configuration and evaluation methods.
pub const Error = std.mem.Allocator.Error || error{
    EmptyChannel,
    ChannelTooLong,
    EmptyMember,
    MemberTooLong,
    ZeroThreshold,
    TooManyChannels,
    OutputTooSmall,
};

/// Channel privilege level relevant to idle-kick exemptions.
pub const Role = enum(u2) {
    /// Ordinary channel member.
    member,
    /// Voiced member; voice does not exempt from idle kicks.
    voiced,
    /// Channel operator; operators are exempt from idle kicks.
    operator,

    /// Return whether this role is protected from idle auto-kicks.
    pub fn isExempt(self: Role) bool {
        return switch (self) {
            .member => false,
            .voiced => false,
            .operator => true,
        };
    }
};

/// Injected member activity snapshot for one channel evaluation.
pub const MemberActivity = struct {
    /// Stable member identifier to return in kick candidates.
    member: []const u8,
    /// Last activity timestamp in milliseconds.
    last_activity_ms: i64,
    /// Channel privilege used for exemption checks.
    role: Role = .member,
};

/// Candidate selected for idle auto-kick.
pub const KickCandidate = struct {
    /// Stable member identifier from the injected snapshot.
    member: []const u8,
    /// Computed idle duration in milliseconds, saturated at `maxInt(u64)`.
    idle_ms: u64,
    /// Original last activity timestamp from the injected snapshot.
    last_activity_ms: i64,
};

/// Per-channel idle auto-kick threshold store and evaluator.
pub const IdleKick = struct {
    allocator: std.mem.Allocator,
    params: Params,
    thresholds: std.StringHashMap(u64),

    /// Initialize an idle-kick policy with default limits.
    pub fn init(allocator: std.mem.Allocator) IdleKick {
        return initWithParams(allocator, .{});
    }

    /// Initialize an idle-kick policy with caller-provided limits.
    pub fn initWithParams(allocator: std.mem.Allocator, params: Params) IdleKick {
        std.debug.assert(params.max_channels > 0);
        std.debug.assert(params.max_channel_len > 0);
        std.debug.assert(params.max_member_len > 0);
        return .{
            .allocator = allocator,
            .params = params,
            .thresholds = std.StringHashMap(u64).init(allocator),
        };
    }

    /// Free all threshold storage owned by the policy.
    pub fn deinit(self: *IdleKick) void {
        self.clear();
        self.thresholds.deinit();
        self.* = undefined;
    }

    /// Remove every configured channel threshold while retaining map capacity.
    pub fn clear(self: *IdleKick) void {
        var it = self.thresholds.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.thresholds.clearRetainingCapacity();
    }

    /// Configure `channel` to kick non-exempt members idle for at least `threshold_ms`.
    pub fn setThreshold(self: *IdleKick, channel: []const u8, threshold_ms: u64) Error!bool {
        try self.validateChannel(channel);
        if (threshold_ms == 0) return error.ZeroThreshold;

        if (self.thresholds.getPtr(channel)) |existing| {
            existing.* = threshold_ms;
            return false;
        }
        if (self.thresholds.count() >= self.params.max_channels) return error.TooManyChannels;

        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);
        try self.thresholds.putNoClobber(owned_channel, threshold_ms);
        return true;
    }

    /// Remove `channel`'s configured threshold and return whether it existed.
    pub fn clearThreshold(self: *IdleKick, channel: []const u8) bool {
        const removed = self.thresholds.fetchRemove(channel) orelse return false;
        self.allocator.free(removed.key);
        return true;
    }

    /// Return the configured threshold for `channel`, if present.
    pub fn thresholdFor(self: *const IdleKick, channel: []const u8) ?u64 {
        return self.thresholds.get(channel);
    }

    /// Return the number of channels with configured thresholds.
    pub fn channelCount(self: *const IdleKick) usize {
        return self.thresholds.count();
    }

    /// Evaluate injected member activity and write idle kick candidates into `out`.
    ///
    /// Candidates are ordered by descending idle duration. Members with equal
    /// idle duration keep their input order. Channels without a threshold return
    /// an empty result.
    pub fn candidates(
        self: *const IdleKick,
        channel: []const u8,
        now_ms: i64,
        members: []const MemberActivity,
        out: []KickCandidate,
    ) Error![]const KickCandidate {
        try self.validateChannel(channel);
        const threshold_ms = self.thresholds.get(channel) orelse return out[0..0];

        var count: usize = 0;
        for (members) |member| {
            try self.validateMember(member.member);
            if (member.role.isExempt()) continue;

            const idle_ms = idleDurationMs(member.last_activity_ms, now_ms);
            if (idle_ms < threshold_ms) continue;
            if (count >= out.len) return error.OutputTooSmall;

            const candidate = KickCandidate{
                .member = member.member,
                .idle_ms = idle_ms,
                .last_activity_ms = member.last_activity_ms,
            };
            insertCandidate(out, count, candidate);
            count += 1;
        }
        return out[0..count];
    }

    /// Return true when `member` would be selected on `channel` at `now_ms`.
    pub fn shouldKick(self: *const IdleKick, channel: []const u8, now_ms: i64, member: MemberActivity) Error!bool {
        var one: [1]KickCandidate = undefined;
        const found = try self.candidates(channel, now_ms, &.{member}, &one);
        return found.len == 1;
    }

    fn validateChannel(self: *const IdleKick, channel: []const u8) Error!void {
        if (channel.len == 0) return error.EmptyChannel;
        if (channel.len > self.params.max_channel_len) return error.ChannelTooLong;
    }

    fn validateMember(self: *const IdleKick, member: []const u8) Error!void {
        if (member.len == 0) return error.EmptyMember;
        if (member.len > self.params.max_member_len) return error.MemberTooLong;
    }
};

/// Compute non-negative idle duration in milliseconds with saturation.
pub fn idleDurationMs(last_activity_ms: i64, now_ms: i64) u64 {
    const delta = @as(i128, now_ms) - @as(i128, last_activity_ms);
    if (delta <= 0) return 0;
    if (delta > std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(delta);
}

fn insertCandidate(out: []KickCandidate, count: usize, candidate: KickCandidate) void {
    var index = count;
    while (index > 0 and candidate.idle_ms > out[index - 1].idle_ms) : (index -= 1) {
        out[index] = out[index - 1];
    }
    out[index] = candidate;
}

const testing = std.testing;

test "configured threshold selects only members idle at or beyond the limit" {
    // Arrange.
    var policy = IdleKick.init(testing.allocator);
    defer policy.deinit();
    try testing.expect(try policy.setThreshold("#main", 60_000));

    const members = [_]MemberActivity{
        .{ .member = "recent", .last_activity_ms = 95_000 },
        .{ .member = "exact", .last_activity_ms = 40_000 },
        .{ .member = "stale", .last_activity_ms = 1_000 },
    };
    var out: [4]KickCandidate = undefined;

    // Act.
    const selected = try policy.candidates("#main", 100_000, &members, &out);

    // Assert.
    try testing.expectEqual(@as(usize, 2), selected.len);
    try testing.expectEqualStrings("stale", selected[0].member);
    try testing.expectEqual(@as(u64, 99_000), selected[0].idle_ms);
    try testing.expectEqualStrings("exact", selected[1].member);
    try testing.expectEqual(@as(u64, 60_000), selected[1].idle_ms);
}

test "operator members are exempt while voiced members remain eligible" {
    // Arrange.
    var policy = IdleKick.init(testing.allocator);
    defer policy.deinit();
    _ = try policy.setThreshold("#ops", 10_000);

    const members = [_]MemberActivity{
        .{ .member = "oper", .last_activity_ms = 0, .role = .operator },
        .{ .member = "voice", .last_activity_ms = 1_000, .role = .voiced },
        .{ .member = "plain", .last_activity_ms = 2_000, .role = .member },
    };
    var out: [3]KickCandidate = undefined;

    // Act.
    const selected = try policy.candidates("#ops", 20_000, &members, &out);

    // Assert.
    try testing.expectEqual(@as(usize, 2), selected.len);
    try testing.expectEqualStrings("voice", selected[0].member);
    try testing.expectEqualStrings("plain", selected[1].member);
}

test "kick candidates are ordered by longest idle with stable ties" {
    // Arrange.
    var policy = IdleKick.init(testing.allocator);
    defer policy.deinit();
    _ = try policy.setThreshold("#sort", 100);

    const members = [_]MemberActivity{
        .{ .member = "middle", .last_activity_ms = 600 },
        .{ .member = "oldest", .last_activity_ms = 100 },
        .{ .member = "tie-a", .last_activity_ms = 200 },
        .{ .member = "fresh", .last_activity_ms = 950 },
        .{ .member = "tie-b", .last_activity_ms = 200 },
    };
    var out: [5]KickCandidate = undefined;

    // Act.
    const selected = try policy.candidates("#sort", 1_000, &members, &out);

    // Assert.
    try testing.expectEqual(@as(usize, 4), selected.len);
    try testing.expectEqualStrings("oldest", selected[0].member);
    try testing.expectEqualStrings("tie-a", selected[1].member);
    try testing.expectEqualStrings("tie-b", selected[2].member);
    try testing.expectEqualStrings("middle", selected[3].member);
}

test "channels without thresholds produce no kick candidates" {
    // Arrange.
    var policy = IdleKick.init(testing.allocator);
    defer policy.deinit();

    const members = [_]MemberActivity{
        .{ .member = "idle", .last_activity_ms = 0 },
    };
    var out: [1]KickCandidate = undefined;

    // Act.
    const selected = try policy.candidates("#unset", 1_000_000, &members, &out);

    // Assert.
    try testing.expectEqual(@as(usize, 0), selected.len);
}

test "threshold updates clear cleanly and enforce configured limits" {
    // Arrange.
    var policy = IdleKick.initWithParams(testing.allocator, .{
        .max_channels = 1,
        .max_channel_len = 5,
        .max_member_len = 4,
    });
    defer policy.deinit();

    // Act / Assert.
    try testing.expectError(error.EmptyChannel, policy.setThreshold("", 1));
    try testing.expectError(error.ChannelTooLong, policy.setThreshold("#wider", 1));
    try testing.expectError(error.ZeroThreshold, policy.setThreshold("#one", 0));
    try testing.expect(try policy.setThreshold("#one", 10));
    try testing.expect(!try policy.setThreshold("#one", 20));
    try testing.expectEqual(@as(?u64, 20), policy.thresholdFor("#one"));
    try testing.expectError(error.TooManyChannels, policy.setThreshold("#two", 10));
    try testing.expect(policy.clearThreshold("#one"));
    try testing.expect(!policy.clearThreshold("#one"));
    try testing.expectEqual(@as(usize, 0), policy.channelCount());
}

test "evaluation rejects invalid members and reports small output buffers" {
    // Arrange.
    var policy = IdleKick.initWithParams(testing.allocator, .{
        .max_channels = 2,
        .max_channel_len = 16,
        .max_member_len = 3,
    });
    defer policy.deinit();
    _ = try policy.setThreshold("#tiny", 1);

    const too_many = [_]MemberActivity{
        .{ .member = "one", .last_activity_ms = 0 },
        .{ .member = "two", .last_activity_ms = 0 },
    };
    const empty_member = [_]MemberActivity{
        .{ .member = "", .last_activity_ms = 0 },
    };
    const long_member = [_]MemberActivity{
        .{ .member = "four", .last_activity_ms = 0 },
    };
    var small: [1]KickCandidate = undefined;

    // Act / Assert.
    try testing.expectError(error.OutputTooSmall, policy.candidates("#tiny", 10, &too_many, &small));
    try testing.expectError(error.EmptyMember, policy.candidates("#tiny", 10, &empty_member, &small));
    try testing.expectError(error.MemberTooLong, policy.candidates("#tiny", 10, &long_member, &small));
}

test "idle duration never goes negative and saturates on overflow" {
    // Arrange.
    const future_last = idleDurationMs(200, 100);
    const ordinary = idleDurationMs(50, 125);
    const saturated = idleDurationMs(std.math.minInt(i64), std.math.maxInt(i64));

    // Act / Assert.
    try testing.expectEqual(@as(u64, 0), future_last);
    try testing.expectEqual(@as(u64, 75), ordinary);
    try testing.expectEqual(std.math.maxInt(u64), saturated);
}

test "single-member helper mirrors candidate evaluation" {
    // Arrange.
    var policy = IdleKick.init(testing.allocator);
    defer policy.deinit();
    _ = try policy.setThreshold("#single", 500);

    // Act / Assert.
    try testing.expect(try policy.shouldKick("#single", 1_000, .{
        .member = "idle",
        .last_activity_ms = 500,
    }));
    try testing.expect(!try policy.shouldKick("#single", 1_000, .{
        .member = "oper",
        .last_activity_ms = 0,
        .role = .operator,
    }));
    try testing.expect(!try policy.shouldKick("#unset", 1_000, .{
        .member = "idle",
        .last_activity_ms = 0,
    }));
}
