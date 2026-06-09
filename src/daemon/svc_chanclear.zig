//! Pure CHANCLEAR service-command parser and action planner.
//!
//! This module deliberately has no daemon/protocol imports and performs no IO.
//! It parses the real server command surface and returns a typed plan that a
//! caller can translate into world mutations and numeric replies.

const std = @import("std");

pub const command_name = "CHANCLEAR";
pub const max_channel_len: usize = 50;
pub const max_actions: usize = 21;

pub const Error = error{
    EmptyInput,
    TooFewArguments,
    TooManyArguments,
    UnknownCommand,
    UnknownFeature,
    InvalidChannel,
};

pub const Feature = enum {
    modes,

    pub fn parse(bytes: []const u8) ?Feature {
        if (std.ascii.eqlIgnoreCase(bytes, "MODES")) return .modes;
        return null;
    }
};

pub const ListMode = enum {
    ban,
    exception,
    invite_exception,
};

pub const ParameterMode = enum {
    key,
    limit,
};

pub const FlagMode = enum {
    invite_only,
    moderated,
    no_external,
    topic_ops,
    secret,
    no_ctcp,
    no_notice,
    no_nick,
    free_invite,
    tls_only,
    registered_only_speak,
};

pub const PrefixMode = enum {
    founder,
    owner,
    op,
    halfop,
    voice,
};

/// One planned strip operation. The caller decides how to enumerate concrete
/// list entries or members from current channel state.
pub const StripAction = union(enum) {
    list_mode: ListMode,
    parameter_mode: ParameterMode,
    flag_mode: FlagMode,
    prefix_mode: PrefixMode,
};

pub const Request = struct {
    channel: []const u8,
    feature: Feature,
};

pub const Plan = struct {
    channel: []const u8,
    feature: Feature,
    storage: [max_actions]StripAction = undefined,
    count: usize = 0,

    pub fn actions(self: *const Plan) []const StripAction {
        return self.storage[0..self.count];
    }

    pub fn contains(self: *const Plan, action: StripAction) bool {
        for (self.actions()) |candidate| {
            if (std.meta.eql(candidate, action)) return true;
        }
        return false;
    }

    fn append(self: *Plan, action: StripAction) void {
        std.debug.assert(self.count < self.storage.len);
        self.storage[self.count] = action;
        self.count += 1;
    }
};

/// Parse a caller-owned line. A leading CHANCLEAR verb is accepted but not
/// required so dispatchers may pass either the full command line or parameters.
pub fn parse(line: []const u8) Error!Request {
    var it = std.mem.tokenizeAny(u8, line, " \t\r\n");
    var parts: [3][]const u8 = undefined;
    var count: usize = 0;
    while (it.next()) |part| {
        if (count >= parts.len) return error.TooManyArguments;
        parts[count] = part;
        count += 1;
    }
    return parseTokens(parts[0..count]);
}

/// Parse command parameters. A leading CHANCLEAR verb is tolerated for tests
/// and direct callers; otherwise args must be `<channel> MODES`.
pub fn parseArgs(args: []const []const u8) Error!Request {
    if (args.len > 3) return error.TooManyArguments;
    return parseTokens(args);
}

pub fn planFor(request: Request) Plan {
    var out = Plan{
        .channel = request.channel,
        .feature = request.feature,
    };

    switch (request.feature) {
        .modes => appendModesPlan(&out),
    }

    return out;
}

pub fn parseAndPlan(line: []const u8) Error!Plan {
    return planFor(try parse(line));
}

fn parseTokens(tokens: []const []const u8) Error!Request {
    if (tokens.len == 0) return error.EmptyInput;

    var start: usize = 0;
    if (std.ascii.eqlIgnoreCase(tokens[0], command_name)) {
        start = 1;
    } else if (looksLikeCommand(tokens[0])) {
        return error.UnknownCommand;
    }

    const remaining = tokens.len - start;
    if (remaining < 2) return error.TooFewArguments;
    if (remaining > 2) return error.TooManyArguments;

    const channel = tokens[start];
    const feature = Feature.parse(tokens[start + 1]) orelse return error.UnknownFeature;
    try validateChannel(channel);

    return .{
        .channel = channel,
        .feature = feature,
    };
}

fn appendModesPlan(out: *Plan) void {
    out.append(.{ .list_mode = .ban });
    out.append(.{ .list_mode = .exception });
    out.append(.{ .list_mode = .invite_exception });

    out.append(.{ .parameter_mode = .key });
    out.append(.{ .parameter_mode = .limit });

    out.append(.{ .flag_mode = .invite_only });
    out.append(.{ .flag_mode = .moderated });
    out.append(.{ .flag_mode = .no_external });
    out.append(.{ .flag_mode = .topic_ops });
    out.append(.{ .flag_mode = .secret });
    out.append(.{ .flag_mode = .no_ctcp });
    out.append(.{ .flag_mode = .no_notice });
    out.append(.{ .flag_mode = .no_nick });
    out.append(.{ .flag_mode = .free_invite });
    out.append(.{ .flag_mode = .tls_only });
    out.append(.{ .flag_mode = .registered_only_speak });

    out.append(.{ .prefix_mode = .founder });
    out.append(.{ .prefix_mode = .owner });
    out.append(.{ .prefix_mode = .op });
    out.append(.{ .prefix_mode = .halfop });
    out.append(.{ .prefix_mode = .voice });
}

fn validateChannel(channel: []const u8) Error!void {
    if (channel.len < 2 or channel.len > max_channel_len or channel[0] != '#') {
        return error.InvalidChannel;
    }
    for (channel) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == '|' or byte == ',' or byte == ':') {
            return error.InvalidChannel;
        }
    }
}

fn looksLikeCommand(bytes: []const u8) bool {
    if (bytes.len == 0 or bytes[0] == '#') return false;
    for (bytes) |byte| {
        if (!std.ascii.isAlphabetic(byte)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parse accepts full CHANCLEAR MODES command" {
    const req = try parse("CHANCLEAR #ops MODES");
    try testing.expectEqualStrings("#ops", req.channel);
    try testing.expectEqual(Feature.modes, req.feature);
}

test "parse accepts dispatch parameters without command verb" {
    const req = try parse("#ops MODES");
    try testing.expectEqualStrings("#ops", req.channel);
    try testing.expectEqual(Feature.modes, req.feature);
}

test "parse is case-insensitive for command and feature only" {
    const req = try parse("chanclear #MiXuP modes");
    try testing.expectEqualStrings("#MiXuP", req.channel);
    try testing.expectEqual(Feature.modes, req.feature);
}

test "parseArgs accepts caller-owned slices" {
    const args = [_][]const u8{ "#chat", "MODES" };
    const req = try parseArgs(&args);
    try testing.expectEqualStrings("#chat", req.channel);
    try testing.expectEqual(Feature.modes, req.feature);
}

test "parse rejects empty missing and extra arguments" {
    try testing.expectError(error.EmptyInput, parse(""));
    try testing.expectError(error.TooFewArguments, parse("CHANCLEAR"));
    try testing.expectError(error.TooFewArguments, parse("CHANCLEAR #ops"));
    try testing.expectError(error.TooManyArguments, parse("CHANCLEAR #ops MODES extra"));
}

test "parse rejects unknown command and unknown feature" {
    try testing.expectError(error.UnknownCommand, parse("CHANFIX #ops MODES"));
    try testing.expectError(error.UnknownFeature, parse("CHANCLEAR #ops USERS"));
}

test "parse rejects invalid channel names" {
    try testing.expectError(error.InvalidChannel, parse("CHANCLEAR ops MODES"));
    try testing.expectError(error.InvalidChannel, parse("CHANCLEAR # MODES"));
    try testing.expectError(error.InvalidChannel, parse("CHANCLEAR #bad:name MODES"));
    try testing.expectError(error.InvalidChannel, parse("CHANCLEAR #bad,name MODES"));
    try testing.expectError(error.InvalidChannel, parse("CHANCLEAR #bad|name MODES"));
    try testing.expectError(error.InvalidChannel, parse("CHANCLEAR #aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX MODES"));
}

test "plan for MODES strips list parameter flag and prefix mode categories" {
    const plan = planFor(.{ .channel = "#ops", .feature = .modes });
    try testing.expectEqualStrings("#ops", plan.channel);
    try testing.expectEqual(Feature.modes, plan.feature);
    try testing.expectEqual(max_actions, plan.actions().len);
    try testing.expect(plan.contains(.{ .list_mode = .ban }));
    try testing.expect(plan.contains(.{ .list_mode = .exception }));
    try testing.expect(plan.contains(.{ .list_mode = .invite_exception }));
    try testing.expect(plan.contains(.{ .parameter_mode = .key }));
    try testing.expect(plan.contains(.{ .parameter_mode = .limit }));
    try testing.expect(plan.contains(.{ .flag_mode = .invite_only }));
    try testing.expect(plan.contains(.{ .flag_mode = .moderated }));
    try testing.expect(plan.contains(.{ .flag_mode = .no_external }));
    try testing.expect(plan.contains(.{ .flag_mode = .topic_ops }));
    try testing.expect(plan.contains(.{ .flag_mode = .secret }));
    try testing.expect(plan.contains(.{ .flag_mode = .no_ctcp }));
    try testing.expect(plan.contains(.{ .flag_mode = .no_notice }));
    try testing.expect(plan.contains(.{ .flag_mode = .no_nick }));
    try testing.expect(plan.contains(.{ .flag_mode = .free_invite }));
    try testing.expect(plan.contains(.{ .flag_mode = .tls_only }));
    try testing.expect(plan.contains(.{ .flag_mode = .registered_only_speak }));
    try testing.expect(plan.contains(.{ .prefix_mode = .founder }));
    try testing.expect(plan.contains(.{ .prefix_mode = .owner }));
    try testing.expect(plan.contains(.{ .prefix_mode = .op }));
    try testing.expect(plan.contains(.{ .prefix_mode = .halfop }));
    try testing.expect(plan.contains(.{ .prefix_mode = .voice }));
}

test "MODES plan order is stable for deterministic integration" {
    const plan = try parseAndPlan("CHANCLEAR #ops MODES");
    const actions = plan.actions();
    try testing.expectEqual(StripAction{ .list_mode = .ban }, actions[0]);
    try testing.expectEqual(StripAction{ .list_mode = .exception }, actions[1]);
    try testing.expectEqual(StripAction{ .list_mode = .invite_exception }, actions[2]);
    try testing.expectEqual(StripAction{ .parameter_mode = .key }, actions[3]);
    try testing.expectEqual(StripAction{ .parameter_mode = .limit }, actions[4]);
    try testing.expectEqual(StripAction{ .prefix_mode = .voice }, actions[actions.len - 1]);
}

test "plan is stack-owned and borrows the parsed channel slice" {
    const line = "CHANCLEAR #borrowed MODES";
    const plan = try parseAndPlan(line);
    try testing.expectEqualStrings("#borrowed", plan.channel);
    try testing.expectEqual(@as(usize, max_actions), plan.actions().len);
}
