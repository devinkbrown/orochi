//! IRCv3 UTF8ONLY helpers.
//!
//! This module validates UTF-8-only command parameters, builds the `UTF8ONLY`
//! ISUPPORT token, and composes the IRCv3 standard-replies
//! `FAIL <command> INVALID_UTF8 :<description>` line body into caller-provided
//! storage. It does not import the generic standard-replies builder so command
//! handlers can reject malformed UTF-8 without depending on that module.
const std = @import("std");

pub const ClientId = u64;
pub const ISUPPORT_TOKEN: []const u8 = "UTF8ONLY";
pub const STANDARD_REPLIES_CAP: []const u8 = "standard-replies";
pub const INVALID_UTF8_CODE: []const u8 = "INVALID_UTF8";
pub const DEFAULT_INVALID_UTF8_DESCRIPTION: []const u8 =
    "Message rejected, your IRC software MUST use UTF-8 encoding on this network";

pub const DEFAULT_MAX_COMMAND_BYTES: usize = 32;
pub const DEFAULT_MAX_DESCRIPTION_BYTES: usize = 256;
pub const DEFAULT_MAX_PARAM_BYTES: usize = 8191;
pub const DEFAULT_MAX_PARAMS: usize = 32;

pub const Utf8OnlyError = error{
    InvalidUtf8,
    InvalidCommand,
    CommandTooLong,
    InvalidDescription,
    DescriptionTooLong,
    ParamTooLong,
    TooManyParams,
    OutputTooSmall,
    TooManyRecipients,
};

// Compile-time limits for validators and builders.
pub const Params = struct {
    max_command_bytes: usize = DEFAULT_MAX_COMMAND_BYTES,
    max_description_bytes: usize = DEFAULT_MAX_DESCRIPTION_BYTES,
    max_param_bytes: usize = DEFAULT_MAX_PARAM_BYTES,
    max_params: usize = DEFAULT_MAX_PARAMS,
};

// One client that may receive standard replies.
pub const Watcher = struct {
    client: ClientId,
    standard_replies: bool = false,
};

// One selected standard-replies recipient.
pub const Utf8OnlyRecipient = struct {
    client: ClientId,
};

// Caller-provided storage for selected standard-replies recipients.
pub const Utf8OnlyRecipientSink = struct {
    recipients: []Utf8OnlyRecipient,
    count: usize = 0,

    pub fn append(self: *Utf8OnlyRecipientSink, client: ClientId) Utf8OnlyError!void {
        if (self.count >= self.recipients.len) return error.TooManyRecipients;
        self.recipients[self.count] = .{ .client = client };
        self.count += 1;
    }

    pub fn slice(self: *const Utf8OnlyRecipientSink) []const Utf8OnlyRecipient {
        return self.recipients[0..self.count];
    }

    pub fn reset(self: *Utf8OnlyRecipientSink) void {
        self.count = 0;
    }
};

// Return true when one IRC parameter is well-formed UTF-8.
pub fn isValidParam(param: []const u8) bool {
    return isValidParamWith(.{}, param);
}

// Return true when one IRC parameter is well-formed UTF-8 and within limits.
pub fn isValidParamWith(comptime params: Params, param: []const u8) bool {
    validateParamWith(params, param) catch return false;
    return true;
}

// Return true when all supplied IRC parameters are well-formed UTF-8.
pub fn areValidParams(param_slices: []const []const u8) bool {
    return areValidParamsWith(.{}, param_slices);
}

// Return true when all supplied IRC parameters are well-formed UTF-8 and within limits.
pub fn areValidParamsWith(comptime params: Params, param_slices: []const []const u8) bool {
    validateParamsWith(params, param_slices) catch return false;
    return true;
}

// Validate one IRC parameter as well-formed UTF-8.
pub fn validateParam(param: []const u8) Utf8OnlyError!void {
    return validateParamWith(.{}, param);
}

// Validate one IRC parameter as well-formed UTF-8 and within caller limits.
pub fn validateParamWith(comptime params: Params, param: []const u8) Utf8OnlyError!void {
    if (param.len > params.max_param_bytes) return error.ParamTooLong;
    try validateUtf8(param);
}

// Validate a set of IRC parameters as well-formed UTF-8.
pub fn validateParams(param_slices: []const []const u8) Utf8OnlyError!void {
    return validateParamsWith(.{}, param_slices);
}

// Validate a set of IRC parameters as well-formed UTF-8 and within caller limits.
pub fn validateParamsWith(comptime params: Params, param_slices: []const []const u8) Utf8OnlyError!void {
    if (param_slices.len > params.max_params) return error.TooManyParams;
    for (param_slices) |param| {
        try validateParamWith(params, param);
    }
}

// Build the valueless ISUPPORT `UTF8ONLY` token into caller-owned storage.
pub fn buildIsupportToken(out: []u8) Utf8OnlyError![]const u8 {
    if (out.len < ISUPPORT_TOKEN.len) return error.OutputTooSmall;
    @memcpy(out[0..ISUPPORT_TOKEN.len], ISUPPORT_TOKEN);
    return out[0..ISUPPORT_TOKEN.len];
}

// Build `FAIL <command> INVALID_UTF8 :<default description>`.
pub fn buildInvalidUtf8Fail(out: []u8, command: []const u8) Utf8OnlyError![]const u8 {
    return buildInvalidUtf8FailWith(.{}, out, command, DEFAULT_INVALID_UTF8_DESCRIPTION);
}

// Build `FAIL <command> INVALID_UTF8 :<description>` with caller-selected limits.
pub fn buildInvalidUtf8FailWith(
    comptime params: Params,
    out: []u8,
    command: []const u8,
    description: []const u8,
) Utf8OnlyError![]const u8 {
    try validateCommandWith(params, command);
    try validateDescriptionWith(params, description);

    var n: usize = 0;
    try append(out, &n, "FAIL ");
    try append(out, &n, command);
    try append(out, &n, " ");
    try append(out, &n, INVALID_UTF8_CODE);
    try append(out, &n, " :");
    try append(out, &n, description);
    return out[0..n];
}

// Select clients that negotiated the `standard-replies` capability.
pub fn selectStandardReplyRecipients(
    watchers: []const Watcher,
    sink: *Utf8OnlyRecipientSink,
) Utf8OnlyError!void {
    for (watchers) |watcher| {
        if (watcher.standard_replies) try sink.append(watcher.client);
    }
}

// Validate the standard-replies command parameter for an INVALID_UTF8 failure.
pub fn validateCommand(command: []const u8) Utf8OnlyError!void {
    return validateCommandWith(.{}, command);
}

// Validate the standard-replies command parameter using caller-selected limits.
pub fn validateCommandWith(comptime params: Params, command: []const u8) Utf8OnlyError!void {
    if (command.len == 0) return error.InvalidCommand;
    if (command.len > params.max_command_bytes) return error.CommandTooLong;
    if (std.mem.eql(u8, command, "*")) return;

    for (command) |ch| {
        if (!validCommandByte(ch)) return error.InvalidCommand;
    }
}

// Validate the standard-replies description parameter for an INVALID_UTF8 failure.
pub fn validateDescription(description: []const u8) Utf8OnlyError!void {
    return validateDescriptionWith(.{}, description);
}

// Validate the standard-replies description parameter using caller-selected limits.
pub fn validateDescriptionWith(comptime params: Params, description: []const u8) Utf8OnlyError!void {
    if (description.len == 0) return error.InvalidDescription;
    if (description.len > params.max_description_bytes) return error.DescriptionTooLong;
    try validateUtf8(description);

    for (description) |ch| {
        if (ch < 0x20 or ch == 0x7f) return error.InvalidDescription;
    }
}

fn validateUtf8(input: []const u8) Utf8OnlyError!void {
    var index: usize = 0;

    while (index < input.len) {
        const first = input[index];
        if (first < 0x80) {
            index += 1;
            continue;
        }

        index = try skipUtf8Sequence(input, index);
    }
}

fn skipUtf8Sequence(input: []const u8, index: usize) Utf8OnlyError!usize {
    const first = input[index];

    if (first >= 0xC2 and first <= 0xDF) {
        if (index + 1 >= input.len or !isContinuation(input[index + 1])) return error.InvalidUtf8;
        return index + 2;
    }

    if (first == 0xE0) {
        if (index + 2 >= input.len) return error.InvalidUtf8;
        const second = input[index + 1];
        if (second < 0xA0 or second > 0xBF or !isContinuation(input[index + 2])) return error.InvalidUtf8;
        return index + 3;
    }

    if (first >= 0xE1 and first <= 0xEC) {
        if (index + 2 >= input.len or !isContinuation(input[index + 1]) or !isContinuation(input[index + 2])) return error.InvalidUtf8;
        return index + 3;
    }

    if (first == 0xED) {
        if (index + 2 >= input.len) return error.InvalidUtf8;
        const second = input[index + 1];
        if (second < 0x80 or second > 0x9F or !isContinuation(input[index + 2])) return error.InvalidUtf8;
        return index + 3;
    }

    if (first >= 0xEE and first <= 0xEF) {
        if (index + 2 >= input.len or !isContinuation(input[index + 1]) or !isContinuation(input[index + 2])) return error.InvalidUtf8;
        return index + 3;
    }

    if (first == 0xF0) {
        if (index + 3 >= input.len) return error.InvalidUtf8;
        const second = input[index + 1];
        if (second < 0x90 or second > 0xBF or !isContinuation(input[index + 2]) or !isContinuation(input[index + 3])) return error.InvalidUtf8;
        return index + 4;
    }

    if (first >= 0xF1 and first <= 0xF3) {
        if (index + 3 >= input.len or !isContinuation(input[index + 1]) or !isContinuation(input[index + 2]) or !isContinuation(input[index + 3])) return error.InvalidUtf8;
        return index + 4;
    }

    if (first == 0xF4) {
        if (index + 3 >= input.len) return error.InvalidUtf8;
        const second = input[index + 1];
        if (second < 0x80 or second > 0x8F or !isContinuation(input[index + 2]) or !isContinuation(input[index + 3])) return error.InvalidUtf8;
        return index + 4;
    }

    return error.InvalidUtf8;
}

fn isContinuation(byte: u8) bool {
    return byte >= 0x80 and byte <= 0xBF;
}

fn validCommandByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9' => true,
        else => false,
    };
}

fn append(out: []u8, n: *usize, bytes: []const u8) Utf8OnlyError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn expectRecipient(recipient: Utf8OnlyRecipient, client: ClientId) !void {
    try std.testing.expectEqual(client, recipient.client);
}

test "validates one parameter and a parameter set" {
    const euro = [_]u8{ 0xE2, 0x82, 0xAC };
    const pile_of_poo = [_]u8{ 0xF0, 0x9F, 0x92, 0xA9 };

    try validateParam("plain ascii");
    try validateParam(&euro);

    const params = [_][]const u8{ "PRIVMSG", "#chan", &pile_of_poo };
    try validateParams(&params);
    try std.testing.expect(isValidParam(&pile_of_poo));
    try std.testing.expect(areValidParams(&params));
}

test "rejects malformed utf8 parameters" {
    const continuation_only = [_]u8{0x80};
    const two_byte_overlong = [_]u8{ 0xC0, 0xAF };
    const three_byte_overlong = [_]u8{ 0xE0, 0x80, 0xAF };
    const surrogate = [_]u8{ 0xED, 0xA0, 0x80 };
    const above_unicode_max = [_]u8{ 0xF4, 0x90, 0x80, 0x80 };
    const truncated_three = [_]u8{ 0xE2, 0x82 };
    const bad_continuation = [_]u8{ 0xE2, 0x28, 0xA1 };

    try std.testing.expectError(error.InvalidUtf8, validateParam(&continuation_only));
    try std.testing.expectError(error.InvalidUtf8, validateParam(&two_byte_overlong));
    try std.testing.expectError(error.InvalidUtf8, validateParam(&three_byte_overlong));
    try std.testing.expectError(error.InvalidUtf8, validateParam(&surrogate));
    try std.testing.expectError(error.InvalidUtf8, validateParam(&above_unicode_max));
    try std.testing.expectError(error.InvalidUtf8, validateParam(&truncated_three));
    try std.testing.expectError(error.InvalidUtf8, validateParam(&bad_continuation));
    try std.testing.expect(!isValidParam(&surrogate));
}

test "parameter limits apply" {
    try validateParamWith(.{ .max_param_bytes = 4 }, "four");
    try std.testing.expectError(error.ParamTooLong, validateParamWith(.{ .max_param_bytes = 4 }, "five!"));

    const too_many = [_][]const u8{ "a", "b", "c" };
    try std.testing.expectError(error.TooManyParams, validateParamsWith(.{ .max_params = 2 }, &too_many));
}

test "builds isupport utf8only token" {
    var buf: [16]u8 = undefined;
    const token = try buildIsupportToken(&buf);
    try std.testing.expectEqualStrings("UTF8ONLY", token);
}

test "isupport token builder reports output too small" {
    var buf: [7]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildIsupportToken(&buf));
}

test "builds invalid utf8 fail with default description" {
    var buf: [128]u8 = undefined;
    const line = try buildInvalidUtf8Fail(&buf, "PRIVMSG");
    try std.testing.expectEqualStrings(
        "FAIL PRIVMSG INVALID_UTF8 :Message rejected, your IRC software MUST use UTF-8 encoding on this network",
        line,
    );
}

test "builds invalid utf8 fail with custom description and wildcard command" {
    var buf: [64]u8 = undefined;
    const line = try buildInvalidUtf8FailWith(.{}, &buf, "*", "Invalid UTF-8");
    try std.testing.expectEqualStrings("FAIL * INVALID_UTF8 :Invalid UTF-8", line);
}

test "fail builder reports output too small" {
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildInvalidUtf8Fail(&buf, "USER"));
}

test "fail builder validates command and description" {
    const invalid_description_utf8 = [_]u8{ 0xE2, 0x82 };
    var buf: [128]u8 = undefined;

    try std.testing.expectError(error.InvalidCommand, buildInvalidUtf8Fail(&buf, ""));
    try std.testing.expectError(error.InvalidCommand, buildInvalidUtf8Fail(&buf, "BAD CMD"));
    try std.testing.expectError(error.InvalidCommand, buildInvalidUtf8Fail(&buf, "*BAD"));
    try std.testing.expectError(error.CommandTooLong, buildInvalidUtf8FailWith(.{ .max_command_bytes = 4 }, &buf, "PRIVMSG", "Invalid UTF-8"));
    try std.testing.expectError(error.InvalidDescription, buildInvalidUtf8FailWith(.{}, &buf, "PRIVMSG", ""));
    try std.testing.expectError(error.InvalidDescription, buildInvalidUtf8FailWith(.{}, &buf, "PRIVMSG", "bad\ntext"));
    try std.testing.expectError(error.InvalidUtf8, buildInvalidUtf8FailWith(.{}, &buf, "PRIVMSG", &invalid_description_utf8));
    try std.testing.expectError(error.DescriptionTooLong, buildInvalidUtf8FailWith(.{ .max_description_bytes = 4 }, &buf, "PRIVMSG", "Invalid UTF-8"));
}

test "cap-gated standard-replies recipient selection" {
    const watchers = [_]Watcher{
        .{ .client = 1, .standard_replies = true },
        .{ .client = 2, .standard_replies = false },
        .{ .client = 3, .standard_replies = true },
    };

    var storage: [2]Utf8OnlyRecipient = undefined;
    var sink = Utf8OnlyRecipientSink{ .recipients = &storage };
    try selectStandardReplyRecipients(&watchers, &sink);

    try std.testing.expectEqual(@as(usize, 2), sink.slice().len);
    try expectRecipient(sink.slice()[0], 1);
    try expectRecipient(sink.slice()[1], 3);

    sink.reset();
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);
}

test "recipient sink reports too many recipients" {
    const watchers = [_]Watcher{
        .{ .client = 1, .standard_replies = true },
        .{ .client = 2, .standard_replies = true },
    };

    var storage: [1]Utf8OnlyRecipient = undefined;
    var sink = Utf8OnlyRecipientSink{ .recipients = &storage };
    try std.testing.expectError(error.TooManyRecipients, selectStandardReplyRecipients(&watchers, &sink));
    try std.testing.expectEqual(@as(usize, 1), sink.slice().len);
    try expectRecipient(sink.slice()[0], 1);
}
