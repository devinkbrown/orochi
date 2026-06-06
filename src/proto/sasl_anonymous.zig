//! Pure SASL ANONYMOUS helpers.
//!
//! This module validates the optional RFC 4505 trace token and reports whether
//! ANONYMOUS may continue as a guest login. The server assigns the actual guest
//! account name outside this module; no persistent identity is created here.
const std = @import("std");

/// SASL mechanism name advertised for ANONYMOUS.
pub const mechanism = "ANONYMOUS";

/// Default maximum trace token size in bytes.
pub const default_max_trace_bytes: usize = 255;

/// Policy limits for ANONYMOUS authentication.
pub const Params = struct {
    /// Whether ANONYMOUS is available to clients.
    enabled: bool = true,
    /// Maximum trace token length in bytes.
    max_trace_bytes: usize = default_max_trace_bytes,
};

/// Parsing failures for ANONYMOUS client responses.
pub const ParseError = error{
    InvalidTrace,
    TraceTooLong,
};

/// Result of one ANONYMOUS server step.
pub const Result = union(enum) {
    /// Guest login accepted; the trace is borrowed from the client response.
    guest: struct {
        /// Optional trace token supplied by the client.
        trace: ?[]const u8,
    },
    /// Guest login rejected by policy or parser validation.
    fail,
};

/// Parse an ANONYMOUS client response using the default trace limit.
///
/// Empty responses are accepted as no trace. Non-empty responses must be valid
/// UTF-8, contain no control bytes, and fit the default trace byte limit. The
/// returned slice is borrowed from `msg`.
pub fn parse(msg: []const u8) ParseError!?[]const u8 {
    return parseBounded(msg, .{});
}

/// Process an ANONYMOUS client response under caller policy.
///
/// Success means the caller may assign a guest account name. This function does
/// not create or persist the guest identity; it only validates the optional
/// trace token and signals success.
pub fn step(msg: []const u8, params: Params) Result {
    if (!params.enabled) return .fail;
    const trace = parseBounded(msg, params) catch return .fail;
    return .{ .guest = .{ .trace = trace } };
}

fn parseBounded(msg: []const u8, params: Params) ParseError!?[]const u8 {
    if (msg.len == 0) return null;
    if (msg.len > params.max_trace_bytes) return error.TraceTooLong;
    if (!std.unicode.utf8ValidateSlice(msg)) return error.InvalidTrace;

    var index: usize = 0;
    while (index < msg.len) {
        const byte = msg[index];
        if (byte < 0x20 or byte == 0x7f) return error.InvalidTrace;
        if (byte < 0x80) {
            index += 1;
        } else if (byte < 0xe0) {
            const codepoint = (@as(u21, byte & 0x1f) << 6) | @as(u21, msg[index + 1] & 0x3f);
            if (codepoint >= 0x80 and codepoint <= 0x9f) return error.InvalidTrace;
            index += 2;
        } else if (byte < 0xf0) {
            index += 3;
        } else {
            index += 4;
        }
    }
    return msg;
}

test "parse empty trace returns null and allocates nothing" {
    const allocator = std.testing.allocator;

    const borrowed = "unused";
    const trace = try parse(borrowed[0..0]);

    _ = allocator;
    try std.testing.expectEqual(@as(?[]const u8, null), trace);
}

test "parse valid trace returns borrowed slice" {
    const allocator = std.testing.allocator;

    const msg = try allocator.dupe(u8, "guest@example.test");
    defer allocator.free(msg);
    const trace = try parse(msg);

    try std.testing.expect(trace != null);
    try std.testing.expectEqualStrings("guest@example.test", trace.?);
    try std.testing.expectEqual(@intFromPtr(msg.ptr), @intFromPtr(trace.?.ptr));
}

test "parse valid utf8 trace accepts non ascii text" {
    const allocator = std.testing.allocator;

    const msg = "opaque-\xc3\xa9-token";
    const trace = try parse(msg);

    _ = allocator;
    try std.testing.expect(trace != null);
    try std.testing.expectEqualStrings(msg, trace.?);
}

test "parse rejects control characters" {
    const allocator = std.testing.allocator;

    const with_nul = "guest\x00trace";
    const with_lf = "guest\ntrace";
    const with_del = "guest\x7ftrace";
    const with_unicode_control = "guest\xc2\x80trace";

    _ = allocator;
    try std.testing.expectError(error.InvalidTrace, parse(with_nul));
    try std.testing.expectError(error.InvalidTrace, parse(with_lf));
    try std.testing.expectError(error.InvalidTrace, parse(with_del));
    try std.testing.expectError(error.InvalidTrace, parse(with_unicode_control));
}

test "parse rejects invalid utf8" {
    const allocator = std.testing.allocator;

    const invalid = [_]u8{ 0xf0, 0x28, 0x8c, 0x28 };

    _ = allocator;
    try std.testing.expectError(error.InvalidTrace, parse(&invalid));
}

test "parse rejects oversize trace" {
    const allocator = std.testing.allocator;

    const msg = "a" ** (default_max_trace_bytes + 1);

    _ = allocator;
    try std.testing.expectError(error.TraceTooLong, parse(msg));
}

test "step disabled policy fails" {
    const allocator = std.testing.allocator;

    const result = step("guest@example.test", .{ .enabled = false });

    _ = allocator;
    try std.testing.expectEqual(Result.fail, result);
}

test "step enabled policy accepts empty trace as guest" {
    const allocator = std.testing.allocator;

    const result = step("", .{ .enabled = true });

    _ = allocator;
    switch (result) {
        .guest => |guest| try std.testing.expectEqual(@as(?[]const u8, null), guest.trace),
        .fail => return error.TestUnexpectedResult,
    }
}

test "step enabled policy accepts trace and borrows caller buffer" {
    const allocator = std.testing.allocator;

    const msg = try allocator.dupe(u8, "opaque-client-trace");
    defer allocator.free(msg);
    const result = step(msg, .{ .enabled = true });

    switch (result) {
        .guest => |guest| {
            try std.testing.expect(guest.trace != null);
            try std.testing.expectEqualStrings("opaque-client-trace", guest.trace.?);
            try std.testing.expectEqual(@intFromPtr(msg.ptr), @intFromPtr(guest.trace.?.ptr));
        },
        .fail => return error.TestUnexpectedResult,
    }
}

test "step applies custom max trace bytes" {
    const allocator = std.testing.allocator;

    const accepted = step("abc", .{ .enabled = true, .max_trace_bytes = 3 });
    const rejected = step("abcd", .{ .enabled = true, .max_trace_bytes = 3 });

    _ = allocator;
    switch (accepted) {
        .guest => |guest| try std.testing.expectEqualStrings("abc", guest.trace.?),
        .fail => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(Result.fail, rejected);
}

test "all declarations are referenced" {
    std.testing.refAllDecls(@This());
}
