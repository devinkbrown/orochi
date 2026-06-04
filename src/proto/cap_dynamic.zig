//! Pure IRCv3 cap-notify line builders.
//!
//! The daemon supplies any server prefix separately, so emitted lines start at
//! `CAP <nick> ...` and do not include CRLF.
const std = @import("std");

pub const MAX_LINE_BYTES: usize = 400;

pub const Error = error{
    InvalidCapName,
    InvalidNick,
    OutputTooSmall,
};

pub const Kind = enum {
    new,
    del,

    fn verb(self: Kind) []const u8 {
        return switch (self) {
            .new => "NEW",
            .del => "DEL",
        };
    }
};

/// Caller-owned fixed storage for emitted CAP NEW / CAP DEL lines.
pub const LineSink = struct {
    lines: [][]const u8,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    pub fn append(self: *LineSink, line: []const u8) Error!void {
        if (line.len > MAX_LINE_BYTES) return error.OutputTooSmall;
        if (self.count >= self.lines.len) return error.OutputTooSmall;
        if (self.used + line.len > self.storage.len) return error.OutputTooSmall;

        const start = self.used;
        const end = start + line.len;
        @memcpy(self.storage[start..end], line);
        self.used = end;
        self.lines[self.count] = self.storage[start..end];
        self.count += 1;
    }

    pub fn slice(self: *const LineSink) []const []const u8 {
        return self.lines[0..self.count];
    }
};

pub const DiffResult = struct {
    added: []const []const u8,
    removed: []const []const u8,
};

/// Build one or more `CAP <nick> NEW :...` lines into caller storage.
pub fn buildCapNew(
    out: *LineSink,
    client_nick: []const u8,
    caps: []const []const u8,
) Error![]const []const u8 {
    return build(.new, out, client_nick, caps);
}

/// Build one or more `CAP <nick> DEL :...` lines into caller storage.
pub fn buildCapDel(
    out: *LineSink,
    client_nick: []const u8,
    caps: []const []const u8,
) Error![]const []const u8 {
    return build(.del, out, client_nick, caps);
}

/// Compute capability names added to and removed from an advertised set.
///
/// Added names are returned in `new_set` order; removed names are returned in
/// `old_set` order. Duplicate names in an input are collapsed in the output.
pub fn diff(
    old_set: []const []const u8,
    new_set: []const []const u8,
    added_out: [][]const u8,
    removed_out: [][]const u8,
) Error!DiffResult {
    for (old_set) |name| try validateCapName(name);
    for (new_set) |name| try validateCapName(name);

    var added_count: usize = 0;
    for (new_set) |name| {
        if (containsName(old_set, name)) continue;
        if (containsName(added_out[0..added_count], name)) continue;
        if (added_count >= added_out.len) return error.OutputTooSmall;
        added_out[added_count] = name;
        added_count += 1;
    }

    var removed_count: usize = 0;
    for (old_set) |name| {
        if (containsName(new_set, name)) continue;
        if (containsName(removed_out[0..removed_count], name)) continue;
        if (removed_count >= removed_out.len) return error.OutputTooSmall;
        removed_out[removed_count] = name;
        removed_count += 1;
    }

    return .{
        .added = added_out[0..added_count],
        .removed = removed_out[0..removed_count],
    };
}

fn build(
    kind: Kind,
    out: *LineSink,
    client_nick: []const u8,
    caps: []const []const u8,
) Error![]const []const u8 {
    const saved = out.*;
    errdefer out.* = saved;

    if (caps.len == 0) return out.lines[saved.count..out.count];
    try validateNick(client_nick);

    const prefix_len = linePrefixLen(kind, client_nick);
    if (prefix_len >= MAX_LINE_BYTES) return error.OutputTooSmall;
    const max_body = MAX_LINE_BYTES - prefix_len;

    var body: [MAX_LINE_BYTES]u8 = undefined;
    var body_len: usize = 0;

    for (caps) |cap_name| {
        try validateCapName(cap_name);
        if (cap_name.len > max_body) return error.OutputTooSmall;

        const space_len: usize = if (body_len == 0) 0 else 1;
        if (body_len != 0 and body_len + space_len + cap_name.len > max_body) {
            try appendLine(out, kind, client_nick, body[0..body_len]);
            body_len = 0;
        }

        if (body_len != 0) {
            body[body_len] = ' ';
            body_len += 1;
        }
        @memcpy(body[body_len .. body_len + cap_name.len], cap_name);
        body_len += cap_name.len;
    }

    if (body_len != 0) {
        try appendLine(out, kind, client_nick, body[0..body_len]);
    }

    return out.lines[saved.count..out.count];
}

fn appendLine(
    out: *LineSink,
    kind: Kind,
    client_nick: []const u8,
    body: []const u8,
) Error!void {
    var line: [MAX_LINE_BYTES]u8 = undefined;
    var len: usize = 0;

    @memcpy(line[len .. len + "CAP ".len], "CAP ");
    len += "CAP ".len;
    @memcpy(line[len .. len + client_nick.len], client_nick);
    len += client_nick.len;
    line[len] = ' ';
    len += 1;
    const verb = kind.verb();
    @memcpy(line[len .. len + verb.len], verb);
    len += verb.len;
    @memcpy(line[len .. len + " :".len], " :");
    len += " :".len;
    @memcpy(line[len .. len + body.len], body);
    len += body.len;

    try out.append(line[0..len]);
}

fn linePrefixLen(kind: Kind, client_nick: []const u8) usize {
    return "CAP ".len + client_nick.len + 1 + kind.verb().len + " :".len;
}

fn validateCapName(name: []const u8) Error!void {
    if (name.len == 0) return error.InvalidCapName;
    for (name) |byte| {
        switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.' => {},
            else => return error.InvalidCapName,
        }
    }
}

fn validateNick(nick: []const u8) Error!void {
    if (nick.len == 0) return error.InvalidNick;
    for (nick) |byte| {
        switch (byte) {
            0, '\r', '\n', ' ' => return error.InvalidNick,
            else => {},
        }
    }
}

fn containsName(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |name| {
        if (std.mem.eql(u8, name, needle)) return true;
    }
    return false;
}

fn testSink(line_count: usize, storage_size: usize) !struct {
    lines: [][]const u8,
    storage: []u8,
    sink: LineSink,
} {
    const allocator = std.testing.allocator;
    const lines = try allocator.alloc([]const u8, line_count);
    errdefer allocator.free(lines);
    const storage = try allocator.alloc(u8, storage_size);
    errdefer allocator.free(storage);
    return .{
        .lines = lines,
        .storage = storage,
        .sink = .{ .lines = lines, .storage = storage },
    };
}

test "NEW and DEL exact bytes" {
    const allocator = std.testing.allocator;
    var fixture = try testSink(4, 256);
    defer allocator.free(fixture.storage);
    defer allocator.free(fixture.lines);

    const new_lines = try buildCapNew(&fixture.sink, "alice", &.{
        "cap-notify",
        "sasl",
    });
    try std.testing.expectEqual(@as(usize, 1), new_lines.len);
    try std.testing.expectEqualStrings("CAP alice NEW :cap-notify sasl", new_lines[0]);

    const del_lines = try buildCapDel(&fixture.sink, "alice", &.{
        "sasl",
    });
    try std.testing.expectEqual(@as(usize, 1), del_lines.len);
    try std.testing.expectEqualStrings("CAP alice DEL :sasl", del_lines[0]);
}

test "diff reports additions and removals" {
    var added: [4][]const u8 = undefined;
    var removed: [4][]const u8 = undefined;

    const result = try diff(
        &.{ "sasl", "cap-notify" },
        &.{ "cap-notify", "message-tags", "echo-message" },
        added[0..],
        removed[0..],
    );

    try std.testing.expectEqual(@as(usize, 2), result.added.len);
    try std.testing.expectEqualStrings("message-tags", result.added[0]);
    try std.testing.expectEqualStrings("echo-message", result.added[1]);
    try std.testing.expectEqual(@as(usize, 1), result.removed.len);
    try std.testing.expectEqualStrings("sasl", result.removed[0]);
}

test "chunking splits a long list" {
    const allocator = std.testing.allocator;
    var fixture = try testSink(8, 1200);
    defer allocator.free(fixture.storage);
    defer allocator.free(fixture.lines);

    const caps: []const []const u8 = &.{
        "capaaaaaaaaaaaaaaaaaaaaaaaa",
        "capbbbbbbbbbbbbbbbbbbbbbbbb",
        "capcccccccccccccccccccccccc",
        "capdddddddddddddddddddddddd",
        "capeeeeeeeeeeeeeeeeeeeeeeee",
        "capffffffffffffffffffffffff",
        "capgggggggggggggggggggggggg",
        "caphhhhhhhhhhhhhhhhhhhhhhhh",
        "capiiiiiiiiiiiiiiiiiiiiiiii",
        "capjjjjjjjjjjjjjjjjjjjjjjjj",
        "capkkkkkkkkkkkkkkkkkkkkkkkk",
        "capllllllllllllllllllllllll",
        "capmmmmmmmmmmmmmmmmmmmmmmmm",
        "capnnnnnnnnnnnnnnnnnnnnnnnn",
        "capoooooooooooooooooooooooo",
        "cappppppppppppppppppppppppp",
    };

    const lines = try buildCapNew(&fixture.sink, "n", caps);
    try std.testing.expect(lines.len > 1);
    for (lines) |line| {
        try std.testing.expect(line.len <= MAX_LINE_BYTES);
        try std.testing.expect(std.mem.startsWith(u8, line, "CAP n NEW :"));
    }
}

test "invalid cap name rejected" {
    const allocator = std.testing.allocator;
    var fixture = try testSink(2, 128);
    defer allocator.free(fixture.storage);
    defer allocator.free(fixture.lines);

    try std.testing.expectError(
        error.InvalidCapName,
        buildCapNew(&fixture.sink, "alice", &.{"ophion/prop-notify"}),
    );
}
