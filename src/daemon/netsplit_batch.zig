//! Pure IRCv3 netsplit/netjoin BATCH formatter for Suimyaku peer transitions.
//!
//! Callers decide recipients and per-channel fan-out. This module only renders
//! wire bytes into caller-owned storage and never allocates.
const std = @import("std");

pub const Error = error{OutputTooSmall};

/// A member that vanished (netsplit) or appeared (netjoin) due to a peer transition.
pub const Ghost = struct {
    /// "nick!user@host" for the QUIT/JOIN source.
    prefix: []const u8,
    nick: []const u8,
};

/// Generate a short opaque batch reference tag from a caller-provided seed.
pub fn makeBatchRef(buf: []u8, seed: u64) []const u8 {
    const len = 18;
    if (buf.len < len) return "";

    buf[0] = 'm';
    buf[1] = 'z';
    writeFixedHex(mix64(seed), buf[2..len]);
    return buf[0..len];
}

/// Write a netsplit batch to `out` for one recipient's view.
pub fn writeNetsplit(
    out: []u8,
    ref: []const u8,
    local_server: []const u8,
    remote_server: []const u8,
    ghosts: []const Ghost,
) Error![]const u8 {
    var writer = FixedWriter.init(out);

    try writeBatchOpen(&writer, local_server, ref, "netsplit", local_server, remote_server);
    for (ghosts) |ghost| {
        try writer.append("@batch=");
        try writer.append(ref);
        try writer.append(" :");
        try writer.append(ghost.prefix);
        try writer.append(" QUIT :");
        try writer.append(local_server);
        try writer.appendByte(' ');
        try writer.append(remote_server);
        try writer.append("\r\n");
    }
    try writeBatchClose(&writer, local_server, ref);

    return writer.written();
}

/// Write a netjoin batch to `out` for one recipient's channel view.
pub fn writeNetjoin(
    out: []u8,
    ref: []const u8,
    local_server: []const u8,
    remote_server: []const u8,
    channel: []const u8,
    ghosts: []const Ghost,
) Error![]const u8 {
    var writer = FixedWriter.init(out);

    try writeBatchOpen(&writer, local_server, ref, "netjoin", local_server, remote_server);
    for (ghosts) |ghost| {
        try writer.append("@batch=");
        try writer.append(ref);
        try writer.append(" :");
        try writer.append(ghost.prefix);
        try writer.append(" JOIN ");
        try writer.append(channel);
        try writer.append("\r\n");
    }
    try writeBatchClose(&writer, local_server, ref);

    return writer.written();
}

/// Write un-batched QUIT lines (no `@batch` tag, no BATCH open/close) for one
/// recipient that did NOT negotiate the `batch` cap. Same QUIT events a netsplit
/// batch carries, just without the IRCv3 framing such a client can't parse.
pub fn writeQuitsPlain(
    out: []u8,
    local_server: []const u8,
    remote_server: []const u8,
    ghosts: []const Ghost,
) Error![]const u8 {
    var writer = FixedWriter.init(out);
    for (ghosts) |ghost| {
        try writer.append(":");
        try writer.append(ghost.prefix);
        try writer.append(" QUIT :");
        try writer.append(local_server);
        try writer.appendByte(' ');
        try writer.append(remote_server);
        try writer.append("\r\n");
    }
    return writer.written();
}

/// Write un-batched JOIN lines for a channel for one recipient that did NOT
/// negotiate the `batch` cap. Same JOIN events a netjoin batch carries.
pub fn writeJoinsPlain(
    out: []u8,
    channel: []const u8,
    ghosts: []const Ghost,
) Error![]const u8 {
    var writer = FixedWriter.init(out);
    for (ghosts) |ghost| {
        try writer.append(":");
        try writer.append(ghost.prefix);
        try writer.append(" JOIN ");
        try writer.append(channel);
        try writer.append("\r\n");
    }
    return writer.written();
}

const FixedWriter = struct {
    out: []u8,
    cursor: usize = 0,

    fn init(out: []u8) FixedWriter {
        return .{ .out = out };
    }

    fn written(self: *const FixedWriter) []const u8 {
        return self.out[0..self.cursor];
    }

    fn appendByte(self: *FixedWriter, byte: u8) Error!void {
        if (self.cursor >= self.out.len) return error.OutputTooSmall;
        self.out[self.cursor] = byte;
        self.cursor += 1;
    }

    fn append(self: *FixedWriter, bytes: []const u8) Error!void {
        if (bytes.len > self.out.len -| self.cursor) return error.OutputTooSmall;
        @memcpy(self.out[self.cursor .. self.cursor + bytes.len], bytes);
        self.cursor += bytes.len;
    }
};

fn writeBatchOpen(
    writer: *FixedWriter,
    server: []const u8,
    ref: []const u8,
    kind: []const u8,
    local_server: []const u8,
    remote_server: []const u8,
) Error!void {
    try writer.appendByte(':');
    try writer.append(server);
    try writer.append(" BATCH +");
    try writer.append(ref);
    try writer.appendByte(' ');
    try writer.append(kind);
    try writer.appendByte(' ');
    try writer.append(local_server);
    try writer.appendByte(' ');
    try writer.append(remote_server);
    try writer.append("\r\n");
}

fn writeBatchClose(writer: *FixedWriter, server: []const u8, ref: []const u8) Error!void {
    try writer.appendByte(':');
    try writer.append(server);
    try writer.append(" BATCH -");
    try writer.append(ref);
    try writer.append("\r\n");
}

fn mix64(seed: u64) u64 {
    var value = seed +% 0x9e3779b97f4a7c15;
    value = (value ^ (value >> 30)) *% 0xbf58476d1ce4e5b9;
    value = (value ^ (value >> 27)) *% 0x94d049bb133111eb;
    return value ^ (value >> 31);
}

fn writeFixedHex(value: u64, out: []u8) void {
    var shift: u6 = 60;
    var cursor: usize = 0;
    while (cursor < out.len) : (cursor += 1) {
        const nibble: u8 = @intCast((value >> shift) & 0x0f);
        out[cursor] = if (nibble < 10) '0' + nibble else 'a' + (nibble - 10);
        if (shift >= 4) {
            shift -= 4;
        } else {
            shift = 0;
        }
    }
}

test "netsplit batch wraps two ghost quits" {
    const ghosts = [_]Ghost{
        .{ .prefix = "alice!a@leaf", .nick = "alice" },
        .{ .prefix = "bob!b@leaf", .nick = "bob" },
    };
    var out: [256]u8 = undefined;

    const written = try writeNetsplit(&out, "ref", "a", "b", &ghosts);

    try std.testing.expectEqualStrings(
        ":a BATCH +ref netsplit a b\r\n" ++
            "@batch=ref :alice!a@leaf QUIT :a b\r\n" ++
            "@batch=ref :bob!b@leaf QUIT :a b\r\n" ++
            ":a BATCH -ref\r\n",
        written,
    );
}

test "netjoin batch wraps two ghost joins" {
    const ghosts = [_]Ghost{
        .{ .prefix = "alice!a@leaf", .nick = "alice" },
        .{ .prefix = "bob!b@leaf", .nick = "bob" },
    };
    var out: [256]u8 = undefined;

    const written = try writeNetjoin(&out, "ref", "a", "b", "#room", &ghosts);

    try std.testing.expectEqualStrings(
        ":a BATCH +ref netjoin a b\r\n" ++
            "@batch=ref :alice!a@leaf JOIN #room\r\n" ++
            "@batch=ref :bob!b@leaf JOIN #room\r\n" ++
            ":a BATCH -ref\r\n",
        written,
    );
}

test "plain quit/join lines carry no batch framing" {
    const ghosts = [_]Ghost{
        .{ .prefix = "alice!a@leaf", .nick = "alice" },
        .{ .prefix = "bob!b@leaf", .nick = "bob" },
    };
    var out: [256]u8 = undefined;

    try std.testing.expectEqualStrings(
        ":alice!a@leaf QUIT :a b\r\n" ++
            ":bob!b@leaf QUIT :a b\r\n",
        try writeQuitsPlain(&out, "a", "b", &ghosts),
    );
    try std.testing.expectEqualStrings(
        ":alice!a@leaf JOIN #room\r\n" ++
            ":bob!b@leaf JOIN #room\r\n",
        try writeJoinsPlain(&out, "#room", &ghosts),
    );
}

test "tiny output buffer reports OutputTooSmall" {
    const ghosts = [_]Ghost{
        .{ .prefix = "alice!a@leaf", .nick = "alice" },
    };
    var out: [8]u8 = undefined;

    try std.testing.expectError(
        error.OutputTooSmall,
        writeNetsplit(&out, "ref", "a", "b", &ghosts),
    );
}

test "batch references are deterministic and fit caller storage" {
    var first: [18]u8 = undefined;
    var second: [18]u8 = undefined;
    var tiny: [4]u8 = undefined;

    try std.testing.expectEqualStrings(makeBatchRef(&first, 7), makeBatchRef(&second, 7));
    try std.testing.expectEqual(@as(usize, 18), makeBatchRef(&first, 8).len);
    try std.testing.expectEqualStrings("", makeBatchRef(&tiny, 8));
}
