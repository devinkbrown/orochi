//! Browser transport shim core (#32).
//!
//! Ocean runs in the browser, where the only byte transport is a WebSocket — a
//! message/stream pipe, not a line protocol. This module turns that raw byte
//! stream into framed IRC lines and structured IRCv3 messages, and helps build
//! outbound lines, so the JS client never hand-rolls CRLF framing or tag
//! escaping (both easy to get subtly wrong).
//!
//! Pure `std` + the std-only `irc_line` parser, so it compiles to
//! `wasm32-freestanding` and is unit-tested natively. The WASM export surface in
//! `transport_shim.zig` is a thin wrapper over the functions here.
const std = @import("std");
const irc_line = @import("../proto/irc_line.zig");

/// Largest IRC line body the framer will surface (matches the parser bound).
pub const max_line: usize = irc_line.MAX_LINE_BODY;

pub const EscapeError = error{BufTooSmall};

/// Streaming line framer over a fixed-capacity accumulator.
///
/// Splits on `\n`, stripping an optional preceding `\r`, so it accepts both CRLF
/// (IRC wire form) and bare LF. A line that would exceed `cap` without a newline
/// is dropped and framing resyncs at the next newline, rather than corrupting
/// every subsequent line. `next` copies each completed line into a stable slot,
/// so the returned slice survives the accumulator shift until the following call.
pub fn Framer(comptime cap: usize) type {
    return struct {
        const Self = @This();

        buf: [cap]u8 = undefined,
        len: usize = 0,
        /// True while discarding the tail of an over-long line (until its `\n`).
        skipping: bool = false,
        line: [cap]u8 = undefined,
        line_len: usize = 0,

        pub fn reset(self: *Self) void {
            self.len = 0;
            self.skipping = false;
            self.line_len = 0;
        }

        /// Append inbound bytes. Over-long lines (no `\n` within `cap`) are
        /// dropped; partial lines are retained until their newline arrives.
        pub fn feed(self: *Self, bytes: []const u8) void {
            for (bytes) |b| {
                if (self.skipping) {
                    if (b == '\n') self.skipping = false;
                    continue;
                }
                if (self.len == cap) {
                    // Filled without a newline: drop this line, resync.
                    self.len = 0;
                    self.skipping = (b != '\n');
                    continue;
                }
                self.buf[self.len] = b;
                self.len += 1;
            }
        }

        /// Pop the next complete line (CR/LF stripped), or null if none is
        /// buffered yet. Valid until the next `feed`/`next`/`reset`.
        pub fn next(self: *Self) ?[]const u8 {
            const nl = std.mem.indexOfScalar(u8, self.buf[0..self.len], '\n') orelse return null;
            var end = nl;
            if (end > 0 and self.buf[end - 1] == '\r') end -= 1;

            @memcpy(self.line[0..end], self.buf[0..end]);
            self.line_len = end;

            // Shift the consumed bytes (line + the newline) out of the buffer.
            const consumed = nl + 1;
            const rest = self.len - consumed;
            if (rest != 0) std.mem.copyForwards(u8, self.buf[0..rest], self.buf[consumed..self.len]);
            self.len = rest;

            return self.line[0..self.line_len];
        }
    };
}

/// Parse one framed line into an IRCv3 message view, or null when malformed.
/// The view's slices borrow `line`.
pub fn parse(line: []const u8) ?irc_line.LineView {
    return irc_line.parseLine(line) catch null;
}

/// Unescape an IRCv3 tag value (`\:` `\s` `\\` `\r` `\n`, trailing `\` dropped)
/// into `out`. Re-exported from the parser for the shim's symmetry.
pub fn unescapeTagValue(raw: []const u8, out: []u8) irc_line.UnescapeError![]const u8 {
    return irc_line.unescapeTagValue(raw, out);
}

/// Escape a raw tag value into `out` per IRCv3 message-tags rules — the inverse
/// of `unescapeTagValue`. Returns the written slice or `error.BufTooSmall`.
pub fn escapeTagValue(raw: []const u8, out: []u8) EscapeError![]const u8 {
    var n: usize = 0;
    for (raw) |c| {
        const pair: ?[2]u8 = switch (c) {
            ';' => .{ '\\', ':' },
            ' ' => .{ '\\', 's' },
            '\\' => .{ '\\', '\\' },
            '\r' => .{ '\\', 'r' },
            '\n' => .{ '\\', 'n' },
            else => null,
        };
        if (pair) |p| {
            if (n + 2 > out.len) return error.BufTooSmall;
            out[n] = p[0];
            out[n + 1] = p[1];
            n += 2;
        } else {
            if (n + 1 > out.len) return error.BufTooSmall;
            out[n] = c;
            n += 1;
        }
    }
    return out[0..n];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "framer splits CRLF lines, including across feeds" {
    var f = Framer(64){};
    f.feed("PING :a\r\nPRIV");
    const first = f.next().?;
    try testing.expectEqualStrings("PING :a", first);
    try testing.expectEqual(@as(?[]const u8, null), f.next());
    f.feed("MSG #x :hi\r\n");
    try testing.expectEqualStrings("PRIVMSG #x :hi", f.next().?);
    try testing.expectEqual(@as(?[]const u8, null), f.next());
}

test "framer accepts bare LF and strips stray CR" {
    var f = Framer(64){};
    f.feed("A\nB\r\n");
    try testing.expectEqualStrings("A", f.next().?);
    try testing.expectEqualStrings("B", f.next().?);
    try testing.expectEqual(@as(?[]const u8, null), f.next());
}

test "framer drops an over-long line and resyncs at the next newline" {
    var f = Framer(8){};
    // 12 bytes with no newline overflows the 8-byte buffer; it is dropped.
    f.feed("XXXXXXXXXXXX\r\nGOOD\r\n");
    try testing.expectEqualStrings("GOOD", f.next().?);
    try testing.expectEqual(@as(?[]const u8, null), f.next());
}

test "parse surfaces tags, prefix, command, and params" {
    const view = parse("@id=42;k=v :nick!u@h PRIVMSG #chan :hello world").?;
    try testing.expectEqualStrings("PRIVMSG", view.command);
    try testing.expectEqualStrings("nick!u@h", view.prefix.?);
    try testing.expectEqual(@as(usize, 2), view.param_count);
    try testing.expectEqualStrings("#chan", view.paramSlice()[0]);
    try testing.expectEqualStrings("hello world", view.paramSlice()[1]);
    try testing.expectEqual(@as(usize, 2), view.tag_count);
}

test "parse returns null on a malformed line" {
    try testing.expectEqual(@as(?irc_line.LineView, null), parse("@bad"));
}

test "tag value escape/unescape round-trips the special characters" {
    const raw = "a b;c\\d\re\nf";
    var enc: [64]u8 = undefined;
    const escaped = try escapeTagValue(raw, &enc);
    try testing.expectEqualStrings("a\\sb\\:c\\\\d\\re\\nf", escaped);

    var dec: [64]u8 = undefined;
    const back = try unescapeTagValue(escaped, &dec);
    try testing.expectEqualStrings(raw, back);
}

test "escapeTagValue reports a too-small buffer" {
    var tiny: [1]u8 = undefined;
    try testing.expectError(error.BufTooSmall, escapeTagValue("  ", &tiny));
}
