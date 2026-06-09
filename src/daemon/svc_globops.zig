//! GLOBOPS / oper-broadcast routing core.
//!
//! In Mizuchi an operator broadcast (the classic GLOBOPS) is **not** a `+w`
//! umode and **not** a pseudo-client message: it is published through the
//! Event Spine to the opers who have subscribed to the `globops` snomask
//! category. This module is the pure, allocation-free decision-and-format
//! core that complements `daemon/event_spine.zig` (the generic typed bus)
//! and `proto/global_notice.zig` (the user-facing `$*` notice):
//!
//!   * `event_spine.zig`   — generic subscriber/category fan-out machinery.
//!   * `global_notice.zig` — global notices aimed at *users*.
//!   * this module         — decide which *opers* receive a GLOBOPS based on
//!                           their oper status + `globops` snomask bit, and
//!                           format the single broadcast wire line.
//!
//! Everything here borrows the caller's slices. No function allocates, does
//! IO, or mutates a recipient. The server is responsible for snapshotting the
//! oper sessions into a `[]const Recipient`, calling `select`, and writing the
//! formatted line to each selected index.

const std = @import("std");

/// Tunable byte bounds for formatting. All limits are inclusive byte counts;
/// values larger than the limit are rejected with a typed error rather than
/// silently truncated.
pub const Params = struct {
    /// Maximum length of the broadcast text in bytes (after control-byte
    /// stripping is *not* applied — the raw input is bounded first).
    max_text_bytes: usize = 400,
    /// Maximum length of the originating oper's name in bytes.
    max_oper_bytes: usize = 64,
    /// Maximum length of the formatting server name in bytes.
    max_server_name_bytes: usize = 255,
    /// Maximum length of a fully formatted wire line in bytes (the classic
    /// IRC line limit of 512 including CR-LF).
    max_line_bytes: usize = 512,
};

/// One connected session considered as a possible GLOBOPS recipient. Both
/// fields are caller-owned snapshots; this module never mutates a recipient.
pub const Recipient = struct {
    /// Whether the session is an authenticated operator. A non-oper never
    /// receives a GLOBOPS regardless of its snomask state.
    is_oper: bool = false,
    /// Whether the session subscribes to the `globops` snomask category.
    sno_has_globops: bool = false,

    /// A recipient is eligible when it is both an oper and subscribed to the
    /// `globops` category. Both conditions are required.
    pub fn eligible(self: Recipient) bool {
        return self.is_oper and self.sno_has_globops;
    }
};

/// Caller-owned sink that collects the selected recipient indices. The sink
/// refuses to write past its backing buffer, so the caller sizes it to at
/// least `recipients.len`.
pub const IndexSink = struct {
    buf: []usize,
    count: usize = 0,

    pub fn init(buf: []usize) IndexSink {
        return .{ .buf = buf };
    }

    pub fn reset(self: *IndexSink) void {
        self.count = 0;
    }

    /// The selected indices in ascending recipient order.
    pub fn slice(self: *const IndexSink) []const usize {
        return self.buf[0..self.count];
    }

    fn append(self: *IndexSink, index: usize) SelectError!void {
        if (self.count >= self.buf.len) return error.OutputTooSmall;
        self.buf[self.count] = index;
        self.count += 1;
    }
};

/// Errors produced while selecting recipients.
pub const SelectError = error{
    /// The index sink was too small to hold every eligible recipient.
    OutputTooSmall,
};

/// Errors produced while formatting the broadcast wire line.
pub const FormatError = error{
    /// The supplied output buffer was too small for the formatted line, or
    /// the formatted line exceeded `Params.max_line_bytes`.
    OutputTooSmall,
    /// The server name was empty.
    InvalidServerName,
    /// The server name exceeded `Params.max_server_name_bytes`.
    ServerNameTooLong,
    /// The oper name was empty.
    InvalidOper,
    /// The oper name exceeded `Params.max_oper_bytes`.
    OperTooLong,
    /// The broadcast text was empty (after bound checks but before stripping).
    EmptyText,
    /// The broadcast text exceeded `Params.max_text_bytes`.
    TextTooLong,
};

/// The fixed marker that precedes every GLOBOPS payload so opers can tell a
/// network-wide oper broadcast apart from an ordinary notice.
pub const global_marker = "*** Global -- from ";

/// Count the eligible recipients in `recipients` without selecting them. Used
/// by callers that want to size a sink up front.
pub fn eligibleCount(recipients: []const Recipient) usize {
    var n: usize = 0;
    for (recipients) |r| {
        if (r.eligible()) n += 1;
    }
    return n;
}

/// Select the indices of every eligible recipient into `sink`, in ascending
/// order. Fails before writing anything when the sink cannot hold them all,
/// so a returned error leaves a fully-consistent (reset) sink count.
///
/// Returns the selected slice borrowed from the sink's buffer.
pub fn select(recipients: []const Recipient, sink: *IndexSink) SelectError![]const usize {
    sink.reset();

    const needed = eligibleCount(recipients);
    if (needed > sink.buf.len) return error.OutputTooSmall;

    for (recipients, 0..) |r, index| {
        if (r.eligible()) try sink.append(index);
    }
    return sink.slice();
}

/// Format the GLOBOPS broadcast wire line into `out` using the default
/// `Params`. Returns a slice of `out` ending in CR-LF.
pub fn formatLine(
    out: []u8,
    server_name: []const u8,
    oper_name: []const u8,
    text: []const u8,
) FormatError![]const u8 {
    return formatLineBounded(.{}, out, server_name, oper_name, text);
}

/// Format the GLOBOPS broadcast wire line into `out` using explicit `bounds`.
/// The produced line has the shape:
///
///   `:<server> NOTICE * :*** Global -- from <oper>: <text>\r\n`
///
/// `text` is copied into the line with control bytes stripped: any byte below
/// ASCII space (NUL, CR, LF, BEL, …) or the DEL byte (0x7f) is dropped so a
/// hostile broadcast cannot inject extra protocol lines or terminal control
/// sequences. The `<oper>` and `<server>` tokens are validated to contain no
/// control bytes rather than being stripped, because a corrupt identity is a
/// caller bug, not untrusted free text.
///
/// Returns a slice of `out`; the caller owns the backing buffer.
pub fn formatLineBounded(
    comptime bounds: Params,
    out: []u8,
    server_name: []const u8,
    oper_name: []const u8,
    text: []const u8,
) FormatError![]const u8 {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > bounds.max_server_name_bytes) return error.ServerNameTooLong;
    if (containsControlByte(server_name)) return error.InvalidServerName;

    if (oper_name.len == 0) return error.InvalidOper;
    if (oper_name.len > bounds.max_oper_bytes) return error.OperTooLong;
    if (containsControlByte(oper_name)) return error.InvalidOper;

    if (text.len == 0) return error.EmptyText;
    if (text.len > bounds.max_text_bytes) return error.TextTooLong;

    var writer = BufferWriter.init(out);
    try writer.appendByte(':');
    try writer.appendBytes(server_name);
    try writer.appendBytes(" NOTICE * :");
    try writer.appendBytes(global_marker);
    try writer.appendBytes(oper_name);
    try writer.appendBytes(": ");
    try writer.appendStripped(text);
    try writer.appendBytes("\r\n");

    if (writer.len > bounds.max_line_bytes) return error.OutputTooSmall;
    return writer.slice();
}

/// True when `text` contains any ASCII control byte (below space) or DEL.
fn containsControlByte(text: []const u8) bool {
    for (text) |byte| {
        if (isControlByte(byte)) return true;
    }
    return false;
}

/// Control bytes are everything below ASCII space plus the DEL byte. These are
/// stripped from free-form broadcast text to prevent line injection.
fn isControlByte(byte: u8) bool {
    return byte < ' ' or byte == 0x7f;
}

/// Bounded sink that appends into a caller-owned buffer, refusing to write
/// past the end. Mirrors the writer style used across `proto`/`daemon`.
const BufferWriter = struct {
    out: []u8,
    len: usize = 0,

    fn init(out: []u8) BufferWriter {
        return .{ .out = out };
    }

    fn slice(self: *const BufferWriter) []const u8 {
        return self.out[0..self.len];
    }

    fn appendBytes(self: *BufferWriter, bytes: []const u8) FormatError!void {
        if (self.len > self.out.len or bytes.len > self.out.len - self.len) {
            return error.OutputTooSmall;
        }
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *BufferWriter, byte: u8) FormatError!void {
        if (self.len >= self.out.len) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }

    /// Append `bytes` while dropping control bytes (line-injection guard).
    fn appendStripped(self: *BufferWriter, bytes: []const u8) FormatError!void {
        for (bytes) |byte| {
            if (isControlByte(byte)) continue;
            try self.appendByte(byte);
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "eligible requires both oper status and globops snomask" {
    try std.testing.expect((Recipient{ .is_oper = true, .sno_has_globops = true }).eligible());
    try std.testing.expect(!(Recipient{ .is_oper = true, .sno_has_globops = false }).eligible());
    try std.testing.expect(!(Recipient{ .is_oper = false, .sno_has_globops = true }).eligible());
    try std.testing.expect(!(Recipient{ .is_oper = false, .sno_has_globops = false }).eligible());
}

test "select filters to opers subscribed to globops in ascending order" {
    // Arrange
    const recipients = [_]Recipient{
        .{ .is_oper = true, .sno_has_globops = true }, // 0: eligible
        .{ .is_oper = true, .sno_has_globops = false }, // 1: oper, no sno
        .{ .is_oper = false, .sno_has_globops = true }, // 2: sno, not oper
        .{ .is_oper = false, .sno_has_globops = false }, // 3: neither
        .{ .is_oper = true, .sno_has_globops = true }, // 4: eligible
    };
    var buf: [5]usize = undefined;
    var sink = IndexSink.init(&buf);

    // Act
    const selected = try select(&recipients, &sink);

    // Assert
    try std.testing.expectEqual(@as(usize, 2), selected.len);
    try std.testing.expectEqual(@as(usize, 0), selected[0]);
    try std.testing.expectEqual(@as(usize, 4), selected[1]);
    try std.testing.expectEqual(@as(usize, 2), eligibleCount(&recipients));
}

test "select with no eligible recipients yields empty selection" {
    // Arrange
    const recipients = [_]Recipient{
        .{ .is_oper = true, .sno_has_globops = false },
        .{ .is_oper = false, .sno_has_globops = true },
    };
    var buf: [2]usize = undefined;
    var sink = IndexSink.init(&buf);

    // Act
    const selected = try select(&recipients, &sink);

    // Assert
    try std.testing.expectEqual(@as(usize, 0), selected.len);
    try std.testing.expectEqual(@as(usize, 0), sink.count);
}

test "select on an empty recipient slice is an empty selection" {
    var buf: [1]usize = undefined;
    var sink = IndexSink.init(&buf);
    const selected = try select(&.{}, &sink);
    try std.testing.expectEqual(@as(usize, 0), selected.len);
}

test "select reports too-small sinks without partial fan-out" {
    // Arrange: two eligible recipients but room for only one index.
    const recipients = [_]Recipient{
        .{ .is_oper = true, .sno_has_globops = true },
        .{ .is_oper = true, .sno_has_globops = true },
    };
    var buf: [1]usize = undefined;
    var sink = IndexSink.init(&buf);

    // Assert: the whole selection is refused, sink left consistent.
    try std.testing.expectError(error.OutputTooSmall, select(&recipients, &sink));
    try std.testing.expectEqual(@as(usize, 0), sink.count);
}

test "select reset reuses the sink across publishes" {
    const first = [_]Recipient{.{ .is_oper = true, .sno_has_globops = true }};
    const second = [_]Recipient{
        .{ .is_oper = false, .sno_has_globops = true },
        .{ .is_oper = true, .sno_has_globops = true },
    };
    var buf: [4]usize = undefined;
    var sink = IndexSink.init(&buf);

    const a = try select(&first, &sink);
    try std.testing.expectEqual(@as(usize, 1), a.len);
    try std.testing.expectEqual(@as(usize, 0), a[0]);

    const b = try select(&second, &sink);
    try std.testing.expectEqual(@as(usize, 1), b.len);
    try std.testing.expectEqual(@as(usize, 1), b[0]);
}

test "formatLine produces the expected GLOBOPS wire line" {
    // Arrange
    var out: [128]u8 = undefined;

    // Act
    const line = try formatLine(&out, "irc.example.test", "rootop", "rolling restart in 5");

    // Assert
    try std.testing.expectEqualStrings(
        ":irc.example.test NOTICE * :*** Global -- from rootop: rolling restart in 5\r\n",
        line,
    );
}

test "formatLine strips control bytes from text to block line injection" {
    // Arrange: an attacker tries to inject a second protocol line and a BEL.
    var out: [256]u8 = undefined;
    const hostile = "hi\r\n:evil.server PRIVMSG #c :pwned\x07 end\x00";

    // Act
    const line = try formatLine(&out, "irc.example.test", "op", hostile);

    // Assert: every control byte (CR, LF, BEL, NUL) is gone; only the trailing
    // CR-LF terminator remains, so no extra line can be smuggled in.
    try std.testing.expectEqualStrings(
        ":irc.example.test NOTICE * :*** Global -- from op: hi:evil.server PRIVMSG #c :pwned end\r\n",
        line,
    );
}

test "formatLine rejects empty and oversized server name" {
    var out: [128]u8 = undefined;
    const Tiny = Params{ .max_server_name_bytes = 3 };

    try std.testing.expectError(error.InvalidServerName, formatLine(&out, "", "op", "hi"));
    try std.testing.expectError(
        error.ServerNameTooLong,
        formatLineBounded(Tiny, &out, "long.name", "op", "hi"),
    );
}

test "formatLine rejects control bytes in server and oper identity" {
    var out: [128]u8 = undefined;

    try std.testing.expectError(
        error.InvalidServerName,
        formatLine(&out, "bad\nserver", "op", "hi"),
    );
    try std.testing.expectError(
        error.InvalidOper,
        formatLine(&out, "irc.example.test", "bad\rop", "hi"),
    );
}

test "formatLine rejects empty and oversized oper name" {
    var out: [128]u8 = undefined;
    const Tiny = Params{ .max_oper_bytes = 2 };

    try std.testing.expectError(error.InvalidOper, formatLine(&out, "s", "", "hi"));
    try std.testing.expectError(
        error.OperTooLong,
        formatLineBounded(Tiny, &out, "s", "toolong", "hi"),
    );
}

test "formatLine enforces text bounds and emptiness" {
    var out: [256]u8 = undefined;
    const Tiny = Params{ .max_text_bytes = 4 };

    try std.testing.expectError(error.EmptyText, formatLine(&out, "s", "op", ""));
    try std.testing.expectError(
        error.TextTooLong,
        formatLineBounded(Tiny, &out, "s", "op", "toolong"),
    );
}

test "formatLine reports output too small for the destination buffer" {
    var out: [8]u8 = undefined;
    try std.testing.expectError(
        error.OutputTooSmall,
        formatLine(&out, "irc.example.test", "op", "text"),
    );
}

test "formatLineBounded enforces the max line length cap" {
    // Arrange: the buffer is large, but the configured line cap is tiny.
    var out: [256]u8 = undefined;
    const Capped = Params{ .max_line_bytes = 32 };

    // Assert: formatting succeeds into the buffer but exceeds the line cap.
    try std.testing.expectError(
        error.OutputTooSmall,
        formatLineBounded(Capped, &out, "irc.example.test", "op", "a reasonably long message"),
    );
}

test "end to end select then format a broadcast for each recipient" {
    // Arrange: three sessions, two eligible.
    const recipients = [_]Recipient{
        .{ .is_oper = true, .sno_has_globops = true },
        .{ .is_oper = true, .sno_has_globops = false },
        .{ .is_oper = true, .sno_has_globops = true },
    };
    var index_buf: [3]usize = undefined;
    var sink = IndexSink.init(&index_buf);

    // Act: select recipients, then format the one shared line.
    const selected = try select(&recipients, &sink);
    var line_buf: [128]u8 = undefined;
    const line = try formatLine(&line_buf, "mesh.example.test", "netadmin", "mesh degraded");

    // Assert
    try std.testing.expectEqual(@as(usize, 2), selected.len);
    try std.testing.expectEqual(@as(usize, 0), selected[0]);
    try std.testing.expectEqual(@as(usize, 2), selected[1]);
    try std.testing.expectEqualStrings(
        ":mesh.example.test NOTICE * :*** Global -- from netadmin: mesh degraded\r\n",
        line,
    );
}
