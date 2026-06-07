//! Minimal Markdown to IRC formatting-code conversion for the web/bridge path.
//!
//! Bridges chat surfaces that author messages in Markdown (web clients, bots,
//! external bridges) into the IRC formatting control bytes understood by IRC
//! clients. Only a small, well-defined subset of inline Markdown is recognized:
//!
//!   - `**bold**`   / `__bold__`   -> \x02 ... \x02   (bold)
//!   - `*italic*`   / `_italic_`   -> \x1d ... \x1d   (italic)
//!   - `` `code` ``                -> \x11 ... \x11   (monospace)
//!   - `~~strike~~`                -> \x1e ... \x1e   (strikethrough)
//!
//! All other text passes through verbatim. A marker that has no closing partner
//! is emitted literally so that lopsided input never silently loses characters.
//! Conversion writes into a caller-supplied buffer and never allocates.

const std = @import("std");

/// IRC formatting control bytes emitted by this module.
pub const Control = struct {
    pub const bold: u8 = 0x02;
    pub const monospace: u8 = 0x11;
    pub const italic: u8 = 0x1d;
    pub const strike: u8 = 0x1e;
};

/// Errors returned by conversion routines.
pub const Error = error{
    /// The caller buffer was too small to hold the result.
    OutputTooSmall,
};

/// A recognized inline marker and the metadata needed to process it.
const Marker = struct {
    /// Number of source bytes the marker occupies (1 or 2).
    width: usize,
    /// IRC control byte to emit when converting (only used by `toIrc`).
    control: u8,
};

/// Identify a recognized opening/closing marker at `md[index]`, if any.
fn markerAt(md: []const u8, index: usize) ?Marker {
    const c = md[index];
    const next: ?u8 = if (index + 1 < md.len) md[index + 1] else null;

    return switch (c) {
        '*' => if (next == @as(u8, '*'))
            Marker{ .width = 2, .control = Control.bold }
        else
            Marker{ .width = 1, .control = Control.italic },
        '_' => if (next == @as(u8, '_'))
            Marker{ .width = 2, .control = Control.bold }
        else
            Marker{ .width = 1, .control = Control.italic },
        '~' => if (next == @as(u8, '~'))
            Marker{ .width = 2, .control = Control.strike }
        else
            null,
        '`' => Marker{ .width = 1, .control = Control.monospace },
        else => null,
    };
}

/// Return the index just past a matching closing marker that equals the bytes
/// `md[open .. open + width]`, searching after the opening run. Returns null
/// when no closing partner exists.
fn findClose(md: []const u8, open: usize, width: usize) ?usize {
    const pattern = md[open .. open + width];
    var i = open + width;
    while (i + width <= md.len) : (i += 1) {
        if (std.mem.eql(u8, md[i .. i + width], pattern)) return i;
    }
    return null;
}

/// Append `byte` to `out` at `*written`, advancing the cursor.
fn put(out: []u8, written: *usize, byte: u8) Error!void {
    if (written.* >= out.len) return error.OutputTooSmall;
    out[written.*] = byte;
    written.* += 1;
}

/// Append `bytes` to `out` at `*written`, advancing the cursor.
fn putSlice(out: []u8, written: *usize, bytes: []const u8) Error!void {
    for (bytes) |b| try put(out, written, b);
}

/// Convert Markdown `md` into IRC-formatted text written to `out`.
///
/// Returns the written slice of `out`. Unmatched markers are emitted literally.
pub fn toIrc(out: []u8, md: []const u8) Error![]const u8 {
    var written: usize = 0;
    var read: usize = 0;

    while (read < md.len) {
        if (markerAt(md, read)) |marker| {
            if (findClose(md, read, marker.width)) |close| {
                // Emit control, inner text, control. Inner text may itself
                // contain markers; convert it recursively.
                try put(out, &written, marker.control);
                const inner = try toIrc(out[written..], md[read + marker.width .. close]);
                written += inner.len;
                try put(out, &written, marker.control);
                read = close + marker.width;
                continue;
            }
            // No closing partner: emit the marker bytes literally.
            try putSlice(out, &written, md[read .. read + marker.width]);
            read += marker.width;
            continue;
        }

        try put(out, &written, md[read]);
        read += 1;
    }

    return out[0..written];
}

/// Strip recognized Markdown markers from `md`, writing plain text to `out`.
///
/// Returns the written slice of `out`. Unmatched markers are kept literally.
pub fn stripMarkdown(out: []u8, md: []const u8) Error![]const u8 {
    var written: usize = 0;
    var read: usize = 0;

    while (read < md.len) {
        if (markerAt(md, read)) |marker| {
            if (findClose(md, read, marker.width)) |close| {
                const inner = try stripMarkdown(out[written..], md[read + marker.width .. close]);
                written += inner.len;
                read = close + marker.width;
                continue;
            }
            try putSlice(out, &written, md[read .. read + marker.width]);
            read += marker.width;
            continue;
        }

        try put(out, &written, md[read]);
        read += 1;
    }

    return out[0..written];
}

test "toIrc converts bold with asterisks" {
    var buf: [64]u8 = undefined;
    const got = try toIrc(&buf, "a **b** c");
    try std.testing.expectEqualStrings("a \x02b\x02 c", got);
}

test "toIrc converts bold with underscores" {
    var buf: [64]u8 = undefined;
    const got = try toIrc(&buf, "__b__");
    try std.testing.expectEqualStrings("\x02b\x02", got);
}

test "toIrc converts italic with asterisk and underscore" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("\x1dx\x1d", try toIrc(&buf, "*x*"));
    var buf2: [64]u8 = undefined;
    try std.testing.expectEqualStrings("\x1dy\x1d", try toIrc(&buf2, "_y_"));
}

test "toIrc converts inline code to monospace" {
    var buf: [64]u8 = undefined;
    const got = try toIrc(&buf, "run `cmd` now");
    try std.testing.expectEqualStrings("run \x11cmd\x11 now", got);
}

test "toIrc converts strikethrough" {
    var buf: [64]u8 = undefined;
    const got = try toIrc(&buf, "~~gone~~");
    try std.testing.expectEqualStrings("\x1egone\x1e", got);
}

test "toIrc handles nested styles" {
    var buf: [64]u8 = undefined;
    const got = try toIrc(&buf, "**bold _and italic_**");
    try std.testing.expectEqualStrings("\x02bold \x1dand italic\x1d\x02", got);
}

test "toIrc handles adjacent styles" {
    var buf: [64]u8 = undefined;
    const got = try toIrc(&buf, "**a**`b`");
    try std.testing.expectEqualStrings("\x02a\x02\x11b\x11", got);
}

test "toIrc emits unmatched marker literally" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("a * b", try toIrc(&buf, "a * b"));
    var buf2: [64]u8 = undefined;
    try std.testing.expectEqualStrings("**oops", try toIrc(&buf2, "**oops"));
}

test "toIrc leaves plain text verbatim" {
    var buf: [64]u8 = undefined;
    const got = try toIrc(&buf, "nothing special here");
    try std.testing.expectEqualStrings("nothing special here", got);
}

test "toIrc returns OutputTooSmall when buffer is exhausted" {
    var buf: [3]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, toIrc(&buf, "**bold**"));
}

test "stripMarkdown removes all recognized markers" {
    var buf: [64]u8 = undefined;
    const got = try stripMarkdown(&buf, "**b** *i* `c` ~~s~~ __u__");
    try std.testing.expectEqualStrings("b i c s u", got);
}

test "stripMarkdown keeps unmatched markers literally" {
    var buf: [64]u8 = undefined;
    const got = try stripMarkdown(&buf, "a ~~ b");
    try std.testing.expectEqualStrings("a ~~ b", got);
}

test "stripMarkdown handles nested markers" {
    var buf: [64]u8 = undefined;
    const got = try stripMarkdown(&buf, "**bold _and italic_**");
    try std.testing.expectEqualStrings("bold and italic", got);
}

test "stripMarkdown returns OutputTooSmall when buffer is exhausted" {
    var buf: [2]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, stripMarkdown(&buf, "**bold**"));
}
