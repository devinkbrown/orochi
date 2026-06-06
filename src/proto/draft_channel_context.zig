//! IRCv3 draft/channel-context tag parser and relay helper.
//!
//! The module validates the value of `+draft/channel-context`, and can attach
//! or remove that client-only tag from a normalized IRCv3 tag segment. Returned
//! tag segments never include the leading `@` or trailing render-space.
const std = @import("std");

comptime {
    if (@sizeOf(usize) != 8) @compileError("draft/channel-context requires a 64-bit target");
}

/// IRCv3 client-only message tag key for channel context on direct messages.
pub const TAG_KEY = "+draft/channel-context";

/// Maximum IRCv3 message tag segment bytes accepted by the default helpers.
pub const MAX_TAG_SEGMENT: usize = 8191;

/// Validation and rendering limits for channel-context tags.
pub const Params = struct {
    /// Maximum bytes in the validated channel name.
    max_channel_bytes: usize = 64,
    /// Maximum bytes in an incoming tag segment, excluding a leading `@`.
    max_tag_segment_bytes: usize = MAX_TAG_SEGMENT,
    /// Maximum bytes in an emitted tag segment, excluding a leading `@`.
    max_output_bytes: usize = MAX_TAG_SEGMENT,
};

/// Errors returned by channel-context parsing and tag relay helpers.
pub const ChannelContextError = error{
    MissingValue,
    InvalidChannel,
    ChannelTooLong,
    OutputTooSmall,
    OversizeTags,
    MalformedTags,
    InvalidTagKey,
    InvalidTagValue,
    DuplicateContext,
};

/// A validated channel-context association.
pub const ChannelContext = struct {
    /// Channel name associated with a direct message.
    channel: []const u8,

    /// Validate `channel` with default limits and wrap it.
    pub fn init(channel: []const u8) ChannelContextError!ChannelContext {
        return initWith(.{}, channel);
    }

    /// Validate `channel` with custom limits and wrap it.
    pub fn initWith(comptime params: Params, channel: []const u8) ChannelContextError!ChannelContext {
        return .{ .channel = try parseWith(params, channel) };
    }

    /// Return the validated channel bytes.
    pub fn value(self: ChannelContext) []const u8 {
        return self.channel;
    }

    /// Attach this context to `raw_tags` using default limits.
    pub fn attachTo(self: ChannelContext, raw_tags: ?[]const u8, out: []u8) ChannelContextError![]const u8 {
        return attach(raw_tags, self.channel, out);
    }
};

/// Result of stripping a channel-context tag from a tag segment.
pub const StripResult = struct {
    /// Normalized tag segment with the channel-context tag removed.
    tags: []const u8,
    /// Validated channel value removed from the input, or null when absent.
    channel: ?[]const u8,
};

/// Parse and validate a decoded `+draft/channel-context` tag value.
pub fn parse(tag_value: []const u8) ChannelContextError![]const u8 {
    return parseWith(.{}, tag_value);
}

/// Parse and validate a decoded `+draft/channel-context` tag value with custom limits.
pub fn parseWith(comptime params: Params, tag_value: []const u8) ChannelContextError![]const u8 {
    if (tag_value.len == 0) return error.MissingValue;
    try validateChannelWith(params, tag_value);
    return tag_value;
}

/// Validate a tag-safe IRC channel name with default limits.
pub fn validateChannel(channel: []const u8) ChannelContextError!void {
    return validateChannelWith(.{}, channel);
}

/// Validate a tag-safe IRC channel name with custom limits.
pub fn validateChannelWith(comptime params: Params, channel: []const u8) ChannelContextError!void {
    if (channel.len == 0) return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (!isChannelPrefix(channel[0])) return error.InvalidChannel;
    if (channel.len == 1) return error.InvalidChannel;

    for (channel[1..]) |byte| {
        if (!isChannelByte(byte)) return error.InvalidChannel;
    }
}

/// Attach a channel-context tag to a normalized tag segment.
///
/// `raw_tags` may be null, empty, or begin with `@`; the returned segment never
/// begins with `@`. An existing channel-context tag is validated and replaced.
pub fn attach(raw_tags: ?[]const u8, channel: []const u8, out: []u8) ChannelContextError![]const u8 {
    return attachWith(.{}, raw_tags, channel, out);
}

/// Attach a channel-context tag to a normalized tag segment with custom limits.
pub fn attachWith(
    comptime params: Params,
    raw_tags: ?[]const u8,
    channel: []const u8,
    out: []u8,
) ChannelContextError![]const u8 {
    const checked_channel = try parseWith(params, channel);
    var writer = TagWriter.init(out, params.max_output_bytes);
    var removed_channel: ?[]const u8 = null;

    try copySansContext(params, raw_tags, &writer, &removed_channel);
    try writer.writeContext(checked_channel);
    return writer.slice();
}

/// Strip a channel-context tag from a normalized tag segment.
///
/// `raw_tags` may be null, empty, or begin with `@`; the returned segment never
/// begins with `@`. The removed channel slice points into `raw_tags`.
pub fn strip(raw_tags: ?[]const u8, out: []u8) ChannelContextError!StripResult {
    return stripWith(.{}, raw_tags, out);
}

/// Strip a channel-context tag from a normalized tag segment with custom limits.
pub fn stripWith(
    comptime params: Params,
    raw_tags: ?[]const u8,
    out: []u8,
) ChannelContextError!StripResult {
    var writer = TagWriter.init(out, params.max_output_bytes);
    var removed_channel: ?[]const u8 = null;

    try copySansContext(params, raw_tags, &writer, &removed_channel);
    return .{ .tags = writer.slice(), .channel = removed_channel };
}

fn copySansContext(
    comptime params: Params,
    raw_tags: ?[]const u8,
    writer: *TagWriter,
    removed_channel: *?[]const u8,
) ChannelContextError!void {
    const segment = try normalizeTagSegment(params, raw_tags);
    if (segment.len == 0) return;

    var cursor: usize = 0;
    while (cursor <= segment.len) {
        const next = std.mem.indexOfScalarPos(u8, segment, cursor, ';') orelse segment.len;
        if (next == cursor) return error.MalformedTags;

        const item = segment[cursor..next];
        const eq = std.mem.indexOfScalar(u8, item, '=');
        const key = if (eq) |pos| item[0..pos] else item;
        const value = if (eq) |pos| item[pos + 1 ..] else null;

        if (!validTagKey(key)) return error.InvalidTagKey;
        if (value) |raw_value| try validateRawTagValue(raw_value);

        if (std.mem.eql(u8, key, TAG_KEY)) {
            if (removed_channel.* != null) return error.DuplicateContext;
            const tag_value = value orelse return error.MissingValue;
            removed_channel.* = try parseWith(params, tag_value);
        } else {
            try writer.writeRaw(item);
        }

        if (next == segment.len) break;
        cursor = next + 1;
    }
}

fn normalizeTagSegment(comptime params: Params, raw_tags: ?[]const u8) ChannelContextError![]const u8 {
    const raw = raw_tags orelse return "";
    if (raw.len == 0) return "";

    const segment = if (raw[0] == '@') blk: {
        if (raw.len == 1) return error.MalformedTags;
        break :blk raw[1..];
    } else raw;

    if (segment.len > params.max_tag_segment_bytes) return error.OversizeTags;
    for (segment) |byte| {
        switch (byte) {
            0, '\r', '\n', ' ' => return error.MalformedTags,
            else => {},
        }
    }
    return segment;
}

fn validateRawTagValue(value: []const u8) ChannelContextError!void {
    for (value) |byte| {
        switch (byte) {
            0, '\r', '\n', ' ' => return error.InvalidTagValue,
            else => {},
        }
    }
}

fn validTagKey(key: []const u8) bool {
    if (key.len == 0) return false;

    const start: usize = if (key[0] == '+') 1 else 0;
    if (start == key.len) return false;

    for (key[start..]) |byte| {
        switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '/', '_' => {},
            else => return false,
        }
    }
    return true;
}

fn isChannelPrefix(byte: u8) bool {
    return switch (byte) {
        '#', '&', '+', '!' => true,
        else => false,
    };
}

fn isChannelByte(byte: u8) bool {
    return switch (byte) {
        0...0x20, 0x7f, ',', ';', '\\' => false,
        else => true,
    };
}

const TagWriter = struct {
    out: []u8,
    max_len: usize,
    len: usize = 0,
    count: usize = 0,

    fn init(out: []u8, max_len: usize) TagWriter {
        return .{ .out = out, .max_len = max_len };
    }

    fn slice(self: *const TagWriter) []const u8 {
        return self.out[0..self.len];
    }

    fn writeRaw(self: *TagWriter, item: []const u8) ChannelContextError!void {
        try self.begin();
        try self.append(item);
    }

    fn writeContext(self: *TagWriter, channel: []const u8) ChannelContextError!void {
        try self.begin();
        try self.append(TAG_KEY);
        try self.appendByte('=');
        try self.append(channel);
    }

    fn begin(self: *TagWriter) ChannelContextError!void {
        if (self.count != 0) try self.appendByte(';');
        self.count += 1;
    }

    fn append(self: *TagWriter, bytes: []const u8) ChannelContextError!void {
        if (bytes.len > self.max_len - self.len) return error.OversizeTags;
        if (bytes.len > self.out.len - self.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *TagWriter, byte: u8) ChannelContextError!void {
        if (self.len == self.max_len) return error.OversizeTags;
        if (self.len == self.out.len) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test "parse accepts valid tag safe channel names" {
    _ = std.testing.allocator;

    const hash = try parse("#chan");
    const amp = try parse("&operators");
    const local = try parse("+local");
    const bang = try parse("!abcdecontext");
    const unicode = try parse("#mizu\xe3\x81\xa1");

    try std.testing.expectEqualStrings("#chan", hash);
    try std.testing.expectEqualStrings("&operators", amp);
    try std.testing.expectEqualStrings("+local", local);
    try std.testing.expectEqualStrings("!abcdecontext", bang);
    try std.testing.expectEqualStrings("#mizu\xe3\x81\xa1", unicode);
}

test "parse rejects missing malformed and oversized channel names" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.MissingValue, parse(""));
    try std.testing.expectError(error.InvalidChannel, parse("chan"));
    try std.testing.expectError(error.InvalidChannel, parse("#"));
    try std.testing.expectError(error.InvalidChannel, parse("#bad name"));
    try std.testing.expectError(error.InvalidChannel, parse("#bad,comma"));
    try std.testing.expectError(error.InvalidChannel, parse("#bad;semicolon"));
    try std.testing.expectError(error.InvalidChannel, parse("#bad\\slash"));
    try std.testing.expectError(error.InvalidChannel, parse("#bad\x07bell"));

    var too_long = try allocator.alloc(u8, (Params{}).max_channel_bytes + 1);
    defer allocator.free(too_long);
    too_long[0] = '#';
    @memset(too_long[1..], 'a');
    try std.testing.expectError(error.ChannelTooLong, parse(too_long));

    try std.testing.expectError(
        error.ChannelTooLong,
        parseWith(.{ .max_channel_bytes = 5 }, "#sixxx"),
    );
}

test "attach adds channel context to empty and existing tag segments" {
    _ = std.testing.allocator;
    var out: [192]u8 = undefined;

    const only = try attach(null, "#chan", &out);
    try std.testing.expectEqualStrings("+draft/channel-context=#chan", only);

    const merged = try attach("account=alice;+typing=active", "#team", &out);
    try std.testing.expectEqualStrings(
        "account=alice;+typing=active;+draft/channel-context=#team",
        merged,
    );

    const from_prefix = try attach("@account=alice", "#team", &out);
    try std.testing.expectEqualStrings("account=alice;+draft/channel-context=#team", from_prefix);
}

test "attach replaces an existing valid channel context" {
    _ = std.testing.allocator;
    var out: [192]u8 = undefined;

    const replaced = try attach(
        "account=alice;+draft/channel-context=#old;+typing=active",
        "#new",
        &out,
    );

    try std.testing.expectEqualStrings(
        "account=alice;+typing=active;+draft/channel-context=#new",
        replaced,
    );
}

test "strip removes channel context and reports validated channel" {
    _ = std.testing.allocator;
    var out: [192]u8 = undefined;

    const result = try strip(
        "account=alice;+draft/channel-context=#chan;+typing=active",
        &out,
    );

    try std.testing.expectEqualStrings("account=alice;+typing=active", result.tags);
    try std.testing.expect(result.channel != null);
    try std.testing.expectEqualStrings("#chan", result.channel.?);

    const none = try strip("@account=alice;+typing=active", &out);
    try std.testing.expectEqualStrings("account=alice;+typing=active", none.tags);
    try std.testing.expect(none.channel == null);
}

test "attach and strip round trip without changing unrelated tags" {
    _ = std.testing.allocator;
    var attached_buf: [192]u8 = undefined;
    var stripped_buf: [192]u8 = undefined;

    const original = "account=alice;+typing=active;draft/label=server";
    const attached = try attach(original, "#context", &attached_buf);
    const stripped = try strip(attached, &stripped_buf);

    try std.testing.expectEqualStrings(original, stripped.tags);
    try std.testing.expect(stripped.channel != null);
    try std.testing.expectEqualStrings("#context", stripped.channel.?);

    // Copy the borrowed channel slice (it points into attached_buf) and write to
    // a fresh buffer so the re-attach never aliases its inputs.
    var chan_buf: [64]u8 = undefined;
    const chan = chan_buf[0..stripped.channel.?.len];
    @memcpy(chan, stripped.channel.?);
    var again_buf: [192]u8 = undefined;
    const attached_again = try attach(stripped.tags, chan, &again_buf);
    try std.testing.expectEqualStrings(attached, attached_again);
}

test "tag segment validation rejects malformed inputs" {
    _ = std.testing.allocator;
    var out: [128]u8 = undefined;

    try std.testing.expectError(error.MalformedTags, strip("@", &out));
    try std.testing.expectError(error.MalformedTags, strip("account=alice;", &out));
    try std.testing.expectError(error.InvalidTagKey, strip("++bad=value", &out));
    try std.testing.expectError(error.MalformedTags, strip("+ok=bad value", &out));
    try std.testing.expectError(error.MissingValue, strip("+draft/channel-context", &out));
    try std.testing.expectError(error.InvalidChannel, strip("+draft/channel-context=chan", &out));
    try std.testing.expectError(
        error.DuplicateContext,
        strip("+draft/channel-context=#a;+draft/channel-context=#b", &out),
    );
}

test "attach and strip respect output and segment limits" {
    const allocator = std.testing.allocator;
    var tiny: [4]u8 = undefined;

    try std.testing.expectError(error.OutputTooSmall, attach(null, "#chan", &tiny));

    const segment = try allocator.alloc(u8, MAX_TAG_SEGMENT + 1);
    defer allocator.free(segment);
    @memset(segment, 'a');

    var out: [64]u8 = undefined;
    try std.testing.expectError(error.OversizeTags, strip(segment, &out));
    try std.testing.expectError(
        error.OversizeTags,
        attachWith(.{ .max_output_bytes = TAG_KEY.len + 4 }, null, "#chan", &out),
    );
}
