//! IRCv3 draft/chathistory query model and selector parsing.
//!
//! This module handles the protocol-facing side of CHATHISTORY: parsing the
//! textual subcommands (LATEST, BEFORE, AFTER, AROUND, BETWEEN), resolving
//! `msgid=<id>`, `timestamp=<ISO8601>`, and `*` selectors against a caller-
//! supplied ordered message list, validating limits against a server maximum,
//! and returning the correct message window per spec semantics.
//!
//! Storage is intentionally excluded. The caller passes a slice of `Message`
//! structs ordered oldest-first; this module returns index ranges or copies
//! into a caller-owned output buffer.
const std = @import("std");

pub const ParseError = error{
    UnknownSubcommand,
    MalformedSelector,
    MalformedMsgid,
    MalformedTimestamp,
    LimitExceedsMax,
    InvalidLimit,
    InvalidRange,
    OutputTooSmall,
};

/// Microseconds since the Unix epoch, UTC. Maps to the `server-time` tag format.
pub const Timestamp = i64;

/// Parse an ISO 8601 UTC datetime string of the form
/// `YYYY-MM-DDTHH:MM:SS.uuuuuuZ` (variable fractional digits, 0–6).
///
/// Returns microseconds since the Unix epoch.
pub fn parseTimestamp(s: []const u8) ParseError!Timestamp {
    // Minimum: "YYYY-MM-DDTHH:MM:SSZ" = 20 chars
    if (s.len < 20) return error.MalformedTimestamp;
    if (s[s.len - 1] != 'Z') return error.MalformedTimestamp;

    const year = parseDigits(s[0..4]) catch return error.MalformedTimestamp;
    if (s[4] != '-') return error.MalformedTimestamp;
    const month = parseDigits(s[5..7]) catch return error.MalformedTimestamp;
    if (s[7] != '-') return error.MalformedTimestamp;
    const day = parseDigits(s[8..10]) catch return error.MalformedTimestamp;
    if (s[10] != 'T') return error.MalformedTimestamp;
    const hour = parseDigits(s[11..13]) catch return error.MalformedTimestamp;
    if (s[13] != ':') return error.MalformedTimestamp;
    const minute = parseDigits(s[14..16]) catch return error.MalformedTimestamp;
    if (s[16] != ':') return error.MalformedTimestamp;
    const second = parseDigits(s[17..19]) catch return error.MalformedTimestamp;

    if (month < 1 or month > 12) return error.MalformedTimestamp;
    if (day < 1 or day > 31) return error.MalformedTimestamp;
    if (hour > 23 or minute > 59 or second > 60) return error.MalformedTimestamp;

    var frac_us: i64 = 0;
    var pos: usize = 19;
    if (pos < s.len - 1) {
        if (s[pos] != '.') return error.MalformedTimestamp;
        pos += 1;
        const frac_start = pos;
        while (pos < s.len - 1) : (pos += 1) {
            if (s[pos] < '0' or s[pos] > '9') return error.MalformedTimestamp;
        }
        const frac_len = pos - frac_start;
        if (frac_len == 0 or frac_len > 6) return error.MalformedTimestamp;
        const raw = parseDigits(s[frac_start..pos]) catch return error.MalformedTimestamp;
        var scale: i64 = 1;
        var pad = frac_len;
        while (pad < 6) : (pad += 1) scale *= 10;
        frac_us = @as(i64, @intCast(raw)) * scale;
    }
    if (pos != s.len - 1) return error.MalformedTimestamp;

    // Convert Gregorian date → days since Unix epoch (1970-01-01).
    const days = gregorianToDays(
        @intCast(year),
        @intCast(month),
        @intCast(day),
    );
    const secs: i64 = days * 86400 +
        @as(i64, @intCast(hour)) * 3600 +
        @as(i64, @intCast(minute)) * 60 +
        @as(i64, @intCast(second));

    return secs * 1_000_000 + frac_us;
}

fn parseDigits(s: []const u8) error{InvalidDigits}!u64 {
    if (s.len == 0) return error.InvalidDigits;
    var result: u64 = 0;
    for (s) |ch| {
        if (ch < '0' or ch > '9') return error.InvalidDigits;
        result = result * 10 + (ch - '0');
    }
    return result;
}

// Days since 1970-01-01 (Howard Hinnant civil_from_days inverse).
fn gregorianToDays(year: i32, month: u32, day: u32) i64 {
    const y: i64 = if (month <= 2) @as(i64, year) - 1 else @as(i64, year);
    const era: i64 = @divFloor(y, 400);
    const yoe: i64 = y - era * 400;
    const m: i64 = @as(i64, month);
    const doy: i64 = @divFloor(153 * (if (m > 2) m - 3 else m + 9) + 2, 5) + @as(i64, day) - 1;
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// A parsed CHATHISTORY selector: `*`, `msgid=<id>`, or `timestamp=<ISO8601Z>`.
pub const Selector = union(enum) {
    wildcard,
    msgid: []const u8,
    timestamp: Timestamp,
};

/// Parse a raw selector token. `Selector.msgid` borrows from `raw`.
pub fn parseSelector(raw: []const u8) ParseError!Selector {
    if (std.mem.eql(u8, raw, "*")) return .wildcard;

    if (std.mem.startsWith(u8, raw, "msgid=")) {
        const id = raw[6..];
        if (id.len == 0) return error.MalformedMsgid;
        // msgid values must not contain spaces, NUL, or CR/LF
        for (id) |ch| {
            if (ch == 0 or ch == ' ' or ch == '\r' or ch == '\n')
                return error.MalformedMsgid;
        }
        return .{ .msgid = id };
    }

    if (std.mem.startsWith(u8, raw, "timestamp=")) {
        const ts_str = raw[10..];
        const ts = try parseTimestamp(ts_str);
        return .{ .timestamp = ts };
    }

    return error.MalformedSelector;
}

pub const SubcommandTag = enum { latest, before, after, around, between };

/// A fully parsed CHATHISTORY query.
pub const Query = union(SubcommandTag) {
    latest: struct { selector: Selector, limit: usize },
    before: struct { anchor: Selector, limit: usize },
    after: struct { anchor: Selector, limit: usize },
    around: struct { anchor: Selector, limit: usize },
    between: struct { from: Selector, to: Selector, limit: usize },
};

/// Parse a CHATHISTORY subcommand name (case-insensitive).
pub fn parseSubcommand(name: []const u8) ParseError!SubcommandTag {
    // Uppercase compare without allocating
    var buf: [8]u8 = undefined;
    if (name.len > buf.len) return error.UnknownSubcommand;
    const upper = std.ascii.upperString(buf[0..name.len], name);
    if (std.mem.eql(u8, upper, "LATEST")) return .latest;
    if (std.mem.eql(u8, upper, "BEFORE")) return .before;
    if (std.mem.eql(u8, upper, "AFTER")) return .after;
    if (std.mem.eql(u8, upper, "AROUND")) return .around;
    if (std.mem.eql(u8, upper, "BETWEEN")) return .between;
    return error.UnknownSubcommand;
}

/// Parse a decimal limit string and validate it against `server_max`.
pub fn parseLimit(raw: []const u8, server_max: usize) ParseError!usize {
    const n = parseDigits(raw) catch return error.InvalidLimit;
    if (n > server_max) return error.LimitExceedsMax;
    return @intCast(n);
}

/// Build a `Query` from the already-split parameter tokens.
///
/// For LATEST/BEFORE/AFTER/AROUND: `params` = [selector, limit].
/// For BETWEEN: `params` = [selector_a, selector_b, limit].
/// The `target` param is assumed to be stripped before calling.
pub fn parseQuery(
    subcmd: SubcommandTag,
    params: []const []const u8,
    server_max: usize,
) ParseError!Query {
    switch (subcmd) {
        .latest, .before, .after, .around => {
            if (params.len < 2) return error.MalformedSelector;
            const sel = try parseSelector(params[0]);
            const limit = try parseLimit(params[1], server_max);
            return switch (subcmd) {
                .latest => .{ .latest = .{ .selector = sel, .limit = limit } },
                .before => .{ .before = .{ .anchor = sel, .limit = limit } },
                .after => .{ .after = .{ .anchor = sel, .limit = limit } },
                .around => .{ .around = .{ .anchor = sel, .limit = limit } },
                else => unreachable,
            };
        },
        .between => {
            if (params.len < 3) return error.MalformedSelector;
            const from = try parseSelector(params[0]);
            const to = try parseSelector(params[1]);
            const limit = try parseLimit(params[2], server_max);
            return .{ .between = .{ .from = from, .to = to, .limit = limit } };
        },
    }
}

/// One message in the ordered (oldest-first) caller-supplied store.
pub const Message = struct {
    msgid: []const u8,
    ts: Timestamp,
};

/// Apply a `Query` to an ordered (oldest-first) message slice.
/// `out` must be at least `limit` entries. Returns a sub-slice of `out`.
pub fn applyQuery(
    messages: []const Message,
    query: Query,
    out: []Message,
) ParseError![]const Message {
    return switch (query) {
        .latest => |q| applyLatest(messages, q.selector, q.limit, out),
        .before => |q| applyBefore(messages, q.anchor, q.limit, out),
        .after => |q| applyAfter(messages, q.anchor, q.limit, out),
        .around => |q| applyAround(messages, q.anchor, q.limit, out),
        .between => |q| applyBetween(messages, q.from, q.to, q.limit, out),
    };
}

// LATEST: newest `limit` messages; selector is an exclusive upper bound or `*`.
fn applyLatest(
    messages: []const Message,
    selector: Selector,
    limit: usize,
    out: []Message,
) ParseError![]const Message {
    if (out.len < limit) return error.OutputTooSmall;
    const window = switch (selector) {
        .wildcard => messages,
        .msgid => |id| messages[0..findMsgidExclusive(messages, id)],
        .timestamp => |ts| messages[0..findTimestampAtOrAfter(messages, ts)],
    };
    if (window.len == 0 or limit == 0) return out[0..0];
    const take = @min(window.len, limit);
    const start = window.len - take;
    @memcpy(out[0..take], window[start..]);
    return out[0..take];
}

// BEFORE: messages strictly before the anchor, newest `limit`.
fn applyBefore(
    messages: []const Message,
    anchor: Selector,
    limit: usize,
    out: []Message,
) ParseError![]const Message {
    if (out.len < limit) return error.OutputTooSmall;
    const end = switch (anchor) {
        .wildcard => messages.len,
        .msgid => |id| findMsgidExclusive(messages, id),
        .timestamp => |ts| findTimestampAtOrAfter(messages, ts),
    };
    const window = messages[0..end];
    if (window.len == 0 or limit == 0) return out[0..0];
    const take = @min(window.len, limit);
    const start = window.len - take;
    @memcpy(out[0..take], window[start..]);
    return out[0..take];
}

// AFTER: messages strictly after the anchor, oldest `limit`.
fn applyAfter(
    messages: []const Message,
    anchor: Selector,
    limit: usize,
    out: []Message,
) ParseError![]const Message {
    if (out.len < limit) return error.OutputTooSmall;
    const start = switch (anchor) {
        .wildcard => 0,
        .msgid => |id| findMsgidAfter(messages, id),
        .timestamp => |ts| findTimestampAfter(messages, ts),
    };
    const window = messages[start..];
    if (window.len == 0 or limit == 0) return out[0..0];
    const take = @min(window.len, limit);
    @memcpy(out[0..take], window[0..take]);
    return out[0..take];
}

// AROUND: centre on the anchor, up to `limit` total, oldest-first.
fn applyAround(
    messages: []const Message,
    anchor: Selector,
    limit: usize,
    out: []Message,
) ParseError![]const Message {
    if (out.len < limit) return error.OutputTooSmall;
    if (messages.len == 0 or limit == 0) return out[0..0];

    const pivot: usize = switch (anchor) {
        .wildcard => if (messages.len == 0) 0 else messages.len - 1,
        .msgid => |id| findPivot(messages, id),
        .timestamp => |ts| findPivotTs(messages, ts),
    };

    const take = @min(messages.len, limit);
    const half_before = (take - 1) / 2;
    const desired_start = if (pivot >= half_before) pivot - half_before else 0;
    var start = desired_start;

    // Shift left if we would run off the end
    const available_from_start = messages.len - start;
    if (available_from_start < take and start > 0) {
        const deficit = take - available_from_start;
        start -= @min(start, deficit);
    }

    const actual_take = @min(take, messages.len - start);
    @memcpy(out[0..actual_take], messages[start .. start + actual_take]);
    return out[0..actual_take];
}

// BETWEEN: messages in [from, to] inclusive, oldest-first, up to `limit`.
fn applyBetween(
    messages: []const Message,
    from: Selector,
    to: Selector,
    limit: usize,
    out: []Message,
) ParseError![]const Message {
    if (out.len < limit) return error.OutputTooSmall;

    const start_idx: usize = switch (from) {
        .wildcard => 0,
        .msgid => |id| findMsgidInclusiveStart(messages, id),
        .timestamp => |ts| findTimestampAtOrAfter(messages, ts),
    };
    const end_idx: usize = switch (to) {
        .wildcard => messages.len,
        .msgid => |id| findMsgidInclusiveEnd(messages, id),
        .timestamp => |ts| findTimestampInclusiveEnd(messages, ts),
    };

    if (start_idx >= end_idx) return out[0..0];
    const window = messages[start_idx..end_idx];
    if (window.len == 0 or limit == 0) return out[0..0];
    const take = @min(window.len, limit);
    @memcpy(out[0..take], window[0..take]);
    return out[0..take];
}

// Index of the first message whose msgid matches; messages.len if none.
fn findMsgidExclusive(messages: []const Message, id: []const u8) usize {
    for (messages, 0..) |msg, i| {
        if (std.mem.eql(u8, msg.msgid, id)) return i;
    }
    return messages.len;
}

/// Index one past the message with matching msgid (exclusive upper bound).
/// Used for "strictly after msgid" — not exported; AFTER uses findMsgidInclusive.
fn findMsgidInclusiveEnd(messages: []const Message, id: []const u8) usize {
    for (messages, 0..) |msg, i| {
        if (std.mem.eql(u8, msg.msgid, id)) return i + 1;
    }
    return messages.len;
}

/// Index of the first message *after* the matched msgid (exclusive lower bound for AFTER).
fn findMsgidAfter(messages: []const Message, id: []const u8) usize {
    for (messages, 0..) |msg, i| {
        if (std.mem.eql(u8, msg.msgid, id)) return i + 1;
    }
    return messages.len;
}

/// Index of the first message with matching msgid (inclusive lower bound for BETWEEN).
fn findMsgidInclusiveStart(messages: []const Message, id: []const u8) usize {
    for (messages, 0..) |msg, i| {
        if (std.mem.eql(u8, msg.msgid, id)) return i;
    }
    return messages.len;
}

/// Index of first message with ts strictly after anchor (exclusive lower for AFTER).
fn findTimestampAfter(messages: []const Message, ts: Timestamp) usize {
    for (messages, 0..) |msg, i| {
        if (msg.ts > ts) return i;
    }
    return messages.len;
}

/// Index of first message with ts >= anchor (inclusive for BETWEEN/LATEST upper bound).
fn findTimestampAtOrAfter(messages: []const Message, ts: Timestamp) usize {
    for (messages, 0..) |msg, i| {
        if (msg.ts >= ts) return i;
    }
    return messages.len;
}

/// Index one past the last message with ts <= anchor.
fn findTimestampInclusiveEnd(messages: []const Message, ts: Timestamp) usize {
    var last: usize = 0;
    for (messages, 0..) |msg, i| {
        if (msg.ts <= ts) last = i + 1;
    }
    return last;
}

fn findPivot(messages: []const Message, id: []const u8) usize {
    for (messages, 0..) |msg, i| {
        if (std.mem.eql(u8, msg.msgid, id)) return i;
    }
    return if (messages.len > 0) messages.len - 1 else 0;
}

fn findPivotTs(messages: []const Message, ts: Timestamp) usize {
    var best: usize = 0;
    var best_diff: u64 = std.math.maxInt(u64);
    for (messages, 0..) |msg, i| {
        const diff: u64 = @abs(msg.ts - ts);
        if (diff < best_diff) {
            best_diff = diff;
            best = i;
        }
    }
    return best;
}

const testing = std.testing;

// A tiny ordered store for tests (oldest-first)
const store = [_]Message{
    .{ .msgid = "m1", .ts = 1_000_000 },
    .{ .msgid = "m2", .ts = 2_000_000 },
    .{ .msgid = "m3", .ts = 3_000_000 },
    .{ .msgid = "m4", .ts = 4_000_000 },
    .{ .msgid = "m5", .ts = 5_000_000 },
    .{ .msgid = "m6", .ts = 6_000_000 },
    .{ .msgid = "m7", .ts = 7_000_000 },
    .{ .msgid = "m8", .ts = 8_000_000 },
};

const max_limit: usize = 50;
test "parseSelector wildcard" {
    const sel = try parseSelector("*");
    try testing.expect(sel == .wildcard);
}

test "parseSelector msgid" {
    const sel = try parseSelector("msgid=abc-123");
    try testing.expectEqualStrings("abc-123", sel.msgid);
}

test "parseSelector empty msgid is rejected" {
    try testing.expectError(error.MalformedMsgid, parseSelector("msgid="));
}

test "parseSelector msgid with space is rejected" {
    try testing.expectError(error.MalformedMsgid, parseSelector("msgid=a b"));
}

test "parseSelector timestamp basic" {
    const sel = try parseSelector("timestamp=2024-01-01T00:00:00Z");
    try testing.expect(sel == .timestamp);
    // 2024-01-01 = days since epoch, just check it's positive
    try testing.expect(sel.timestamp > 0);
}

test "parseSelector timestamp with fractional seconds" {
    const sel = try parseSelector("timestamp=2024-06-15T12:30:45.123456Z");
    try testing.expect(sel == .timestamp);
    try testing.expect(sel.timestamp > 0);
}

test "parseSelector unknown prefix is rejected" {
    try testing.expectError(error.MalformedSelector, parseSelector("unknown=foo"));
}

test "parseSelector empty string is rejected" {
    try testing.expectError(error.MalformedSelector, parseSelector(""));
}
test "parseTimestamp unix epoch" {
    const ts = try parseTimestamp("1970-01-01T00:00:00Z");
    try testing.expectEqual(@as(Timestamp, 0), ts);
}

test "parseTimestamp one second after epoch" {
    const ts = try parseTimestamp("1970-01-01T00:00:01Z");
    try testing.expectEqual(@as(Timestamp, 1_000_000), ts);
}

test "parseTimestamp with microseconds" {
    const ts = try parseTimestamp("1970-01-01T00:00:00.500000Z");
    try testing.expectEqual(@as(Timestamp, 500_000), ts);
}

test "parseTimestamp no trailing Z is rejected" {
    try testing.expectError(error.MalformedTimestamp, parseTimestamp("1970-01-01T00:00:00"));
}

test "parseTimestamp bad month is rejected" {
    try testing.expectError(error.MalformedTimestamp, parseTimestamp("1970-13-01T00:00:00Z"));
}

test "parseTimestamp too short is rejected" {
    try testing.expectError(error.MalformedTimestamp, parseTimestamp("1970-01-01"));
}
test "parseSubcommand case insensitive" {
    try testing.expectEqual(SubcommandTag.latest, try parseSubcommand("LATEST"));
    try testing.expectEqual(SubcommandTag.latest, try parseSubcommand("latest"));
    try testing.expectEqual(SubcommandTag.before, try parseSubcommand("Before"));
    try testing.expectEqual(SubcommandTag.after, try parseSubcommand("AFTER"));
    try testing.expectEqual(SubcommandTag.around, try parseSubcommand("around"));
    try testing.expectEqual(SubcommandTag.between, try parseSubcommand("BETWEEN"));
}

test "parseSubcommand unknown is rejected" {
    try testing.expectError(error.UnknownSubcommand, parseSubcommand("HISTORY"));
}
test "parseLimit valid" {
    try testing.expectEqual(@as(usize, 10), try parseLimit("10", 50));
}

test "parseLimit at max" {
    try testing.expectEqual(@as(usize, 50), try parseLimit("50", 50));
}

test "parseLimit exceeds max is rejected" {
    try testing.expectError(error.LimitExceedsMax, parseLimit("51", 50));
}

test "parseLimit non-numeric is rejected" {
    try testing.expectError(error.InvalidLimit, parseLimit("abc", 50));
}

test "parseLimit zero is valid" {
    try testing.expectEqual(@as(usize, 0), try parseLimit("0", 50));
}
test "parseQuery LATEST wildcard" {
    const params = [_][]const u8{ "*", "5" };
    const q = try parseQuery(.latest, &params, max_limit);
    try testing.expect(q.latest.selector == .wildcard);
    try testing.expectEqual(@as(usize, 5), q.latest.limit);
}

test "parseQuery BEFORE msgid" {
    const params = [_][]const u8{ "msgid=m4", "3" };
    const q = try parseQuery(.before, &params, max_limit);
    try testing.expectEqualStrings("m4", q.before.anchor.msgid);
    try testing.expectEqual(@as(usize, 3), q.before.limit);
}

test "parseQuery AFTER timestamp" {
    const params = [_][]const u8{ "timestamp=1970-01-01T00:00:01Z", "2" };
    const q = try parseQuery(.after, &params, max_limit);
    try testing.expect(q.after.anchor == .timestamp);
}

test "parseQuery AROUND msgid" {
    const params = [_][]const u8{ "msgid=m5", "4" };
    const q = try parseQuery(.around, &params, max_limit);
    try testing.expectEqualStrings("m5", q.around.anchor.msgid);
}

test "parseQuery BETWEEN two msgids" {
    const params = [_][]const u8{ "msgid=m2", "msgid=m6", "4" };
    const q = try parseQuery(.between, &params, max_limit);
    try testing.expectEqualStrings("m2", q.between.from.msgid);
    try testing.expectEqualStrings("m6", q.between.to.msgid);
    try testing.expectEqual(@as(usize, 4), q.between.limit);
}

test "parseQuery rejects limit exceeding server max" {
    const params = [_][]const u8{ "*", "100" };
    try testing.expectError(error.LimitExceedsMax, parseQuery(.latest, &params, 50));
}
test "LATEST * returns newest N" {
    var out: [8]Message = undefined;
    const q = Query{ .latest = .{ .selector = .wildcard, .limit = 3 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 3), result.len);
    try testing.expectEqualStrings("m6", result[0].msgid);
    try testing.expectEqualStrings("m7", result[1].msgid);
    try testing.expectEqualStrings("m8", result[2].msgid);
}

test "LATEST limit larger than store returns all" {
    var out: [20]Message = undefined;
    const q = Query{ .latest = .{ .selector = .wildcard, .limit = 20 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 8), result.len);
    try testing.expectEqualStrings("m1", result[0].msgid);
}

test "LATEST msgid=X returns newest N before X (exclusive)" {
    var out: [8]Message = undefined;
    const q = Query{ .latest = .{ .selector = .{ .msgid = "m5" }, .limit = 2 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 2), result.len);
    try testing.expectEqualStrings("m3", result[0].msgid);
    try testing.expectEqualStrings("m4", result[1].msgid);
}

test "LATEST limit=0 returns empty" {
    var out: [8]Message = undefined;
    const q = Query{ .latest = .{ .selector = .wildcard, .limit = 0 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 0), result.len);
}
test "BEFORE msgid=m5 limit=3 returns m2 m3 m4" {
    var out: [8]Message = undefined;
    const q = Query{ .before = .{ .anchor = .{ .msgid = "m5" }, .limit = 3 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 3), result.len);
    try testing.expectEqualStrings("m2", result[0].msgid);
    try testing.expectEqualStrings("m3", result[1].msgid);
    try testing.expectEqualStrings("m4", result[2].msgid);
}

test "BEFORE timestamp selects correctly" {
    var out: [8]Message = undefined;
    // ts=3_000_000 → exclusive upper bound, so m3 is excluded → window is m1,m2
    const q = Query{ .before = .{ .anchor = .{ .timestamp = 3_000_000 }, .limit = 5 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 2), result.len);
    try testing.expectEqualStrings("m1", result[0].msgid);
    try testing.expectEqualStrings("m2", result[1].msgid);
}

test "BEFORE m1 returns empty (nothing before first message)" {
    var out: [8]Message = undefined;
    const q = Query{ .before = .{ .anchor = .{ .msgid = "m1" }, .limit = 5 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 0), result.len);
}
test "AFTER msgid=m4 limit=3 returns m5 m6 m7" {
    var out: [8]Message = undefined;
    const q = Query{ .after = .{ .anchor = .{ .msgid = "m4" }, .limit = 3 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 3), result.len);
    try testing.expectEqualStrings("m5", result[0].msgid);
    try testing.expectEqualStrings("m6", result[1].msgid);
    try testing.expectEqualStrings("m7", result[2].msgid);
}

test "AFTER timestamp selects correctly" {
    var out: [10]Message = undefined;
    // ts=5_000_000 exclusive → m6,m7,m8
    const q = Query{ .after = .{ .anchor = .{ .timestamp = 5_000_000 }, .limit = 10 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 3), result.len);
    try testing.expectEqualStrings("m6", result[0].msgid);
}

test "AFTER m8 returns empty (nothing after last)" {
    var out: [8]Message = undefined;
    const q = Query{ .after = .{ .anchor = .{ .msgid = "m8" }, .limit = 5 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 0), result.len);
}
test "AROUND m4 limit=3 centres correctly" {
    var out: [8]Message = undefined;
    const q = Query{ .around = .{ .anchor = .{ .msgid = "m4" }, .limit = 3 } };
    const result = try applyQuery(&store, q, &out);
    // pivot=3 (m4 at index 3), half_before=1 → start=2 → m3,m4,m5
    try testing.expectEqual(@as(usize, 3), result.len);
    try testing.expectEqualStrings("m3", result[0].msgid);
    try testing.expectEqualStrings("m4", result[1].msgid);
    try testing.expectEqualStrings("m5", result[2].msgid);
}

test "AROUND m1 limit=4 shifts window to start" {
    var out: [8]Message = undefined;
    const q = Query{ .around = .{ .anchor = .{ .msgid = "m1" }, .limit = 4 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 4), result.len);
    try testing.expectEqualStrings("m1", result[0].msgid);
    try testing.expectEqualStrings("m4", result[3].msgid);
}

test "AROUND m8 limit=4 shifts window to end" {
    var out: [8]Message = undefined;
    const q = Query{ .around = .{ .anchor = .{ .msgid = "m8" }, .limit = 4 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 4), result.len);
    try testing.expectEqualStrings("m5", result[0].msgid);
    try testing.expectEqualStrings("m8", result[3].msgid);
}

test "AROUND timestamp centres on nearest message" {
    var out: [8]Message = undefined;
    // ts=3_500_000 is between m3(3M) and m4(4M); nearest is m4
    const q = Query{ .around = .{ .anchor = .{ .timestamp = 3_500_000 }, .limit = 3 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 3), result.len);
}

test "AROUND limit=1 returns single message" {
    var out: [8]Message = undefined;
    const q = Query{ .around = .{ .anchor = .{ .msgid = "m5" }, .limit = 1 } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 1), result.len);
    try testing.expectEqualStrings("m5", result[0].msgid);
}
test "BETWEEN m2 m6 limit=10 returns m2..m6" {
    var out: [10]Message = undefined;
    const q = Query{ .between = .{
        .from = .{ .msgid = "m2" },
        .to = .{ .msgid = "m6" },
        .limit = 10,
    } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 5), result.len);
    try testing.expectEqualStrings("m2", result[0].msgid);
    try testing.expectEqualStrings("m6", result[4].msgid);
}

test "BETWEEN limit clamps window oldest-first" {
    var out: [8]Message = undefined;
    const q = Query{ .between = .{
        .from = .{ .msgid = "m2" },
        .to = .{ .msgid = "m6" },
        .limit = 3,
    } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 3), result.len);
    // oldest-first within window → m2, m3, m4
    try testing.expectEqualStrings("m2", result[0].msgid);
    try testing.expectEqualStrings("m3", result[1].msgid);
    try testing.expectEqualStrings("m4", result[2].msgid);
}

test "BETWEEN timestamp bounds inclusive" {
    var out: [10]Message = undefined;
    const q = Query{ .between = .{
        .from = .{ .timestamp = 2_000_000 },
        .to = .{ .timestamp = 4_000_000 },
        .limit = 10,
    } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 3), result.len);
    try testing.expectEqualStrings("m2", result[0].msgid);
    try testing.expectEqualStrings("m4", result[2].msgid);
}

test "BETWEEN equal selectors returns single message" {
    var out: [10]Message = undefined;
    const q = Query{ .between = .{
        .from = .{ .msgid = "m5" },
        .to = .{ .msgid = "m5" },
        .limit = 10,
    } };
    const result = try applyQuery(&store, q, &out);
    try testing.expectEqual(@as(usize, 1), result.len);
    try testing.expectEqualStrings("m5", result[0].msgid);
}
test "empty store returns no results for all ops" {
    const empty: []const Message = &[_]Message{};
    var out: [8]Message = undefined;

    const ops = [_]Query{
        .{ .latest = .{ .selector = .wildcard, .limit = 5 } },
        .{ .before = .{ .anchor = .{ .msgid = "x" }, .limit = 5 } },
        .{ .after = .{ .anchor = .{ .msgid = "x" }, .limit = 5 } },
        .{ .around = .{ .anchor = .{ .msgid = "x" }, .limit = 5 } },
        .{ .between = .{ .from = .{ .msgid = "x" }, .to = .{ .msgid = "y" }, .limit = 5 } },
    };

    for (ops) |q| {
        const result = try applyQuery(empty, q, &out);
        try testing.expectEqual(@as(usize, 0), result.len);
    }
}

test "OutputTooSmall is returned when out buffer is too small" {
    var out: [1]Message = undefined;
    const q = Query{ .latest = .{ .selector = .wildcard, .limit = 5 } };
    try testing.expectError(error.OutputTooSmall, applyQuery(&store, q, &out));
}

test "malformed selector rejects bad input" {
    try testing.expectError(error.MalformedSelector, parseSelector("notaprefix=x"));
    try testing.expectError(error.MalformedSelector, parseSelector("MSGID=abc"));
    try testing.expectError(error.MalformedMsgid, parseSelector("msgid="));
}

test "limit clamped to server max end-to-end via parseQuery" {
    const params = [_][]const u8{ "*", "10" };
    const q = try parseQuery(.latest, &params, 10);
    try testing.expectEqual(@as(usize, 10), q.latest.limit);

    const params2 = [_][]const u8{ "*", "11" };
    try testing.expectError(error.LimitExceedsMax, parseQuery(.latest, &params2, 10));
}
