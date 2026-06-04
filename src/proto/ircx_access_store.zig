//! IRCX per-channel ACCESS parsing, storage, matching, and reply builders.
//!
//! This complements `ircx_saccess.zig`: SACCESS handles server-level entries,
//! while this module owns channel-scoped ACCESS entries with setter metadata.
const std = @import("std");
const listx = @import("listx.zig");

pub const RPL_ACCESSADD: u16 = 801;
pub const RPL_ACCESSDELETE: u16 = 802;
pub const RPL_ACCESSSTART: u16 = 803;
pub const RPL_ACCESSENTRY: u16 = 804;
pub const RPL_ACCESSEND: u16 = 805;

pub const DEFAULT_MAX_ENTRIES: usize = 256;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 128;
pub const DEFAULT_MAX_MASK_BYTES: usize = 128;
pub const DEFAULT_MAX_SET_BY_BYTES: usize = 64;
pub const DEFAULT_MAX_REASON_BYTES: usize = 256;
pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_REQUESTER_BYTES: usize = 64;
pub const DEFAULT_MAX_DURATION_DIGITS: usize = 20;

pub const AccessError = error{
    MissingChannel,
    InvalidChannel,
    MissingSubcommand,
    InvalidSubcommand,
    MissingLevel,
    InvalidLevel,
    MissingMask,
    InvalidMask,
    MaskTooLong,
    InvalidSetBy,
    InvalidDuration,
    DurationTooLong,
    InvalidReason,
    ReasonTooLong,
    TooManyParameters,
    TooManyEntries,
    InvalidServerName,
    InvalidRequester,
    LineTooLong,
    OutputTooSmall,
};

pub const StoreError = AccessError || std.mem.Allocator.Error;

pub const Params = struct {
    max_entries: usize = DEFAULT_MAX_ENTRIES,
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
    max_mask_bytes: usize = DEFAULT_MAX_MASK_BYTES,
    max_set_by_bytes: usize = DEFAULT_MAX_SET_BY_BYTES,
    max_reason_bytes: usize = DEFAULT_MAX_REASON_BYTES,
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_requester_bytes: usize = DEFAULT_MAX_REQUESTER_BYTES,
    max_duration_digits: usize = DEFAULT_MAX_DURATION_DIGITS,
};

pub const Level = enum {
    voice,
    host,
    owner,
    grant,
    deny,

    pub fn token(self: Level) []const u8 {
        return switch (self) {
            .owner => "OWNER",
            .host => "HOST",
            .voice => "VOICE",
            .deny => "DENY",
            .grant => "GRANT",
        };
    }

    pub fn parse(raw: []const u8) ?Level {
        if (std.ascii.eqlIgnoreCase(raw, "OWNER")) return .owner;
        if (std.ascii.eqlIgnoreCase(raw, "HOST")) return .host;
        if (std.ascii.eqlIgnoreCase(raw, "VOICE")) return .voice;
        if (std.ascii.eqlIgnoreCase(raw, "DENY")) return .deny;
        if (std.ascii.eqlIgnoreCase(raw, "GRANT")) return .grant;
        return null;
    }

    pub fn precedence(self: Level) u8 {
        return switch (self) {
            .deny => 50,
            .grant => 40,
            .owner => 30,
            .host => 20,
            .voice => 10,
        };
    }
};

pub const AddRequest = struct {
    channel: []const u8,
    level: Level,
    mask: []const u8,
    timeout: ?u64 = null,
    reason: ?[]const u8 = null,
};

pub const DeleteRequest = struct {
    channel: []const u8,
    level: Level,
    mask: []const u8,
};

pub const Selector = struct {
    channel: []const u8,
    level: ?Level = null,
    mask: ?[]const u8 = null,

    fn matches(self: Selector, entry: Entry) bool {
        if (!std.ascii.eqlIgnoreCase(self.channel, entry.channel)) return false;
        if (self.level) |level| {
            if (level != entry.level) return false;
        }
        if (self.mask) |mask| {
            if (!std.ascii.eqlIgnoreCase(mask, entry.mask)) return false;
        }
        return true;
    }
};

pub const Request = union(enum) {
    add: AddRequest,
    delete: DeleteRequest,
    list: Selector,
    clear: Selector,
};

pub const EntryView = struct {
    channel: []const u8,
    level: Level,
    mask: []const u8,
    set_by: []const u8,
    duration: ?u64 = null,
};

pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
};

const Entry = struct {
    channel: []u8,
    level: Level,
    mask: []u8,
    set_by: []u8,
    duration: ?u64,

    fn view(self: *const Entry) EntryView {
        return .{
            .channel = self.channel,
            .level = self.level,
            .mask = self.mask,
            .set_by = self.set_by,
            .duration = self.duration,
        };
    }
};

pub const AccessStore = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    max_entries: usize = DEFAULT_MAX_ENTRIES,

    pub fn init(allocator: std.mem.Allocator) AccessStore {
        return .{ .allocator = allocator };
    }

    pub fn initWith(allocator: std.mem.Allocator, max_entries: usize) AccessStore {
        return .{ .allocator = allocator, .max_entries = max_entries };
    }

    pub fn deinit(self: *AccessStore) void {
        for (self.entries.items) |entry| freeEntry(self.allocator, entry);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn add(
        self: *AccessStore,
        channel: []const u8,
        level: Level,
        mask: []const u8,
        set_by: []const u8,
        duration: ?u64,
    ) StoreError!void {
        try validateChannelWith(.{}, channel);
        try validateMaskWith(.{}, mask);
        try validateSetByWith(.{}, set_by);

        if (self.findIndex(channel, level, mask)) |idx| {
            const set_by_copy = try self.allocator.dupe(u8, set_by);
            self.allocator.free(self.entries.items[idx].set_by);
            self.entries.items[idx].set_by = set_by_copy;
            self.entries.items[idx].duration = duration;
            return;
        }

        if (self.entries.items.len >= self.max_entries) return error.TooManyEntries;

        const channel_copy = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(channel_copy);
        const mask_copy = try self.allocator.dupe(u8, mask);
        errdefer self.allocator.free(mask_copy);
        const set_by_copy = try self.allocator.dupe(u8, set_by);
        errdefer self.allocator.free(set_by_copy);

        try self.entries.append(self.allocator, .{
            .channel = channel_copy,
            .level = level,
            .mask = mask_copy,
            .set_by = set_by_copy,
            .duration = duration,
        });
    }

    pub fn remove(self: *AccessStore, channel: []const u8, level: Level, mask: []const u8) AccessError!bool {
        try validateChannelWith(.{}, channel);
        try validateMaskWith(.{}, mask);

        const idx = self.findIndex(channel, level, mask) orelse return false;
        const removed = self.entries.swapRemove(idx);
        freeEntry(self.allocator, removed);
        return true;
    }

    pub fn clear(self: *AccessStore, selector: Selector) AccessError!usize {
        try validateSelectorWith(.{}, selector);

        var removed_count: usize = 0;
        var idx: usize = 0;
        while (idx < self.entries.items.len) {
            if (selector.matches(self.entries.items[idx])) {
                const removed = self.entries.swapRemove(idx);
                freeEntry(self.allocator, removed);
                removed_count += 1;
            } else {
                idx += 1;
            }
        }
        return removed_count;
    }

    pub fn list(self: *const AccessStore, channel: []const u8, out: []EntryView) AccessError![]const EntryView {
        return self.listMatching(.{ .channel = channel }, out);
    }

    pub fn listMatching(self: *const AccessStore, selector: Selector, out: []EntryView) AccessError![]const EntryView {
        try validateSelectorWith(.{}, selector);

        var count: usize = 0;
        for (self.entries.items) |*entry| {
            if (!selector.matches(entry.*)) continue;
            if (count >= out.len) return error.OutputTooSmall;
            out[count] = entry.view();
            count += 1;
        }
        return out[0..count];
    }

    pub fn matchHostmask(self: *const AccessStore, channel: []const u8, hostmask: []const u8) AccessError!?EntryView {
        try validateChannelWith(.{}, channel);
        try validateHostmaskWith(.{}, hostmask);

        var best: ?*const Entry = null;
        for (self.entries.items) |*entry| {
            if (!std.ascii.eqlIgnoreCase(entry.channel, channel)) continue;
            if (!listx.globMatch(entry.mask, hostmask)) continue;
            if (best == null or entry.level.precedence() > best.?.level.precedence()) {
                best = entry;
            }
        }

        if (best) |entry| return entry.view();
        return null;
    }

    fn findIndex(self: *const AccessStore, channel: []const u8, level: Level, mask: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, idx| {
            if (entry.level == level and
                std.ascii.eqlIgnoreCase(entry.channel, channel) and
                std.ascii.eqlIgnoreCase(entry.mask, mask))
            {
                return idx;
            }
        }
        return null;
    }
};

const Subcommand = enum {
    add,
    delete,
    list,
    clear,

    fn parse(raw: []const u8) ?Subcommand {
        if (std.ascii.eqlIgnoreCase(raw, "ADD")) return .add;
        if (std.ascii.eqlIgnoreCase(raw, "DEL") or std.ascii.eqlIgnoreCase(raw, "DELETE")) return .delete;
        if (std.ascii.eqlIgnoreCase(raw, "LIST")) return .list;
        if (std.ascii.eqlIgnoreCase(raw, "CLEAR")) return .clear;
        return null;
    }
};

pub fn parse(params: []const []const u8) AccessError!Request {
    return parseWith(.{}, params);
}

pub fn parseWith(comptime limits: Params, params: []const []const u8) AccessError!Request {
    if (params.len == 0) return error.MissingChannel;
    const channel = params[0];
    try validateChannelWith(limits, channel);

    if (params.len == 1) return error.MissingSubcommand;
    const subcommand = Subcommand.parse(params[1]) orelse return error.InvalidSubcommand;
    const tail = params[2..];

    return switch (subcommand) {
        .add => .{ .add = try parseAddWith(limits, channel, tail) },
        .delete => .{ .delete = try parseDeleteWith(limits, channel, tail) },
        .list => .{ .list = try parseSelectorWith(limits, channel, tail) },
        .clear => .{ .clear = try parseSelectorWith(limits, channel, tail) },
    };
}

pub fn buildAccessStart(out: []u8, ctx: ReplyContext, channel: []const u8) AccessError![]const u8 {
    try validateContextWith(.{}, ctx);
    try validateChannelWith(.{}, channel);

    var b = LineBuilder.init(out, DEFAULT_MAX_LINE_BYTES);
    try b.numericPrefix(RPL_ACCESSSTART, ctx.server_name, ctx.requester);
    try b.spaceParam(channel);
    try b.spaceTrailing("ACCESS list begins");
    try b.crlf();
    return b.slice();
}

pub fn buildAccessEntry(out: []u8, ctx: ReplyContext, entry: EntryView) AccessError![]const u8 {
    try validateContextWith(.{}, ctx);
    try validateEntryViewWith(.{}, entry);

    var b = LineBuilder.init(out, DEFAULT_MAX_LINE_BYTES);
    try b.numericPrefix(RPL_ACCESSENTRY, ctx.server_name, ctx.requester);
    try appendEntryFields(&b, entry);
    try b.crlf();
    return b.slice();
}

pub fn buildAccessEnd(out: []u8, ctx: ReplyContext, channel: []const u8) AccessError![]const u8 {
    try validateContextWith(.{}, ctx);
    try validateChannelWith(.{}, channel);

    var b = LineBuilder.init(out, DEFAULT_MAX_LINE_BYTES);
    try b.numericPrefix(RPL_ACCESSEND, ctx.server_name, ctx.requester);
    try b.spaceParam(channel);
    try b.spaceTrailing("End of ACCESS list");
    try b.crlf();
    return b.slice();
}

pub fn buildAccessAdd(out: []u8, ctx: ReplyContext, entry: EntryView) AccessError![]const u8 {
    try validateContextWith(.{}, ctx);
    try validateEntryViewWith(.{}, entry);

    var b = LineBuilder.init(out, DEFAULT_MAX_LINE_BYTES);
    try b.numericPrefix(RPL_ACCESSADD, ctx.server_name, ctx.requester);
    try b.spaceParam(entry.channel);
    try b.spaceParam(entry.level.token());
    try b.spaceParam(entry.mask);
    try b.spaceTrailing("ACCESS entry added");
    try b.crlf();
    return b.slice();
}

pub fn buildAccessDelete(out: []u8, ctx: ReplyContext, entry: DeleteRequest) AccessError![]const u8 {
    try validateContextWith(.{}, ctx);
    try validateChannelWith(.{}, entry.channel);
    try validateMaskWith(.{}, entry.mask);

    var b = LineBuilder.init(out, DEFAULT_MAX_LINE_BYTES);
    try b.numericPrefix(RPL_ACCESSDELETE, ctx.server_name, ctx.requester);
    try b.spaceParam(entry.channel);
    try b.spaceParam(entry.level.token());
    try b.spaceParam(entry.mask);
    try b.spaceTrailing("ACCESS entry deleted");
    try b.crlf();
    return b.slice();
}

fn parseAddWith(comptime limits: Params, channel: []const u8, params: []const []const u8) AccessError!AddRequest {
    if (params.len == 0) return error.MissingLevel;
    if (params.len == 1) return error.MissingMask;
    if (params.len > 4) return error.TooManyParameters;

    const level = Level.parse(params[0]) orelse return error.InvalidLevel;
    const mask = params[1];
    try validateMaskWith(limits, mask);

    var request = AddRequest{ .channel = channel, .level = level, .mask = mask };
    if (params.len >= 3) {
        if (params[2].len > 0 and params[2][0] == ':') {
            if (params.len > 3) return error.TooManyParameters;
            request.reason = try parseReasonWith(limits, params[2]);
        } else {
            request.timeout = try parseDurationWith(limits, params[2]);
        }
    }
    if (params.len == 4) request.reason = try parseReasonWith(limits, params[3]);
    return request;
}

fn parseDeleteWith(comptime limits: Params, channel: []const u8, params: []const []const u8) AccessError!DeleteRequest {
    if (params.len == 0) return error.MissingLevel;
    if (params.len == 1) return error.MissingMask;
    if (params.len > 2) return error.TooManyParameters;

    const level = Level.parse(params[0]) orelse return error.InvalidLevel;
    const mask = params[1];
    try validateMaskWith(limits, mask);
    return .{ .channel = channel, .level = level, .mask = mask };
}

fn parseSelectorWith(comptime limits: Params, channel: []const u8, params: []const []const u8) AccessError!Selector {
    if (params.len > 2) return error.TooManyParameters;

    var selector = Selector{ .channel = channel };
    if (params.len >= 1) {
        selector.level = Level.parse(params[0]) orelse return error.InvalidLevel;
    }
    if (params.len == 2) {
        try validateMaskWith(limits, params[1]);
        selector.mask = params[1];
    }
    return selector;
}

fn parseDurationWith(comptime limits: Params, raw: []const u8) AccessError!u64 {
    if (raw.len == 0) return error.InvalidDuration;
    if (raw.len > limits.max_duration_digits) return error.DurationTooLong;

    var value: u64 = 0;
    for (raw) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidDuration;
        const digit: u64 = byte - '0';
        if (value > (std.math.maxInt(u64) - digit) / 10) return error.InvalidDuration;
        value = value * 10 + digit;
    }
    return value;
}

fn parseReasonWith(comptime limits: Params, raw: []const u8) AccessError![]const u8 {
    const reason = if (raw.len > 0 and raw[0] == ':') raw[1..] else raw;
    try validateReasonWith(limits, reason);
    return reason;
}

fn validateSelectorWith(comptime limits: Params, selector: Selector) AccessError!void {
    try validateChannelWith(limits, selector.channel);
    if (selector.mask) |mask| try validateMaskWith(limits, mask);
}

fn validateEntryViewWith(comptime limits: Params, entry: EntryView) AccessError!void {
    try validateChannelWith(limits, entry.channel);
    try validateMaskWith(limits, entry.mask);
    try validateSetByWith(limits, entry.set_by);
}

fn validateContextWith(comptime limits: Params, ctx: ReplyContext) AccessError!void {
    try validateParamBounded(ctx.server_name, limits.max_server_bytes, error.InvalidServerName);
    try validateParamBounded(ctx.requester, limits.max_requester_bytes, error.InvalidRequester);
}

fn validateChannelWith(comptime limits: Params, channel: []const u8) AccessError!void {
    if (channel.len == 0 or channel.len > limits.max_channel_bytes) return error.InvalidChannel;
    try validateSafeText(channel, error.InvalidChannel);
    switch (channel[0]) {
        '#', '&', '%', '+' => {},
        else => return error.InvalidChannel,
    }
    for (channel) |byte| {
        if (byte == ' ' or byte == ',' or byte == 7) return error.InvalidChannel;
    }
}

fn validateMaskWith(comptime limits: Params, mask: []const u8) AccessError!void {
    if (mask.len == 0) return error.InvalidMask;
    if (mask.len > limits.max_mask_bytes) return error.MaskTooLong;
    if (mask[0] == ':') return error.InvalidMask;
    try validateSafeText(mask, error.InvalidMask);

    var bang: ?usize = null;
    var at: ?usize = null;
    for (mask, 0..) |byte, idx| {
        switch (byte) {
            ' ', '\t', ',' => return error.InvalidMask,
            '!' => {
                if (bang == null) bang = idx;
            },
            '@' => {
                if (at == null) at = idx;
            },
            else => {},
        }
    }

    const bang_idx = bang orelse return error.InvalidMask;
    const at_idx = at orelse return error.InvalidMask;
    if (bang_idx == 0 or at_idx <= bang_idx + 1 or at_idx == mask.len - 1) return error.InvalidMask;
}

fn validateHostmaskWith(comptime limits: Params, hostmask: []const u8) AccessError!void {
    try validateMaskWith(limits, hostmask);
    if (std.mem.indexOfScalar(u8, hostmask, '*') != null) return error.InvalidMask;
    if (std.mem.indexOfScalar(u8, hostmask, '?') != null) return error.InvalidMask;
}

fn validateSetByWith(comptime limits: Params, set_by: []const u8) AccessError!void {
    try validateParamBounded(set_by, limits.max_set_by_bytes, error.InvalidSetBy);
}

fn validateReasonWith(comptime limits: Params, reason: []const u8) AccessError!void {
    if (reason.len > limits.max_reason_bytes) return error.ReasonTooLong;
    for (reason) |byte| {
        switch (byte) {
            0, '\r', '\n' => return error.InvalidReason,
            else => {},
        }
    }
}

fn validateParamBounded(param: []const u8, max_len: usize, err: AccessError) AccessError!void {
    if (param.len == 0 or param.len > max_len) return err;
    if (param[0] == ':') return err;
    for (param) |byte| {
        if (byte <= ' ' or byte == 0x7f) return err;
    }
}

fn validateSafeText(bytes: []const u8, err: AccessError) AccessError!void {
    for (bytes) |byte| {
        switch (byte) {
            0, '\r', '\n' => return err,
            1...8, 11, 12, 14...31, 127 => return err,
            else => {},
        }
    }
}

fn appendEntryFields(b: *LineBuilder, entry: EntryView) AccessError!void {
    try b.spaceParam(entry.channel);
    try b.spaceParam(entry.level.token());
    try b.spaceParam(entry.mask);
    try b.spaceParam(entry.set_by);
    try b.spaceUnsigned(entry.duration orelse 0);
}

fn freeEntry(allocator: std.mem.Allocator, entry: Entry) void {
    allocator.free(entry.channel);
    allocator.free(entry.mask);
    allocator.free(entry.set_by);
}

fn formatCodeValue(value: u16, buf: []u8) []const u8 {
    if (buf.len < 3) return buf[0..0];
    buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
    return buf[0..3];
}

const LineBuilder = struct {
    out: []u8,
    max_line_bytes: usize,
    len: usize = 0,

    fn init(out: []u8, max_line_bytes: usize) LineBuilder {
        return .{ .out = out, .max_line_bytes = max_line_bytes };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(self: *LineBuilder, code_value: u16, server_name: []const u8, requester: []const u8) AccessError!void {
        try self.appendByte(':');
        try self.appendBytes(server_name);
        try self.appendByte(' ');
        var code_buf: [3]u8 = undefined;
        try self.appendBytes(formatCodeValue(code_value, &code_buf));
        try self.appendByte(' ');
        try self.appendBytes(requester);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) AccessError!void {
        try self.appendByte(' ');
        try self.appendBytes(param);
    }

    fn spaceTrailing(self: *LineBuilder, param: []const u8) AccessError!void {
        try self.appendBytes(" :");
        try self.appendBytes(param);
    }

    fn spaceUnsigned(self: *LineBuilder, value: u64) AccessError!void {
        try self.appendByte(' ');
        try self.appendUnsigned(value);
    }

    fn appendUnsigned(self: *LineBuilder, value: u64) AccessError!void {
        var buf: [20]u8 = undefined;
        var cursor: usize = buf.len;
        var current = value;
        while (true) {
            cursor -= 1;
            buf[cursor] = @as(u8, '0') + @as(u8, @intCast(current % 10));
            current /= 10;
            if (current == 0) break;
        }
        try self.appendBytes(buf[cursor..]);
    }

    fn crlf(self: *LineBuilder) AccessError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) AccessError!void {
        if (self.len + bytes.len > self.out.len) return error.OutputTooSmall;
        if (self.len + bytes.len > self.max_line_bytes) return error.LineTooLong;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) AccessError!void {
        if (self.len == self.out.len) return error.OutputTooSmall;
        if (self.len + 1 > self.max_line_bytes) return error.LineTooLong;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test "add match precedence and update without leaks" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();

    try store.add("#zig", .voice, "nick!*@example.test", "alice", 10);
    try store.add("#zig", .host, "*!*@example.test", "alice", 20);
    try store.add("#zig", .owner, "nick!*@example.test", "bob", 30);
    try store.add("#zig", .grant, "nick!*@example.test", "carol", 40);
    try store.add("#zig", .deny, "nick!*@example.test", "dan", 50);

    const best = (try store.matchHostmask("#zig", "Nick!u@example.test")).?;
    try std.testing.expectEqual(Level.deny, best.level);
    try std.testing.expectEqual(@as(?u64, 50), best.duration);

    try store.add("#zig", .deny, "nick!*@example.test", "erin", 60);
    const updated = (try store.matchHostmask("#zig", "nick!u@example.test")).?;
    try std.testing.expectEqual(Level.deny, updated.level);
    try std.testing.expectEqualStrings("erin", updated.set_by);
    try std.testing.expectEqual(@as(?u64, 60), updated.duration);
}

test "parse each ACCESS subcommand" {
    const add_req = try parse(&.{ "#zig", "ADD", "OWNER", "nick!*@host.test", "3600", ":founder" });
    try std.testing.expectEqual(Level.owner, add_req.add.level);
    try std.testing.expectEqualStrings("#zig", add_req.add.channel);
    try std.testing.expectEqualStrings("nick!*@host.test", add_req.add.mask);
    try std.testing.expectEqual(@as(?u64, 3600), add_req.add.timeout);
    try std.testing.expectEqualStrings("founder", add_req.add.reason.?);

    const del_req = try parse(&.{ "#zig", "DEL", "VOICE", "*!*@guest.test" });
    try std.testing.expectEqual(Level.voice, del_req.delete.level);
    try std.testing.expectEqualStrings("*!*@guest.test", del_req.delete.mask);

    const list_req = try parse(&.{ "#zig", "LIST", "HOST", "*!*@staff.test" });
    try std.testing.expectEqual(@as(?Level, .host), list_req.list.level);
    try std.testing.expectEqualStrings("*!*@staff.test", list_req.list.mask.?);

    const clear_req = try parse(&.{ "#zig", "CLEAR", "DENY" });
    try std.testing.expectEqual(@as(?Level, .deny), clear_req.clear.level);
    try std.testing.expectEqual(@as(?[]const u8, null), clear_req.clear.mask);
}

test "list remove clear and reply builders" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();

    try store.add("#zig", .voice, "a!*@host.test", "oper", null);
    try store.add("#zig", .host, "b!*@host.test", "oper", 25);
    try store.add("#ops", .deny, "*!*@bad.test", "oper", null);

    var views: [4]EntryView = undefined;
    const listed = try store.list("#zig", &views);
    try std.testing.expectEqual(@as(usize, 2), listed.len);
    try std.testing.expectEqual(Level.voice, listed[0].level);
    try std.testing.expectEqual(Level.host, listed[1].level);

    try std.testing.expect(try store.remove("#zig", .voice, "a!*@host.test"));
    try std.testing.expectEqual(@as(usize, 1), (try store.list("#zig", &views)).len);
    try std.testing.expectEqual(@as(usize, 1), try store.clear(.{ .channel = "#ops" }));

    const ctx = ReplyContext{ .server_name = "irc.example.test", .requester = "dan" };
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        ":irc.example.test 803 dan #zig :ACCESS list begins\r\n",
        try buildAccessStart(&buf, ctx, "#zig"),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 804 dan #zig HOST b!*@host.test oper 25\r\n",
        try buildAccessEntry(&buf, ctx, listed[1]),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 805 dan #zig :End of ACCESS list\r\n",
        try buildAccessEnd(&buf, ctx, "#zig"),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 801 dan #zig HOST b!*@host.test :ACCESS entry added\r\n",
        try buildAccessAdd(&buf, ctx, listed[1]),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 802 dan #zig HOST b!*@host.test :ACCESS entry deleted\r\n",
        try buildAccessDelete(&buf, ctx, .{ .channel = "#zig", .level = .host, .mask = "b!*@host.test" }),
    );
}

test "validation and bounded outputs" {
    var tiny = AccessStore.initWith(std.testing.allocator, 1);
    defer tiny.deinit();

    try tiny.add("#zig", .voice, "a!*@host.test", "oper", null);
    try std.testing.expectError(error.TooManyEntries, tiny.add("#zig", .host, "b!*@host.test", "oper", null));
    try std.testing.expectError(error.InvalidMask, parse(&.{ "#zig", "ADD", "VOICE", "not-a-hostmask" }));
    try std.testing.expectError(error.InvalidDuration, parse(&.{ "#zig", "ADD", "VOICE", "a!*@h", "abc" }));

    const ctx = ReplyContext{ .server_name = "irc.example.test", .requester = "dan" };
    var short: [8]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildAccessEnd(&short, ctx, "#zig"));
}
