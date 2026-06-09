//! Oper-only WHOIS privileged-information helpers.
//!
//! This module is deliberately standalone: command handlers pass borrowed
//! snapshots in, and the formatter emits ordinary server numeric replies into
//! caller-owned buffers. It never models services as users and never emits
//! pseudo-client traffic.
const std = @import("std");

pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_TOKEN_BYTES: usize = 128;
pub const DEFAULT_MAX_FIELD_LIST_BYTES: usize = 128;

/// Real WHOIS numerics used by the oper-info renderer.
pub const Numeric = enum(u16) {
    RPL_WHOISSERVER = 312,
    RPL_WHOISOPERATOR = 313,
    RPL_WHOISIDLE = 317,
    RPL_WHOISACTUALLY = 338,
    RPL_WHOISSECURE = 671,

    pub fn code(self: Numeric) u16 {
        return @intFromEnum(self);
    }

    pub fn format(self: Numeric, buf: []u8) OperInfoError![]const u8 {
        return formatCode(self.code(), buf);
    }
};

pub const Params = struct {
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_token_bytes: usize = DEFAULT_MAX_TOKEN_BYTES,
    max_field_list_bytes: usize = DEFAULT_MAX_FIELD_LIST_BYTES,
};

pub const default_params = Params{};

pub const OperInfoError = error{
    OutputTooSmall,
    TooManyLines,
    MessageTooLong,
    EmptyFieldList,
    UnknownField,
    DuplicateField,
    FieldListTooLong,
    InvalidServerName,
    ServerNameTooLong,
    InvalidNick,
    NickTooLong,
    InvalidHost,
    HostTooLong,
    InvalidToken,
    TokenTooLong,
};

/// Privileged WHOIS fields this helper knows how to expose.
pub const Field = enum {
    real_ip,
    real_host,
    connect_time,
    server,
    ssl_cipher,
    oper_class,
};

/// Parsed set of requested privileged WHOIS fields.
pub const FieldSet = struct {
    set: std.EnumSet(Field) = .empty,

    pub fn empty() FieldSet {
        return .{};
    }

    pub fn all() FieldSet {
        return .{ .set = std.EnumSet(Field).full };
    }

    pub fn initMany(fields: []const Field) FieldSet {
        return .{ .set = std.EnumSet(Field).initMany(fields) };
    }

    pub fn parse(raw: []const u8) OperInfoError!FieldSet {
        return parseWithParams(default_params, raw);
    }

    /// Parse a comma/space separated field list. `*` and `all` request every
    /// supported field. Field aliases accept either `_` or `-`.
    pub fn parseWithParams(comptime params: Params, raw: []const u8) OperInfoError!FieldSet {
        if (raw.len > params.max_field_list_bytes) return error.FieldListTooLong;

        var out = FieldSet.empty();
        var saw_token = false;
        var index: usize = 0;
        while (index < raw.len) {
            while (index < raw.len and isFieldSeparator(raw[index])) index += 1;
            if (index >= raw.len) break;

            const start = index;
            while (index < raw.len and !isFieldSeparator(raw[index])) index += 1;
            const token = raw[start..index];
            saw_token = true;

            if (tokenEq(token, "*") or tokenEq(token, "all")) {
                if (out.count() != 0) return error.DuplicateField;
                out = FieldSet.all();
                continue;
            }

            const field = fieldFromToken(token) orelse return error.UnknownField;
            if (out.contains(field)) return error.DuplicateField;
            out.insert(field);
        }

        if (!saw_token) return error.EmptyFieldList;
        return out;
    }

    pub fn contains(self: FieldSet, field: Field) bool {
        return self.set.contains(field);
    }

    pub fn insert(self: *FieldSet, field: Field) void {
        self.set.insert(field);
    }

    pub fn count(self: FieldSet) usize {
        return self.set.count();
    }
};

/// Caller-provided WHOIS envelope. `server_name` is the numeric source,
/// `requester_nick` receives the replies, and `target_nick` is the WHOIS
/// subject.
pub const WhoisEnvelope = struct {
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
};

/// Borrowed privileged data for a WHOIS subject.
pub const OperWhoisInfo = struct {
    real_ip: ?[]const u8 = null,
    real_host: ?[]const u8 = null,
    connect_time: ?u64 = null,
    server: ?[]const u8 = null,
    ssl_cipher: ?[]const u8 = null,
    oper_class: ?[]const u8 = null,

    pub fn hasField(self: OperWhoisInfo, field: Field) bool {
        return switch (field) {
            .real_ip => self.real_ip != null,
            .real_host => self.real_host != null,
            .connect_time => self.connect_time != null,
            .server => self.server != null,
            .ssl_cipher => self.ssl_cipher != null,
            .oper_class => self.oper_class != null,
        };
    }
};

pub const Line = struct {
    bytes: []const u8,
};

/// Caller-owned storage for complete CRLF-terminated numeric lines.
pub const LineSink = struct {
    lines: []Line,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    pub fn slice(self: *const LineSink) []const Line {
        return self.lines[0..self.count];
    }

    pub fn reset(self: *LineSink) void {
        self.count = 0;
        self.used = 0;
    }

    fn beginLine(self: *LineSink, max_line_bytes: usize) OperInfoError!LineBuilder {
        if (self.count >= self.lines.len) return error.TooManyLines;
        return LineBuilder.init(self.storage[self.used..], max_line_bytes);
    }

    fn commitLine(self: *LineSink, builder: *const LineBuilder) OperInfoError!void {
        if (self.count >= self.lines.len) return error.TooManyLines;
        if (builder.len > builder.max_line_bytes) return error.MessageTooLong;
        if (builder.len > self.storage.len - self.used) return error.OutputTooSmall;

        const start = self.used;
        self.used += builder.len;
        self.lines[self.count] = .{ .bytes = self.storage[start..self.used] };
        self.count += 1;
    }
};

/// The explicit oper gate. Non-opers receive no privileged WHOIS lines.
pub fn requesterMaySeeOperInfo(requester_is_oper: bool) bool {
    return requester_is_oper;
}

/// Return whether a specific field is both requested and available after the
/// oper gate. `real_ip` and `real_host` are paired because RPL_WHOISACTUALLY
/// carries both values in one real numeric reply.
pub fn shouldRenderField(
    requester_is_oper: bool,
    requested: FieldSet,
    info: OperWhoisInfo,
    field: Field,
) bool {
    if (!requesterMaySeeOperInfo(requester_is_oper)) return false;
    if (!requested.contains(field)) return false;
    return switch (field) {
        .real_ip, .real_host => info.real_ip != null and info.real_host != null,
        else => info.hasField(field),
    };
}

/// Render oper-only WHOIS extras. Returns the number of lines appended.
///
/// If `requester_is_oper` is false this returns `0` before validating the
/// envelope or privileged data, so malformed hidden data cannot affect a
/// non-oper response.
pub fn renderOperWhoisExtras(
    sink: *LineSink,
    envelope: WhoisEnvelope,
    requester_is_oper: bool,
    requested: FieldSet,
    info: OperWhoisInfo,
) OperInfoError!usize {
    return renderOperWhoisExtrasWith(default_params, sink, envelope, requester_is_oper, requested, info);
}

pub fn renderOperWhoisExtrasWith(
    comptime params: Params,
    sink: *LineSink,
    envelope: WhoisEnvelope,
    requester_is_oper: bool,
    requested: FieldSet,
    info: OperWhoisInfo,
) OperInfoError!usize {
    if (!requesterMaySeeOperInfo(requester_is_oper)) return 0;

    try validateEnvelopeWith(params, envelope);
    const start_count = sink.count;

    if ((requested.contains(.real_ip) or requested.contains(.real_host)) and
        info.real_ip != null and info.real_host != null)
    {
        try validateHostWith(params, info.real_host.?);
        try validateHostWith(params, info.real_ip.?);
        try writeWhoisActually(params, sink, envelope, info.real_host.?, info.real_ip.?);
    }

    if (requested.contains(.connect_time)) {
        if (info.connect_time) |connect_time| {
            try writeWhoisConnectTime(params, sink, envelope, connect_time);
        }
    }

    if (requested.contains(.server)) {
        if (info.server) |server| {
            try validateServerNameWith(params, server);
            try writeWhoisServer(params, sink, envelope, server);
        }
    }

    if (requested.contains(.ssl_cipher)) {
        if (info.ssl_cipher) |cipher| {
            try validateTokenWith(params, cipher);
            try writeWhoisSecure(params, sink, envelope, cipher);
        }
    }

    if (requested.contains(.oper_class)) {
        if (info.oper_class) |class| {
            try validateTokenWith(params, class);
            try writeWhoisOperator(params, sink, envelope, class);
        }
    }

    return sink.count - start_count;
}

fn writeWhoisActually(
    comptime params: Params,
    sink: *LineSink,
    envelope: WhoisEnvelope,
    real_host: []const u8,
    real_ip: []const u8,
) OperInfoError!void {
    try appendNumericLine(params, sink, .RPL_WHOISACTUALLY, envelope, &.{ envelope.target_nick, real_host, real_ip }, "actually using host");
}

fn writeWhoisConnectTime(
    comptime params: Params,
    sink: *LineSink,
    envelope: WhoisEnvelope,
    connect_time: u64,
) OperInfoError!void {
    var zero_buf: [1]u8 = .{'0'};
    var time_buf: [20]u8 = undefined;
    try appendNumericLine(params, sink, .RPL_WHOISIDLE, envelope, &.{ envelope.target_nick, zero_buf[0..], unsignedToken(connect_time, &time_buf) }, "seconds idle, signon time");
}

fn writeWhoisServer(
    comptime params: Params,
    sink: *LineSink,
    envelope: WhoisEnvelope,
    server: []const u8,
) OperInfoError!void {
    try appendNumericLine(params, sink, .RPL_WHOISSERVER, envelope, &.{ envelope.target_nick, server }, "is connected to this server");
}

fn writeWhoisSecure(
    comptime params: Params,
    sink: *LineSink,
    envelope: WhoisEnvelope,
    cipher: []const u8,
) OperInfoError!void {
    var trailing: [DEFAULT_MAX_TOKEN_BYTES + 32]u8 = undefined;
    var writer = LineBuilder.init(&trailing, trailing.len);
    try writer.bytes("is using a secure connection (");
    try writer.bytes(cipher);
    try writer.byte(')');
    try appendNumericLine(params, sink, .RPL_WHOISSECURE, envelope, &.{envelope.target_nick}, writer.slice());
}

fn writeWhoisOperator(
    comptime params: Params,
    sink: *LineSink,
    envelope: WhoisEnvelope,
    oper_class: []const u8,
) OperInfoError!void {
    var trailing: [DEFAULT_MAX_TOKEN_BYTES + 29]u8 = undefined;
    var writer = LineBuilder.init(&trailing, trailing.len);
    try writer.bytes("is an IRC operator (");
    try writer.bytes(oper_class);
    try writer.byte(')');
    try appendNumericLine(params, sink, .RPL_WHOISOPERATOR, envelope, &.{envelope.target_nick}, writer.slice());
}

fn appendNumericLine(
    comptime params: Params,
    sink: *LineSink,
    numeric: Numeric,
    envelope: WhoisEnvelope,
    middle_params: []const []const u8,
    trailing: []const u8,
) OperInfoError!void {
    var b = try sink.beginLine(params.max_line_bytes);
    try b.byte(':');
    try b.bytes(envelope.server_name);
    try b.byte(' ');
    var code_buf: [3]u8 = undefined;
    try b.bytes(try numeric.format(&code_buf));
    try b.byte(' ');
    try b.bytes(envelope.requester_nick);
    for (middle_params) |param| {
        try b.byte(' ');
        try b.bytes(param);
    }
    try b.bytes(" :");
    try b.bytes(trailing);
    try b.bytes("\r\n");
    try sink.commitLine(&b);
}

pub fn validateEnvelope(envelope: WhoisEnvelope) OperInfoError!void {
    return validateEnvelopeWith(default_params, envelope);
}

pub fn validateEnvelopeWith(comptime params: Params, envelope: WhoisEnvelope) OperInfoError!void {
    try validateServerNameWith(params, envelope.server_name);
    try validateNickWith(params, envelope.requester_nick);
    try validateNickWith(params, envelope.target_nick);
}

pub fn validateServerName(server_name: []const u8) OperInfoError!void {
    return validateServerNameWith(default_params, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) OperInfoError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validHostByte(ch)) return error.InvalidServerName;
    }
}

pub fn validateNick(nick: []const u8) OperInfoError!void {
    return validateNickWith(default_params, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) OperInfoError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateHost(host: []const u8) OperInfoError!void {
    return validateHostWith(default_params, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) OperInfoError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
}

pub fn validateToken(token: []const u8) OperInfoError!void {
    return validateTokenWith(default_params, token);
}

pub fn validateTokenWith(comptime params: Params, token: []const u8) OperInfoError!void {
    if (token.len == 0) return error.InvalidToken;
    if (token.len > params.max_token_bytes) return error.TokenTooLong;
    for (token) |ch| {
        if (!validTokenByte(ch)) return error.InvalidToken;
    }
}

fn fieldFromToken(token: []const u8) ?Field {
    if (tokenEq(token, "real_ip") or tokenEq(token, "real-ip") or tokenEq(token, "ip")) return .real_ip;
    if (tokenEq(token, "real_host") or tokenEq(token, "real-host") or tokenEq(token, "host")) return .real_host;
    if (tokenEq(token, "connect_time") or tokenEq(token, "connect-time") or tokenEq(token, "signon")) return .connect_time;
    if (tokenEq(token, "server")) return .server;
    if (tokenEq(token, "ssl_cipher") or tokenEq(token, "ssl-cipher") or tokenEq(token, "cipher")) return .ssl_cipher;
    if (tokenEq(token, "oper_class") or tokenEq(token, "oper-class") or tokenEq(token, "class")) return .oper_class;
    return null;
}

fn isFieldSeparator(ch: u8) bool {
    return ch == ',' or ch == ' ' or ch == '\t';
}

fn tokenEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |aa, bb| {
        if (asciiLower(aa) != asciiLower(bb)) return false;
    }
    return true;
}

fn asciiLower(ch: u8) u8 {
    return if (ch >= 'A' and ch <= 'Z') ch + 32 else ch;
}

fn validNickByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
}

fn validHostByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']', '/' => true,
        else => false,
    };
}

fn validTokenByte(ch: u8) bool {
    if (ch <= 0x20 or ch == 0x7f) return false;
    return ch != ':';
}

fn formatCode(value: u16, buf: []u8) OperInfoError![]const u8 {
    if (buf.len < 3) return error.OutputTooSmall;
    buf[0] = '0' + @as(u8, @intCast((value / 100) % 10));
    buf[1] = '0' + @as(u8, @intCast((value / 10) % 10));
    buf[2] = '0' + @as(u8, @intCast(value % 10));
    return buf[0..3];
}

fn unsignedToken(value: u64, buf: *[20]u8) []const u8 {
    var n = buf.len;
    var current = value;
    while (true) {
        n -= 1;
        buf[n] = '0' + @as(u8, @intCast(current % 10));
        current /= 10;
        if (current == 0) break;
    }
    return buf[n..];
}

const LineBuilder = struct {
    out: []u8,
    len: usize = 0,
    max_line_bytes: usize,

    fn init(out: []u8, max_line_bytes: usize) LineBuilder {
        return .{ .out = out, .max_line_bytes = max_line_bytes };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn bytes(self: *LineBuilder, data: []const u8) OperInfoError!void {
        if (data.len > self.out.len - self.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + data.len], data);
        self.len += data.len;
    }

    fn byte(self: *LineBuilder, value: u8) OperInfoError!void {
        if (self.len >= self.out.len) return error.OutputTooSmall;
        self.out[self.len] = value;
        self.len += 1;
    }
};

const testing = std.testing;

fn testSink(lines: []Line, storage: []u8) LineSink {
    return .{ .lines = lines, .storage = storage };
}

fn sampleEnvelope() WhoisEnvelope {
    return .{
        .server_name = "irc.example",
        .requester_nick = "RootOper",
        .target_nick = "Alice",
    };
}

fn sampleInfo() OperWhoisInfo {
    return .{
        .real_ip = "203.0.113.9",
        .real_host = "pool-203-0-113-9.example.net",
        .connect_time = 1_700_000_000,
        .server = "leaf1.example",
        .ssl_cipher = "TLS_AES_256_GCM_SHA384",
        .oper_class = "netadmin",
    };
}

test "field parser accepts names aliases wildcard and case" {
    const fields = try FieldSet.parse("REAL-IP, real_host connect-time\tserver,ssl-cipher oper-class");
    try testing.expect(fields.contains(.real_ip));
    try testing.expect(fields.contains(.real_host));
    try testing.expect(fields.contains(.connect_time));
    try testing.expect(fields.contains(.server));
    try testing.expect(fields.contains(.ssl_cipher));
    try testing.expect(fields.contains(.oper_class));
    try testing.expectEqual(@as(usize, 6), fields.count());

    const aliases = try FieldSet.parse("ip host signon cipher class");
    try testing.expect(aliases.contains(.real_ip));
    try testing.expect(aliases.contains(.real_host));
    try testing.expect(aliases.contains(.connect_time));
    try testing.expect(aliases.contains(.ssl_cipher));
    try testing.expect(aliases.contains(.oper_class));

    const all = try FieldSet.parse("*");
    try testing.expectEqual(@as(usize, 6), all.count());
}

test "field parser rejects empty unknown duplicate and too long lists" {
    try testing.expectError(error.EmptyFieldList, FieldSet.parse(" , \t "));
    try testing.expectError(error.UnknownField, FieldSet.parse("real_ip,private_note"));
    try testing.expectError(error.DuplicateField, FieldSet.parse("real_ip,ip"));
    try testing.expectError(error.DuplicateField, FieldSet.parse("real_ip,all"));

    const Small = Params{ .max_field_list_bytes = 4 };
    try testing.expectError(error.FieldListTooLong, FieldSet.parseWithParams(Small, "server"));
}

test "numeric formatting uses real three digit codes" {
    var buf: [3]u8 = undefined;
    try testing.expectEqual(@as(u16, 338), Numeric.RPL_WHOISACTUALLY.code());
    try testing.expectEqual(@as(u16, 671), Numeric.RPL_WHOISSECURE.code());
    try testing.expectEqualStrings("312", try Numeric.RPL_WHOISSERVER.format(&buf));
    try testing.expectEqualStrings("313", try Numeric.RPL_WHOISOPERATOR.format(&buf));
    try testing.expectEqualStrings("317", try Numeric.RPL_WHOISIDLE.format(&buf));

    var tiny: [2]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, Numeric.RPL_WHOISACTUALLY.format(&tiny));
}

test "gate and shouldRenderField hide everything from non opers" {
    const requested = FieldSet.all();
    const info = sampleInfo();

    try testing.expect(!requesterMaySeeOperInfo(false));
    try testing.expect(requesterMaySeeOperInfo(true));
    try testing.expect(!shouldRenderField(false, requested, info, .real_ip));
    try testing.expect(shouldRenderField(true, requested, info, .real_ip));
    try testing.expect(shouldRenderField(true, requested, info, .real_host));
    try testing.expect(shouldRenderField(true, requested, info, .ssl_cipher));

    var partial = info;
    partial.real_ip = null;
    try testing.expect(!shouldRenderField(true, requested, partial, .real_ip));
    try testing.expect(!shouldRenderField(true, requested, partial, .real_host));
}

test "non oper render is empty and does not validate hidden data" {
    var lines: [1]Line = undefined;
    var storage: [16]u8 = undefined;
    var sink = testSink(&lines, &storage);

    const count = try renderOperWhoisExtras(
        &sink,
        .{ .server_name = "bad server", .requester_nick = "bad nick", .target_nick = "Alice" },
        false,
        FieldSet.all(),
        .{ .real_ip = "bad ip with spaces", .ssl_cipher = "bad cipher with spaces" },
    );

    try testing.expectEqual(@as(usize, 0), count);
    try testing.expectEqual(@as(usize, 0), sink.count);
    try testing.expectEqual(@as(usize, 0), sink.used);
}

test "oper render emits all privileged WHOIS extras in stable numeric order" {
    var lines: [8]Line = undefined;
    var storage: [1024]u8 = undefined;
    var sink = testSink(&lines, &storage);

    const count = try renderOperWhoisExtras(&sink, sampleEnvelope(), true, FieldSet.all(), sampleInfo());

    try testing.expectEqual(@as(usize, 5), count);
    try testing.expectEqual(@as(usize, 5), sink.slice().len);
    try testing.expectEqualStrings(
        ":irc.example 338 RootOper Alice pool-203-0-113-9.example.net 203.0.113.9 :actually using host\r\n",
        sink.slice()[0].bytes,
    );
    try testing.expectEqualStrings(
        ":irc.example 317 RootOper Alice 0 1700000000 :seconds idle, signon time\r\n",
        sink.slice()[1].bytes,
    );
    try testing.expectEqualStrings(
        ":irc.example 312 RootOper Alice leaf1.example :is connected to this server\r\n",
        sink.slice()[2].bytes,
    );
    try testing.expectEqualStrings(
        ":irc.example 671 RootOper Alice :is using a secure connection (TLS_AES_256_GCM_SHA384)\r\n",
        sink.slice()[3].bytes,
    );
    try testing.expectEqualStrings(
        ":irc.example 313 RootOper Alice :is an IRC operator (netadmin)\r\n",
        sink.slice()[4].bytes,
    );
}

test "selective render skips unrequested and unavailable fields" {
    var lines: [4]Line = undefined;
    var storage: [512]u8 = undefined;
    var sink = testSink(&lines, &storage);

    const requested = FieldSet.initMany(&.{ .real_ip, .ssl_cipher, .oper_class });
    var info = sampleInfo();
    info.ssl_cipher = null;

    const count = try renderOperWhoisExtras(&sink, sampleEnvelope(), true, requested, info);

    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualStrings(
        ":irc.example 338 RootOper Alice pool-203-0-113-9.example.net 203.0.113.9 :actually using host\r\n",
        sink.slice()[0].bytes,
    );
    try testing.expectEqualStrings(
        ":irc.example 313 RootOper Alice :is an IRC operator (netadmin)\r\n",
        sink.slice()[1].bytes,
    );
}

test "real host and ip are paired for RPL_WHOISACTUALLY" {
    var lines: [2]Line = undefined;
    var storage: [256]u8 = undefined;
    var sink = testSink(&lines, &storage);

    var info = sampleInfo();
    info.real_host = null;
    const requested = FieldSet.initMany(&.{ .real_ip, .real_host });

    const count = try renderOperWhoisExtras(&sink, sampleEnvelope(), true, requested, info);

    try testing.expectEqual(@as(usize, 0), count);
    try testing.expectEqual(@as(usize, 0), sink.count);
}

test "validation rejects invalid envelope and privileged tokens for opers" {
    var lines: [4]Line = undefined;
    var storage: [512]u8 = undefined;
    var sink = testSink(&lines, &storage);

    try testing.expectError(
        error.InvalidServerName,
        renderOperWhoisExtras(&sink, .{ .server_name = "bad server", .requester_nick = "RootOper", .target_nick = "Alice" }, true, FieldSet.all(), sampleInfo()),
    );

    sink.reset();
    var bad_cipher = sampleInfo();
    bad_cipher.ssl_cipher = "TLS bad";
    try testing.expectError(error.InvalidToken, renderOperWhoisExtras(&sink, sampleEnvelope(), true, FieldSet.initMany(&.{.ssl_cipher}), bad_cipher));

    sink.reset();
    var bad_ip = sampleInfo();
    bad_ip.real_ip = "203.0.113.9\r\n";
    try testing.expectError(error.InvalidHost, renderOperWhoisExtras(&sink, sampleEnvelope(), true, FieldSet.initMany(&.{.real_ip}), bad_ip));
}

test "sink reports line count storage and configured line bounds" {
    var one_line: [1]Line = undefined;
    var enough_storage: [1024]u8 = undefined;
    var count_limited = testSink(&one_line, &enough_storage);
    try testing.expectError(error.TooManyLines, renderOperWhoisExtras(&count_limited, sampleEnvelope(), true, FieldSet.all(), sampleInfo()));

    var many_lines: [8]Line = undefined;
    var tiny_storage: [20]u8 = undefined;
    var storage_limited = testSink(&many_lines, &tiny_storage);
    try testing.expectError(error.OutputTooSmall, renderOperWhoisExtras(&storage_limited, sampleEnvelope(), true, FieldSet.initMany(&.{.server}), sampleInfo()));

    var bounded_storage: [512]u8 = undefined;
    var bounded = testSink(&many_lines, &bounded_storage);
    const TinyLine = Params{ .max_line_bytes = 24 };
    try testing.expectError(error.MessageTooLong, renderOperWhoisExtrasWith(TinyLine, &bounded, sampleEnvelope(), true, FieldSet.initMany(&.{.server}), sampleInfo()));
}

test "line sink reset allows reuse" {
    var lines: [2]Line = undefined;
    var storage: [256]u8 = undefined;
    var sink = testSink(&lines, &storage);

    _ = try renderOperWhoisExtras(&sink, sampleEnvelope(), true, FieldSet.initMany(&.{.server}), sampleInfo());
    try testing.expectEqual(@as(usize, 1), sink.count);
    try testing.expect(sink.used > 0);

    sink.reset();
    try testing.expectEqual(@as(usize, 0), sink.count);
    try testing.expectEqual(@as(usize, 0), sink.used);

    _ = try renderOperWhoisExtras(&sink, sampleEnvelope(), true, FieldSet.initMany(&.{.oper_class}), sampleInfo());
    try testing.expectEqualStrings(
        ":irc.example 313 RootOper Alice :is an IRC operator (netadmin)\r\n",
        sink.slice()[0].bytes,
    );
}
