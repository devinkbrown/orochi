//! CTCP codec for IRC PRIVMSG and NOTICE bodies.
//!
//! CTCP frames are embedded in the trailing parameter as SOH-delimited spans:
//! `\x01COMMAND optional-argument\x01`. This module keeps parsing zero-copy and
//! allocation-free; dequoting and builders write into caller-provided buffers.
const std = @import("std");

pub const delimiter: u8 = 0x01;
pub const quote_byte: u8 = 0x10;

/// Conservative command bound for hot-path parsed views.
pub const default_max_command_len: usize = 32;

pub const ParseError = error{
    InvalidMessage,
    UnterminatedCtcp,
    EmptyCtcp,
    InvalidCommand,
    CommandTooLong,
    MalformedQuote,
};

pub const QuoteError = error{
    InvalidByte,
    MalformedQuote,
    OutputTooSmall,
};

pub const BuildError = error{
    InvalidCommand,
    InvalidTarget,
    InvalidByte,
    OutputTooSmall,
};

/// IRC command carrying the CTCP body.
pub const Carrier = enum {
    privmsg,
    notice,
};

/// Known CTCP commands. Unknown commands remain parseable and are preserved raw.
pub const CommandId = enum {
    version,
    ping,
    time,
    action,
    clientinfo,
    source,
    userinfo,
    finger,
    dcc,
    unknown,
};

/// Common DCC subcommands detected from a CTCP DCC argument.
pub const DccKind = enum {
    send,
    chat,
    accept,
    resume_file,
    unknown,
};

pub const ParseConfig = struct {
    max_command_len: usize = default_max_command_len,
    require_entire_message: bool = false,
};

/// Zero-copy parsed CTCP view. Slices point into the caller-owned message body.
pub const CtcpView = struct {
    carrier: Carrier,
    raw: []const u8,
    command: []const u8,
    arg_raw: ?[]const u8 = null,
    id: CommandId,
    dcc: ?DccKind = null,

    pub fn isReply(self: CtcpView) bool {
        return self.carrier == .notice;
    }

    pub fn argOrEmpty(self: CtcpView) []const u8 {
        return self.arg_raw orelse "";
    }

    /// Dequote the CTCP argument into caller storage.
    pub fn dequoteArg(self: CtcpView, out_buf: []u8) QuoteError![]const u8 {
        return dequote(self.argOrEmpty(), out_buf);
    }
};

/// Compile-time configurable parser and iterator.
pub fn Parser(comptime config: ParseConfig) type {
    comptime {
        if (config.max_command_len == 0) @compileError("max_command_len must be nonzero");
    }

    return struct {
        pub const Iterator = struct {
            carrier: Carrier,
            text: []const u8,
            cursor: usize = 0,

            pub fn next(self: *Iterator) ParseError!?CtcpView {
                validateMessageText(self.text) catch |err| return err;

                const start = findByte(self.text, self.cursor, delimiter) orelse {
                    self.cursor = self.text.len;
                    return null;
                };
                const end = findByte(self.text, start + 1, delimiter) orelse return error.UnterminatedCtcp;

                if (config.require_entire_message and (start != 0 or end + 1 != self.text.len)) {
                    return error.InvalidMessage;
                }

                self.cursor = end + 1;
                return try parseBody(self.carrier, self.text[start .. end + 1], self.text[start + 1 .. end]);
            }
        };

        pub fn iterator(carrier: Carrier, text: []const u8) Iterator {
            return .{ .carrier = carrier, .text = text };
        }

        pub fn parseFirst(carrier: Carrier, text: []const u8) ParseError!?CtcpView {
            var it = @This().iterator(carrier, text);
            return it.next();
        }

        fn parseBody(carrier: Carrier, raw: []const u8, body: []const u8) ParseError!CtcpView {
            if (body.len == 0) return error.EmptyCtcp;

            const command_end = findSpace(body, 0) orelse body.len;
            const command = body[0..command_end];
            if (command.len == 0) return error.InvalidCommand;
            if (command.len > config.max_command_len) return error.CommandTooLong;
            if (!validCommand(command)) return error.InvalidCommand;

            var arg_raw: ?[]const u8 = null;
            if (command_end < body.len) {
                const arg_start = skipSpaces(body, command_end);
                if (arg_start < body.len) {
                    arg_raw = body[arg_start..];
                    try validateQuoted(arg_raw.?);
                }
            }

            const id = classifyCommand(command);
            return .{
                .carrier = carrier,
                .raw = raw,
                .command = command,
                .arg_raw = arg_raw,
                .id = id,
                .dcc = if (id == .dcc) classifyDcc(arg_raw) else null,
            };
        }
    };
}

/// Return true when the text contains a CTCP delimiter byte.
pub fn hasCtcp(text: []const u8) bool {
    return findByte(text, 0, delimiter) != null;
}

/// Iterate over CTCP spans in a PRIVMSG/NOTICE trailing parameter.
pub fn iterator(carrier: Carrier, text: []const u8) Parser(.{}).Iterator {
    return Parser(.{}).iterator(carrier, text);
}

/// Parse the first CTCP span. Ordinary non-CTCP text returns null.
pub fn parseFirst(carrier: Carrier, text: []const u8) ParseError!?CtcpView {
    return Parser(.{}).parseFirst(carrier, text);
}

/// Write CTCP low-level quoted bytes into caller storage.
///
/// The CTCP delimiter itself has no low-level quote form, so it is rejected.
pub fn quote(input: []const u8, out_buf: []u8) QuoteError![]const u8 {
    var write: usize = 0;
    for (input) |ch| {
        switch (ch) {
            delimiter => return error.InvalidByte,
            0 => try appendEscaped(&write, out_buf, '0'),
            '\n' => try appendEscaped(&write, out_buf, 'n'),
            '\r' => try appendEscaped(&write, out_buf, 'r'),
            quote_byte => try appendEscaped(&write, out_buf, quote_byte),
            else => {
                if (write >= out_buf.len) return error.OutputTooSmall;
                out_buf[write] = ch;
                write += 1;
            },
        }
    }
    return out_buf[0..write];
}

/// Decode CTCP low-level quoted bytes into caller storage.
pub fn dequote(input: []const u8, out_buf: []u8) QuoteError![]const u8 {
    var read: usize = 0;
    var write: usize = 0;

    while (read < input.len) {
        var ch = input[read];
        read += 1;

        if (ch == quote_byte) {
            if (read >= input.len) return error.MalformedQuote;
            const esc = input[read];
            read += 1;
            ch = switch (esc) {
                '0' => 0,
                'n' => '\n',
                'r' => '\r',
                quote_byte => quote_byte,
                else => return error.MalformedQuote,
            };
        }

        if (write >= out_buf.len) return error.OutputTooSmall;
        out_buf[write] = ch;
        write += 1;
    }

    return out_buf[0..write];
}

/// Build only the SOH-delimited CTCP payload.
pub fn buildPayload(command: []const u8, arg: ?[]const u8, out_buf: []u8) BuildError![]const u8 {
    if (!validCommand(command)) return error.InvalidCommand;

    var write: usize = 0;
    try appendByte(&write, out_buf, delimiter);
    try appendSlice(&write, out_buf, command);

    if (arg) |bytes| {
        if (bytes.len != 0) {
            try appendByte(&write, out_buf, ' ');
            const quoted = quote(bytes, out_buf[write..]) catch |err| return switch (err) {
                error.InvalidByte => error.InvalidByte,
                error.OutputTooSmall => error.OutputTooSmall,
                error.MalformedQuote => error.InvalidByte,
            };
            write += quoted.len;
        }
    }

    try appendByte(&write, out_buf, delimiter);
    return out_buf[0..write];
}

/// Build a complete IRC PRIVMSG CTCP request line without CRLF.
pub fn buildRequest(target: []const u8, command: []const u8, arg: ?[]const u8, out_buf: []u8) BuildError![]const u8 {
    return buildLine(.privmsg, target, command, arg, out_buf);
}

/// Build a complete IRC NOTICE CTCP reply line without CRLF.
pub fn buildReply(target: []const u8, command: []const u8, arg: ?[]const u8, out_buf: []u8) BuildError![]const u8 {
    return buildLine(.notice, target, command, arg, out_buf);
}

/// Build a complete IRC CTCP carrier line without CRLF.
pub fn buildLine(
    carrier: Carrier,
    target: []const u8,
    command: []const u8,
    arg: ?[]const u8,
    out_buf: []u8,
) BuildError![]const u8 {
    if (!validTarget(target)) return error.InvalidTarget;

    var write: usize = 0;
    try appendSlice(&write, out_buf, carrierName(carrier));
    try appendByte(&write, out_buf, ' ');
    try appendSlice(&write, out_buf, target);
    try appendSlice(&write, out_buf, " :");

    const payload = try buildPayload(command, arg, out_buf[write..]);
    write += payload.len;
    return out_buf[0..write];
}

/// Canonical uppercase spelling for known CTCP commands.
pub fn commandName(id: CommandId) ?[]const u8 {
    return switch (id) {
        .version => "VERSION",
        .ping => "PING",
        .time => "TIME",
        .action => "ACTION",
        .clientinfo => "CLIENTINFO",
        .source => "SOURCE",
        .userinfo => "USERINFO",
        .finger => "FINGER",
        .dcc => "DCC",
        .unknown => null,
    };
}

fn carrierName(carrier: Carrier) []const u8 {
    return switch (carrier) {
        .privmsg => "PRIVMSG",
        .notice => "NOTICE",
    };
}

fn classifyCommand(command: []const u8) CommandId {
    if (asciiEqlIgnoreCase(command, "VERSION")) return .version;
    if (asciiEqlIgnoreCase(command, "PING")) return .ping;
    if (asciiEqlIgnoreCase(command, "TIME")) return .time;
    if (asciiEqlIgnoreCase(command, "ACTION")) return .action;
    if (asciiEqlIgnoreCase(command, "CLIENTINFO")) return .clientinfo;
    if (asciiEqlIgnoreCase(command, "SOURCE")) return .source;
    if (asciiEqlIgnoreCase(command, "USERINFO")) return .userinfo;
    if (asciiEqlIgnoreCase(command, "FINGER")) return .finger;
    if (asciiEqlIgnoreCase(command, "DCC")) return .dcc;
    return .unknown;
}

fn classifyDcc(arg_raw: ?[]const u8) DccKind {
    const arg = arg_raw orelse return .unknown;
    const token_end = findSpace(arg, 0) orelse arg.len;
    const token = arg[0..token_end];
    if (asciiEqlIgnoreCase(token, "SEND")) return .send;
    if (asciiEqlIgnoreCase(token, "CHAT")) return .chat;
    if (asciiEqlIgnoreCase(token, "ACCEPT")) return .accept;
    if (asciiEqlIgnoreCase(token, "RESUME")) return .resume_file;
    return .unknown;
}

fn validateMessageText(text: []const u8) ParseError!void {
    for (text) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidMessage,
            else => {},
        }
    }
}

fn validateQuoted(input: []const u8) ParseError!void {
    var read: usize = 0;
    while (read < input.len) {
        const ch = input[read];
        read += 1;
        if (ch != quote_byte) continue;

        if (read >= input.len) return error.MalformedQuote;
        const esc = input[read];
        read += 1;
        switch (esc) {
            '0', 'n', 'r', quote_byte => {},
            else => return error.MalformedQuote,
        }
    }
}

fn validCommand(command: []const u8) bool {
    if (command.len == 0) return false;
    for (command) |ch| {
        switch (ch) {
            'A'...'Z', 'a'...'z', '0'...'9', '-' => {},
            else => return false,
        }
    }
    return true;
}

fn validTarget(target: []const u8) bool {
    if (target.len == 0) return false;
    for (target) |ch| {
        switch (ch) {
            0, '\r', '\n', ' ', ':' => return false,
            else => {},
        }
    }
    return true;
}

fn appendEscaped(write: *usize, out_buf: []u8, esc: u8) QuoteError!void {
    if (write.* + 2 > out_buf.len) return error.OutputTooSmall;
    out_buf[write.*] = quote_byte;
    out_buf[write.* + 1] = esc;
    write.* += 2;
}

fn appendByte(write: *usize, out_buf: []u8, byte: u8) BuildError!void {
    if (write.* >= out_buf.len) return error.OutputTooSmall;
    out_buf[write.*] = byte;
    write.* += 1;
}

fn appendSlice(write: *usize, out_buf: []u8, bytes: []const u8) BuildError!void {
    if (write.* + bytes.len > out_buf.len) return error.OutputTooSmall;
    @memcpy(out_buf[write.* .. write.* + bytes.len], bytes);
    write.* += bytes.len;
}

fn skipSpaces(bytes: []const u8, start: usize) usize {
    var cursor = start;
    while (cursor < bytes.len and bytes[cursor] == ' ') {
        cursor += 1;
    }
    return cursor;
}

fn findSpace(bytes: []const u8, start: usize) ?usize {
    return findByte(bytes, start, ' ');
}

fn findByte(bytes: []const u8, start: usize, needle: u8) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ach, bch| {
        if (asciiUpper(ach) != asciiUpper(bch)) return false;
    }
    return true;
}

fn asciiUpper(ch: u8) u8 {
    return switch (ch) {
        'a'...'z' => ch - ('a' - 'A'),
        else => ch,
    };
}

test "parses ACTION from PRIVMSG body" {
    const view = (try parseFirst(.privmsg, "\x01ACTION waves hello\x01")).?;
    try std.testing.expectEqual(Carrier.privmsg, view.carrier);
    try std.testing.expect(!view.isReply());
    try std.testing.expectEqual(CommandId.action, view.id);
    try std.testing.expectEqualStrings("\x01ACTION waves hello\x01", view.raw);
    try std.testing.expectEqualStrings("ACTION", view.command);
    try std.testing.expectEqualStrings("waves hello", view.argOrEmpty());
}

test "parses embedded spans and keeps ACTIONGRAB distinct from ACTION" {
    const embedded = (try parseFirst(.privmsg, "hi \x01VERSION\x01 there")).?;
    try std.testing.expectEqual(CommandId.version, embedded.id);
    try std.testing.expectEqualStrings("\x01VERSION\x01", embedded.raw);

    const actiongrab = (try parseFirst(.privmsg, "\x01ACTIONGRAB x\x01")).?;
    try std.testing.expectEqual(CommandId.unknown, actiongrab.id);
    try std.testing.expectEqualStrings("ACTIONGRAB", actiongrab.command);
}

test "parses VERSION reply from NOTICE body" {
    const view = (try parseFirst(.notice, "prefix \x01VERSION Orochi 0.1\x01 suffix")).?;
    try std.testing.expect(view.isReply());
    try std.testing.expectEqual(CommandId.version, view.id);
    try std.testing.expectEqualStrings("VERSION", view.command);
    try std.testing.expectEqualStrings("Orochi 0.1", view.argOrEmpty());
}

test "parses and dequotes PING argument" {
    const view = (try parseFirst(.privmsg, "\x01PING token\x10n42\x01")).?;
    try std.testing.expectEqual(CommandId.ping, view.id);

    var out: [32]u8 = undefined;
    const arg = try view.dequoteArg(&out);
    try std.testing.expectEqualStrings("token\n42", arg);
}

test "detects DCC subcommands" {
    const view = (try parseFirst(.privmsg, "\x01DCC SEND file.txt 1 2 3\x01")).?;
    try std.testing.expectEqual(CommandId.dcc, view.id);
    try std.testing.expectEqual(@as(?DccKind, .send), view.dcc);
}

test "builds CTCP request and reply lines" {
    var request_buf: [128]u8 = undefined;
    const request = try buildRequest("nick", "PING", "12345", &request_buf);
    try std.testing.expectEqualStrings("PRIVMSG nick :\x01PING 12345\x01", request);

    var reply_buf: [128]u8 = undefined;
    const reply = try buildReply("nick", "VERSION", "Orochi 0.1", &reply_buf);
    try std.testing.expectEqualStrings("NOTICE nick :\x01VERSION Orochi 0.1\x01", reply);
}

test "low-level quoting round trip" {
    const input = [_]u8{ 'a', 0, 'b', '\n', 'c', '\r', 'd', quote_byte, 'e' };

    var quoted_buf: [32]u8 = undefined;
    const quoted = try quote(&input, &quoted_buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        'a', quote_byte, '0', 'b', quote_byte, 'n', 'c', quote_byte, 'r', 'd', quote_byte, quote_byte, 'e',
    }, quoted);

    var dequoted_buf: [16]u8 = undefined;
    const dequoted = try dequote(quoted, &dequoted_buf);
    try std.testing.expectEqualSlices(u8, &input, dequoted);
}

test "rejects malformed and empty CTCP" {
    try std.testing.expectEqual(@as(?CtcpView, null), try parseFirst(.privmsg, "plain text"));
    try std.testing.expectError(error.EmptyCtcp, parseFirst(.privmsg, "\x01\x01"));
    try std.testing.expectError(error.UnterminatedCtcp, parseFirst(.privmsg, "\x01VERSION"));
    try std.testing.expectError(error.InvalidCommand, parseFirst(.privmsg, "\x01 ACTION\x01"));
    try std.testing.expectError(error.MalformedQuote, parseFirst(.privmsg, "\x01PING \x10x\x01"));
    try std.testing.expectError(error.InvalidMessage, parseFirst(.privmsg, "\x01PING raw\nline\x01"));
}

test "builders reject invalid bytes and small buffers" {
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildPayload("PING", "12345", &tiny));

    var buf: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidByte, buildPayload("PING", "\x01", &buf));
    try std.testing.expectError(error.InvalidCommand, buildPayload("BAD CMD", null, &buf));
    try std.testing.expectError(error.InvalidTarget, buildRequest("bad target", "PING", null, &buf));
}
