//! Client command dispatch and preregistration pipeline.
//!
//! Transport code feeds already parsed IRC lines into this module. Dispatch
//! runs preregistration middleware, enforces command arity, calls typed
//! handlers, and writes replies into caller-owned storage for deterministic
//! tests and reactor integration.
const std = @import("std");
const sasl = @import("../proto/sasl.zig");
const usermode = @import("../proto/usermode.zig");

pub const UserMode = usermode.UserMode;

pub const DispatchError = error{
    ControlByte,
    OutputTooSmall,
    TextTooLong,
};

const SERVER_NAME = "mizuchi.local";
const NETWORK_NAME = "Mizuchi";
const MAX_PARAMS: usize = 15;
const MAX_NICK_BYTES: usize = 64;
const MAX_UID_BYTES: usize = 16;
const MAX_REALNAME_BYTES: usize = 256;
const MAX_ACCOUNT_BYTES: usize = 64;
const MAX_AWAY_BYTES: usize = 256;

/// Parsed IRC line view. Slices borrow from the caller-owned input buffer.
pub const LineView = struct {
    command: []const u8,
    params: [MAX_PARAMS][]const u8 = [_][]const u8{""} ** MAX_PARAMS,
    param_count: usize = 0,

    pub fn paramSlice(self: *const LineView) []const []const u8 {
        return self.params[0..self.param_count];
    }
};

/// Minimal parser used by this file's isolation tests.
pub fn parseLine(input: []const u8) error{ EmptyLine, EmbeddedNul, EmbeddedLineBreak, MissingCommand, TooManyParams }!LineView {
    var body = input;
    if (body.len >= 2 and body[body.len - 2] == '\r' and body[body.len - 1] == '\n') {
        body = body[0 .. body.len - 2];
    } else if (body.len >= 1 and (body[body.len - 1] == '\r' or body[body.len - 1] == '\n')) {
        body = body[0 .. body.len - 1];
    }
    if (body.len == 0) return error.EmptyLine;
    for (body) |ch| {
        switch (ch) {
            0 => return error.EmbeddedNul,
            '\r', '\n' => return error.EmbeddedLineBreak,
            else => {},
        }
    }

    var cursor = skipSpaces(body, 0);
    if (cursor >= body.len) return error.MissingCommand;
    if (body[cursor] == ':') {
        cursor = skipSpaces(body, findSpace(body, cursor) orelse return error.MissingCommand);
    }

    const command_end = findSpace(body, cursor) orelse body.len;
    if (command_end == cursor) return error.MissingCommand;
    var line = LineView{ .command = body[cursor..command_end] };
    cursor = skipSpaces(body, command_end);

    while (cursor < body.len) {
        if (line.param_count == MAX_PARAMS) return error.TooManyParams;
        if (body[cursor] == ':') {
            line.params[line.param_count] = body[cursor + 1 ..];
            line.param_count += 1;
            break;
        }
        const end = findSpace(body, cursor) orelse body.len;
        line.params[line.param_count] = body[cursor..end];
        line.param_count += 1;
        cursor = skipSpaces(body, end);
    }

    return line;
}

const Numeric = enum(u16) {
    RPL_WELCOME = 1,
    RPL_YOURHOST = 2,
    RPL_CREATED = 3,
    RPL_MYINFO = 4,
    RPL_ISUPPORT = 5,
    ERR_INVALIDCAPCMD = 410,
    ERR_UNKNOWNCOMMAND = 421,
    ERR_ERRONEUSNICKNAME = 432,
    ERR_NOTREGISTERED = 451,
    ERR_NEEDMOREPARAMS = 461,
    ERR_ALREADYREGISTRED = 462,
    RPL_LOGGEDIN = 900,
    RPL_SASLSUCCESS = 903,
    ERR_SASLFAIL = 904,
    ERR_SASLABORTED = 906,
};

fn formatCode(numeric: Numeric, buf: []u8) []const u8 {
    const value: u16 = @intFromEnum(numeric);
    buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
    return buf[0..3];
}

fn FixedString(comptime capacity: usize) type {
    return struct {
        bytes: [capacity]u8 = [_]u8{0} ** capacity,
        len: usize = 0,

        fn slice(self: *const @This()) []const u8 {
            return self.bytes[0..self.len];
        }

        fn set(self: *@This(), value: []const u8) DispatchError!void {
            try requireNoControlBytes(value);
            if (value.len > capacity) return error.TextTooLong;
            @memcpy(self.bytes[0..value.len], value);
            self.len = value.len;
        }
    };
}

const PreregState = enum {
    fresh,
    pass_seen,
    nick_seen,
    user_seen,
    registered,
    closing,
};

const CapState = enum {
    idle,
    negotiating,
    complete,
};

const SaslState = enum {
    idle,
    authenticating,
    failed,
    succeeded,
};

const Client = struct {
    identity: struct {
        nick: FixedString(MAX_NICK_BYTES) = .{},
        uid: FixedString(MAX_UID_BYTES) = .{},
        realname: FixedString(MAX_REALNAME_BYTES) = .{},
    } = .{},
    registration: struct {
        prereg: PreregState = .fresh,
        cap: CapState = .idle,
        sasl: SaslState = .idle,
    } = .{},
    protocol: struct {
        negotiated_caps: u128 = 0,
    } = .{},
};

pub const CapId = enum(u6) {
    server_time,
    message_tags,
    echo_message,
    sasl,
    multi_prefix,
    userhost_in_names,
    away_notify,
    setname,
    extended_join,
    account_notify,
    invite_notify,
};

const CapSet = struct {
    bits: u64 = 0,

    fn add(self: *CapSet, id: CapId) void {
        self.bits |= capBit(id);
    }

    fn remove(self: *CapSet, id: CapId) void {
        self.bits &= ~capBit(id);
    }

    fn contains(self: CapSet, id: CapId) bool {
        return (self.bits & capBit(id)) != 0;
    }
};

const CapSpec = struct {
    id: CapId,
    name: []const u8,
    value_302: ?[]const u8 = null,
};

const cap_specs = [_]CapSpec{
    .{ .id = .server_time, .name = "server-time" },
    .{ .id = .message_tags, .name = "message-tags" },
    .{ .id = .echo_message, .name = "echo-message" },
    // Advertise only what handleAuthenticate actually accepts (PLAIN today).
    // EXTERNAL/SCRAM are implemented in proto/sasl.zig but not yet wired here;
    // advertising them would let a client pick a dead mechanism.
    .{ .id = .sasl, .name = "sasl", .value_302 = "PLAIN" },
    .{ .id = .multi_prefix, .name = "multi-prefix" },
    .{ .id = .userhost_in_names, .name = "userhost-in-names" },
    .{ .id = .away_notify, .name = "away-notify" },
    .{ .id = .setname, .name = "setname" },
    .{ .id = .extended_join, .name = "extended-join" },
    .{ .id = .invite_notify, .name = "invite-notify" },
    // account-notify is enumerated but not advertised: the only auth change is
    // SASL during pre-registration, before the client shares any channel, so
    // there is no post-join ACCOUNT event to deliver yet.
};

const CapReplyKind = enum {
    ls,
    ack,
    nak,
};

const CapReply = struct {
    kind: CapReplyKind,
    continuation: bool = false,
    body: []const u8,
};

const CapReplySink = struct {
    replies: []CapReply,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    fn append(self: *CapReplySink, kind: CapReplyKind, continuation: bool, body: []const u8) DispatchError!void {
        if (self.count >= self.replies.len) return error.OutputTooSmall;
        if (self.used + body.len > self.storage.len) return error.OutputTooSmall;
        @memcpy(self.storage[self.used .. self.used + body.len], body);
        self.replies[self.count] = .{
            .kind = kind,
            .continuation = continuation,
            .body = self.storage[self.used .. self.used + body.len],
        };
        self.used += body.len;
        self.count += 1;
    }

    fn slice(self: *const CapReplySink) []const CapReply {
        return self.replies[0..self.count];
    }
};

const CapSession = struct {
    state: CapState = .idle,
    negotiated: CapSet = .{},
    cap_302: bool = false,

    fn registrationHeld(self: CapSession) bool {
        return self.state == .negotiating;
    }

    fn handle(
        self: *CapSession,
        subcommand: []const u8,
        params: []const []const u8,
        sink: *CapReplySink,
    ) DispatchError!CapHandleResult {
        if (std.ascii.eqlIgnoreCase(subcommand, "LS")) {
            self.state = .negotiating;
            self.cap_302 = self.cap_302 or (params.len != 0 and std.mem.eql(u8, params[0], "302"));
            var body: [512]u8 = undefined;
            const caps = try writeCapList(self.cap_302, &body);
            try sink.append(.ls, false, caps);
            return .ok;
        }
        if (std.ascii.eqlIgnoreCase(subcommand, "REQ")) {
            if (params.len == 0) return .missing_parameter;
            self.state = .negotiating;
            if (applyCapRequest(&self.negotiated, params[0])) {
                try sink.append(.ack, false, params[0]);
            } else {
                try sink.append(.nak, false, params[0]);
            }
            return .ok;
        }
        if (std.ascii.eqlIgnoreCase(subcommand, "END")) {
            self.state = .complete;
            return .ok;
        }
        return .invalid_command;
    }
};

const CapHandleResult = enum {
    ok,
    invalid_command,
    missing_parameter,
};

fn capBit(id: CapId) u64 {
    return @as(u64, 1) << @as(u6, @intCast(@intFromEnum(id)));
}

fn writeCapList(cap_302: bool, out: []u8) DispatchError![]const u8 {
    var len: usize = 0;
    for (cap_specs) |spec| {
        const value = if (cap_302) spec.value_302 else null;
        const value_len: usize = if (value) |v| 1 + v.len else 0;
        const space_len: usize = if (len == 0) 0 else 1;
        if (len + space_len + spec.name.len + value_len > out.len) return error.OutputTooSmall;
        if (len != 0) {
            out[len] = ' ';
            len += 1;
        }
        @memcpy(out[len .. len + spec.name.len], spec.name);
        len += spec.name.len;
        if (value) |v| {
            out[len] = '=';
            len += 1;
            @memcpy(out[len .. len + v.len], v);
            len += v.len;
        }
    }
    return out[0..len];
}

fn applyCapRequest(negotiated: *CapSet, raw_list: []const u8) bool {
    var cursor: usize = 0;
    var saw_token = false;
    var changes = negotiated.*;

    while (cursor < raw_list.len) {
        cursor = skipSpaces(raw_list, cursor);
        if (cursor >= raw_list.len) break;

        const start = cursor;
        while (cursor < raw_list.len and raw_list[cursor] != ' ') : (cursor += 1) {}
        var token = raw_list[start..cursor];
        const remove = token.len != 0 and token[0] == '-';
        if (remove) token = token[1..];
        if (token.len == 0) return false;

        const spec = findCap(token) orelse return false;
        if (remove) {
            changes.remove(spec.id);
        } else {
            changes.add(spec.id);
        }
        saw_token = true;
    }

    if (!saw_token) return false;
    negotiated.* = changes;
    return true;
}

fn findCap(name: []const u8) ?CapSpec {
    for (cap_specs) |spec| {
        if (std.mem.eql(u8, spec.name, name)) return spec;
    }
    return null;
}

fn skipSpaces(bytes: []const u8, start: usize) usize {
    var cursor = start;
    while (cursor < bytes.len and bytes[cursor] == ' ') {
        cursor += 1;
    }
    return cursor;
}

fn findSpace(bytes: []const u8, start: usize) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == ' ') return cursor;
    }
    return null;
}

/// Authoritative registration flags for local dispatch; `Client.registration`
/// is a compatibility mirror kept in sync for component-facing state.
pub const RegistrationState = struct {
    pass_seen: bool = false,
    nick_seen: bool = false,
    user_seen: bool = false,
    registered: bool = false,
};

/// Per-local-client dispatch state.
pub const ClientSession = struct {
    client: Client = .{},
    registration: RegistrationState = .{},
    cap: CapSession = .{},

    /// SASL mechanism awaiting its credentials line (null = none selected).
    sasl_pending: ?sasl.Mechanism = null,
    /// Injected PLAIN verifier. The live server sets this to a services-backed
    /// checker; left null (e.g. no account store yet) SASL PLAIN fails closed.
    sasl_plain: ?sasl.PlainChecker = null,
    account_store: FixedString(MAX_ACCOUNT_BYTES) = .{},
    logged_in: bool = false,

    /// AWAY state (RFC 1459 / IRCv3 away-notify). `away_active` gates whether
    /// `away_store` holds a live message; cleared by a parameterless AWAY.
    away_store: FixedString(MAX_AWAY_BYTES) = .{},
    away_active: bool = false,
    /// Set once the client completes a successful OPER. Gates oper-only commands
    /// (WALLOPS, REHASH, KILL, ...) and the RPL_WHOISOPERATOR line.
    is_oper: bool = false,
    /// User modes (+i invisible, +B bot, ...). Set via MODE on the own nick.
    umodes: usermode.UmodeSet = .{},

    pub fn init() ClientSession {
        return .{};
    }

    /// The client's AWAY message, or null when not marked away.
    pub fn awayMessage(self: *const ClientSession) ?[]const u8 {
        return if (self.away_active) self.away_store.slice() else null;
    }

    /// Mark the client away with `text`, truncating to the buffer if needed.
    pub fn setAway(self: *ClientSession, text: []const u8) void {
        const n = @min(text.len, self.away_store.bytes.len);
        @memcpy(self.away_store.bytes[0..n], text[0..n]);
        self.away_store.len = n;
        self.away_active = true;
    }

    /// Clear any away state (parameterless AWAY).
    pub fn clearAway(self: *ClientSession) void {
        self.away_store.len = 0;
        self.away_active = false;
    }

    /// Replace the client's realname (IRCv3 SETNAME). Rejects control bytes and
    /// over-length values via the underlying FixedString validation.
    pub fn setRealname(self: *ClientSession, value: []const u8) DispatchError!void {
        try self.client.identity.realname.set(value);
    }

    /// Replace the client's nick (registered NICK change). Validation/collision
    /// is the caller's responsibility; this only rewrites the inline buffer.
    pub fn setNick(self: *ClientSession, value: []const u8) DispatchError!void {
        try self.client.identity.nick.set(value);
    }

    /// Whether the client has completed OPER authentication.
    pub fn isOper(self: *const ClientSession) bool {
        return self.is_oper;
    }

    /// Set or clear a user mode. Returns true if the set changed.
    pub fn setUmode(self: *ClientSession, mode: usermode.UserMode, on: bool) bool {
        const before = self.umodes.contains(mode);
        if (on) self.umodes.add(mode) else self.umodes.remove(mode);
        return before != on;
    }

    pub fn hasUmode(self: *const ClientSession, mode: usermode.UserMode) bool {
        return self.umodes.contains(mode);
    }

    /// Whether the client flagged itself a bot (+B / IRCv3 bot-mode).
    pub fn isBot(self: *const ClientSession) bool {
        return self.umodes.contains(.bot);
    }

    /// Render active user modes as "+iB" into `out` (caller-owned, >= 9 bytes).
    pub fn umodeString(self: *const ClientSession, out: []u8) []const u8 {
        var n: usize = 0;
        if (n < out.len) {
            out[n] = '+';
            n += 1;
        }
        const letters = [_]struct { m: usermode.UserMode, c: u8 }{
            .{ .m = .invisible, .c = 'i' },
            .{ .m = .bot, .c = 'B' },
            .{ .m = .registered, .c = 'r' },
            .{ .m = .secure_tls, .c = 'Z' },
            .{ .m = .deaf, .c = 'D' },
            .{ .m = .callerid, .c = 'g' },
            .{ .m = .no_ctcp, .c = 'T' },
            .{ .m = .cloaked, .c = 'x' },
        };
        for (letters) |l| {
            if (self.umodes.contains(l.m) and n < out.len) {
                out[n] = l.c;
                n += 1;
            }
        }
        return out[0..n];
    }

    /// Authenticated account name, or null when not logged in (SASL).
    pub fn account(self: *const ClientSession) ?[]const u8 {
        return if (self.logged_in) self.account_store.slice() else null;
    }

    pub fn registered(self: ClientSession) bool {
        return self.registration.registered;
    }

    pub fn displayName(self: *const ClientSession) []const u8 {
        const nick = self.client.identity.nick.slice();
        return if (nick.len == 0) "*" else nick;
    }

    /// The client's username (from USER), or "user" before registration.
    pub fn username(self: *const ClientSession) []const u8 {
        const u = self.client.identity.uid.slice();
        return if (u.len == 0) "user" else u;
    }

    /// The client's realname (from USER), or the nick if unset.
    pub fn realname(self: *const ClientSession) []const u8 {
        const r = self.client.identity.realname.slice();
        return if (r.len == 0) self.displayName() else r;
    }

    /// Whether this client negotiated `id` via CAP. Lets the message path apply
    /// per-recipient IRCv3 behavior (echo-message, extended-join, ...).
    pub fn hasCap(self: *const ClientSession, id: CapId) bool {
        return self.cap.negotiated.contains(id);
    }
};

/// Caller-owned reply collector.
pub const ReplyCtx = struct {
    storage: []u8,
    used: usize = 0,
    server_name: []const u8 = SERVER_NAME,
    network_name: []const u8 = NETWORK_NAME,

    pub fn init(storage: []u8) ReplyCtx {
        return .{ .storage = storage };
    }

    pub fn written(self: *const ReplyCtx) []const u8 {
        return self.storage[0..self.used];
    }

    pub fn clear(self: *ReplyCtx) void {
        self.used = 0;
    }

    pub fn message(
        self: *ReplyCtx,
        prefix: ?[]const u8,
        command: []const u8,
        params: []const []const u8,
        trailing: ?[]const u8,
    ) DispatchError!void {
        if (prefix) |value| try requireNoControlBytes(value);
        try requireNoControlBytes(command);
        for (params) |param| try requireNoControlBytes(param);
        if (trailing) |value| try requireNoControlBytes(value);

        if (prefix) |value| {
            try self.appendByte(':');
            try self.append(value);
            try self.appendByte(' ');
        }

        try self.append(command);
        for (params) |param| {
            try self.appendByte(' ');
            try self.append(param);
        }

        if (trailing) |value| {
            try self.appendByte(' ');
            try self.appendByte(':');
            try self.append(value);
        }

        try self.append("\r\n");
    }

    pub fn numeric(
        self: *ReplyCtx,
        session: *const ClientSession,
        code: Numeric,
        params: []const []const u8,
        trailing: []const u8,
    ) DispatchError!void {
        try self.numericTarget(session.displayName(), code, params, trailing);
    }

    fn numericTarget(
        self: *ReplyCtx,
        target: []const u8,
        code: Numeric,
        params: []const []const u8,
        trailing: []const u8,
    ) DispatchError!void {
        try requireNoControlBytes(target);
        for (params) |param| try requireNoControlBytes(param);
        try requireNoControlBytes(trailing);

        var code_buf: [3]u8 = undefined;
        try self.appendByte(':');
        try self.append(self.server_name);
        try self.appendByte(' ');
        try self.append(formatCode(code, &code_buf));
        try self.appendByte(' ');
        try self.append(target);
        for (params) |param| {
            try self.appendByte(' ');
            try self.append(param);
        }
        try self.appendByte(' ');
        try self.appendByte(':');
        try self.append(trailing);
        try self.append("\r\n");
    }

    fn append(self: *ReplyCtx, bytes: []const u8) DispatchError!void {
        if (self.used + bytes.len > self.storage.len) return error.OutputTooSmall;
        @memcpy(self.storage[self.used .. self.used + bytes.len], bytes);
        self.used += bytes.len;
    }

    fn appendByte(self: *ReplyCtx, byte: u8) DispatchError!void {
        if (self.used == self.storage.len) return error.OutputTooSmall;
        self.storage[self.used] = byte;
        self.used += 1;
    }
};

/// Dispatch one parsed client line.
pub fn dispatchLine(
    session: *ClientSession,
    replies: *ReplyCtx,
    line: *const LineView,
) DispatchError!void {
    const entry = lookupCommand(line.command) orelse {
        try emitUnknownCommand(session, replies, line.command);
        return;
    };

    const params = line.paramSlice();
    if (params.len < entry.min_params) {
        try emitNeedMoreParams(session, replies, entry.name);
        return;
    }

    if (!session.registered() and !entry.prereg_allowed) {
        try replies.numeric(session, .ERR_NOTREGISTERED, &.{}, "You have not registered");
        return;
    }

    const before_registered = session.registered();
    try entry.handler(.{
        .session = session,
        .replies = replies,
        .line = line,
        .entry = entry,
    });
    syncClientRegistration(session);

    if (!before_registered) {
        try maybeCompleteRegistration(session, replies);
    }
}

const Handler = *const fn (ctx: DispatchCtx) DispatchError!void;

const CommandEntry = struct {
    name: []const u8,
    min_params: usize,
    prereg_allowed: bool = false,
    handler: Handler,
};

const DispatchCtx = struct {
    session: *ClientSession,
    replies: *ReplyCtx,
    line: *const LineView,
    entry: CommandEntry,

    fn params(self: DispatchCtx) []const []const u8 {
        return self.line.paramSlice();
    }
};

const command_table = [_]CommandEntry{
    .{ .name = "PASS", .min_params = 1, .prereg_allowed = true, .handler = handlePass },
    .{ .name = "NICK", .min_params = 1, .prereg_allowed = true, .handler = handleNick },
    .{ .name = "USER", .min_params = 4, .prereg_allowed = true, .handler = handleUser },
    .{ .name = "CAP", .min_params = 1, .prereg_allowed = true, .handler = handleCap },
    .{ .name = "AUTHENTICATE", .min_params = 1, .prereg_allowed = true, .handler = handleAuthenticate },
    .{ .name = "PING", .min_params = 1, .prereg_allowed = true, .handler = handlePing },
    .{ .name = "PONG", .min_params = 1, .prereg_allowed = true, .handler = handleNoop },
    .{ .name = "QUIT", .min_params = 0, .prereg_allowed = true, .handler = handleQuit },
};

fn lookupCommand(name: []const u8) ?CommandEntry {
    for (command_table) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.name, name)) return entry;
    }
    return null;
}

fn handlePass(ctx: DispatchCtx) DispatchError!void {
    if (ctx.session.registered()) {
        try ctx.replies.numeric(ctx.session, .ERR_ALREADYREGISTRED, &.{}, "You may not reregister");
        return;
    }

    ctx.session.registration.pass_seen = true;
    if (ctx.session.client.registration.prereg == .fresh) {
        ctx.session.client.registration.prereg = .pass_seen;
    }
}

fn handleNick(ctx: DispatchCtx) DispatchError!void {
    const nick = ctx.params()[0];
    if (hasControlByte(nick)) {
        try ctx.replies.numeric(ctx.session, .ERR_ERRONEUSNICKNAME, &.{"*"}, "Erroneous nickname");
        return;
    }

    try ctx.session.client.identity.nick.set(nick);
    ctx.session.registration.nick_seen = true;
    if (!ctx.session.registration.user_seen) {
        ctx.session.client.registration.prereg = .nick_seen;
    }
}

fn handleUser(ctx: DispatchCtx) DispatchError!void {
    if (ctx.session.registered()) {
        try ctx.replies.numeric(ctx.session, .ERR_ALREADYREGISTRED, &.{}, "You may not reregister");
        return;
    }

    const params = ctx.params();
    try requireNoControlBytes(params[0]);
    try requireNoControlBytes(params[3]);
    try ctx.session.client.identity.uid.set(params[0]);
    try ctx.session.client.identity.realname.set(params[3]);
    ctx.session.registration.user_seen = true;
    if (!ctx.session.registration.nick_seen) {
        ctx.session.client.registration.prereg = .user_seen;
    }
}

fn handleCap(ctx: DispatchCtx) DispatchError!void {
    var cap_replies: [8]CapReply = undefined;
    var cap_storage: [2048]u8 = undefined;
    var sink = CapReplySink{
        .replies = &cap_replies,
        .storage = &cap_storage,
    };

    const params = ctx.params();
    switch (try ctx.session.cap.handle(params[0], params[1..], &sink)) {
        .ok => {},
        .invalid_command => {
            try ctx.replies.numeric(ctx.session, .ERR_INVALIDCAPCMD, &.{params[0]}, "Invalid CAP command");
            return;
        },
        .missing_parameter => {
            try emitNeedMoreParams(ctx.session, ctx.replies, ctx.entry.name);
            return;
        },
    }

    syncCapState(ctx.session);
    try emitCapReplies(ctx.session, ctx.replies, sink.slice());
}

fn handleAuthenticate(ctx: DispatchCtx) DispatchError!void {
    if (ctx.session.registered()) {
        try ctx.replies.numeric(ctx.session, .ERR_ALREADYREGISTRED, &.{}, "You may not reregister");
        return;
    }

    if (!ctx.session.cap.negotiated.contains(.sasl)) {
        try ctx.replies.numeric(ctx.session, .ERR_SASLFAIL, &.{}, "SASL authentication failed");
        return;
    }

    const payload = ctx.params()[0];
    if (std.mem.eql(u8, payload, "*")) {
        ctx.session.sasl_pending = null;
        ctx.session.client.registration.sasl = .failed;
        try ctx.replies.numeric(ctx.session, .ERR_SASLABORTED, &.{}, "SASL authentication aborted");
        return;
    }

    // Phase 1 — mechanism selection. Only PLAIN is wired today; EXTERNAL/SCRAM
    // arrive when the certfp/SCRAM checkers are plumbed in.
    if (ctx.session.sasl_pending == null) {
        const mech = sasl.Mechanism.parse(payload) orelse return saslFail(ctx, "Unsupported SASL mechanism");
        if (mech != .plain) return saslFail(ctx, "Unsupported SASL mechanism");
        // Starting a fresh exchange clears any prior login so a re-auth can
        // never leave logged_in set with a stale/failed account.
        ctx.session.logged_in = false;
        ctx.session.account_store.len = 0;
        ctx.session.sasl_pending = mech;
        ctx.session.client.registration.sasl = .authenticating;
        try ctx.replies.message(null, "AUTHENTICATE", &.{"+"}, null);
        return;
    }

    // Phase 2 — credentials for the pending PLAIN mechanism.
    ctx.session.sasl_pending = null;
    const checker = ctx.session.sasl_plain orelse return saslFail(ctx, "SASL authentication failed");

    // Sized for a full line's worth of base64 (lines are capped upstream); a
    // payload that still overflows fails closed via decodeAuthPayload.
    var decode_buf: [sasl_decode_cap]u8 = undefined;
    const raw = decodeAuthPayload(payload, &decode_buf) catch return saslFail(ctx, "SASL authentication failed");
    const creds = sasl.parsePlain(raw) catch return saslFail(ctx, "SASL authentication failed");
    if (!checker.verify(creds)) return saslFail(ctx, "SASL authentication failed");

    // Store the CANONICAL (ASCII-lowercased) account name, matching how the
    // account store keys accounts (services.accountKey). Otherwise account()
    // would report the client's claimed casing ("Alice") while authz uses the
    // canonical form ("alice") — an identity mismatch.
    if (creds.authcid.len > MAX_ACCOUNT_BYTES) return saslFail(ctx, "SASL authentication failed");
    var account_buf: [MAX_ACCOUNT_BYTES]u8 = undefined;
    const account = std.ascii.lowerString(account_buf[0..creds.authcid.len], creds.authcid);
    ctx.session.account_store.set(account) catch return saslFail(ctx, "SASL authentication failed");
    ctx.session.logged_in = true;
    ctx.session.client.registration.sasl = .succeeded;
    try ctx.replies.numeric(ctx.session, .RPL_LOGGEDIN, &.{ ctx.session.displayName(), account }, "You are now logged in");
    try ctx.replies.numeric(ctx.session, .RPL_SASLSUCCESS, &.{}, "SASL authentication successful");
}

/// Decoded-credential buffer cap: covers a full IRC line of base64 so legit
/// PLAIN credentials never silently fail; oversize still fails closed.
const sasl_decode_cap: usize = 8192;

fn saslFail(ctx: DispatchCtx, message: []const u8) DispatchError!void {
    ctx.session.sasl_pending = null;
    ctx.session.logged_in = false;
    ctx.session.account_store.len = 0;
    ctx.session.client.registration.sasl = .failed;
    try ctx.replies.numeric(ctx.session, .ERR_SASLFAIL, &.{}, message);
}

/// Decode a base64 AUTHENTICATE payload into `out`, rejecting oversize input.
fn decodeAuthPayload(payload_b64: []const u8, out: []u8) ![]const u8 {
    const decoder = std.base64.standard.Decoder;
    const len = try decoder.calcSizeForSlice(payload_b64);
    if (len > out.len) return error.OutputTooSmall;
    try decoder.decode(out[0..len], payload_b64);
    return out[0..len];
}

fn handlePing(ctx: DispatchCtx) DispatchError!void {
    try ctx.replies.message(ctx.replies.server_name, "PONG", &.{ctx.replies.server_name}, ctx.params()[0]);
}

fn handleNoop(_: DispatchCtx) DispatchError!void {}

fn handleQuit(ctx: DispatchCtx) DispatchError!void {
    ctx.session.client.registration.prereg = .closing;
}

fn maybeCompleteRegistration(session: *ClientSession, replies: *ReplyCtx) DispatchError!void {
    if (session.registration.registered) return;
    if (!session.registration.nick_seen or !session.registration.user_seen) return;
    if (session.cap.registrationHeld()) return;

    session.registration.registered = true;
    session.client.registration.prereg = .registered;
    try emitWelcome(session, replies);
}

fn emitWelcome(session: *ClientSession, replies: *ReplyCtx) DispatchError!void {
    try replies.numeric(session, .RPL_WELCOME, &.{}, "Welcome to the Mizuchi IRC Network");
    try replies.numeric(session, .RPL_YOURHOST, &.{}, "Your host is mizuchi.local, running Mizuchi");
    try replies.numeric(session, .RPL_CREATED, &.{}, "This server was created for deterministic tests");
    try replies.numeric(session, .RPL_MYINFO, &.{ SERVER_NAME, "mizuchi-0.1", "io", "ov" }, "are supported by this server");
    try replies.numeric(session, .RPL_ISUPPORT, &.{ "CHANTYPES=#", "NICKLEN=64", "CASEMAPPING=ascii", "PREFIX=(Qqov)~.@+", "CHANMODES=beI,k,l,imnst", "STATUSMSG=~.@+", "BOT=B" }, "are supported by this server");
}

fn emitUnknownCommand(
    session: *const ClientSession,
    replies: *ReplyCtx,
    command: []const u8,
) DispatchError!void {
    try requireNoControlBytes(command);
    try replies.numeric(session, .ERR_UNKNOWNCOMMAND, &.{command}, "Unknown command");
}

fn emitNeedMoreParams(
    session: *const ClientSession,
    replies: *ReplyCtx,
    command: []const u8,
) DispatchError!void {
    try replies.numeric(session, .ERR_NEEDMOREPARAMS, &.{command}, "Not enough parameters");
}

fn emitCapReplies(
    session: *ClientSession,
    replies: *ReplyCtx,
    cap_replies: []const CapReply,
) DispatchError!void {
    for (cap_replies) |reply| {
        const verb = switch (reply.kind) {
            .ls => "LS",
            .ack => "ACK",
            .nak => "NAK",
        };

        var params: [3][]const u8 = undefined;
        params[0] = session.displayName();
        params[1] = verb;
        var param_count: usize = 2;
        if (reply.continuation) {
            params[2] = "*";
            param_count = 3;
        }

        try replies.message(replies.server_name, "CAP", params[0..param_count], reply.body);
    }
}

fn syncClientRegistration(session: *ClientSession) void {
    syncCapState(session);
    if (session.registration.registered) {
        session.client.registration.prereg = .registered;
    } else if (session.registration.nick_seen and session.registration.user_seen) {
        session.client.registration.prereg = .user_seen;
    }
}

fn syncCapState(session: *ClientSession) void {
    session.client.registration.cap = switch (session.cap.state) {
        .idle => .idle,
        .negotiating => .negotiating,
        .complete => .complete,
    };
    session.client.protocol.negotiated_caps = session.cap.negotiated.bits;
}

fn dispatchText(session: *ClientSession, replies: *ReplyCtx, text: []const u8) DispatchError!void {
    const line = parseLine(text) catch return;
    try dispatchLine(session, replies, &line);
}

fn hasControlByte(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte < 0x20 or byte == 0x7f) return true;
    }
    return false;
}

fn requireNoControlBytes(bytes: []const u8) DispatchError!void {
    if (hasControlByte(bytes)) return error.ControlByte;
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) != null);
}

fn expectNotContains(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) == null);
}

fn expectCodesInOrder(haystack: []const u8, codes: []const []const u8) !void {
    var pos: usize = 0;
    for (codes) |code| {
        const found = std.mem.indexOfPos(u8, haystack, pos, code) orelse return error.TestExpectedEqual;
        pos = found + code.len;
    }
}

test "full registration handshake emits welcome numerics" {
    const allocator = std.testing.allocator;
    _ = allocator;

    var session = ClientSession.init();
    var storage: [2048]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    try dispatchText(&session, &replies, "NICK kain");
    try std.testing.expect(!session.registered());
    try std.testing.expectEqual(@as(usize, 0), replies.written().len);

    try dispatchText(&session, &replies, "USER kain 0 * :Kain Mizuchi");
    try std.testing.expect(session.registered());
    try expectCodesInOrder(replies.written(), &.{ " 001 ", " 002 ", " 003 ", " 004 ", " 005 " });
}

test "CAP negotiation holds registration until CAP END" {
    const allocator = std.testing.allocator;
    _ = allocator;

    var session = ClientSession.init();
    var storage: [4096]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    try dispatchText(&session, &replies, "CAP LS 302");
    try expectContains(replies.written(), " CAP * LS :");
    replies.clear();

    try dispatchText(&session, &replies, "NICK kain");
    try dispatchText(&session, &replies, "USER kain 0 * :Kain Mizuchi");
    try std.testing.expect(!session.registered());
    try expectNotContains(replies.written(), " 001 ");

    try dispatchText(&session, &replies, "CAP END");
    try std.testing.expect(session.registered());
    try expectCodesInOrder(replies.written(), &.{ " 001 ", " 002 ", " 003 ", " 004 ", " 005 " });
}

test "short parameters emit ERR_NEEDMOREPARAMS" {
    const allocator = std.testing.allocator;
    _ = allocator;

    var session = ClientSession.init();
    var storage: [512]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    try dispatchText(&session, &replies, "NICK");
    try expectContains(replies.written(), " 461 * NICK :Not enough parameters\r\n");
}

test "unknown command emits ERR_UNKNOWNCOMMAND" {
    const allocator = std.testing.allocator;
    _ = allocator;

    var session = ClientSession.init();
    var storage: [512]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    try dispatchText(&session, &replies, "WAT");
    try expectContains(replies.written(), " 421 * WAT :Unknown command\r\n");
}

test "malformed text line is dropped without replies" {
    var session = ClientSession.init();
    var storage: [512]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    try dispatchText(&session, &replies, "PING a\nb");
    try std.testing.expectEqual(@as(usize, 0), replies.written().len);
}

test "NICK containing a control byte is rejected" {
    var session = ClientSession.init();
    var storage: [512]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    try dispatchText(&session, &replies, "NICK bad\x01nick");
    try expectContains(replies.written(), " 432 * * :Erroneous nickname\r\n");
    try std.testing.expect(!session.registration.nick_seen);
    try std.testing.expectEqual(@as(usize, 0), session.client.identity.nick.slice().len);
}

const TestPlainChecker = struct {
    fn verify(_: *anyopaque, creds: sasl.PlainCredentials) bool {
        return std.mem.eql(u8, creds.authcid, "alice") and std.mem.eql(u8, creds.password, "secret");
    }
};

test "sasl PLAIN exchange logs in and exposes the account" {
    var session = ClientSession.init();
    session.cap.negotiated.add(.sasl);
    var anchor: u8 = 0;
    session.sasl_plain = .{ .ptr = &anchor, .verifyFn = TestPlainChecker.verify };

    var storage: [1024]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    try dispatchText(&session, &replies, "AUTHENTICATE PLAIN");
    try expectContains(replies.written(), "AUTHENTICATE +\r\n");
    try std.testing.expect(session.sasl_pending != null);

    var b64: [64]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&b64, "\x00alice\x00secret");
    var linebuf: [128]u8 = undefined;
    const line = try std.fmt.bufPrint(&linebuf, "AUTHENTICATE {s}", .{enc});

    replies.clear();
    try dispatchText(&session, &replies, line);
    try std.testing.expectEqualStrings("alice", session.account().?);
    try expectContains(replies.written(), " 900 ");
    try expectContains(replies.written(), " 903 ");
}

test "sasl PLAIN rejects bad credentials and stays logged out" {
    var session = ClientSession.init();
    session.cap.negotiated.add(.sasl);
    var anchor: u8 = 0;
    session.sasl_plain = .{ .ptr = &anchor, .verifyFn = TestPlainChecker.verify };

    var storage: [1024]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    try dispatchText(&session, &replies, "AUTHENTICATE PLAIN");
    var b64: [64]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&b64, "\x00alice\x00wrongpass");
    var linebuf: [128]u8 = undefined;
    const line = try std.fmt.bufPrint(&linebuf, "AUTHENTICATE {s}", .{enc});

    replies.clear();
    try dispatchText(&session, &replies, line);
    try std.testing.expect(session.account() == null);
    try expectContains(replies.written(), " 904 ");
}
