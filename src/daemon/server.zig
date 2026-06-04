//! Ringlane-backed TCP server for the daemon M1 keystone.
//!
//! The socket path is intentionally small: accept a TCP client, receive IRC
//! bytes through `Ring`, feed complete CRLF lines into the pure command core,
//! and send queued replies back through `Ring`. The IRC core is kept separate so
//! registration and PING behavior test without sockets or io_uring.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

const dispatch = @import("dispatch.zig");
const event_spine = @import("event_spine.zig");
const client_model = @import("client.zig");
const world_model = @import("world.zig");
const sasl = @import("../proto/sasl.zig");
const names_reply = @import("../proto/names_reply.zig");
const chanmode = @import("chanmode.zig");
const kick = @import("../proto/kick.zig");
const ison_userhost = @import("../proto/ison_userhost.zig");
const lusers = @import("../proto/lusers.zig");
const motd = @import("../proto/motd.zig");
const serverinfo = @import("../proto/serverinfo.zig");
const invite = @import("../proto/invite.zig");
const whois = @import("whois.zig");
const whowas = @import("whowas.zig");
const whowas_reply = @import("../proto/whowas_reply.zig");
const monitor = @import("../proto/monitor.zig");

/// Bounded WHOWAS history ring shared by the live server. Field caps match the
/// daemon's identity limits (NICKLEN=64) so live identities are never rejected.
const WhowasStore = whowas.Whowas(.{ .capacity = 256, .max_nick_len = 64, .max_user_len = 64 });
const list = @import("../proto/list.zig");
const who = @import("../proto/who.zig");
const platform = @import("../substrate/platform.zig");

/// Format the current wall-clock time as "YYYY-MM-DD HH:MM:SS UTC" for RPL_TIME.
fn formatServerTime(buf: []u8) []const u8 {
    const ms = platform.realtimeMillis();
    const secs: u64 = @intCast(@divTrunc(ms, 1000));
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} UTC", .{
        yd.year,              md.month.numeric(),      @as(u16, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch "unknown";
}

/// IRCv3 server-time tag: `@time=2026-06-04T12:34:56.789Z ` (ISO-8601 UTC with
/// millisecond precision, trailing space so it prepends directly before the ':'
/// message prefix). Empty string on format failure (tag simply omitted).
fn serverTimeTag(buf: []u8) []const u8 {
    const ms = platform.realtimeMillis();
    const secs: u64 = @intCast(@divTrunc(ms, 1000));
    const millis: u16 = @intCast(@mod(ms, 1000));
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "@time={d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z ", .{
        yd.year,              md.month.numeric(),      @as(u16, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
        millis,
    }) catch "";
}

/// The bare ISO-8601 server-time VALUE (no `@time=` key, no trailing space) for
/// composing a multi-tag segment via buildTagPrefix.
fn serverTimeValue(buf: []u8) []const u8 {
    const ms = platform.realtimeMillis();
    const secs: u64 = @intCast(@divTrunc(ms, 1000));
    const millis: u16 = @intCast(@mod(ms, 1000));
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        yd.year,              md.month.numeric(),      @as(u16, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
        millis,
    }) catch "";
}

/// Assemble a per-recipient IRCv3 tag segment `@k=v;k=v ` (trailing space) from
/// the tags available this event and the caps `session` negotiated. Returns ""
/// when the recipient gets no tags. Only ONE `@`-segment is ever emitted, so
/// server-time and account-tag coexist correctly (never two `@` blocks).
fn buildTagPrefix(session: *const dispatch.ClientSession, tags: LinuxServer.MsgTags, out: []u8) []const u8 {
    var b = Buf{ .storage = out };
    var any = false;
    if (tags.time_value.len != 0 and session.hasCap(.server_time)) {
        b.append("@time=") catch return "";
        b.append(tags.time_value) catch return "";
        any = true;
    }
    if (session.hasCap(.account_tag)) {
        if (tags.account) |acct| {
            b.append(if (any) ";account=" else "@account=") catch return "";
            b.append(acct) catch return "";
            any = true;
        }
    }
    if (!any) return "";
    b.appendByte(' ') catch return "";
    return b.written();
}

/// ISON predicate: nicks are pre-filtered to online before the builder runs.
fn alwaysOnline(_: []const u8) bool {
    return true;
}

const server_version = "mizuchi-0.1";
const motd_text = [_][]const u8{
    "Welcome to Mizuchi — a clean-room, Zig-native IRCX/IRCv3 daemon.",
    "Suimyaku mesh + Tsumugi forward-secret links.",
};

/// Sink adapter that writes complete (CRLF-terminated) builder lines to a conn.
const ConnLineSink = struct {
    conn: *ConnState,
    // Narrow error set so it coerces into builder error sets (e.g. LusersError).
    pub fn send(self: *ConnLineSink, bytes: []const u8) error{OutputTooSmall}!void {
        appendToConn(self.conn, bytes) catch return error.OutputTooSmall;
    }
};

/// Like ConnLineSink but appends CRLF (for builders whose lines omit it, e.g. LIST).
const ConnLineSinkCRLF = struct {
    conn: *ConnState,
    pub fn send(self: *ConnLineSinkCRLF, bytes: []const u8) error{OutputTooSmall}!void {
        appendToConn(self.conn, bytes) catch return error.OutputTooSmall;
        appendToConn(self.conn, "\r\n") catch return error.OutputTooSmall;
    }
};

const irc_line = struct {
    pub const MAXPARA: usize = 15;
    pub const MAX_LINE_BODY: usize = 8191;

    pub const ParseError = error{
        EmptyLine,
        OversizeLine,
        EmbeddedNul,
        EmbeddedLineBreak,
        MissingCommand,
        MalformedPrefix,
        TooManyParams,
    };

    pub const LineView = struct {
        raw: []const u8,
        prefix: ?[]const u8 = null,
        /// IRCv3 client message-tags segment WITHOUT the leading '@' (null if
        /// none). Relayed verbatim by TAGMSG to message-tags recipients.
        tags_raw: ?[]const u8 = null,
        command: []const u8,
        params: [MAXPARA][]const u8 = [_][]const u8{""} ** MAXPARA,
        param_count: usize = 0,

        pub fn paramSlice(self: *const LineView) []const []const u8 {
            return self.params[0..self.param_count];
        }
    };

    pub fn parseLine(input: []const u8) ParseError!LineView {
        const body = stripLineEnding(input);
        if (body.len == 0) return error.EmptyLine;
        if (body.len > MAX_LINE_BODY) return error.OversizeLine;

        for (body) |ch| switch (ch) {
            0 => return error.EmbeddedNul,
            '\r', '\n' => return error.EmbeddedLineBreak,
            else => {},
        };

        var view = LineView{ .raw = body, .command = "" };
        var cursor = skipSpaces(body, 0);
        if (cursor >= body.len) return error.MissingCommand;

        if (body[cursor] == '@') {
            const tag_end = findSpace(body, cursor) orelse return error.MissingCommand;
            if (tag_end > cursor + 1) view.tags_raw = body[cursor + 1 .. tag_end];
            cursor = skipSpaces(body, tag_end);
            if (cursor >= body.len) return error.MissingCommand;
        }

        if (body[cursor] == ':') {
            const prefix_end = findSpace(body, cursor) orelse return error.MissingCommand;
            if (prefix_end == cursor + 1) return error.MalformedPrefix;
            view.prefix = body[cursor + 1 .. prefix_end];
            cursor = skipSpaces(body, prefix_end);
            if (cursor >= body.len) return error.MissingCommand;
        }

        const command_end = findSpace(body, cursor) orelse body.len;
        if (command_end == cursor) return error.MissingCommand;
        view.command = body[cursor..command_end];
        cursor = skipSpaces(body, command_end);

        while (cursor < body.len) {
            if (view.param_count == MAXPARA) return error.TooManyParams;
            if (body[cursor] == ':') {
                view.params[view.param_count] = body[cursor + 1 ..];
                view.param_count += 1;
                break;
            }
            const end = findSpace(body, cursor) orelse body.len;
            view.params[view.param_count] = body[cursor..end];
            view.param_count += 1;
            cursor = skipSpaces(body, end);
        }

        return view;
    }

    fn stripLineEnding(input: []const u8) []const u8 {
        if (input.len >= 2 and input[input.len - 2] == '\r' and input[input.len - 1] == '\n') {
            return input[0 .. input.len - 2];
        }
        if (input.len >= 1 and (input[input.len - 1] == '\r' or input[input.len - 1] == '\n')) {
            return input[0 .. input.len - 1];
        }
        return input;
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
};

const ringlane = struct {
    const IoUring = linux.IoUring;

    pub const default_cqe_batch: usize = 256;

    pub const RingFeatures = struct {
        multishot_accept: bool = false,
        multishot_recv: bool = false,
        buf_ring: bool = false,
        send_zc: bool = false,
        fixed_files: bool = false,
        defer_taskrun: bool = false,
        sqpoll: bool = false,

        pub const baseline: @This() = .{};

        fn setupFlags(self: @This()) u32 {
            var flags: u32 = 0;
            if (self.sqpoll) flags |= linux.IORING_SETUP_SQPOLL;
            if (self.defer_taskrun) {
                flags |= linux.IORING_SETUP_DEFER_TASKRUN;
                flags |= linux.IORING_SETUP_SINGLE_ISSUER;
            }
            return flags;
        }
    };

    pub const OpKind = enum(u8) {
        other = 0,
        accept = 1,
        recv = 2,
        send = 3,
        timeout = 4,
    };

    pub const FdToken = struct {
        slot: u32,
        gen: u32,
    };

    const gen_bits = 28;
    const slot_bits = 28;
    const slot_shift = gen_bits;
    const kind_shift = gen_bits + slot_bits;
    const field_mask: u64 = (1 << gen_bits) - 1;
    const slot_max: u32 = (1 << slot_bits) - 1;
    const gen_max: u32 = (1 << gen_bits) - 1;

    fn encodeUserData(kind: OpKind, token: FdToken) error{TokenOutOfRange}!u64 {
        if (token.slot > slot_max or token.gen > gen_max) return error.TokenOutOfRange;
        return (@as(u64, @intFromEnum(kind)) << kind_shift) |
            (@as(u64, token.slot) << slot_shift) |
            @as(u64, token.gen);
    }

    fn decodeUserData(raw: u64) error{UnknownOpKind}!struct { kind: OpKind, token: FdToken } {
        const kind_raw: u8 = @intCast(raw >> kind_shift);
        const kind: OpKind = switch (kind_raw) {
            0 => .other,
            1 => .accept,
            2 => .recv,
            3 => .send,
            4 => .timeout,
            else => return error.UnknownOpKind,
        };
        return .{
            .kind = kind,
            .token = .{
                .slot = @intCast((raw >> slot_shift) & field_mask),
                .gen = @intCast(raw & field_mask),
            },
        };
    }

    pub const AcceptEvent = struct {
        token: FdToken,
        res: i32,
        more: bool,
    };

    pub const RecvEvent = struct {
        token: FdToken,
        res: i32,
        more: bool,
    };

    pub const SendEvent = struct {
        token: FdToken,
        res: i32,
        more: bool,
        notif: bool,
    };

    pub const Completion = union(OpKind) {
        other: void,
        accept: AcceptEvent,
        recv: RecvEvent,
        send: SendEvent,
        timeout: void,
    };

    fn decodeCompletion(cqe: linux.io_uring_cqe) error{UnknownOpKind}!Completion {
        const ud = try decodeUserData(cqe.user_data);
        const more = (cqe.flags & linux.IORING_CQE_F_MORE) != 0;
        return switch (ud.kind) {
            .other => .{ .other = {} },
            .accept => .{ .accept = .{ .token = ud.token, .res = cqe.res, .more = more } },
            .recv => .{ .recv = .{ .token = ud.token, .res = cqe.res, .more = more } },
            .send => .{ .send = .{
                .token = ud.token,
                .res = cqe.res,
                .more = more,
                .notif = (cqe.flags & linux.IORING_CQE_F_NOTIF) != 0,
            } },
            .timeout => .{ .timeout = {} },
        };
    }

    pub fn isUnsupportedInitError(err: anyerror) bool {
        return switch (err) {
            error.PermissionDenied,
            error.SystemOutdated,
            error.SystemResources,
            error.ProcessFdQuotaExceeded,
            error.SystemFdQuotaExceeded,
            error.ArgumentsInvalid,
            => true,
            else => false,
        };
    }

    pub const Ring = struct {
        inner: IoUring,
        features: RingFeatures,

        pub fn init(entries: u16, features: RingFeatures) !Ring {
            return .{ .inner = try IoUring.init(entries, features.setupFlags()), .features = features };
        }

        pub fn deinit(self: *Ring) void {
            self.inner.deinit();
        }

        pub fn submit(self: *Ring) !u32 {
            return self.inner.submit();
        }

        pub fn submitAndWait(self: *Ring, wait_nr: u32) !u32 {
            return self.inner.submit_and_wait(wait_nr);
        }

        pub fn submitAccept(self: *Ring, token: FdToken, listener_fd: linux.fd_t) !void {
            _ = self.features;
            _ = try self.inner.accept(try encodeUserData(.accept, token), listener_fd, null, null, 0);
        }

        pub fn submitRecv(self: *Ring, token: FdToken, fd: linux.fd_t, buffer: []u8) !void {
            _ = try self.inner.recv(try encodeUserData(.recv, token), fd, .{ .buffer = buffer }, 0);
        }

        pub fn submitSend(self: *Ring, token: FdToken, fd: linux.fd_t, buffer: []const u8) !void {
            _ = try self.inner.send(try encodeUserData(.send, token), fd, buffer, 0);
        }

        pub fn reapCompletions(self: *Ring, out: []linux.io_uring_cqe, wait_nr: u32, handler: anytype) !void {
            const n = try self.inner.copy_cqes(out, wait_nr);
            for (out[0..n]) |cqe| {
                const completion = decodeCompletion(cqe) catch continue;
                handler.onCompletion(completion);
            }
        }
    };
};

const RingFdToken = ringlane.FdToken;
const RingCore = ringlane.Ring;
const RingFeatureSet = ringlane.RingFeatures;

const listener_token: RingFdToken = .{ .slot = 0, .gen = 0 };
const default_reply_bytes: usize = 8192;
const default_recv_bytes: usize = 4096;
const default_line_bytes: usize = irc_line.MAX_LINE_BODY + 2;
const server_name = "mizuchi.local";
const default_host = "localhost";

const Numeric = enum(u16) {
    RPL_MAP = 15,
    RPL_MAPEND = 17,
    RPL_LINKS = 364,
    RPL_ENDOFLINKS = 365,
    RPL_YOUREOPER = 381,
    RPL_REHASHING = 382,
    RPL_INFO = 371,
    RPL_ENDOFINFO = 374,
    RPL_INFOSTART = 373,
    RPL_USERSSTART = 392,
    RPL_USERS = 393,
    RPL_ENDOFUSERS = 394,
    RPL_NOUSERS = 395,
    RPL_AWAY = 301,
    RPL_UNAWAY = 305,
    RPL_NOWAWAY = 306,
    RPL_NOTOPIC = 331,
    RPL_TOPIC = 332,
    RPL_CHANNELMODEIS = 324,
    RPL_UMODEIS = 221,
    RPL_NAMREPLY = 353,
    RPL_ENDOFNAMES = 366,
    RPL_BANLIST = 367,
    RPL_ENDOFBANLIST = 368,
    RPL_INVITELIST = 346,
    RPL_ENDOFINVITELIST = 347,
    RPL_EXCEPTLIST = 348,
    RPL_ENDOFEXCEPTLIST = 349,
    RPL_KNOCK = 710,
    RPL_KNOCKDLVR = 711,
    ERR_CHANOPEN = 713,
    ERR_KNOCKONCHAN = 714,
    RPL_MONONLINE = 730,
    RPL_MONOFFLINE = 731,
    RPL_MONLIST = 732,
    RPL_ENDOFMONLIST = 733,
    ERR_MONLISTFULL = 734,
    RPL_STATSUPTIME = 242,
    RPL_STATSOLINE = 243,
    RPL_ENDOFSTATS = 219,
    ERR_NOSUCHNICK = 401,
    ERR_NOSUCHCHANNEL = 403,
    ERR_CANNOTSENDTOCHAN = 404,
    ERR_CHANNELISFULL = 471,
    ERR_INVITEONLYCHAN = 473,
    ERR_BANNEDFROMCHAN = 474,
    ERR_BADCHANNELKEY = 475,
    ERR_NONICKNAMEGIVEN = 431,
    ERR_ERRONEUSNICKNAME = 432,
    ERR_NICKNAMEINUSE = 433,
    ERR_USERNOTINCHANNEL = 441,
    ERR_USERONCHANNEL = 443,
    ERR_NOTONCHANNEL = 442,
    ERR_NEEDMOREPARAMS = 461,
    ERR_PASSWDMISMATCH = 464,
    ERR_SUMMONDISABLED = 445,
    ERR_USERSDONTMATCH = 502,
    ERR_NOPRIVILEGES = 481,
    ERR_CHANOPRIVSNEEDED = 482,
};

fn formatNumericCode(code: Numeric, buf: []u8) []const u8 {
    if (buf.len < 3) return buf[0..0];
    const value: u16 = @intFromEnum(code);
    buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
    return buf[0..3];
}

pub const ServerError = error{
    InvalidAddress,
    PermissionDenied,
    AddressInUse,
    ConnectionRefused,
    ConnectionReset,
    SocketUnavailable,
    LineTooLong,
    ClientNotFound,
    BadCompletion,
    OutputTooSmall,
    TextTooLong,
    TokenOutOfRange,
    UnknownOpKind,
    Unsupported,
    Unexpected,
    NoSpaceLeft,
    EmptyLine,
    OversizeLine,
    EmbeddedNul,
    EmbeddedLineBreak,
    MissingCommand,
    MalformedPrefix,
    TooManyParams,
} || world_model.WorldError || std.mem.Allocator.Error;

pub const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16,
    backlog: u31 = 128,
    ring_entries: u16 = 32,
    /// Hard cap on concurrent connections. The client table reserves this many
    /// slots up front so ConnState buffers (targeted by in-flight io_uring I/O)
    /// never move; accepts past the cap are refused.
    max_clients: u31 = 1024,
    features: RingFeatureSet = RingFeatureSet.baseline,
    /// Optional SASL PLAIN verifier. Injected (not owned) so the Server does not
    /// take on the account store's I/O lifecycle: a caller that has a store wires
    /// `sasl_bridge.ServicesPlainChecker.checker()` here. Null = SASL fails closed.
    sasl_checker: ?sasl.PlainChecker = null,
};

/// Per-connection daemon state used by both the pure command core and the
/// socket loop. No slices in this struct borrow from transient recv buffers.
pub const ConnState = struct {
    fd: linux.fd_t = -1,
    token: RingFdToken = .{ .slot = 0, .gen = 0 },
    session: dispatch.ClientSession = dispatch.ClientSession.init(),
    recv_buf: [default_recv_bytes]u8 = undefined,
    line_buf: [default_line_bytes]u8 = undefined,
    line_len: usize = 0,
    send_buf: [default_reply_bytes]u8 = undefined,
    send_len: usize = 0,
    send_offset: usize = 0,
    send_armed: bool = false,
    closing: bool = false,

    pub fn init(fd: linux.fd_t) ConnState {
        return .{ .fd = fd };
    }
};

const ClientTable = client_model.Table(ConnState, client_model.ClientId);

/// Parse and route one complete IRC line. This function performs no socket or
/// io_uring work and is the unit-testable daemon command core.
pub fn processLine(conn_state: *ConnState, line: []const u8, sink: anytype) !void {
    const parsed = try irc_line.parseLine(line);

    if (std.ascii.eqlIgnoreCase(parsed.command, "PING") and parsed.param_count != 0) {
        const token = parsed.paramSlice()[0];
        var pong: [irc_line.MAX_LINE_BODY + 16]u8 = undefined;
        const out = try std.fmt.bufPrint(&pong, "PONG :{s}\r\n", .{token});
        try sink.write(out);
        return;
    }

    var dline = dispatch.LineView{ .command = parsed.command };
    for (parsed.paramSlice(), 0..) |param, idx| {
        dline.params[idx] = param;
    }
    dline.param_count = parsed.param_count;

    var reply_storage: [default_reply_bytes]u8 = undefined;
    var replies = dispatch.ReplyCtx.init(&reply_storage);
    try dispatch.dispatchLine(&conn_state.session, &replies, &dline);
    if (replies.written().len != 0) {
        try sink.write(replies.written());
    }
}

const QueueSink = struct {
    conn: *ConnState,

    fn write(self: *QueueSink, bytes: []const u8) ServerError!void {
        if (self.conn.send_len + bytes.len > self.conn.send_buf.len) {
            return error.OutputTooSmall;
        }
        @memcpy(self.conn.send_buf[self.conn.send_len .. self.conn.send_len + bytes.len], bytes);
        self.conn.send_len += bytes.len;
    }
};

pub const LinuxServer = struct {
    allocator: std.mem.Allocator,
    config: Config,
    listener_fd: linux.fd_t,
    ring: RingCore,
    clients: ClientTable,
    world: world_model.World,
    whowas: WhowasStore,
    monitor: monitor.MonitorStore,
    accept_armed: bool = false,

    /// Single configured operator credential (OPER <name> <pass>). Static for
    /// now; a full oper-block table arrives with the config overhaul.
    oper_name: []const u8 = "admin",
    oper_pass: []const u8 = "mizuchi",
    /// Monotonic millis captured at init, for STATS u uptime.
    start_ms: i64 = 0,

    /// Create, bind, and listen on a TCP socket, then initialize the Ringlane
    /// ring used for accept/recv/send completions.
    pub fn init(allocator: std.mem.Allocator, config: Config) !LinuxServer {
        if (builtin.os.tag != .linux) return error.Unsupported;

        const listener_fd = try createListener(config.host, config.port, config.backlog);
        errdefer closeFd(listener_fd);

        var ring = RingCore.init(config.ring_entries, config.features) catch |err| {
            if (ringlane.isUnsupportedInitError(err)) return error.Unsupported;
            return err;
        };
        errdefer ring.deinit();

        var whowas_store = try WhowasStore.init(allocator);
        errdefer whowas_store.deinit();

        // Reserve the full connection table up front so ConnState buffers never
        // move under in-flight io_uring I/O (a realloc would corrupt them).
        var clients = ClientTable.init(allocator, 0);
        errdefer clients.deinit();
        try clients.reserve(config.max_clients);

        return .{
            .allocator = allocator,
            .config = config,
            .listener_fd = listener_fd,
            .ring = ring,
            .clients = clients,
            .world = world_model.World.init(allocator),
            .whowas = whowas_store,
            .monitor = monitor.MonitorStore.init(allocator, 128),
            .start_ms = platform.monotonicMillis(),
        };
    }

    pub fn deinit(self: *LinuxServer) void {
        for (self.clients.slots.items) |*slot| {
            if (slot.occupied) closeFd(slot.value.fd);
        }
        self.monitor.deinit();
        self.whowas.deinit();
        self.world.deinit();
        self.clients.deinit();
        self.ring.deinit();
        closeFd(self.listener_fd);
        self.* = undefined;
    }

    /// Arm the accept SQE if needed. Submission is batched by `runOnce`.
    pub fn armAccept(self: *LinuxServer) !void {
        if (self.accept_armed) return;
        try self.ring.submitAccept(listener_token, self.listener_fd);
        self.accept_armed = true;
    }

    /// Process at least one io_uring completion. Callers may loop this until
    /// their own stop condition is satisfied.
    pub fn runOnce(self: *LinuxServer) !void {
        try self.armAccept();
        _ = try self.ring.submitAndWait(1);

        var handler = CompletionHandler{ .server = self };
        var cqes: [ringlane.default_cqe_batch]linux.io_uring_cqe = undefined;
        _ = try self.ring.reapCompletions(&cqes, 0, &handler);
        if (handler.err) |err| return err;

        _ = try self.ring.submit();
    }

    pub fn boundPort(self: *LinuxServer) !u16 {
        return socketPort(self.listener_fd);
    }

    /// Run the reactor loop on the calling thread until `run` is cleared. Wakes
    /// on each io_uring completion and re-checks the flag, so a client
    /// disconnect (or any I/O) lets a requested shutdown take effect. (T1 of the
    /// threading plan — docs/planning/06-threading.md.)
    pub fn runThreaded(self: *LinuxServer, run: *std.atomic.Value(bool)) void {
        while (run.load(.acquire)) {
            self.runOnce() catch return;
        }
    }

    fn handleAccept(self: *LinuxServer, event: ringlane.AcceptEvent) !void {
        if (!event.more) self.accept_armed = false;
        if (event.res < 0) return error.BadCompletion;

        const fd: linux.fd_t = event.res;
        errdefer closeFd(fd);

        // Refuse past the reserved cap: alloc beyond capacity would realloc the
        // slot array and move ConnState buffers out from under in-flight I/O.
        if (self.clients.len() >= self.config.max_clients) {
            closeFd(fd);
            return;
        }

        const id = try self.clients.alloc(ConnState.init(fd));
        const conn = self.clients.get(id).?;
        conn.token = try tokenFromId(id);
        // Make the injected SASL verifier available before the client can send
        // AUTHENTICATE (during CAP negotiation, pre-registration).
        if (self.config.sasl_checker) |chk| conn.session.sasl_plain = chk;
        try self.ring.submitRecv(conn.token, conn.fd, &conn.recv_buf);
    }

    fn handleRecv(self: *LinuxServer, event: ringlane.RecvEvent) !void {
        const id = idFromToken(event.token);
        const conn = try self.connForToken(event.token);
        conn.closing = event.res <= 0;
        if (event.res > 0) {
            try self.feedBytes(id, conn, conn.recv_buf[0..@as(usize, @intCast(event.res))]);
            try self.armSendIfNeeded(conn);
            if (!conn.closing) {
                try self.ring.submitRecv(conn.token, conn.fd, &conn.recv_buf);
            }
        }
        if (conn.closing and !conn.send_armed and conn.send_len == conn.send_offset) {
            try self.closeConn(event.token, "Client quit");
        }
    }

    fn handleSend(self: *LinuxServer, event: ringlane.SendEvent) !void {
        const conn = try self.connForToken(event.token);
        conn.send_armed = false;
        if (event.res < 0) {
            try self.closeConn(event.token, "Client quit");
            return;
        }

        conn.send_offset += @as(usize, @intCast(event.res));
        if (conn.send_offset >= conn.send_len) {
            conn.send_offset = 0;
            conn.send_len = 0;
        }

        try self.armSendIfNeeded(conn);
        if (conn.closing and !conn.send_armed and conn.send_len == conn.send_offset) {
            try self.closeConn(event.token, "Client quit");
        }
    }

    fn deliver(self: *LinuxServer, id: client_model.ClientId, bytes: []const u8) !void {
        const conn = self.clients.get(id) orelse return error.ClientNotFound;
        if (conn.closing) return;
        try appendToConn(conn, bytes);
        try self.armSendIfNeeded(conn);
    }

    /// Deliver `bytes` (a complete `:prefix ...` line), prepending the IRCv3
    /// server-time `tag` for recipients that negotiated the server-time cap.
    /// `tag` is precomputed once per event so all recipients share a timestamp.
    fn deliverTimed(self: *LinuxServer, id: client_model.ClientId, tag: []const u8, bytes: []const u8) !void {
        const conn = self.clients.get(id) orelse return error.ClientNotFound;
        if (conn.closing) return;
        if (tag.len != 0 and conn.session.hasCap(.server_time)) {
            try appendToConn(conn, tag);
        }
        try appendToConn(conn, bytes);
        try self.armSendIfNeeded(conn);
    }

    /// Per-event message tags available to attach (server-time value WITHOUT the
    /// `@time=` already formatted, and the sender's account if logged in). The
    /// actual `@k=v;k=v ` segment is assembled PER RECIPIENT from the caps they
    /// negotiated, so a client gets exactly the tags it asked for in one segment.
    const MsgTags = struct {
        time_value: []const u8, // ISO-8601, e.g. "2026-06-04T..Z" (no key)
        account: ?[]const u8, // sender's account, or null when not logged in
    };

    /// Deliver `bytes` with an IRCv3 message-tag segment assembled for THIS
    /// recipient: `@time=…;account=… ` including only the tags whose caps the
    /// recipient negotiated. Used by the PRIVMSG/NOTICE/TAGMSG paths.
    fn deliverTagged(self: *LinuxServer, id: client_model.ClientId, tags: MsgTags, bytes: []const u8) !void {
        const conn = self.clients.get(id) orelse return error.ClientNotFound;
        if (conn.closing) return;
        var tagbuf: [128]u8 = undefined;
        const prefix = buildTagPrefix(&conn.session, tags, &tagbuf);
        if (prefix.len != 0) try appendToConn(conn, prefix);
        try appendToConn(conn, bytes);
        try self.armSendIfNeeded(conn);
    }

    fn broadcastChannelTagged(
        self: *LinuxServer,
        channel: []const u8,
        tags: MsgTags,
        bytes: []const u8,
        except: ?client_model.ClientId,
    ) !void {
        var members = self.world.memberIterator(channel) orelse return error.NoSuchChannel;
        while (members.next()) |member| {
            const mid = clientIdFromWorld(member.*);
            if (except) |skip| {
                if (mid.eql(skip)) continue;
            }
            try self.deliverTagged(mid, tags, bytes);
        }
    }

    fn broadcastChannel(
        self: *LinuxServer,
        channel: []const u8,
        bytes: []const u8,
        except: ?client_model.ClientId,
    ) !void {
        var tag_buf: [48]u8 = undefined;
        const tag = serverTimeTag(&tag_buf);
        var members = self.world.memberIterator(channel) orelse return error.NoSuchChannel;
        while (members.next()) |member| {
            const id = clientIdFromWorld(member.*);
            if (except) |skip| {
                if (id.eql(skip)) continue;
            }
            try self.deliverTimed(id, tag, bytes);
        }
    }

    /// Like broadcastChannelTagged but only to members whose status rank is >=
    /// min_rank (STATUSMSG: `@#chan`, `+#chan`, ...).
    fn broadcastChannelMinRank(
        self: *LinuxServer,
        channel: []const u8,
        tags: MsgTags,
        bytes: []const u8,
        except: ?client_model.ClientId,
        min_rank: u8,
    ) !void {
        var members = self.world.memberIterator(channel) orelse return error.NoSuchChannel;
        while (members.next()) |member| {
            const mm = self.world.memberModes(channel, member.*) orelse continue;
            if (mm.rank() < min_rank) continue;
            const id = clientIdFromWorld(member.*);
            if (except) |skip| {
                if (id.eql(skip)) continue;
            }
            try self.deliverTagged(id, tags, bytes);
        }
    }

    fn armSendIfNeeded(self: *LinuxServer, conn: *ConnState) !void {
        if (conn.send_armed) return;
        if (conn.send_offset >= conn.send_len) return;
        try self.ring.submitSend(conn.token, conn.fd, conn.send_buf[conn.send_offset..conn.send_len]);
        conn.send_armed = true;
    }

    fn connForToken(self: *LinuxServer, token: RingFdToken) ServerError!*ConnState {
        return self.clients.get(idFromToken(token)) orelse error.ClientNotFound;
    }

    fn closeConn(self: *LinuxServer, token: RingFdToken, reason: []const u8) !void {
        const id = idFromToken(token);
        if (self.clients.get(id)) |conn| {
            defer self.world.removeClient(worldIdFromClient(id));
            // Record only for abrupt drops: a clean QUIT already recorded (and
            // removed the nick) in handleQuit, so skip to avoid a duplicate.
            if (self.world.nickOf(worldIdFromClient(id)) != null) self.recordWhowas(conn);
            // MONITOR: report this nick offline + drop its own subscriptions.
            if (conn.session.registered()) {
                const nick = conn.session.displayName();
                if (!std.mem.eql(u8, nick, "*")) self.monitorOffline(id, nick) catch {};
            }
            try self.broadcastQuit(id, conn, reason);
            closeFd(conn.fd);
            _ = self.clients.free(id);
        }
    }

    /// Snapshot a departing client's identity into the WHOWAS ring. The store
    /// copies into fixed slots, so the borrowed session strings are safe to pass.
    /// Best-effort: validation failures (e.g. over-length) are dropped.
    fn recordWhowas(self: *LinuxServer, conn: *const ConnState) void {
        if (!conn.session.registered()) return;
        const nick = conn.session.displayName();
        if (std.mem.eql(u8, nick, "*")) return;
        self.whowas.addOnQuit(.{
            .nick = nick,
            .user = conn.session.username(),
            .host = default_host,
            .realname = conn.session.realname(),
            .account = conn.session.account() orelse "",
            .signoff_time = @divTrunc(platform.realtimeMillis(), 1000),
        }) catch {};
    }

    fn broadcastQuit(self: *LinuxServer, id: client_model.ClientId, conn: *const ConnState, reason: []const u8) !void {
        if (self.world.nickOf(worldIdFromClient(id)) == null) return;

        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const msg = try formatMessage(&msg_buf, try clientPrefix(conn, &prefix_buf), "QUIT", &.{}, reason);

        var it = self.world.channels.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.members.contains(worldIdFromClient(id))) {
                try self.broadcastChannel(entry.key_ptr.*, msg, id);
            }
        }
    }

    fn feedBytes(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, bytes: []const u8) !void {
        for (bytes) |byte| {
            if (conn.line_len == conn.line_buf.len) {
                conn.closing = true;
                return error.LineTooLong;
            }
            conn.line_buf[conn.line_len] = byte;
            conn.line_len += 1;

            if (conn.line_len >= 2 and
                conn.line_buf[conn.line_len - 2] == '\r' and conn.line_buf[conn.line_len - 1] == '\n')
            {
                try self.processLiveLine(id, conn, conn.line_buf[0..conn.line_len]);
                conn.line_len = 0;
            }
        }
    }

    fn processLiveLine(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, line: []const u8) !void {
        const parsed = try irc_line.parseLine(line);
        const was_registered = conn.session.registered();

        if (!was_registered) {
            var sink = QueueSink{ .conn = conn };
            try processLine(conn, line, &sink);
            if (conn.session.registered()) {
                try self.registerConnNick(id, conn);
            }
            if (std.ascii.eqlIgnoreCase(parsed.command, "QUIT")) {
                conn.closing = true;
            }
            return;
        }

        if (std.ascii.eqlIgnoreCase(parsed.command, "PING")) {
            var sink = QueueSink{ .conn = conn };
            try processLine(conn, line, &sink);
            return;
        }

        // A per-client fault (oversized reply, malformed param) must close only
        // THAT connection — never escalate to runOnce and tear down the reactor.
        self.dispatchRegistered(id, conn, &parsed, line) catch |err| switch (err) {
            error.OutputTooSmall,
            error.TextTooLong,
            error.NoSpaceLeft,
            error.OversizeLine,
            error.LineTooLong,
            => conn.closing = true,
            else => return err, // infra (OOM, ring) bubbles up
        };
    }

    fn dispatchRegistered(
        self: *LinuxServer,
        id: client_model.ClientId,
        conn: *ConnState,
        parsed: *const irc_line.LineView,
        line: []const u8,
    ) !void {
        if (std.ascii.eqlIgnoreCase(parsed.command, "JOIN")) {
            try self.handleJoin(id, conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "PART")) {
            try self.handlePart(id, conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "NAMES")) {
            try self.handleNames(conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "MODE")) {
            try self.handleMode(id, conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "KICK")) {
            try self.handleKick(id, conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "ISON")) {
            try self.handleIson(conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "USERHOST")) {
            try self.handleUserhost(conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "LUSERS")) {
            try self.handleLusers(conn);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "MOTD")) {
            try self.handleMotd(conn);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "VERSION")) {
            try self.handleVersion(conn);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "TIME")) {
            try self.handleTime(conn);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "ADMIN")) {
            try self.handleAdmin(conn);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "INVITE")) {
            try self.handleInvite(id, conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "WHOIS")) {
            try self.handleWhois(conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "LIST")) {
            try self.handleList(conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "WHO")) {
            try self.handleWho(conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "PRIVMSG")) {
            try self.handleMessage(id, conn, parsed, "PRIVMSG");
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "NOTICE")) {
            try self.handleMessage(id, conn, parsed, "NOTICE");
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "TOPIC")) {
            try self.handleTopic(id, conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "QUIT")) {
            try self.handleQuit(id, conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "NICK")) {
            try self.handleNickChange(id, conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "AWAY")) {
            try self.handleAway(id, conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "SETNAME")) {
            try self.handleSetname(id, conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "OPER")) {
            try self.handleOper(conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "WALLOPS")) {
            try self.handleWallops(conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "REHASH")) {
            try self.handleRehash(conn);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "INFO")) {
            try self.handleInfo(conn);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "USERS")) {
            try self.handleUsers(conn);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "LINKS")) {
            try self.handleLinks(conn);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "MAP")) {
            try self.handleMap(conn);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "KILL")) {
            try self.handleKill(conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "WHOWAS")) {
            try self.handleWhowas(conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "KNOCK")) {
            try self.handleKnock(id, conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "MONITOR")) {
            try self.handleMonitor(id, conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "STATS")) {
            try self.handleStats(conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "TAGMSG")) {
            try self.handleTagmsg(id, conn, parsed);
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "SUMMON")) {
            try queueNumeric(conn, .ERR_SUMMONDISABLED, &.{}, "SUMMON has been disabled");
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "PONG")) {
            // Client heartbeat reply; accepted, no response required.
        } else {
            var sink = QueueSink{ .conn = conn };
            try processLine(conn, line, &sink);
        }
    }

    fn registerConnNick(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState) !void {
        const nick = conn.session.displayName();
        if (std.mem.eql(u8, nick, "*")) return;
        self.world.registerNick(nick, worldIdFromClient(id)) catch |err| switch (err) {
            error.NickInUse => {
                try queueNumeric(conn, .ERR_NICKNAMEINUSE, &.{nick}, "Nickname is already in use");
                conn.closing = true;
                return;
            },
            else => return err,
        };
        // Notify any MONITOR watchers that this nick just came online.
        try self.monitorOnline(nick);
    }

    /// Broadcast a JOIN to every channel member, choosing the IRCv3 extended-join
    /// form (`JOIN #c <account> :<realname>`) for recipients that negotiated the
    /// cap and the plain form otherwise. Server-time is applied per recipient.
    fn broadcastJoin(self: *LinuxServer, channel: []const u8, conn: *ConnState) !void {
        var prefix_buf: [256]u8 = undefined;
        const prefix = try clientPrefix(conn, &prefix_buf);
        const account = conn.session.account() orelse "*";

        var plain_buf: [default_reply_bytes]u8 = undefined;
        const plain = try formatMessage(&plain_buf, prefix, "JOIN", &.{channel}, null);

        var ext_buf: [default_reply_bytes]u8 = undefined;
        const ext = try formatMessage(&ext_buf, prefix, "JOIN", &.{ channel, account }, conn.session.realname());

        var tag_buf: [48]u8 = undefined;
        const tag = serverTimeTag(&tag_buf);

        var members = self.world.memberIterator(channel) orelse return error.NoSuchChannel;
        while (members.next()) |member| {
            const mid = clientIdFromWorld(member.*);
            const mconn = self.clients.get(mid) orelse continue;
            const body = if (mconn.session.hasCap(.extended_join)) ext else plain;
            try self.deliverTimed(mid, tag, body);
        }
    }

    /// Channel-mode gate for JOIN. Returns true (and emits the numeric) when the
    /// join must be refused: +b ban (474), +i invite-only (473), +k bad key
    /// (475), +l full (471). A pending INVITE bypasses ban and invite-only.
    fn joinDenied(
        self: *LinuxServer,
        conn: *ConnState,
        id: client_model.ClientId,
        channel: []const u8,
        supplied_key: ?[]const u8,
    ) !bool {
        const wid = worldIdFromClient(id);
        const invited = self.world.hasInvite(channel, wid);

        var mask_buf: [256]u8 = undefined;
        const mask = try clientPrefix(conn, &mask_buf);
        if (!invited) {
            // +b ban (isBanned already honors +e exceptions) blocks the join.
            if (self.world.isBanned(channel, mask)) {
                try queueNumeric(conn, .ERR_BANNEDFROMCHAN, &.{channel}, "Cannot join channel (+b)");
                return true;
            }
            // +i blocks unless the user holds an invite OR matches a +I invex mask.
            if (self.world.channelHasFlag(channel, .invite_only) and !self.world.isInvexed(channel, mask)) {
                try queueNumeric(conn, .ERR_INVITEONLYCHAN, &.{channel}, "Cannot join channel (+i)");
                return true;
            }
        }
        if (self.world.channelKey(channel)) |key| {
            if (supplied_key == null or !std.mem.eql(u8, supplied_key.?, key)) {
                try queueNumeric(conn, .ERR_BADCHANNELKEY, &.{channel}, "Cannot join channel (+k)");
                return true;
            }
        }
        if (self.world.channelLimit(channel)) |limit| {
            if (self.world.memberCount(channel) >= limit) {
                try queueNumeric(conn, .ERR_CHANNELISFULL, &.{channel}, "Cannot join channel (+l)");
                return true;
            }
        }
        return false;
    }

    fn handleJoin(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"JOIN"}, "Not enough parameters");
            return;
        }
        // `JOIN #a,#b key1,key2`: channels and keys are positional comma lists.
        var channels = std.mem.splitScalar(u8, parsed.paramSlice()[0], ',');
        var keys = std.mem.splitScalar(u8, if (parsed.param_count >= 2) parsed.paramSlice()[1] else "", ',');
        while (channels.next()) |channel| {
            if (channel.len == 0) continue;
            const key_part = keys.next() orelse "";
            const key: ?[]const u8 = if (key_part.len != 0) key_part else null;
            try self.joinOne(id, conn, channel, key);
        }
    }

    fn joinOne(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, channel: []const u8, key: ?[]const u8) !void {
        if (!world_model.isChannelName(channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{channel}, "No such channel");
            return;
        }

        // Enforce channel modes only when joining an EXISTING channel as a new
        // member. Creating a fresh channel (founder path) bypasses all gates.
        const wid = worldIdFromClient(id);
        if (self.world.channelExists(channel) and !self.world.isMember(channel, wid)) {
            if (try self.joinDenied(conn, id, channel, key)) return;
        }

        _ = try self.world.join(channel, wid);

        try self.broadcastJoin(channel, conn);
        try self.sendTopicReply(conn, channel);
        try self.sendNames(conn, channel);
    }

    fn handlePart(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"PART"}, "Not enough parameters");
            return;
        }
        const reason = if (parsed.param_count >= 2) parsed.paramSlice()[1] else null;
        // `PART #a,#b :reason`: comma-separated channel list, shared reason.
        var channels = std.mem.splitScalar(u8, parsed.paramSlice()[0], ',');
        while (channels.next()) |channel| {
            if (channel.len == 0) continue;
            try self.partOne(id, conn, channel, reason);
        }
    }

    fn partOne(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, channel: []const u8, reason: ?[]const u8) !void {
        if (!self.world.channelExists(channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{channel}, "No such channel");
            return;
        }
        if (!self.world.isMember(channel, worldIdFromClient(id))) {
            try queueNumeric(conn, .ERR_NOTONCHANNEL, &.{channel}, "You're not on that channel");
            return;
        }

        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const msg = try formatMessage(&msg_buf, try clientPrefix(conn, &prefix_buf), "PART", &.{channel}, reason);
        try self.broadcastChannel(channel, msg, null);
        try self.world.part(channel, worldIdFromClient(id));
    }

    fn handleNames(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"NAMES"}, "Not enough parameters");
            return;
        }

        const channel = parsed.paramSlice()[0];
        if (!self.world.channelExists(channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{channel}, "No such channel");
            return;
        }
        try self.sendNames(conn, channel);
    }

    /// MODE for channel member status modes (+Q/+q/+o/+v, founder +Q is creation-
    /// only) gated by tier rank, flag modes (i/m/n/t/s), and parameterised modes
    /// (+k key, +l limit, +b ban; `MODE #c b` lists bans). User-target MODE is not
    /// handled on this path.
    fn handleMode(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MODE"}, "Not enough parameters");
            return;
        }
        const channel = parsed.paramSlice()[0];
        if (!world_model.isChannelName(channel)) {
            // User-target MODE: only the client's own nick is settable.
            try self.handleUserMode(conn, parsed, channel);
            return;
        }
        if (!self.world.channelExists(channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{channel}, "No such channel");
            return;
        }

        // Query form: MODE #chan -> RPL_CHANNELMODEIS. Per ophion channel_modes:
        // the +l/+k LETTERS are shown to everyone, but their PARAM VALUES (limit,
        // key) only to members. Param order matches letter order (l before k).
        if (parsed.param_count == 1) {
            var flags_buf: [16]u8 = undefined;
            const flags = self.world.channelModeString(channel, &flags_buf); // "+imnt"
            const limit = self.world.channelLimit(channel);
            const key = self.world.channelKey(channel);
            const is_member = self.world.isMember(channel, worldIdFromClient(id));

            var modes_buf: [24]u8 = undefined;
            var mb = Buf{ .storage = &modes_buf };
            mb.append(flags) catch {};
            if (limit != null) mb.appendByte('l') catch {};
            if (key != null) mb.appendByte('k') catch {};

            var parts: [4][]const u8 = undefined;
            var n: usize = 0;
            parts[n] = channel;
            n += 1;
            parts[n] = mb.written();
            n += 1;
            var lim_buf: [16]u8 = undefined;
            if (is_member) {
                if (limit) |lv| {
                    parts[n] = std.fmt.bufPrint(&lim_buf, "{d}", .{lv}) catch "0";
                    n += 1;
                }
                if (key) |k| {
                    parts[n] = k;
                    n += 1;
                }
            }
            try queueNumeric(conn, .RPL_CHANNELMODEIS, parts[0..n], "");
            return;
        }

        const setter = self.world.memberModes(channel, worldIdFromClient(id)) orelse {
            try queueNumeric(conn, .ERR_NOTONCHANNEL, &.{channel}, "You're not on that channel");
            return;
        };
        if (!setter.isOperator()) {
            try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{channel}, "You're not channel operator");
            return;
        }

        const mode_str = parsed.paramSlice()[1];
        // Sized generously; appends soft-fail (break) rather than erroring so a
        // pathological toggle string ("+i-i+i...") truncates instead of faulting.
        var applied_buf: [256]u8 = undefined;
        var applied = Buf{ .storage = &applied_buf };
        var targets_buf: [default_reply_bytes / 2]u8 = undefined;
        var targets = Buf{ .storage = &targets_buf };
        var arg_index: usize = 2;
        var adding = true;
        var emitted_sign: u8 = 0;

        for (mode_str) |ch| {
            switch (ch) {
                '+' => adding = true,
                '-' => adding = false,
                'Q', 'q', 'o', 'v' => {
                    if (arg_index >= parsed.param_count) continue;
                    const target_nick = parsed.paramSlice()[arg_index];
                    arg_index += 1;
                    const mode: world_model.MemberMode = switch (ch) {
                        'Q' => .founder,
                        'q' => .owner,
                        'o' => .op,
                        'v' => .voice,
                        else => unreachable,
                    };
                    // Founder is singular and granted only at channel creation;
                    // it cannot be handed out via MODE (a founder may still drop
                    // or transfer their own via dedicated mechanisms later).
                    if (mode == .founder and adding) {
                        try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{channel}, "Founder is set at channel creation, not by MODE");
                        continue;
                    }
                    // Authority: a member may only set/clear a status tier whose
                    // rank is <= their own highest rank. So op manages op/voice,
                    // owner manages owner/op/voice, founder manages all — and an
                    // owner can NEVER strip a founder, nor an op an owner.
                    if (setter.rank() < chanmode.rankOfMode(mode)) {
                        try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{channel}, "Insufficient channel privilege for that mode");
                        continue;
                    }
                    const target = self.world.findNick(target_nick) orelse {
                        try queueNumeric(conn, .ERR_NOSUCHNICK, &.{target_nick}, "No such nick");
                        continue;
                    };
                    const changed = self.world.setMemberMode(channel, target, mode, adding) catch {
                        try queueNumeric(conn, .ERR_USERNOTINCHANNEL, &.{ target_nick, channel }, "They aren't on that channel");
                        continue;
                    };
                    if (changed) {
                        const want_sign: u8 = if (adding) '+' else '-';
                        if (emitted_sign != want_sign) {
                            applied.appendByte(want_sign) catch break;
                            emitted_sign = want_sign;
                        }
                        applied.appendByte(ch) catch break;
                        targets.appendByte(' ') catch break;
                        targets.append(target_nick) catch break;
                    }
                },
                'i', 'm', 'n', 't', 's' => {
                    const mode: world_model.ChannelMode = switch (ch) {
                        'i' => .invite_only,
                        'm' => .moderated,
                        'n' => .no_external,
                        't' => .topic_ops,
                        's' => .secret,
                        else => unreachable,
                    };
                    const changed = self.world.setChannelFlag(channel, mode, adding) catch continue;
                    if (changed) {
                        const want_sign: u8 = if (adding) '+' else '-';
                        if (emitted_sign != want_sign) {
                            applied.appendByte(want_sign) catch break;
                            emitted_sign = want_sign;
                        }
                        applied.appendByte(ch) catch break;
                    }
                },
                'k' => {
                    if (adding) {
                        if (arg_index >= parsed.param_count) continue;
                        const key = parsed.paramSlice()[arg_index];
                        arg_index += 1;
                        self.world.setChannelKey(channel, key) catch continue;
                        appendParamMode(&applied, &targets, &emitted_sign, '+', 'k', key);
                    } else {
                        self.world.setChannelKey(channel, null) catch continue;
                        appendParamMode(&applied, &targets, &emitted_sign, '-', 'k', "*");
                    }
                },
                'l' => {
                    if (adding) {
                        if (arg_index >= parsed.param_count) continue;
                        const arg = parsed.paramSlice()[arg_index];
                        arg_index += 1;
                        const limit = std.fmt.parseInt(u32, arg, 10) catch continue;
                        self.world.setChannelLimit(channel, limit) catch continue;
                        appendParamMode(&applied, &targets, &emitted_sign, '+', 'l', arg);
                    } else {
                        self.world.setChannelLimit(channel, null) catch continue;
                        appendModeLetter(&applied, &emitted_sign, '-', 'l');
                    }
                },
                'b' => {
                    // No argument => RPL_BANLIST query.
                    if (arg_index >= parsed.param_count) {
                        try self.sendBanList(conn, channel);
                        continue;
                    }
                    const mask = parsed.paramSlice()[arg_index];
                    arg_index += 1;
                    const changed = if (adding)
                        (self.world.addBan(channel, mask) catch continue)
                    else
                        (self.world.removeBan(channel, mask) catch continue);
                    if (changed) {
                        const sign: u8 = if (adding) '+' else '-';
                        appendParamMode(&applied, &targets, &emitted_sign, sign, 'b', mask);
                    }
                },
                'e' => {
                    // No argument => RPL_EXCEPTLIST query (348/349).
                    if (arg_index >= parsed.param_count) {
                        try self.sendMaskList(conn, channel, self.world.exemptsOf(channel), .RPL_EXCEPTLIST, .RPL_ENDOFEXCEPTLIST, "End of channel exception list");
                        continue;
                    }
                    const mask = parsed.paramSlice()[arg_index];
                    arg_index += 1;
                    const changed = if (adding)
                        (self.world.addExempt(channel, mask) catch continue)
                    else
                        (self.world.removeExempt(channel, mask) catch continue);
                    if (changed) appendParamMode(&applied, &targets, &emitted_sign, if (adding) '+' else '-', 'e', mask);
                },
                'I' => {
                    // No argument => RPL_INVITELIST query (346/347).
                    if (arg_index >= parsed.param_count) {
                        try self.sendMaskList(conn, channel, self.world.invexOf(channel), .RPL_INVITELIST, .RPL_ENDOFINVITELIST, "End of channel invite exception list");
                        continue;
                    }
                    const mask = parsed.paramSlice()[arg_index];
                    arg_index += 1;
                    const changed = if (adding)
                        (self.world.addInvex(channel, mask) catch continue)
                    else
                        (self.world.removeInvex(channel, mask) catch continue);
                    if (changed) appendParamMode(&applied, &targets, &emitted_sign, if (adding) '+' else '-', 'I', mask);
                },
                else => {}, // remaining list/param modes not tracked yet
            }
        }

        if (applied.written().len == 0) return;

        var prefix_buf: [256]u8 = undefined;
        var line_buf: [default_reply_bytes]u8 = undefined;
        var line = Buf{ .storage = &line_buf };
        try line.append(":");
        try line.append(try clientPrefix(conn, &prefix_buf));
        try line.append(" MODE ");
        try line.append(channel);
        try line.appendByte(' ');
        try line.append(applied.written());
        try line.append(targets.written());
        try line.append("\r\n");
        try self.broadcastChannel(channel, line.written(), null);
    }

    /// MODE <nick> [modes] — user modes. A client may only view/change its own
    /// (ERR_USERSDONTMATCH 502 otherwise). Query form returns RPL_UMODEIS (221).
    /// Supports +i invisible and +B bot today (IRCv3 bot-mode).
    fn handleUserMode(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView, target: []const u8) !void {
        _ = self;
        if (!std.mem.eql(u8, target, conn.session.displayName())) {
            try queueNumeric(conn, .ERR_USERSDONTMATCH, &.{}, "Cannot change mode for other users");
            return;
        }
        // Query form: MODE <ownnick>.
        if (parsed.param_count == 1) {
            var ms_buf: [16]u8 = undefined;
            try queueNumeric(conn, .RPL_UMODEIS, &.{}, conn.session.umodeString(&ms_buf));
            return;
        }

        const mode_str = parsed.paramSlice()[1];
        var applied_buf: [32]u8 = undefined;
        var applied = Buf{ .storage = &applied_buf };
        var adding = true;
        var emitted_sign: u8 = 0;
        for (mode_str) |ch| {
            switch (ch) {
                '+' => adding = true,
                '-' => adding = false,
                'i', 'B' => {
                    const mode: dispatch.UserMode = if (ch == 'i') .invisible else .bot;
                    if (conn.session.setUmode(mode, adding)) {
                        appendModeLetter(&applied, &emitted_sign, if (adding) '+' else '-', ch);
                    }
                },
                else => {}, // other umodes (r/Z/D/g/T/x) are server-managed
            }
        }
        if (applied.written().len == 0) return;

        var prefix_buf: [256]u8 = undefined;
        var line_buf: [default_reply_bytes]u8 = undefined;
        const nick = conn.session.displayName();
        const msg = try formatMessage(&line_buf, try clientPrefix(conn, &prefix_buf), "MODE", &.{ nick, applied.written() }, null);
        try appendToConn(conn, msg);
    }

    /// KICK <channel> <user> [:reason]. Kicker must be op-or-higher and may not
    /// kick a member who outranks them (tier rank). The target sees their own
    /// kick (broadcast before removal).
    fn handleKick(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const args = kick.parseKickArgs(parsed.paramSlice()) catch {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"KICK"}, "Not enough parameters");
            return;
        };
        if (!self.world.channelExists(args.channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{args.channel}, "No such channel");
            return;
        }
        const kicker = self.world.memberModes(args.channel, worldIdFromClient(id)) orelse {
            try queueNumeric(conn, .ERR_NOTONCHANNEL, &.{args.channel}, "You're not on that channel");
            return;
        };
        if (!kicker.isOperator()) {
            try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{args.channel}, "You're not channel operator");
            return;
        }
        const target = self.world.findNick(args.user) orelse {
            try queueNumeric(conn, .ERR_USERNOTINCHANNEL, &.{ args.user, args.channel }, "They aren't on that channel");
            return;
        };
        const target_mm = self.world.memberModes(args.channel, target) orelse {
            try queueNumeric(conn, .ERR_USERNOTINCHANNEL, &.{ args.user, args.channel }, "They aren't on that channel");
            return;
        };
        if (kicker.rank() < target_mm.rank()) {
            try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{args.channel}, "Cannot kick a higher-ranked member");
            return;
        }

        const kicker_prefix = kick.Prefix{ .nick = conn.session.displayName(), .user = conn.session.username(), .host = default_host };
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const msg = kick.buildKickBroadcastWith(.{ .require_utf8 = false }, &msg_buf, kicker_prefix, args.channel, args.user, args.reason) catch return;
        try self.broadcastChannel(args.channel, msg, null);
        self.world.part(args.channel, target) catch {};
    }

    /// ISON <nick>... — reply RPL_ISON (303) with the subset that is online.
    fn handleIson(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        var online_buf: [32][]const u8 = undefined;
        var count: usize = 0;
        for (parsed.paramSlice()) |nick| {
            if (count >= online_buf.len) break;
            if (self.world.findNick(nick) != null) {
                online_buf[count] = nick;
                count += 1;
            }
        }
        var out_buf: [default_reply_bytes]u8 = undefined;
        var lines_buf: [8]ison_userhost.ReplyLine = undefined;
        var sink = ison_userhost.ReplyLineSink{ .lines = &lines_buf };
        ison_userhost.writeIsonReplies(&out_buf, server_name, conn.session.displayName(), online_buf[0..count], alwaysOnline, &sink) catch return;
        for (sink.slice()) |line| try appendToConn(conn, line.bytes);
    }

    /// USERHOST <nick>... (up to 5) — reply RPL_USERHOST (302).
    fn handleUserhost(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        var targets: [ison_userhost.USERHOST_MAX_TARGETS]ison_userhost.UserhostTarget = undefined;
        var count: usize = 0;
        for (parsed.paramSlice()) |nick| {
            if (count >= targets.len) break;
            const wid = self.world.findNick(nick) orelse continue;
            // oper/away and host are not tracked per-client yet (M2 placeholder);
            // username is now the real USER-supplied value.
            targets[count] = .{ .nick = nick, .is_oper = false, .is_away = false, .user = usernameOf(self, wid), .host = default_host };
            count += 1;
        }
        var out_buf: [default_reply_bytes]u8 = undefined;
        const line = ison_userhost.writeUserhostReply(&out_buf, server_name, conn.session.displayName(), targets[0..count]) catch return;
        try appendToConn(conn, line);
    }

    /// WHO <channel|nick> — RPL_WHOREPLY (352) per match + RPL_ENDOFWHO (315).
    fn handleWho(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"WHO"}, "Not enough parameters");
            return;
        }
        const target = parsed.paramSlice()[0];
        const requester = conn.session.displayName();
        var buf: [default_reply_bytes]u8 = undefined;

        if (world_model.isChannelName(target) and self.world.channelExists(target)) {
            var it = self.world.memberIterator(target) orelse return;
            while (it.next()) |member| {
                const nick = self.world.nickOf(member.*) orelse continue;
                const mconn = self.clients.get(clientIdFromWorld(member.*));
                const hp = (self.world.memberModes(target, member.*) orelse world_model.MemberModes.empty()).highestPrefix();
                const ctx = who.ReplyContext{
                    .server_name = server_name,
                    .requester = requester,
                    .target = target,
                    .client = .{
                        .nick = nick,
                        .user = usernameOf(self, member.*),
                        .host = default_host,
                        .server = server_name,
                        .realname = if (mconn) |c| c.session.realname() else nick,
                        .account = if (mconn) |c| c.session.account() else null,
                    },
                    .member = .{ .channel = target, .channel_prefix = if (hp != 0) hp else null },
                };
                const line = who.writeWhoReply(&buf, ctx) catch continue;
                try appendToConn(conn, line);
                try appendToConn(conn, "\r\n");
            }
        } else if (self.world.findNick(target)) |wid| {
            const mconn = self.clients.get(clientIdFromWorld(wid));
            const ctx = who.ReplyContext{
                .server_name = server_name,
                .requester = requester,
                .target = target,
                .client = .{
                    .nick = target,
                    .user = usernameOf(self, wid),
                    .host = default_host,
                    .server = server_name,
                    .realname = if (mconn) |c| c.session.realname() else target,
                    .account = if (mconn) |c| c.session.account() else null,
                },
            };
            if (who.writeWhoReply(&buf, ctx)) |line| {
                try appendToConn(conn, line);
                try appendToConn(conn, "\r\n");
            } else |_| {}
        }

        const end = who.writeEndOfWho(&buf, server_name, requester, target) catch return;
        try appendToConn(conn, end);
        try appendToConn(conn, "\r\n");
    }

    /// LIST [<filters>] — RPL_LISTSTART/RPL_LIST/RPL_LISTEND. Secret (+s)
    /// channels are hidden. Filters that fail to parse fall back to listing all.
    fn handleList(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const request = list.parseList(parsed.paramSlice()) catch list.Request{};
        const Adapter = struct {
            it: world_model.World.ChannelViewIterator,
            pub fn next(s: *@This()) ?list.ChannelInfo {
                while (s.it.next()) |v| {
                    if (v.secret) continue;
                    return .{ .name = v.name, .users = @intCast(v.members), .topic = v.topic };
                }
                return null;
            }
        };
        var adapter = Adapter{ .it = self.world.channelIterator() };
        var scratch: [default_reply_bytes]u8 = undefined;
        var sink = ConnLineSinkCRLF{ .conn = conn };
        list.emitList(Adapter, &adapter, request, .{ .server_name = server_name, .requester = conn.session.displayName(), .now_seconds = 0 }, &scratch, &sink) catch return;
    }

    /// WHOIS [server] <nick> — full WHOIS sequence for a local user.
    fn handleWhois(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"WHOIS"}, "Not enough parameters");
            return;
        }
        // WHOIS [<server>] <nick>: the target is the last parameter.
        const target_nick = parsed.paramSlice()[parsed.param_count - 1];
        var storage: [default_reply_bytes * 2]u8 = undefined;
        var lines_buf: [40]whois.WhoisLine = undefined;
        var sink = whois.WhoisLineSink{ .lines = &lines_buf, .storage = &storage };

        const target_wid = self.world.findNick(target_nick);
        const target_conn: ?*ConnState = if (target_wid) |w| self.clients.get(clientIdFromWorld(w)) else null;
        if (target_wid == null or target_conn == null) {
            whois.writeNoSuchNick(&sink, server_name, conn.session.displayName(), target_nick) catch return;
            for (sink.slice()) |line| try appendToConn(conn, line.bytes);
            return;
        }

        // Channels the target is in, with their highest status prefix.
        var chan_names: [32][]const u8 = undefined;
        const nchan = self.world.channelsOf(target_wid.?, &chan_names);
        var memberships: [32]whois.ChannelMembership = undefined;
        var prefix_store: [32][1]u8 = undefined;
        for (chan_names[0..nchan], 0..) |cn, i| {
            const modes = self.world.memberModes(cn, target_wid.?) orelse world_model.MemberModes.empty();
            const hp = modes.highestPrefix();
            var pfx: []const u8 = "";
            if (hp != 0) {
                prefix_store[i][0] = hp;
                pfx = prefix_store[i][0..1];
            }
            memberships[i] = .{ .prefix = pfx, .channel = cn };
        }

        const tconn = target_conn.?;
        const subject = whois.WhoisSubject{
            .nick = target_nick,
            .user = tconn.session.username(),
            .host = default_host,
            .realname = tconn.session.realname(),
            .account = tconn.session.account(),
            .away = tconn.session.awayMessage(),
            .is_oper = tconn.session.isOper(),
            .is_bot = tconn.session.isBot(),
            .channels = memberships[0..nchan],
        };
        whois.writeWhois(&sink, server_name, conn.session.displayName(), subject) catch return;
        for (sink.slice()) |line| try appendToConn(conn, line.bytes);
    }

    /// INVITE <nick> <channel> — invite a user; +i channels require op (no +g
    /// free-invite mode yet). RPL_INVITING to inviter + INVITE line to target.
    fn handleInvite(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const args = invite.parseInviteArgs(parsed.paramSlice()) catch {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"INVITE"}, "Not enough parameters");
            return;
        };
        if (!self.world.channelExists(args.channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{args.channel}, "No such channel");
            return;
        }
        const inviter_modes = self.world.memberModes(args.channel, worldIdFromClient(id));
        const target_wid = self.world.findNick(args.nick);
        const result = invite.checkInvitePreconditions(.{
            .on_channel = inviter_modes != null,
            .is_operator = if (inviter_modes) |m| m.isOperator() else false,
            .invite_only = self.world.channelHasFlag(args.channel, .invite_only),
            .free_invite = false,
            .target_on_channel = if (target_wid) |t| self.world.isMember(args.channel, t) else false,
        });
        switch (result) {
            .allow => {},
            .deny_not_on_channel => return queueNumeric(conn, .ERR_NOTONCHANNEL, &.{args.channel}, "You're not on that channel"),
            .deny_user_on_channel => return queueNumeric(conn, .ERR_USERONCHANNEL, &.{ args.nick, args.channel }, "is already on channel"),
            .deny_chan_op_privs_needed => return queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{args.channel}, "You're not channel operator"),
        }
        const target = target_wid orelse {
            try queueNumeric(conn, .ERR_NOSUCHNICK, &.{args.nick}, "No such nick");
            return;
        };

        // Record the invite so the target can bypass +i / +b on JOIN.
        self.world.addInvite(args.channel, target) catch {};

        var num_buf: [default_reply_bytes]u8 = undefined;
        const inviting = invite.buildInvitingNumeric(&num_buf, server_name, conn.session.displayName(), args.nick, args.channel) catch return;
        try appendToConn(conn, inviting);
        try appendToConn(conn, "\r\n");

        const prefix = invite.Prefix{ .nick = conn.session.displayName(), .user = conn.session.username(), .host = default_host };
        var line_buf: [default_reply_bytes]u8 = undefined;
        const target_line = invite.buildTargetInviteLine(&line_buf, prefix, args.nick, args.channel) catch return;
        // deliver() expects a CRLF-terminated line; the builder omits it.
        var full_buf: [default_reply_bytes]u8 = undefined;
        const full = std.fmt.bufPrint(&full_buf, "{s}\r\n", .{target_line}) catch return;
        try self.deliver(clientIdFromWorld(target), full);

        // IRCv3 invite-notify (ophion m_invite.c): tell channel members who hold
        // the cap, except the inviter — `:inviter!u@h INVITE <target> :<channel>`.
        var notif_prefix: [256]u8 = undefined;
        var notif_buf: [default_reply_bytes]u8 = undefined;
        const notif = try formatMessage(&notif_buf, try clientPrefix(conn, &notif_prefix), "INVITE", &.{args.nick}, args.channel);
        var members = self.world.memberIterator(args.channel) orelse return;
        while (members.next()) |member| {
            const mid = clientIdFromWorld(member.*);
            if (mid.eql(id)) continue;
            const mconn = self.clients.get(mid) orelse continue;
            if (!mconn.session.hasCap(.invite_notify)) continue;
            try self.deliver(mid, notif);
        }
    }

    /// KILL <nick> :<reason> — oper-only forced disconnect. Delivers a KILL line
    /// then routes the victim through the graceful close-on-drain path (its
    /// channels see a QUIT once the buffer flushes). Non-opers get 481.
    fn handleKill(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        if (parsed.param_count < 1) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"KILL"}, "Not enough parameters");
            return;
        }
        const target_nick = parsed.paramSlice()[0];
        const reason = if (parsed.param_count >= 2) parsed.paramSlice()[1] else "Killed";
        const target_wid = self.world.findNick(target_nick) orelse {
            try queueNumeric(conn, .ERR_NOSUCHNICK, &.{target_nick}, "No such nick");
            return;
        };
        const tconn = self.clients.get(clientIdFromWorld(target_wid)) orelse {
            try queueNumeric(conn, .ERR_NOSUCHNICK, &.{target_nick}, "No such nick");
            return;
        };

        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const killer = conn.session.displayName();
        const kill_line = try formatMessage(&msg_buf, try clientPrefix(conn, &prefix_buf), "KILL", &.{target_nick}, reason);
        try self.deliver(clientIdFromWorld(target_wid), kill_line);

        var err_buf: [default_reply_bytes]u8 = undefined;
        const err_line = std.fmt.bufPrint(&err_buf, "ERROR :Closing Link: {s} (Killed ({s} ({s})))\r\n", .{ target_nick, killer, reason }) catch return error.OutputTooSmall;
        try self.deliver(clientIdFromWorld(target_wid), err_line);

        // Graceful close: the send-drain path fires QUIT to channels and frees
        // the slot once the buffer flushes (mirrors a self-QUIT).
        tconn.closing = true;
        try self.armSendIfNeeded(tconn);
    }

    /// WHOWAS <nick> [count] — historical identities from the ring, most-recent
    /// first (314 + 312 signoff, 406 if none, 369 end).
    fn handleWhowas(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"WHOWAS"}, "Not enough parameters");
            return;
        }
        const target = parsed.paramSlice()[0];

        var records: [16]whowas.Record = undefined;
        const found = self.whowas.query(target, records.len, &records) catch records[0..0];
        const n = found.len;

        var entries: [16]whowas_reply.HistoryEntry = undefined;
        for (found, 0..) |rec, i| {
            entries[i] = .{
                .nick = rec.nick,
                .user = rec.user,
                .host = rec.host,
                .realname = rec.realname,
                .signoff_time = rec.signoff_time,
                .server = server_name,
            };
        }

        var scratch: [default_reply_bytes]u8 = undefined;
        var sink = ConnLineSink{ .conn = conn };
        whowas_reply.emitWhowas(&scratch, server_name, conn.session.displayName(), target, entries[0..n], &sink) catch return;
    }

    /// KNOCK <channel> [:reason] — ask for an invite to a +i channel. Channel
    /// ops get RPL_KNOCK (710); the knocker gets RPL_KNOCKDLVR (711). Refused if
    /// the channel is open (713) or the knocker is already a member (714).
    fn handleKnock(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"KNOCK"}, "Not enough parameters");
            return;
        }
        const channel = parsed.paramSlice()[0];
        const reason = if (parsed.param_count >= 2) parsed.paramSlice()[1] else "wants to join";
        if (!self.world.channelExists(channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{channel}, "No such channel");
            return;
        }
        const wid = worldIdFromClient(id);
        if (self.world.isMember(channel, wid)) {
            try queueNumeric(conn, .ERR_KNOCKONCHAN, &.{channel}, "You are already on that channel");
            return;
        }
        if (!self.world.channelHasFlag(channel, .invite_only)) {
            try queueNumeric(conn, .ERR_CHANOPEN, &.{channel}, "Channel is open");
            return;
        }

        // Notify every operator-or-higher member.
        var mask_buf: [256]u8 = undefined;
        const mask = try clientPrefix(conn, &mask_buf);
        var members = self.world.memberIterator(channel) orelse return;
        while (members.next()) |member| {
            const mm = self.world.memberModes(channel, member.*) orelse continue;
            if (!mm.isOperator()) continue;
            const op_id = clientIdFromWorld(member.*);
            const opconn = self.clients.get(op_id) orelse continue;
            try queueNumeric(opconn, .RPL_KNOCK, &.{ channel, mask }, reason);
            try self.armSendIfNeeded(opconn);
        }
        try queueNumeric(conn, .RPL_KNOCKDLVR, &.{channel}, "Your KNOCK has been delivered");
    }

    /// MONITOR +/-/C/L/S — IRCv3 contact notification. Targets' online/offline
    /// transitions are reported (730/731); L lists (732/733), S reports status.
    fn handleMonitor(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        var replies_buf: [64]monitor.MonitorReply = undefined;
        var storage: [default_reply_bytes]u8 = undefined;
        var sink = monitor.MonitorReplySink{ .replies = &replies_buf, .storage = &storage };
        self.monitor.handle(monitorIdFromClient(id), parsed.paramSlice(), &sink) catch |err| switch (err) {
            error.MissingParameter => return queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MONITOR"}, "Not enough parameters"),
            error.OutOfMemory => return error.OutOfMemory,
            else => return, // InvalidTarget / TooManyReplies / OutputTooSmall: best-effort
        };
        try self.flushMonitorReplies(&sink);
    }

    /// Route each structured MONITOR reply to its destination watcher and arm
    /// that connection's send (replies may target clients other than the caller).
    fn flushMonitorReplies(self: *LinuxServer, sink: *const monitor.MonitorReplySink) !void {
        for (sink.slice()) |reply| {
            const wconn = self.clients.get(clientIdFromMonitor(reply.client)) orelse continue;
            const trailing = if (reply.targets.len != 0) reply.targets else reply.text;
            try queueNumeric(wconn, monitorNumeric(reply.numeric), &.{}, trailing);
            try self.armSendIfNeeded(wconn);
        }
    }

    /// Notify MONITOR watchers that `nick` just came online (on registration).
    fn monitorOnline(self: *LinuxServer, nick: []const u8) !void {
        var replies_buf: [64]monitor.MonitorReply = undefined;
        var storage: [default_reply_bytes]u8 = undefined;
        var sink = monitor.MonitorReplySink{ .replies = &replies_buf, .storage = &storage };
        self.monitor.setOnline(nick, &sink) catch return;
        try self.flushMonitorReplies(&sink);
    }

    /// Notify watchers that `nick` went offline, then drop the disconnecting
    /// client's own monitor subscriptions.
    fn monitorOffline(self: *LinuxServer, id: client_model.ClientId, nick: []const u8) !void {
        var replies_buf: [64]monitor.MonitorReply = undefined;
        var storage: [default_reply_bytes]u8 = undefined;
        var sink = monitor.MonitorReplySink{ .replies = &replies_buf, .storage = &storage };
        self.monitor.setOffline(nick, &sink) catch {};
        self.flushMonitorReplies(&sink) catch {};
        self.monitor.removeClient(monitorIdFromClient(id));
    }

    /// STATS <letter> — server statistics. Supports u (uptime, 242) and o (oper
    /// blocks, 243). All queries terminate with RPL_ENDOFSTATS (219).
    fn handleStats(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"STATS"}, "Not enough parameters");
            return;
        }
        const letter = parsed.paramSlice()[0];
        switch (letter[0]) {
            'u' => {
                const up_secs: u64 = @intCast(@max(@as(i64, 0), @divTrunc(platform.monotonicMillis() - self.start_ms, 1000)));
                const days = up_secs / 86_400;
                const hours = (up_secs % 86_400) / 3600;
                const mins = (up_secs % 3600) / 60;
                const secs = up_secs % 60;
                var buf: [96]u8 = undefined;
                const text = std.fmt.bufPrint(&buf, "Server Up {d} days {d:0>2}:{d:0>2}:{d:0>2}", .{ days, hours, mins, secs }) catch return;
                try queueNumeric(conn, .RPL_STATSUPTIME, &.{}, text);
            },
            'o' => {
                // One static oper block (matches the OPER credential).
                try queueNumeric(conn, .RPL_STATSOLINE, &.{ "O", "*@*", "*", self.oper_name, "0", "0" }, "");
            },
            else => {}, // other letters not implemented yet
        }
        try queueNumeric(conn, .RPL_ENDOFSTATS, &.{letter}, "End of /STATS report");
    }

    /// LUSERS — network/user counters (251-255, 265/266).
    fn handleLusers(self: *LinuxServer, conn: *ConnState) !void {
        const clients: u64 = @intCast(self.clients.len());
        var opers: u64 = 0;
        var oit = self.clients.iterator();
        while (oit.next()) |entry| {
            if (entry.value.session.isOper()) opers += 1;
        }
        const counts = lusers.Counts{
            .users = clients,
            .invisible = 0,
            .servers = 1,
            .opers = opers,
            .unknown = 0,
            .channels = @intCast(self.world.channelCount()),
            .local_clients = clients,
            .local_max = clients,
            .global_clients = clients,
            .global_max = clients,
        };
        var scratch: [default_reply_bytes]u8 = undefined;
        var sink = ConnLineSink{ .conn = conn };
        lusers.emit(.{ .server_name = server_name, .requester = conn.session.displayName() }, counts, &scratch, &sink) catch return;
    }

    /// MOTD (375/372/376).
    fn handleMotd(self: *LinuxServer, conn: *ConnState) !void {
        _ = self;
        var out_buf: [default_reply_bytes]u8 = undefined;
        var lines_buf: [8]motd.MotdLine = undefined;
        var sink = motd.MotdLineSink{ .lines = &lines_buf };
        motd.writeMotdRepliesForRequester(&out_buf, server_name, conn.session.displayName(), &motd_text, &sink) catch return;
        for (sink.slice()) |line| {
            try appendToConn(conn, line.bytes);
            try appendToConn(conn, "\r\n");
        }
    }

    /// TIME (391) — current wall-clock server time.
    fn handleTime(self: *LinuxServer, conn: *ConnState) !void {
        _ = self;
        var tbuf: [64]u8 = undefined;
        const tstr = formatServerTime(&tbuf);
        var out_buf: [default_reply_bytes]u8 = undefined;
        const line = serverinfo.writeTimeReply(&out_buf, .{ .server_name = server_name, .requester = conn.session.displayName() }, server_name, tstr) catch return;
        try appendToConn(conn, line);
    }

    /// ADMIN (256/257/258/259).
    fn handleAdmin(self: *LinuxServer, conn: *ConnState) !void {
        _ = self;
        var out_buf: [default_reply_bytes]u8 = undefined;
        var lines_buf: [4]serverinfo.ReplyLine = undefined;
        var sink = serverinfo.ReplyLineSink{ .lines = &lines_buf };
        serverinfo.writeAdminReplies(&out_buf, .{ .server_name = server_name, .requester = conn.session.displayName() }, .{
            .reply_server = server_name,
            .location1 = "Mizuchi IRC network",
            .email = "admin@mizuchi.local",
        }, &sink) catch return;
        for (sink.slice()) |line| try appendToConn(conn, line.bytes);
    }

    /// VERSION (351).
    fn handleVersion(self: *LinuxServer, conn: *ConnState) !void {
        _ = self;
        var out_buf: [default_reply_bytes]u8 = undefined;
        const info = serverinfo.VersionInfo{
            .version = server_version,
            .build = "zig",
            .reply_server = server_name,
            .description = "Mizuchi IRC daemon",
            .sid = "0MZ",
        };
        const line = serverinfo.writeVersionReply(&out_buf, .{ .server_name = server_name, .requester = conn.session.displayName() }, info) catch return;
        try appendToConn(conn, line);
    }

    /// NICK <newnick> — registered nick change. Validates, rejects collisions
    /// (433), rewrites the world registry + session, then broadcasts
    /// `:old!u@h NICK :new` to the client and every common-channel member.
    /// MONITOR watchers see old offline / new online; the old identity is
    /// recorded in WHOWAS.
    fn handleNickChange(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
            try queueNumeric(conn, .ERR_NONICKNAMEGIVEN, &.{}, "No nickname given");
            return;
        }
        const newnick = parsed.paramSlice()[0];
        if (!isValidNick(newnick)) {
            try queueNumeric(conn, .ERR_ERRONEUSNICKNAME, &.{newnick}, "Erroneous nickname");
            return;
        }
        // Snapshot the old nick into a stack buffer: displayName() borrows the
        // session's inline nick buffer, which setNick() overwrites below — so the
        // post-setNick MONITOR transition must read this copy, not the alias.
        var old_buf: [64]u8 = undefined;
        const old_slice = conn.session.displayName();
        @memcpy(old_buf[0..old_slice.len], old_slice);
        const old = old_buf[0..old_slice.len];
        if (std.mem.eql(u8, old, newnick)) return; // no-op
        const wid = worldIdFromClient(id);

        // Reserve the new nick (frees the old mapping for this client).
        self.world.registerNick(newnick, wid) catch |err| switch (err) {
            error.NickInUse => {
                try queueNumeric(conn, .ERR_NICKNAMEINUSE, &.{newnick}, "Nickname is already in use");
                return;
            },
            else => return err,
        };

        // Build the NICK line with the OLD prefix before rewriting the session.
        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const old_prefix = try clientPrefix(conn, &prefix_buf);
        const msg = try formatMessage(&msg_buf, old_prefix, "NICK", &.{}, newnick);

        // Record the old identity, then rewrite the session nick.
        self.recordWhowas(conn);
        conn.session.setNick(newnick) catch {
            // Should not happen (already validated); leave registry consistent.
            return;
        };

        // Deliver to self + every common-channel member (dedup, except self once).
        try self.deliver(id, msg);
        try self.notifyCommonChannels(id, msg, null, id);

        // MONITOR: old nick went away, new nick appeared.
        self.monitorTransition(old, newnick) catch {};
    }

    /// MONITOR notify for a nick change: old offline, new online, WITHOUT
    /// dropping the client's own subscriptions (unlike a disconnect).
    fn monitorTransition(self: *LinuxServer, old: []const u8, new: []const u8) !void {
        var replies_buf: [64]monitor.MonitorReply = undefined;
        var storage: [default_reply_bytes]u8 = undefined;
        var sink = monitor.MonitorReplySink{ .replies = &replies_buf, .storage = &storage };
        self.monitor.setOffline(old, &sink) catch {};
        self.monitor.setOnline(new, &sink) catch {};
        try self.flushMonitorReplies(&sink);
    }

    /// AWAY [:message] — RFC 1459 / IRCv3 away-notify. A parameter sets the away
    /// message (RPL_NOWAWAY 306); a bare AWAY clears it (RPL_UNAWAY 305). When
    /// the away-notify cap is negotiated by peers, an `AWAY` state change is
    /// announced to all common-channel members.
    fn handleAway(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const reason: ?[]const u8 = if (parsed.param_count >= 1 and parsed.paramSlice()[0].len != 0)
            parsed.paramSlice()[0]
        else
            null;

        if (reason) |text| {
            conn.session.setAway(text);
            try queueNumeric(conn, .RPL_NOWAWAY, &.{}, "You have been marked as being away");
        } else {
            conn.session.clearAway();
            try queueNumeric(conn, .RPL_UNAWAY, &.{}, "You are no longer marked as being away");
        }

        // away-notify: announce to common-channel members who negotiated it.
        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const prefix = try clientPrefix(conn, &prefix_buf);
        const msg = try formatMessage(&msg_buf, prefix, "AWAY", &.{}, reason);
        try self.notifyCommonChannels(id, msg, .away_notify, id);
    }

    /// SETNAME :<realname> — IRCv3 setname. Updates the GECOS and echoes the
    /// change to the client and to setname-capable common-channel members.
    fn handleSetname(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"SETNAME"}, "Not enough parameters");
            return;
        }
        const newname = parsed.paramSlice()[0];
        conn.session.setRealname(newname) catch {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"SETNAME"}, "Realname too long");
            return;
        };

        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const prefix = try clientPrefix(conn, &prefix_buf);
        const msg = try formatMessage(&msg_buf, prefix, "SETNAME", &.{}, newname);
        try self.deliver(id, msg); // echo to self
        try self.notifyCommonChannels(id, msg, .setname, id);
    }

    /// OPER <name> <password> — elevate to IRC operator. Matches against the
    /// single configured oper block; success sets the session oper flag, emits
    /// RPL_YOUREOPER (381) and the +o umode reflection.
    fn handleOper(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 2) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"OPER"}, "Not enough parameters");
            return;
        }
        const name = parsed.paramSlice()[0];
        const pass = parsed.paramSlice()[1];
        if (!std.mem.eql(u8, name, self.oper_name) or !std.mem.eql(u8, pass, self.oper_pass)) {
            try queueNumeric(conn, .ERR_PASSWDMISMATCH, &.{}, "Password incorrect");
            return;
        }
        conn.session.is_oper = true;
        // Subscribe the new oper to all Event Spine categories — wallops, oper
        // notices, kills, etc. arrive as typed events (IRCX EVENT model).
        conn.session.setEventMask(event_spine.CategoryMask.all());
        try queueNumeric(conn, .RPL_YOUREOPER, &.{}, "You are now an IRC operator");
        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const prefix = try clientPrefix(conn, &prefix_buf);
        const nick = conn.session.displayName();
        const msg = try formatMessage(&msg_buf, prefix, "MODE", &.{ nick, "+o" }, null);
        try appendToConn(conn, msg);
    }

    /// WALLOPS :<message> — oper-only broadcast to every operator. Non-opers get
    /// ERR_NOPRIVILEGES (481).
    fn handleWallops(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"WALLOPS"}, "Not enough parameters");
            return;
        }
        // IRCX (ophion m_ircx_event.c): WALLOPS is merged into the EVENT
        // BROADCAST/announce category — an oper-visible typed event, not a +w
        // umode. Build the event with the sender as subject and deliver the
        // rendered `NOTE EVENT ANNOUNCE` to every announce-subscribed session.
        var subj_buf: [256]u8 = undefined;
        const subject = try clientPrefix(conn, &subj_buf);
        var msg_buf: [512]u8 = undefined;
        const message = std.fmt.bufPrint(&msg_buf, "{s}: {s}", .{ subject, parsed.paramSlice()[0] }) catch parsed.paramSlice()[0];
        const event = event_spine.Event{
            .category = .announce,
            .severity = .notice,
            .timestamp_ms = platform.realtimeMillis(),
            .message = message,
        };
        var line_buf: [default_reply_bytes]u8 = undefined;
        const line = event_spine.renderOperNote(.{ .server_name = server_name, .event = event }, &line_buf) catch return;
        var it = self.clients.iterator();
        while (it.next()) |entry| {
            if (entry.value.session.subscribesTo(.announce)) try self.deliver(entry.id, line);
        }
    }

    /// REHASH — oper-only configuration reload. The config store is static at
    /// present, so this acknowledges with RPL_REHASHING (382) without I/O.
    fn handleRehash(self: *LinuxServer, conn: *ConnState) !void {
        _ = self;
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        try queueNumeric(conn, .RPL_REHASHING, &.{"mizuchi.conf"}, "Rehashing");
    }

    /// INFO — RPL_INFO (371) lines bracketed by RPL_INFOSTART/RPL_ENDOFINFO.
    fn handleInfo(self: *LinuxServer, conn: *ConnState) !void {
        _ = self;
        const lines = [_][]const u8{
            "Mizuchi IRC daemon — a clean-room Zig-native successor to ophion.",
            "100% Zig, no C interop. Substrate + crypto + daemon.",
            "Mesh protocol: Suimyaku (CRDT) + Sazanami (gossip) + Goryu (membership).",
        };
        try queueNumeric(conn, .RPL_INFOSTART, &.{}, server_name);
        for (lines) |l| try queueNumeric(conn, .RPL_INFO, &.{}, l);
        try queueNumeric(conn, .RPL_ENDOFINFO, &.{}, "End of /INFO list");
    }

    /// USERS — local user listing (RPL_USERSSTART/RPL_USERS/RPL_ENDOFUSERS).
    fn handleUsers(self: *LinuxServer, conn: *ConnState) !void {
        try queueNumeric(conn, .RPL_USERSSTART, &.{}, "UserID   Terminal  Host");
        var any = false;
        var it = self.clients.iterator();
        while (it.next()) |entry| {
            if (!entry.value.session.registered()) continue;
            any = true;
            var line_buf: [128]u8 = undefined;
            const detail = std.fmt.bufPrint(&line_buf, "{s} {s} {s}", .{
                entry.value.session.username(),
                entry.value.session.displayName(),
                default_host,
            }) catch continue;
            try queueNumeric(conn, .RPL_USERS, &.{}, detail);
        }
        if (!any) try queueNumeric(conn, .RPL_NOUSERS, &.{}, "Nobody logged in");
        try queueNumeric(conn, .RPL_ENDOFUSERS, &.{}, "End of users");
    }

    /// LINKS — single-node mesh view: just this server (RPL_LINKS 364 /
    /// RPL_ENDOFLINKS 365). Reimagined for Suimyaku once S2S lands.
    fn handleLinks(self: *LinuxServer, conn: *ConnState) !void {
        _ = self;
        var line_buf: [128]u8 = undefined;
        const detail = std.fmt.bufPrint(&line_buf, "0 {s}", .{"Mizuchi IRC daemon"}) catch return;
        try queueNumeric(conn, .RPL_LINKS, &.{ server_name, server_name }, detail);
        try queueNumeric(conn, .RPL_ENDOFLINKS, &.{"*"}, "End of /LINKS list");
    }

    /// MAP — network topology. Single node today (RPL_MAP 015 / RPL_MAPEND 017).
    fn handleMap(self: *LinuxServer, conn: *ConnState) !void {
        var line_buf: [160]u8 = undefined;
        const detail = std.fmt.bufPrint(&line_buf, "{s} [Users: {d}]", .{
            server_name,
            self.clients.len(),
        }) catch return;
        try queueNumeric(conn, .RPL_MAP, &.{}, detail);
        try queueNumeric(conn, .RPL_MAPEND, &.{}, "End of /MAP");
    }

    /// Fan a pre-built message out to every member of every channel `id` shares,
    /// optionally gated on a negotiated capability, skipping `except`. Each
    /// recipient is delivered at most once even across multiple shared channels.
    fn notifyCommonChannels(
        self: *LinuxServer,
        id: client_model.ClientId,
        msg: []const u8,
        cap: ?dispatch.CapId,
        except: client_model.ClientId,
    ) !void {
        var seen = std.AutoHashMap(u64, void).init(self.allocator);
        defer seen.deinit();
        var it = self.world.channels.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.members.contains(worldIdFromClient(id))) continue;
            var members = self.world.memberIterator(entry.key_ptr.*) orelse continue;
            while (members.next()) |member| {
                const mid = clientIdFromWorld(member.*);
                if (mid.eql(except)) continue;
                const key = @as(u64, @bitCast(mid));
                if (seen.contains(key)) continue;
                seen.put(key, {}) catch {};
                const mconn = self.clients.get(mid) orelse continue;
                if (cap) |c| {
                    if (!mconn.session.hasCap(c)) continue;
                }
                try self.deliver(mid, msg);
            }
        }
    }

    /// TAGMSG <target> — IRCv3 message-tags: relay the sender's client tags (no
    /// text body) to recipients that negotiated message-tags. A TAGMSG carrying
    /// no tags is a no-op. Delivered untagged-by-server (the client `@tags`
    /// segment is the whole tag set) — server-time-in-tags is a future merge.
    fn handleTagmsg(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) return;
        const tags = parsed.tags_raw orelse return; // nothing to relay
        const target = parsed.paramSlice()[0];

        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "@{s} :{s} TAGMSG {s}\r\n", .{
            tags, try clientPrefix(conn, &prefix_buf), target,
        }) catch return error.OutputTooSmall;
        const echo = conn.session.hasCap(.echo_message);

        if (world_model.isChannelName(target)) {
            if (!self.world.channelExists(target)) return;
            if (!self.world.isMember(target, worldIdFromClient(id))) return;
            var members = self.world.memberIterator(target) orelse return;
            while (members.next()) |member| {
                const mid = clientIdFromWorld(member.*);
                if (mid.eql(id) and !echo) continue;
                const mconn = self.clients.get(mid) orelse continue;
                if (!mconn.session.hasCap(.message_tags)) continue;
                try self.deliver(mid, msg);
            }
            return;
        }
        const recipient = self.world.findNick(target) orelse return;
        const rconn = self.clients.get(clientIdFromWorld(recipient)) orelse return;
        if (rconn.session.hasCap(.message_tags)) try self.deliver(clientIdFromWorld(recipient), msg);
        if (echo) try self.deliver(id, msg);
    }

    fn handleMessage(
        self: *LinuxServer,
        id: client_model.ClientId,
        conn: *ConnState,
        parsed: *const irc_line.LineView,
        command: []const u8,
    ) !void {
        if (parsed.param_count < 2 or parsed.paramSlice()[1].len == 0) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{command}, "Not enough parameters");
            return;
        }
        const text = parsed.paramSlice()[1];
        // `PRIVMSG a,#b,c :text`: deliver to each comma-separated target.
        var targets = std.mem.splitScalar(u8, parsed.paramSlice()[0], ',');
        while (targets.next()) |target| {
            if (target.len == 0) continue;
            try self.messageOne(id, conn, command, target, text);
        }
    }

    fn messageOne(
        self: *LinuxServer,
        id: client_model.ClientId,
        conn: *ConnState,
        command: []const u8,
        target: []const u8,
        text: []const u8,
    ) !void {
        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const msg = try formatMessage(&msg_buf, try clientPrefix(conn, &prefix_buf), command, &.{target}, text);

        // IRCv3 echo-message: a sender that negotiated the cap also receives its
        // own message back, byte-identical to what recipients see (`msg`).
        const echo = conn.session.hasCap(.echo_message);

        // RFC 1459 / ophion m_message.c: NOTICE must NEVER generate an error
        // reply (prevents NOTICE/error ping-pong between bots and servers). All
        // delivery-failure numerics below are suppressed for NOTICE.
        const is_notice = std.ascii.eqlIgnoreCase(command, "NOTICE");

        // STATUSMSG: a leading prefix (~/./@/+) before a channel name restricts
        // delivery to members of that rank or higher. `chan` is the bare channel
        // for world lookups; `target` keeps the prefix for the displayed line.
        var chan = target;
        var min_rank: u8 = 0;
        if (target.len >= 2) {
            const r = statusPrefixRank(target[0]);
            if (r > 0 and world_model.isChannelName(target[1..])) {
                min_rank = r;
                chan = target[1..];
            }
        }

        if (world_model.isChannelName(chan)) {
            if (!self.world.channelExists(chan)) {
                if (!is_notice) try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{target}, "No such channel");
                return;
            }
            // +n no-external-messages: a non-member may message the channel only
            // when +n is unset (RFC 1459). Members always pass this gate.
            if (!self.world.isMember(chan, worldIdFromClient(id)) and
                self.world.channelHasFlag(chan, .no_external))
            {
                if (!is_notice) try queueNumeric(conn, .ERR_CANNOTSENDTOCHAN, &.{target}, "Cannot send to channel (+n)");
                return;
            }
            // +m moderated: only voiced (+v) or any operator tier may speak.
            if (self.world.channelHasFlag(chan, .moderated)) {
                const mm = self.world.memberModes(chan, worldIdFromClient(id)) orelse world_model.MemberModes.empty();
                if (!mm.canSpeakModerated()) {
                    if (!is_notice) try queueNumeric(conn, .ERR_CANNOTSENDTOCHAN, &.{target}, "Cannot send to channel (+m)");
                    return;
                }
            }
            // STATUSMSG sender gate (ophion m_message.c: is_chanop_voiced): only a
            // member who is voiced-or-higher may send to a status-prefixed target.
            if (min_rank > 0) {
                const sm = self.world.memberModes(chan, worldIdFromClient(id)) orelse world_model.MemberModes.empty();
                if (sm.rank() < 1) {
                    if (!is_notice) try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{target}, "You're not channel operator");
                    return;
                }
            }
            var time_buf: [40]u8 = undefined;
            const ctags = MsgTags{ .time_value = serverTimeValue(&time_buf), .account = conn.session.account() };
            if (min_rank == 0) {
                try self.broadcastChannelTagged(chan, ctags, msg, id);
            } else {
                try self.broadcastChannelMinRank(chan, ctags, msg, id, min_rank);
            }
            if (echo) try self.deliverTagged(id, ctags, msg);
            return;
        }

        const recipient = self.world.findNick(target) orelse {
            if (!is_notice) try queueNumeric(conn, .ERR_NOSUCHNICK, &.{target}, "No such nick");
            return;
        };
        var time_buf: [40]u8 = undefined;
        const dtags = MsgTags{ .time_value = serverTimeValue(&time_buf), .account = conn.session.account() };
        try self.deliverTagged(clientIdFromWorld(recipient), dtags, msg);
        if (echo) try self.deliverTagged(id, dtags, msg);

        // RFC 1459: a PRIVMSG (not NOTICE) to an away user returns RPL_AWAY so
        // the sender sees the auto-reply. NOTICE never auto-responds.
        if (std.ascii.eqlIgnoreCase(command, "PRIVMSG")) {
            if (self.clients.get(clientIdFromWorld(recipient))) |rconn| {
                if (rconn.session.awayMessage()) |reason| {
                    try queueNumeric(conn, .RPL_AWAY, &.{target}, reason);
                }
            }
        }
    }

    fn handleTopic(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"TOPIC"}, "Not enough parameters");
            return;
        }

        const channel = parsed.paramSlice()[0];
        if (!self.world.channelExists(channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{channel}, "No such channel");
            return;
        }

        if (parsed.param_count == 1) {
            try self.sendTopicReply(conn, channel);
            return;
        }

        const topic_setter = self.world.memberModes(channel, worldIdFromClient(id)) orelse {
            try queueNumeric(conn, .ERR_NOTONCHANNEL, &.{channel}, "You're not on that channel");
            return;
        };
        // +t: only channel operators (op or higher) may change the topic.
        if (self.world.channelHasFlag(channel, .topic_ops) and !topic_setter.isOperator()) {
            try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{channel}, "You're not channel operator");
            return;
        }

        const text = parsed.paramSlice()[1];
        try self.world.setTopic(channel, text);

        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const msg = try formatMessage(&msg_buf, try clientPrefix(conn, &prefix_buf), "TOPIC", &.{channel}, text);
        try self.broadcastChannel(channel, msg, null);
    }

    fn handleQuit(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const reason = if (parsed.param_count >= 1) parsed.paramSlice()[0] else "Client quit";
        self.recordWhowas(conn); // before removeClient: snapshot the live identity
        try self.broadcastQuit(id, conn, reason);
        self.world.removeClient(worldIdFromClient(id));
        conn.closing = true;
    }

    fn sendTopicReply(self: *LinuxServer, conn: *ConnState, channel: []const u8) !void {
        if (conn.session.registered()) {
            if (self.world.topic(channel)) |text| {
                try queueNumeric(conn, .RPL_TOPIC, &.{channel}, text);
            } else {
                try queueNumeric(conn, .RPL_NOTOPIC, &.{channel}, "No topic is set");
            }
        }
    }

    /// RPL_BANLIST (367) for each +b mask, terminated by RPL_ENDOFBANLIST (368).
    fn sendBanList(self: *LinuxServer, conn: *ConnState, channel: []const u8) !void {
        try self.sendMaskList(conn, channel, self.world.bansOf(channel), .RPL_BANLIST, .RPL_ENDOFBANLIST, "End of channel ban list");
    }

    /// Emit a channel mask list (one `list_code` per mask, then `end_code`).
    /// Shared by +b (367/368), +e (348/349), +I (346/347).
    fn sendMaskList(
        self: *LinuxServer,
        conn: *ConnState,
        channel: []const u8,
        masks: ?[]const []const u8,
        list_code: Numeric,
        end_code: Numeric,
        end_text: []const u8,
    ) !void {
        _ = self;
        if (masks) |entries| {
            for (entries) |mask| {
                try queueNumeric(conn, list_code, &.{ channel, mask }, "");
            }
        }
        try queueNumeric(conn, end_code, &.{channel}, end_text);
    }

    fn sendNames(self: *LinuxServer, conn: *ConnState, channel: []const u8) !void {
        // Render NAMES via the names_reply module: each member carries its status
        // prefixes (all of them when the requester negotiated multi-prefix, else
        // only the highest) and optionally nick!user@host (userhost-in-names).
        const max_members: usize = 128;
        var members_buf: [max_members]names_reply.Member = undefined;
        var prefix_buf: [max_members]chanmode.PrefixList = undefined;
        var count: usize = 0;

        var it = self.world.memberIterator(channel) orelse return error.NoSuchChannel;
        while (it.next()) |member| {
            if (count >= max_members) break;
            const nick = self.world.nickOf(member.*) orelse continue;
            const modes = self.world.memberModes(channel, member.*) orelse world_model.MemberModes.empty();
            prefix_buf[count] = modes.allPrefixes();
            members_buf[count] = .{
                .prefixes = prefix_buf[count].asSlice(),
                .nick = nick,
                .user = usernameOf(self, member.*),
                .host = default_host,
            };
            count += 1;
        }

        const caps = names_reply.RequesterCaps{
            .multi_prefix = conn.session.hasCap(.multi_prefix),
            .userhost_in_names = conn.session.hasCap(.userhost_in_names),
        };

        var out_buf: [default_reply_bytes]u8 = undefined;
        var lines_buf: [32]names_reply.NamesLine = undefined;
        var sink = names_reply.NamesLineSink{ .lines = &lines_buf };
        // 353 visibility symbol: '@' for secret (+s), '=' otherwise.
        const channel_status: u8 = if (self.world.channelHasFlag(channel, .secret)) '@' else '=';
        names_reply.writeNamesReplies(&out_buf, server_name, conn.session.displayName(), channel, channel_status, members_buf[0..count], caps, &sink) catch {
            // Oversized channel for this single pass: still close the list out.
            try queueNumeric(conn, .RPL_ENDOFNAMES, &.{channel}, "End of /NAMES list");
            return;
        };
        for (sink.slice()) |line| {
            try appendToConn(conn, line.bytes);
            try appendToConn(conn, "\r\n");
        }
    }
};

/// Public entry point. `LinuxServer` is the io_uring fast path; other targets
/// get a stub whose `init` fails closed until a portable poll/kqueue backend
/// lands (CROSS-PLATFORM MANDATE). main() already falls back to the DST boot
/// banner when `init` returns error.Unsupported, so the daemon still links and
/// runs its non-socket paths on macOS/BSD/Windows.
pub const Server = if (builtin.os.tag == .linux) LinuxServer else PortableServer;

const PortableServer = struct {
    pub fn init(_: std.mem.Allocator, _: Config) ServerError!PortableServer {
        return error.Unsupported;
    }
    pub fn deinit(_: *PortableServer) void {}
    pub fn boundPort(_: *PortableServer) ServerError!u16 {
        return error.Unsupported;
    }
    pub fn runOnce(_: *PortableServer) ServerError!void {
        return error.Unsupported;
    }
    /// Symbol parity with LinuxServer so the threaded end-to-end tests compile on
    /// non-Linux targets. Never reached: `init` returns Unsupported first, so the
    /// tests SkipZigTest before any thread is spawned.
    pub fn runThreaded(_: *PortableServer, _: *std.atomic.Value(bool)) void {}
};

const CompletionHandler = struct {
    server: *LinuxServer,
    err: ?anyerror = null,

    fn onCompletion(self: *CompletionHandler, completion: ringlane.Completion) void {
        if (self.err != null) return;
        switch (completion) {
            .accept => |event| self.server.handleAccept(event) catch |err| {
                self.err = err;
            },
            .recv => |event| self.server.handleRecv(event) catch |err| {
                self.err = err;
            },
            .send => |event| self.server.handleSend(event) catch |err| {
                self.err = err;
            },
            .timeout, .other => {},
        }
    }
};

fn tokenFromId(id: client_model.ClientId) ServerError!RingFdToken {
    if (id.gen > ((@as(u32, 1) << 28) - 1)) return error.TokenOutOfRange;
    return .{ .slot = id.slot, .gen = id.gen };
}

fn idFromToken(token: RingFdToken) client_model.ClientId {
    return .{ .shard = 0, .slot = @intCast(token.slot), .gen = token.gen };
}

fn worldIdFromClient(id: client_model.ClientId) world_model.ClientId {
    return .{ .shard = id.shard, .slot = id.slot, .gen = id.gen };
}

/// The USER-supplied username of the member behind a world client id, or "user".
fn usernameOf(self: *LinuxServer, world_id: world_model.ClientId) []const u8 {
    if (self.clients.get(clientIdFromWorld(world_id))) |c| return c.session.username();
    return "user";
}

fn clientIdFromWorld(id: world_model.ClientId) client_model.ClientId {
    return .{ .shard = id.shard, .slot = id.slot, .gen = id.gen };
}

/// MonitorStore keys clients by a flat u64; convert to/from the packed ClientId.
fn monitorIdFromClient(id: client_model.ClientId) u64 {
    return @bitCast(id);
}

fn clientIdFromMonitor(id: u64) client_model.ClientId {
    return @bitCast(id);
}

/// Map a MonitorStore numeric to the live server's numeric enum.
fn monitorNumeric(n: monitor.MonitorNumeric) Numeric {
    return switch (n) {
        .RPL_MONONLINE => .RPL_MONONLINE,
        .RPL_MONOFFLINE => .RPL_MONOFFLINE,
        .RPL_MONLIST => .RPL_MONLIST,
        .RPL_ENDOFMONLIST => .RPL_ENDOFMONLIST,
        .ERR_MONLISTFULL => .ERR_MONLISTFULL,
    };
}

const Buf = struct {
    storage: []u8,
    len: usize = 0,

    fn append(self: *Buf, bytes: []const u8) ServerError!void {
        if (self.len + bytes.len > self.storage.len) return error.OutputTooSmall;
        @memcpy(self.storage[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *Buf, byte: u8) ServerError!void {
        if (self.len == self.storage.len) return error.OutputTooSmall;
        self.storage[self.len] = byte;
        self.len += 1;
    }

    fn written(self: *const Buf) []const u8 {
        return self.storage[0..self.len];
    }
};

fn appendToConn(conn: *ConnState, bytes: []const u8) ServerError!void {
    if (conn.send_len + bytes.len > conn.send_buf.len) return error.OutputTooSmall;
    @memcpy(conn.send_buf[conn.send_len .. conn.send_len + bytes.len], bytes);
    conn.send_len += bytes.len;
}

fn queueNumeric(
    conn: *ConnState,
    code: Numeric,
    params: []const []const u8,
    trailing: []const u8,
) ServerError!void {
    var line_buf: [default_reply_bytes]u8 = undefined;
    var out = Buf{ .storage = &line_buf };
    var code_buf: [3]u8 = undefined;

    try out.appendByte(':');
    try out.append(server_name);
    try out.appendByte(' ');
    try out.append(formatNumericCode(code, &code_buf));
    try out.appendByte(' ');
    try out.append(conn.session.displayName());
    for (params) |param| {
        try out.appendByte(' ');
        try out.append(param);
    }
    try out.append(" :");
    try out.append(trailing);
    try out.append("\r\n");

    try appendToConn(conn, out.written());
}

/// Append a parameterised mode change (`+k key`, `+l 50`, `+b mask`) to the
/// MODE echo accumulators: the letter goes into `applied` (with a sign flip when
/// the run direction changes), the value into `targets` as ` <param>`. Buffers
/// are generously sized; appends soft-fail rather than fault.
fn appendParamMode(applied: *Buf, targets: *Buf, emitted_sign: *u8, sign: u8, letter: u8, param: []const u8) void {
    appendModeLetter(applied, emitted_sign, sign, letter);
    targets.appendByte(' ') catch return;
    targets.append(param) catch return;
}

/// Append a bare mode letter (`-l`, `-k *`) to the MODE echo, flipping the sign
/// prefix when the run direction changes.
fn appendModeLetter(applied: *Buf, emitted_sign: *u8, sign: u8, letter: u8) void {
    if (emitted_sign.* != sign) {
        applied.appendByte(sign) catch return;
        emitted_sign.* = sign;
    }
    applied.appendByte(letter) catch return;
}

fn formatMessage(
    out_storage: []u8,
    prefix: []const u8,
    command: []const u8,
    params: []const []const u8,
    trailing: ?[]const u8,
) ServerError![]const u8 {
    var out = Buf{ .storage = out_storage };
    try out.appendByte(':');
    try out.append(prefix);
    try out.appendByte(' ');
    try out.append(command);
    for (params) |param| {
        try out.appendByte(' ');
        try out.append(param);
    }
    if (trailing) |text| {
        try out.append(" :");
        try out.append(text);
    }
    try out.append("\r\n");
    return out.written();
}

/// RFC-ish nick validation: 1..64 bytes, no space/comma/'*'/'?'/'!'/'@'/'.' and
/// not a channel-name lead char; first char not a digit or '-'.
fn isValidNick(nick: []const u8) bool {
    if (nick.len == 0 or nick.len > 64) return false;
    if (nick[0] == '-' or (nick[0] >= '0' and nick[0] <= '9')) return false;
    for (nick) |ch| {
        switch (ch) {
            ' ', ',', '*', '?', '!', '@', '.', '#', '&', '+', '~' => return false,
            else => if (ch <= 32) return false,
        }
    }
    return true;
}

/// STATUSMSG prefix -> minimum member rank (founder 4 > owner 3 > op 2 > voice
/// 1). 0 means the char is not a status prefix.
fn statusPrefixRank(ch: u8) u8 {
    return switch (ch) {
        '~' => 4,
        '.' => 3,
        '@' => 2,
        '+' => 1,
        else => 0,
    };
}

fn clientPrefix(conn: *const ConnState, storage: []u8) ServerError![]const u8 {
    return std.fmt.bufPrint(storage, "{s}!{s}@{s}", .{
        conn.session.displayName(),
        conn.session.username(),
        default_host,
    }) catch return error.OutputTooSmall;
}

fn createListener(host: []const u8, port: u16, backlog: u31) ServerError!linux.fd_t {
    const fd = try socketTcp();
    errdefer closeFd(fd);

    var yes: u32 = 1;
    try setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes));

    var addr = try sockaddrIn(host, port);
    try bindSocket(fd, &addr);
    try listenSocket(fd, backlog);
    return fd;
}

fn sockaddrIn(host: []const u8, port: u16) ServerError!posix.sockaddr.in {
    const parsed = std.Io.net.Ip4Address.parse(host, port) catch return error.InvalidAddress;
    return .{
        .port = std.mem.nativeToBig(u16, parsed.port),
        .addr = @bitCast(parsed.bytes),
    };
}

fn socketTcp() ServerError!linux.fd_t {
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES, .PERM => return error.PermissionDenied,
        .MFILE, .NFILE, .NOBUFS, .NOMEM => return error.SocketUnavailable,
        else => return error.Unexpected,
    }
}

fn bindSocket(fd: linux.fd_t, addr: *const posix.sockaddr.in) ServerError!void {
    const ptr: *const posix.sockaddr = @ptrCast(addr);
    const rc = linux.bind(fd, ptr, @sizeOf(posix.sockaddr.in));
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.PermissionDenied,
        .ADDRINUSE => return error.AddressInUse,
        else => return error.Unexpected,
    }
}

fn listenSocket(fd: linux.fd_t, backlog: u31) ServerError!void {
    const rc = linux.listen(fd, backlog);
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ADDRINUSE => return error.AddressInUse,
        .ACCES, .PERM => return error.PermissionDenied,
        else => return error.Unexpected,
    }
}

fn setsockopt(fd: linux.fd_t, level: i32, optname: u32, opt: []const u8) ServerError!void {
    const rc = linux.setsockopt(fd, level, optname, opt.ptr, @intCast(opt.len));
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.PermissionDenied,
        else => return error.Unexpected,
    }
}

fn socketPort(fd: linux.fd_t) ServerError!u16 {
    var storage: posix.sockaddr.storage = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    const rc = linux.getsockname(fd, @ptrCast(&storage), &len);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.Unexpected,
    }
    const addr: *const posix.sockaddr.in = @ptrCast(@alignCast(&storage));
    return std.mem.bigToNative(u16, addr.port);
}

fn connectLoopback(port: u16) ServerError!linux.fd_t {
    const fd = try socketTcp();
    errdefer closeFd(fd);
    var addr = try sockaddrIn("127.0.0.1", port);
    const rc = linux.connect(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
    switch (posix.errno(rc)) {
        .SUCCESS => return fd,
        .CONNREFUSED => return error.ConnectionRefused,
        .ACCES, .PERM => return error.PermissionDenied,
        else => return error.Unexpected,
    }
}

fn writeAllFd(fd: linux.fd_t, bytes: []const u8) ServerError!void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = linux.write(fd, bytes[sent..].ptr, bytes.len - sent);
        switch (posix.errno(rc)) {
            .SUCCESS => sent += @intCast(rc),
            .CONNRESET => return error.ConnectionReset,
            else => return error.Unexpected,
        }
    }
}

fn readFd(fd: linux.fd_t, buf: []u8) ServerError!usize {
    const n = posix.read(fd, buf) catch |err| switch (err) {
        error.ConnectionResetByPeer => return error.ConnectionReset,
        error.WouldBlock => return error.Unexpected,
        else => return error.Unexpected,
    };
    return n;
}

fn closeFd(fd: linux.fd_t) void {
    _ = linux.close(fd);
}

const TestSink = struct {
    storage: []u8,
    used: usize = 0,

    fn write(self: *TestSink, bytes: []const u8) ServerError!void {
        if (self.used + bytes.len > self.storage.len) return error.OutputTooSmall;
        @memcpy(self.storage[self.used .. self.used + bytes.len], bytes);
        self.used += bytes.len;
    }

    fn written(self: *const TestSink) []const u8 {
        return self.storage[0..self.used];
    }
};

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) != null);
}

fn expectCodesInOrder(haystack: []const u8, codes: []const []const u8) !void {
    var pos: usize = 0;
    for (codes) |code| {
        const found = std.mem.indexOfPos(u8, haystack, pos, code) orelse return error.TestExpectedEqual;
        pos = found + code.len;
    }
}

const LiveClient = struct {
    fd: linux.fd_t,
    buf: [default_reply_bytes]u8 = undefined,
    len: usize = 0,

    fn readAvailable(self: *LiveClient) ServerError!void {
        while (true) {
            var fds = [_]posix.pollfd{.{
                .fd = self.fd,
                .events = linux.POLL.IN,
                .revents = 0,
            }};
            const ready = posix.poll(&fds, 0) catch return error.Unexpected;
            if (ready == 0 or (fds[0].revents & linux.POLL.IN) == 0) return;
            if (self.len == self.buf.len) return error.OutputTooSmall;
            const n = try readFd(self.fd, self.buf[self.len..]);
            if (n == 0) return;
            self.len += n;
        }
    }

    fn written(self: *const LiveClient) []const u8 {
        return self.buf[0..self.len];
    }

    fn reset(self: *LiveClient) void {
        self.len = 0;
    }
};

test "processLine answers PING with bare PONG token" {
    const allocator = std.testing.allocator;
    _ = allocator;

    var conn = ConnState.init(-1);
    var storage: [128]u8 = undefined;
    var sink = TestSink{ .storage = &storage };

    try processLine(&conn, "PING :abc", &sink);
    try std.testing.expectEqualStrings("PONG :abc\r\n", sink.written());
}

test "processLine registration sequence emits welcome numerics" {
    const allocator = std.testing.allocator;
    _ = allocator;

    var conn = ConnState.init(-1);
    var storage: [4096]u8 = undefined;
    var sink = TestSink{ .storage = &storage };

    try processLine(&conn, "NICK kain", &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.written().len);
    try processLine(&conn, "USER kain 0 * :Kain Mizuchi", &sink);

    try std.testing.expect(conn.session.registered());
    try expectCodesInOrder(sink.written(), &.{ " 001 ", " 002 ", " 003 ", " 004 ", " 005 " });
    try expectContains(sink.written(), "Welcome to the Mizuchi IRC Network");
}

test "processLine rejects malformed input without writing" {
    var conn = ConnState.init(-1);
    var storage: [128]u8 = undefined;
    var sink = TestSink{ .storage = &storage };

    try std.testing.expectError(error.EmbeddedLineBreak, processLine(&conn, "PING :abc\nWHOIS kain", &sink));
    try std.testing.expectEqual(@as(usize, 0), sink.written().len);
}

/// Blocking read with a bounded poll budget (so a misbehaving server fails the
/// test instead of hanging). Accumulates into `client` and returns when `needle`
/// is present, or errors after ~3s.
fn recvUntil(client: *LiveClient, needle: []const u8, max_polls: usize) !void {
    var polls: usize = 0;
    while (polls < max_polls) : (polls += 1) {
        if (std.mem.indexOf(u8, client.written(), needle) != null) return;
        var fds = [_]posix.pollfd{.{ .fd = client.fd, .events = linux.POLL.IN, .revents = 0 }};
        const ready = posix.poll(&fds, 25) catch return error.Unexpected;
        if (ready == 0) continue;
        if ((fds[0].revents & linux.POLL.IN) == 0) continue;
        if (client.len == client.buf.len) return error.OutputTooSmall;
        const n = try readFd(client.fd, client.buf[client.len..]);
        if (n == 0) return error.ConnectionReset;
        client.len += n;
    }
    return error.TestTimeout;
}

test "threaded server: real end-to-end registration, JOIN, PRIVMSG (T1)" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    // Reactor on its own thread; the test thread is a real loopback client.
    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    // Shutdown that can't hang: clear the flag, then a throwaway connection wakes
    // the reactor (accept completion) so it observes the flag, then join.
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch |err| switch (err) {
        error.PermissionDenied, error.SocketUnavailable, error.ConnectionRefused => return error.SkipZigTest,
        else => return err,
    };
    defer closeFd(fd_a);
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);

    var a = LiveClient{ .fd = fd_a };
    var b = LiveClient{ .fd = fd_b };

    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try recvUntil(&b, " 001 B ", 200);

    a.reset();
    try writeAllFd(fd_a, "JOIN #x\r\n");
    try recvUntil(&a, " 366 A #x ", 200);
    try writeAllFd(fd_b, "JOIN #x\r\n");

    b.reset();
    try writeAllFd(fd_a, "PRIVMSG #x :hi\r\n");
    // Real username (alice) now flows through (not the old "user" placeholder).
    try recvUntil(&b, ":A!alice@localhost PRIVMSG #x :hi\r\n", 200);
}

test "threaded server: founder/MODE/KICK/NAMES/WHOIS/LIST/WHO/ISON/LUSERS end-to-end" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);
    var a = LiveClient{ .fd = fd_a };
    var b = LiveClient{ .fd = fd_b };

    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try recvUntil(&b, " 001 B ", 200);

    // A founds #x -> A is FOUNDER (~). B joins -> no status.
    a.reset();
    try writeAllFd(fd_a, "JOIN #x\r\n");
    try recvUntil(&a, " 353 ", 200); // NAMES
    try recvUntil(&a, "~A", 200); // founder prefix on A
    try writeAllFd(fd_b, "JOIN #x\r\n");
    try recvUntil(&b, " 366 B #x ", 200);

    // Founder ops B: MODE #x +o B -> broadcast +o.
    a.reset();
    try writeAllFd(fd_a, "MODE #x +o B\r\n");
    try recvUntil(&a, "MODE #x +o B", 200);

    // A KICKs B (founder outranks op).
    a.reset();
    try writeAllFd(fd_a, "KICK #x B :bye\r\n");
    try recvUntil(&a, "KICK #x B :bye", 200);

    // WHOIS A -> 311 user line + 318 end.
    a.reset();
    try writeAllFd(fd_a, "WHOIS A\r\n");
    try recvUntil(&a, " 311 A A alice ", 200);
    try recvUntil(&a, " 318 A A ", 200);

    // LIST -> #x present (322).
    a.reset();
    try writeAllFd(fd_a, "LIST\r\n");
    try recvUntil(&a, " 322 A #x ", 200);

    // WHO #x -> 352 + 315 end.
    a.reset();
    try writeAllFd(fd_a, "WHO #x\r\n");
    try recvUntil(&a, " 315 A #x ", 200);

    // ISON A B -> 303 lists A (B parted via kick but reconnect-less; A online).
    a.reset();
    try writeAllFd(fd_a, "ISON A B\r\n");
    try recvUntil(&a, " 303 A :", 200);

    // LUSERS -> 251, VERSION -> 351.
    a.reset();
    try writeAllFd(fd_a, "LUSERS\r\n");
    try recvUntil(&a, " 251 A ", 200);
    a.reset();
    try writeAllFd(fd_a, "VERSION\r\n");
    try recvUntil(&a, " 351 A ", 200);
    a.reset();
    try writeAllFd(fd_a, "TIME\r\n");
    try recvUntil(&a, " 391 A ", 200);
    a.reset();
    try writeAllFd(fd_a, "ADMIN\r\n");
    try recvUntil(&a, " 256 A ", 200);
}

test "threaded server: AWAY/SETNAME/OPER/WALLOPS/INFO/USERS/LINKS/MAP end-to-end" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);
    var a = LiveClient{ .fd = fd_a };
    var b = LiveClient{ .fd = fd_b };

    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try recvUntil(&b, " 001 B ", 200);

    // B marks away -> 306; A PRIVMSGs B -> A sees RPL_AWAY (301).
    b.reset();
    try writeAllFd(fd_b, "AWAY :lunch\r\n");
    try recvUntil(&b, " 306 B ", 200);
    a.reset();
    try writeAllFd(fd_a, "PRIVMSG B :hey\r\n");
    try recvUntil(&a, " 301 A B :lunch\r\n", 200);
    // B returns -> 305.
    b.reset();
    try writeAllFd(fd_b, "AWAY\r\n");
    try recvUntil(&b, " 305 B ", 200);

    // SETNAME echoes back to the sender.
    a.reset();
    try writeAllFd(fd_a, "SETNAME :Alice Liddell\r\n");
    try recvUntil(&a, "SETNAME :Alice Liddell\r\n", 200);

    // Non-oper WALLOPS -> 481; OPER with good creds -> 381; then WALLOPS reaches self.
    a.reset();
    try writeAllFd(fd_a, "WALLOPS :nope\r\n");
    try recvUntil(&a, " 481 A ", 200);
    a.reset();
    try writeAllFd(fd_a, "OPER admin mizuchi\r\n");
    try recvUntil(&a, " 381 A ", 200);
    // WHOIS now shows the operator line (313).
    a.reset();
    try writeAllFd(fd_a, "WHOIS A\r\n");
    try recvUntil(&a, " 313 A A ", 200);
    a.reset();
    // WALLOPS is delivered as an oper-visible Event Spine announce: the oper A
    // (subscribed on OPER) receives a NOTE EVENT ANNOUNCE carrying the message.
    try writeAllFd(fd_a, "WALLOPS :hello opers\r\n");
    try recvUntil(&a, "NOTE EVENT ANNOUNCE :", 200);
    try recvUntil(&a, "hello opers", 200);
    // REHASH now permitted (382).
    a.reset();
    try writeAllFd(fd_a, "REHASH\r\n");
    try recvUntil(&a, " 382 A ", 200);

    // INFO (371), USERS (392), LINKS (364), MAP (015).
    a.reset();
    try writeAllFd(fd_a, "INFO\r\n");
    try recvUntil(&a, " 371 A ", 200);
    a.reset();
    try writeAllFd(fd_a, "USERS\r\n");
    try recvUntil(&a, " 392 A ", 200);
    a.reset();
    try writeAllFd(fd_a, "LINKS\r\n");
    try recvUntil(&a, " 364 A ", 200);
    a.reset();
    try writeAllFd(fd_a, "MAP\r\n");
    try recvUntil(&a, " 015 A ", 200);
    // STATS u -> uptime (242) + end (219).
    a.reset();
    try writeAllFd(fd_a, "STATS u\r\n");
    try recvUntil(&a, " 242 A ", 200);
    try recvUntil(&a, " 219 A u ", 200);

    // Bot mode: B sets +B on itself -> MODE echo; WHOIS B shows 335.
    b.reset();
    try writeAllFd(fd_b, "MODE B +B\r\n");
    try recvUntil(&b, "MODE B +B", 200);
    a.reset();
    try writeAllFd(fd_a, "WHOIS B\r\n");
    try recvUntil(&a, " 335 A B ", 200);

    // KILL: oper A kills B -> B receives a KILL line then is disconnected.
    b.reset();
    try writeAllFd(fd_a, "KILL B :spam\r\n");
    try recvUntil(&b, "KILL B :spam\r\n", 200);
}

test "threaded server: channel-mode enforcement +k/+l/+b/+i end-to-end" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);
    var a = LiveClient{ .fd = fd_a };
    var b = LiveClient{ .fd = fd_b };

    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try recvUntil(&b, " 001 B ", 200);

    // A founds #c, then sets a key.
    a.reset();
    try writeAllFd(fd_a, "JOIN #c\r\n");
    try recvUntil(&a, " 366 A #c ", 200);
    a.reset();
    try writeAllFd(fd_a, "MODE #c +k sesame\r\n");
    try recvUntil(&a, "MODE #c +k sesame", 200);

    // B joins without key -> 475; with the right key -> success.
    b.reset();
    try writeAllFd(fd_b, "JOIN #c\r\n");
    try recvUntil(&b, " 475 B #c ", 200);
    b.reset();
    try writeAllFd(fd_b, "JOIN #c sesame\r\n");
    try recvUntil(&b, " 366 B #c ", 200);

    // +l limit: A founds #l, sets +l 1 (A is the only member) -> B is full out.
    a.reset();
    try writeAllFd(fd_a, "JOIN #l\r\n");
    try recvUntil(&a, " 366 A #l ", 200);
    a.reset();
    try writeAllFd(fd_a, "MODE #l +l 1\r\n");
    try recvUntil(&a, "MODE #l +l 1", 200);
    b.reset();
    try writeAllFd(fd_b, "JOIN #l\r\n");
    try recvUntil(&b, " 471 B #l ", 200);

    // +b ban: A bans B, B parts and is refused re-entry (474, even with key).
    a.reset();
    try writeAllFd(fd_a, "MODE #c +b B!*@*\r\n");
    try recvUntil(&a, "MODE #c +b B!*@*", 200);
    b.reset();
    try writeAllFd(fd_b, "PART #c\r\n");
    try recvUntil(&b, "PART #c", 200);
    b.reset();
    try writeAllFd(fd_b, "JOIN #c sesame\r\n");
    try recvUntil(&b, " 474 B #c ", 200);

    // INVITE lets the banned user back in (invite bypasses +b/+i).
    a.reset();
    try writeAllFd(fd_a, "INVITE B #c\r\n");
    try recvUntil(&a, " 341 A B #c", 200);
    b.reset();
    try writeAllFd(fd_b, "JOIN #c sesame\r\n");
    try recvUntil(&b, " 366 B #c ", 200);

    // Ban-list query: 367 entry + 368 end.
    a.reset();
    try writeAllFd(fd_a, "MODE #c b\r\n");
    try recvUntil(&a, " 367 A #c B!*@*", 200);
    try recvUntil(&a, " 368 A #c ", 200);

    // KNOCK: A founds a fresh +i channel #i (B is not a member); B knocks ->
    // A (op) gets 710, B gets 711. B stays in #c for the WHOWAS step below.
    a.reset();
    try writeAllFd(fd_a, "JOIN #i\r\n");
    try recvUntil(&a, " 366 A #i ", 200);
    a.reset();
    try writeAllFd(fd_a, "MODE #i +i\r\n");
    try recvUntil(&a, "MODE #i +i", 200);
    a.reset();
    b.reset();
    try writeAllFd(fd_b, "KNOCK #i :let me in\r\n");
    try recvUntil(&a, " 710 A #i ", 200);
    try recvUntil(&b, " 711 B #i ", 200);

    // WHOWAS: B quits (A shares #c so sees the QUIT, after the whowas record is
    // taken), then A WHOWAS B -> 314 user line + 369 end.
    a.reset();
    try writeAllFd(fd_b, "QUIT :gone\r\n");
    try recvUntil(&a, "QUIT :gone", 200);
    a.reset();
    try writeAllFd(fd_a, "WHOWAS B\r\n");
    try recvUntil(&a, " 314 A B ", 200);
    try recvUntil(&a, " 369 A B ", 200);
}

test "threaded server: IRCv3 server-time tag on PRIVMSG for cap holders" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);
    var a = LiveClient{ .fd = fd_a };
    var b = LiveClient{ .fd = fd_b };

    // A negotiates server-time; B does not.
    try writeAllFd(fd_a, "CAP REQ :server-time\r\n");
    try recvUntil(&a, "ACK :server-time", 200);
    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\nCAP END\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&b, " 001 B ", 200);

    try writeAllFd(fd_a, "JOIN #t\r\n");
    try recvUntil(&a, " 366 A #t ", 200);
    try writeAllFd(fd_b, "JOIN #t\r\n");
    try recvUntil(&b, " 366 B #t ", 200);

    // B messages the channel; A (cap holder) sees a @time= tag before the prefix.
    a.reset();
    try writeAllFd(fd_b, "PRIVMSG #t :hello\r\n");
    try recvUntil(&a, "@time=", 200);
    try recvUntil(&a, ":B!bob@localhost PRIVMSG #t :hello\r\n", 200);
}

test "buildTagPrefix assembles server-time + account into one tag segment" {
    var session = dispatch.ClientSession.init();
    const tags = LinuxServer.MsgTags{ .time_value = "2026-06-04T12:00:00.000Z", .account = "alice" };
    var buf: [128]u8 = undefined;

    // No caps -> no tag segment.
    try std.testing.expectEqualStrings("", buildTagPrefix(&session, tags, &buf));

    // server-time only.
    session.addCap(.server_time);
    try std.testing.expectEqualStrings("@time=2026-06-04T12:00:00.000Z ", buildTagPrefix(&session, tags, &buf));

    // both caps -> single segment, semicolon-joined, trailing space.
    session.addCap(.account_tag);
    try std.testing.expectEqualStrings("@time=2026-06-04T12:00:00.000Z;account=alice ", buildTagPrefix(&session, tags, &buf));

    // account-tag only, no account -> empty (nothing to add).
    var s2 = dispatch.ClientSession.init();
    s2.addCap(.account_tag);
    const no_acct = LinuxServer.MsgTags{ .time_value = "", .account = null };
    try std.testing.expectEqualStrings("", buildTagPrefix(&s2, no_acct, &buf));
}

test "threaded server: TAGMSG relays client tags to message-tags peers" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);
    var a = LiveClient{ .fd = fd_a };
    var b = LiveClient{ .fd = fd_b };

    try writeAllFd(fd_a, "CAP REQ :message-tags\r\nNICK A\r\nUSER alice 0 * :Alice\r\nCAP END\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try writeAllFd(fd_b, "CAP REQ :message-tags\r\nNICK B\r\nUSER bob 0 * :Bob\r\nCAP END\r\n");
    try recvUntil(&b, " 001 B ", 200);

    try writeAllFd(fd_a, "JOIN #t\r\n");
    try recvUntil(&a, " 366 A #t ", 200);
    try writeAllFd(fd_b, "JOIN #t\r\n");
    try recvUntil(&b, " 366 B #t ", 200);

    // A's tagged TAGMSG is relayed verbatim to B (message-tags peer).
    b.reset();
    try writeAllFd(fd_a, "@+typing=active TAGMSG #t\r\n");
    try recvUntil(&b, "@+typing=active :A!alice@localhost TAGMSG #t\r\n", 200);
}

test "threaded server: +e/+I list queries + +I join bypass" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);
    var a = LiveClient{ .fd = fd_a };
    var b = LiveClient{ .fd = fd_b };

    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try recvUntil(&b, " 001 B ", 200);

    // A founds #p, sets +i, and a +I invite-exception matching B.
    try writeAllFd(fd_a, "JOIN #p\r\n");
    try recvUntil(&a, " 366 A #p ", 200);
    try writeAllFd(fd_a, "MODE #p +i\r\n");
    try recvUntil(&a, "MODE #p +i", 200);
    a.reset();
    try writeAllFd(fd_a, "MODE #p +I B!*@*\r\n");
    try recvUntil(&a, "MODE #p +I B!*@*", 200);

    // B (no invite) joins #p because it matches the +I mask.
    try writeAllFd(fd_b, "JOIN #p\r\n");
    try recvUntil(&b, " 366 B #p ", 200);

    // +e list query: empty -> just 349; after +e -> 348 entry + 349.
    a.reset();
    try writeAllFd(fd_a, "MODE #p e\r\n");
    try recvUntil(&a, " 349 A #p ", 200);
    a.reset();
    try writeAllFd(fd_a, "MODE #p +e x!*@*\r\n");
    try recvUntil(&a, "MODE #p +e x!*@*", 200);
    a.reset();
    try writeAllFd(fd_a, "MODE #p e\r\n");
    try recvUntil(&a, " 348 A #p x!*@*", 200);
    try recvUntil(&a, " 349 A #p ", 200);

    // +I list query -> 346 entry + 347.
    a.reset();
    try writeAllFd(fd_a, "MODE #p I\r\n");
    try recvUntil(&a, " 346 A #p B!*@*", 200);
    try recvUntil(&a, " 347 A #p ", 200);
}

test "threaded server: IRCv3 invite-notify to cap holders" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);
    const fd_c = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_c);
    const alloc = std.testing.allocator;
    const a = try alloc.create(LiveClient);
    defer alloc.destroy(a);
    const b = try alloc.create(LiveClient);
    defer alloc.destroy(b);
    const c = try alloc.create(LiveClient);
    defer alloc.destroy(c);
    a.* = .{ .fd = fd_a };
    b.* = .{ .fd = fd_b };
    c.* = .{ .fd = fd_c };

    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try recvUntil(a, " 001 A ", 200);
    try writeAllFd(fd_b, "CAP REQ :invite-notify\r\n");
    try recvUntil(b, "ACK :invite-notify", 200);
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\nCAP END\r\n");
    try recvUntil(b, " 001 B ", 200);
    try writeAllFd(fd_c, "NICK C\r\nUSER carol 0 * :Carol\r\n");
    try recvUntil(c, " 001 C ", 200);

    // A founds #i, B (cap holder) joins.
    try writeAllFd(fd_a, "JOIN #i\r\n");
    try recvUntil(a, " 366 A #i ", 200);
    try writeAllFd(fd_b, "JOIN #i\r\n");
    try recvUntil(b, " 366 B #i ", 200);

    // A invites C; B (member with invite-notify) sees the INVITE.
    b.reset();
    try writeAllFd(fd_a, "INVITE C #i\r\n");
    try recvUntil(b, ":A!alice@localhost INVITE C :#i\r\n", 200);
}

test "threaded server: STATUSMSG @#chan rank filter + sender gate" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);
    const fd_c = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_c);
    const alloc = std.testing.allocator;
    const a = try alloc.create(LiveClient);
    defer alloc.destroy(a);
    const b = try alloc.create(LiveClient);
    defer alloc.destroy(b);
    const c = try alloc.create(LiveClient);
    defer alloc.destroy(c);
    a.* = .{ .fd = fd_a };
    b.* = .{ .fd = fd_b };
    c.* = .{ .fd = fd_c };

    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try writeAllFd(fd_c, "NICK C\r\nUSER carol 0 * :Carol\r\n");
    try recvUntil(a, " 001 A ", 200);
    try recvUntil(b, " 001 B ", 200);
    try recvUntil(c, " 001 C ", 200);

    // A founds #s; B and C join; A ops B.
    try writeAllFd(fd_a, "JOIN #s\r\n");
    try recvUntil(a, " 366 A #s ", 200);
    try writeAllFd(fd_b, "JOIN #s\r\n");
    try recvUntil(b, " 366 B #s ", 200);
    try writeAllFd(fd_c, "JOIN #s\r\n");
    try recvUntil(c, " 366 C #s ", 200);
    try writeAllFd(fd_a, "MODE #s +o B\r\n");
    try recvUntil(b, "MODE #s +o B", 200);

    // A -> @#s reaches op B (rank filter); plain member C is excluded.
    b.reset();
    try writeAllFd(fd_a, "PRIVMSG @#s :ops only\r\n");
    try recvUntil(b, ":A!alice@localhost PRIVMSG @#s :ops only\r\n", 200);

    // C (plain member) cannot send to a status-prefixed target -> 482.
    c.reset();
    try writeAllFd(fd_c, "PRIVMSG @#s :sneaky\r\n");
    try recvUntil(c, " 482 C @#s ", 200);
}

test "threaded server: PRIVMSG multi-target delivery" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);
    const fd_c = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_c);
    // LiveClient carries an 8 KiB buffer; three on the stack alongside the
    // Server (with its io_uring ring) overflow the test frame, so heap them.
    const alloc = std.testing.allocator;
    const a = try alloc.create(LiveClient);
    defer alloc.destroy(a);
    const b = try alloc.create(LiveClient);
    defer alloc.destroy(b);
    const c = try alloc.create(LiveClient);
    defer alloc.destroy(c);
    a.* = .{ .fd = fd_a };
    b.* = .{ .fd = fd_b };
    c.* = .{ .fd = fd_c };

    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try writeAllFd(fd_c, "NICK C\r\nUSER carol 0 * :Carol\r\n");
    try recvUntil(a, " 001 A ", 200);
    try recvUntil(b, " 001 B ", 200);
    try recvUntil(c, " 001 C ", 200);

    // One PRIVMSG addressed to both B and C reaches each.
    try writeAllFd(fd_a, "PRIVMSG B,C :hi both\r\n");
    try recvUntil(b, ":A!alice@localhost PRIVMSG B :hi both\r\n", 200);
    try recvUntil(c, ":A!alice@localhost PRIVMSG C :hi both\r\n", 200);
}

test "threaded server: JOIN/PART comma-lists" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    var a = LiveClient{ .fd = fd_a };
    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try recvUntil(&a, " 001 A ", 200);

    // One JOIN with two channels -> both NAMES-end (366) arrive.
    a.reset();
    try writeAllFd(fd_a, "JOIN #x,#y\r\n");
    try recvUntil(&a, " 366 A #x ", 200);
    try recvUntil(&a, " 366 A #y ", 200);

    // One PART with two channels -> both PART lines echoed back to A.
    a.reset();
    try writeAllFd(fd_a, "PART #x,#y :later\r\n");
    try recvUntil(&a, "PART #x :later\r\n", 200);
    try recvUntil(&a, "PART #y :later\r\n", 200);
}

test "threaded server: registered NICK change broadcasts + collision" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);
    var a = LiveClient{ .fd = fd_a };
    var b = LiveClient{ .fd = fd_b };

    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try recvUntil(&b, " 001 B ", 200);

    try writeAllFd(fd_a, "JOIN #n\r\n");
    try recvUntil(&a, " 366 A #n ", 200);
    try writeAllFd(fd_b, "JOIN #n\r\n");
    try recvUntil(&b, " 366 B #n ", 200);

    // A changes nick -> B (common channel) and A both see the NICK line.
    a.reset();
    b.reset();
    try writeAllFd(fd_a, "NICK Alice2\r\n");
    try recvUntil(&b, ":A!alice@localhost NICK :Alice2\r\n", 200);
    try recvUntil(&a, "NICK :Alice2\r\n", 200);

    // B cannot take the now-occupied nick -> 433.
    b.reset();
    try writeAllFd(fd_b, "NICK Alice2\r\n");
    try recvUntil(&b, " 433 ", 200);
}

test "threaded server: IRCv3 extended-join per-recipient format" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);
    var a = LiveClient{ .fd = fd_a };
    var b = LiveClient{ .fd = fd_b };

    try writeAllFd(fd_a, "CAP REQ :extended-join\r\n");
    try recvUntil(&a, "ACK :extended-join", 200);
    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\nCAP END\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&b, " 001 B ", 200);

    try writeAllFd(fd_a, "JOIN #e\r\n");
    try recvUntil(&a, " 366 A #e ", 200);

    // B joins; A (extended-join) sees the account + realname form (account "*"
    // since B isn't logged in).
    a.reset();
    try writeAllFd(fd_b, "JOIN #e\r\n");
    try recvUntil(&a, ":B!bob@localhost JOIN #e * :Bob\r\n", 200);
}

test "threaded server: MONITOR online/offline/list end-to-end" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    var a = LiveClient{ .fd = fd_a };
    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try recvUntil(&a, " 001 A ", 200);

    // A monitors B while B is offline -> RPL_MONOFFLINE (731).
    a.reset();
    try writeAllFd(fd_a, "MONITOR + B\r\n");
    try recvUntil(&a, " 731 A :B", 200);

    // B connects and registers -> A is told B is online (730).
    a.reset();
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    var b = LiveClient{ .fd = fd_b };
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&b, " 001 B ", 200);
    try recvUntil(&a, " 730 A :B", 200);

    // MONITOR L -> 732 list + 733 end.
    a.reset();
    try writeAllFd(fd_a, "MONITOR L\r\n");
    try recvUntil(&a, " 732 A :B", 200);
    try recvUntil(&a, " 733 A ", 200);

    // B quits -> A is told B is offline (731).
    a.reset();
    try writeAllFd(fd_b, "QUIT :bye\r\n");
    try recvUntil(&a, " 731 A :B", 200);
    closeFd(fd_b);
}

test {
    std.testing.refAllDecls(@This());
}
