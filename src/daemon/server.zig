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
const module_core = @import("module_core.zig");
const module_manifest = @import("modules/manifest.zig");
const mod_registry = @import("registry.zig");
const wasm_bridge = @import("../wasm/host/bridge.zig");
const netsplit_batch = @import("netsplit_batch.zig");
const message_relay = @import("../substrate/suimyaku/message_relay.zig");
const tiered_keys = @import("tiered_keys.zig");
const nick_enforcement = @import("nick_enforcement.zig");
const media_session = @import("../substrate/media_session.zig");
const sdp = @import("../proto/sdp.zig");
const event_spine = @import("event_spine.zig");
const observe_mod = @import("observe.zig");
const client_model = @import("client.zig");
const world_model = @import("world.zig");
const sasl = @import("../proto/sasl.zig");
const sasl_mechrouter = @import("../proto/sasl_mechrouter.zig");
const certfp = @import("../proto/certfp.zig");
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
const utf8_guard = @import("../proto/utf8_guard.zig");
const whisper = @import("../proto/whisper.zig");
const read_marker_store = @import("../proto/read_marker_store.zig");
const silence = @import("../proto/silence.zig");
const chanserv_cmd = @import("../proto/chanserv_cmd.zig");
const oper_motd_mod = @import("../proto/oper_motd.zig");
const host_request_mod = @import("host_request.zig");
const guise_mod = @import("guise.zig");
const shun_mod = @import("shun.zig");
const autojoin_mod = @import("autojoin.zig");
const memo_group_mod = @import("memo_group.zig");
const welcome_pack_mod = @import("welcome_pack.zig");
const mode_lock_mod = @import("../proto/mode_lock.zig");
const account_verify_mod = @import("account_verify.zig");
const wildcard_limit = @import("../proto/wildcard_limit.zig");
const color_strip = @import("../proto/color_strip.zig");
const snowflake_id = @import("../proto/snowflake_id.zig");
const msgid_mod = @import("../proto/msgid.zig");
const multiline = @import("../proto/multiline.zig");
const secure_fns = @import("../proto/secure_fns.zig");
const global_notice = @import("../proto/global_notice.zig");
const help_db = @import("../proto/help_db.zig");
const lotus = @import("../proto/lotus.zig");
const chathistory_cmd = @import("../proto/chathistory_cmd.zig");
const warden = @import("warden.zig");
const whox = @import("../proto/whox.zig");
const metadata_store = @import("../proto/metadata_store.zig");
const ircx_prop_store = @import("../proto/ircx_prop_store.zig");
const ircx_access_store = @import("../proto/ircx_access_store.zig");
const chanmode_ext = @import("../proto/chanmode_ext.zig");
const ircx_modex = @import("../proto/ircx_modex.zig");
const auditorium = @import("../proto/auditorium.zig");
const s2s_link = @import("s2s_link.zig");
const tracelog = @import("../substrate/trace.zig");
const accept_list = @import("../proto/accept_list.zig");
const cloak = @import("../proto/cloak.zig");
const dns = @import("../proto/dns.zig");
const resolv_conf = @import("../proto/resolv_conf.zig");
const chan_forward = @import("../proto/chan_forward.zig");
const clone_limit_mod = @import("clone_limit.zig");
const ip_reputation_mod = @import("ip_reputation.zig");
const chghost = @import("../proto/chghost.zig");
const channel_rename = @import("../proto/channel_rename.zig");
const usermode = @import("../proto/usermode.zig");
const content_filter_mod = @import("content_filter.zig");
const media_room = @import("media_room.zig");
const media_plane_mod = @import("media_plane.zig");
const native_media_mod = @import("native_media_transport.zig");
const media_bridge_mod = @import("media_bridge.zig");
const helix_live = @import("helix/live.zig");
const session_snapshot = @import("helix/session_snapshot.zig");

/// Per-channel cross-leg media bridge (native ↔ opt-in WebRTC roster).
const Bridge = media_bridge_mod.ChannelBridge(native_media_mod.max_call_participants);

/// Blocking acquire on the tryLock-only `std.atomic.Mutex` guarding the media
/// bridge registry (rare register/leave vs. the native pump thread).
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

/// Context for the native→WebRTC cross-leg send callback.
const BridgeSendCtx = struct {
    server: *LinuxServer,
    channel: []const u8,
};

/// Resolve a WebRTC target's live address from the media plane and send the
/// rewrapped RTP packet there.
fn bridgeSendToWebrtc(ctx: *anyopaque, target: *const media_bridge_mod.Member, bytes: []const u8) void {
    const s: *BridgeSendCtx = @ptrCast(@alignCast(ctx));
    if (s.server.media_plane.remoteFor(s.channel, target.id())) |addr|
        s.server.media_plane.sendTo(addr, bytes);
}

/// Cross-leg sink invoked by the native pump: rewrap the native frame to RTP and
/// fan it out to the channel's WebRTC members (live addresses resolved per peer).
fn bridgeOnNativeFrame(ctx: *anyopaque, channel: []const u8, datagram: []const u8) void {
    const self: *LinuxServer = @ptrCast(@alignCast(ctx));
    lockSpin(&self.media_bridges_mu);
    defer self.media_bridges_mu.unlock();
    const br = self.media_bridges.getPtr(channel) orelse return;
    var sctx = BridgeSendCtx{ .server = self, .channel = channel };
    br.fanoutNativeToWebrtc(datagram, &sctx, bridgeSendToWebrtc);
}

/// Resolve a native target's learned address from the native transport and send
/// the rewrapped opcodec datagram there.
fn bridgeSendToNative(ctx: *anyopaque, target: *const media_bridge_mod.Member, bytes: []const u8) void {
    const s: *BridgeSendCtx = @ptrCast(@alignCast(ctx));
    if (s.server.native_media.remoteFor(s.channel, target.id())) |addr|
        s.server.native_media.sendTo(addr, bytes);
}

/// Cross-leg sink invoked by the WebRTC relay: rewrap the RTP frame to opcodec
/// and fan it out to the channel's native members (live addresses per peer).
fn bridgeOnRtpFrame(ctx: *anyopaque, channel: []const u8, rtp: []const u8, keyframe_hint: bool) void {
    const self: *LinuxServer = @ptrCast(@alignCast(ctx));
    lockSpin(&self.media_bridges_mu);
    defer self.media_bridges_mu.unlock();
    const br = self.media_bridges.getPtr(channel) orelse return;
    var sctx = BridgeSendCtx{ .server = self, .channel = channel };
    br.fanoutWebrtcToNative(rtp, keyframe_hint, &sctx, bridgeSendToNative);
}
const tegami_mod = @import("tegami.zig");
const transcript_mod = @import("transcript.zig");
const announce_board_mod = @import("announce_board.zig");
const bot_registry_mod = @import("bot_registry.zig");
const ircx_create_cmd = @import("../proto/ircx_create_cmd.zig");
const elist = @import("../proto/elist.zig");
const userip = @import("../proto/userip.zig");
const server_stats = @import("server_stats.zig");
const activity = @import("../proto/activity.zig");
const activity_subscriptions = @import("activity_subscriptions.zig");
const node_identity = @import("node_identity.zig");
const secured_s2s_link = @import("secured_s2s_link.zig");
const tls_conn = @import("tls_conn.zig");
const reactor_wake = @import("reactor_wake.zig");
const shard_mod = @import("shard.zig");
const reactor_pool_mod = @import("reactor_pool.zig");
const reuseport = @import("reuseport.zig");
const reactor_fabric = @import("reactor_fabric.zig");
const deliver_handle = @import("deliver_handle.zig");
const oper_mod = @import("oper.zig");
const config_format = @import("config_format.zig");
const services_mod = @import("services.zig");
const account_register = @import("../proto/account_register.zig");
const account_notify = @import("../proto/account_notify.zig");
const sessions_mod = @import("sessions.zig");
const tsumugi_hs = @import("../crypto/tsumugi_handshake.zig");
const trace = @import("../proto/trace.zig");

/// Live CHATHISTORY message store (per-channel ring).
const HistoryStore = lotus.Lotus(.{ .max_targets = 512, .max_per_target = 256, .max_text = 512 });

/// Bounded WHOWAS history ring shared by the live server. Field caps match the
/// daemon's identity limits (NICKLEN=64) so live identities are never rejected.
const WhowasStore = whowas.Whowas(.{ .capacity = 256, .max_nick_len = 64, .max_user_len = 64 });
const list = @import("../proto/list.zig");
const listx = @import("../proto/listx.zig");
const who = @import("../proto/who.zig");
const platform = @import("../substrate/platform.zig");
const reactor_mod = @import("../substrate/reactor.zig");

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
    // msgid: the server-minted per-message id, delivered to recipients that
    // negotiated message-tags (the prerequisite for receiving server tags).
    // This is what message-redaction later references.
    if (tags.msgid) |id| {
        if (session.hasCap(.message_tags)) {
            b.append(if (any) ";msgid=" else "@msgid=") catch return "";
            b.append(id) catch return "";
            any = true;
        }
    }
    // Relay the sender's CLIENT-ONLY (`+`) tags to message-tags recipients,
    // merged into the single @-segment. Server-supplied tags in the sender's
    // segment (no `+`) are NOT relayed, so a client can't spoof server-time etc.
    if (tags.client_tags) |raw| {
        if (session.hasCap(.message_tags)) {
            var it = std.mem.splitScalar(u8, raw, ';');
            while (it.next()) |t| {
                if (t.len == 0 or t[0] != '+') continue;
                b.append(if (any) ";" else "@") catch return "";
                b.append(t) catch return "";
                any = true;
            }
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

/// The value of the IRCv3 `batch` tag on a line, or null if absent. Parses the
/// raw tag segment (the daemon's line parser keeps tags as `tags_raw`).
fn batchTagValue(parsed: *const irc_line.LineView) ?[]const u8 {
    const raw = parsed.tags_raw orelse return null;
    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |tag| {
        if (std.mem.startsWith(u8, tag, "batch=")) return tag["batch=".len..];
    }
    return null;
}

/// Whether a BATCH line opens a `draft/multiline` batch
/// (`BATCH +<ref> draft/multiline <target>`).
fn isMultilineOpen(parsed: *const irc_line.LineView) bool {
    return parsed.param_count == 3 and
        parsed.params[0].len >= 1 and parsed.params[0][0] == '+' and
        std.mem.eql(u8, parsed.params[1], multiline.draft_multiline_batch);
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

/// Public alias of the daemon's parsed-line view so module files (module_core.zig)
/// can name the type the live dispatch path uses.
pub const ParsedLine = irc_line.LineView;

/// Public alias of the daemon's numeric-reply code enum so modules can emit
/// numerics through `Core.reply` without reaching into server internals.
pub const ReplyCode = Numeric;

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
        connect = 5,
        // poll: readiness watch on a bare fd (e.g. a reactor's cross-reactor
        // wake eventfd). Fires a `.poll` completion when the fd is readable.
        poll = 6,
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
            5 => .connect,
            6 => .poll,
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

    pub const ConnectEvent = struct {
        token: FdToken,
        res: i32,
    };

    pub const PollEvent = struct {
        token: FdToken,
        res: i32,
    };

    pub const Completion = union(OpKind) {
        other: void,
        accept: AcceptEvent,
        recv: RecvEvent,
        send: SendEvent,
        timeout: void,
        connect: ConnectEvent,
        poll: PollEvent,
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
            .connect => .{ .connect = .{ .token = ud.token, .res = cqe.res } },
            .poll => .{ .poll = .{ .token = ud.token, .res = cqe.res } },
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

        pub fn submitConnect(self: *Ring, token: FdToken, fd: linux.fd_t, addr: *const posix.sockaddr, addrlen: posix.socklen_t) !void {
            _ = try self.inner.connect(try encodeUserData(.connect, token), fd, addr, addrlen);
        }

        pub fn submitSend(self: *Ring, token: FdToken, fd: linux.fd_t, buffer: []const u8) !void {
            _ = try self.inner.send(try encodeUserData(.send, token), fd, buffer, 0);
        }

        /// Queue a relative single-shot timeout; fires as a `.timeout` completion.
        pub fn submitTimeout(self: *Ring, token: FdToken, ts: *const linux.kernel_timespec) !void {
            _ = try self.inner.timeout(try encodeUserData(.timeout, token), ts, 0, 0);
        }

        /// Watch `fd` for readability (single-shot); fires a `.poll` completion.
        /// Used by a reactor to wake on its cross-reactor eventfd (see
        /// reactor_wake.zig) — re-arm after each completion.
        pub fn submitPollAdd(self: *Ring, token: FdToken, fd: linux.fd_t, poll_mask: u32) !void {
            _ = try self.inner.poll_add(try encodeUserData(.poll, token), fd, poll_mask);
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
/// Distinct accept token for the S2S listener so handleAccept can tell the two
/// listeners apart (same accept op; disambiguated by slot).
const s2s_listener_token: RingFdToken = .{ .slot = 1, .gen = 0 };
/// Reserved token for the periodic timeout sweep timer (single in-flight timer).
const timer_token: RingFdToken = .{ .slot = 2, .gen = 0 };
/// Distinct accept token for the implicit-TLS client listener (:6697), so
/// handleAccept can tell it apart from the plaintext + S2S listeners.
const tls_listener_token: RingFdToken = .{ .slot = 3, .gen = 0 };
/// Reserved token for this reactor's cross-reactor wake eventfd poll. When the
/// multi-reactor model lands, another reactor `wake()`s this fd to make the loop
/// run and drain its cross-shard mailbox.
const wake_token: RingFdToken = .{ .slot = 4, .gen = 0 };
// Timeout-sweep period and IP-reputation penalty weights are operator-tunable
// via `[limits].sweep_interval` and `[reputation]` (see Config fields).
const default_reply_bytes: usize = 8192;
const default_recv_bytes: usize = 4096;
const default_line_bytes: usize = irc_line.MAX_LINE_BODY + 2;
const server_name = "mizuchi.local";
const default_host = "localhost";

const Numeric = enum(u16) {
    RPL_MAP = 15,
    RPL_MAPEND = 17,
    RPL_PRIVS = 270,
    ERR_SECUREONLYCHAN = 489,
    ERR_THROTTLE = 480,
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
    RPL_QUIETLIST = 728,
    RPL_ENDOFQUIETLIST = 729,
    RPL_INVITELIST = 346,
    RPL_ENDOFINVITELIST = 347,
    RPL_EXCEPTLIST = 348,
    RPL_ENDOFEXCEPTLIST = 349,
    RPL_SILELIST = 271,
    RPL_ENDOFSILELIST = 272,
    RPL_KEYVALUE = 761,
    RPL_METADATAEND = 762,
    ERR_KEYNOTSET = 766,
    ERR_KEYINVALID = 767,
    ERR_KEYNOPERMISSION = 769,
    // IRCX draft: 913 IRCERR_NOACCESS ("insufficient privileges for operation").
    // (918 is IRCERR_EVENTDUP — do not reuse it for PROP denial.)
    ERR_NOACCESS = 913,
    ERR_NOWHISPER = 923,
    ERR_BADVALUE = 906,
    ERR_BADTAG = 904,
    RPL_IRCX = 800,
    RPL_TESTLINE = 725,
    RPL_NOTESTLINE = 726,
    RPL_TESTMASK = 727,
    RPL_ACCEPTLIST = 281,
    RPL_ENDOFACCEPT = 282,
    RPL_KNOCK = 710,
    RPL_KNOCKDLVR = 711,
    ERR_CHANOPEN = 713,
    ERR_KNOCKONCHAN = 714,
    RPL_MONONLINE = 730,
    RPL_MONOFFLINE = 731,
    RPL_MONLIST = 732,
    RPL_ENDOFMONLIST = 733,
    ERR_MONLISTFULL = 734,
    RPL_STATSDEBUG = 249,
    RPL_STATSUPTIME = 242,
    RPL_STATSOLINE = 243,
    RPL_STATSKLINE = 216,
    RPL_STATSDLINE = 225,
    RPL_ENDOFSTATS = 219,
    ERR_NOSUCHNICK = 401,
    ERR_NOSUCHSERVER = 402,
    ERR_NOSUCHCHANNEL = 403,
    ERR_CANNOTSENDTOCHAN = 404,
    ERR_CHANNELISFULL = 471,
    ERR_INVITEONLYCHAN = 473,
    ERR_BANNEDFROMCHAN = 474,
    ERR_BADCHANNELKEY = 475,
    ERR_NEEDREGGEDNICK = 477,
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
    ERR_NOOPERHOST = 491,
    // IRCX residual 9xx error numerics (decision: adopt the draft taxonomy). Inert
    // until a handler emits them; 926/927 back the clone/CREATE conformance path.
    ERR_BADCOMMAND = 900,
    ERR_BADLEVEL = 903,
    ERR_BADPROPERTY = 905,
    ERR_RESOURCE = 907,
    ERR_SECURITY = 908,
    ERR_UNKNOWNPACKAGE = 912,
    ERR_DUPACCESS = 914,
    ERR_MISACCESS = 915,
    ERR_TOOMANYACCESSES = 916,
    ERR_NOSUCHOBJECT = 924,
    ERR_NOTSUPPORTED = 925,
    ERR_CHANNELEXIST = 926,
    ERR_ALREADYONCHANNEL = 927,
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
    /// UDP port for the media (SFU) transport plane; 0 = ephemeral. Bound on boot.
    media_port: u16 = 0,
    /// Host/IP advertised to clients as the server's media (ICE) candidate.
    media_host: []const u8 = "127.0.0.1",
    /// Optional STUN server (IPv4 literal) queried at boot to discover the
    /// reflexive media candidate behind NAT; overrides media_host when it works.
    media_stun_host: []const u8 = "",
    media_stun_port: u16 = 0,
    /// UDP port for the native media transport (our own OPVOX/OPVIS codec leg);
    /// 0 = ephemeral. Bound on boot alongside the WebRTC/UDP media plane.
    native_media_port: u16 = 0,
    /// An already-bound+listening socket fd to ADOPT instead of binding fresh
    /// (Helix hot-UPGRADE listener handoff: the port stays bound across execve).
    /// null = bind a new listener normally. Linux only.
    inherited_listener_fd: ?linux.fd_t = null,
    /// Inherited Helix state-arena memfd (UPGRADE handoff); `adoptInheritedSessions`
    /// reads it after boot to re-attach carried-over client connections. null = none.
    resume_arena_fd: ?linux.fd_t = null,
    backlog: u31 = 128,
    ring_entries: u16 = 32,
    /// Hard cap on concurrent connections. The client table reserves this many
    /// slots up front so ConnState buffers (targeted by in-flight io_uring I/O)
    /// never move; accepts past the cap are refused.
    max_clients: u31 = 1024,
    /// Requested number of worker reactor shards (one io_uring loop per shard).
    /// 1 = the single-reactor model. Values >1 are accepted and carried but
    /// currently clamped to 1 at `runThreaded` until the per-shard reactor array
    /// + RCU world adoption land (the substrate — EBR/HAMT/RcuMap/world_rcu/
    /// reactor_pool/fabric — is already in tree). See docs/planning/24-multithreading.md.
    num_shards: u16 = 1,
    /// Drop a connection that has not completed registration (NICK+USER) within
    /// this many milliseconds (the io_uring timeout sweep enforces it).
    registration_timeout_ms: i64 = 30_000,
    /// Grace window (ms) an unauthenticated user may hold a REGISTERED nick before
    /// being force-renamed to a Guest nick. 0 disables nick protection.
    nick_grace_ms: i64 = 60_000,
    /// A registered client idle (no inbound bytes) for this long is sent a
    /// server PING; if it does not answer within `ping_timeout_ms` it is dropped
    /// with "Ping timeout". The same periodic sweep enforces both.
    ping_interval_ms: i64 = 120_000,
    /// Grace after a server PING before a silent client is dropped (Ping timeout).
    ping_timeout_ms: i64 = 60_000,
    /// Max concurrent client connections from one exact IP (0 = unlimited). Over
    /// the cap, the accept is refused with an ERROR. Loopback is counted too, so
    /// raise this if local bots/services open many connections.
    max_clones_per_ip: u32 = 0,
    /// Max concurrent client connections aggregated across a /24 (IPv4) or /64
    /// (IPv6) prefix (0 = unlimited).
    max_clones_per_net: u32 = 0,
    /// IP-reputation refuse threshold: a peer whose decaying penalty score
    /// reaches this is refused at accept (0 = reputation disabled entirely).
    reputation_refuse_threshold: u32 = 0,
    /// Half-life (ms) of the IP-reputation penalty decay.
    reputation_half_life_ms: i64 = 60_000,
    /// Period (ms) of the io_uring timeout-sweep timer; enforcement granularity
    /// of registration/ping/idle timeouts.
    sweep_interval_ms: i64 = 2_000,
    /// IP-reputation penalty added when a connection never finishes registration.
    reg_timeout_penalty: f64 = 50.0,
    /// IP-reputation penalty added when accept is refused by the clone limiter.
    clone_refuse_penalty: f64 = 25.0,
    /// Multi-session/bouncer registry sizing.
    session_max_accounts: u64 = 65536,
    session_max_per_account: u32 = 64,
    features: RingFeatureSet = RingFeatureSet.baseline,
    /// Optional SASL PLAIN verifier. Injected (not owned) so the Server does not
    /// take on the account store's I/O lifecycle: a caller that has a store wires
    /// `sasl_bridge.ServicesPlainChecker.checker()` here. Null = SASL fails closed.
    sasl_checker: ?sasl.PlainChecker = null,
    /// Optional SASL SCRAM-SHA-256 credential lookup (account -> SCRAM record).
    /// Injected from the SCRAM credential store; null = SCRAM fails closed. When
    /// set, each accepted connection also gets a fresh CSPRNG server nonce.
    sasl_scram256: ?sasl_mechrouter.Scram256Lookup = null,
    /// Optional SASL EXTERNAL verifier (TLS certfp -> account). Injected from the
    /// account ⇄ certfp binding bridge; null = EXTERNAL fails closed.
    sasl_external: ?sasl_mechrouter.ExternalLookup = null,
    /// Mutual TLS: request a client certificate on the TLS listener so SASL
    /// EXTERNAL has a fingerprint to match. Off by default.
    tls_request_client_cert: bool = false,
    /// Optional IRCv3 STS wire value ("duration=..,port=..[,preload]"), built by
    /// main.zig from `[sts]` config when a TLS listener is live. Null = STS not
    /// advertised (the default-off honesty guard). Borrowed for the server's life.
    sts_value: ?[]const u8 = null,
    /// Optional server-to-server listener port (0 = disabled). Accepts on this
    /// socket are driven as Suimyaku mesh peers via S2sLink, not IRC clients.
    s2s_port: u16 = 0,
    /// Optional implicit-TLS client listener port (0 = disabled). Accepts here
    /// are ordinary IRC clients whose bytes are wrapped in TLS 1.3 (no STARTTLS).
    /// Requires both `tls_cert_chain` and `tls_signing_key`.
    tls_port: u16 = 0,
    /// Leaf-first DER certificate chain presented on the TLS listener. Borrowed
    /// for the server's lifetime (loaded by main.zig via tls_certs.loadOrBootstrap).
    tls_cert_chain: []const []const u8 = &.{},
    /// Ed25519 key matching the leaf cert's SPKI; signs each TLS CertificateVerify.
    tls_signing_key: ?std.crypto.sign.Ed25519.KeyPair = null,
    /// This node's sovereign mesh identity — the single id that keys the server
    /// registry, the CRDT replica lane, and gossip/routing. No legacy server-id
    /// (SID): one identity. MUST be unique per node and non-zero. The default is a
    /// placeholder; real deployments set it per server (ultimately derived from
    /// the node's public key).
    node_id: u64 = 1,
    /// Optional reactor seam for time (and, later, I/O). When set, all daemon
    /// time reads route through it instead of the system monotonic clock,
    /// enabling deterministic simulation (DST). Null = real clock (production).
    reactor: ?reactor_mod.Reactor = null,
    /// Optional PQ-secured S2S: when both are set, server-to-server links run the
    /// Tsumugi AKE (TOFU) before the CRDT stream. Null = plaintext S2S handshake
    /// (backward compatible). `node_identity` is borrowed (owned by main); `io`
    /// supplies the handshake CSPRNG.
    node_identity: ?*const node_identity.NodeIdentity = null,
    crypto_io: ?std.Io = null,
    mesh_pass: []const u8 = "",
    /// Operator registry from config `[oper]` blocks (account -> class/privileges).
    /// Oper is SASL-only: a client is elevated on SASL login if its account has a
    /// binding here. Null/empty = no operators (the OPER command never grants).
    oper_registry: ?oper_mod.OperRegistry = null,
    /// Account services (REGISTER/IDENTIFY/DROP/…) backed by the WAL store. Null =
    /// account management disabled. Borrowed; outlives the server (owned by main).
    account_services: ?*services_mod.Services = null,
    /// Hostname cloak key. When set, every client's real IP/host is HMAC-cloaked
    /// on connect so other users never see the raw address. Null = no cloaking
    /// (real host shown). main derives this from `[server] cloak_secret`, or a
    /// random per-boot key when account/SASL features imply privacy is wanted.
    cloak_key: ?cloak.SecretKey = null,
    /// Config file path + resolver for live REHASH. When set (by main), REHASH
    /// re-reads and re-parses this file and swaps in the new oper registry. Null
    /// = REHASH acknowledges without reloading (e.g. defaults-only boot, tests).
    config_path: ?[]const u8 = null,
    config_resolver: config_format.Resolver = .{},
};

/// Per-connection daemon state used by both the pure command core and the
/// socket loop. No slices in this struct borrow from transient recv buffers.
/// draft/multiline reassembly limits. Advertised verbatim in the cap value
/// (`max-bytes`/`max-lines`) and enforced by the per-conn assembler. Sized
/// modestly so a single open batch costs ~4 KiB of heap, allocated lazily.
pub const multiline_cfg = multiline.Config{
    .max_bytes = 4096,
    .max_lines = 24,
    .max_ref_len = 64,
    .max_target_len = 128,
};
const MultilineAssembler = multiline.Assembler(multiline_cfg);

/// Per-connection state for one in-flight inbound draft/multiline batch.
/// Heap-owned (so the `out` accumulator has a stable address) and allocated
/// only while a batch is open; freed on close/abort and connection teardown.
const MultilineState = struct {
    assembler: MultilineAssembler = MultilineAssembler.init(),
    out: [multiline_cfg.max_bytes]u8 = undefined,
};

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
    /// When this connection took a REGISTERED nick while unauthenticated (UNIX ms;
    /// 0 = nick is free / owned by this account). The sweep enforces the grace.
    nick_claimed_at_ms: i64 = 0,
    /// QUIT reason broadcast to shared channels when this connection is torn down
    /// via the send-drain path. Defaults to the generic socket-close reason; the
    /// timeout sweep overrides it (e.g. "Ping timeout") before marking `closing`.
    close_reason: []const u8 = "Client quit",
    /// Wall-clock ms when the connection was accepted (registration-timeout base).
    connected_at_ms: i64 = 0,
    /// Wall-clock ms of the last inbound activity (recv with data). Updated on
    /// every received chunk; the idle/ping sweep measures silence against it.
    last_activity_ms: i64 = 0,
    /// True after the sweep sent an unsolicited server PING and is awaiting any
    /// inbound byte (PONG or otherwise) before the ping-timeout grace elapses.
    awaiting_pong: bool = false,
    /// Wall-clock ms when the unsolicited server PING was sent (ping-timeout base).
    ping_sent_ms: i64 = 0,
    /// The peer's parsed IP, captured at accept (null if getpeername failed or the
    /// family is unsupported). Drives the clone limiter and is released on close.
    peer_addr: ?dns.Address = null,
    /// True once this connection was counted by the clone limiter, so `closeConn`
    /// releases exactly the registrations it made (refused accepts never count).
    clone_counted: bool = false,
    /// Whether this session was accepted over TLS (implicit-TLS connection fact;
    /// there is no STARTTLS). Gates +S channels. False until TLS lands.
    is_tls: bool = false,
    /// IRCX opt-in: set true after the client sends `IRCX` (draft-pfenning §IRCX).
    /// Gates IRCX-only behaviors; base RFC1459/IRCv3 always works regardless.
    ircx: bool = false,
    /// IRCX +z GAG (sysop-set): the server silently discards this user's
    /// PRIVMSG/NOTICE. Not client-settable.
    gagged: bool = false,
    /// Non-null for server-to-server peer connections: inbound bytes drive this
    /// Suimyaku link instead of the IRC line parser. Heap-owned (stable address
    /// required by the link's self-referential clock); freed in closeConn/deinit.
    s2s: ?*s2s_link.S2sLink = null,
    /// Non-null for a PQ-SECURED S2S peer: the framed Tsumugi link drives inbound
    /// bytes instead of `s2s`. Exactly one of `s2s`/`s2s_secured` is set per peer.
    /// Heap-owned; freed in closeConn/deinit.
    s2s_secured: ?*secured_s2s_link.SecuredLink = null,
    /// One-shot guard: membership-roster burst sent to this peer once its link
    /// first reaches established (so the peer's NAMES/WHO is correct immediately,
    /// not only after future joins). See sendMembershipBurstTo / docs/planning/16.
    s2s_burst_done: bool = false,
    /// Target address for an outbound S2S connect, kept here (the slot is stable)
    /// so it outlives the in-flight IORING_OP_CONNECT submission.
    s2s_connect_addr: posix.sockaddr.in = undefined,
    /// Non-null while this client has an open inbound draft/multiline batch.
    /// Heap-owned; freed when the batch closes/aborts or the connection ends.
    multiline: ?*MultilineState = null,
    /// Non-null for an implicit-TLS client: inbound socket bytes are framed +
    /// decrypted through this adapter and outbound bytes encrypted, transparently
    /// to the IRC layer. Heap-owned; freed in closeConn/deinit.
    tls: ?*tls_conn.TlsConn = null,
    /// Stable backing for `session.tls_certfp` (the presented client cert's
    /// lowercase-hex SHA-256), populated once the mTLS handshake completes.
    certfp_buf: [certfp.fingerprint_len]u8 = undefined,

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
        // Route through appendToConn so a TLS connection's pre-registration /
        // PING replies are encrypted on the same seam as everything else.
        return appendToConn(self.conn, bytes);
    }
};

/// Per-reactor I/O resources: everything one reactor thread owns privately and
/// touches without a lock. The shared world + stores stay on `LinuxServer`; this
/// is the disjoint slice each shard runs on. Single embedded instance today,
/// reached via `LinuxServer.rx()`; the sharded model turns this into an array
/// (one per thread) addressed by a thread-local current reactor, with no
/// call-site changes (every handler already goes through `rx()`).
const Reactor = struct {
    /// This reactor's io_uring (accept/recv/send/poll/timeout completions).
    ring: RingCore,
    /// Connections pinned to this reactor (recv/send buffers, TlsConn, fd). Never
    /// touched by another reactor — cross-shard work routes through the fabric.
    clients: ClientTable,
    /// The shard index this reactor owns; stamped into each connection's
    /// `ClientId.shard`. Always 0 in the single-reactor configuration.
    shard_id: u12 = 0,

    /// Client listener (SO_REUSEPORT per reactor in the sharded model).
    listener_fd: linux.fd_t,
    /// S2S listener (-1 = disabled) + its accept-armed flag.
    s2s_listener_fd: linux.fd_t = -1,
    /// Implicit-TLS client listener (-1 = disabled) + its accept-armed flag.
    tls_listener_fd: linux.fd_t = -1,

    accept_armed: bool = false,
    s2s_accept_armed: bool = false,
    tls_accept_armed: bool = false,
    /// Whether the periodic timeout-sweep timer is currently in flight.
    timer_armed: bool = false,

    /// This reactor's cross-reactor wake eventfd (null if eventfd is unavailable),
    /// its in-flight poll-arm flag, and a monotonic count of observed wakes. Lets
    /// another thread `wakeReactor()` make this loop run and drain its mailbox.
    wake: ?reactor_wake.ReactorWake = null,
    wake_armed: bool = false,
    wake_count: std.atomic.Value(u32) = .init(0),

    /// Tear down the reactor's ring, connection table, wake fd, and listeners.
    /// The caller drains per-connection link/tls/multiline state first.
    fn deinit(self: *Reactor) void {
        self.clients.deinit();
        self.ring.deinit();
        if (self.wake) |*w| w.deinit();
        closeFd(self.listener_fd);
        if (self.s2s_listener_fd >= 0) closeFd(self.s2s_listener_fd);
        if (self.tls_listener_fd >= 0) closeFd(self.tls_listener_fd);
    }
};

/// The reactor whose loop is running on THIS thread. Each reactor thread sets it
/// once at loop entry (`runOnce`); handlers reach their own ring/connection table
/// through `LinuxServer.rx()` with no parameter threading. Null off any reactor
/// thread (e.g. a test calling a handler directly, or the main thread querying
/// `boundPort`), where `rx()` falls back to the single embedded reactor — which is
/// the same pointer in the single-reactor configuration, so the fallback is exact.
threadlocal var current_reactor: ?*Reactor = null;

pub const LinuxServer = struct {
    allocator: std.mem.Allocator,
    config: Config,
    /// MizuWasm control-plane plugin bridge: loaded third-party plugins whose
    /// declared commands are dispatched after the comptime registry misses.
    /// Empty by default (no plugins) => the consult is a fast miss.
    wasm: wasm_bridge.Bridge,
    /// Server-wide loop-guard for cross-node relayed messages, keyed by
    /// (origin_node, hlc). Per-peer seen-sets miss cross-path duplicates in a
    /// cyclic mesh; this global set dedups deliver + re-forward across all paths.
    relay_seen: message_relay.SeenSet,
    /// Per-reactor I/O (ring, connection table, listeners, wake). One entry per
    /// shard, heap-allocated at init (`reactors.len == clamped num_shards`).
    /// `reactors[0]` is the single-reactor fast path; reached through `rx()` so
    /// every handler resolves to the reactor whose ring produced its completion.
    reactors: []Reactor,
    /// Cross-shard outbound delivery fabric (per-shard mailbox + wake + shared
    /// pool). Null in the single-reactor configuration (no cross-shard handoff is
    /// ever needed); allocated by `runThreaded` when `reactors.len > 1`.
    fabric: ?reactor_fabric.ReactorFabric = null,
    /// Worker-thread pool that owns the per-shard reactor threads while
    /// `runThreaded` runs the multi-reactor topology. Idle in single-reactor mode.
    pool: reactor_pool_mod.ReactorPool(*LinuxServer),
    world: world_model.World,
    whowas: WhowasStore,
    monitor: monitor.MonitorStore,
    read_markers: read_marker_store.DefaultStore,
    silence: silence.Store,
    /// Operator OBSERVE subscriptions (live Event-Spine surveillance feed).
    observe: observe_mod.Registry,
    /// Operator MOTD (OPERMOTD), distinct from the user MOTD.
    oper_motd: oper_motd_mod.OperMotd,
    /// Pending/decided vhost requests (VHOST REQUEST → oper APPROVE/DENY).
    host_requests: host_request_mod.Queue,
    /// Guise: per-account persona wardrobe + operator offer templates.
    guises: guise_mod.Registry,
    /// Network-wide silent mutes (SHUN): shunned senders' messages are dropped.
    shuns: shun_mod.ShunList,
    /// Per-account auto-join channel lists, applied on login.
    autojoins: autojoin_mod.AutoJoin,
    /// Per-account grouped-nick sets (GROUP), with a primary nick.
    nick_groups: memo_group_mod.NickGroup,
    /// Network onboarding pack delivered once per account on first login.
    welcome: welcome_pack_mod.WelcomePack,
    /// Per-channel services mode-lock specs (MLOCK), keyed by channel name.
    mlocks: std.StringHashMapUnmanaged([]u8) = .empty,
    /// Pending account email/token verifications (REGISTER -> VERIFY).
    account_verifies: account_verify_mod.VerifyStore,
    history: HistoryStore,
    warden: warden.Registry,
    metadata: metadata_store.DefaultStore,
    props: ircx_prop_store.DefaultStore,
    access: ircx_access_store.AccessStore,
    /// Concurrent-connection clone limiter (per exact IP and per /24|/64 prefix).
    /// Limits come from Config; a zero limit disables that dimension.
    clone_limit: clone_limit_mod.CloneLimiter,
    /// Decaying per-IP penalty table. Only consulted/updated when Config's
    /// reputation_refuse_threshold is non-zero (otherwise reputation is off).
    reputation: ip_reputation_mod.IpReputation,
    /// Optional reactor seam (time/IO). Null = system monotonic clock.
    reactor: ?reactor_mod.Reactor = null,
    /// Run flag from runThreaded, so DIE/RESTART can stop the reactor.
    shutdown: ?*std.atomic.Value(bool) = null,
    accepts: accept_list.AcceptList(.{}),
    msg_seq: u64 = 0,
    /// Snowflake msgid generator: globally-unique, time-ordered, node-embedded
    /// message ids for CHATHISTORY/REDACT (better than a per-node counter on a mesh).
    snowflake: snowflake_id.Generator,
    /// IRCv3 `msgid` minter for relayed PRIVMSG/NOTICE/TAGMSG (`@msgid=<id>`).
    /// Seeded once from boot entropy so ids are opaque and disjoint across boots;
    /// the value message-redaction later references. See proto/msgid.zig.
    msgid_gen: msgid_mod.Generator,
    /// Oper-set drain mode: when true, new client connections are refused (S2S
    /// links and existing clients are unaffected). Toggled by the DRAIN command
    /// for graceful pre-shutdown / maintenance windows.
    draining: bool = false,
    /// Observability: a lock-free flight recorder (last N structured events,
    /// dumped on oper DEBUG / crash) + per-category level filter.
    trace_recorder: tracelog.FlightRecorder(256) = .{},
    trace_filter: tracelog.CategoryFilter = tracelog.CategoryFilter.init(.info),
    /// Observability: allocation-free runtime counters (totals + gauges), bumped
    /// inline on the hot path and rendered on demand (STATS z / Prometheus).
    stats: server_stats.Stats = .{},
    /// #33 ACTIVITY: per-channel real-time activity-stream subscribers.
    activity_subs: activity_subscriptions.SubscriptionStore,
    /// Phase 3: per-account live session registry (multi-device / bouncer).
    sessions: sessions_mod.SessionStore,
    /// Koshi content filter: oper-curated patterns that block matching messages.
    content_filter: content_filter_mod.ContentFilter,
    /// Per-channel media rooms (Mizuchi media SFU control plane): who is in each call.
    media_rooms: media_room.MediaRooms,
    /// Media transport plane: UDP socket + ICE/STUN endpoint registry + pump
    /// thread. Started on boot (`start`), torn down on `deinit`.
    media_plane: media_plane_mod.MediaPlane,
    /// Native media transport: UDP leg for our own OPVOX/OPVIS codec
    /// (opcodec_frame datagrams). Started on boot, torn down on `deinit`.
    native_media: native_media_mod.NativeMediaTransport,
    /// Per-channel cross-leg bridge roster (native ↔ opt-in WebRTC). Consulted by
    /// the native pump's cross-leg sink; guarded by `media_bridges_mu`.
    media_bridges: std.StringHashMapUnmanaged(Bridge) = .empty,
    media_bridges_mu: std.atomic.Mutex = .unlocked,
    /// Tegami: per-account offline messages, delivered on next login.
    tegami: tegami_mod.TegamiBox,
    /// Per-channel live media transcript (speaker-tagged caption ring).
    transcript: transcript_mod.TranscriptLog,
    /// Server-owned config reloaded by the most recent REHASH. The live
    /// `oper_registry` borrows `reload_bindings`, which borrow `reload_parsed`;
    /// all three are freed (and the prior generation replaced) on each REHASH and
    /// on deinit. Null/empty until the first successful REHASH.
    reload_parsed: ?config_format.Config = null,
    reload_bindings: []oper_mod.OperBinding = &.{},
    /// Monotonically increasing seed fed to S2sLink.feed for deterministic gossip
    /// rng. (The S2S/TLS listener fds, accept-armed flags, and the cross-reactor
    /// wake eventfd now live on `reactor`.)
    s2s_feed_seq: u64 = 0,

    /// Operator registry (account -> oper class), from config. Borrowed; outlives
    /// the server via the loaded config.
    oper_registry: ?oper_mod.OperRegistry = null,
    /// Account services backend (borrowed; owned by main).
    account_services: ?*services_mod.Services = null,
    /// Monotonic millis captured at init, for STATS u uptime.
    start_ms: i64 = 0,

    /// The reactor this call is running on. Single embedded reactor today, so it
    /// is just `&self.reactor`; when the daemon shards into N reactor threads this
    /// resolves to the thread-local current reactor (set at each thread's loop
    /// entry). Centralizing the lookup keeps every handler's `self.rx().ring` /
    /// `self.rx().clients` access shard-correct with no signature changes.
    inline fn rx(self: *LinuxServer) *Reactor {
        return current_reactor orelse &self.reactors[0];
    }

    /// Clamp the configured shard count to `[1, max_shards]`. A zero (unset) or
    /// out-of-range request collapses to a single reactor — the safe default.
    fn clampShards(config: Config) u12 {
        const requested: usize = if (config.num_shards == 0) 1 else config.num_shards;
        const capped = @min(requested, shard_mod.max_shards);
        return @intCast(@max(@as(usize, 1), capped));
    }

    /// Build one shard's `Reactor`: its own ring, connection table (reserved to
    /// `max_clients`), wake eventfd, and listeners stamped with `shard_id`. When
    /// `reuse_port` is set every listener is a `SO_REUSEPORT` socket so N reactors
    /// can share the same `(host, port)` and the kernel load-balances accepts;
    /// the single-reactor path keeps the plain `createListener` sockets (and the
    /// inherited-fd upgrade handoff) for byte-identical behavior. On any partial
    /// failure every fd/resource already created for this shard is released.
    fn initReactor(allocator: std.mem.Allocator, config: Config, shard_id: u12, reuse_port: bool) !Reactor {
        const listener_fd = if (!reuse_port and config.inherited_listener_fd != null) blk: {
            const fd = config.inherited_listener_fd.?;
            std.debug.print("mizuchi: adopting inherited listener fd {d}\n", .{fd});
            break :blk fd;
        } else if (reuse_port)
            try reuseport.createReusePortListener(config.host, config.port, config.backlog)
        else
            try createListener(config.host, config.port, config.backlog);
        errdefer closeFd(listener_fd);

        const s2s_listener_fd: linux.fd_t = if (config.s2s_port != 0)
            (if (reuse_port)
                try reuseport.createReusePortListener(config.host, config.s2s_port, config.backlog)
            else
                try createListener(config.host, config.s2s_port, config.backlog))
        else
            -1;
        errdefer if (s2s_listener_fd >= 0) closeFd(s2s_listener_fd);

        // Cert presence is the "TLS configured" signal (main.zig only supplies a
        // chain when [tls] is enabled). Port 0 then means an ephemeral bind, the
        // same convention the plaintext listener uses.
        const tls_listener_fd: linux.fd_t = if (config.tls_cert_chain.len != 0 and config.tls_signing_key != null)
            (if (reuse_port)
                try reuseport.createReusePortListener(config.host, config.tls_port, config.backlog)
            else
                try createListener(config.host, config.tls_port, config.backlog))
        else
            -1;
        errdefer if (tls_listener_fd >= 0) closeFd(tls_listener_fd);

        var ring = RingCore.init(config.ring_entries, config.features) catch |err| {
            if (ringlane.isUnsupportedInitError(err)) return error.Unsupported;
            return err;
        };
        errdefer ring.deinit();

        // Reserve the full connection table up front so ConnState buffers never
        // move under in-flight io_uring I/O (a realloc would corrupt them). Each
        // reactor owns a disjoint slab keyed by its own `shard_id`.
        var clients = ClientTable.init(allocator, shard_id);
        errdefer clients.deinit();
        try clients.reserve(config.max_clients);

        return .{
            .ring = ring,
            .clients = clients,
            .shard_id = shard_id,
            .listener_fd = listener_fd,
            .s2s_listener_fd = s2s_listener_fd,
            .tls_listener_fd = tls_listener_fd,
            // Best-effort: a daemon without eventfd simply runs un-wakeable (a
            // single reactor never needs an external nudge; multi-reactor needs it
            // for cross-shard delivery, so a failure there degrades to busier polls).
            .wake = reactor_wake.ReactorWake.init() catch null,
        };
    }

    /// Create, bind, and listen on a TCP socket, then initialize the Ringlane
    /// ring used for accept/recv/send completions.
    pub fn init(allocator: std.mem.Allocator, config: Config) !LinuxServer {
        if (builtin.os.tag != .linux) return error.Unsupported;

        const shard_count = clampShards(config);
        // For >1 shard EVERY listener (shard 0 included) must be SO_REUSEPORT or
        // the kernel rejects the second bind on the shared port. The single-shard
        // path keeps plain sockets so its behavior is byte-identical to before.
        const reuse_port = shard_count > 1;

        const reactors = try allocator.alloc(Reactor, shard_count);
        errdefer allocator.free(reactors);
        var built: usize = 0;
        errdefer for (reactors[0..built]) |*r| r.deinit();
        while (built < shard_count) : (built += 1) {
            reactors[built] = try initReactor(allocator, config, @intCast(built), reuse_port);
        }

        var whowas_store = try WhowasStore.init(allocator);
        errdefer whowas_store.deinit();

        return .{
            .allocator = allocator,
            .config = config,
            .wasm = wasm_bridge.Bridge.init(allocator),
            .relay_seen = message_relay.SeenSet.init(allocator, 4096),
            .reactors = reactors,
            .pool = reactor_pool_mod.ReactorPool(*LinuxServer).init(allocator),
            .world = world_model.World.init(allocator),
            .whowas = whowas_store,
            .monitor = monitor.MonitorStore.init(allocator, 128),
            .read_markers = read_marker_store.DefaultStore.init(allocator),
            .silence = silence.Store.init(allocator),
            .observe = observe_mod.Registry.init(allocator, .{}),
            .oper_motd = oper_motd_mod.OperMotd.init(allocator),
            .host_requests = host_request_mod.Queue.init(allocator, .{}),
            .guises = guise_mod.Registry.init(allocator, .{}),
            .shuns = shun_mod.ShunList.init(allocator, .{}),
            .autojoins = autojoin_mod.AutoJoin.init(allocator),
            .nick_groups = memo_group_mod.NickGroup.init(allocator),
            .welcome = welcome_pack_mod.WelcomePack.init(allocator),
            .account_verifies = account_verify_mod.VerifyStore.init(allocator, .{ .token_bytes = 16 }),
            .history = HistoryStore.init(allocator),
            .warden = warden.Registry.init(allocator, .{}),
            .metadata = metadata_store.DefaultStore.init(allocator),
            .props = ircx_prop_store.DefaultStore.init(allocator),
            .access = ircx_access_store.AccessStore.init(allocator),
            .clone_limit = clone_limit_mod.CloneLimiter.init(allocator, .{
                .max_per_ip = config.max_clones_per_ip,
                .max_per_net = config.max_clones_per_net,
            }),
            .reputation = ip_reputation_mod.IpReputation.init(allocator, .{
                .half_life_ms = @intCast(@max(1, config.reputation_half_life_ms)),
                .refuse_threshold = @floatFromInt(config.reputation_refuse_threshold),
            }) catch unreachable,
            .accepts = accept_list.AcceptList(.{}).init(allocator),
            .snowflake = snowflake_id.Generator.init(.{ .node_id = @intCast(config.node_id & snowflake_id.NODE_MASK) }) catch unreachable,
            // Seed the msgid minter once from boot entropy (OS CSPRNG via
            // secure_fns/getrandom) so ids are opaque and disjoint across boots.
            .msgid_gen = msgid_mod.Generator.init(secure_fns.randomU64()),
            .activity_subs = activity_subscriptions.SubscriptionStore.init(allocator),
            .sessions = sessions_mod.SessionStore.initWithConfig(allocator, .{
                .max_accounts = @intCast(config.session_max_accounts),
                .max_sessions_per_account = config.session_max_per_account,
            }),
            .content_filter = content_filter_mod.ContentFilter.init(allocator),
            .media_rooms = media_room.MediaRooms.init(allocator),
            .media_plane = media_plane_mod.MediaPlane.init(allocator),
            .native_media = native_media_mod.NativeMediaTransport.init(allocator),
            .tegami = tegami_mod.TegamiBox.init(allocator),
            .transcript = transcript_mod.TranscriptLog.init(allocator),
            .oper_registry = config.oper_registry,
            .account_services = config.account_services,
            .reactor = config.reactor,
            .start_ms = if (config.reactor) |r| r.nowMillis() else platform.monotonicMillis(),
        };
    }

    /// Run module init→ready lifecycle once the server is at its final address
    /// (called by main after construction; init() returns by value so `self`
    /// is not stable inside it).
    pub fn start(self: *LinuxServer) void {
        self.driveLifecycle(.init);
        self.driveLifecycle(.ready);
        // Optional STUN-based reflexive-candidate discovery at boot (before the
        // pump thread starts). Configured as an IPv4 literal + port.
        if (self.config.media_stun_port != 0) {
            if (parseIp4(self.config.media_stun_host)) |ip4| {
                self.media_plane.stun_server = media_plane_mod.TransportAddress.fromBytes(&ip4, self.config.media_stun_port) catch null;
            }
        }
        // Bring the native media transport online (our own OPVOX/OPVIS codec
        // leg). Independent of the WebRTC plane below; a bind failure logs and
        // the daemon keeps serving IRC.
        self.native_media.start(native_media_mod.any_be, self.config.native_media_port) catch |e| {
            std.debug.print("mizuchi: native media transport disabled ({s})\n", .{@errorName(e)});
        };
        if (self.native_media.port != 0) {
            std.debug.print("mizuchi: native media on UDP :{d} (codec OPVOX/OPVIS)\n", .{self.native_media.port});
            // Bridge native frames to any opt-in WebRTC members of each channel.
            self.native_media.setCrossLegSink(.{ .ctx = self, .on_native_frame = bridgeOnNativeFrame });
        }

        // Bring the media transport plane online (bind UDP + pump thread). Media
        // is optional: a bind failure logs and the daemon keeps serving IRC.
        self.media_plane.start(media_plane_mod.any_be, self.config.media_port) catch |e| {
            std.debug.print("mizuchi: media plane disabled ({s})\n", .{@errorName(e)});
            return;
        };
        var host_buf: [16]u8 = undefined;
        const cand = self.media_plane.candidateIp(&host_buf) orelse self.config.media_host;
        std.debug.print("mizuchi: media plane on UDP :{d} (candidate host {s})\n", .{ self.media_plane.port, cand });
        // Bridge WebRTC RTP frames to any native members of each channel.
        self.media_plane.setCrossLegSink(.{ .ctx = self, .on_rtp_frame = bridgeOnRtpFrame });
    }

    pub fn deinit(self: *LinuxServer) void {
        self.driveDeinit();
        self.wasm.deinit();
        self.relay_seen.deinit();
        // Tear down every connection owned by every shard's reactor (each reactor
        // owns a disjoint slab). Single-reactor mode just walks `reactors[0]`.
        for (self.reactors) |*reactor| {
            for (reactor.clients.slots.items) |*slot| {
                if (slot.occupied) {
                    if (slot.value.s2s) |link| {
                        link.deinit();
                        self.allocator.destroy(link);
                        slot.value.s2s = null;
                    }
                    if (slot.value.s2s_secured) |link| {
                        link.deinit();
                        self.allocator.destroy(link);
                        slot.value.s2s_secured = null;
                    }
                    if (slot.value.multiline) |ms| {
                        self.allocator.destroy(ms);
                        slot.value.multiline = null;
                    }
                    if (slot.value.tls) |t| {
                        t.deinit();
                        self.allocator.destroy(t);
                        slot.value.tls = null;
                    }
                    closeFd(slot.value.fd);
                }
            }
        }
        self.history.deinit();
        self.warden.deinit();
        self.metadata.deinit();
        self.props.deinit();
        self.access.deinit();
        self.clone_limit.deinit();
        self.reputation.deinit();
        self.accepts.deinit();
        self.silence.deinit();
        self.observe.deinit();
        self.oper_motd.deinit();
        self.host_requests.deinit();
        self.guises.deinit();
        self.shuns.deinit();
        self.autojoins.deinit();
        self.nick_groups.deinit();
        self.welcome.deinit();
        {
            var it = self.mlocks.iterator();
            while (it.next()) |e| {
                self.allocator.free(e.key_ptr.*);
                self.allocator.free(e.value_ptr.*);
            }
            self.mlocks.deinit(self.allocator);
        }
        self.account_verifies.deinit();
        self.activity_subs.deinit();
        self.sessions.deinit();
        self.content_filter.deinit();
        self.media_rooms.deinit();
        self.media_plane.deinit();
        self.native_media.deinit();
        {
            var bit = self.media_bridges.keyIterator();
            while (bit.next()) |k| self.allocator.free(k.*);
            self.media_bridges.deinit(self.allocator);
        }
        self.tegami.deinit();
        self.transcript.deinit();
        self.allocator.free(self.reload_bindings);
        if (self.reload_parsed) |*p| p.deinit(self.allocator);
        self.read_markers.deinit();
        self.monitor.deinit();
        self.whowas.deinit();
        self.world.deinit();
        // Join any worker threads (no-op if runThreaded already joined), then tear
        // down each reactor's ring/table/wake/listeners and free the slice + fabric.
        self.pool.deinit();
        for (self.reactors) |*reactor| reactor.deinit();
        self.allocator.free(self.reactors);
        if (self.fabric) |*f| f.deinit();
        self.* = undefined;
    }

    /// Arm the accept SQE if needed. Submission is batched by `runOnce`.
    pub fn armAccept(self: *LinuxServer) !void {
        if (!self.rx().accept_armed) {
            try self.rx().ring.submitAccept(listener_token, self.rx().listener_fd);
            self.rx().accept_armed = true;
        }
        if (self.rx().s2s_listener_fd >= 0 and !self.rx().s2s_accept_armed) {
            try self.rx().ring.submitAccept(s2s_listener_token, self.rx().s2s_listener_fd);
            self.rx().s2s_accept_armed = true;
        }
        if (self.rx().tls_listener_fd >= 0 and !self.rx().tls_accept_armed) {
            try self.rx().ring.submitAccept(tls_listener_token, self.rx().tls_listener_fd);
            self.rx().tls_accept_armed = true;
        }
    }

    /// Keep exactly one poll on the cross-reactor wake eventfd in flight, so a
    /// foreign reactor's `wakeReactor()` makes this loop run.
    fn armWake(self: *LinuxServer) !void {
        if (self.rx().wake) |w| {
            if (!self.rx().wake_armed) {
                try self.rx().ring.submitPollAdd(wake_token, w.fd(), linux.POLL.IN);
                self.rx().wake_armed = true;
            }
        }
    }

    /// Wake this reactor from any thread: the in-flight wake poll completes, the
    /// loop runs, and (once the multi-reactor model lands) drains its mailbox.
    pub fn wakeReactor(self: *LinuxServer) void {
        if (self.rx().wake) |*w| w.wake();
    }

    /// Wake EVERY reactor's wake eventfd from any thread. Each reactor keeps a
    /// poll on its own wake fd in flight (`armWake` each `runOnce`), so this makes
    /// every blocked `submitAndWait(1)` return at once. Used by the stop path: a
    /// SO_REUSEPORT throwaway connection only nudges the one reactor the kernel
    /// happens to route it to, leaving the others blocked forever in
    /// `submitAndWait`; an explicit wake-all is what lets `pool.join()` complete.
    pub fn wakeAllReactors(self: *LinuxServer) void {
        for (self.reactors) |*r| {
            if (r.wake) |*w| w.wake();
        }
    }

    /// Cooperative multi-reactor stop: clear the shared run flag, then wake every
    /// reactor so each blocked loop returns from `submitAndWait`, re-checks the
    /// (now false) flag, and exits — letting `runThreaded`'s `pool.join()` finish.
    /// Callable from any thread (e.g. a test driver, or DIE/RESTART). Without the
    /// wake-all a reactor with no pending completion would never observe the clear.
    pub fn requestStop(self: *LinuxServer, run: *std.atomic.Value(bool)) void {
        run.store(false, .release);
        self.wakeAllReactors();
    }

    /// Handle the wake-fd poll completion: drain the eventfd, mark the poll
    /// consumed (re-armed next `runOnce`), record the wake, then drain this
    /// shard's cross-shard mailbox and flush the handed-off bytes to the local
    /// connections they target.
    fn onWakePoll(self: *LinuxServer) void {
        self.rx().wake_armed = false;
        if (self.rx().wake) |*w| w.drain();
        _ = self.rx().wake_count.fetchAdd(1, .monotonic);
        self.drainFabric();
    }

    /// Drain every cross-shard delivery addressed to THIS reactor's shard and
    /// append each handoff's bytes to the local connection it targets, then arm
    /// send and release the pooled buffer. Runs under the world write lock (the
    /// completion bracket), so it is serialized against every other reactor's
    /// world access. The connection lookup uses THIS reactor's slab — the only
    /// reactor that may touch these send buffers. A handoff whose target slot is
    /// gone (the connection closed before its bytes arrived) is dropped; its
    /// buffer is still released so the pool never leaks.
    fn drainFabric(self: *LinuxServer) void {
        const fabric = if (self.fabric) |*f| f else return;
        const my_shard = self.rx().shard_id;
        var msgs: [64]reactor_fabric.DeliverMsg = undefined;
        while (true) {
            const n = fabric.drain(my_shard, &msgs);
            if (n == 0) break;
            for (msgs[0..n]) |msg| {
                defer fabric.release(msg.buf);
                const bytes = fabric.bytes(msg.buf);
                const conn = self.rx().clients.get(msg.to) orelse continue;
                if (conn.closing) continue;
                appendToConn(conn, bytes) catch continue;
                self.armSendIfNeeded(conn) catch {};
            }
        }
    }

    /// Keep exactly one periodic timeout-sweep timer in flight.
    fn armTimer(self: *LinuxServer) !void {
        if (self.rx().timer_armed) return;
        const ns = self.config.sweep_interval_ms * std.time.ns_per_ms;
        const ts: linux.kernel_timespec = .{ .sec = @intCast(@divFloor(ns, std.time.ns_per_s)), .nsec = @intCast(@mod(ns, std.time.ns_per_s)) };
        try self.rx().ring.submitTimeout(timer_token, &ts);
        self.rx().timer_armed = true;
    }

    /// Fired when the periodic timer elapses: run the timeout sweep and re-arm.
    fn onTimerTick(self: *LinuxServer) void {
        self.rx().timer_armed = false;
        self.sweepTimeouts();
    }

    /// Drop connections that have not completed registration within the
    /// configured window. (Idle/ping timeouts for registered clients build on
    /// this same sweep.)
    fn sweepTimeouts(self: *LinuxServer) void {
        const now = self.nowMs();
        const reg_deadline = self.config.registration_timeout_ms;
        const ping_interval = self.config.ping_interval_ms;
        const ping_grace = self.config.ping_timeout_ms;
        var it = self.rx().clients.iterator();
        while (it.next()) |entry| {
            const c = entry.value;
            if (c.closing) continue; // already tearing down
            if (c.s2s != null or c.s2s_secured != null) continue; // server links exempt

            if (!c.session.registered()) {
                // Unregistered: enforce the registration handshake window.
                if (now - c.connected_at_ms <= reg_deadline) continue;
                // Queue the ERROR and mark closing; the existing send-drain path
                // (handleSend) calls closeConn for the proper io_uring-integrated
                // teardown (shutdown in-flight recv, free slot). Never closeFd here.
                self.penalizePeer(c, self.config.reg_timeout_penalty);
                appendToConn(c, ":" ++ server_name ++ " ERROR :Registration timeout\r\n") catch {};
                c.close_reason = "Registration timeout";
                c.closing = true;
                self.armSendIfNeeded(c) catch {};
                continue;
            }

            // Nick protection: a registered nick held by an unauthenticated user
            // is force-renamed to a Guest nick once the grace window elapses. The
            // check self-clears once the user identifies (authenticated_to_owner).
            if (c.nick_claimed_at_ms != 0) {
                const authed_owner = if (c.session.account()) |a|
                    std.ascii.eqlIgnoreCase(a, c.session.displayName())
                else
                    false;
                switch (nick_enforcement.evaluate(.{
                    .nick_is_registered = true,
                    .authenticated_to_owner = authed_owner,
                    .claimed_at_ms = c.nick_claimed_at_ms,
                    .now_ms = now,
                    .grace_ms = self.config.nick_grace_ms,
                })) {
                    .allow => c.nick_claimed_at_ms = 0,
                    .warn => {},
                    .enforce => {
                        var gbuf: [32]u8 = undefined;
                        const seed: u64 = @as(u64, @bitCast(entry.id)) & 0xFFFFFF;
                        if (nick_enforcement.guestNick(&gbuf, seed)) |guest| {
                            self.forceRenameTo(entry.id, c, guest);
                            self.armSendIfNeeded(c) catch {};
                        } else |_| {}
                        c.nick_claimed_at_ms = 0;
                    },
                }
            }

            // Registered: idle clients get a server PING; if the grace elapses
            // with no inbound traffic the connection is dropped (Ping timeout).
            if (c.awaiting_pong) {
                if (now - c.ping_sent_ms <= ping_grace) continue;
                appendToConn(c, ":" ++ server_name ++ " ERROR :Ping timeout\r\n") catch {};
                c.close_reason = "Ping timeout";
                c.closing = true;
                self.armSendIfNeeded(c) catch {};
                continue;
            }
            if (now - c.last_activity_ms <= ping_interval) continue;
            appendToConn(c, "PING :" ++ server_name ++ "\r\n") catch {};
            c.awaiting_pong = true;
            c.ping_sent_ms = now;
            self.armSendIfNeeded(c) catch {};
        }
    }

    pub fn s2sBoundPort(self: *LinuxServer) !u16 {
        if (self.rx().s2s_listener_fd < 0) return error.Unsupported;
        return socketPort(self.rx().s2s_listener_fd);
    }

    pub fn tlsBoundPort(self: *LinuxServer) !u16 {
        if (self.rx().tls_listener_fd < 0) return error.Unsupported;
        return socketPort(self.rx().tls_listener_fd);
    }

    /// Process at least one io_uring completion. Callers may loop this until
    /// their own stop condition is satisfied.
    pub fn runOnce(self: *LinuxServer) !void {
        // Bind this thread to its reactor so every handler's rx() resolves to the
        // reactor whose ring produced the completions. A multi-reactor worker has
        // already bound its own shard before looping (so we never clobber it);
        // single-reactor callers and direct-test invocations bind shard 0 here.
        if (current_reactor == null) current_reactor = &self.reactors[0];
        try self.armAccept();
        self.armWake() catch {}; // cross-reactor wake poll; non-fatal if it can't arm
        self.armTimer() catch {}; // periodic timeout sweep; non-fatal if it can't arm
        _ = try self.rx().ring.submitAndWait(1);

        var handler = CompletionHandler{ .server = self };
        var cqes: [ringlane.default_cqe_batch]linux.io_uring_cqe = undefined;
        _ = try self.rx().ring.reapCompletions(&cqes, 0, &handler);
        if (handler.err) |err| return err;

        // Belt-and-suspenders against a lost wake: drain any cross-shard handoffs
        // addressed to this reactor every iteration, not only on the wake-poll
        // completion. Cheap when empty (one lock-free pop returning 0). Each
        // reactor drains only its own mailbox into its own connections, so this is
        // reactor-local and needs no world lock. No-op in single-reactor mode.
        if (self.fabric != null) self.drainFabric();

        _ = try self.rx().ring.submit();
    }

    pub fn boundPort(self: *LinuxServer) !u16 {
        return socketPort(self.rx().listener_fd);
    }

    /// Run the reactor loop on the calling thread until `run` is cleared. Wakes
    /// on each io_uring completion and re-checks the flag, so a client
    /// disconnect (or any I/O) lets a requested shutdown take effect. (T1 of the
    /// threading plan — docs/planning/06-threading.md.)
    pub fn runThreaded(self: *LinuxServer, run: *std.atomic.Value(bool)) void {
        self.shutdown = run; // expose to DIE/RESTART

        // Single reactor: run the loop in-line on the calling thread, byte-identical
        // to the historical path (no pool, no fabric, no extra threads).
        if (self.reactors.len <= 1) {
            current_reactor = &self.reactors[0];
            while (run.load(.acquire)) {
                self.runOnce() catch return;
            }
            return;
        }

        // Multi-reactor: stand up the shared cross-shard delivery fabric (one
        // mailbox + wake per shard, one shared buffer pool), then spawn one worker
        // thread per shard. Each worker owns exactly one reactor for its lifetime.
        // If the fabric cannot be created (no eventfd, OOM) fall back to a single
        // in-line reactor rather than running without cross-shard delivery.
        self.fabric = reactor_fabric.ReactorFabric.init(self.allocator, self.reactors.len) catch |err| {
            std.debug.print(
                "mizuchi: cross-shard fabric init failed ({s}); running 1 reactor\n",
                .{@errorName(err)},
            );
            current_reactor = &self.reactors[0];
            while (run.load(.acquire)) {
                self.runOnce() catch return;
            }
            return;
        };

        std.debug.print("mizuchi: starting {d} reactor threads (SO_REUSEPORT)\n", .{self.reactors.len});
        self.pool.start(self.reactors.len, self, run, reactorWorker) catch |err| {
            std.debug.print(
                "mizuchi: reactor pool spawn failed ({s}); running 1 reactor\n",
                .{@errorName(err)},
            );
            if (self.fabric) |*f| f.deinit();
            self.fabric = null;
            current_reactor = &self.reactors[0];
            while (run.load(.acquire)) {
                self.runOnce() catch return;
            }
            return;
        };
        // Block here until the run flag clears and every worker has exited, so the
        // caller's `runThreaded` returning means the daemon has fully stopped.
        self.pool.join();
    }

    /// One reactor worker thread: bind this thread to its shard's reactor, then
    /// loop `runOnce` (which arms accept/wake/timer and reaps completions) until
    /// the shared run flag clears. Each worker touches only its own reactor's ring
    /// and connection slab; cross-shard work crosses via the fabric.
    fn reactorWorker(self: *LinuxServer, shard: u12, run: *reactor_pool_mod.RunFlag) void {
        current_reactor = &self.reactors[shard];
        while (run.load(.acquire)) {
            self.runOnce() catch return;
        }
    }

    pub fn handleAccept(self: *LinuxServer, event: ringlane.AcceptEvent) !void {
        const is_s2s = event.token.slot == s2s_listener_token.slot;
        const is_tls = event.token.slot == tls_listener_token.slot;
        if (!event.more) {
            if (is_s2s) {
                self.rx().s2s_accept_armed = false;
            } else if (is_tls) {
                self.rx().tls_accept_armed = false;
            } else {
                self.rx().accept_armed = false;
            }
        }
        if (event.res < 0) return error.BadCompletion;

        const fd: linux.fd_t = event.res;
        errdefer closeFd(fd);

        // Refuse past the reserved cap: alloc beyond capacity would realloc the
        // slot array and move ConnState buffers out from under in-flight I/O.
        if (self.rx().clients.len() >= self.config.max_clients) {
            closeFd(fd);
            return;
        }

        const id = try self.rx().clients.alloc(ConnState.init(fd));
        // Free the slot on any later failure so a half-set-up accept never leaves
        // an occupied slot (which deinit would then try to tear down).
        errdefer _ = self.rx().clients.free(id);
        const conn = self.rx().clients.get(id).?;
        conn.token = try tokenFromId(id);
        conn.connected_at_ms = self.nowMs();
        conn.last_activity_ms = conn.connected_at_ms;

        if (is_s2s and self.s2sSecured()) {
            // PQ-secured peer: stand up a SecuredLink (responder). Its TOFU prekey
            // preamble is already queued; send it and wait for the initiator's M1.
            const link = try self.newSecuredLink(.responder);
            errdefer {
                link.deinit();
                self.allocator.destroy(link);
            }
            conn.s2s_secured = link;
            errdefer conn.s2s_secured = null;
            const out = link.outbound();
            if (out.len != 0) {
                try appendToConn(conn, out);
                link.clearOutbound();
            }
            try self.armSendIfNeeded(conn);
            try self.rx().ring.submitRecv(conn.token, conn.fd, &conn.recv_buf);
            self.stats.onS2sAccept();
            self.traceLog(.info, .s2s, "s2s secured peer accepted");
            return;
        }
        if (is_s2s) {
            // Server-to-server peer: stand up an S2sLink and wait for its inbound
            // handshake (the connecting side opens it; we respond on recv).
            const link = try self.allocator.create(s2s_link.S2sLink);
            errdefer self.allocator.destroy(link);
            try link.init(.{
                .allocator = self.allocator,
                .local_node_id = self.config.node_id,
                // remote_node_id is learned from the inbound handshake.
                .remote_node_id = 0,
                .local_epoch_ms = @intCast(@max(0, platform.realtimeMillis())),
                .server_name = server_name,
            });
            errdefer link.deinit();
            conn.s2s = link;
            // Clear the dangling pointer before the slot is freed if submitRecv
            // fails, so deinit can never observe a freed link.
            errdefer conn.s2s = null;
            try self.rx().ring.submitRecv(conn.token, conn.fd, &conn.recv_buf);
            self.stats.onS2sAccept();
            self.traceLog(.info, .s2s, "s2s peer accepted");
            return;
        }

        if (is_tls) {
            // Implicit-TLS client. Refusals MUST be silent here: a plaintext IRC
            // ERROR sent to a peer mid-TLS-handshake is protocol garbage, so we
            // gate then close the fd directly rather than queueing a message.
            self.captureClientHost(conn);
            var refuse = self.draining;
            if (!refuse and self.reputationOn()) {
                if (conn.peer_addr) |addr| {
                    if (self.reputation.shouldRefuse(addr, self.nowU64())) refuse = true;
                }
            }
            if (!refuse) {
                if (conn.peer_addr) |addr| {
                    if (self.clone_limit.register(addr)) {
                        conn.clone_counted = true;
                    } else |err| switch (err) {
                        error.TooManyPerIp, error.TooManyPerNet => {
                            self.penalizePeer(conn, self.config.clone_refuse_penalty);
                            refuse = true;
                        },
                        error.NoSpaceLeft => {},
                    }
                }
            }
            if (refuse) {
                closeFd(conn.fd);
                _ = self.rx().clients.free(id);
                self.stats.onAccept();
                return;
            }
            // Stand up the per-connection TLS engine; the IRC layer above sees
            // only decrypted plaintext once the handshake completes.
            const tls = try self.allocator.create(tls_conn.TlsConn);
            tls.* = tls_conn.TlsConn.init(self.allocator, .{
                .cert_chain = self.config.tls_cert_chain,
                .signing_key = self.config.tls_signing_key.?,
                .request_client_cert = self.config.tls_request_client_cert,
            }) catch {
                self.allocator.destroy(tls);
                closeFd(conn.fd);
                _ = self.rx().clients.free(id);
                self.stats.onAccept();
                return;
            };
            errdefer {
                tls.deinit();
                self.allocator.destroy(tls);
            }
            conn.tls = tls;
            conn.is_tls = true;
            self.injectSessionState(conn);
            try self.rx().ring.submitRecv(conn.token, conn.fd, &conn.recv_buf);
            self.stats.onAccept();
            self.traceLog(.info, .net, "tls client accepted");
            return;
        }

        // Capture the peer host (real + auto-cloak) before the client registers,
        // so its first JOIN/PRIVMSG prefix already carries the cloaked host.
        self.captureClientHost(conn);

        // Drain mode: refuse new client connections (oper-initiated maintenance).
        if (self.draining) {
            appendToConn(conn, ":" ++ server_name ++ " ERROR :Server is draining; try again later\r\n") catch {};
            conn.close_reason = "Server draining";
            conn.closing = true;
            self.armSendIfNeeded(conn) catch {};
            self.stats.onAccept();
            return;
        }

        // IP reputation: refuse a peer whose decaying penalty score has reached
        // the configured threshold (drain-close, same as clone refusal).
        if (self.reputationOn()) {
            if (conn.peer_addr) |addr| {
                if (self.reputation.shouldRefuse(addr, self.nowU64())) {
                    appendToConn(conn, ":" ++ server_name ++ " ERROR :Connection refused (reputation)\r\n") catch {};
                    conn.close_reason = "Reputation";
                    conn.closing = true;
                    self.armSendIfNeeded(conn) catch {};
                    self.stats.onAccept();
                    return;
                }
            }
        }

        // Clone limiting: count this connection against its IP / prefix. Over the
        // cap, tell the client and drain-close WITHOUT arming recv — the queued
        // ERROR flushes via handleSend, which then closeConn's the slot. The
        // connection was never counted, so closeConn performs no release.
        if (conn.peer_addr) |addr| {
            if (self.clone_limit.register(addr)) {
                conn.clone_counted = true;
            } else |err| switch (err) {
                error.TooManyPerIp, error.TooManyPerNet => {
                    self.penalizePeer(conn, self.config.clone_refuse_penalty);
                    appendToConn(conn, ":" ++ server_name ++ " ERROR :Too many connections from your host\r\n") catch {};
                    conn.close_reason = "Too many connections";
                    conn.closing = true;
                    self.armSendIfNeeded(conn) catch {};
                    self.stats.onAccept();
                    return;
                },
                error.NoSpaceLeft => {}, // tracking table OOM: fail open, allow the client
            }
        }

        // Make the injected SASL verifiers available before the client can send
        // AUTHENTICATE (during CAP negotiation, pre-registration).
        self.injectSessionState(conn);
        try self.rx().ring.submitRecv(conn.token, conn.fd, &conn.recv_buf);
        self.stats.onAccept();
        self.traceLog(.info, .net, "client accepted");
    }

    /// Capture the peer's IP at accept: record it as the real host and, when a
    /// cloak key is configured, set the visible host to its HMAC cloak so other
    /// users never see the raw address. Best-effort: any failure leaves the host
    /// fields empty and the prefix path falls back to the default host.
    fn captureClientHost(self: *LinuxServer, conn: *ConnState) void {
        var storage: posix.sockaddr.storage = undefined;
        var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        const rc = linux.getpeername(conn.fd, @ptrCast(&storage), &len);
        if (posix.errno(rc) != .SUCCESS) return;
        const sa: *const posix.sockaddr = @ptrCast(@alignCast(&storage));
        var ipbuf: [cloak.max_cloak_len]u8 = undefined;
        const ip = switch (sa.family) {
            posix.AF.INET => blk: {
                const in: *const posix.sockaddr.in = @ptrCast(@alignCast(&storage));
                const b: [4]u8 = @bitCast(in.addr);
                conn.peer_addr = .{ .ipv4 = b };
                break :blk std.fmt.bufPrint(&ipbuf, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch return;
            },
            posix.AF.INET6 => blk: {
                const in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(&storage));
                conn.peer_addr = .{ .ipv6 = in6.addr };
                break :blk formatIp6(&ipbuf, in6.addr) catch return;
            },
            else => return,
        };
        // Loopback connections display as the conventional "localhost" (cloaking
        // a 127.x / ::1 address is pointless and noisy).
        if (std.mem.startsWith(u8, ip, "127.") or std.mem.eql(u8, ip, "0:0:0:0:0:0:0:1")) {
            conn.session.setRealHost(default_host);
            conn.session.setVisibleHost(default_host);
            return;
        }
        conn.session.setRealHost(ip);
        if (self.config.cloak_key) |key| {
            var cbuf: [cloak.max_cloak_len]u8 = undefined;
            const cloaked = cloak.cloak(&cbuf, &key, ip, .{}) catch {
                conn.session.setVisibleHost(ip);
                return;
            };
            conn.session.setVisibleHost(cloaked);
        } else {
            conn.session.setVisibleHost(ip);
        }
    }

    /// Drive a server-to-server peer connection: feed inbound bytes to its
    /// S2sLink and queue any outbound frames the link produced for sending.
    /// Monotonic time in ms, routed through the reactor seam when one is injected
    /// (deterministic simulation), else the system monotonic clock.
    fn nowMs(self: *const LinuxServer) i64 {
        return if (self.reactor) |r| r.nowMillis() else platform.monotonicMillis();
    }

    /// Monotonic ms as a non-negative u64 (the reputation table's clock type).
    fn nowU64(self: *const LinuxServer) u64 {
        return @intCast(@max(0, self.nowMs()));
    }

    /// Whether IP reputation is active (a non-zero refuse threshold configured).
    fn reputationOn(self: *const LinuxServer) bool {
        return self.config.reputation_refuse_threshold != 0;
    }

    /// Add `points` of penalty to a peer's reputation (no-op when disabled or the
    /// peer address is unknown). Best-effort: decay-math errors are swallowed.
    fn penalizePeer(self: *LinuxServer, conn: *const ConnState, points: f64) void {
        if (!self.reputationOn()) return;
        if (conn.peer_addr) |addr| {
            _ = self.reputation.penalize(addr, points, self.nowU64()) catch {};
        }
    }

    /// Bands/features advertised by this node's S2S prekeys.
    const s2s_bands: u128 = 0b1111;
    const s2s_features: u128 = 0b1;

    /// True when PQ-secured S2S is configured (node identity + a CSPRNG io).
    fn s2sSecured(self: *const LinuxServer) bool {
        return self.config.node_identity != null and self.config.crypto_io != null;
    }

    /// Build a heap-owned SecuredLink for `role`, using a freshly-derived prekey.
    /// Validity uses the wall clock so the window is comparable across nodes.
    fn newSecuredLink(self: *LinuxServer, role: secured_s2s_link.Role) !*secured_s2s_link.SecuredLink {
        const ident = self.config.node_identity.?;
        const wall: u64 = @intCast(@max(0, platform.realtimeMillis()));
        // Back-date not_before so a peer that captured its verify-clock slightly
        // earlier (connect/accept ordering + modest skew) still sees the prekey as
        // valid; the validity window stays long via the ttl.
        const not_before = wall -| (5 * 60 * 1000);
        const prekey = try ident.signedPrekey(1, not_before, 24 * 60 * 60 * 1000, s2s_bands, s2s_features);
        const link = try self.allocator.create(secured_s2s_link.SecuredLink);
        errdefer self.allocator.destroy(link);
        link.* = try secured_s2s_link.SecuredLink.init(.{
            .allocator = self.allocator,
            .role = role,
            .identity = ident,
            .local_prekey = prekey,
            .cfg = .{
                .realm = ident.realm,
                .supported_bands = s2s_bands,
                .supported_features = s2s_features,
                .mesh_pass = self.config.mesh_pass,
                .now_ms = wall,
            },
            .rng = self.config.crypto_io.?,
            .server_name = server_name,
            .local_epoch_ms = wall,
        });
        return link;
    }

    /// Drive a PQ-secured S2S peer: feed inbound bytes through the framed Tsumugi
    /// link and queue its outbound. Logs the AKE establishment transition.
    fn driveS2sSecured(self: *LinuxServer, conn: *ConnState, link: *secured_s2s_link.SecuredLink, bytes: []const u8) void {
        const was = link.established();
        const now: u64 = @intCast(@max(0, self.nowMs()));
        link.feed(bytes, now) catch {
            conn.closing = true;
            return;
        };
        const out = link.outbound();
        if (out.len != 0) {
            appendToConn(conn, out) catch {
                conn.closing = true;
                return;
            };
            link.clearOutbound();
        }
        if (!was and link.established()) self.traceLog(.info, .s2s, "s2s secured link established");
        // Drain inbound cross-node user messages over the secured link.
        if (link.takeInbound()) |inbound| {
            for (inbound) |*owned| {
                self.deliverRelay(owned.msg);
                owned.deinit(self.allocator);
            }
            self.allocator.free(inbound);
        } else |_| {}
        if (!conn.s2s_burst_done and link.established()) {
            conn.s2s_burst_done = true;
            self.sendMembershipBurstTo(conn); // #65: roster burst to the new peer
        }
    }

    fn driveS2s(self: *LinuxServer, conn: *ConnState, link: *s2s_link.S2sLink, bytes: []const u8) void {
        self.s2s_feed_seq +%= 1;
        const now: u64 = @intCast(@max(0, self.nowMs()));
        link.feed(bytes, now, self.s2s_feed_seq) catch {
            conn.closing = true;
            return;
        };
        const out = link.outbound();
        if (out.len != 0) {
            appendToConn(conn, out) catch {
                conn.closing = true;
                return;
            };
            link.clearOutbound();
        }
        // Drain inbound cross-node user messages and deliver to local clients.
        if (link.takeInbound()) |inbound| {
            for (inbound) |*owned| {
                self.deliverRelay(owned.msg);
                owned.deinit(self.allocator);
            }
            self.allocator.free(inbound);
        } else |_| {}
        if (!conn.s2s_burst_done and link.established()) {
            conn.s2s_burst_done = true;
            self.sendMembershipBurstTo(conn); // #65: roster burst to the new peer
        }
    }

    /// Completion for an outbound S2S connect: on success open the handshake from
    /// our side and start receiving; on failure tear the peer down.
    pub fn handleConnect(self: *LinuxServer, event: ringlane.ConnectEvent) !void {
        const conn = self.connForToken(event.token) catch return;
        if (event.res < 0) {
            try self.closeConn(event.token, "S2S connect failed");
            return;
        }
        if (conn.s2s_secured) |_| {
            // Secured initiator: just listen — the responder sends its prekey
            // preamble first, which drives the handshake on recv.
            try self.rx().ring.submitRecv(conn.token, conn.fd, &conn.recv_buf);
            return;
        }
        const link = conn.s2s orelse return;
        const now: u64 = @intCast(@max(0, self.nowMs()));
        link.start(now) catch {
            try self.closeConn(event.token, "S2S handshake failed");
            return;
        };
        const out = link.outbound();
        if (out.len != 0) {
            appendToConn(conn, out) catch {
                try self.closeConn(event.token, "S2S send overflow");
                return;
            };
            link.clearOutbound();
        }
        try self.armSendIfNeeded(conn);
        try self.rx().ring.submitRecv(conn.token, conn.fd, &conn.recv_buf);
    }

    pub fn handleRecv(self: *LinuxServer, event: ringlane.RecvEvent) !void {
        const id = idFromToken(event.token);
        const conn = try self.connForToken(event.token);
        conn.closing = event.res <= 0;
        if (event.res > 0) {
            const chunk = conn.recv_buf[0..@as(usize, @intCast(event.res))];
            self.stats.onBytesIn(chunk.len);
            // Any inbound traffic proves liveness: refresh the idle clock and
            // clear a pending ping-timeout (the client answered, PONG or not).
            conn.last_activity_ms = self.nowMs();
            conn.awaiting_pong = false;
            if (conn.s2s_secured) |link| {
                self.driveS2sSecured(conn, link, chunk);
            } else if (conn.s2s) |link| {
                self.driveS2s(conn, link, chunk);
            } else if (conn.tls != null) {
                try self.driveTls(id, conn, chunk);
            } else {
                try self.feedBytes(id, conn, chunk);
            }
            try self.armSendIfNeeded(conn);
            if (!conn.closing) {
                try self.rx().ring.submitRecv(conn.token, conn.fd, &conn.recv_buf);
            }
        }
        if (conn.closing and !conn.send_armed and conn.send_len == conn.send_offset) {
            try self.closeConn(event.token, conn.close_reason);
        }
    }

    pub fn handleSend(self: *LinuxServer, event: ringlane.SendEvent) !void {
        const conn = try self.connForToken(event.token);
        conn.send_armed = false;
        if (event.res < 0) {
            try self.closeConn(event.token, conn.close_reason);
            return;
        }

        self.stats.onBytesOut(@as(usize, @intCast(event.res)));
        conn.send_offset += @as(usize, @intCast(event.res));
        if (conn.send_offset >= conn.send_len) {
            conn.send_offset = 0;
            conn.send_len = 0;
        }

        try self.armSendIfNeeded(conn);
        if (conn.closing and !conn.send_armed and conn.send_len == conn.send_offset) {
            try self.closeConn(event.token, conn.close_reason);
        }
    }

    /// The single cross-shard-aware outbound byte sink. Every "write a finished
    /// line (or lines) to the connection behind `id`" path funnels here so the
    /// shard decision is made in exactly one place:
    ///
    ///   * `id` on THIS reactor's shard  → append to its local send buffer and arm
    ///     send, exactly as the single-reactor path always did (no copy, no lock).
    ///   * `id` on ANOTHER shard          → copy the bytes into pooled `DeliverBuf`s
    ///     (chunked to the pool's per-buffer max, FIFO-ordered), hand each off to
    ///     the owning shard's fabric mailbox, and wake that reactor. The target
    ///     reactor drains its mailbox in `onWakePoll`, appends to the local conn,
    ///     and releases the buffer. A connection's send buffer / ring is therefore
    ///     never touched by a non-owning reactor.
    ///
    /// Returns `error.ClientNotFound` only for a LOCAL miss (stale/closed slot);
    /// a cross-shard handoff cannot see the target's liveness, so it best-effort
    /// enqueues and the owning reactor drops the bytes if the slot is gone.
    fn enqueueDelivery(self: *LinuxServer, id: client_model.ClientId, bytes: []const u8) !void {
        // Local fast path (always taken in single-reactor mode, where shard_id==0
        // and every id carries shard 0).
        if (id.shard == self.rx().shard_id) {
            const conn = self.rx().clients.get(id) orelse return error.ClientNotFound;
            if (conn.closing) return;
            try appendToConn(conn, bytes);
            try self.armSendIfNeeded(conn);
            return;
        }
        // Cross-shard: hand off through the fabric. Absent a fabric (should not
        // happen while multiple reactors run) the bytes are dropped rather than
        // touching another reactor's connection.
        const fabric = if (self.fabric) |*f| f else return;
        var off: usize = 0;
        while (off < bytes.len) {
            const end = @min(off + deliver_handle.max_bytes, bytes.len);
            const chunk = bytes[off..end];
            // Retry acquire on momentary pool exhaustion; the target drains
            // continuously so a buffer frees shortly. Bounded so a wedged target
            // cannot spin this forever.
            var spins: usize = 0;
            const buf = while (true) {
                if (fabric.acquire(chunk)) |b| break b;
                spins += 1;
                if (spins > 4096) return; // give up on this chunk; never block the reactor
                std.atomic.spinLoopHint();
            };
            // Likewise retry a full inbox briefly, then drop to avoid a stall.
            var pushed = false;
            var psp: usize = 0;
            while (psp < 4096) : (psp += 1) {
                if (fabric.sendTo(id.shard, .{ .to = id, .buf = buf })) {
                    pushed = true;
                    break;
                }
                std.atomic.spinLoopHint();
            }
            if (!pushed) {
                fabric.release(buf);
                return;
            }
            off = end;
        }
        // Wake the OWNING reactor through its own wake eventfd (the one it arms a
        // poll on each loop). Its wake-poll completion runs `drainFabric`, which
        // consumes the mailbox we just pushed to. We deliberately do not use the
        // fabric's own wake fds: the reactor loop only watches `Reactor.wake`, so
        // unifying on it reuses the existing arm/poll plumbing.
        if (self.reactors[id.shard].wake) |*w| w.wake();
    }

    fn deliver(self: *LinuxServer, id: client_model.ClientId, bytes: []const u8) !void {
        return self.enqueueDelivery(id, bytes);
    }

    /// Shard-aware equivalent of `queueNumeric` + arm: format the numeric for the
    /// connection behind `id` (using its display name read from the owning reactor
    /// under the world lock) and route the bytes through `enqueueDelivery` (local
    /// append or cross-shard fabric handoff). Use this wherever a numeric must go
    /// to a connection that is NOT the one currently being processed and may live
    /// on another shard.
    fn deliverNumeric(
        self: *LinuxServer,
        id: client_model.ClientId,
        code: Numeric,
        params: []const []const u8,
        trailing: []const u8,
    ) !void {
        const target = self.connFor(id) orelse return;
        if (target.closing) return;
        var line_buf: [default_reply_bytes]u8 = undefined;
        const line = try formatNumericLine(&line_buf, target.session.displayName(), code, params, trailing);
        try self.enqueueDelivery(id, line);
    }

    /// Look up the connection behind `id` on its OWNING reactor's slab, whatever
    /// shard that is. Safe for READ-ONLY inspection of the connection's session
    /// (caps, away, umodes, display name): every such field is mutated only while
    /// holding `world.lockWrite`, which brackets the whole completion, so a read
    /// here is serialized against that connection's own command processing. NEVER
    /// write to a returned foreign connection's send buffer or arm its ring — that
    /// is its reactor's job; route bytes there through `enqueueDelivery`.
    fn connFor(self: *LinuxServer, id: client_model.ClientId) ?*ConnState {
        if (id.shard >= self.reactors.len) return null;
        return self.reactors[id.shard].clients.get(id);
    }

    /// Deliver `bytes` (a complete `:prefix ...` line), prepending the IRCv3
    /// server-time `tag` for recipients that negotiated the server-time cap.
    /// `tag` is precomputed once per event so all recipients share a timestamp.
    fn deliverTimed(self: *LinuxServer, id: client_model.ClientId, tag: []const u8, bytes: []const u8) !void {
        const conn = self.connFor(id) orelse return error.ClientNotFound;
        if (conn.closing) return;
        // Cap inspection is a serialized read of the owning reactor's session; the
        // byte handoff below routes to that reactor (local append or fabric).
        if (tag.len != 0 and conn.session.hasCap(.server_time)) {
            // Concatenate so the tag + line cross the shard boundary as one ordered
            // unit (two enqueues could interleave a foreign reactor's drain).
            if (id.shard != self.rx().shard_id) {
                var joined: [default_reply_bytes]u8 = undefined;
                if (tag.len + bytes.len <= joined.len) {
                    @memcpy(joined[0..tag.len], tag);
                    @memcpy(joined[tag.len .. tag.len + bytes.len], bytes);
                    return self.enqueueDelivery(id, joined[0 .. tag.len + bytes.len]);
                }
            }
            try self.enqueueDelivery(id, tag);
        }
        try self.enqueueDelivery(id, bytes);
    }

    /// Per-event message tags available to attach (server-time value WITHOUT the
    /// `@time=` already formatted, and the sender's account if logged in). The
    /// actual `@k=v;k=v ` segment is assembled PER RECIPIENT from the caps they
    /// negotiated, so a client gets exactly the tags it asked for in one segment.
    const MsgTags = struct {
        time_value: []const u8, // ISO-8601, e.g. "2026-06-04T..Z" (no key)
        account: ?[]const u8, // sender's account, or null when not logged in
        /// Sender's raw IRCv3 tag segment (no leading '@'); only its client-only
        /// (`+...`) tags are relayed, to recipients negotiating message-tags.
        client_tags: ?[]const u8 = null,
        /// Server-minted `msgid` value (no `msgid=` key), shared by every
        /// recipient of this message. Null for events that carry no msgid.
        msgid: ?[]const u8 = null,
    };

    /// Deliver `bytes` with an IRCv3 message-tag segment assembled for THIS
    /// recipient: `@time=…;account=… ` including only the tags whose caps the
    /// recipient negotiated. Used by the PRIVMSG/NOTICE/TAGMSG paths.
    fn deliverTagged(self: *LinuxServer, id: client_model.ClientId, tags: MsgTags, bytes: []const u8) !void {
        const conn = self.connFor(id) orelse return error.ClientNotFound;
        if (conn.closing) return;
        // Sized for the full @-segment: server-time + account + msgid + relayed
        // client-only tags. Built from a serialized read of the owning reactor's
        // negotiated caps; the bytes then route to that reactor via enqueueDelivery.
        var tagbuf: [256]u8 = undefined;
        const prefix = buildTagPrefix(&conn.session, tags, &tagbuf);
        if (prefix.len != 0 and id.shard != self.rx().shard_id) {
            // Cross-shard: send prefix + line as one ordered unit.
            var joined: [default_reply_bytes]u8 = undefined;
            if (prefix.len + bytes.len <= joined.len) {
                @memcpy(joined[0..prefix.len], prefix);
                @memcpy(joined[prefix.len .. prefix.len + bytes.len], bytes);
                return self.enqueueDelivery(id, joined[0 .. prefix.len + bytes.len]);
            }
        }
        if (prefix.len != 0) try self.enqueueDelivery(id, prefix);
        try self.enqueueDelivery(id, bytes);
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

    /// Forward a cross-node user message to every established S2S peer except
    /// `skip`. Loop-guarded per-peer by (origin_node, hlc). Best-effort: a full
    /// link buffer never faults the local delivery that triggered it.
    /// Which peers a relayed message should go to, narrowed via route_table so we
    /// don't broadcast every message to the whole mesh.
    const RelayScope = union(enum) {
        all,
        channel: []const u8, // only peers that announced members of this channel
        nick: []const u8, // only the peer whose route_table owns this nick
    };

    /// Forward a relayed message to the peers selected by `scope`. Returns the
    /// number of peer links it was sent to (so callers can fall back to a wider
    /// scope when a targeted route is not yet known).
    fn relayToPeers(self: *LinuxServer, msg: s2s_link.RelayMessage, scope: RelayScope) usize {
        var sent: usize = 0;
        for (self.rx().clients.slots.items) |*slot| {
            if (!slot.occupied) continue;
            const c = &slot.value;
            if (c.s2s_secured) |link| {
                if (!link.established()) continue;
                if (!relayWanted(link, scope)) continue;
                link.sendMessage(msg) catch continue;
                self.flushS2sOutbound(c, link.outbound()) catch continue;
                link.clearOutbound();
                sent += 1;
            } else if (c.s2s) |link| {
                if (!link.established()) continue;
                if (!relayWanted(link, scope)) continue;
                link.sendMessage(msg) catch continue;
                self.flushS2sOutbound(c, link.outbound()) catch continue;
                link.clearOutbound();
                sent += 1;
            }
        }
        return sent;
    }

    /// Per-link scope test (duck-typed over S2sLink / SecuredLink — both expose
    /// channelMembers + routeNickNode).
    fn relayWanted(link: anytype, scope: RelayScope) bool {
        return switch (scope) {
            .all => true,
            .channel => |ch| link.channelMembers(ch).len > 0,
            .nick => |nk| link.routeNickNode(nk) != null,
        };
    }

    /// True if any S2S peer link (secured or plaintext) is established — used to
    /// decide whether an unknown-local nick might be reachable across the mesh.
    fn hasEstablishedPeer(self: *LinuxServer) bool {
        for (self.rx().clients.slots.items) |*slot| {
            if (!slot.occupied) continue;
            if (slot.value.s2s_secured) |l| {
                if (l.established()) return true;
            } else if (slot.value.s2s) |l| {
                if (l.established()) return true;
            }
        }
        return false;
    }

    /// Deliver an inbound relayed user message to LOCAL recipients (channel
    /// members or a local nick), then re-forward to other peers for multi-hop
    /// (loop-guarded by the per-peer seen-set + origin id).
    fn deliverRelay(self: *LinuxServer, msg: s2s_link.RelayMessage) void {
        // Global mesh-wide dedup (handles cross-path duplicates in a cyclic mesh).
        if (self.relay_seen.observe(msg.origin_node, msg.hlc)) return;
        const verb = switch (msg.verb) {
            .privmsg => "PRIVMSG",
            .notice => "NOTICE",
            .tagmsg => "TAGMSG",
        };
        var line_buf: [default_reply_bytes]u8 = undefined;
        const line = if (msg.verb == .tagmsg)
            (if (msg.tags.len > 0)
                std.fmt.bufPrint(&line_buf, "@{s} :{s} TAGMSG {s}\r\n", .{ msg.tags, msg.source_prefix, msg.target }) catch return
            else
                std.fmt.bufPrint(&line_buf, ":{s} TAGMSG {s}\r\n", .{ msg.source_prefix, msg.target }) catch return)
        else if (msg.tags.len > 0)
            std.fmt.bufPrint(&line_buf, "@{s} :{s} {s} {s} :{s}\r\n", .{ msg.tags, msg.source_prefix, verb, msg.target, msg.text }) catch return
        else
            std.fmt.bufPrint(&line_buf, ":{s} {s} {s} :{s}\r\n", .{ msg.source_prefix, verb, msg.target, msg.text }) catch return;

        if (world_model.isChannelName(msg.target)) {
            if (self.world.memberIterator(msg.target)) |*it| {
                var members = it.*;
                while (members.next()) |member| {
                    self.deliver(clientIdFromWorld(member.*), line) catch {};
                }
            }
        } else if (self.world.findNick(msg.target)) |wid| {
            self.deliver(clientIdFromWorld(wid), line) catch {};
        }
        // Multi-hop re-forward, scoped via route_table (global seen-set already
        // deduped, so re-forwarding the source link is harmless).
        const scope: RelayScope = if (world_model.isChannelName(msg.target))
            .{ .channel = msg.target }
        else
            .{ .nick = msg.target };
        if (self.relayToPeers(msg, scope) == 0 and !world_model.isChannelName(msg.target)) {
            _ = self.relayToPeers(msg, .all); // unknown nick route → widen for multi-hop
        }
    }

    fn armSendIfNeeded(self: *LinuxServer, conn: *ConnState) !void {
        if (conn.send_armed) return;
        if (conn.send_offset >= conn.send_len) return;
        try self.rx().ring.submitSend(conn.token, conn.fd, conn.send_buf[conn.send_offset..conn.send_len]);
        conn.send_armed = true;
    }

    fn connForToken(self: *LinuxServer, token: RingFdToken) ServerError!*ConnState {
        return self.rx().clients.get(idFromToken(token)) orelse error.ClientNotFound;
    }

    /// Apply server-injected per-session state on a freshly accepted client
    /// before it can negotiate: the SASL verifiers (PLAIN fat-pointer checker;
    /// SCRAM additionally needs a per-connection CSPRNG hex server nonce —
    /// printable + comma-free per the SCRAM grammar) and the STS policy (so the
    /// `sts` cap is advertised on CAP LS when an operator enabled it).
    fn injectSessionState(self: *LinuxServer, conn: *ConnState) void {
        if (self.config.sasl_checker) |chk| conn.session.sasl_plain = chk;
        if (self.config.sasl_scram256) |scram| {
            if (self.config.crypto_io) |io| {
                var raw: [16]u8 = undefined;
                io.random(&raw);
                var hex: [32]u8 = undefined;
                const charset = "0123456789abcdef";
                for (raw, 0..) |b, i| {
                    hex[i * 2] = charset[b >> 4];
                    hex[i * 2 + 1] = charset[b & 0x0f];
                }
                conn.session.setSaslServerNonce(&hex);
                conn.session.sasl_scram256 = scram;
            }
        }
        if (self.config.sts_value) |v| conn.session.enableSts(v) catch {};
        if (self.config.sasl_external) |ext| conn.session.sasl_external = ext;
    }

    fn closeConn(self: *LinuxServer, token: RingFdToken, reason: []const u8) !void {
        const id = idFromToken(token);
        if (self.rx().clients.get(id)) |conn| {
            // S2S peer: tear down the link, close, free the slot — no IRC quit path.
            if (conn.s2s_secured) |link| {
                self.netsplitOnPeerDrop(conn); // #64: notify locals before the roster is gone
                link.deinit();
                self.allocator.destroy(link);
                conn.s2s_secured = null;
                closeFd(conn.fd);
                _ = self.rx().clients.free(id);
                self.stats.onClose(true);
                return;
            }
            if (conn.s2s) |link| {
                self.netsplitOnPeerDrop(conn); // #64: notify locals before the roster is gone
                link.deinit();
                self.allocator.destroy(link);
                conn.s2s = null;
                closeFd(conn.fd);
                _ = self.rx().clients.free(id);
                self.stats.onClose(true);
                return;
            }
            self.stats.onClose(false);
            self.stats.onQuit();
            // Free any in-flight inbound multiline batch buffer.
            self.abortMultiline(conn);
            // Tear down the per-connection TLS engine, if any.
            if (conn.tls) |t| {
                t.deinit();
                self.allocator.destroy(t);
                conn.tls = null;
            }
            // Release this connection's clone-limiter slot (only if it was counted;
            // refused accepts and addr-less peers never registered).
            if (conn.clone_counted) {
                if (conn.peer_addr) |addr| self.clone_limit.release(addr);
                conn.clone_counted = false;
            }
            self.activity_subs.removeClient(monitorIdFromClient(id));
            // Multi-session: a logged-in client's session is *retained* as
            // detached (for reclaim/bouncer); an anonymous client is dropped.
            if (conn.session.account()) |acct| {
                _ = self.sessions.markDetached(acct, monitorIdFromClient(id));
            } else {
                _ = self.sessions.removeClient(monitorIdFromClient(id));
            }
            defer self.world.removeClient(worldIdFromClient(id));
            // Record only for abrupt drops: a clean QUIT already recorded (and
            // removed the nick) in handleQuit, so skip to avoid a duplicate.
            if (self.world.nickOf(worldIdFromClient(id)) != null) self.recordWhowas(conn);
            // MONITOR: report this nick offline + drop its own subscriptions.
            if (conn.session.registered()) {
                const nick = conn.session.displayName();
                if (!std.mem.eql(u8, nick, "*")) self.monitorOffline(id, nick) catch {};
            }
            // Media: drop the departing nick from any call, notifying members.
            if (conn.session.registered()) self.leaveAllMediaRooms(id, conn);
            // OBSERVE: push a quit record, then drop this client's own subscription.
            if (conn.session.registered()) self.notifyObservers(.quit, observeSubject(conn, reason));
            _ = self.observe.clear(monitorIdFromClient(id));
            try self.broadcastQuit(id, conn, reason);
            closeFd(conn.fd);
            _ = self.rx().clients.free(id);
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

    /// Drive an implicit-TLS client's recv chunk: frame + decrypt through the
    /// per-conn adapter, write any handshake flight back (raw — appendToConn
    /// leaves it unencrypted while the handshake is incomplete), and feed any
    /// decrypted plaintext into the normal line parser. A handshake/record fault
    /// closes only this connection.
    fn driveTls(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, chunk: []const u8) !void {
        const outcome = conn.tls.?.onInbound(chunk) catch {
            conn.closing = true;
            return;
        };
        // Once the mTLS handshake completes, bind the presented client cert's
        // fingerprint to the session so SASL EXTERNAL can match it to an account.
        if (conn.session.tls_certfp == null and conn.tls.?.handshakeDone()) {
            if (conn.tls.?.clientCertDer()) |der| {
                certfp.computeHex(der, &conn.certfp_buf);
                conn.session.tls_certfp = conn.certfp_buf[0..];
            }
        }
        if (outcome.handshake_bytes.len != 0) {
            appendToConn(conn, outcome.handshake_bytes) catch {
                conn.closing = true;
                return;
            };
        }
        if (outcome.plaintext.len != 0) {
            try self.feedBytes(id, conn, outcome.plaintext);
        }
    }

    fn feedBytes(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, bytes: []const u8) !void {
        for (bytes) |byte| {
            if (conn.line_len == conn.line_buf.len) {
                conn.closing = true;
                self.stats.onError();
                return error.LineTooLong;
            }
            conn.line_buf[conn.line_len] = byte;
            conn.line_len += 1;

            if (conn.line_len >= 2 and
                conn.line_buf[conn.line_len - 2] == '\r' and conn.line_buf[conn.line_len - 1] == '\n')
            {
                self.stats.onLine();
                try self.processLiveLine(id, conn, conn.line_buf[0..conn.line_len]);
                conn.line_len = 0;
            }
        }
    }

    fn processLiveLine(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, line: []const u8) !void {
        const parsed = try irc_line.parseLine(line);
        const was_registered = conn.session.registered();

        if (!was_registered) {
            // IRCX discovery must work BEFORE registration (draft-pfenning): an
            // unregistered client probes support via IRCX/ISIRCX/MODE ISIRCX.
            if (std.ascii.eqlIgnoreCase(parsed.command, "IRCX")) {
                try self.handleIrcx(conn, true);
                return;
            }
            if (std.ascii.eqlIgnoreCase(parsed.command, "ISIRCX")) {
                try self.handleIrcx(conn, false);
                return;
            }
            if (std.ascii.eqlIgnoreCase(parsed.command, "MODE") and
                parsed.param_count >= 1 and std.ascii.eqlIgnoreCase(parsed.paramSlice()[0], "ISIRCX"))
            {
                try self.handleIrcx(conn, false);
                return;
            }
            // draft/pre-away: a negotiating client may set its AWAY state during
            // the registration handshake. Apply it now so the user is already
            // marked away when registration completes. away-notify fan-out is a
            // no-op here (no channels joined yet).
            if (std.ascii.eqlIgnoreCase(parsed.command, "AWAY") and conn.session.hasCap(.pre_away)) {
                try self.handleAway(id, conn, &parsed);
                return;
            }
            var sink = QueueSink{ .conn = conn };
            try processLine(conn, line, &sink);
            if (conn.session.registered()) {
                try self.registerConnNick(id, conn);
                // SASL-only oper: elevate now if the (SASL-set) account is bound to
                // an operator class. Emits 381 + MODE +o after the welcome burst.
                try self.elevateOperFromAccount(conn);
                self.trackSession(id, conn); // multi-session registry (SASL login)
                try self.deliverTegami(conn); // hand over any offline messages
                // OBSERVE: push a connect record to watching operators.
                self.notifyObservers(.connect, observeSubject(conn, ""));
                // Apply any operator-approved vhost waiting for this account.
                self.maybeApplyApprovedVhost(id, conn);
                // Auto-join the account's configured channels.
                self.applyAutojoin(id, conn);
                self.deliverWelcome(conn);
                self.emitClientRegistered(id, conn);
                self.evaluateNickProtection(conn);
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
        // Refresh the world's wall-clock so a channel created by this command
        // (JOIN/CREATE) gets a correct IRCX CREATION timestamp without the pure
        // world taking a clock dependency.
        self.world.clock_unix = @divFloor(self.nowMs(), 1000);

        // draft/multiline: a negotiating client's `BATCH +ref draft/multiline`
        // and its @batch-tagged PRIVMSG/NOTICE chunks are routed into the
        // per-conn reassembler instead of normal dispatch. Returns true when the
        // line was consumed by the multiline path.
        if (conn.session.hasCap(.multiline)) {
            if (try self.routeMultiline(id, conn, parsed, line)) return;
        }

        // SerpentRegistry module spine (strangler-fig): consult the comptime
        // module registry first. A migrated command is handled here and returns;
        // anything not yet migrated falls through to the legacy chain below.
        {
            var core = module_core.Core{
                .services = .{ .allocator = self.allocator, .config = &self.config },
                .server = self,
                .id = id,
                .conn = conn,
                .parsed = parsed,
                .line = line,
            };
            switch (try module_manifest.Live.dispatch(&core, parsed.command, parsed.paramSlice())) {
                .handled => return,
                .too_few_params => {
                    try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{parsed.command}, "Not enough parameters");
                    return;
                },
                .not_found => {},
            }
        }

        // MizuWasm control-plane plugins: a loaded third-party plugin may own this
        // command. Consulted after the comptime registry misses; empty by default.
        if (self.wasm.count() > 0 and self.wasm.hasCommand(parsed.command)) {
            var wcore = module_core.Core{
                .services = .{ .allocator = self.allocator, .config = &self.config },
                .server = self,
                .id = id,
                .conn = conn,
                .parsed = parsed,
                .line = line,
            };
            const host = wasm_bridge.HostBindings{
                .ctx = &wcore,
                .reply = wasmReplyCb,
                .log = wasmLogCb,
                .now_ms = wasmNowCb,
            };
            switch (self.wasm.dispatch(parsed.command, parsed.paramSlice(), host)) {
                .handled => return,
                .denied => {
                    try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{parsed.command}, "Plugin lacks the required capability");
                    return;
                },
                .trap => {
                    try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{parsed.command}, "Plugin execution trapped");
                    return;
                },
                .not_found => {},
            }
        }

        // Residual: commands not (yet) owned by a SerpentRegistry module.
        // Everything above has been migrated into src/daemon/modules/* and is
        // dispatched by the registry block at the top of this function.
        if (std.ascii.eqlIgnoreCase(parsed.command, "SUMMON")) {
            try queueNumeric(conn, .ERR_SUMMONDISABLED, &.{}, "SUMMON has been disabled");
        } else if (std.ascii.eqlIgnoreCase(parsed.command, "PONG")) {
            // Client heartbeat reply; accepted, no response required.
        } else {
            var sink = QueueSink{ .conn = conn };
            try processLine(conn, line, &sink);
        }
    }

    /// Module-facing numeric reply: lets a SerpentRegistry module emit a numeric
    /// to a client through `Core.reply` without touching server internals.
    pub fn moduleNumeric(self: *LinuxServer, conn: *ConnState, code: Numeric, params: []const []const u8, trailing: []const u8) ServerError!void {
        _ = self;
        try queueNumeric(conn, code, params, trailing);
    }

    /// Module-facing raw line emit (already CRLF-terminated by the caller).
    pub fn moduleRaw(self: *LinuxServer, conn: *ConnState, bytes: []const u8) ServerError!void {
        _ = self;
        try appendToConn(conn, bytes);
    }

    /// Drive a module-lifecycle phase across every enabled module. Hook handlers
    /// (and lifecycle fns) receive `*LinuxServer` as their erased ctx. No module
    /// declares lifecycle fns yet, so this is a no-op walk today — but the spine
    /// is live so a module/plugin can opt in without further server changes.
    fn driveLifecycle(self: *LinuxServer, comptime phase: enum { init, ready }) void {
        inline for (module_manifest.enabled) |m| {
            const fn_opt = switch (phase) {
                .init => m.on_init,
                .ready => m.on_ready,
            };
            if (fn_opt) |f| f(self) catch |err| {
                std.debug.print("mizuchi: module {s} on_{s} failed: {s}\n", .{ m.id, @tagName(phase), @errorName(err) });
            };
        }
    }

    fn driveDeinit(self: *LinuxServer) void {
        inline for (module_manifest.enabled) |m| {
            if (m.on_deinit) |f| f(self);
        }
    }

    /// Fire the informational `client_registered` typed hook for a freshly
    /// welcomed client. Veto is N/A (informational). Errors are swallowed: a
    /// subscriber fault must never break registration.
    fn emitClientRegistered(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState) void {
        var payload = mod_registry.ClientRegisteredPayload{
            .client_id = @as(u64, @bitCast(id)),
            .nick = conn.session.displayName(),
        };
        _ = module_manifest.Live.callHook(.client_registered, self, &payload) catch {};
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
    /// World projection (#6) producer: announce a local member's presence (or
    /// departure) in `channel` to every established S2S peer. Best-effort — a full
    /// link buffer or send-arm failure never faults the local membership change.
    /// On peer-link drop, notify local members with an IRCv3 netsplit BATCH of
    /// QUITs for the remote members that link had announced (instead of letting
    /// them silently vanish from NAMES). Must run BEFORE the link is deinit'd
    /// (it reads the link's remote roster). Best-effort. (#64)
    fn netsplitOnPeerDrop(self: *LinuxServer, conn: *ConnState) void {
        const remote_name = if (conn.s2s_secured) |l| l.remoteName() else if (conn.s2s) |l| l.remoteName() else return;
        var cit = self.world.channelIterator();
        while (cit.next()) |cv| {
            const remote_members = if (conn.s2s_secured) |l|
                l.channelMembers(cv.name)
            else if (conn.s2s) |l|
                l.channelMembers(cv.name)
            else
                &.{};
            if (remote_members.len == 0) continue;

            var ghosts: [32]netsplit_batch.Ghost = undefined;
            var prefixes: [32][160]u8 = undefined;
            var n: usize = 0;
            for (remote_members) |m| {
                if (n >= ghosts.len) break;
                const prefix = std.fmt.bufPrint(&prefixes[n], "{s}!*@{s}", .{ m.nick, remote_name }) catch continue;
                ghosts[n] = .{ .prefix = prefix, .nick = m.nick };
                n += 1;
            }
            if (n == 0) continue;

            var ref_buf: [16]u8 = undefined;
            const ref = netsplit_batch.makeBatchRef(&ref_buf, @intCast(@max(@as(i64, 0), self.nowMs())));
            var batch_buf: [8192]u8 = undefined;
            const batch = netsplit_batch.writeNetsplit(&batch_buf, ref, server_name, remote_name, ghosts[0..n]) catch continue;

            var members = self.world.memberIterator(cv.name) orelse continue;
            while (members.next()) |member| {
                const mid = clientIdFromWorld(member.*);
                const mc = self.connFor(mid) orelse continue;
                if (mc.s2s != null or mc.s2s_secured != null) continue; // skip peer links
                // Route via the shard-aware sink: local append or cross-shard
                // handoff (the batch is chunked to the pool's per-buffer max).
                self.enqueueDelivery(mid, batch) catch continue;
            }
        }
    }

    /// Burst the full local channel-member roster to ONE freshly-established peer
    /// link (the conn's s2s/s2s_secured), so the peer's NAMES/WHO is correct
    /// immediately rather than only after subsequent joins. Best-effort. (#65)
    fn sendMembershipBurstTo(self: *LinuxServer, conn: *ConnState) void {
        const hlc: u64 = @intCast(@max(@as(i64, 0), self.nowMs()));
        var cit = self.world.channelIterator();
        while (cit.next()) |cv| {
            var members = self.world.memberIterator(cv.name) orelse continue;
            while (members.next()) |member| {
                const mconn = self.rx().clients.get(clientIdFromWorld(member.*)) orelse continue;
                if (mconn.s2s != null or mconn.s2s_secured != null) continue; // skip peer links
                const nick = mconn.session.displayName();
                const status: u4 = @truncate((self.world.memberModes(cv.name, member.*) orelse world_model.MemberModes.empty()).bits);
                if (conn.s2s_secured) |link| {
                    link.sendMembership(cv.name, nick, status, hlc, true) catch continue;
                } else if (conn.s2s) |link| {
                    link.sendMembership(cv.name, nick, status, hlc, true) catch continue;
                }
            }
        }
        if (conn.s2s_secured) |link| {
            self.flushS2sOutbound(conn, link.outbound()) catch {};
            link.clearOutbound();
        } else if (conn.s2s) |link| {
            self.flushS2sOutbound(conn, link.outbound()) catch {};
            link.clearOutbound();
        }
    }

    fn announceMembership(self: *LinuxServer, channel: []const u8, nick: []const u8, status: u4, present: bool) void {
        const hlc: u64 = @intCast(@max(@as(i64, 0), self.nowMs()));
        for (self.rx().clients.slots.items) |*slot| {
            if (!slot.occupied) continue;
            if (slot.value.s2s_secured) |link| {
                if (!link.established()) continue;
                link.sendMembership(channel, nick, status, hlc, present) catch continue;
                self.flushS2sOutbound(&slot.value, link.outbound()) catch continue;
                link.clearOutbound();
            } else if (slot.value.s2s) |link| {
                if (!link.established()) continue;
                link.sendMembership(channel, nick, status, hlc, present) catch continue;
                self.flushS2sOutbound(&slot.value, link.outbound()) catch continue;
                link.clearOutbound();
            }
        }
    }

    fn flushS2sOutbound(self: *LinuxServer, conn: *ConnState, out: []const u8) !void {
        if (out.len == 0) return;
        try appendToConn(conn, out);
        try self.armSendIfNeeded(conn);
    }

    /// Append a peer's remote channel members into the NAMES buffer (deduped,
    /// auditorium-filtered; host = origin server name). Returns the new count.
    /// `members` is a borrowed roster from either link type.
    fn addRemoteMembers(
        self: *LinuxServer,
        members_buf: []names_reply.Member,
        prefix_buf: []chanmode.PrefixList,
        count_in: usize,
        is_auditorium: bool,
        viewer_rank: auditorium.Rank,
        remote_name: []const u8,
        members: anytype,
    ) usize {
        _ = self;
        var count = count_in;
        for (members) |rm| {
            if (count >= members_buf.len) break;
            if (nameAlreadyListed(members_buf[0..count], rm.nick)) continue;
            const modes = world_model.MemberModes{ .bits = @as(u8, rm.status) };
            if (is_auditorium and !auditorium.visibleTo(viewer_rank, auditoriumRank(modes))) continue;
            prefix_buf[count] = modes.allPrefixes();
            members_buf[count] = .{
                .prefixes = prefix_buf[count].asSlice(),
                .nick = rm.nick,
                .user = "mesh",
                .host = if (remote_name.len != 0) remote_name else default_host,
            };
            count += 1;
        }
        return count;
    }

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

        // +x AUDITORIUM: a regular member's JOIN is only relayed to ops/voiced
        // (and the joiner itself); ops/voiced joins are relayed to everyone.
        const is_auditorium = self.world.channelHasExtFlag(channel, .auditorium);
        const joiner_wid = self.world.findNick(conn.session.displayName());
        const joiner_rank = if (joiner_wid) |jw|
            auditoriumRank(self.world.memberModes(channel, jw) orelse world_model.MemberModes.empty())
        else
            auditorium.Rank.regular;
        const relay_all = !is_auditorium or auditorium.shouldRelayJoinPart(joiner_rank);

        var members = self.world.memberIterator(channel) orelse return error.NoSuchChannel;
        while (members.next()) |member| {
            if (!relay_all) {
                const is_self = if (joiner_wid) |jw| member.*.eql(jw) else false;
                const mrank = auditoriumRank(self.world.memberModes(channel, member.*) orelse world_model.MemberModes.empty());
                if (!is_self and !auditorium.shouldRelayJoinPart(mrank)) continue;
            }
            const mid = clientIdFromWorld(member.*);
            const mconn = self.connFor(mid) orelse continue;
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
        quiet: bool,
    ) !bool {
        const wid = worldIdFromClient(id);
        const invited = self.world.hasInvite(channel, wid);

        // +S TLS-only: join permitted only over a TLS session (implicit-TLS fact;
        // no STARTTLS). Server opers bypass.
        if (self.world.channelHasFlag(channel, .tls_only) and !conn.is_tls and !conn.session.isOper()) {
            if (!quiet) try queueNumeric(conn, .ERR_SECUREONLYCHAN, &.{channel}, "Cannot join channel (+S) - TLS required");
            return true;
        }

        // +a AUTHONLY (IRCX): only authenticated accounts may join, regardless of
        // invite. Enforced before all other gates.
        if (self.world.channelHasExtFlag(channel, .authonly) and conn.session.account() == null) {
            if (!quiet) try queueNumeric(conn, .ERR_NEEDREGGEDNICK, &.{channel}, "Cannot join channel (+a) - you must be authenticated");
            return true;
        }

        var mask_buf: [256]u8 = undefined;
        const mask = try clientPrefix(conn, &mask_buf);
        // Extended-ban context (account/realname/channels + host glob fallthrough).
        var chan_buf: [64][]const u8 = undefined;
        const ban_ctx = banContextFor(self, conn, wid, mask, &chan_buf);
        if (!invited) {
            // +b ban (isBannedCtx honors +e exceptions and extended bans) blocks the join.
            if (self.world.isBannedCtx(channel, ban_ctx)) {
                if (!quiet) try queueNumeric(conn, .ERR_BANNEDFROMCHAN, &.{channel}, "Cannot join channel (+b)");
                return true;
            }
            // +i blocks unless the user holds an invite OR matches a +I invex mask.
            if (self.world.channelHasFlag(channel, .invite_only) and !self.world.isInvexedCtx(channel, ban_ctx)) {
                if (!quiet) try queueNumeric(conn, .ERR_INVITEONLYCHAN, &.{channel}, "Cannot join channel (+i)");
                return true;
            }
        }
        if (self.world.channelKey(channel)) |key| {
            if (supplied_key == null or !std.mem.eql(u8, supplied_key.?, key)) {
                if (!quiet) try queueNumeric(conn, .ERR_BADCHANNELKEY, &.{channel}, "Cannot join channel (+k)");
                return true;
            }
        }
        // NOTE: +l (full) is handled separately in joinOne so it can fall back to
        // the IRCX +d auto-clone path; all the gates above are hard denials.
        return false;
    }

    /// True when `channel` has a +l member limit and is at or over it.
    fn isChannelFull(self: *LinuxServer, channel: []const u8) bool {
        const limit = self.world.channelLimit(channel) orelse return false;
        return self.world.memberCount(channel) >= limit;
    }

    /// IRCX CLONEABLE: resolve the channel a join should land on when `parent` is
    /// +l-full and +d cloneable — the first `#parent<n>` clone that is joinable
    /// (an existing non-full +E clone), creating a fresh clone if none is. The
    /// returned name is written into `buf`. Null if no slot could be found.
    fn resolveCloneTarget(self: *LinuxServer, parent: []const u8, buf: []u8) !?[]const u8 {
        var n: u32 = 1;
        while (n < 1000) : (n += 1) {
            const name = std.fmt.bufPrint(buf, "{s}{d}", .{ parent, n }) catch return null;
            if (!self.world.channelExists(name)) {
                _ = self.world.cloneChannel(parent, name) catch return null;
                return name;
            }
            // An existing clone with room takes the join; a full one is skipped.
            if (self.world.channelHasExtFlag(name, .clone) and !self.isChannelFull(name)) {
                return name;
            }
        }
        return null;
    }

    pub fn handleJoin(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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
            try self.joinOne(id, conn, channel, key, 0);
        }
    }

    /// If `channel` has a usable +f forward target (one hop only, gated by
    /// `depth`), emit RPL_LINKCHANNEL (470), copy the target into `out`, and
    /// return it for the caller to JOIN. Returns null when no usable forward
    /// exists. Does NOT call joinOne itself (keeps joinOne's error set clean).
    fn forwardTarget(self: *LinuxServer, conn: *ConnState, channel: []const u8, depth: u8, out: []u8) !?[]const u8 {
        if (depth != 0) return null;
        // User mode +Q (no-forward): a user who opted out is never redirected to a
        // +f forward target — the original blocked-JOIN deny numeric fires instead.
        if (conn.session.hasUmode(.no_forward)) return null;
        const fwd = self.world.forwardOf(channel) orelse return null;
        if (std.ascii.eqlIgnoreCase(fwd, channel)) return null;
        if (!world_model.isChannelName(fwd)) return null;
        if (fwd.len > out.len) return null;
        @memcpy(out[0..fwd.len], fwd);
        const ftarget = out[0..fwd.len];
        var lb: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&lb, ":{s} 470 {s} {s} {s} :Forwarding to another channel\r\n", .{ server_name, conn.session.displayName(), channel, ftarget }) catch return null;
        try appendToConn(conn, line);
        return ftarget;
    }

    fn joinOne(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, channel: []const u8, key: ?[]const u8, depth: u8) !void {
        if (!world_model.isChannelName(channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{channel}, "No such channel");
            return;
        }

        // Enforce channel modes only when joining an EXISTING channel as a new
        // member. Creating a fresh channel (founder path) bypasses all gates.
        const wid = worldIdFromClient(id);
        var clone_buf: [160]u8 = undefined;
        var fwd_buf: [80]u8 = undefined;
        var join_target = channel;
        if (self.world.channelExists(channel) and !self.world.isMember(channel, wid)) {
            // +f forward: when refused, redirect to the forward target (one hop).
            // Suppress the deny numeric while a forward is a candidate, then either
            // redirect quietly or, if the forward is unusable, emit the real deny.
            const fwd_quiet = depth == 0 and self.world.forwardOf(channel) != null;
            if (try self.joinDenied(conn, id, channel, key, fwd_quiet)) {
                if (fwd_quiet) {
                    if (try self.forwardTarget(conn, channel, depth, &fwd_buf)) |target| {
                        return self.joinOne(id, conn, target, null, depth + 1);
                    }
                    _ = try self.joinDenied(conn, id, channel, key, false);
                }
                return;
            }
            // +j join throttle: deny if the per-channel window is full. Opers and
            // invited users bypass. Checked after the hard gates so a denied join
            // does not consume a throttle slot.
            if (!conn.session.isOper() and !self.world.hasInvite(channel, wid) and
                !self.world.throttleAdmit(channel, self.nowMs()))
            {
                try queueNumeric(conn, .ERR_THROTTLE, &.{channel}, "Cannot join channel (+j) - join rate exceeded, try again shortly");
                return;
            }
            // +l full: IRCX +d cloneable channels redirect the join to a clone;
            // otherwise it is a hard 471.
            if (self.isChannelFull(channel)) {
                if (self.world.channelHasExtFlag(channel, .cloneable)) {
                    join_target = (try self.resolveCloneTarget(channel, &clone_buf)) orelse {
                        try queueNumeric(conn, .ERR_CHANNELISFULL, &.{channel}, "Cannot join channel (+l)");
                        return;
                    };
                } else {
                    // +l full: redirect to +f forward target if set, else hard 471.
                    if (try self.forwardTarget(conn, channel, depth, &fwd_buf)) |target| {
                        return self.joinOne(id, conn, target, null, depth + 1);
                    }
                    try queueNumeric(conn, .ERR_CHANNELISFULL, &.{channel}, "Cannot join channel (+l)");
                    return;
                }
            }
        }

        // Founder creating a brand-new channel: purge any orphaned IRCX state from
        // a prior same-named incarnation so stale ACCESS DENY/GRANT entries or
        // secret PROP keys can never bleed into the new channel. (A clone target is
        // already set up by cloneChannel, so it is never "creating" here.)
        const creating = !self.world.channelExists(join_target);
        if (creating) {
            self.props.clearChannel(join_target);
            _ = self.access.clear(.{ .channel = join_target }) catch {};
        }

        _ = try self.world.join(join_target, wid);

        // IRCX tiered keys: a presented key matching the channel's HOSTKEY/OWNERKEY
        // property grants graduated status (op / owner) on join — additive, so a
        // founder keeps founder. Member-tier (+k) is already enforced as the gate.
        if (key) |presented| {
            var tkeys = tiered_keys.ChannelKeys{};
            defer tkeys.deinit(self.allocator);
            const chan_entity = ircx_prop_store.Entity{ .kind = .channel, .id = join_target };
            if (self.props.getProp(chan_entity, "HOSTKEY")) |ev| {
                tkeys.setKey(self.allocator, .host, ev.value) catch {};
            } else |_| {}
            if (self.props.getProp(chan_entity, "OWNERKEY")) |ev| {
                tkeys.setKey(self.allocator, .owner, ev.value) catch {};
            } else |_| {}
            switch (tkeys.grantFor(presented)) {
                .owner => _ = self.world.setMemberMode(join_target, wid, .owner, true) catch {},
                .host => _ = self.world.setMemberMode(join_target, wid, .op, true) catch {},
                .member, .none => {},
            }
        }

        try self.broadcastJoin(join_target, conn);
        try self.sendTopicReply(conn, join_target);
        // draft/no-implicit-names: a capable client suppresses the automatic
        // NAMES burst on JOIN (it can still request NAMES explicitly).
        if (!conn.session.hasCap(.no_implicit_names)) try self.sendNames(conn, join_target);

        // Bouncer rewind: a reconnecting client with mizuchi/bouncer gets the
        // channel messages it missed (everything after its stored read marker)
        // replayed as a chathistory BATCH right after the NAMES burst.
        try self.replayRewindOnJoin(conn, join_target);

        // Propagate this membership to mesh peers (status = the joiner's modes,
        // e.g. founder on a freshly created/cloned channel).
        const jmodes = self.world.memberModes(join_target, wid) orelse world_model.MemberModes.empty();
        self.announceMembership(join_target, conn.session.displayName(), @truncate(jmodes.bits), true);
    }

    pub fn handlePart(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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

        // +x AUDITORIUM: a regular member's PART is only relayed to ops/voiced (and
        // the parter itself), mirroring the JOIN relay gating.
        const wid = worldIdFromClient(id);
        const parter_rank = auditoriumRank(self.world.memberModes(channel, wid) orelse world_model.MemberModes.empty());
        if (self.world.channelHasExtFlag(channel, .auditorium) and !auditorium.shouldRelayJoinPart(parter_rank)) {
            var tag_buf: [48]u8 = undefined;
            const tag = serverTimeTag(&tag_buf);
            var members = self.world.memberIterator(channel) orelse return error.NoSuchChannel;
            while (members.next()) |member| {
                const is_self = member.*.eql(wid);
                const mrank = auditoriumRank(self.world.memberModes(channel, member.*) orelse world_model.MemberModes.empty());
                if (!is_self and !auditorium.shouldRelayJoinPart(mrank)) continue;
                try self.deliverTimed(clientIdFromWorld(member.*), tag, msg);
            }
        } else {
            try self.broadcastChannel(channel, msg, null);
        }
        const parted_nick = conn.session.displayName();
        try self.world.part(channel, wid);
        // Tell mesh peers this member left.
        self.announceMembership(channel, parted_nick, 0, false);
    }

    pub fn handleNames(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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

    /// Apply IRCX +z/-z GAG to another user (operator-only; caller verified oper).
    fn applyGag(self: *LinuxServer, conn: *ConnState, target_nick: []const u8, mode_str: []const u8) !void {
        const twid = self.world.findNick(target_nick) orelse {
            try queueNumeric(conn, .ERR_NOSUCHNICK, &.{target_nick}, "No such nick");
            return;
        };
        const tconn = self.rx().clients.get(clientIdFromWorld(twid)) orelse {
            try queueNumeric(conn, .ERR_NOSUCHNICK, &.{target_nick}, "No such nick");
            return;
        };
        var adding = true;
        for (mode_str) |ch| switch (ch) {
            '+' => adding = true,
            '-' => adding = false,
            'z' => tconn.gagged = adding,
            else => {},
        };
        var buf: [128]u8 = undefined;
        const reflect = std.fmt.bufPrint(&buf, ":{s} MODE {s} {s}z\r\n", .{ server_name, target_nick, if (tconn.gagged) "+" else "-" }) catch return;
        try appendToConn(conn, reflect);
    }

    /// MODE for channel member status modes (+Q/+q/+o/+v, founder +Q is creation-
    /// only) gated by tier rank, flag modes (i/m/n/t/s), and parameterised modes
    /// (+k key, +l limit, +b ban; `MODE #c b` lists bans). User-target MODE is not
    /// handled on this path.
    pub fn handleMode(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MODE"}, "Not enough parameters");
            return;
        }
        const channel = parsed.paramSlice()[0];
        // `MODE ISIRCX` is the IRCX discovery form (draft-pfenning): reply RPL_IRCX.
        if (std.ascii.eqlIgnoreCase(channel, "ISIRCX")) {
            try self.handleIrcx(conn, false);
            return;
        }
        if (!world_model.isChannelName(channel)) {
            // IRCX +z GAG: an operator may set/clear GAG on ANOTHER user; the
            // server then silently drops that user's messages. Other cross-user
            // umode changes remain forbidden.
            if (conn.session.isOper() and parsed.param_count >= 2 and
                !std.mem.eql(u8, channel, conn.session.displayName()))
            {
                const ms = parsed.paramSlice()[1];
                if (std.mem.indexOfScalar(u8, ms, 'z') != null) {
                    try self.applyGag(conn, channel, ms);
                    return;
                }
            }
            // User-target MODE: only the client's own nick is settable.
            try self.handleUserMode(conn, parsed, channel);
            return;
        }
        if (!self.world.channelExists(channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{channel}, "No such channel");
            return;
        }

        // Query form: MODE #chan -> RPL_CHANNELMODEIS. Per the channel-mode rules:
        // the +l/+k LETTERS are shown to everyone, but their PARAM VALUES (limit,
        // key) only to members. Param order matches letter order (l before k).
        if (parsed.param_count == 1) {
            var flags_buf: [16]u8 = undefined;
            const flags = self.world.channelModeString(channel, &flags_buf); // "+imnt"
            const limit = self.world.channelLimit(channel);
            const key = self.world.channelKey(channel);
            const is_member = self.world.isMember(channel, worldIdFromClient(id));

            var modes_buf: [48]u8 = undefined;
            var mb = Buf{ .storage = &modes_buf };
            mb.append(flags) catch {};
            if (limit != null) mb.appendByte('l') catch {};
            if (key != null) mb.appendByte('k') catch {};
            // Append IRCX extended flag letters (rendered "+abc"; drop the sign).
            var ext_buf: [32]u8 = undefined;
            if (chanmode_ext.renderModes(self.world.channelExtModes(channel), &ext_buf)) |ext_str| {
                if (ext_str.len > 1) mb.append(ext_str[1..]) catch {};
            } else |_| {}

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

        // MLOCK: a services mode-lock forbids non-founder, non-oper ops from
        // changing locked flags. The founder (+Q) and server opers bypass it.
        if (!conn.session.isOper() and !setter.contains(.founder)) {
            if (self.mlocks.get(channel)) |spec_str| {
                if (mode_lock_mod.LockSpec.parse(spec_str)) |spec| {
                    var sign_on = true;
                    for (mode_str) |ch| {
                        switch (ch) {
                            '+' => sign_on = true,
                            '-' => sign_on = false,
                            // Param/status modes are not lockable simple flags.
                            'Q', 'q', 'o', 'v', 'b', 'e', 'I', 'k', 'l' => {},
                            else => {
                                if (mode_lock_mod.evaluate(spec, ch, sign_on) == .forbid) {
                                    var nb: [default_reply_bytes]u8 = undefined;
                                    const note = std.fmt.bufPrint(&nb, "Mode +{c} is locked by services (MLOCK {s})", .{ ch, spec_str }) catch return;
                                    try self.noticeTo(conn, note);
                                    return;
                                }
                            },
                        }
                    }
                } else |_| {}
            }
        }
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
                'i', 'm', 'n', 't', 's', 'C', 'T', 'N', 'g', 'S', 'M' => {
                    const mode: world_model.ChannelMode = switch (ch) {
                        'i' => .invite_only,
                        'm' => .moderated,
                        'n' => .no_external,
                        't' => .topic_ops,
                        's' => .secret,
                        'C' => .no_ctcp,
                        'T' => .no_notice,
                        'N' => .no_nick,
                        'g' => .free_invite,
                        'S' => .tls_only,
                        'M' => .mod_reg,
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
                'p', 'h' => {
                    // +p private / +h IRCX HIDDEN (world.Channel flags, not chanmode).
                    const changed = if (ch == 'p')
                        (self.world.setPrivate(channel, adding) catch continue)
                    else
                        (self.world.setHidden(channel, adding) catch continue);
                    if (changed) appendModeLetter(&applied, &emitted_sign, if (adding) '+' else '-', ch);
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
                'Z' => {
                    // +Z quiet (MUTE) list — like +b but only suppresses speech.
                    // No argument => list query (RPL_QUIETLIST 728 / 729).
                    if (arg_index >= parsed.param_count) {
                        try self.sendMaskList(conn, channel, self.world.mutesOf(channel), .RPL_QUIETLIST, .RPL_ENDOFQUIETLIST, "End of channel quiet list");
                        continue;
                    }
                    const mask = parsed.paramSlice()[arg_index];
                    arg_index += 1;
                    const changed = if (adding)
                        (self.world.addMute(channel, mask) catch continue)
                    else
                        (self.world.removeMute(channel, mask) catch continue);
                    if (changed) appendParamMode(&applied, &targets, &emitted_sign, if (adding) '+' else '-', 'Z', mask);
                },
                'j' => {
                    // +j join throttle: param "joins:seconds" on set, bare on unset.
                    if (adding) {
                        if (arg_index >= parsed.param_count) continue;
                        const spec = parsed.paramSlice()[arg_index];
                        arg_index += 1;
                        const colon = std.mem.indexOfScalar(u8, spec, ':') orelse continue;
                        const joins = std.fmt.parseInt(u16, spec[0..colon], 10) catch continue;
                        const secs = std.fmt.parseInt(u32, spec[colon + 1 ..], 10) catch continue;
                        if (joins == 0 or secs == 0) continue;
                        self.world.setThrottle(channel, joins, secs) catch continue;
                        appendParamMode(&applied, &targets, &emitted_sign, '+', 'j', spec);
                    } else {
                        if (self.world.throttleOf(channel) == null) continue;
                        self.world.clearThrottle(channel) catch continue;
                        appendModeLetter(&applied, &emitted_sign, '-', 'j');
                    }
                },
                'f' => {
                    // +f forward: param is the target channel on set, bare on unset.
                    if (adding) {
                        if (arg_index >= parsed.param_count) continue;
                        const target = parsed.paramSlice()[arg_index];
                        arg_index += 1;
                        if (!chan_forward.validForwardTarget(target, channel)) continue;
                        self.world.setForward(channel, target) catch continue;
                        appendParamMode(&applied, &targets, &emitted_sign, '+', 'f', target);
                    } else {
                        if (self.world.forwardOf(channel) == null) continue;
                        self.world.setForward(channel, null) catch continue;
                        appendModeLetter(&applied, &emitted_sign, '-', 'f');
                    }
                },
                else => {
                    // IRCX extended channel flags (AUTHONLY a, AUDITORIUM x,
                    // NOWHISPER w, CLONEABLE d, KNOCK u, etc.) with no base-mode slot.
                    if (chanmode_ext.letterToFlag(ch)) |flag| {
                        if (chanmode_ext.requiresOper(flag) and !conn.session.isOper()) {
                            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "That channel mode is operator-only");
                            continue;
                        }
                        const changed = self.world.setChannelExtFlag(channel, flag, adding) catch continue;
                        if (changed) appendModeLetter(&applied, &emitted_sign, if (adding) '+' else '-', ch);
                    }
                },
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
    pub fn handleUserMode(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView, target: []const u8) !void {
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
                else => {
                    // Catalog-driven: apply any client-writable user mode (i, B, D,
                    // g, C, R, p, …). Server-managed modes (r/z/x) and unknown
                    // letters are silently ignored.
                    const mode = usermode.modeFromLetter(ch) orelse continue;
                    const spec = usermode.specFor(mode) orelse continue;
                    if (spec.policy != .client_writable) continue;
                    if (conn.session.setUmode(mode, adding)) {
                        appendModeLetter(&applied, &emitted_sign, if (adding) '+' else '-', ch);
                    }
                },
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
    pub fn handleKick(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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

        const kicker_prefix = kick.Prefix{ .nick = conn.session.displayName(), .user = conn.session.username(), .host = hostOf(conn) };
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const msg = kick.buildKickBroadcastWith(.{ .require_utf8 = false }, &msg_buf, kicker_prefix, args.channel, args.user, args.reason) catch return;
        try self.broadcastChannel(args.channel, msg, null);
        self.world.part(args.channel, target) catch {};
    }

    /// ISON <nick>... — reply RPL_ISON (303) with the subset that is online.
    pub fn handleIson(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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
    pub fn handleUserhost(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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
    /// WHOX channel reply: RPL_WHOSPCRPL (354) per member with only the requested
    /// fields, then RPL_ENDOFWHO (315).
    pub fn handleWhox(self: *LinuxServer, conn: *ConnState, target: []const u8, req: whox.Request) !void {
        const requester = conn.session.displayName();
        if (world_model.isChannelName(target) and self.world.channelExists(target)) {
            var it = self.world.memberIterator(target) orelse return;
            while (it.next()) |member| {
                const nick = self.world.nickOf(member.*) orelse continue;
                const mconn = self.connFor(clientIdFromWorld(member.*));
                const hp = (self.world.memberModes(target, member.*) orelse world_model.MemberModes.empty()).highestPrefix();
                try self.emitWhoxRow(conn, req, requester, target, nick, usernameOf(self, member.*), mconn, hp);
            }
        } else if (self.world.findNick(target)) |wid| {
            // Nick target: a single 354 row, no channel context (channel "*").
            const mconn = self.connFor(clientIdFromWorld(wid));
            try self.emitWhoxRow(conn, req, requester, "*", target, usernameOf(self, wid), mconn, 0);
        }
        var endbuf: [default_reply_bytes]u8 = undefined;
        const end = who.writeEndOfWho(&endbuf, server_name, requester, target) catch return;
        try appendToConn(conn, end);
        try appendToConn(conn, "\r\n");
    }

    /// Emit one RPL_WHOSPCRPL (354) row. Flags are `<H|G>[*][<prefix>]`: away,
    /// then oper, then the highest channel prefix (channel targets only).
    fn emitWhoxRow(
        self: *LinuxServer,
        conn: *ConnState,
        req: whox.Request,
        requester: []const u8,
        channel: []const u8,
        nick: []const u8,
        username: []const u8,
        mconn: ?*ConnState,
        prefix: u8,
    ) !void {
        var flags_buf: [6]u8 = undefined;
        var fl: usize = 0;
        flags_buf[fl] = if (mconn != null and mconn.?.session.awayMessage() != null) 'G' else 'H';
        fl += 1;
        if (mconn != null and mconn.?.session.isOper()) {
            flags_buf[fl] = '*';
            fl += 1;
        }
        if (prefix != 0) {
            flags_buf[fl] = prefix;
            fl += 1;
        }
        const idle: u32 = if (mconn) |c|
            @intCast(@max(0, @divTrunc(self.nowMs() - c.last_activity_ms, 1000)))
        else
            0;
        const ctx = whox.ReplyContext{
            .server_name = server_name,
            .requester = requester,
            .request = req,
            .member = .{
                .channel = channel,
                .user = username,
                .host = default_host,
                .server = server_name,
                .nick = nick,
                .flags = flags_buf[0..fl],
                .idle_seconds = idle,
                .account = if (mconn) |c| (c.session.account() orelse "0") else "0",
                .realname = if (mconn) |c| c.session.realname() else nick,
            },
        };
        const line = whox.buildReply(self.allocator, ctx) catch return;
        defer self.allocator.free(line);
        try appendToConn(conn, line);
    }

    pub fn handleWho(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"WHO"}, "Not enough parameters");
            return;
        }
        const target = parsed.paramSlice()[0];
        const requester = conn.session.displayName();
        var buf: [default_reply_bytes]u8 = undefined;

        // WHOX: `WHO <target> %<fields>[,token]` -> RPL_WHOSPCRPL (354).
        if (parsed.param_count >= 2 and parsed.paramSlice()[1].len >= 1 and parsed.paramSlice()[1][0] == '%') {
            if (whox.parse(parsed.paramSlice()[1])) |req| {
                try self.handleWhox(conn, target, req);
                return;
            } else |_| {} // malformed selector: fall through to plain WHO
        }

        if (world_model.isChannelName(target) and self.world.channelExists(target)) {
            var it = self.world.memberIterator(target) orelse return;
            while (it.next()) |member| {
                const nick = self.world.nickOf(member.*) orelse continue;
                const mconn = self.connFor(clientIdFromWorld(member.*));
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
            const mconn = self.connFor(clientIdFromWorld(wid));
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
    pub fn handleList(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const request = list.parseList(parsed.paramSlice()) catch list.Request{};
        // ELIST extended filters (>N/<N/C/T/mask); empty set matches everything.
        var filters = elist.parseParams(self.allocator, parsed.paramSlice()) catch elist.FilterSet{};
        defer filters.deinit(self.allocator);
        const Adapter = struct {
            it: world_model.World.ChannelViewIterator,
            filters: *const elist.FilterSet,
            pub fn next(s: *@This()) ?list.ChannelInfo {
                while (s.it.next()) |v| {
                    if (v.secret or v.hidden) continue;
                    if (!s.filters.matches(.{ .name = v.name, .users = @intCast(v.members), .created_ago = 0, .topic_age = 0 })) continue;
                    return .{ .name = v.name, .users = @intCast(v.members), .topic = v.topic };
                }
                return null;
            }
        };
        var adapter = Adapter{ .it = self.world.channelIterator(), .filters = &filters };
        var scratch: [default_reply_bytes]u8 = undefined;
        var sink = ConnLineSinkCRLF{ .conn = conn };
        list.emitList(Adapter, &adapter, request, .{ .server_name = server_name, .requester = conn.session.displayName(), .now_seconds = 0 }, &scratch, &sink) catch return;
    }

    /// LISTX [<filter>] — IRCX extended channel list (811/812/817). Filter terms
    /// (member-count, name/topic/subject mask, registered) per draft; time-based
    /// terms degrade gracefully (no creation/topic timestamps tracked yet).
    pub fn handleListx(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const request = listx.parse(parsed.paramSlice()) catch {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"LISTX"}, "Invalid LISTX filter");
            return;
        };
        const ctx = listx.ReplyContext{ .server_name = server_name, .requester = conn.session.displayName() };
        var buf: [default_reply_bytes]u8 = undefined;
        if (listx.writeListxStart(&buf, ctx)) |line| try appendToConn(conn, line) else |_| {}
        var it = self.world.channelIterator();
        while (it.next()) |v| {
            if (v.secret or v.hidden) continue;
            const info = listx.ChannelInfo{
                .name = v.name,
                .members = @intCast(v.members),
                .topic = v.topic,
                .created_ms = 0,
                .topic_ms = null,
            };
            if (!request.matches(info, 0)) continue;
            var ebuf: [default_reply_bytes]u8 = undefined;
            if (listx.writeListxEntry(&ebuf, ctx, info)) |line| try appendToConn(conn, line) else |_| {}
        }
        var endbuf: [default_reply_bytes]u8 = undefined;
        if (listx.writeListxEnd(&endbuf, ctx)) |line| try appendToConn(conn, line) else |_| {}
    }

    /// WHOIS [server] <nick> — full WHOIS sequence for a local user.
    pub fn handleWhois(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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
        const target_conn: ?*ConnState = if (target_wid) |w| self.connFor(clientIdFromWorld(w)) else null;
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
            // RPL_WHOISCERTFP (276): surface the TLS client-cert fingerprint of a
            // mutual-TLS user (the same value SASL EXTERNAL matches to an account).
            .certfp = tconn.session.tls_certfp,
            // +p hide-chans: suppress the channel list unless the requester is the
            // user themselves or an oper.
            .channels = blk: {
                const hide = tconn.session.umodes.contains(.hide_chans) and
                    !conn.session.isOper() and conn != tconn;
                break :blk memberships[0..if (hide) 0 else nchan];
            },
        };
        whois.writeWhois(&sink, server_name, conn.session.displayName(), subject) catch return;
        for (sink.slice()) |line| try appendToConn(conn, line.bytes);
    }

    /// INVITE <nick> <channel> — invite a user; +i channels require op (no +g
    /// free-invite mode yet). RPL_INVITING to inviter + INVITE line to target.
    pub fn handleInvite(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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
            .free_invite = self.world.channelHasFlag(args.channel, .free_invite),
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

        const prefix = invite.Prefix{ .nick = conn.session.displayName(), .user = conn.session.username(), .host = hostOf(conn) };
        var line_buf: [default_reply_bytes]u8 = undefined;
        const target_line = invite.buildTargetInviteLine(&line_buf, prefix, args.nick, args.channel) catch return;
        // deliver() expects a CRLF-terminated line; the builder omits it.
        var full_buf: [default_reply_bytes]u8 = undefined;
        const full = std.fmt.bufPrint(&full_buf, "{s}\r\n", .{target_line}) catch return;
        try self.deliver(clientIdFromWorld(target), full);

        // IRCv3 invite-notify: tell channel members who hold
        // the cap, except the inviter — `:inviter!u@h INVITE <target> :<channel>`.
        var notif_prefix: [256]u8 = undefined;
        var notif_buf: [default_reply_bytes]u8 = undefined;
        const notif = try formatMessage(&notif_buf, try clientPrefix(conn, &notif_prefix), "INVITE", &.{args.nick}, args.channel);
        var members = self.world.memberIterator(args.channel) orelse return;
        while (members.next()) |member| {
            const mid = clientIdFromWorld(member.*);
            if (mid.eql(id)) continue;
            const mconn = self.connFor(mid) orelse continue;
            if (!mconn.session.hasCap(.invite_notify)) continue;
            try self.deliver(mid, notif);
        }
    }

    /// KILL <nick> :<reason> — oper-only forced disconnect. Delivers a KILL line
    /// then routes the victim through the graceful close-on-drain path (its
    /// channels see a QUIT once the buffer flushes). Non-opers get 481.
    /// `CLOSE` (oper) — drop every still-unregistered connection. A classic
    /// anti-flood tool: clears half-open/handshake-stalled clients without
    /// touching registered users or server links. Each victim is torn down via
    /// the standard drain-close path (queue ERROR, mark closing, arm send).
    /// `UNREJECT <ip>` (oper) — forget an IP's accumulated reputation penalty so
    /// a falsely-flagged host can reconnect immediately. No-op (but reported) if
    /// reputation is disabled or the IP carries no penalty.
    pub fn handleUnreject(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"UNREJECT"}, "Usage: UNREJECT <ip>");
            return;
        }
        const ip_text = parsed.paramSlice()[0];
        const addr = resolv_conf.parseIp(ip_text) orelse {
            try self.failReply(conn, "UNREJECT", "INVALID_IP", "Not a valid IP address");
            return;
        };
        const cleared = self.reputation.clear(addr);
        var buf: [default_reply_bytes]u8 = undefined;
        const state = if (cleared) "cleared" else "had no penalty";
        const line = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :UNREJECT {s}: {s}\r\n", .{ server_name, conn.session.displayName(), ip_text, state }) catch return;
        try appendToConn(conn, line);
    }

    /// `DRAIN [OFF]` (oper) — toggle drain mode. With no arg (or `ON`) the server
    /// refuses new client connections; `DRAIN OFF` resumes accepting. Existing
    /// clients and S2S links are never affected.
    pub fn handleDrain(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        const off = parsed.param_count >= 1 and std.ascii.eqlIgnoreCase(parsed.paramSlice()[0], "OFF");
        self.draining = !off;
        var buf: [default_reply_bytes]u8 = undefined;
        const state = if (self.draining) "enabled (refusing new connections)" else "disabled (accepting connections)";
        const line = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :DRAIN {s}\r\n", .{ server_name, conn.session.displayName(), state }) catch return;
        try appendToConn(conn, line);
    }

    pub fn handleClose(self: *LinuxServer, conn: *ConnState) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        var closed: usize = 0;
        var it = self.rx().clients.iterator();
        while (it.next()) |entry| {
            const c = entry.value;
            if (c.closing) continue;
            if (c.s2s != null or c.s2s_secured != null) continue;
            if (c.session.registered()) continue;
            appendToConn(c, ":" ++ server_name ++ " ERROR :Closing unregistered connection\r\n") catch {};
            c.close_reason = "Closed by operator";
            c.closing = true;
            self.armSendIfNeeded(c) catch {};
            closed += 1;
        }
        var buf: [default_reply_bytes]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :CLOSE: {d} unregistered connection(s) closed\r\n", .{ server_name, conn.session.displayName(), closed }) catch return;
        try appendToConn(conn, line);
    }

    pub fn handleKill(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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
        const tconn = self.rx().clients.get(clientIdFromWorld(target_wid)) orelse {
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

        // Oper-visible KILL event through the Event Spine (kill category).
        var kev_buf: [512]u8 = undefined;
        const kev = std.fmt.bufPrint(&kev_buf, "{s} killed {s} ({s})", .{ killer, target_nick, reason }) catch reason;
        try self.publishOperEvent(.kill, .warn, kev);

        // Graceful close: the send-drain path fires QUIT to channels and frees
        // the slot once the buffer flushes (mirrors a self-QUIT).
        tconn.closing = true;
        try self.armSendIfNeeded(tconn);
    }

    /// WHOWAS <nick> [count] — historical identities from the ring, most-recent
    /// first (314 + 312 signoff, 406 if none, 369 end).
    pub fn handleWhowas(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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
    pub fn handleKnock(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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
        // IRCX KNOCK gating (additive, decision 6a): KNOCK is accepted when the
        // channel is invite-only (+i) OR explicitly knock-enabled (+u). A channel
        // with neither is "open" and refuses the knock (713).
        const knock_invite = self.world.channelHasFlag(channel, .invite_only);
        const knock_ext = self.world.channelHasExtFlag(channel, .knock);
        if (!knock_invite and !knock_ext) {
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
            try self.deliverNumeric(op_id, .RPL_KNOCK, &.{ channel, mask }, reason);
        }
        try queueNumeric(conn, .RPL_KNOCKDLVR, &.{channel}, "Your KNOCK has been delivered");
    }

    /// RENAME <#old> <#new> [:reason] — IRCv3 draft/channel-rename. A channel
    /// operator (or server oper) renames a channel in place; membership/modes/
    /// bans/topic carry over. Members negotiating draft/channel-rename receive a
    /// native `:renamer RENAME #old #new [:reason]`; others get a PART(old)+
    /// JOIN(new) fallback so their client tracks the move.
    pub fn handleRename(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const args = channel_rename.parseRenameArgs(parsed.paramSlice()) catch |e| {
            const code: []const u8 = switch (e) {
                error.MissingOldChannel, error.MissingNewChannel => "NEED_MORE_PARAMS",
                error.NeedSameType => "NEED_SAME_TYPE",
                else => "INVALID_PARAMS",
            };
            try self.failReply(conn, "RENAME", code, "Invalid RENAME parameters");
            return;
        };
        const old = args.old_channel;
        const new = args.new_channel;
        if (!self.world.channelExists(old)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{old}, "No such channel");
            return;
        }
        const wid = worldIdFromClient(id);
        if (!self.world.isMember(old, wid)) {
            try queueNumeric(conn, .ERR_NOTONCHANNEL, &.{old}, "You're not on that channel");
            return;
        }
        const mm = self.world.memberModes(old, wid) orelse world_model.MemberModes.empty();
        if (!mm.isOperator() and !conn.session.isOper()) {
            try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{old}, "You're not channel operator");
            return;
        }
        const ok = self.world.renameChannel(old, new) catch {
            try self.failReply(conn, "RENAME", "CANNOT_RENAME", "Could not rename channel");
            return;
        };
        if (!ok) {
            try self.failReply(conn, "RENAME", "CHANNEL_NAME_IN_USE", "Target channel name is already in use");
            return;
        }

        // Native RENAME line, sourced from the renamer's prefix.
        var pfx_buf: [256]u8 = undefined;
        const pfx = clientPrefix(conn, &pfx_buf) catch return;
        var rline_buf: [default_reply_bytes]u8 = undefined;
        const rline = if (args.reason.len != 0)
            std.fmt.bufPrint(&rline_buf, ":{s} RENAME {s} {s} :{s}\r\n", .{ pfx, old, new, args.reason }) catch return
        else
            std.fmt.bufPrint(&rline_buf, ":{s} RENAME {s} {s}\r\n", .{ pfx, old, new }) catch return;

        // Fan out to every member (channel now lives under the new key).
        var members = self.world.memberIterator(new) orelse return;
        while (members.next()) |member| {
            const mid = clientIdFromWorld(member.*);
            const mconn = self.connFor(mid) orelse continue;
            if (mconn.session.hasCap(.channel_rename)) {
                self.deliver(mid, rline) catch {};
            } else {
                // PART(old)+JOIN(new) fallback, sourced as the member themself.
                var mpfx_buf: [256]u8 = undefined;
                const mpfx = clientPrefix(mconn, &mpfx_buf) catch continue;
                var part_buf: [default_reply_bytes]u8 = undefined;
                const part = std.fmt.bufPrint(&part_buf, ":{s} PART {s} :Channel renamed to {s}\r\n", .{ mpfx, old, new }) catch continue;
                self.deliver(mid, part) catch {};
                var join_buf: [default_reply_bytes]u8 = undefined;
                const join = std.fmt.bufPrint(&join_buf, ":{s} JOIN {s}\r\n", .{ mpfx, new }) catch continue;
                self.deliver(mid, join) catch {};
            }
        }
    }

    /// MONITOR +/-/C/L/S — IRCv3 contact notification. Targets' online/offline
    /// transitions are reported (730/731); L lists (732/733), S reports status.
    pub fn handleMonitor(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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
            const wid = clientIdFromMonitor(reply.client);
            const trailing = if (reply.targets.len != 0) reply.targets else reply.text;
            try self.deliverNumeric(wid, monitorNumeric(reply.numeric), &.{}, trailing);
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
    pub fn handleStats(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"STATS"}, "Not enough parameters");
            return;
        }
        const letter = parsed.paramSlice()[0];
        switch (letter[0]) {
            'u' => {
                const up_secs: u64 = @intCast(@max(@as(i64, 0), @divTrunc(self.nowMs() - self.start_ms, 1000)));
                const days = up_secs / 86_400;
                const hours = (up_secs % 86_400) / 3600;
                const mins = (up_secs % 3600) / 60;
                const secs = up_secs % 60;
                var buf: [96]u8 = undefined;
                const text = std.fmt.bufPrint(&buf, "Server Up {d} days {d:0>2}:{d:0>2}:{d:0>2}", .{ days, hours, mins, secs }) catch return;
                try queueNumeric(conn, .RPL_STATSUPTIME, &.{}, text);
            },
            'o' => {
                // One RPL_STATSOLINE per configured oper binding (account -> class).
                if (self.oper_registry) |reg| {
                    for (reg.bindings) |b| {
                        try queueNumeric(conn, .RPL_STATSOLINE, &.{ "O", b.account_name, "*", b.class_name, "0", "0" }, "");
                    }
                }
            },
            'k', 'K' => try self.statsLines(conn, .mask, .RPL_STATSKLINE),
            'd', 'D' => try self.statsLines(conn, .address, .RPL_STATSDLINE),
            'z', 'Z' => {
                // Runtime counters (RPL_STATSDEBUG 249), oper-only.
                if (!conn.session.isOper()) {
                    try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission denied; STATS z is for operators");
                } else {
                    const Ctx = struct { c: *ConnState };
                    try self.stats.forEachLine(Ctx{ .c = conn }, struct {
                        fn emit(cx: Ctx, line: []const u8) !void {
                            try queueNumeric(cx.c, .RPL_STATSDEBUG, &.{}, line);
                        }
                    }.emit);
                }
            },
            else => {}, // other letters not implemented yet
        }
        try queueNumeric(conn, .RPL_ENDOFSTATS, &.{letter}, "End of /STATS report");
    }

    /// MARKREAD <target> [timestamp=…] — IRCv3 read-marker. GET returns the
    /// stored marker (or `*`); SET advances it (monotonic) and echoes it back.
    /// Keyed by the client's account when logged in, else its nick.
    pub fn handleMarkread(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const owner = conn.session.account() orelse conn.session.displayName();
        const req = read_marker_store.parse(parsed.paramSlice()) catch {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MARKREAD"}, "Invalid MARKREAD parameters");
            return;
        };
        var out_buf: [default_reply_bytes]u8 = undefined;
        const line = switch (req) {
            .get => |target| blk: {
                const ts = self.read_markers.get(owner, target) catch null;
                break :blk if (ts) |t|
                    (read_marker_store.buildTimestampResponse(target, t, &out_buf) catch return)
                else
                    (read_marker_store.buildResponse(target, .unset, &out_buf) catch return);
            },
            .set => |sr| blk: {
                const ts = switch (sr.marker) {
                    .timestamp => |t| t,
                    .unset => break :blk (read_marker_store.buildResponse(sr.target, .unset, &out_buf) catch return),
                };
                const res = self.read_markers.set(owner, sr.target, ts) catch return;
                break :blk (read_marker_store.buildTimestampResponse(sr.target, res.timestamp, &out_buf) catch return);
            },
        };
        try appendToConn(conn, line);
    }

    /// SILENCE [+mask|-mask ...] — server-side ignore list. With no args (or a
    /// query) it lists the caller's masks (RPL_SILELIST 271 / 272). Add/remove
    /// ops are applied and echoed. Keyed by the caller's nick.
    pub fn handleSilence(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const owner = conn.session.displayName();
        if (parsed.param_count == 0) {
            var lbuf: [default_reply_bytes]u8 = undefined;
            const masks = self.silence.list(owner, &lbuf) catch "";
            if (masks.len != 0) try queueNumeric(conn, .RPL_SILELIST, &.{masks}, "");
            try queueNumeric(conn, .RPL_ENDOFSILELIST, &.{}, "End of SILENCE list");
            return;
        }
        const req = silence.parse(parsed.paramSlice()) catch {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"SILENCE"}, "Invalid SILENCE mask");
            return;
        };
        var prefix_buf: [256]u8 = undefined;
        const prefix = try clientPrefix(conn, &prefix_buf);
        for (req.slice()) |op| {
            const changed = switch (op.kind) {
                .add => self.silence.add(owner, op.mask) catch continue,
                .remove => self.silence.remove(owner, op.mask) catch continue,
            };
            if (!changed) continue;
            var line_buf: [default_reply_bytes]u8 = undefined;
            const sign: u8 = if (op.kind == .add) '+' else '-';
            const line = std.fmt.bufPrint(&line_buf, ":{s} SILENCE {c}{s}\r\n", .{ prefix, sign, op.mask }) catch continue;
            try appendToConn(conn, line);
        }
    }

    /// Record a channel message into the CHATHISTORY ring (Lotus). msgid is a
    /// monotonic server counter; sender is the full nick!user@host prefix.
    fn recordHistory(self: *LinuxServer, target: []const u8, conn: *ConnState, text: []const u8) void {
        self.msg_seq += 1;
        const ts: u64 = @intCast(@max(@as(i64, 0), platform.realtimeMillis()));
        // Unique, time-ordered, node-embedded msgid (falls back to the counter
        // only if the snowflake clock overflows).
        const sf = self.snowflake.next(ts) catch self.msg_seq;
        var id_buf: [24]u8 = undefined;
        const msgid = std.fmt.bufPrint(&id_buf, "{d}", .{sf}) catch return;
        var prefix_buf: [256]u8 = undefined;
        const sender = clientPrefix(conn, &prefix_buf) catch return;
        _ = self.history.append(target, .{ .msgid = msgid, .sender = sender, .text = text, .timestamp = ts }) catch {};
    }

    /// Convert a fixed-width `YYYY-MM-DDThh:mm:ss.sssZ` read-marker timestamp to
    /// epoch milliseconds (the unit the Lotus history ring is keyed on). Returns
    /// null on any malformed field. Uses the civil-from-days algorithm so it is
    /// allocation- and table-free.
    fn markerToMillis(s: []const u8) ?u64 {
        if (s.len < 24) return null;
        const year = std.fmt.parseInt(i64, s[0..4], 10) catch return null;
        const month = std.fmt.parseInt(i64, s[5..7], 10) catch return null;
        const day = std.fmt.parseInt(i64, s[8..10], 10) catch return null;
        const hh = std.fmt.parseInt(i64, s[11..13], 10) catch return null;
        const mm = std.fmt.parseInt(i64, s[14..16], 10) catch return null;
        const ss = std.fmt.parseInt(i64, s[17..19], 10) catch return null;
        const ms = std.fmt.parseInt(i64, s[20..23], 10) catch return null;
        const y = if (month <= 2) year - 1 else year;
        const era = @divFloor(if (y >= 0) y else y - 399, 400);
        const yoe = y - era * 400;
        const mp: i64 = if (month > 2) month - 3 else month + 9;
        const doy = @divFloor(153 * mp + 2, 5) + day - 1;
        const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
        const days = era * 146097 + doe - 719468;
        const total_ms = (((days * 24 + hh) * 60 + mm) * 60 + ss) * 1000 + ms;
        if (total_ms < 0) return null;
        return @intCast(total_ms);
    }

    /// Bouncer rewind: when a `mizuchi/bouncer` client (re)joins a channel,
    /// replay the messages it missed — everything after its stored read marker —
    /// as a `chathistory` BATCH. No marker means there is nothing to rewind to
    /// (a fresh client has read everything), so we stay silent rather than dump
    /// the full ring. No-op for clients without the cap or without an account.
    fn replayRewindOnJoin(self: *LinuxServer, conn: *ConnState, channel: []const u8) !void {
        if (!conn.session.hasCap(.mizuchi_bouncer)) return;
        const owner = conn.session.account() orelse return;
        const marker = (self.read_markers.get(owner, channel) catch null) orelse return;
        const marker_ms = markerToMillis(marker.slice()) orelse return;
        var buf: [64]lotus.Message = undefined;
        const found = self.history.after(channel, marker_ms, buf.len, buf[0..]) catch return;
        if (found.len == 0) return;
        var cmsgs: [64]chathistory_cmd.Message = undefined;
        var cn: usize = 0;
        for (found) |m| {
            if (m.tombstone) continue;
            cmsgs[cn] = .{ .timestamp_ms = m.timestamp, .msgid = m.msgid, .sender = m.sender, .text = m.text };
            cn += 1;
        }
        if (cn == 0) return;
        var out_buf: [default_reply_bytes * 4]u8 = undefined;
        const batch = chathistory_cmd.writeBatch(&out_buf, "rewind", channel, cmsgs[0..cn]) catch return;
        try appendToConn(conn, batch);
    }

    /// CHATHISTORY <sub> <target> <criteria...> <limit> — IRCv3 history replay.
    /// Supports LATEST and BEFORE/AFTER with timestamp selectors over the Lotus
    /// ring; emits a `chathistory` BATCH of PRIVMSG lines (msgid+server-time).
    pub fn handleChathistory(self: *LinuxServer, conn: *ConnState, line: []const u8) !void {
        const trimmed = std.mem.trimEnd(u8, line, "\r\n");
        const req = chathistory_cmd.parse(trimmed) catch return; // malformed: silent (FAIL TODO)
        var buf: [64]lotus.Message = undefined;
        var target: []const u8 = "";
        var found: []const lotus.Message = buf[0..0];
        switch (req) {
            .latest => |r| {
                target = r.target;
                const n = @min(@as(usize, r.limit), buf.len);
                found = self.history.latest(target, n, buf[0..n]) catch buf[0..0];
            },
            .before => |r| {
                target = r.target;
                const n = @min(@as(usize, r.limit), buf.len);
                switch (r.selector) {
                    .timestamp => |ts| found = self.history.before(target, ts, n, buf[0..n]) catch buf[0..0],
                    .msgid => {},
                }
            },
            .after => |r| {
                target = r.target;
                const n = @min(@as(usize, r.limit), buf.len);
                switch (r.selector) {
                    .timestamp => |ts| found = self.history.after(target, ts, n, buf[0..n]) catch buf[0..0],
                    .msgid => {},
                }
            },
            .between => |r| target = r.target,
            .around => |r| target = r.target,
        }

        var cmsgs: [64]chathistory_cmd.Message = undefined;
        var cn: usize = 0;
        for (found) |m| {
            if (m.tombstone) continue;
            cmsgs[cn] = .{ .timestamp_ms = m.timestamp, .msgid = m.msgid, .sender = m.sender, .text = m.text };
            cn += 1;
        }
        var out_buf: [default_reply_bytes * 4]u8 = undefined;
        const batch = chathistory_cmd.writeBatch(&out_buf, "1", target, cmsgs[0..cn]) catch return;
        try appendToConn(conn, batch);
    }

    /// `OPERMOTD` — show the operator MOTD (RPL_OMOTDSTART/OMOTD/ENDOFOMOTD, or
    /// ERR_NOOPERMOTD if unset). `OPERMOTD SET :<text>` (oper-only) replaces it.
    pub fn handleOperMotd(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        const p = parsed.paramSlice();
        if (p.len >= 1 and std.ascii.eqlIgnoreCase(p[0], "SET")) {
            const text = if (p.len >= 2) p[1] else "";
            self.oper_motd.setFromText(text) catch {
                try self.noticeTo(conn, "OPERMOTD: could not set (too long)");
                return;
            };
            try self.noticeTo(conn, "OPERMOTD updated");
            return;
        }
        const nick = conn.session.displayName();
        var buf: [default_reply_bytes]u8 = undefined;
        if (self.oper_motd.isEmpty()) {
            const line = oper_motd_mod.buildNoOperMotd(&buf, server_name, nick) catch return;
            try appendToConn(conn, line);
            return;
        }
        if (oper_motd_mod.buildOperMotdStart(&buf, server_name, nick)) |line| try appendToConn(conn, line) else |_| {}
        for (self.oper_motd.lines()) |l| {
            var lb: [default_reply_bytes]u8 = undefined;
            if (oper_motd_mod.buildOperMotdLine(&lb, server_name, nick, l)) |line| try appendToConn(conn, line) else |_| {}
        }
        if (oper_motd_mod.buildOperMotdEnd(&buf, server_name, nick)) |line| try appendToConn(conn, line) else |_| {}
    }

    /// `AUTOJOIN <ADD|DEL|LIST> [#channel]` — manage the caller's per-account
    /// auto-join list (applied automatically on each login). Requires login.
    pub fn handleAutojoin(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const account = conn.session.account() orelse {
            try self.failReply(conn, "AUTOJOIN", "ACCOUNT_REQUIRED", "Log in to manage autojoin");
            return;
        };
        const p = parsed.paramSlice();
        if (p.len == 0 or std.ascii.eqlIgnoreCase(p[0], "LIST")) {
            const chans = self.autojoins.list(account) catch &.{};
            for (chans) |c| {
                var b: [default_reply_bytes]u8 = undefined;
                const line = std.fmt.bufPrint(&b, ":{s} NOTICE {s} :AUTOJOIN {s}\r\n", .{ server_name, conn.session.displayName(), c }) catch continue;
                try appendToConn(conn, line);
            }
            try self.noticeTo(conn, "AUTOJOIN: end of list");
            return;
        }
        if (p.len < 2 or p[1].len == 0) {
            try self.noticeTo(conn, "Usage: AUTOJOIN <ADD|DEL|LIST> [#channel]");
            return;
        }
        const channel = p[1];
        if (std.ascii.eqlIgnoreCase(p[0], "ADD")) {
            self.autojoins.add(account, channel) catch {
                try self.noticeTo(conn, "AUTOJOIN: could not add (invalid channel, duplicate, or limit)");
                return;
            };
            try self.noticeTo(conn, "AUTOJOIN added");
        } else if (std.ascii.eqlIgnoreCase(p[0], "DEL")) {
            self.autojoins.remove(account, channel) catch {
                try self.noticeTo(conn, "AUTOJOIN: no such entry");
                return;
            };
            try self.noticeTo(conn, "AUTOJOIN removed");
        } else {
            try self.noticeTo(conn, "Usage: AUTOJOIN <ADD|DEL|LIST> [#channel]");
        }
    }

    /// `GROUP <ADD|DEL|LIST|PRIMARY> [nick]` — group multiple nicks under the
    /// caller's account, with a primary. Backed by memo_group.NickGroup. Requires
    /// login. (Distinct from single-nick reservation in reserved_nick.)
    pub fn handleGroup(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const account = conn.session.account() orelse {
            try self.failReply(conn, "GROUP", "ACCOUNT_REQUIRED", "Log in to manage your nick group");
            return;
        };
        const p = parsed.paramSlice();
        if (p.len == 0 or std.ascii.eqlIgnoreCase(p[0], "LIST")) {
            var buf: [64][]const u8 = undefined;
            const nicks = self.nick_groups.list(account, &buf) catch &.{};
            const primary = (self.nick_groups.primary(account) catch null) orelse "";
            for (nicks) |nk| {
                var b: [default_reply_bytes]u8 = undefined;
                const star: []const u8 = if (std.ascii.eqlIgnoreCase(nk, primary)) " (primary)" else "";
                const line = std.fmt.bufPrint(&b, ":{s} NOTICE {s} :GROUP {s}{s}\r\n", .{ server_name, conn.session.displayName(), nk, star }) catch continue;
                try appendToConn(conn, line);
            }
            try self.noticeTo(conn, "GROUP: end of list");
            return;
        }
        if (p.len < 2 or p[1].len == 0) {
            try self.noticeTo(conn, "Usage: GROUP <ADD|DEL|LIST|PRIMARY> [nick]");
            return;
        }
        const nick = p[1];
        if (std.ascii.eqlIgnoreCase(p[0], "ADD")) {
            _ = self.nick_groups.add(account, nick) catch {
                try self.noticeTo(conn, "GROUP: could not add (invalid, duplicate, or limit)");
                return;
            };
            try self.noticeTo(conn, "GROUP nick added");
        } else if (std.ascii.eqlIgnoreCase(p[0], "DEL")) {
            _ = self.nick_groups.remove(account, nick) catch {
                try self.noticeTo(conn, "GROUP: no such grouped nick");
                return;
            };
            try self.noticeTo(conn, "GROUP nick removed");
        } else if (std.ascii.eqlIgnoreCase(p[0], "PRIMARY")) {
            self.nick_groups.setPrimary(account, nick) catch {
                try self.noticeTo(conn, "GROUP: nick must be in your group first");
                return;
            };
            try self.noticeTo(conn, "GROUP primary set");
        } else {
            try self.noticeTo(conn, "Usage: GROUP <ADD|DEL|LIST|PRIMARY> [nick]");
        }
    }

    /// `VERIFY <code>` — confirm a pending account email verification issued at
    /// REGISTER time. Backed by account_verify.
    pub fn handleVerify(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const account = conn.session.account() orelse {
            try self.failReply(conn, "VERIFY", "ACCOUNT_REQUIRED", "Log in before verifying");
            return;
        };
        if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
            try self.noticeTo(conn, "Usage: VERIFY <code>");
            return;
        }
        const now_u: u64 = @intCast(@max(0, self.nowMs()));
        switch (self.account_verifies.confirm(account, parsed.paramSlice()[0], now_u)) {
            .verified => try self.noticeTo(conn, "VERIFY: your account email is now verified"),
            .expired => try self.failReply(conn, "VERIFY", "EXPIRED", "Verification code expired; re-register or request a new one"),
            .no_pending => try self.noticeTo(conn, "VERIFY: nothing to verify for your account"),
            .bad_token => try self.failReply(conn, "VERIFY", "INVALID_CODE", "Incorrect verification code"),
            .locked => try self.failReply(conn, "VERIFY", "TOO_MANY_ATTEMPTS", "Too many attempts; verification locked"),
        }
    }

    /// `WELCOME <ADD :line | CLEAR | SHOW>` — oper-managed network onboarding
    /// pack delivered once per account on first login (backed by welcome_pack).
    pub fn handleWelcome(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const p = parsed.paramSlice();
        if (p.len == 0 or std.ascii.eqlIgnoreCase(p[0], "SHOW")) {
            for (self.welcome.lines()) |l| {
                var b: [default_reply_bytes]u8 = undefined;
                const line = std.fmt.bufPrint(&b, ":{s} NOTICE {s} :WELCOME :{s}\r\n", .{ server_name, conn.session.displayName(), l }) catch continue;
                try appendToConn(conn, line);
            }
            try self.noticeTo(conn, "WELCOME: end of pack");
            return;
        }
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        if (std.ascii.eqlIgnoreCase(p[0], "CLEAR")) {
            self.welcome.setLines(&.{}) catch {};
            try self.noticeTo(conn, "WELCOME pack cleared");
            return;
        }
        if (std.ascii.eqlIgnoreCase(p[0], "ADD") and p.len >= 2 and p[1].len != 0) {
            // Rebuild the pack = current lines + the new one, via independent
            // dupes so setLines never aliases the pack's own storage.
            var tmp: std.ArrayListUnmanaged([]const u8) = .empty;
            defer {
                for (tmp.items) |it| self.allocator.free(it);
                tmp.deinit(self.allocator);
            }
            for (self.welcome.lines()) |l| try tmp.append(self.allocator, try self.allocator.dupe(u8, l));
            try tmp.append(self.allocator, try self.allocator.dupe(u8, p[1]));
            self.welcome.setLines(tmp.items) catch {
                try self.noticeTo(conn, "WELCOME: could not add (limit or invalid)");
                return;
            };
            try self.noticeTo(conn, "WELCOME line added");
            return;
        }
        try self.noticeTo(conn, "Usage: WELCOME <ADD :line | CLEAR | SHOW>");
    }

    /// On login, deliver the onboarding pack to a brand-new account exactly once.
    fn deliverWelcome(self: *LinuxServer, conn: *ConnState) void {
        const account = conn.session.account() orelse return;
        const lines = (self.welcome.deliverOnce(account) catch return) orelse return;
        for (lines) |l| {
            var b: [default_reply_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&b, ":{s} NOTICE {s} :[Welcome] {s}\r\n", .{ server_name, conn.session.displayName(), l }) catch continue;
            appendToConn(conn, line) catch {};
        }
    }

    /// On login, join the account's auto-join channels.
    fn applyAutojoin(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState) void {
        const account = conn.session.account() orelse return;
        const chans = self.autojoins.list(account) catch return;
        for (chans) |c| self.joinOne(id, conn, c, null, 0) catch {};
    }

    /// `SHUN <mask> [secs] [:reason]` / `UNSHUN <mask>` — oper network mute.
    /// A shunned (non-oper) sender stays connected but their PRIVMSG/NOTICE are
    /// silently dropped. Bare `SHUN` lists active shuns.
    pub fn handleShun(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView, adding: bool) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        const p = parsed.paramSlice();
        if (adding and p.len == 0) {
            var rows: [256]shun_mod.Shun = undefined;
            for (self.shuns.list(&rows)) |s| {
                var b: [default_reply_bytes]u8 = undefined;
                const line = std.fmt.bufPrint(&b, ":{s} NOTICE {s} :SHUN {s} by {s} :{s}\r\n", .{ server_name, conn.session.displayName(), s.mask, s.set_by, s.reason }) catch continue;
                try appendToConn(conn, line);
            }
            try self.noticeTo(conn, "SHUN: end of list");
            return;
        }
        if (p.len == 0) {
            try self.noticeTo(conn, "Usage: SHUN <mask> [secs] [:reason] | UNSHUN <mask>");
            return;
        }
        const mask = p[0];
        if (!adding) {
            const removed = self.shuns.remove(mask);
            var b: [default_reply_bytes]u8 = undefined;
            const note = std.fmt.bufPrint(&b, "UNSHUN {s}: {s}", .{ mask, if (removed) "removed" else "not found" }) catch return;
            try self.publishOperEvent(.oper_action, .notice, note);
            return;
        }
        // Reject over-broad shun masks (e.g. *!*@*) so a shun can't mute everyone.
        if (wildcard_limit.isTooBroad(mask, wildcard_limit.Policy.channel_ban)) {
            try self.noticeTo(conn, "SHUN: mask too broad (needs more literal characters)");
            return;
        }
        var secs: i64 = 0;
        var reason: []const u8 = "No reason";
        if (p.len >= 2) {
            if (std.fmt.parseInt(i64, p[1], 10)) |n| secs = n else |_| reason = p[1];
        }
        if (p.len >= 3) reason = p[2];
        const now = self.nowMs();
        self.shuns.add(.{
            .mask = mask,
            .reason = reason,
            .set_by = conn.session.displayName(),
            .created_ms = now,
            .expires_ms = if (secs > 0) now + secs * 1000 else 0,
        }) catch {
            try self.noticeTo(conn, "SHUN: could not add (limit or invalid mask)");
            return;
        };
        var b: [default_reply_bytes]u8 = undefined;
        const note = std.fmt.bufPrint(&b, "SHUN {s}", .{mask}) catch return;
        try self.publishOperEvent(.oper_action, .notice, note);
    }

    /// `GLOBAL [<mask>|#chan] :<text>` — oper broadcast to all users (or a
    /// hostmask/channel audience). Delivered as a server NOTICE.
    pub fn handleGlobal(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        _ = id;
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        const req = global_notice.Request.parse(parsed.paramSlice()) catch {
            try self.noticeTo(conn, "Usage: GLOBAL [<mask>|#channel] :<text>");
            return;
        };
        var line_buf: [default_reply_bytes]u8 = undefined;
        const line = global_notice.formatLine(&line_buf, server_name, req.text) catch {
            try self.noticeTo(conn, "GLOBAL: message too long");
            return;
        };
        var sent: u32 = 0;
        var it = self.rx().clients.iterator();
        while (it.next()) |entry| {
            const c = entry.value;
            if (!c.session.registered()) continue;
            // Build this recipient's facets for audience matching.
            var hm_buf: [320]u8 = undefined;
            const hm = clientPrefix(c, &hm_buf) catch continue;
            var chans: [64][]const u8 = undefined;
            const nchans = self.world.channelsOf(worldIdFromClient(entry.id), &chans);
            if (!req.inAudience(hm, chans[0..nchans])) continue;
            self.deliver(entry.id, line) catch {};
            sent += 1;
        }
        var nb: [96]u8 = undefined;
        const note = std.fmt.bufPrint(&nb, "GLOBAL sent to {d} user(s)", .{sent}) catch return;
        try self.noticeTo(conn, note);
    }

    /// `WARD <ADD|DEL|LIST|TEST> …` — the unified network-ban command for admins
    /// and opers, replacing the legacy K/D/G/Z/X/Q-line alphabet with one
    /// orthogonal model (backed by the Warden registry: Match × Scope × Action).
    /// Oper-only.
    ///   ADD  <match> <pattern> [scope] [action] [duration_secs] [:reason]
    ///   DEL  <match> <pattern>
    ///   LIST [match]
    ///   TEST <match> <value>
    pub fn handleWard(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        const p = parsed.paramSlice();
        if (p.len < 1) {
            try self.noticeTo(conn, "Usage: WARD <ADD|DEL|LIST|TEST> …");
            return;
        }
        const sub = p[0];
        if (std.ascii.eqlIgnoreCase(sub, "LIST")) {
            const only: ?warden.Match = if (p.len >= 2) warden.Match.parse(p[1]) else null;
            var rows: [256]warden.Ward = undefined;
            const wards = self.warden.list(only, &rows);
            for (wards) |w| {
                var b: [default_reply_bytes]u8 = undefined;
                const line = std.fmt.bufPrint(&b, ":{s} NOTICE {s} :WARD {s} {s} {s}/{s} by {s} :{s}\r\n", .{ server_name, conn.session.displayName(), w.match.token(), w.pattern, w.scope.token(), w.action.token(), w.set_by, w.reason }) catch continue;
                try appendToConn(conn, line);
            }
            try self.noticeTo(conn, "WARD: end of list");
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "TEST")) {
            if (p.len < 3) {
                try self.noticeTo(conn, "Usage: WARD TEST <match> <value>");
                return;
            }
            const m = warden.Match.parse(p[1]) orelse {
                try self.noticeTo(conn, "WARD: unknown match facet");
                return;
            };
            var facets = warden.Facets{};
            switch (m) {
                .address => facets.address = p[2],
                .host => facets.host = p[2],
                .mask => facets.mask = p[2],
                .account => facets.account = p[2],
                .realname => facets.realname = p[2],
                .certfp => facets.certfp = p[2],
            }
            if (self.warden.check(facets, platform.realtimeMillis())) |w| {
                var b: [default_reply_bytes]u8 = undefined;
                const line = std.fmt.bufPrint(&b, "WARD TEST: matched {s} {s} ({s}) :{s}", .{ w.match.token(), w.pattern, w.action.token(), w.reason }) catch return;
                try self.noticeTo(conn, line);
            } else {
                try self.noticeTo(conn, "WARD TEST: no match");
            }
            return;
        }
        const adding = std.ascii.eqlIgnoreCase(sub, "ADD");
        const deleting = std.ascii.eqlIgnoreCase(sub, "DEL");
        if ((!adding and !deleting) or p.len < 3) {
            try self.noticeTo(conn, "Usage: WARD ADD <match> <pattern> [scope] [action] [secs] [:reason] | DEL <match> <pattern>");
            return;
        }
        const match = warden.Match.parse(p[1]) orelse {
            try self.noticeTo(conn, "WARD: unknown match facet (address|host|mask|account|realname|certfp)");
            return;
        };
        const pattern = p[2];
        if (deleting) {
            const removed = self.warden.remove(match, pattern);
            var b: [default_reply_bytes]u8 = undefined;
            const note = std.fmt.bufPrint(&b, "WARD DEL {s} {s}: {s}", .{ match.token(), pattern, if (removed) "removed" else "not found" }) catch return;
            try self.publishOperEvent(.oper_action, .notice, note);
            return;
        }
        // Reject over-broad glob patterns (e.g. *!*@*) for non-address facets so
        // a single ward can't sweep the whole network. Address (CIDR) is exempt.
        if (match != .address and wildcard_limit.isTooBroad(pattern, wildcard_limit.Policy.channel_ban)) {
            try self.noticeTo(conn, "WARD: pattern too broad (needs more literal characters)");
            return;
        }
        // ADD: optional positional scope, action, duration, then trailing reason.
        var scope: warden.Scope = .node;
        var action: warden.Action = .expel;
        var secs: i64 = 0;
        var reason: []const u8 = "No reason";
        var i: usize = 3;
        while (i < p.len) : (i += 1) {
            if (warden.Scope.parse(p[i])) |s| {
                scope = s;
            } else if (warden.Action.parse(p[i])) |a| {
                action = a;
            } else if (std.fmt.parseInt(i64, p[i], 10)) |n| {
                secs = n;
            } else |_| {
                reason = p[i]; // first non-axis, non-numeric token is the reason
                break;
            }
        }
        const now = platform.realtimeMillis();
        self.warden.add(.{
            .match = match,
            .pattern = pattern,
            .scope = scope,
            .action = action,
            .reason = reason,
            .set_by = conn.session.displayName(),
            .created_ms = now,
            .expires_ms = if (secs > 0) now + secs * 1000 else 0,
        }) catch {
            try self.noticeTo(conn, "WARD: could not add ward (limit or invalid input)");
            return;
        };
        var b: [default_reply_bytes]u8 = undefined;
        const note = std.fmt.bufPrint(&b, "WARD ADD {s} {s} {s}/{s}", .{ match.token(), pattern, scope.token(), action.token() }) catch return;
        try self.publishOperEvent(.oper_action, .notice, note);
    }

    /// ACCEPT [+nick|-nick|*|...] — caller-id (+g) allow list. Bare/`*` lists
    /// (RPL_ACCEPTLIST 281 / RPL_ENDOFACCEPT 282); +/- add/remove. Keyed by nick.
    pub fn handleAcceptCmd(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const owner = conn.session.displayName();
        if (parsed.param_count == 0) {
            try self.sendAcceptList(conn, owner);
            return;
        }
        const cmd = accept_list.parse(parsed.paramSlice()) catch {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"ACCEPT"}, "Invalid ACCEPT");
            return;
        };
        for (cmd.slice()) |op| {
            switch (op.action) {
                .add => self.accepts.add(owner, op.nick) catch {},
                .remove => self.accepts.remove(owner, op.nick) catch {},
                .list => try self.sendAcceptList(conn, owner),
            }
        }
    }

    fn sendAcceptList(self: *LinuxServer, conn: *ConnState, owner: []const u8) !void {
        var nicks: [64][]const u8 = undefined;
        const got = self.accepts.list(owner, &nicks) catch nicks[0..0];
        for (got) |n| try queueNumeric(conn, .RPL_ACCEPTLIST, &.{n}, "");
        try queueNumeric(conn, .RPL_ENDOFACCEPT, &.{}, "End of /ACCEPT list");
    }

    /// USERIP <nick>... — like USERHOST but shows IP (340).
    pub fn handleUserip(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"USERIP"}, "Not enough parameters");
            return;
        }
        var targets: [5]userip.UseripTarget = undefined;
        var n: usize = 0;
        for (parsed.paramSlice()) |nick| {
            if (n >= targets.len) break;
            const wid = self.world.findNick(nick) orelse continue;
            const c = self.connFor(clientIdFromWorld(wid));
            targets[n] = .{
                .nick = nick,
                .oper = if (c) |cc| cc.session.isOper() else false,
                .away = if (c) |cc| cc.session.awayMessage() != null else false,
                .user = usernameOf(self, wid),
                .ip = default_host,
            };
            n += 1;
        }
        var buf: [default_reply_bytes]u8 = undefined;
        const line = userip.writeUseripReply(&buf, server_name, conn.session.displayName(), targets[0..n]) catch return;
        try appendToConn(conn, line);
        if (!std.mem.endsWith(u8, line, "\n")) try appendToConn(conn, "\r\n");
    }

    /// DIE / RESTART — oper-only server shutdown. Clears the reactor run flag so
    /// runThreaded exits after the current iteration.
    pub fn handleDie(self: *LinuxServer, conn: *ConnState, cmd: []const u8) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        var nbuf: [128]u8 = undefined;
        const note = std.fmt.bufPrint(&nbuf, "{s} requested by {s}", .{ cmd, conn.session.displayName() }) catch cmd;
        try self.publishOperEvent(.oper_action, .critical, note);
        if (self.shutdown) |flag| flag.store(false, .release);
    }

    /// `UPGRADE` — oper-only hot in-place binary upgrade (Helix). Serializes every
    /// registered session into a sealed memfd arena, then re-execs
    /// `/proc/self/exe --supervisor` preserving both the listening socket and the
    /// arena, so the port stays bound and the successor recovers session state.
    /// Client socket-fd re-attach (so connections survive, not just state) is the
    /// next increment; for now clients reconnect to the new image.
    pub fn handleUpgrade(self: *LinuxServer, conn: *ConnState) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        if (comptime builtin.os.tag != .linux) {
            try self.noticeTo(conn, "UPGRADE is Linux-only");
            return;
        }
        var nbuf: [128]u8 = undefined;
        const note = std.fmt.bufPrint(&nbuf, "UPGRADE requested by {s}", .{conn.session.displayName()}) catch "UPGRADE";
        try self.publishOperEvent(.oper_action, .critical, note);

        // Serialize every registered session into encoded snapshot pieces.
        var blobs: std.ArrayList([]u8) = .empty;
        defer {
            for (blobs.items) |b| self.allocator.free(b);
            blobs.deinit(self.allocator);
        }
        var pieces: std.ArrayList(helix_live.StatePiece) = .empty;
        defer pieces.deinit(self.allocator);
        var it = self.rx().clients.iterator();
        while (it.next()) |e| {
            if (!e.value.session.registered()) continue;
            // Don't carry the requesting oper's own connection: it issued UPGRADE
            // and its buffered reply would be lost across the swap; let it reconnect.
            if (e.value.fd == conn.fd) continue;
            var snap = e.value.session.snapshot();
            snap.fd = e.value.fd; // re-attached by the successor
            // Capture channel memberships + member modes so the successor re-joins.
            var chan_names: [64][]const u8 = undefined;
            const nch = self.world.channelsOf(worldIdFromClient(e.id), &chan_names);
            var chans: [64]session_snapshot.ChannelMembership = undefined;
            for (chan_names[0..nch], 0..) |cname, ci| {
                const m = self.world.memberModes(cname, worldIdFromClient(e.id)) orelse continue;
                chans[ci] = .{ .name = cname, .modes = m.bits };
            }
            snap.channels = chans[0..nch];
            const blob = session_snapshot.encode(self.allocator, snap) catch continue;
            blobs.append(self.allocator, blob) catch {
                self.allocator.free(blob);
                continue;
            };
            pieces.append(self.allocator, .{ .kind = .clients, .bytes = blob }) catch {};
            // Preserve the client socket across execve so the successor re-attaches it.
            _ = linux.fcntl(e.value.fd, posix.F.SETFD, 0);
        }

        // Seal the state arena. On failure, fall back to a listener-only upgrade
        // so UPGRADE still works (just without state carry-over).
        const now = self.nowMs();
        var prepared = helix_live.prepare(self.allocator, .{
            .epoch = @intCast(@max(0, now)),
            .now_ms = now,
            .timeout_ms = 5000,
            .arena_name = "mizuchi-helix",
            .pieces = pieces.items,
            .fds = &.{},
        }) catch |e| {
            var eb: [96]u8 = undefined;
            try self.noticeTo(conn, std.fmt.bufPrint(&eb, "UPGRADE: state seal failed ({s}); listener-only", .{@errorName(e)}) catch "UPGRADE: listener-only");
            return self.upgradeListenerOnly(conn);
        };
        defer prepared.deinit();

        const arena = prepared.runtime.arena orelse return self.upgradeListenerOnly(conn);
        var sbuf: [96]u8 = undefined;
        try self.noticeTo(conn, std.fmt.bufPrint(&sbuf, "UPGRADE: {d} session(s) sealed; re-exec preserving listener", .{prepared.capsule_count}) catch "UPGRADE: re-exec");

        // Preserve the listener + arena across execve (clear FD_CLOEXEC).
        _ = linux.fcntl(self.rx().listener_fd, posix.F.SETFD, 0);
        _ = linux.fcntl(arena.fd, posix.F.SETFD, 0);
        var plan = helix_live.buildArenaListenerExecPlan(self.allocator, "/proc/self/exe", arena.fd, self.rx().listener_fd) catch |e| {
            _ = linux.fcntl(self.rx().listener_fd, posix.F.SETFD, posix.FD_CLOEXEC);
            var eb: [96]u8 = undefined;
            try self.noticeTo(conn, std.fmt.bufPrint(&eb, "UPGRADE failed (plan): {s}", .{@errorName(e)}) catch "UPGRADE failed");
            return;
        };
        defer plan.deinit(self.allocator);
        plan.commit(self.allocator) catch |e| {
            _ = linux.fcntl(self.rx().listener_fd, posix.F.SETFD, posix.FD_CLOEXEC);
            var eb: [96]u8 = undefined;
            try self.noticeTo(conn, std.fmt.bufPrint(&eb, "UPGRADE failed (execve): {s}", .{@errorName(e)}) catch "UPGRADE failed");
            return;
        };
    }

    /// Successor side of UPGRADE: read the inherited state arena and re-attach
    /// every carried-over client connection (inherited socket fd + restored
    /// session) into the client table + io_uring recv. Called once after boot.
    /// Best-effort: a client that can't be re-attached is dropped, not fatal.
    pub fn adoptInheritedSessions(self: *LinuxServer) void {
        if (comptime builtin.os.tag != .linux) return;
        const arena_fd = self.config.resume_arena_fd orelse return;
        const caps = helix_live.readArena(self.allocator, arena_fd) catch |e| {
            std.debug.print("mizuchi: UPGRADE resume — arena read failed ({s})\n", .{@errorName(e)});
            return;
        };
        defer {
            for (caps) |*c| c.deinit(self.allocator);
            self.allocator.free(caps);
        }
        var adopted: usize = 0;
        for (caps) |c| {
            if (c.fields.len == 0) continue;
            const snap = session_snapshot.decode(c.fields[0].bytes) catch continue;
            if (snap.fd < 0) continue;
            if (self.adoptInheritedClient(snap)) adopted += 1;
        }
        // The arena is fully consumed; close the inherited memfd.
        closeFd(arena_fd);
        self.config.resume_arena_fd = null;
        std.debug.print("mizuchi: UPGRADE resume — re-attached {d} client connection(s)\n", .{adopted});
    }

    /// Re-attach one carried-over client: take ownership of its inherited socket
    /// fd, restore its session, and arm recv. Returns true on success.
    fn adoptInheritedClient(self: *LinuxServer, snap: session_snapshot.Snapshot) bool {
        if (self.rx().clients.len() >= self.config.max_clients) {
            closeFd(snap.fd);
            return false;
        }
        const id = self.rx().clients.alloc(ConnState.init(snap.fd)) catch {
            closeFd(snap.fd);
            return false;
        };
        const conn = self.rx().clients.get(id).?;
        conn.token = tokenFromId(id) catch {
            _ = self.rx().clients.free(id);
            closeFd(snap.fd);
            return false;
        };
        conn.connected_at_ms = self.nowMs();
        conn.last_activity_ms = conn.connected_at_ms;
        conn.session.restore(snap);
        self.injectSessionState(conn);
        // Re-populate the world nick registry so the carried client stays
        // addressable (WHOIS, PRIVMSG target). A fresh successor world has no
        // collisions; ignore NickInUse defensively. Channel membership carry-over
        // is a further refinement.
        if (snap.nick.len != 0 and !std.mem.eql(u8, snap.nick, "*")) {
            self.world.registerNick(snap.nick, worldIdFromClient(id)) catch {};
        }
        // Re-join the carried channel memberships with their exact member modes.
        var cit = session_snapshot.channelIter(snap.channels_blob);
        while (cit.next()) |ch| {
            self.world.restoreMember(ch.name, worldIdFromClient(id), .{ .bits = ch.modes }) catch {};
        }
        self.rx().ring.submitRecv(conn.token, conn.fd, &conn.recv_buf) catch {
            self.world.removeClient(worldIdFromClient(id));
            _ = self.rx().clients.free(id);
            closeFd(snap.fd);
            return false;
        };
        return true;
    }

    /// Listener-only upgrade fallback: re-exec preserving just the listening
    /// socket (no state arena). Caller has already done the oper/linux checks.
    fn upgradeListenerOnly(self: *LinuxServer, conn: *ConnState) !void {
        _ = linux.fcntl(self.rx().listener_fd, posix.F.SETFD, 0);
        var plan = helix_live.buildListenerExecPlan(self.allocator, "/proc/self/exe", self.rx().listener_fd) catch |e| {
            _ = linux.fcntl(self.rx().listener_fd, posix.F.SETFD, posix.FD_CLOEXEC);
            var eb: [96]u8 = undefined;
            try self.noticeTo(conn, std.fmt.bufPrint(&eb, "UPGRADE failed (plan): {s}", .{@errorName(e)}) catch "UPGRADE failed");
            return;
        };
        defer plan.deinit(self.allocator);
        plan.commit(self.allocator) catch |e| {
            _ = linux.fcntl(self.rx().listener_fd, posix.F.SETFD, posix.FD_CLOEXEC);
            var eb: [96]u8 = undefined;
            try self.noticeTo(conn, std.fmt.bufPrint(&eb, "UPGRADE failed (execve): {s}", .{@errorName(e)}) catch "UPGRADE failed");
            return;
        };
    }

    /// TRACE — oper-only: RPL_TRACEUSER (205) per connected client + RPL_ENDOFTRACE (262).
    pub fn handleTrace(self: *LinuxServer, conn: *ConnState) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        var scratch: [default_reply_bytes]u8 = undefined;
        var sink = ConnLineSink{ .conn = conn };
        const ctx = trace.ReplyContext{ .server_name = server_name, .requester = conn.session.displayName() };
        var it = self.rx().clients.iterator();
        while (it.next()) |e| {
            if (!e.value.session.registered()) continue;
            const entry = trace.TraceEntry{ .user = .{ .class = "users", .nick = e.value.session.displayName(), .ip = default_host, .connected_seconds = 0, .idle_seconds = 0 } };
            trace.emitTrace(ctx, &.{entry}, &scratch, &sink) catch {};
        }
        trace.emitTrace(ctx, &.{trace.TraceEntry{ .end = server_name }}, &scratch, &sink) catch {};
    }

    /// `ETRACE` (oper) — extended TRACE: one RPL_ETRACE (709) line per local
    /// registered user with class, nick, user, visible+real host, account, and
    /// real name; terminated by RPL_TRACEEND (262). Read-only.
    pub fn handleEtrace(self: *LinuxServer, conn: *ConnState) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        var buf: [default_reply_bytes]u8 = undefined;
        var it = self.rx().clients.iterator();
        while (it.next()) |e| {
            const c = e.value;
            if (!c.session.registered()) continue;
            if (c.s2s != null or c.s2s_secured != null) continue;
            const acct = c.session.account() orelse "0";
            const line = std.fmt.bufPrint(&buf, ":{s} 709 {s} users User {s} {s} {s} {s} {s} :{s}\r\n", .{
                server_name,
                conn.session.displayName(),
                c.session.displayName(),
                c.session.username(),
                c.session.host(),
                c.session.realHost(),
                acct,
                c.session.realname(),
            }) catch continue;
            appendToConn(conn, line) catch {};
        }
        const endl = std.fmt.bufPrint(&buf, ":{s} 262 {s} {s} :End of ETRACE\r\n", .{ server_name, conn.session.displayName(), server_name }) catch return;
        try appendToConn(conn, endl);
    }

    /// Map an EVENT category token (code or tag) to a daemon EventCategory.
    fn eventCategoryFromToken(token: []const u8) ?event_spine.EventCategory {
        inline for (@typeInfo(event_spine.EventCategory).@"enum".fields) |field| {
            const c: event_spine.EventCategory = @field(event_spine.EventCategory, field.name);
            if (std.ascii.eqlIgnoreCase(token, c.code()) or std.ascii.eqlIgnoreCase(token, c.token())) return c;
        }
        return null;
    }

    /// CONNECT <host> <port> — oper command: open an outbound server-to-server
    /// link to a peer. Creates a socket, stands up the outbound-side S2sLink, and
    /// submits an async io_uring connect; the handshake opens on connect completion.
    pub fn handleConnectCmd(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission denied; CONNECT is for operators");
            return;
        }
        if (parsed.param_count < 2) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"CONNECT"}, "Not enough parameters");
            return;
        }
        const host = parsed.paramSlice()[0];
        const port = std.fmt.parseInt(u16, parsed.paramSlice()[1], 10) catch {
            try self.noticeTo(conn, "CONNECT: illegal port number");
            return;
        };
        if (self.rx().clients.len() >= self.config.max_clients) {
            try self.noticeTo(conn, "CONNECT refused: connection table full");
            return;
        }
        const fd = socketTcp() catch {
            try self.noticeTo(conn, "CONNECT failed: cannot create socket");
            return;
        };
        errdefer closeFd(fd);
        const addr = sockaddrIn(host, port) catch {
            try self.noticeTo(conn, "CONNECT failed: invalid host");
            closeFd(fd);
            return;
        };
        const id = try self.rx().clients.alloc(ConnState.init(fd));
        errdefer _ = self.rx().clients.free(id);
        const peer = self.rx().clients.get(id).?;
        peer.token = try tokenFromId(id);
        peer.s2s_connect_addr = addr;

        if (self.s2sSecured()) {
            // PQ-secured initiator: waits (await_prekey) for the responder's TOFU
            // preamble after the TCP connect completes — no output yet.
            const link = try self.newSecuredLink(.initiator);
            errdefer {
                link.deinit();
                self.allocator.destroy(link);
            }
            peer.s2s_secured = link;
            errdefer peer.s2s_secured = null;
            try self.rx().ring.submitConnect(peer.token, peer.fd, @ptrCast(&peer.s2s_connect_addr), @sizeOf(posix.sockaddr.in));
            try self.noticeTo(conn, "CONNECT initiated (secured)");
            return;
        }

        const link = try self.allocator.create(s2s_link.S2sLink);
        errdefer self.allocator.destroy(link);
        try link.init(.{
            .allocator = self.allocator,
            .local_node_id = self.config.node_id,
            .remote_node_id = 0,
            .local_epoch_ms = @intCast(@max(0, platform.realtimeMillis())),
            .server_name = server_name,
        });
        errdefer link.deinit();
        peer.s2s = link;
        errdefer peer.s2s = null;

        try self.rx().ring.submitConnect(peer.token, peer.fd, @ptrCast(&peer.s2s_connect_addr), @sizeOf(posix.sockaddr.in));
        try self.noticeTo(conn, "CONNECT initiated");
    }

    /// SQUIT <server> [:reason] — oper command: tear down the S2S link to a peer
    /// identified by its (handshake-learned) server name.
    pub fn handleSquit(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission denied; SQUIT is for operators");
            return;
        }
        if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"SQUIT"}, "Not enough parameters");
            return;
        }
        const target = parsed.paramSlice()[0];
        // Find the matching peer first, then close it (don't free a slot mid-iter).
        var victim: ?RingFdToken = null;
        var it = self.rx().clients.iterator();
        while (it.next()) |entry| {
            const link = entry.value.s2s orelse continue;
            if (std.ascii.eqlIgnoreCase(link.remoteName(), target)) {
                victim = entry.value.token;
                break;
            }
        }
        if (victim) |tok| {
            try self.closeConn(tok, "SQUIT");
            try self.noticeTo(conn, "SQUIT complete");
        } else {
            try queueNumeric(conn, .ERR_NOSUCHSERVER, &.{target}, "No such server");
        }
    }

    /// Send a server NOTICE to a single connection.
    fn noticeTo(self: *LinuxServer, conn: *ConnState, text: []const u8) !void {
        _ = self;
        var buf: [default_reply_bytes]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :{s}\r\n", .{ server_name, conn.session.displayName(), text }) catch return;
        try appendToConn(conn, line);
    }

    /// Record a structured event into the flight recorder (+ category filter).
    /// Never faults the hot path.
    fn traceLog(self: *LinuxServer, comptime level: tracelog.Level, category: tracelog.Category, msg: []const u8) void {
        const now: u64 = @intCast(@max(0, self.nowMs()));
        tracelog.emit(.debug, level, &self.trace_filter, self.trace_recorder.sink(), category, now, 0, msg, &.{}) catch {};
    }

    /// DEBUG — oper command: dump the flight recorder (last N structured events)
    /// to the operator as notices. The "heavy debugging" entry point.
    pub fn handleDebug(self: *LinuxServer, conn: *ConnState) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission denied; DEBUG is for operators");
            return;
        }
        var buf: [256]tracelog.RecordedEvent = undefined;
        const events = self.trace_recorder.dump(&buf);
        var line_buf: [320]u8 = undefined;
        for (events) |ev| {
            const l = std.fmt.bufPrint(&line_buf, "[{s}/{s}] {s}", .{ ev.level.token(), ev.category.token(), ev.message() }) catch continue;
            try self.noticeTo(conn, l);
        }
        try self.noticeTo(conn, "End of DEBUG flight recorder");
    }

    /// TESTLINE <mask> — oper tool: report the first K/D-line whose mask matches
    /// `mask` (RPL_TESTLINE 725) or RPL_NOTESTLINE 726 if none.
    pub fn handleTestline(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission denied");
            return;
        }
        if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"TESTLINE"}, "Not enough parameters");
            return;
        }
        const target = parsed.paramSlice()[0];
        // Probe the target against the most common facets (IP and nick!user@host
        // / host) so a single token still reports any matching ward.
        const facets = warden.Facets{ .address = target, .mask = target, .host = target };
        if (self.warden.check(facets, platform.realtimeMillis())) |w| {
            try queueNumeric(conn, .RPL_TESTLINE, &.{ w.match.token(), w.pattern }, w.reason);
            return;
        }
        try queueNumeric(conn, .RPL_NOTESTLINE, &.{target}, "No matching ban found");
    }

    /// TESTMASK <mask> — oper tool: count connected clients whose nick!user@host
    /// matches `mask` (RPL_TESTMASK 727).
    pub fn handleTestmask(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission denied");
            return;
        }
        if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"TESTMASK"}, "Not enough parameters");
            return;
        }
        const mask = parsed.paramSlice()[0];
        var matched: u64 = 0;
        var it = self.rx().clients.iterator();
        while (it.next()) |entry| {
            const c = entry.value;
            if (!c.session.registered()) continue;
            var hm_buf: [320]u8 = undefined;
            const hostmask = std.fmt.bufPrint(&hm_buf, "{s}!{s}@{s}", .{ c.session.displayName(), c.session.username(), default_host }) catch continue;
            if (warden.globMatch(mask, hostmask)) matched += 1;
        }
        var cnt_buf: [24]u8 = undefined;
        const cnt = std.fmt.bufPrint(&cnt_buf, "{d}", .{matched}) catch "0";
        try queueNumeric(conn, .RPL_TESTMASK, &.{ mask, cnt }, "clients match");
    }

    /// MODEX <#chan[,nick]> [+/-NAMED...] — IRCX named-mode front-end. Translates
    /// named modes (AUTHONLY/OWNER/…) to mode letters and delegates to the regular
    /// MODE engine (which gates + broadcasts). A bare MODEX queries active modes
    /// (RPL_MODEXLIST 820 + RPL_MODEXEND 821).
    pub fn handleModex(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        var changes_buf: [ircx_modex.DEFAULT_MAX_CHANGES]ircx_modex.ModeChange = undefined;
        const req = ircx_modex.parseParams(parsed.paramSlice(), &changes_buf) catch {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MODEX"}, "Invalid MODEX");
            return;
        };
        const channel = req.target.channel;
        if (!self.world.channelExists(channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{channel}, "No such channel");
            return;
        }
        if (req.changes.len == 0) {
            // Query: collect active mode letters (base + IRCX-extended) as names.
            const ctx = ircx_modex.ReplyContext{ .server_name = server_name, .requester = conn.session.displayName() };
            var names: [32][]const u8 = undefined;
            var nn: usize = 0;
            var flags_buf: [16]u8 = undefined;
            const base = self.world.channelModeString(channel, &flags_buf);
            var ext_buf: [32]u8 = undefined;
            const ext = chanmode_ext.renderModes(self.world.channelExtModes(channel), &ext_buf) catch ext_buf[0..0];
            for ([_][]const u8{ base, ext }) |letters| {
                for (letters) |c| {
                    if (c == '+' or c == '-') continue;
                    if (ircx_modex.letterToName(c)) |name| {
                        if (nn < names.len) {
                            names[nn] = name;
                            nn += 1;
                        }
                    } else |_| {}
                }
            }
            var lbuf: [default_reply_bytes]u8 = undefined;
            if (ircx_modex.writeModexList(&lbuf, ctx, channel, names[0..nn])) |line| {
                try appendToConn(conn, line);
            } else |_| {}
            var ebuf: [default_reply_bytes]u8 = undefined;
            if (ircx_modex.writeModexEnd(&ebuf, ctx, channel)) |line| {
                try appendToConn(conn, line);
            } else |_| {}
            return;
        }
        // Set: synthesize an equivalent MODE line and delegate (reuses all gating,
        // tier rules, and broadcast). Member-mode nicks become positional params,
        // appended in the same order as their letters so handleMode aligns them.
        var synth = irc_line.LineView{ .raw = "", .command = "MODE" };
        synth.params[0] = channel;
        synth.param_count = 1;
        var ms_buf: [128]u8 = undefined;
        var ms = Buf{ .storage = &ms_buf };
        for (req.changes) |chg| {
            if (chg.letter) |letter| {
                ms.appendByte(chg.op.sign()) catch break;
                ms.appendByte(letter) catch break;
            }
        }
        synth.params[1] = ms.written();
        synth.param_count = 2;
        for (req.changes) |chg| {
            if (chg.letter == null) continue;
            if (chg.param) |p| {
                if (synth.param_count < synth.params.len) {
                    synth.params[synth.param_count] = p;
                    synth.param_count += 1;
                }
            }
        }
        try self.handleMode(id, conn, &synth);
    }

    /// EVENT <ADD|DEL|LIST> [category...] — IRCX Event Spine subscription control.
    /// Opers manage which oper-visible event categories they receive (the same
    /// CategoryMask that WALLOPS/KILL/oper-action publish through). Parsed
    /// daemon-native against the real event_spine (the ircx_event_cmd builder
    /// carries its own proto-local mask facade that can't see daemon types).
    pub fn handleEvent(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission denied; EVENT is for operators");
            return;
        }
        const params = parsed.paramSlice();
        if (params.len == 0) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"EVENT"}, "Not enough parameters");
            return;
        }
        // EVENT BROADCAST :<message> — send an oper announce (the former WALLOPS,
        // now folded into the Event Spine): delivered as NOTE EVENT ANNOUNCE to
        // every announce-subscribed operator.
        if (std.ascii.eqlIgnoreCase(params[0], "BROADCAST")) {
            if (params.len < 2 or params[1].len == 0) {
                try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"EVENT"}, "Not enough parameters");
                return;
            }
            var subj_buf: [256]u8 = undefined;
            const subject = try clientPrefix(conn, &subj_buf);
            var msg_buf: [512]u8 = undefined;
            const message = std.fmt.bufPrint(&msg_buf, "{s}: {s}", .{ subject, params[1] }) catch params[1];
            try self.publishOperEvent(.announce, .notice, message);
            return;
        }
        // EVENT OBSERVE <mask> [actions…] | OFF | LIST — a standing operator
        // observation subscription. Unlike a one-shot spy dump, this records the
        // operator's interest mask and pushes a live NOTE EVENT OBSERVE feed of
        // matching client lifecycle events (with real hosts); subscribing also
        // emits an immediate snapshot of the currently-matching population.
        if (std.ascii.eqlIgnoreCase(params[0], "OBSERVE")) {
            try self.handleObserve(conn, params);
            return;
        }
        const is_add = std.ascii.eqlIgnoreCase(params[0], "ADD");
        const is_del = std.ascii.eqlIgnoreCase(params[0], "DEL");
        const is_list = std.ascii.eqlIgnoreCase(params[0], "LIST");
        if (!is_add and !is_del and !is_list) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"EVENT"}, "Invalid EVENT subcommand");
            return;
        }
        if (!is_list) {
            var mask = conn.session.event_mask;
            for (params[1..]) |token| {
                const cat = eventCategoryFromToken(token) orelse continue;
                if (is_add) mask.add(cat) else mask.remove(cat);
            }
            conn.session.setEventMask(mask);
        }
        // Render the current subscription set as `EVENT LIST <CATEGORY>` lines.
        const mask = conn.session.event_mask;
        inline for (@typeInfo(event_spine.EventCategory).@"enum".fields) |field| {
            const c: event_spine.EventCategory = @field(event_spine.EventCategory, field.name);
            if (mask.contains(c)) {
                var lbuf: [128]u8 = undefined;
                if (std.fmt.bufPrint(&lbuf, "EVENT LIST {s}\r\n", .{c.code()})) |line| {
                    try appendToConn(conn, line);
                } else |_| {}
            }
        }
        try appendToConn(conn, "EVENT LIST :End of event list\r\n");
    }

    /// Stable observer key for a connection (bitcast ClientId, matching the
    /// monitor/session keying convention).
    fn observeKey(conn: *const ConnState) u64 {
        return monitorIdFromClient(idFromToken(conn.token));
    }

    /// Build an OBSERVE subject from a live connection. `host` is the REAL host —
    /// observation is an operator-trust surface, so it deliberately bypasses the
    /// cloak applied to ordinary visibility.
    fn observeSubject(conn: *const ConnState, detail: []const u8) observe_mod.Subject {
        return .{
            .nick = conn.session.displayName(),
            .user = conn.session.username(),
            .host = conn.session.realHost(),
            .account = conn.session.account(),
            .detail = detail,
        };
    }

    /// Push a live OBSERVE record to every operator whose standing filter matches
    /// the subject for this action. Best-effort; delivery failures are ignored.
    fn notifyObservers(self: *LinuxServer, action: observe_mod.Action, subject: observe_mod.Subject) void {
        if (self.observe.count() == 0) return;
        var it = self.rx().clients.iterator();
        while (it.next()) |entry| {
            if (!entry.value.session.isOper()) continue;
            const filter = self.observe.get(observeKey(entry.value)) orelse continue;
            if (!observe_mod.Registry.matches(filter, subject, action)) continue;
            var buf: [default_reply_bytes]u8 = undefined;
            const line = observe_mod.Registry.formatNote(&buf, server_name, action, subject) orelse continue;
            self.deliver(entry.id, line) catch {};
        }
    }

    /// `EVENT OBSERVE <mask> [actions…] | OFF | LIST` — manage the caller's
    /// observation subscription. Oper-gated by the EVENT command itself.
    pub fn handleObserve(self: *LinuxServer, conn: *ConnState, params: []const []const u8) !void {
        const key = observeKey(conn);
        if (params.len < 2 or params[1].len == 0 or std.ascii.eqlIgnoreCase(params[1], "LIST")) {
            if (self.observe.get(key)) |f| {
                try self.noticeTo(conn, "OBSERVE: active");
                var lbuf: [default_reply_bytes]u8 = undefined;
                if (std.fmt.bufPrint(&lbuf, ":{s} NOTE EVENT OBSERVE :filter {s}\r\n", .{ server_name, f.mask })) |line| {
                    try appendToConn(conn, line);
                } else |_| {}
            } else {
                try self.noticeTo(conn, "OBSERVE: no active subscription (EVENT OBSERVE <mask>)");
            }
            return;
        }
        if (std.ascii.eqlIgnoreCase(params[1], "OFF")) {
            _ = self.observe.clear(key);
            try self.noticeTo(conn, "OBSERVE: subscription cleared");
            return;
        }
        // Optional trailing action tokens narrow the subscription; default = all.
        var actions: u16 = 0;
        for (params[2..]) |tok| {
            if (observe_mod.Action.parse(tok)) |a| actions |= a.bit();
        }
        self.observe.set(key, params[1], actions, self.nowMs()) catch {
            try self.noticeTo(conn, "OBSERVE: could not set subscription (mask too long or too many observers)");
            return;
        };
        var hbuf: [default_reply_bytes]u8 = undefined;
        if (std.fmt.bufPrint(&hbuf, ":{s} NOTE EVENT OBSERVE :watching {s}\r\n", .{ server_name, params[1] })) |line| {
            try appendToConn(conn, line);
        } else |_| {}
        // Immediate snapshot: enumerate the currently-matching population so the
        // operator gets present state, not only future transitions.
        var it = self.rx().clients.iterator();
        while (it.next()) |entry| {
            if (!entry.value.session.registered()) continue;
            const subj = observeSubject(entry.value, "present");
            var hm: [512]u8 = undefined;
            const mask_str = std.fmt.bufPrint(&hm, "{s}!{s}@{s}", .{ subj.nick, subj.user, subj.host }) catch continue;
            if (!observe_mod.globMatch(params[1], mask_str)) continue;
            var lbuf: [default_reply_bytes]u8 = undefined;
            if (std.fmt.bufPrint(&lbuf, ":{s} NOTE EVENT OBSERVE :present {s}!{s}@{s} acct={s}\r\n", .{ server_name, subj.nick, subj.user, subj.host, subj.account orelse "*" })) |line| {
                try appendToConn(conn, line);
            } else |_| {}
        }
        try self.noticeTo(conn, "OBSERVE: end of snapshot");
    }

    /// Whether `conn` may view/manage the IRCX ACCESS list of `channel`: opers or
    /// channel-operators only (access masks are operator-sensitive).
    fn accessCanManage(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, channel: []const u8, level: ?ircx_access_store.Level) bool {
        if (conn.session.isOper()) return true;
        const mm = self.world.memberModes(channel, worldIdFromClient(id)) orelse return false;
        // OWNER-level entries may only be managed by an owner/founder (IRCX
        // ACCESS write rule); op suffices for HOST/VOICE/etc.
        if (level) |lv| {
            if (lv == .owner) return mm.contains(.owner) or mm.contains(.founder);
        }
        return mm.isOperator();
    }

    /// ACCESS <channel> <ADD|DELETE|LIST|CLEAR> [LEVEL [mask [timeout] [:reason]]] —
    /// IRCX per-channel access list (OWNER/HOST/VOICE/GRANT/DENY). Replies are
    /// RPL_ACCESS{ADD 801,DELETE 802,START 803,ENTRY 804,END 805}. All operations
    /// require channel-operator (or oper).
    pub fn handleAccess(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const req = ircx_access_store.parse(parsed.paramSlice()) catch {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"ACCESS"}, "Invalid ACCESS");
            return;
        };
        const ctx = ircx_access_store.ReplyContext{ .server_name = server_name, .requester = conn.session.displayName() };
        var buf: [default_reply_bytes]u8 = undefined;
        switch (req) {
            .list => |sel| {
                if (!self.accessCanManage(id, conn, sel.channel, sel.level)) {
                    try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{sel.channel}, "You're not channel operator");
                    return;
                }
                if (ircx_access_store.buildAccessStart(&buf, ctx, sel.channel)) |line| {
                    try appendToConn(conn, line);
                } else |_| {}
                var views: [ircx_access_store.DEFAULT_MAX_ENTRIES]ircx_access_store.EntryView = undefined;
                const rows = self.access.listMatching(sel, &views) catch views[0..0];
                for (rows) |ev| {
                    var ebuf: [default_reply_bytes]u8 = undefined;
                    const eln = ircx_access_store.buildAccessEntry(&ebuf, ctx, ev) catch continue;
                    try appendToConn(conn, eln);
                }
                var endbuf: [default_reply_bytes]u8 = undefined;
                if (ircx_access_store.buildAccessEnd(&endbuf, ctx, sel.channel)) |line| {
                    try appendToConn(conn, line);
                } else |_| {}
            },
            .add => |a| {
                if (!self.accessCanManage(id, conn, a.channel, a.level)) {
                    try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{a.channel}, "You're not channel operator");
                    return;
                }
                self.access.add(a.channel, a.level, a.mask, conn.session.displayName(), a.timeout) catch {
                    try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{a.channel}, "Cannot add ACCESS entry");
                    return;
                };
                const ev = ircx_access_store.EntryView{
                    .channel = a.channel,
                    .level = a.level,
                    .mask = a.mask,
                    .set_by = conn.session.displayName(),
                    .duration = a.timeout,
                };
                if (ircx_access_store.buildAccessAdd(&buf, ctx, ev)) |line| {
                    try appendToConn(conn, line);
                } else |_| {}
            },
            .delete => |d| {
                if (!self.accessCanManage(id, conn, d.channel, d.level)) {
                    try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{d.channel}, "You're not channel operator");
                    return;
                }
                _ = self.access.remove(d.channel, d.level, d.mask) catch false;
                if (ircx_access_store.buildAccessDelete(&buf, ctx, d)) |line| {
                    try appendToConn(conn, line);
                } else |_| {}
            },
            .clear => |sel| {
                if (!self.accessCanManage(id, conn, sel.channel, sel.level)) {
                    try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{sel.channel}, "You're not channel operator");
                    return;
                }
                _ = self.access.clear(sel) catch 0;
                if (ircx_access_store.buildAccessEnd(&buf, ctx, sel.channel)) |line| {
                    try appendToConn(conn, line);
                } else |_| {}
            },
        }
    }

    /// Effective IRCX PROP access level for `conn` mutating `entity`, or null when
    /// the client may not write it. Opers act as sysop; channel/member props need
    /// channel-operator; user props need self-ownership.
    fn propAccess(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, entity: ircx_prop_store.Entity) ?ircx_prop_store.AccessLevel {
        if (conn.session.isOper()) return .sysop;
        switch (entity.kind) {
            .channel => {
                const mm = self.world.memberModes(entity.id, worldIdFromClient(id)) orelse return null;
                return if (mm.isOperator()) .owner else null;
            },
            .member => {
                const split = std.mem.indexOfScalar(u8, entity.id, ':') orelse return null;
                const chan = entity.id[0..split];
                const mm = self.world.memberModes(chan, worldIdFromClient(id)) orelse return null;
                return if (mm.isOperator()) .owner else null;
            },
            .user => return if (std.ascii.eqlIgnoreCase(entity.id, conn.session.displayName())) .member else null,
        }
    }

    /// Whether `key` on `entity` is an IRCX secret channel property (the *KEY
    /// family), which must not be disclosed to clients lacking write access.
    fn propIsSecret(entity: ircx_prop_store.Entity, key: []const u8) bool {
        if (entity.kind != .channel) return false;
        const info = ircx_prop_store.channelPropInfo(key) orelse return false;
        return info.secret;
    }

    /// Computed/linked IRCX channel built-in property reads. These reflect live
    /// channel state, not the generic PROP store: NAME (the channel), MEMBERCOUNT
    /// (live count), MEMBERLIMIT (the +l limit). MEMBERKEY is the +k key and is
    /// secret (write-only) so it is never returned here. Returns a value rendered
    /// into `buf`, or null to fall through to the store.
    fn channelBuiltinGet(self: *LinuxServer, entity: ircx_prop_store.Entity, key: []const u8, buf: []u8) ?[]const u8 {
        if (entity.kind != .channel) return null;
        if (std.ascii.eqlIgnoreCase(key, "NAME")) return entity.id;
        if (std.ascii.eqlIgnoreCase(key, "OID")) {
            const oid = self.world.channelOid(entity.id) orelse return null;
            if (oid == 0) return null;
            // IRCX object id: '0' type prefix + 8 hex digits.
            return std.fmt.bufPrint(buf, "0{x:0>8}", .{oid}) catch null;
        }
        if (std.ascii.eqlIgnoreCase(key, "CREATION")) {
            const created = self.world.channelCreatedUnix(entity.id) orelse return null;
            if (created == 0) return null;
            return std.fmt.bufPrint(buf, "{d}", .{created}) catch null;
        }
        if (std.ascii.eqlIgnoreCase(key, "MEMBERCOUNT")) {
            return std.fmt.bufPrint(buf, "{d}", .{self.world.memberCount(entity.id)}) catch null;
        }
        if (std.ascii.eqlIgnoreCase(key, "MEMBERLIMIT")) {
            const limit = self.world.channelLimit(entity.id) orelse return null;
            return std.fmt.bufPrint(buf, "{d}", .{limit}) catch null;
        }
        return null;
    }

    /// Computed/linked IRCX channel built-in property writes. MEMBERKEY <-> +k
    /// channel key; MEMBERLIMIT <-> +l limit. Returns true if the key is a linked
    /// built-in (and was applied), false to fall through to the generic store.
    /// Access is gated by the caller (propAccess == channel-op/owner).
    const BuiltinSet = enum { not_handled, applied, bad_value };

    fn channelBuiltinSet(self: *LinuxServer, entity: ircx_prop_store.Entity, key: []const u8, value: []const u8, deleting: bool) BuiltinSet {
        if (entity.kind != .channel) return .not_handled;
        if (std.ascii.eqlIgnoreCase(key, "MEMBERKEY")) {
            if (!deleting and value.len > 31) return .bad_value; // draft cap
            self.world.setChannelKey(entity.id, if (deleting) null else value) catch return .bad_value;
            return .applied;
        }
        if (std.ascii.eqlIgnoreCase(key, "MEMBERLIMIT")) {
            if (deleting) {
                self.world.setChannelLimit(entity.id, null) catch return .bad_value;
            } else {
                const limit = std.fmt.parseInt(u32, value, 10) catch return .bad_value;
                self.world.setChannelLimit(entity.id, limit) catch return .bad_value;
            }
            return .applied;
        }
        return .not_handled;
    }

    /// Broadcast the equivalent MODE change after a PROP built-in linked to a
    /// channel mode, so every member's mode view stays in sync (MEMBERKEY→+k,
    /// MEMBERLIMIT→+l). Cleared values broadcast the `-` form.
    fn broadcastBuiltinMode(self: *LinuxServer, conn: *ConnState, channel: []const u8, key: []const u8, value: []const u8, deleting: bool) !void {
        const letter: u8 = if (std.ascii.eqlIgnoreCase(key, "MEMBERKEY")) 'k' else 'l';
        var sign_buf = [_]u8{ if (deleting) '-' else '+', letter };
        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const params: []const []const u8 = if (deleting)
            &.{ channel, sign_buf[0..] }
        else
            &.{ channel, sign_buf[0..], value };
        const msg = try formatMessage(&msg_buf, try clientPrefix(conn, &prefix_buf), "MODE", params, null);
        try self.broadcastChannel(channel, msg, null);
    }

    fn propEmitBuiltin(conn: *ConnState, entity: ircx_prop_store.Entity, key: []const u8, value: []const u8) !void {
        var buf: [default_reply_bytes]u8 = undefined;
        const ev = ircx_prop_store.EntryView{ .entity = entity, .key = key, .value = value, .owner = "*", .access = .user };
        const line = ircx_prop_store.buildPropListReply(server_name, conn.session.displayName(), ev, &buf) catch return;
        try appendToConn(conn, line);
        try appendToConn(conn, "\r\n");
    }

    fn propEmitEntry(conn: *ConnState, entry: ircx_prop_store.EntryView) !void {
        var buf: [default_reply_bytes]u8 = undefined;
        const line = ircx_prop_store.buildPropListReply(server_name, conn.session.displayName(), entry, &buf) catch return;
        try appendToConn(conn, line);
        try appendToConn(conn, "\r\n");
    }

    fn propEmitEnd(conn: *ConnState, entity: ircx_prop_store.Entity) !void {
        var buf: [default_reply_bytes]u8 = undefined;
        const line = ircx_prop_store.buildPropEndReply(server_name, conn.session.displayName(), entity, &buf) catch return;
        try appendToConn(conn, line);
        try appendToConn(conn, "\r\n");
    }

    /// PROP <entity> [<key[,key]> [:<value>]] — IRCX property get/list/set/delete.
    /// One param lists all; two gets keys; three sets (empty trailing deletes).
    /// Replies are RPL_PROPLIST 818 + RPL_PROPEND 819. Writes are gated by
    /// channel-operator (channel/member entities) or self (user entities).
    pub fn handleProp(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        // This parser folds the trailing param in without a flag; treating a 3rd
        // param as "trailing present" lets parseParamsBounded map an empty value
        // (`PROP e k :`) to delete and a non-empty value to set — both correct.
        const req = ircx_prop_store.parseParamsBounded(.{}, parsed.paramSlice(), true) catch {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"PROP"}, "Invalid PROP");
            return;
        };
        switch (req) {
            .list => |entity| {
                // Secret props (channel keys) are only visible to those who could
                // write them — never leak OWNERKEY/HOSTKEY/MEMBERKEY to bystanders.
                const may_see_secret = self.propAccess(id, conn, entity) != null;
                var views: [ircx_prop_store.default_max_props_per_entity]ircx_prop_store.EntryView = undefined;
                const rows = self.props.listProps(entity, &views) catch views[0..0];
                for (rows) |ev| {
                    if (propIsSecret(entity, ev.key) and !may_see_secret) continue;
                    try propEmitEntry(conn, ev);
                }
                try propEmitEnd(conn, entity);
            },
            .get => |q| {
                const may_see_secret = self.propAccess(id, conn, q.entity) != null;
                var it = std.mem.splitScalar(u8, q.keys, ',');
                while (it.next()) |key| {
                    if (key.len == 0) continue;
                    if (propIsSecret(q.entity, key) and !may_see_secret) continue;
                    // Computed/linked built-ins (NAME/MEMBERCOUNT/MEMBERLIMIT)
                    // reflect live channel state, ahead of the generic store.
                    var bbuf: [64]u8 = undefined;
                    if (self.channelBuiltinGet(q.entity, key, &bbuf)) |val| {
                        try propEmitBuiltin(conn, q.entity, key, val);
                        continue;
                    }
                    if (self.props.getProp(q.entity, key)) |ev| {
                        try propEmitEntry(conn, ev);
                    } else |_| {}
                }
                try propEmitEnd(conn, q.entity);
            },
            .set => |m| {
                const access = self.propAccess(id, conn, m.entity) orelse {
                    try queueNumeric(conn, .ERR_NOACCESS, &.{m.entity.id}, "Insufficient access to set property");
                    return;
                };
                // Linked built-ins (MEMBERKEY<->+k, MEMBERLIMIT<->+l) write through
                // to live channel state instead of the generic store, and broadcast
                // the equivalent MODE so member mode views stay in sync.
                switch (self.channelBuiltinSet(m.entity, m.key, m.value, false)) {
                    .applied => {
                        try self.broadcastBuiltinMode(conn, m.entity.id, m.key, m.value, false);
                        try propEmitBuiltin(conn, m.entity, m.key, m.value);
                        try propEmitEnd(conn, m.entity);
                        return;
                    },
                    .bad_value => {
                        try queueNumeric(conn, .ERR_BADVALUE, &.{ m.entity.id, m.key }, "Invalid property value");
                        return;
                    },
                    .not_handled => {},
                }
                const setter = ircx_prop_store.Setter{ .id = conn.session.displayName(), .access = access };
                const ev = self.props.setProp(m.entity, m.key, m.value, setter) catch {
                    try queueNumeric(conn, .ERR_NOACCESS, &.{m.entity.id}, "Cannot set that property");
                    return;
                };
                try propEmitEntry(conn, ev);
                try propEmitEnd(conn, m.entity);
            },
            .delete => |k| {
                if (self.propAccess(id, conn, k.entity) == null) {
                    try queueNumeric(conn, .ERR_NOACCESS, &.{k.entity.id}, "Insufficient access to delete property");
                    return;
                }
                self.props.deleteProp(k.entity, k.key) catch {};
                try propEmitEnd(conn, k.entity);
            },
        }
    }

    /// IRCX / ISIRCX — IRCX discovery + opt-in (draft-pfenning §IRCX). `IRCX`
    /// enables IRCX mode for the session; `ISIRCX` only queries. Both reply with
    /// RPL_IRCX (800): `<state> <version> <package-list> <maxmsg> <option-list>`.
    /// Mizuchi advertises its SASL mechanisms as the package list.
    pub fn handleIrcx(self: *LinuxServer, conn: *ConnState, enable: bool) !void {
        _ = self;
        if (enable) conn.ircx = true;
        const state: []const u8 = if (conn.ircx) "1" else "0";
        // version 0; package-list = advertised SASL mechs; maxmsg 512.
        try queueNumeric(conn, .RPL_IRCX, &.{ state, "0", "PLAIN,SCRAM-SHA-256,SCRAM-SHA-512,EXTERNAL", "512" }, "*");
    }

    /// Validate an IRCX DATA tag: first char [A-Za-z], rest [A-Za-z0-9.], ≤15.
    fn validDataTag(tag: []const u8) bool {
        if (tag.len == 0 or tag.len > 15) return false;
        if (!std.ascii.isAlphabetic(tag[0])) return false;
        for (tag) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '.') return false;
        }
        return true;
    }

    /// DATA / REQUEST / REPLY <target> <tag> :<message> — IRCX typed directed
    /// messaging. Tag rules: [A-z][A-z0-9.]{0,14}; reserved prefixes SYS/ADM need
    /// operator, OWN/HST need channel owner/host on a channel target. Relays
    /// `:sender <CMD> <target> <tag> :<message>` to the target (a nick, or all
    /// members of a channel).
    pub fn handleData(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (conn.gagged) return;
        if (parsed.param_count < 3) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{parsed.command}, "Not enough parameters");
            return;
        }
        const target = parsed.paramSlice()[0];
        const tag = parsed.paramSlice()[1];
        const message = parsed.paramSlice()[2];
        if (!validDataTag(tag)) {
            try queueNumeric(conn, .ERR_BADTAG, &.{tag}, "Invalid DATA tag");
            return;
        }
        // Reserved-prefix authorization (case-insensitive 3-letter prefix).
        const is_chan = world_model.isChannelName(target);
        if (tag.len >= 3) {
            const p = tag[0..3];
            if (std.ascii.eqlIgnoreCase(p, "SYS") or std.ascii.eqlIgnoreCase(p, "ADM")) {
                if (!conn.session.isOper()) {
                    try queueNumeric(conn, .ERR_NOACCESS, &.{tag}, "Reserved DATA tag (operator only)");
                    return;
                }
            } else if (std.ascii.eqlIgnoreCase(p, "OWN") or std.ascii.eqlIgnoreCase(p, "HST")) {
                const ok = is_chan and blk: {
                    const mm = self.world.memberModes(target, worldIdFromClient(id)) orelse break :blk false;
                    break :blk mm.isOperator();
                };
                if (!ok and !conn.session.isOper()) {
                    try queueNumeric(conn, .ERR_NOACCESS, &.{tag}, "Reserved DATA tag (channel owner/host only)");
                    return;
                }
            }
        }
        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const line = formatMessage(&msg_buf, try clientPrefix(conn, &prefix_buf), parsed.command, &.{ target, tag }, message) catch return;
        if (is_chan) {
            if (!self.world.channelExists(target) or !self.world.isMember(target, worldIdFromClient(id))) {
                try queueNumeric(conn, .ERR_NOTONCHANNEL, &.{target}, "You're not on that channel");
                return;
            }
            try self.broadcastChannel(target, line, null);
        } else {
            const rwid = self.world.findNick(target) orelse {
                try queueNumeric(conn, .ERR_NOSUCHNICK, &.{target}, "No such nick");
                return;
            };
            self.deliver(clientIdFromWorld(rwid), line) catch {};
        }
    }

    /// WHISPER <channel> <nick[,nick...]> :<text> — IRCX channel-scoped private
    /// message. The sender must be on the channel; each recipient is delivered a
    /// `:sender WHISPER <channel> <nick> :<text>` line only if also on the channel
    /// (ERR_NOSUCHNICK 401 / ERR_NOTONCHANNEL 442 per failing recipient).
    pub fn handleWhisper(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        var recipient_storage: [whisper.DEFAULT_MAX_RECIPIENTS][]const u8 = undefined;
        const args = whisper.parseWhisperArgs(parsed.paramSlice(), &recipient_storage) catch {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"WHISPER"}, "Not enough parameters");
            return;
        };
        if (!self.world.channelExists(args.channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{args.channel}, "No such channel");
            return;
        }
        if (!self.world.isMember(args.channel, worldIdFromClient(id))) {
            try queueNumeric(conn, .ERR_NOTONCHANNEL, &.{args.channel}, "You're not on that channel");
            return;
        }
        // +w NOWHISPER blocks channel whispers (IRCX ERR_NOWHISPER 923).
        if (self.world.channelHasExtFlag(args.channel, .nowhisper)) {
            try queueNumeric(conn, .ERR_NOWHISPER, &.{args.channel}, "Channel does not allow whispers (+w)");
            return;
        }
        const sender = whisper.Prefix{
            .nick = conn.session.displayName(),
            .user = conn.session.username(),
            .host = hostOf(conn),
        };
        for (args.recipients) |nick| {
            const rwid = self.world.findNick(nick) orelse {
                try queueNumeric(conn, .ERR_NOSUCHNICK, &.{nick}, "No such nick");
                continue;
            };
            if (!self.world.isMember(args.channel, rwid)) {
                try queueNumeric(conn, .ERR_USERNOTINCHANNEL, &.{ nick, args.channel }, "They aren't on that channel");
                continue;
            }
            var line_buf: [default_reply_bytes]u8 = undefined;
            const line = whisper.buildWhisperLine(&line_buf, sender, args.channel, nick, args.text) catch continue;
            var crlf_buf: [default_reply_bytes]u8 = undefined;
            const out = std.fmt.bufPrint(&crlf_buf, "{s}\r\n", .{line}) catch continue;
            // A single failed recipient (gone mid-dispatch) must not abort the rest.
            self.deliver(clientIdFromWorld(rwid), out) catch continue;
        }
    }

    /// CREATE <channel> [modes] — IRCX channel creation (create-or-join as
    /// founder). Delegates to the JOIN path after parsing the IRCX form.
    pub fn handleCreate(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const req = ircx_create_cmd.parseParams(parsed.paramSlice()) catch {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"CREATE"}, "Invalid CREATE");
            return;
        };
        // IRCX clone-takeover (founder-reassign, non-destructive): an operator
        // CREATEing an EXISTING channel takes founder status without evicting
        // anyone; stale ACCESS/PROP state is purged. Everyone else (and CREATE of
        // a fresh channel) falls through to the normal JOIN path.
        if (conn.session.isOper() and self.world.channelExists(req.channel)) {
            try self.operFounderTakeover(id, conn, req.channel);
            return;
        }
        try self.joinOne(id, conn, req.channel, null, 0);
    }

    /// Grant founder (+Q) to an operator on an existing channel, joining them
    /// first if needed (gate-bypassing, as a privileged takeover) and purging the
    /// channel's stale ACCESS/PROP state. Members and their existing status modes
    /// are left intact — nobody is kicked.
    fn operFounderTakeover(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, channel: []const u8) !void {
        const wid = worldIdFromClient(id);
        if (!self.world.isMember(channel, wid)) {
            _ = try self.world.join(channel, wid);
            try self.broadcastJoin(channel, conn);
        }
        _ = self.world.setMemberMode(channel, wid, .founder, true) catch {};
        // Wipe persistent ACCESS grants and channel PROPs (a fresh authority);
        // member list and their op/voice status remain.
        self.props.clearChannel(channel);
        _ = self.access.clear(.{ .channel = channel }) catch {};
        // Announce the founder grant to the channel (server-sourced MODE +Q nick).
        var line_buf: [default_reply_bytes]u8 = undefined;
        const nick = conn.session.displayName();
        const msg = try formatMessage(&line_buf, server_name, "MODE", &.{ channel, "+Q", nick }, null);
        try self.broadcastChannel(channel, msg, null);
        try self.sendTopicReply(conn, channel);
        try self.sendNames(conn, channel);
    }

    /// Whether `conn` may mutate metadata on `target`: own nick (case-insensitive)
    /// or a channel where the client holds operator status. Opers may write anywhere.
    fn metadataCanWrite(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, target: []const u8) bool {
        if (conn.session.isOper()) return true;
        // `*` is the IRCv3 metadata-2 alias for the requesting client itself.
        if (std.mem.eql(u8, target, "*")) return true;
        if (world_model.isChannelName(target)) {
            const mm = self.world.memberModes(target, worldIdFromClient(id)) orelse return false;
            return mm.isOperator();
        }
        return std.ascii.eqlIgnoreCase(target, conn.session.displayName());
    }

    /// METADATA <target> <GET|LIST|SET|CLEAR> [key [:value]] — IRCv3 metadata-2.
    /// Per-target key/value store; RPL_KEYVALUE (761) + RPL_METADATAEND (762).
    pub fn handleMetadata(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 2) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"METADATA"}, "Not enough parameters");
            return;
        }
        const target = parsed.paramSlice()[0];
        const sub = parsed.paramSlice()[1];
        // '*' is the IRCv3 metadata-2 alias for the requesting client. Key the
        // store by the resolved nick so each client has its own namespace, while
        // replies still echo the literal `target` the client sent.
        const store_target = if (std.mem.eql(u8, target, "*")) conn.session.displayName() else target;

        if (std.ascii.eqlIgnoreCase(sub, "GET")) {
            var i: usize = 2;
            while (i < parsed.param_count) : (i += 1) {
                const key = parsed.paramSlice()[i];
                if (self.metadata.get(store_target, key)) |ev| {
                    try queueNumeric(conn, .RPL_KEYVALUE, &.{ target, key, "*" }, ev.value);
                } else |_| {
                    try queueNumeric(conn, .ERR_KEYNOTSET, &.{ target, key }, "key not set");
                }
            }
        } else if (std.ascii.eqlIgnoreCase(sub, "LIST")) {
            var views: [64]metadata_store.EntryView = undefined;
            const all = self.metadata.list(store_target, &views) catch views[0..0];
            for (all) |ev| try queueNumeric(conn, .RPL_KEYVALUE, &.{ target, ev.key, "*" }, ev.value);
        } else if (std.ascii.eqlIgnoreCase(sub, "SET")) {
            if (parsed.param_count < 3) {
                try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"METADATA"}, "Not enough parameters");
                return;
            }
            // Permission gate: a client may only mutate metadata on its own nick
            // or on a channel where it holds operator status.
            if (!self.metadataCanWrite(id, conn, target)) {
                try queueNumeric(conn, .ERR_KEYNOPERMISSION, &.{ target, parsed.paramSlice()[2] }, "permission denied");
                try queueNumeric(conn, .RPL_METADATAEND, &.{}, "end of metadata");
                return;
            }
            const key = parsed.paramSlice()[2];
            if (parsed.param_count >= 4 and parsed.paramSlice()[3].len != 0) {
                const value = parsed.paramSlice()[3];
                _ = self.metadata.set(store_target, key, value) catch {
                    try queueNumeric(conn, .ERR_KEYINVALID, &.{ target, key }, "invalid key");
                    return;
                };
                try queueNumeric(conn, .RPL_KEYVALUE, &.{ target, key, "*" }, value);
            } else {
                self.metadata.delete(store_target, key) catch {};
                try queueNumeric(conn, .RPL_KEYVALUE, &.{ target, key, "*" }, "");
            }
        }
        try queueNumeric(conn, .RPL_METADATAEND, &.{}, "end of metadata");
    }

    /// REDACT <channel> <msgid> [:reason] — IRCv3 message-redaction. Tombstones
    /// the message in the CHATHISTORY ring (filtered from future replay) and
    /// broadcasts the redaction to the channel. Requires channel-operator.
    pub fn handleRedact(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 2) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"REDACT"}, "Not enough parameters");
            return;
        }
        const channel = parsed.paramSlice()[0];
        const msgid = parsed.paramSlice()[1];
        const reason = if (parsed.param_count >= 3) parsed.paramSlice()[2] else null;
        if (!self.world.channelExists(channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{channel}, "No such channel");
            return;
        }
        const mm = self.world.memberModes(channel, worldIdFromClient(id)) orelse {
            try queueNumeric(conn, .ERR_NOTONCHANNEL, &.{channel}, "You're not on that channel");
            return;
        };
        if (!mm.isOperator()) {
            try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{channel}, "You're not channel operator");
            return;
        }
        self.history.redact(channel, msgid) catch {};
        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const msg = try formatMessage(&msg_buf, try clientPrefix(conn, &prefix_buf), "REDACT", &.{ channel, msgid }, reason);
        try self.broadcastChannel(channel, msg, null);
    }

    /// HELP / HELPOP [topic] — static help topics (704/705/706, 524 if unknown).
    /// Defaults to the HELP index topic when no argument is given.
    pub fn handleHelp(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const topic = if (parsed.param_count >= 1 and parsed.paramSlice()[0].len != 0)
            parsed.paramSlice()[0]
        else
            "HELP";
        const reply = help_db.buildHelpLookupReply(self.allocator, server_name, conn.session.displayName(), topic) catch return;
        defer self.allocator.free(reply);
        try appendToConn(conn, reply);
    }

    /// STATS k/d — list Warden wards of a match facet (RPL_STATSKLINE/DLINE).
    fn statsLines(self: *LinuxServer, conn: *ConnState, match: warden.Match, code: Numeric) !void {
        var rows: [256]warden.Ward = undefined;
        const wards = self.warden.list(match, &rows);
        for (wards) |w| {
            try queueNumeric(conn, code, &.{ w.match.token(), w.pattern, w.action.token() }, w.reason);
        }
    }

    /// LUSERS — network/user counters (251-255, 265/266).
    pub fn handleLusers(self: *LinuxServer, conn: *ConnState) !void {
        const clients: u64 = @intCast(self.rx().clients.len());
        var opers: u64 = 0;
        var oit = self.rx().clients.iterator();
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
    pub fn handleMotd(self: *LinuxServer, conn: *ConnState) !void {
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
    pub fn handleTime(self: *LinuxServer, conn: *ConnState) !void {
        _ = self;
        var tbuf: [64]u8 = undefined;
        const tstr = formatServerTime(&tbuf);
        var out_buf: [default_reply_bytes]u8 = undefined;
        const line = serverinfo.writeTimeReply(&out_buf, .{ .server_name = server_name, .requester = conn.session.displayName() }, server_name, tstr) catch return;
        try appendToConn(conn, line);
    }

    /// ADMIN (256/257/258/259).
    pub fn handleAdmin(self: *LinuxServer, conn: *ConnState) !void {
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
    pub fn handleVersion(self: *LinuxServer, conn: *ConnState) !void {
        _ = self;
        var out_buf: [default_reply_bytes]u8 = undefined;
        const info = serverinfo.VersionInfo{
            .version = server_version,
            .build = "zig",
            .reply_server = server_name,
            .description = "Mizuchi IRC daemon",
        };
        const line = serverinfo.writeVersionReply(&out_buf, .{ .server_name = server_name, .requester = conn.session.displayName() }, info) catch return;
        try appendToConn(conn, line);
    }

    /// NICK <newnick> — registered nick change. Validates, rejects collisions
    /// (433), rewrites the world registry + session, then broadcasts
    /// `:old!u@h NICK :new` to the client and every common-channel member.
    /// MONITOR watchers see old offline / new online; the old identity is
    /// recorded in WHOWAS.
    /// Server-initiated forced nick change (nick-protection enforcement). Mirrors
    /// the broadcast path of handleNickChange. Best-effort: returns silently if the
    /// target nick is already taken (retried on a later sweep).
    fn forceRenameTo(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, newnick: []const u8) void {
        const wid = worldIdFromClient(id);
        var old_buf: [64]u8 = undefined;
        const old_slice = conn.session.displayName();
        if (old_slice.len == 0 or old_slice.len > old_buf.len) return;
        @memcpy(old_buf[0..old_slice.len], old_slice);
        const old = old_buf[0..old_slice.len];
        if (std.mem.eql(u8, old, newnick)) return;

        self.world.registerNick(newnick, wid) catch return; // taken → try next sweep
        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const old_prefix = clientPrefix(conn, &prefix_buf) catch return;
        const msg = formatMessage(&msg_buf, old_prefix, "NICK", &.{}, newnick) catch return;
        self.recordWhowas(conn);
        conn.session.setNick(newnick) catch return;
        self.deliver(id, msg) catch {};
        self.notifyCommonChannels(id, msg, null, id, null) catch {};
        self.monitorTransition(old, newnick) catch {};
    }

    /// Re-evaluate nick protection after a connection (re)sets its nick: if the
    /// nick maps to a registered account this connection is NOT authenticated to,
    /// start the grace timer and warn; otherwise clear it. The sweep enforces.
    fn evaluateNickProtection(self: *LinuxServer, conn: *ConnState) void {
        conn.nick_claimed_at_ms = 0;
        if (self.config.nick_grace_ms <= 0) return;
        const svc = self.account_services orelse return;
        const nick = conn.session.displayName();
        if (nick.len == 0 or std.mem.eql(u8, nick, "*")) return;
        if (conn.session.account()) |acct| {
            if (std.ascii.eqlIgnoreCase(acct, nick)) return; // already owns it
        }
        _ = svc.accountInfo(nick) catch return; // not registered → nothing to protect
        conn.nick_claimed_at_ms = self.nowMs();
        var b: [default_reply_bytes]u8 = undefined;
        const secs: u64 = @intCast(@divFloor(self.config.nick_grace_ms, 1000));
        const note = std.fmt.bufPrint(&b, ":{s} NOTICE {s} :Nick {s} is registered — IDENTIFY within {d}s or you'll be renamed to a Guest nick.\r\n", .{ server_name, nick, nick, secs }) catch return;
        appendToConn(conn, note) catch {};
    }

    pub fn handleNickChange(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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

        // +N no-nick: a non-op member of any +N channel may not change nick.
        // Server opers bypass.
        if (!conn.session.isOper()) {
            var nit = self.world.channels.iterator();
            while (nit.next()) |entry| {
                if (!entry.value_ptr.members.contains(wid)) continue;
                if (!self.world.channelHasFlag(entry.key_ptr.*, .no_nick)) continue;
                const mm = self.world.memberModes(entry.key_ptr.*, wid) orelse world_model.MemberModes.empty();
                if (!mm.isOperator()) {
                    var nb: [default_reply_bytes]u8 = undefined;
                    const note = std.fmt.bufPrint(&nb, ":{s} NOTICE {s} :Cannot change nick while on {s} (+N)\r\n", .{ server_name, old, entry.key_ptr.* }) catch return;
                    try appendToConn(conn, note);
                    return;
                }
            }
        }

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
        try self.notifyCommonChannels(id, msg, null, id, null);

        // MONITOR: old nick went away, new nick appeared.
        self.monitorTransition(old, newnick) catch {};

        // OBSERVE: push a nick-change record (detail = "-> <new>"); the subject's
        // session now carries the new nick, so report the new identity + change.
        var dbuf: [80]u8 = undefined;
        const detail = std.fmt.bufPrint(&dbuf, "<- {s}", .{old}) catch "";
        self.notifyObservers(.nick, observeSubject(conn, detail));

        // Nick protection: a newly-taken registered nick (while unauthenticated)
        // starts the grace timer; the sweep enforces a Guest rename on expiry.
        self.evaluateNickProtection(conn);
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
    pub fn handleAway(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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
        try self.notifyCommonChannels(id, msg, .away_notify, id, conn.session.displayName());

        // #33: feed the ACTIVITY stream a presence transition.
        self.pushPresenceActivity(id, conn, if (reason != null) .away else .active);
    }

    /// SETNAME :<realname> — IRCv3 setname. Updates the GECOS and echoes the
    /// change to the client and to setname-capable common-channel members.
    pub fn handleSetname(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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
        try self.notifyCommonChannels(id, msg, .setname, id, conn.session.displayName());
    }

    /// OPER <name> <password> — elevate to IRC operator. Matches against the
    /// single configured oper block; success sets the session oper flag, emits
    /// RPL_YOUREOPER (381) and the +o umode reflection.
    pub fn handleOper(self: *LinuxServer, conn: *ConnState, _: *const irc_line.LineView) !void {
        // OPER is disabled: Mizuchi grants operator status SASL-only. A client is
        // elevated automatically on SASL login when its account has an `[oper]`
        // binding (see elevateOperFromAccount). There is no password credential.
        _ = self;
        try queueNumeric(conn, .ERR_NOOPERHOST, &.{}, "OPER is disabled; authenticate via SASL (operator status is granted on login)");
    }

    /// SASL-only operator elevation: if `conn` is authenticated as an account with
    /// an `[oper]` registry binding, grant operator status (RPL_YOUREOPER + the +o
    /// reflection) and subscribe it to the Event Spine. Idempotent and silent when
    /// the account is not an operator. Called after a successful SASL login.
    fn elevateOperFromAccount(self: *LinuxServer, conn: *ConnState) !void {
        if (conn.session.isOper()) return;
        const registry = self.oper_registry orelse return;
        const account = conn.session.account() orelse return;
        _ = registry.elevate(.{ .name = account }) catch return; // not an operator: silent
        conn.session.is_oper = true;
        self.traceLog(.notice, .oper, "operator elevated via SASL account");
        // Wallops, oper notices, kills, etc. arrive as typed Event-Spine events.
        conn.session.setEventMask(event_spine.CategoryMask.all());
        try queueNumeric(conn, .RPL_YOUREOPER, &.{}, "You are now an IRC operator");
        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const prefix = try clientPrefix(conn, &prefix_buf);
        const nick = conn.session.displayName();
        const msg = try formatMessage(&msg_buf, prefix, "MODE", &.{ nick, "+o" }, null);
        try appendToConn(conn, msg);
    }

    // --- Account command family (Phase 2) ----------------------------------

    /// Map a services registration error to an IRCv3 standard-reply FAIL code.
    fn registerFailCode(err: anyerror) []const u8 {
        return switch (err) {
            error.AlreadyExists => "ACCOUNT_EXISTS",
            error.InvalidName => "BAD_ACCOUNT_NAME",
            error.InvalidPassword => "INVALID_PASSWORD",
            else => "TEMPORARILY_UNAVAILABLE",
        };
    }

    /// Services bridge: mark `channel` REGISTERED (+r) in the live world, or
    /// clear it. Registering materializes an empty persistent channel so a
    /// reserved channel survives with no members; dropping clears +r so the
    /// channel becomes ephemeral and is reclaimed on the next empty.
    pub fn markChannelRegistered(self: *LinuxServer, channel: []const u8, registered: bool) std.mem.Allocator.Error!void {
        _ = try self.world.markRegistered(channel, registered);
    }

    /// Mark `conn` logged in as the canonical (lowercased) `account`.
    fn loginSession(conn: *ConnState, account: []const u8) void {
        var buf: [account_register.MAX_ACCOUNT_BYTES]u8 = undefined;
        const n = @min(account.len, buf.len);
        const lower = std.ascii.lowerString(buf[0..n], account[0..n]);
        conn.session.loginAs(lower);
    }

    /// `REGISTER <account> <email|*> <password>` (IRCv3 draft/account-registration).
    /// Immediate registration (no email verification step yet); logs the client in
    /// and applies oper elevation if the account is bound in the registry.
    pub fn handleRegister(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const svc = self.account_services orelse return self.failReply(conn, "REGISTER", "TEMPORARILY_UNAVAILABLE", "Account registration is unavailable");
        if (parsed.param_count < 3) {
            try self.failReply(conn, "REGISTER", "NEED_MORE_PARAMS", "Usage: REGISTER <account> <email|*> <password>");
            return;
        }
        const account = parsed.paramSlice()[0];
        const password = parsed.paramSlice()[2];
        var scratch: [1024]u8 = undefined;
        _ = svc.registerAccount(account, password, &scratch) catch |err| {
            try self.failReply(conn, "REGISTER", registerFailCode(err), "Registration failed");
            return;
        };
        loginSession(conn, account);
        if (conn.session.account()) |acct| self.emitAccountChange(idFromToken(conn.token), conn, acct);
        var buf: [default_reply_bytes]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, ":{s} REGISTER SUCCESS {s} :Account registered\r\n", .{ server_name, account }) catch return;
        try appendToConn(conn, line);
        // Optional email verification: when a real contact is supplied (not "*"),
        // issue a token the user confirms with VERIFY. The account is usable
        // immediately; verification status is tracked for features that gate on it.
        const email = parsed.paramSlice()[1];
        if (email.len != 0 and !std.mem.eql(u8, email, "*")) {
            if (self.config.crypto_io) |io| {
                var tok_bytes: [16]u8 = undefined;
                io.random(&tok_bytes);
                const now_u: u64 = @intCast(@max(0, self.nowMs()));
                if (self.account_verifies.issue(account, email, &tok_bytes, now_u)) |token| {
                    try channelNotice(conn, "VERIFY {s} to confirm your email {s}", .{ token, email });
                } else |_| {}
            }
        }
        try self.elevateOperFromAccount(conn);
        self.trackSession(idFromToken(conn.token), conn);
        try self.deliverTegami(conn);
        self.applyAutojoin(idFromToken(conn.token), conn);
        self.deliverWelcome(conn);
        self.emitClientRegistered(idFromToken(conn.token), conn);
        self.evaluateNickProtection(conn);
    }

    /// `IDENTIFY <account> <password>` — authenticate to an existing account.
    pub fn handleIdentify(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const svc = self.account_services orelse return self.failReply(conn, "IDENTIFY", "TEMPORARILY_UNAVAILABLE", "Accounts are unavailable");
        if (parsed.param_count < 2) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"IDENTIFY"}, "Usage: IDENTIFY <account> <password>");
            return;
        }
        const account = parsed.paramSlice()[0];
        _ = svc.identifyAccount(account, parsed.paramSlice()[1]) catch {
            try queueNumeric(conn, .ERR_PASSWDMISMATCH, &.{}, "Invalid account or password");
            return;
        };
        loginSession(conn, account);
        if (conn.session.account()) |acct| self.emitAccountChange(idFromToken(conn.token), conn, acct);
        var buf: [default_reply_bytes]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :You are now identified as {s}\r\n", .{ server_name, conn.session.displayName(), account }) catch return;
        try appendToConn(conn, line);
        try self.elevateOperFromAccount(conn);
        self.trackSession(idFromToken(conn.token), conn);
        try self.deliverTegami(conn);
        self.applyAutojoin(idFromToken(conn.token), conn);
        self.deliverWelcome(conn);
        self.emitClientRegistered(idFromToken(conn.token), conn);
        self.evaluateNickProtection(conn);
    }

    /// `LOGOUT` — drop the session's account login (does not affect oper for now).
    pub fn handleLogout(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState) !void {
        // Drop this connection's live session before clearing the account binding
        // (the session is keyed by account; logout fully ends it, no reclaim).
        if (conn.session.account()) |acct| _ = self.sessions.remove(acct, monitorIdFromClient(id));
        // account-notify: tell common channels this user is no longer logged in
        // (emit BEFORE clearing the account so the prefix/state is still valid).
        self.emitAccountChange(id, conn, "*");
        conn.session.logout();
        var buf: [default_reply_bytes]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :You are now logged out\r\n", .{ server_name, conn.session.displayName() }) catch return;
        try appendToConn(conn, line);
    }

    /// `DROP <account> <password>` — delete an account (requires its password).
    pub fn handleDrop(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const svc = self.account_services orelse return self.failReply(conn, "DROP", "TEMPORARILY_UNAVAILABLE", "Accounts are unavailable");
        if (parsed.param_count < 2) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"DROP"}, "Usage: DROP <account> <password>");
            return;
        }
        const account = parsed.paramSlice()[0];
        _ = svc.dropAccount(account, parsed.paramSlice()[1]) catch {
            try queueNumeric(conn, .ERR_PASSWDMISMATCH, &.{}, "Invalid account or password");
            return;
        };
        var buf: [default_reply_bytes]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :Account {s} dropped\r\n", .{ server_name, conn.session.displayName(), account }) catch return;
        try appendToConn(conn, line);
    }

    /// `ACCOUNTINFO [account]` — report account name + flags (self if omitted).
    pub fn handleAccountInfo(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const svc = self.account_services orelse return self.failReply(conn, "ACCOUNTINFO", "TEMPORARILY_UNAVAILABLE", "Accounts are unavailable");
        const target = if (parsed.param_count >= 1 and parsed.paramSlice()[0].len != 0)
            parsed.paramSlice()[0]
        else
            (conn.session.account() orelse {
                try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"ACCOUNTINFO"}, "Not logged in; specify an account");
                return;
            });
        const result = svc.accountInfo(target) catch {
            try self.failReply(conn, "ACCOUNTINFO", "ACCOUNT_UNKNOWN", "No such account");
            return;
        };
        const info = result.account_info;
        var buf: [default_reply_bytes]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :account={s} flags={d}\r\n", .{ server_name, conn.session.displayName(), info.name.asSlice(), info.flags }) catch return;
        try appendToConn(conn, line);
    }

    /// `SASLINFO` — report the SASL mechanisms this server accepts and the
    /// caller's current authentication state. Read-only; available to anyone.
    pub fn handleSaslInfo(self: *LinuxServer, conn: *ConnState) !void {
        const mechs = if (self.config.sasl_checker != null)
            (if (self.config.sasl_scram256 != null) "PLAIN,SCRAM-SHA-256" else "PLAIN")
        else
            "(none configured)";
        var buf: [default_reply_bytes]u8 = undefined;
        const m = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :SASL mechanisms: {s}\r\n", .{ server_name, conn.session.displayName(), mechs }) catch return;
        try appendToConn(conn, m);
        var buf2: [default_reply_bytes]u8 = undefined;
        const status = if (conn.session.account()) |acct|
            std.fmt.bufPrint(&buf2, ":{s} NOTICE {s} :You are logged in as {s}\r\n", .{ server_name, conn.session.displayName(), acct }) catch return
        else
            std.fmt.bufPrint(&buf2, ":{s} NOTICE {s} :You are not logged in\r\n", .{ server_name, conn.session.displayName() }) catch return;
        try appendToConn(conn, status);
    }

    /// `CERTADD` — bind the TLS client-certificate fingerprint presented on this
    /// connection to the caller's logged-in account, enabling future password-less
    /// SASL EXTERNAL logins. Requires both an account login and a presented cert.
    pub fn handleCertAdd(self: *LinuxServer, conn: *ConnState) !void {
        const svc = self.account_services orelse return self.failReply(conn, "CERTADD", "TEMPORARILY_UNAVAILABLE", "Accounts are unavailable");
        const account = conn.session.account() orelse return self.failReply(conn, "CERTADD", "NOT_LOGGED_IN", "Log in before binding a certificate");
        const fp = conn.session.tls_certfp orelse return self.failReply(conn, "CERTADD", "NO_CLIENT_CERT", "No TLS client certificate presented on this connection");
        svc.bindCertfp(account, fp) catch return self.failReply(conn, "CERTADD", "CERT_ADD_FAILED", "Could not bind certificate");
        var buf: [default_reply_bytes]u8 = undefined;
        const m = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :Certificate fingerprint {s} bound to {s}\r\n", .{ server_name, conn.session.displayName(), fp, account }) catch return;
        try appendToConn(conn, m);
    }

    /// `ACCOUNTSET <account> <password> <field> <value>` — update an account
    /// setting (field = `email` or `flags`). Backed by services.setAccount.
    pub fn handleAccountSet(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const svc = self.account_services orelse return self.failReply(conn, "ACCOUNTSET", "TEMPORARILY_UNAVAILABLE", "Accounts are unavailable");
        if (parsed.param_count < 4) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"ACCOUNTSET"}, "Usage: ACCOUNTSET <account> <password> <email|flags> <value>");
            return;
        }
        const p = parsed.paramSlice();
        const account = p[0];
        const field: services_mod.AccountSetField = blk: {
            if (std.ascii.eqlIgnoreCase(p[2], "email")) break :blk .{ .email = p[3] };
            if (std.ascii.eqlIgnoreCase(p[2], "flags")) {
                const flags = std.fmt.parseInt(u32, p[3], 10) catch {
                    try self.failReply(conn, "ACCOUNTSET", "INVALID_VALUE", "flags must be a number");
                    return;
                };
                break :blk .{ .flags = flags };
            }
            try self.failReply(conn, "ACCOUNTSET", "INVALID_FIELD", "Unknown field (use email or flags)");
            return;
        };
        var scratch: [512]u8 = undefined;
        _ = svc.setAccount(account, p[1], field, &scratch) catch {
            try queueNumeric(conn, .ERR_PASSWDMISMATCH, &.{}, "Invalid account or password");
            return;
        };
        var buf: [default_reply_bytes]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :Account {s} updated ({s})\r\n", .{ server_name, conn.session.displayName(), account, p[2] }) catch return;
        try appendToConn(conn, line);
    }

    /// `GHOST <nick> <password>` — disconnect a stale session occupying a nick
    /// that belongs to the caller's account (password-verified). The victim is
    /// torn down via the standard drain-close path.
    pub fn handleGhost(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const svc = self.account_services orelse return self.failReply(conn, "GHOST", "TEMPORARILY_UNAVAILABLE", "Accounts are unavailable");
        if (parsed.param_count < 2) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"GHOST"}, "Usage: GHOST <nick> <password>");
            return;
        }
        const target = parsed.paramSlice()[0];
        _ = svc.ghostAccount(target, parsed.paramSlice()[1], target) catch {
            try queueNumeric(conn, .ERR_PASSWDMISMATCH, &.{}, "Invalid account or password");
            return;
        };
        var buf: [default_reply_bytes]u8 = undefined;
        if (self.world.findNick(target)) |wid| {
            if (self.rx().clients.get(clientIdFromWorld(wid))) |victim| {
                if (!victim.closing) {
                    const ln = std.fmt.bufPrint(&buf, ":{s} ERROR :Ghosted by {s}\r\n", .{ server_name, conn.session.displayName() }) catch return;
                    appendToConn(victim, ln) catch {};
                    victim.close_reason = "Ghosted";
                    victim.closing = true;
                    self.armSendIfNeeded(victim) catch {};
                }
            }
        }
        const line = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :Ghost session for {s} removed\r\n", .{ server_name, conn.session.displayName(), target }) catch return;
        try appendToConn(conn, line);
    }

    /// Emit a `NOTICE` from the server to this connection (services replies use
    /// real server NOTICEs — Mizuchi has NO pseudo-clients).
    fn channelNotice(conn: *ConnState, comptime fmt: []const u8, args: anytype) !void {
        var buf: [default_reply_bytes]u8 = undefined;
        const head = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :", .{ server_name, conn.session.displayName() }) catch return;
        try appendToConn(conn, head);
        var body: [default_reply_bytes]u8 = undefined;
        const msg = std.fmt.bufPrint(&body, fmt ++ "\r\n", args) catch return;
        try appendToConn(conn, msg);
    }

    /// `CHANNEL <subcommand> …` (alias `CS`) — channel registration services as a
    /// real server command (no pseudo-client). REGISTER/DROP/INFO are backed by
    /// `services.zig`; REGISTER/DROP additionally reflect into the live `+r`
    /// REGISTERED flag via the installed state hook. Founder/actor identity is the
    /// caller's logged-in account.
    pub fn handleChannel(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const svc = self.account_services orelse return self.failReply(conn, "CHANNEL", "TEMPORARILY_UNAVAILABLE", "Channel services are unavailable");
        if (parsed.param_count < 1) {
            try self.failReply(conn, "CHANNEL", "NEED_MORE_PARAMS", "Usage: CHANNEL <REGISTER|DROP|INFO|ACCESS|AKICK|SET|TRANSFER> <#channel> …");
            return;
        }
        const account = conn.session.account() orelse {
            try self.failReply(conn, "CHANNEL", "ACCOUNT_REQUIRED", "You must be logged in to use channel services");
            return;
        };
        // The CHANNEL parser expects argv[0] to be the command verb; paramSlice()
        // holds only the trailing params, so prepend the command token.
        var argv: [16][]const u8 = undefined;
        argv[0] = parsed.command;
        const params = parsed.paramSlice();
        const take = @min(params.len, argv.len - 1);
        for (params[0..take], 0..) |p, i| argv[1 + i] = p;
        const req = chanserv_cmd.parse(argv[0 .. 1 + take]) catch {
            try self.failReply(conn, "CHANNEL", "INVALID_PARAMS", "Bad CHANNEL syntax");
            return;
        };
        var scratch: [2048]u8 = undefined;
        switch (req) {
            .register => |r| {
                _ = svc.registerChannel(r.channel, account, &scratch) catch |err| {
                    try self.failReply(conn, "CHANNEL", channelFailCode(err), "Channel registration failed");
                    return;
                };
                try channelNotice(conn, "Channel {s} registered to {s}", .{ r.channel, account });
            },
            .drop => |r| {
                _ = svc.dropChannel(r.channel, account) catch |err| {
                    try self.failReply(conn, "CHANNEL", channelFailCode(err), "Channel drop failed");
                    return;
                };
                try channelNotice(conn, "Channel {s} dropped", .{r.channel});
            },
            .info => |r| {
                const result = svc.channelInfo(r.channel) catch |err| {
                    try self.failReply(conn, "CHANNEL", channelFailCode(err), "No such registered channel");
                    return;
                };
                const ci = result.channel_info;
                const mlock = self.mlocks.get(r.channel) orelse "";
                try channelNotice(conn, "channel={s} founder={s} flags={d} mlock={s}", .{ ci.name.asSlice(), ci.founder.asSlice(), ci.flags, mlock });
            },
            .set => |r| {
                // Only the registered founder may SET channel properties.
                const info = svc.channelInfo(r.channel) catch |err| {
                    try self.failReply(conn, "CHANNEL", channelFailCode(err), "No such registered channel");
                    return;
                };
                if (!std.ascii.eqlIgnoreCase(info.channel_info.founder.asSlice(), account)) {
                    try self.failReply(conn, "CHANNEL", "ACCESS_DENIED", "Only the founder may SET channel properties");
                    return;
                }
                if (r.field == .mlock) {
                    _ = mode_lock_mod.LockSpec.parse(r.value) catch {
                        try self.failReply(conn, "CHANNEL", "INVALID_PARAMS", "Bad MLOCK spec (e.g. +nt-k)");
                        return;
                    };
                    self.setMlock(r.channel, r.value) catch {
                        try self.failReply(conn, "CHANNEL", "TEMPORARILY_UNAVAILABLE", "Could not store MLOCK");
                        return;
                    };
                    try channelNotice(conn, "Channel {s} MLOCK set to {s}", .{ r.channel, r.value });
                } else {
                    try channelNotice(conn, "CHANNEL SET {s} is not available yet", .{@tagName(r.field)});
                }
            },
            else => {
                try channelNotice(conn, "{s} is not available yet", .{chanserv_cmd.fmtUsage(req.subcommand())});
            },
        }
    }

    /// Store (replace) a channel's services MLOCK spec, owning both strings.
    fn setMlock(self: *LinuxServer, channel: []const u8, spec: []const u8) !void {
        if (self.mlocks.getEntry(channel)) |e| {
            const new_spec = try self.allocator.dupe(u8, spec);
            self.allocator.free(e.value_ptr.*);
            e.value_ptr.* = new_spec;
            return;
        }
        const k = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(k);
        const v = try self.allocator.dupe(u8, spec);
        errdefer self.allocator.free(v);
        try self.mlocks.put(self.allocator, k, v);
    }

    /// Map a services channel error to an IRCv3 standard-reply FAIL code.
    fn channelFailCode(err: anyerror) []const u8 {
        return switch (err) {
            error.AlreadyExists => "CHANNEL_EXISTS",
            error.NotFound => "CHANNEL_UNKNOWN",
            error.Forbidden => "ACCESS_DENIED",
            error.InvalidChannel, error.InvalidName => "BAD_CHANNEL_NAME",
            else => "TEMPORARILY_UNAVAILABLE",
        };
    }

    /// Generate a 16-byte session reclaim token from the daemon CSPRNG (zeroed
    /// when no crypto_io is configured — reclaim then effectively disabled).
    fn genSessionToken(self: *LinuxServer) sessions_mod.Token {
        var t: sessions_mod.Token = [_]u8{0} ** 16;
        if (self.config.crypto_io) |io| io.random(&t);
        return t;
    }

    /// Register a live session for the client's account (once; keeps the token
    /// stable). No-op if the client is not logged in. Called after account login.
    fn trackSession(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState) void {
        const account = conn.session.account() orelse return;
        const cid = monitorIdFromClient(id);
        for (self.sessions.sessions(account)) |s| {
            if (s.client == cid) return; // already tracked
        }
        const signon: i64 = @intCast(@max(@as(i64, 0), self.nowMs()));
        _ = self.sessions.attach(account, cid, self.genSessionToken(), signon) catch {};
    }

    /// `SESSION [LIST|TOKEN]` — list the account's live sessions, or reveal this
    /// session's reclaim token (to the owning session only).
    pub fn handleSession(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const account = conn.session.account() orelse {
            try self.noticeTo(conn, "SESSION: you are not logged in to an account");
            return;
        };
        const cid = monitorIdFromClient(id);
        const sub = if (parsed.param_count >= 1) parsed.paramSlice()[0] else "LIST";
        var buf: [default_reply_bytes]u8 = undefined;
        if (std.ascii.eqlIgnoreCase(sub, "RESUME")) {
            try self.handleSessionResume(id, conn, account, parsed);
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "TOKEN")) {
            for (self.sessions.sessions(account)) |s| {
                if (s.client != cid) continue;
                const hex = std.fmt.bytesToHex(s.token, .lower);
                const line = std.fmt.bufPrint(&buf, ":{s} NOTE SESSION TOKEN :{s}\r\n", .{ server_name, hex }) catch return;
                try appendToConn(conn, line);
                return;
            }
            try self.noticeTo(conn, "SESSION: no token for this session");
            return;
        }
        // LIST (default): never reveal tokens here.
        var idx: usize = 0;
        for (self.sessions.sessions(account)) |s| {
            idx += 1;
            const current: []const u8 = if (s.client == cid) "*" else "-";
            const state: []const u8 = if (s.attached) "attached" else "detached";
            const line = std.fmt.bufPrint(&buf, ":{s} NOTE SESSION LIST :{s} #{d} signon={d} {s}\r\n", .{ server_name, current, idx, s.signon_ms, state }) catch continue;
            try appendToConn(conn, line);
        }
        const end = std.fmt.bufPrint(&buf, ":{s} NOTE SESSION :End of session list\r\n", .{server_name}) catch return;
        try appendToConn(conn, end);
    }

    /// `SESSION RESUME <token>` — reclaim a previously-detached session of the
    /// caller's own account by its reclaim token. The detached ghost is consumed
    /// (removed) and the caller's live session continues in its place. Bouncer
    /// replay of buffered traffic is layered on top in a later step.
    pub fn handleSessionResume(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, account: []const u8, parsed: *const irc_line.LineView) !void {
        const cid = monitorIdFromClient(id);
        const params = parsed.paramSlice();
        if (params.len < 2 or params[1].len != 2 * @sizeOf(sessions_mod.Token)) {
            try self.failReply(conn, "SESSION", "INVALID_TOKEN", "RESUME requires a valid session token");
            return;
        }
        var token: sessions_mod.Token = undefined;
        _ = std.fmt.hexToBytes(&token, params[1]) catch {
            try self.failReply(conn, "SESSION", "INVALID_TOKEN", "RESUME token is not valid hex");
            return;
        };
        const ghost = self.sessions.findTokenInAccount(account, token) orelse {
            try self.failReply(conn, "SESSION", "NO_SESSION", "No session matches that token");
            return;
        };
        if (ghost == cid) {
            try self.noticeTo(conn, "SESSION: that token is this live session; nothing to resume");
            return;
        }
        _ = self.sessions.remove(account, ghost); // reclaim consumes the ghost
        var buf: [default_reply_bytes]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, ":{s} NOTE SESSION RESUME :Session reclaimed\r\n", .{server_name}) catch return;
        try appendToConn(conn, line);
    }

    /// `TEGAMI <SEND <account> :<msg> | LIST | CLEAR>` — Mizuchi offline mail.
    /// SEND stores a message for an account (delivered when it next logs in);
    /// LIST shows the caller's own pending mail; CLEAR discards it. SEND requires
    /// the sender to be logged in (so recipients can see who wrote).
    pub fn handleTegami(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        const sub = if (parsed.param_count >= 1) parsed.paramSlice()[0] else "LIST";
        const me = conn.session.account();

        if (std.ascii.eqlIgnoreCase(sub, "LIST")) {
            const acct = me orelse {
                try self.failReply(conn, "TEGAMI", "ACCOUNT_REQUIRED", "Log in to read your tegami");
                return;
            };
            try self.tegamiList(conn, acct);
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "CLEAR")) {
            const acct = me orelse {
                try self.failReply(conn, "TEGAMI", "ACCOUNT_REQUIRED", "Log in to clear your tegami");
                return;
            };
            const n = self.tegami.clear(acct);
            var buf: [default_reply_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, ":{s} NOTE TEGAMI :Cleared {d} message(s)\r\n", .{ server_name, n }) catch return;
            try appendToConn(conn, line);
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "SEND")) {
            const from = me orelse {
                try self.failReply(conn, "TEGAMI", "ACCOUNT_REQUIRED", "Log in to send tegami");
                return;
            };
            if (parsed.param_count < 3 or parsed.paramSlice()[2].len == 0) {
                try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"TEGAMI"}, "Usage: TEGAMI SEND <account> :<message>");
                return;
            }
            const to = parsed.paramSlice()[1];
            const text = parsed.paramSlice()[2];
            // The recipient must be a known account (delivery is account-scoped).
            if (self.account_services) |svc| {
                _ = svc.accountInfo(to) catch {
                    try self.failReply(conn, "TEGAMI", "ACCOUNT_UNKNOWN", "No such account");
                    return;
                };
            }
            _ = self.tegami.send(to, from, text, platform.realtimeMillis()) catch |err| {
                const code: []const u8 = switch (err) {
                    error.MailboxFull => "MAILBOX_FULL",
                    error.MessageInvalid => "INVALID_MESSAGE",
                    else => "TEMPORARILY_UNAVAILABLE",
                };
                try self.failReply(conn, "TEGAMI", code, "Could not deliver tegami");
                return;
            };
            try self.noticeTo(conn, "TEGAMI: message stored for delivery");
            return;
        }
        try self.failReply(conn, "TEGAMI", "INVALID_SUBCOMMAND", "Use SEND, LIST, or CLEAR");
    }

    /// Emit the caller's pending tegami as NOTE lines (without clearing).
    fn tegamiList(self: *LinuxServer, conn: *ConnState, account: []const u8) !void {
        for (self.tegami.pending(account)) |m| {
            var buf: [default_reply_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, ":{s} NOTE TEGAMI :from {s} :{s}\r\n", .{ server_name, m.from, m.text }) catch continue;
            try appendToConn(conn, line);
        }
        var end_buf: [default_reply_bytes]u8 = undefined;
        const end = std.fmt.bufPrint(&end_buf, ":{s} NOTE TEGAMI :End of tegami ({d})\r\n", .{ server_name, self.tegami.count(account) }) catch return;
        try appendToConn(conn, end);
    }

    /// Deliver and clear any pending tegami for the freshly-logged-in account.
    fn deliverTegami(self: *LinuxServer, conn: *ConnState) !void {
        const account = conn.session.account() orelse return;
        const msgs = self.tegami.pending(account);
        if (msgs.len == 0) return;
        for (msgs) |m| {
            var buf: [default_reply_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, ":{s} NOTE TEGAMI :from {s} :{s}\r\n", .{ server_name, m.from, m.text }) catch continue;
            try appendToConn(conn, line);
        }
        _ = self.tegami.clear(account);
    }

    /// `MEDIA <JOIN|LEAVE|MUTE|UNMUTE|SPEAKING|ROSTER> <#chan> [kind] [arg]` —
    /// Mizuchi media control plane. Drives the per-channel SFU participant model and
    /// broadcasts room presence to channel members as `NOTE MEDIA` events so
    /// clients can render the call. The media bytes flow over the transport
    /// substrate, not this control socket. Caller must be a channel member.
    pub fn handleMedia(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 2) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MEDIA"}, "Usage: MEDIA <JOIN|LEAVE|MUTE|UNMUTE|SPEAKING|ROSTER> <#chan> [kind]");
            return;
        }
        const sub = parsed.paramSlice()[0];
        const channel = parsed.paramSlice()[1];
        if (!world_model.isChannelName(channel) or !self.world.channelExists(channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{channel}, "No such channel");
            return;
        }
        if (!self.world.isMember(channel, worldIdFromClient(id))) {
            try queueNumeric(conn, .ERR_NOTONCHANNEL, &.{channel}, "You're not on that channel");
            return;
        }
        const nick = conn.session.displayName();

        if (std.ascii.eqlIgnoreCase(sub, "ROSTER")) {
            try self.mediaRoster(conn, channel);
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "OFFER")) {
            try self.mediaOffer(
                id,
                conn,
                channel,
                if (parsed.param_count >= 3) parsed.paramSlice()[2] else "",
                if (parsed.param_count >= 4) parsed.paramSlice()[3] else "",
            );
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "ANSWER")) {
            try self.mediaAnswer(conn, channel, if (parsed.param_count >= 3) parsed.paramSlice()[2] else "");
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "PROFILE")) {
            if (self.media_rooms.profileOf(channel)) |prof|
                try mediaNegotiatedReply(conn, channel, "PROFILE", prof.slice(), prof.fec)
            else
                try self.failReply(conn, "MEDIA", "NO_OFFER", "No active call profile for this channel");
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "STATS")) {
            try self.mediaStats(conn, channel);
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "LAYER")) {
            // `MEDIA LAYER <#chan> <max_spatial> <max_temporal>` — receiver-driven
            // simulcast: ask the native SFU to forward this receiver only up to
            // the given spatial/temporal layer (e.g. a small screen / slow link
            // requests the base layer). The SFU drops higher layers without ever
            // decoding; keyframes at/below the ceiling always pass.
            if (parsed.param_count < 4) {
                try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MEDIA"}, "Usage: MEDIA LAYER <#chan> <max_spatial> <max_temporal>");
                return;
            }
            if (!self.media_rooms.isParticipant(channel, nick)) {
                try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before setting a layer ceiling");
                return;
            }
            const max_spatial = std.fmt.parseInt(u8, parsed.paramSlice()[2], 10) catch {
                try self.failReply(conn, "MEDIA", "BAD_LAYER", "max_spatial must be 0-255");
                return;
            };
            const max_temporal = std.fmt.parseInt(u3, parsed.paramSlice()[3], 10) catch {
                try self.failReply(conn, "MEDIA", "BAD_LAYER", "max_temporal must be 0-7");
                return;
            };
            self.native_media.setSelection(channel, nick, .{ .max_spatial = max_spatial, .max_temporal = max_temporal });
            var lbuf: [160]u8 = undefined;
            const lline = std.fmt.bufPrint(&lbuf, ":{s} NOTE MEDIA {s} LAYER spatial<={d} temporal<={d}\r\n", .{
                server_name, channel, max_spatial, max_temporal,
            }) catch return;
            try appendToConn(conn, lline);
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "BREAKOUT")) {
            if (parsed.param_count < 3 or parsed.paramSlice()[2].len == 0) {
                try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MEDIA"}, "Usage: MEDIA BREAKOUT <#chan> <room>");
                return;
            }
            // Must already be in the call to move between breakouts.
            if (!self.media_rooms.isParticipant(channel, nick)) {
                try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before choosing a breakout");
                return;
            }
            const bname = parsed.paramSlice()[2];
            self.media_rooms.setBreakout(channel, nick, bname) catch {
                try self.failReply(conn, "MEDIA", "BREAKOUT_FAILED", "Could not set breakout");
                return;
            };
            try self.broadcastMediaEvent(channel, "BREAKOUT", nick, bname);
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "POS")) {
            if (parsed.param_count < 4) {
                try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MEDIA"}, "Usage: MEDIA POS <#chan> <x> <y>");
                return;
            }
            if (!self.media_rooms.isParticipant(channel, nick)) {
                try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before setting a position");
                return;
            }
            const x = std.fmt.parseInt(i32, parsed.paramSlice()[2], 10) catch {
                try self.failReply(conn, "MEDIA", "INVALID_POSITION", "x and y must be integers");
                return;
            };
            const y = std.fmt.parseInt(i32, parsed.paramSlice()[3], 10) catch {
                try self.failReply(conn, "MEDIA", "INVALID_POSITION", "x and y must be integers");
                return;
            };
            self.media_rooms.setPosition(channel, nick, .{ .x = x, .y = y }) catch {
                try self.failReply(conn, "MEDIA", "POS_FAILED", "Could not set position");
                return;
            };
            var xy_buf: [32]u8 = undefined;
            const xy = std.fmt.bufPrint(&xy_buf, "{d} {d}", .{ x, y }) catch return;
            try self.broadcastMediaEvent(channel, "POS", nick, xy);
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "CAPTION")) {
            if (parsed.param_count < 3 or parsed.paramSlice()[2].len == 0) {
                try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MEDIA"}, "Usage: MEDIA CAPTION <#chan> :<text>");
                return;
            }
            if (!self.media_rooms.isParticipant(channel, nick)) {
                try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before captioning");
                return;
            }
            const text = parsed.paramSlice()[2];
            _ = self.transcript.push(channel, nick, text, platform.realtimeMillis()) catch {}; // retention is best-effort
            // Live fan-out (text may contain spaces, so use a trailing `:` param).
            var buf: [default_reply_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, ":{s} NOTE MEDIA {s} CAPTION {s} :{s}\r\n", .{ server_name, channel, nick, text }) catch return;
            try self.broadcastChannel(channel, line, null);
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "TRANSCRIPT")) {
            for (self.transcript.recent(channel)) |c| {
                var buf: [default_reply_bytes]u8 = undefined;
                const line = std.fmt.bufPrint(&buf, ":{s} NOTE MEDIA {s} TRANSCRIPT {s} :{s}\r\n", .{ server_name, channel, c.speaker, c.text }) catch continue;
                try appendToConn(conn, line);
            }
            var end_buf: [default_reply_bytes]u8 = undefined;
            const end = std.fmt.bufPrint(&end_buf, ":{s} NOTE MEDIA {s} :End of transcript ({d})\r\n", .{ server_name, channel, self.transcript.recent(channel).len }) catch return;
            try appendToConn(conn, end);
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "HAND")) {
            if (!self.media_rooms.isParticipant(channel, nick)) {
                try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before raising your hand");
                return;
            }
            const up = parsed.param_count < 3 or // bare HAND raises
                std.ascii.eqlIgnoreCase(parsed.paramSlice()[2], "up") or
                std.ascii.eqlIgnoreCase(parsed.paramSlice()[2], "1");
            self.media_rooms.setHand(channel, nick, up) catch {
                try self.failReply(conn, "MEDIA", "HAND_FAILED", "Could not update hand");
                return;
            };
            try self.broadcastMediaEvent(channel, "HAND", nick, if (up) "up" else "down");
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "REACT")) {
            if (parsed.param_count < 3 or parsed.paramSlice()[2].len == 0 or parsed.paramSlice()[2].len > 32) {
                try self.failReply(conn, "MEDIA", "INVALID_REACTION", "Usage: MEDIA REACT <#chan> <reaction>");
                return;
            }
            if (!self.media_rooms.isParticipant(channel, nick)) {
                try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before reacting");
                return;
            }
            // Ephemeral: broadcast only, no retention.
            try self.broadcastMediaEvent(channel, "REACT", nick, parsed.paramSlice()[2]);
            return;
        }
        if (std.ascii.eqlIgnoreCase(sub, "LEAVE")) {
            if (self.media_rooms.leaveAll(channel, nick)) {
                self.media_plane.remove(channel, nick);
                self.native_media.unregister(channel, nick);
                self.bridgeUnregister(channel, nick);
                try self.broadcastMediaEvent(channel, "LEAVE", nick, "");
                if (self.media_rooms.room(channel) == null) _ = self.transcript.clearChannel(channel); // call ended
            } else try self.noticeTo(conn, "MEDIA: you are not in this call");
            return;
        }

        // The remaining subcommands all take a kind (default voice).
        const kind_tok = if (parsed.param_count >= 3) parsed.paramSlice()[2] else "voice";
        const kind = media_room.parseKind(kind_tok) orelse {
            try self.failReply(conn, "MEDIA", "INVALID_KIND", "Kind must be voice, video, or screen");
            return;
        };
        const kname = media_room.kindName(kind);

        if (std.ascii.eqlIgnoreCase(sub, "JOIN")) {
            self.media_rooms.join(channel, nick, kind) catch {
                try self.failReply(conn, "MEDIA", "JOIN_FAILED", "Could not join the call");
                return;
            };
            try self.broadcastMediaEvent(channel, "JOIN", nick, kname);
        } else if (std.ascii.eqlIgnoreCase(sub, "MUTE")) {
            if (self.media_rooms.setMuted(channel, nick, kind, true))
                try self.broadcastMediaEvent(channel, "MUTE", nick, kname)
            else
                try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "You are not publishing that kind");
        } else if (std.ascii.eqlIgnoreCase(sub, "UNMUTE")) {
            if (self.media_rooms.setMuted(channel, nick, kind, false))
                try self.broadcastMediaEvent(channel, "UNMUTE", nick, kname)
            else
                try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "You are not publishing that kind");
        } else if (std.ascii.eqlIgnoreCase(sub, "SPEAKING")) {
            const on = parsed.param_count >= 4 and
                (std.ascii.eqlIgnoreCase(parsed.paramSlice()[3], "on") or std.ascii.eqlIgnoreCase(parsed.paramSlice()[3], "1"));
            if (self.media_rooms.setSpeaking(channel, nick, kind, on))
                try self.broadcastMediaEvent(channel, if (on) "SPEAKING" else "SILENT", nick, kname)
            else
                try self.failReply(conn, "MEDIA", "NOT_PUBLISHING", "You are not publishing that kind");
        } else {
            try self.failReply(conn, "MEDIA", "INVALID_SUBCOMMAND", "Use JOIN, LEAVE, MUTE, UNMUTE, SPEAKING, BREAKOUT, POS, HAND, REACT, CAPTION, TRANSCRIPT, or ROSTER");
        }
    }

    /// Broadcast a `:server NOTE MEDIA <#chan> <verb> <nick> [kind]` presence
    /// event to every member of `channel` (including the actor).
    fn broadcastMediaEvent(self: *LinuxServer, channel: []const u8, verb: []const u8, nick: []const u8, kind: []const u8) !void {
        var buf: [default_reply_bytes]u8 = undefined;
        const line = if (kind.len != 0)
            std.fmt.bufPrint(&buf, ":{s} NOTE MEDIA {s} {s} {s} {s}\r\n", .{ server_name, channel, verb, nick, kind }) catch return
        else
            std.fmt.bufPrint(&buf, ":{s} NOTE MEDIA {s} {s} {s}\r\n", .{ server_name, channel, verb, nick }) catch return;
        try self.broadcastChannel(channel, line, null);
    }

    /// Remove a departing client from every media call it was in, broadcasting a
    /// LEAVE to each affected channel. Called on disconnect (before the client is
    /// removed from the world, so it is still a member for the broadcast).
    fn leaveAllMediaRooms(self: *LinuxServer, id: client_model.ClientId, conn: *const ConnState) void {
        const nick = conn.session.displayName();
        if (std.mem.eql(u8, nick, "*")) return;
        var it = self.world.channels.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.members.contains(worldIdFromClient(id))) continue;
            if (self.media_rooms.leaveAll(entry.key_ptr.*, nick)) {
                self.media_plane.remove(entry.key_ptr.*, nick);
                self.native_media.unregister(entry.key_ptr.*, nick);
                self.bridgeUnregister(entry.key_ptr.*, nick);
                self.broadcastMediaEvent(entry.key_ptr.*, "LEAVE", nick, "") catch {};
                if (self.media_rooms.room(entry.key_ptr.*) == null) _ = self.transcript.clearChannel(entry.key_ptr.*);
            }
        }
    }

    /// Emit the current call roster for `channel` to the caller: one
    /// `NOTE MEDIA <#chan> ROSTER <nick> <kinds>` line per participant.
    fn codecTagName(tag: sdp.CodecTag) []const u8 {
        return switch (tag) {
            .opvox => "opvox",
            .opvis => "opvis",
            .raw => "raw",
        };
    }

    fn fecSchemeName(scheme: sdp.FecScheme) []const u8 {
        return switch (scheme) {
            .none => "none",
            .rateless_lt => "rateless_lt",
            .rs_block => "rs_block",
        };
    }

    /// Parse a "codec[,codec...]" list into `out`, returning how many were
    /// recognized. Unknown names are skipped; the clock rate is codec-derived.
    fn parseCodecCsv(out: []sdp.Codec, codec_csv: []const u8) usize {
        var n: usize = 0;
        var it = std.mem.splitScalar(u8, codec_csv, ',');
        while (it.next()) |name| {
            if (name.len == 0 or n >= out.len) continue;
            const tag: sdp.CodecTag = if (std.ascii.eqlIgnoreCase(name, "opvox"))
                .opvox
            else if (std.ascii.eqlIgnoreCase(name, "opvis"))
                .opvis
            else if (std.ascii.eqlIgnoreCase(name, "raw"))
                .raw
            else
                continue;
            out[n] = .{ .tag = tag, .clock_rate = if (tag == .opvis) 90000 else 48000, .params = 0 };
            n += 1;
        }
        return n;
    }

    /// Format `:server NOTE MEDIA <#chan> <label> codecs=<list> fec=<scheme>\r\n`
    /// into `buf`, returning the written slice (null if it would not fit).
    fn formatMediaCodecLine(buf: []u8, channel: []const u8, label: []const u8, codecs: []const sdp.Codec, fec: sdp.Fec) ?[]const u8 {
        var w = Buf{ .storage = buf };
        w.append(":") catch return null;
        w.append(server_name) catch return null;
        w.append(" NOTE MEDIA ") catch return null;
        w.append(channel) catch return null;
        w.appendByte(' ') catch return null;
        w.append(label) catch return null;
        w.append(" codecs=") catch return null;
        for (codecs, 0..) |c, i| {
            if (i != 0) w.appendByte(',') catch return null;
            w.append(codecTagName(c.tag)) catch return null;
        }
        w.append(" fec=") catch return null;
        w.append(fecSchemeName(fec.scheme)) catch return null;
        w.append("\r\n") catch return null;
        return w.written();
    }

    /// Emit `:server NOTE MEDIA <#chan> <label> codecs=<list> fec=<scheme>`.
    fn mediaNegotiatedReply(conn: *ConnState, channel: []const u8, label: []const u8, codecs: []const sdp.Codec, fec: sdp.Fec) !void {
        var buf: [320]u8 = undefined;
        const line = formatMediaCodecLine(&buf, channel, label, codecs, fec) orelse return;
        try appendToConn(conn, line);
    }

    /// `MEDIA OFFER <#chan> <codec[,codec...]>` — negotiate the call's codec + FEC
    /// set against the SFU's supported codecs (real sdp/media_session offer/answer),
    /// persist it as the channel's active call profile, and reply with the agreed
    /// set. The UDP transport plane (ICE/STUN/TURN/jitter) is a separate layer;
    /// this is the live signaling/negotiation half.
    fn mediaOffer(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, channel: []const u8, codec_csv: []const u8, transport_arg: []const u8) !void {
        var cbuf: [4]sdp.Codec = undefined;
        const cn = parseCodecCsv(&cbuf, codec_csv);
        if (cn == 0) {
            try self.failReply(conn, "MEDIA", "NO_CODECS", "Offer at least one codec: opvox,opvis,raw");
            return;
        }
        const remote = sdp.MediaDescription{ .band_id = 64, .kind = .audio, .codecs = cbuf[0..cn], .fec = .{ .scheme = .rs_block, .redundancy = 1 }, .direction = .sendrecv };
        const server_codecs = [_]sdp.Codec{
            .{ .tag = .opvox, .clock_rate = 48000, .params = 0 },
            .{ .tag = .opvis, .clock_rate = 90000, .params = 0 },
        };
        const local = sdp.MediaDescription{ .band_id = 64, .kind = .audio, .codecs = &server_codecs, .fec = .{ .scheme = .rs_block, .redundancy = 1 }, .direction = .sendrecv };
        var negotiated = media_session.negotiate(self.allocator, local, remote) catch {
            try self.failReply(conn, "MEDIA", "NEGOTIATE_FAILED", "No common codec");
            return;
        };
        defer negotiated.deinit(self.allocator);
        if (negotiated.codecs.len == 0) {
            try self.failReply(conn, "MEDIA", "NO_COMMON_CODEC", "No codec in common with the SFU");
            return;
        }
        // Persist the agreed set as the call profile a later ANSWER negotiates against.
        self.media_rooms.setProfile(channel, negotiated.codecs, negotiated.fec) catch {};
        try mediaNegotiatedReply(conn, channel, "OFFER-ACK", negotiated.codecs, negotiated.fec);
        // Push the new profile to the rest of the channel so everyone converges.
        var pbuf: [320]u8 = undefined;
        if (formatMediaCodecLine(&pbuf, channel, "PROFILE", negotiated.codecs, negotiated.fec)) |line|
            self.broadcastChannel(channel, line, id) catch {};
        // Allocate this caller's ICE endpoint and advertise the server transport
        // (ufrag/pwd + media candidate) so the client can run STUN to the SFU.
        const nick = conn.session.displayName();
        if (self.media_plane.allocate(channel, nick)) |creds| {
            // Per-call SRTP group key (SDES), base64'd; safe over the TLS IRC link.
            const gk = self.media_plane.groupKey(channel);
            var gk_b64: [std.base64.standard.Encoder.calcSize(gk.len)]u8 = undefined;
            const srtp_b64 = std.base64.standard.Encoder.encode(&gk_b64, &gk);
            // Prefer the STUN-discovered reflexive candidate over the static host.
            var host_buf: [16]u8 = undefined;
            const cand_host = self.media_plane.candidateIp(&host_buf) orelse self.config.media_host;
            var tbuf: [400]u8 = undefined;
            const tline = std.fmt.bufPrint(&tbuf, ":{s} NOTE MEDIA {s} TRANSPORT ufrag={s} pwd={s} candidate={s}:{d} srtp={s}\r\n", .{
                server_name, channel, creds.ufragSlice(), creds.pwdSlice(), cand_host, self.media_plane.port, srtp_b64,
            }) catch return;
            try appendToConn(conn, tline);
        }
        // Native transport (our own OPVOX/OPVIS codec leg): register this caller
        // for the channel's native call and advertise the candidate + the
        // stream_id the client must stamp into its opcodec frames. Independent of
        // the WebRTC plane above; best-effort (media is optional).
        const stream_id = nativeStreamId(channel, nick);
        if (self.native_media.port != 0) {
            self.native_media.register(channel, nick, .voice, stream_id, .{}) catch {};
            var nbuf: [256]u8 = undefined;
            const nline = std.fmt.bufPrint(&nbuf, ":{s} NOTE MEDIA {s} NATIVE candidate={s}:{d} stream={d} codec=OPVOX/OPVIS\r\n", .{
                server_name, channel, self.config.media_host, self.native_media.port, stream_id,
            }) catch return;
            try appendToConn(conn, nline);
        }
        // Record this participant's leg in the per-channel cross-leg bridge. The
        // client opts into the WebRTC leg with `transport=webrtc` (default native).
        // The bridge lets a native participant and an opt-in-WebRTC participant in
        // the same call hear each other (rewrap only, never transcode).
        const want_webrtc = isWebrtcTransport(transport_arg);
        const leg: media_bridge_mod.Leg = if (want_webrtc) .webrtc else .native;
        self.bridgeRegister(channel, nick, leg, stream_id);
    }

    /// True when the OFFER's transport token opts into the WebRTC leg
    /// (`transport=webrtc` or bare `webrtc`); anything else means native.
    fn isWebrtcTransport(arg: []const u8) bool {
        const v = if (std.mem.startsWith(u8, arg, "transport=")) arg["transport=".len..] else arg;
        return std.ascii.eqlIgnoreCase(v, "webrtc");
    }

    /// Register (or update) a participant's leg in the channel's bridge roster.
    fn bridgeRegister(self: *LinuxServer, channel: []const u8, id: []const u8, leg: media_bridge_mod.Leg, stream_id: u32) void {
        lockSpin(&self.media_bridges_mu);
        defer self.media_bridges_mu.unlock();
        const gop = self.media_bridges.getOrPut(self.allocator, channel) catch return;
        if (!gop.found_existing) {
            const key = self.allocator.dupe(u8, channel) catch {
                _ = self.media_bridges.remove(channel);
                return;
            };
            gop.key_ptr.* = key;
            gop.value_ptr.* = Bridge.init();
        }
        gop.value_ptr.register(id, .{ .leg = leg, .stream_id = stream_id, .ssrc = stream_id }) catch {};
    }

    /// Remove a participant from the channel's bridge; drop the channel once empty.
    fn bridgeUnregister(self: *LinuxServer, channel: []const u8, id: []const u8) void {
        lockSpin(&self.media_bridges_mu);
        defer self.media_bridges_mu.unlock();
        const br = self.media_bridges.getPtr(channel) orelse return;
        _ = br.unregister(id);
        if (br.count() != 0) return;
        const key = self.media_bridges.getKey(channel).?;
        _ = self.media_bridges.remove(channel);
        self.allocator.free(key);
    }

    /// Deterministic per-(channel,participant) opcodec stream id advertised to the
    /// native client; it stamps this into every opcodec frame it publishes so the
    /// SFU can map a frame back to its publisher. Never 0 (0 reads as "unset").
    fn nativeStreamId(channel: []const u8, nick: []const u8) u32 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(channel);
        hasher.update(":");
        hasher.update(nick);
        const v: u32 = @truncate(hasher.final());
        return if (v == 0) 1 else v;
    }

    /// `MEDIA ANSWER <#chan> <codec[,codec...]>` — a later participant reconciles
    /// their codec capabilities against the call's active profile (set by OFFER).
    /// Replies with the intersection so everyone converges on a shared media set.
    fn mediaAnswer(self: *LinuxServer, conn: *ConnState, channel: []const u8, codec_csv: []const u8) !void {
        const prof = self.media_rooms.profileOf(channel) orelse {
            try self.failReply(conn, "MEDIA", "NO_OFFER", "No active call profile; send MEDIA OFFER first");
            return;
        };
        var cbuf: [4]sdp.Codec = undefined;
        const cn = parseCodecCsv(&cbuf, codec_csv);
        if (cn == 0) {
            try self.failReply(conn, "MEDIA", "NO_CODECS", "Answer at least one codec: opvox,opvis,raw");
            return;
        }
        const answerer = sdp.MediaDescription{ .band_id = 64, .kind = .audio, .codecs = cbuf[0..cn], .fec = .{ .scheme = .rs_block, .redundancy = 1 }, .direction = .sendrecv };
        const offered = sdp.MediaDescription{ .band_id = 64, .kind = .audio, .codecs = prof.slice(), .fec = prof.fec, .direction = .sendrecv };
        var negotiated = media_session.negotiate(self.allocator, offered, answerer) catch {
            try self.failReply(conn, "MEDIA", "NO_COMMON_CODEC", "No codec in common with the call profile");
            return;
        };
        defer negotiated.deinit(self.allocator);
        if (negotiated.codecs.len == 0) {
            try self.failReply(conn, "MEDIA", "NO_COMMON_CODEC", "No codec in common with the call profile");
            return;
        }
        try mediaNegotiatedReply(conn, channel, "ANSWER-ACK", negotiated.codecs, negotiated.fec);
    }

    /// `MEDIA STATS <#chan>` — per-participant transport state: ICE status and
    /// relayed packet/byte counts, terminated by an end line.
    fn mediaStats(self: *LinuxServer, conn: *ConnState, channel: []const u8) !void {
        var buf_stats: [64]media_plane_mod.MediaTransport.ParticipantStat = undefined;
        const n = self.media_plane.statsForChannel(channel, &buf_stats);
        for (buf_stats[0..n]) |s| {
            var buf: [default_reply_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, ":{s} NOTE MEDIA {s} STATS {s} leg=webrtc ice={s} ssrc={x} rx_pkts={d} rx_bytes={d}\r\n", .{
                server_name, channel, s.name(), if (s.connected) "connected" else "pending", s.ssrc, s.rx_packets, s.rx_bytes,
            }) catch continue;
            try appendToConn(conn, line);
        }
        // Native leg (our own OPVOX/OPVIS codec) stats.
        var native_stats: [native_media_mod.max_call_participants]native_media_mod.NativeMediaTransport.Stat = undefined;
        const nn = self.native_media.statsForChannel(channel, &native_stats);
        for (native_stats[0..nn]) |s| {
            var buf: [default_reply_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, ":{s} NOTE MEDIA {s} STATS {s} leg=native stream={d} rx_pkts={d} rx_bytes={d}\r\n", .{
                server_name, channel, s.name(), s.stream_id, s.rx_packets, s.rx_bytes,
            }) catch continue;
            try appendToConn(conn, line);
        }
        var end_buf: [default_reply_bytes]u8 = undefined;
        const end = std.fmt.bufPrint(&end_buf, ":{s} NOTE MEDIA {s} :End of media stats ({d})\r\n", .{ server_name, channel, n + nn }) catch return;
        try appendToConn(conn, end);
    }

    fn mediaRoster(self: *LinuxServer, conn: *ConnState, channel: []const u8) !void {
        for (self.media_rooms.roster(channel)) |p| {
            var kinds_buf: [32]u8 = undefined;
            var n: usize = 0;
            inline for (.{ media_room.MediaKind.voice, .video, .screen }) |k| {
                if (p.joined.contains(k)) {
                    const name = media_room.kindName(k);
                    const mark: []const u8 = if (p.muted.contains(k)) "-" else if (p.speaking.contains(k)) "*" else "";
                    if (n != 0 and n < kinds_buf.len) {
                        kinds_buf[n] = ',';
                        n += 1;
                    }
                    for (mark) |c| {
                        if (n < kinds_buf.len) {
                            kinds_buf[n] = c;
                            n += 1;
                        }
                    }
                    if (n + name.len <= kinds_buf.len) {
                        @memcpy(kinds_buf[n .. n + name.len], name);
                        n += name.len;
                    }
                }
            }
            const breakout = self.media_rooms.breakoutOf(channel, p.id.slice());
            const pos = self.media_rooms.positionOf(channel, p.id.slice());
            const hand: []const u8 = if (self.media_rooms.handRaised(channel, p.id.slice())) "hand" else "-";
            var buf: [default_reply_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, ":{s} NOTE MEDIA {s} ROSTER {s} {s} {s} {d} {d} {s}\r\n", .{ server_name, channel, p.id.slice(), kinds_buf[0..n], breakout, pos.x, pos.y, hand }) catch continue;
            try appendToConn(conn, line);
        }
        var end_buf: [default_reply_bytes]u8 = undefined;
        const end = std.fmt.bufPrint(&end_buf, ":{s} NOTE MEDIA {s} :End of roster ({d})\r\n", .{ server_name, channel, self.media_rooms.roster(channel).len }) catch return;
        try appendToConn(conn, end);
    }

    /// `FILTER ADD|DEL|LIST [pattern]` — oper-only Koshi content-filter control.
    /// ADD/DEL manage case-insensitive substring patterns; LIST reports them.
    /// Matching messages from non-opers are blocked in the message path.
    pub fn handleFilter(self: *LinuxServer, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        const sub = if (parsed.param_count >= 1) parsed.paramSlice()[0] else "LIST";
        if (std.ascii.eqlIgnoreCase(sub, "LIST")) {
            var buf: [default_reply_bytes]u8 = undefined;
            for (self.content_filter.list(), 0..) |p, i| {
                const line = std.fmt.bufPrint(&buf, ":{s} NOTE FILTER LIST :#{d} {s}\r\n", .{ server_name, i + 1, p }) catch continue;
                try appendToConn(conn, line);
            }
            var end_buf: [default_reply_bytes]u8 = undefined;
            const end = std.fmt.bufPrint(&end_buf, ":{s} NOTE FILTER :End of filter list ({d})\r\n", .{ server_name, self.content_filter.list().len }) catch return;
            try appendToConn(conn, end);
            return;
        }
        if (parsed.param_count < 2 or parsed.paramSlice()[1].len == 0) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"FILTER"}, "Usage: FILTER <ADD|DEL|LIST> [pattern]");
            return;
        }
        const pattern = parsed.paramSlice()[1];
        if (std.ascii.eqlIgnoreCase(sub, "ADD")) {
            const ok = self.content_filter.add(pattern) catch {
                try self.failReply(conn, "FILTER", "TEMPORARILY_UNAVAILABLE", "Filter store error");
                return;
            };
            if (!ok) {
                try self.failReply(conn, "FILTER", "INVALID_PATTERN", "Pattern empty, too long, full, or duplicate");
                return;
            }
            try self.noticeTo(conn, "FILTER: pattern added");
        } else if (std.ascii.eqlIgnoreCase(sub, "DEL")) {
            const removed = self.content_filter.remove(pattern) catch false;
            if (!removed) {
                try self.failReply(conn, "FILTER", "NO_SUCH_PATTERN", "No such filter pattern");
                return;
            }
            try self.noticeTo(conn, "FILTER: pattern removed");
        } else {
            try self.failReply(conn, "FILTER", "INVALID_SUBCOMMAND", "Use ADD, DEL, or LIST");
        }
    }

    /// `PRIVS` — report the caller's operator class and privilege set
    /// (RPL_PRIVS 270). Re-derived from the oper registry by account, so it
    /// always reflects the current config binding.
    pub fn handlePrivs(self: *LinuxServer, conn: *ConnState) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        const registry = self.oper_registry orelse {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "No operator registry configured");
            return;
        };
        const account = conn.session.account() orelse return;
        const grant = registry.elevate(.{ .name = account }) catch {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "No operator privileges for your account");
            return;
        };
        var buf: [default_reply_bytes]u8 = undefined;
        var n: usize = 0;
        var it = grant.privileges.set.iterator();
        while (it.next()) |p| {
            const name = @tagName(p);
            if (n != 0 and n < buf.len) {
                buf[n] = ' ';
                n += 1;
            }
            if (n + name.len <= buf.len) {
                @memcpy(buf[n .. n + name.len], name);
                n += name.len;
            }
        }
        try queueNumeric(conn, .RPL_PRIVS, &.{ conn.session.displayName(), grant.class_name }, buf[0..n]);
    }

    /// `VHOST <newhost>` — oper-only visible-host override. Updates the caller's
    /// visible host and broadcasts a native CHGHOST to common-channel members who
    /// negotiated the chghost cap (others see the new host on the next message).
    pub fn handleVhost(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
            return self.vhostList(id, conn); // bare VHOST shows the wardrobe
        }
        const p = parsed.paramSlice();
        // Guise wardrobe (self-service): LIST/USE/OFF/CLAIM, plus REQUEST to ask.
        if (std.ascii.eqlIgnoreCase(p[0], "LIST")) {
            return self.vhostList(id, conn);
        } else if (std.ascii.eqlIgnoreCase(p[0], "USE")) {
            return self.handleVhostUse(id, conn, p);
        } else if (std.ascii.eqlIgnoreCase(p[0], "OFF")) {
            return self.handleVhostOff(id, conn);
        } else if (std.ascii.eqlIgnoreCase(p[0], "CLAIM")) {
            return self.handleVhostClaim(id, conn, p);
        } else if (std.ascii.eqlIgnoreCase(p[0], "REQUEST")) {
            return self.handleVhostRequest(conn, p);
        } else if (std.ascii.eqlIgnoreCase(p[0], "OFFERLIST")) {
            return self.handleVhostOfferList(conn);
        } else if (std.ascii.eqlIgnoreCase(p[0], "APPROVE") or std.ascii.eqlIgnoreCase(p[0], "DENY")) {
            return self.handleVhostReview(id, conn, p);
        } else if (std.ascii.eqlIgnoreCase(p[0], "OFFER")) {
            return self.handleVhostOffer(conn, p);
        } else if (std.ascii.eqlIgnoreCase(p[0], "SET")) {
            return self.handleVhostSet(conn, p);
        }
        // Bare `VHOST <host>` — oper immediate self-set (kept for convenience).
        if (!conn.session.isOper()) {
            try self.noticeTo(conn, "Usage: VHOST LIST|USE <name>|OFF|CLAIM <host>|REQUEST <host>|OFFERLIST");
            return;
        }
        const new_host = parsed.paramSlice()[0];
        const user = conn.session.username();
        chghost.validateHost(new_host) catch {
            try self.failReply(conn, "VHOST", "INVALID_HOST", "Invalid host");
            return;
        };

        // Build the CHGHOST line from the OLD prefix before mutating the host.
        var prefix_buf: [256]u8 = undefined;
        const old_prefix = clientPrefix(conn, &prefix_buf) catch return;
        // old_prefix is nick!user@oldhost; split it back into a chghost.Prefix.
        const bang = std.mem.indexOfScalar(u8, old_prefix, '!') orelse return;
        const at = std.mem.indexOfScalarPos(u8, old_prefix, bang + 1, '@') orelse return;
        const pfx = chghost.Prefix{
            .nick = old_prefix[0..bang],
            .user = old_prefix[bang + 1 .. at],
            .host = old_prefix[at + 1 ..],
        };
        var line_buf: [default_reply_bytes]u8 = undefined;
        const body = chghost.buildChghostLine(&line_buf, pfx, user, new_host) catch {
            try self.failReply(conn, "VHOST", "INVALID_HOST", "Invalid host");
            return;
        };
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "{s}\r\n", .{body}) catch return;

        // Apply the new visible host, then fan the CHGHOST out.
        conn.session.setVisibleHost(new_host);
        try self.notifyCommonChannels(id, msg, .chghost, id, conn.session.displayName());
        if (conn.session.hasCap(.chghost)) try appendToConn(conn, msg);
        var note_buf: [default_reply_bytes]u8 = undefined;
        const note = std.fmt.bufPrint(&note_buf, ":{s} NOTICE {s} :Your host is now {s}\r\n", .{ server_name, conn.session.displayName(), new_host }) catch return;
        try appendToConn(conn, note);
    }

    /// `VHOST REQUEST <host>` — a logged-in user asks for a vhost; queued for oper
    /// review. No effect until an oper APPROVEs.
    pub fn handleVhostRequest(self: *LinuxServer, conn: *ConnState, p: []const []const u8) !void {
        const account = conn.session.account() orelse {
            try self.failReply(conn, "VHOST", "ACCOUNT_REQUIRED", "Log in before requesting a vhost");
            return;
        };
        if (p.len < 2 or p[1].len == 0) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"VHOST"}, "Usage: VHOST REQUEST <host>");
            return;
        }
        const want = p[1];
        chghost.validateHost(want) catch {
            try self.failReply(conn, "VHOST", "INVALID_HOST", "Invalid host");
            return;
        };
        self.host_requests.submit(account, want, self.nowMs()) catch {
            try self.failReply(conn, "VHOST", "TEMPORARILY_UNAVAILABLE", "Could not queue request");
            return;
        };
        try self.noticeTo(conn, "VHOST request submitted; pending operator approval");
    }

    /// `VHOST LIST|APPROVE <account>|DENY <account> [:reason]` — oper review side.
    pub fn handleVhostReview(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, p: []const []const u8) !void {
        _ = id;
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        if (std.ascii.eqlIgnoreCase(p[0], "LIST")) {
            var buf: [128]host_request_mod.Request = undefined;
            const pending = self.host_requests.pendingList(&buf) catch &.{};
            for (pending) |r| {
                var b: [default_reply_bytes]u8 = undefined;
                const line = std.fmt.bufPrint(&b, ":{s} NOTICE {s} :VHOST pending {s} -> {s}\r\n", .{ server_name, conn.session.displayName(), r.account, r.vhost }) catch continue;
                try appendToConn(conn, line);
            }
            try self.noticeTo(conn, "VHOST: end of pending list");
            return;
        }
        if (p.len < 2 or p[1].len == 0) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"VHOST"}, "Usage: VHOST APPROVE|DENY <account> [:reason]");
            return;
        }
        const account = p[1];
        if (std.ascii.eqlIgnoreCase(p[0], "DENY")) {
            const reason = if (p.len >= 3) p[2] else "denied";
            self.host_requests.deny(account, reason, self.nowMs()) catch {
                try self.noticeTo(conn, "VHOST: no such pending request");
                return;
            };
            try self.noticeTo(conn, "VHOST request denied");
            return;
        }
        // APPROVE: record approval, then apply to any online sessions of the
        // account immediately (offline accounts pick it up on next login).
        const req = self.host_requests.get(account) orelse {
            try self.noticeTo(conn, "VHOST: no such pending request");
            return;
        };
        self.host_requests.approve(account, self.nowMs()) catch {
            try self.noticeTo(conn, "VHOST: could not approve");
            return;
        };
        var hbuf: [128]u8 = undefined;
        const host = std.fmt.bufPrint(&hbuf, "{s}", .{req.vhost}) catch return;
        // Record the approved host as a switchable "granted" persona.
        self.guises.grant(account, "granted", host, .granted, self.nowMs()) catch {};
        self.applyVhostToAccount(account, host);
        try self.noticeTo(conn, "VHOST approved and applied");
    }

    /// `VHOST LIST` (or bare VHOST) — show the caller's persona wardrobe and the
    /// operator-published offer templates they can CLAIM.
    fn vhostList(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState) !void {
        _ = id;
        if (conn.session.account()) |account| {
            for (self.guises.personas(account)) |p| {
                var b: [default_reply_bytes]u8 = undefined;
                const line = std.fmt.bufPrint(&b, ":{s} NOTICE {s} :VHOST persona {s} = {s} ({s})\r\n", .{ server_name, conn.session.displayName(), p.name, p.host, p.source.token() }) catch continue;
                try appendToConn(conn, line);
            }
        }
        for (self.guises.offerList()) |o| {
            var b: [default_reply_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&b, ":{s} NOTICE {s} :VHOST offer {s} :{s}\r\n", .{ server_name, conn.session.displayName(), o.template, o.label }) catch continue;
            try appendToConn(conn, line);
        }
        try self.noticeTo(conn, "VHOST: USE <name> to wear a persona, CLAIM <host> for an offer, REQUEST <host> to ask");
    }

    /// `VHOST USE <name>` — instantly wear one of your granted personas.
    pub fn handleVhostUse(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, p: []const []const u8) !void {
        const account = conn.session.account() orelse return self.failReply(conn, "VHOST", "ACCOUNT_REQUIRED", "Log in to use personas");
        if (p.len < 2 or p[1].len == 0) return self.noticeTo(conn, "Usage: VHOST USE <name>");
        const persona = self.guises.find(account, p[1]) orelse return self.noticeTo(conn, "VHOST: no such persona (try VHOST LIST)");
        try applyVhostLine(self, id, conn, persona.host);
    }

    /// `VHOST OFF` — drop the active vhost, restoring the connection's host.
    pub fn handleVhostOff(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState) !void {
        var hb: [128]u8 = undefined;
        const real = conn.session.realHost();
        const host = std.fmt.bufPrint(&hb, "{s}", .{real}) catch return;
        try applyVhostLine(self, id, conn, host);
    }

    /// `VHOST CLAIM <host>` — self-service a host matching an operator offer
    /// template; it becomes a `.claimed` persona and is worn immediately.
    pub fn handleVhostClaim(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, p: []const []const u8) !void {
        const account = conn.session.account() orelse return self.failReply(conn, "VHOST", "ACCOUNT_REQUIRED", "Log in to claim a vhost");
        if (p.len < 2 or p[1].len == 0) return self.noticeTo(conn, "Usage: VHOST CLAIM <host>");
        const host = p[1];
        chghost.validateHost(host) catch return self.failReply(conn, "VHOST", "INVALID_HOST", "Invalid host");
        _ = self.guises.claim(account, host, self.nowMs()) catch return self.noticeTo(conn, "VHOST: no operator offer matches that host");
        try applyVhostLine(self, id, conn, host);
    }

    /// `VHOST OFFERLIST` — show offer templates (any user).
    pub fn handleVhostOfferList(self: *LinuxServer, conn: *ConnState) !void {
        for (self.guises.offerList()) |o| {
            var b: [default_reply_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&b, ":{s} NOTICE {s} :VHOST offer {s} :{s}\r\n", .{ server_name, conn.session.displayName(), o.template, o.label }) catch continue;
            try appendToConn(conn, line);
        }
        try self.noticeTo(conn, "VHOST: end of offer list");
    }

    /// `VHOST OFFER <template> [:label]` — oper publishes a claimable template.
    pub fn handleVhostOffer(self: *LinuxServer, conn: *ConnState, p: []const []const u8) !void {
        if (!conn.session.isOper()) return queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
        if (p.len < 2 or p[1].len == 0) return self.noticeTo(conn, "Usage: VHOST OFFER <template> [:label]");
        const label = if (p.len >= 3) p[2] else "vhost offer";
        self.guises.addOffer(p[1], label) catch return self.noticeTo(conn, "VHOST: could not add offer (duplicate or limit)");
        var b: [default_reply_bytes]u8 = undefined;
        const note = std.fmt.bufPrint(&b, "VHOST OFFER {s}", .{p[1]}) catch return;
        try self.publishOperEvent(.oper_action, .notice, note);
    }

    /// `VHOST SET <account> <host> [name]` — oper assigns a fully custom vhost to
    /// an account as a `.granted` persona, applied live. The robust escape hatch
    /// for hosts no offer template covers.
    pub fn handleVhostSet(self: *LinuxServer, conn: *ConnState, p: []const []const u8) !void {
        if (!conn.session.isOper()) return queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
        if (p.len < 3 or p[1].len == 0 or p[2].len == 0) return self.noticeTo(conn, "Usage: VHOST SET <account> <host> [name]");
        const account = p[1];
        const host = p[2];
        const name = if (p.len >= 4) p[3] else "oper";
        chghost.validateHost(host) catch return self.failReply(conn, "VHOST", "INVALID_HOST", "Invalid host");
        self.guises.grant(account, name, host, .granted, self.nowMs()) catch return self.noticeTo(conn, "VHOST: could not set (limit or invalid)");
        self.applyVhostToAccount(account, host);
        var b: [default_reply_bytes]u8 = undefined;
        const note = std.fmt.bufPrint(&b, "VHOST SET {s} -> {s}", .{ account, host }) catch return;
        try self.publishOperEvent(.oper_action, .notice, note);
        try self.noticeTo(conn, "VHOST set and applied");
    }

    /// On login, apply (and consume) an approved vhost request for the account.
    fn maybeApplyApprovedVhost(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState) void {
        const account = conn.session.account() orelse return;
        const req = self.host_requests.get(account) orelse return;
        if (req.status != .approved) return;
        var hbuf: [128]u8 = undefined;
        const host = std.fmt.bufPrint(&hbuf, "{s}", .{req.vhost}) catch return;
        applyVhostLine(self, id, conn, host) catch {};
        _ = self.host_requests.take(account);
    }

    /// Apply `new_host` to every online session of `account` (CHGHOST fan-out).
    fn applyVhostToAccount(self: *LinuxServer, account: []const u8, new_host: []const u8) void {
        var it = self.rx().clients.iterator();
        while (it.next()) |entry| {
            const c = entry.value;
            const acct = c.session.account() orelse continue;
            if (!std.ascii.eqlIgnoreCase(acct, account)) continue;
            applyVhostLine(self, entry.id, c, new_host) catch {};
        }
    }

    /// Set a client's visible host and fan a CHGHOST out to common channels.
    fn applyVhostLine(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, new_host: []const u8) !void {
        var prefix_buf: [256]u8 = undefined;
        const old_prefix = clientPrefix(conn, &prefix_buf) catch return;
        const bang = std.mem.indexOfScalar(u8, old_prefix, '!') orelse return;
        const at = std.mem.indexOfScalarPos(u8, old_prefix, bang + 1, '@') orelse return;
        const pfx = chghost.Prefix{ .nick = old_prefix[0..bang], .user = old_prefix[bang + 1 .. at], .host = old_prefix[at + 1 ..] };
        var line_buf: [default_reply_bytes]u8 = undefined;
        const body = chghost.buildChghostLine(&line_buf, pfx, conn.session.username(), new_host) catch return;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "{s}\r\n", .{body}) catch return;
        conn.session.setVisibleHost(new_host);
        try self.notifyCommonChannels(id, msg, .chghost, id, conn.session.displayName());
        if (conn.session.hasCap(.chghost)) try appendToConn(conn, msg);
        var nb: [default_reply_bytes]u8 = undefined;
        const note = std.fmt.bufPrint(&nb, ":{s} NOTICE {s} :Your host is now {s}\r\n", .{ server_name, conn.session.displayName(), new_host }) catch return;
        try appendToConn(conn, note);
    }

    /// Emit an IRCv3 `FAIL <command> <code> :<reason>` standard reply.
    fn failReply(self: *LinuxServer, conn: *ConnState, command: []const u8, code: []const u8, reason: []const u8) !void {
        _ = self;
        var buf: [default_reply_bytes]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "FAIL {s} {s} :{s}\r\n", .{ command, code, reason }) catch return;
        try appendToConn(conn, line);
    }

    /// Render a typed Event Spine event as `NOTE EVENT <CATEGORY>` and deliver it
    /// to every session subscribed to that category (oper notices: wallops,
    /// kills, connects, …). Replaces the legacy snote/wallops broadcast channels.
    fn publishOperEvent(self: *LinuxServer, category: event_spine.EventCategory, severity: event_spine.EventSeverity, message: []const u8) !void {
        const event = event_spine.Event{
            .category = category,
            .severity = severity,
            .timestamp_ms = platform.realtimeMillis(),
            .message = message,
        };
        var line_buf: [default_reply_bytes]u8 = undefined;
        const line = event_spine.renderOperNote(.{ .server_name = server_name, .event = event }, &line_buf) catch return;
        var it = self.rx().clients.iterator();
        while (it.next()) |entry| {
            if (entry.value.session.subscribesTo(category)) try self.deliver(entry.id, line);
        }
    }

    /// REHASH — oper-only configuration reload. Re-reads and re-parses the
    /// configured file and swaps in a freshly-built oper registry (account→class
    /// bindings). Existing sessions keep their current oper state; new SASL logins
    /// observe the reloaded bindings. Without a config path it acknowledges only.
    pub fn handleRehash(self: *LinuxServer, conn: *ConnState) !void {
        if (!conn.session.isOper()) {
            try queueNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission Denied- You're not an IRC operator");
            return;
        }
        const path = self.config.config_path orelse {
            try queueNumeric(conn, .RPL_REHASHING, &.{"mizuchi.conf"}, "No config file; nothing to reload");
            return;
        };
        const io = self.config.crypto_io orelse {
            try queueNumeric(conn, .RPL_REHASHING, &.{path}, "No I/O available; cannot reload");
            return;
        };
        const text = std.Io.Dir.cwd().readFileAlloc(io, path, self.allocator, .limited(1 << 20)) catch {
            try self.noticeTo(conn, "REHASH: cannot read config file");
            return;
        };
        defer self.allocator.free(text);

        var parsed = config_format.parseToml(self.allocator, text, self.config.config_resolver) catch {
            try self.noticeTo(conn, "REHASH: config parse error; keeping current config");
            return;
        };
        // Build the new oper bindings (strings borrow `parsed`, kept alive below).
        const bindings = self.allocator.alloc(oper_mod.OperBinding, parsed.opers.len) catch {
            parsed.deinit(self.allocator);
            try self.noticeTo(conn, "REHASH: out of memory; keeping current config");
            return;
        };
        for (parsed.opers, 0..) |o, i| {
            bindings[i] = .{
                .account_name = o.account,
                .class_name = if (o.class.len != 0) o.class else "operator",
                .privileges = oper_mod.OperPrivileges.full,
            };
        }
        const new_registry: ?oper_mod.OperRegistry = if (bindings.len != 0)
            (oper_mod.OperRegistry.init(bindings) catch {
                self.allocator.free(bindings);
                parsed.deinit(self.allocator);
                try self.noticeTo(conn, "REHASH: invalid oper bindings; keeping current config");
                return;
            })
        else
            null;

        // Commit: replace the previous reloaded generation, then point the live
        // registry at the new bindings.
        self.allocator.free(self.reload_bindings);
        if (self.reload_parsed) |*p| p.deinit(self.allocator);
        self.reload_parsed = parsed;
        self.reload_bindings = bindings;
        self.oper_registry = new_registry;

        var note_buf: [default_reply_bytes]u8 = undefined;
        const note = std.fmt.bufPrint(&note_buf, "Configuration reloaded ({d} oper bindings)", .{bindings.len}) catch "Configuration reloaded";
        try queueNumeric(conn, .RPL_REHASHING, &.{path}, note);
    }

    /// INFO — RPL_INFO (371) lines bracketed by RPL_INFOSTART/RPL_ENDOFINFO.
    pub fn handleInfo(self: *LinuxServer, conn: *ConnState) !void {
        _ = self;
        const lines = [_][]const u8{
            "Mizuchi IRC daemon — a clean-room Zig-native mesh IRC server.",
            "100% Zig, no C interop. Substrate + crypto + daemon.",
            "Mesh protocol: Suimyaku (CRDT) + Sazanami (gossip) + Goryu (membership).",
        };
        try queueNumeric(conn, .RPL_INFOSTART, &.{}, server_name);
        for (lines) |l| try queueNumeric(conn, .RPL_INFO, &.{}, l);
        try queueNumeric(conn, .RPL_ENDOFINFO, &.{}, "End of /INFO list");
    }

    /// USERS — local user listing (RPL_USERSSTART/RPL_USERS/RPL_ENDOFUSERS).
    pub fn handleUsers(self: *LinuxServer, conn: *ConnState) !void {
        try queueNumeric(conn, .RPL_USERSSTART, &.{}, "UserID   Terminal  Host");
        var any = false;
        var it = self.rx().clients.iterator();
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
    pub fn handleLinks(self: *LinuxServer, conn: *ConnState) !void {
        var line_buf: [128]u8 = undefined;
        const detail = std.fmt.bufPrint(&line_buf, "0 {s}", .{"Mizuchi IRC daemon"}) catch return;
        try queueNumeric(conn, .RPL_LINKS, &.{ server_name, server_name }, detail);
        // Reflect each established S2S peer as a 1-hop neighbour.
        var it = self.rx().clients.iterator();
        while (it.next()) |entry| {
            const link = entry.value.s2s orelse continue;
            if (!link.established()) continue;
            const rname = link.remoteName();
            if (rname.len == 0) continue;
            var lbuf: [128]u8 = undefined;
            const ldetail = std.fmt.bufPrint(&lbuf, "1 {s}", .{"Suimyaku peer"}) catch continue;
            try queueNumeric(conn, .RPL_LINKS, &.{ rname, server_name }, ldetail);
        }
        try queueNumeric(conn, .RPL_ENDOFLINKS, &.{"*"}, "End of /LINKS list");
    }

    /// MAP — network topology. Single node today (RPL_MAP 015 / RPL_MAPEND 017).
    pub fn handleMap(self: *LinuxServer, conn: *ConnState) !void {
        var line_buf: [160]u8 = undefined;
        const detail = std.fmt.bufPrint(&line_buf, "{s} [Users: {d}]", .{
            server_name,
            self.rx().clients.len(),
        }) catch return;
        try queueNumeric(conn, .RPL_MAP, &.{}, detail);
        // Established S2S peers as child nodes of this server.
        var it = self.rx().clients.iterator();
        while (it.next()) |entry| {
            const link = entry.value.s2s orelse continue;
            if (!link.established() or link.remoteName().len == 0) continue;
            var pbuf: [160]u8 = undefined;
            const pdetail = std.fmt.bufPrint(&pbuf, "  `- {s}", .{link.remoteName()}) catch continue;
            try queueNumeric(conn, .RPL_MAP, &.{}, pdetail);
        }
        try queueNumeric(conn, .RPL_MAPEND, &.{}, "End of /MAP");
    }

    /// Fan a pre-built message out to every member of every channel `id` shares,
    /// optionally gated on a negotiated capability, skipping `except`. Each
    /// recipient is delivered at most once even across multiple shared channels.
    /// Fan an IRCv3 `ACCOUNT` line out to common-channel members that negotiated
    /// account-notify, after this client logs in (`label` = account name) or out
    /// (`label` = "*"). Best-effort; no-op if the client shares no channels.
    fn emitAccountChange(self: *LinuxServer, id: client_model.ClientId, conn: *const ConnState, label: []const u8) void {
        // Compose via the shared account_notify builder (single source of truth
        // for the ACCOUNT line format + validation); "*" is the logout sentinel.
        const change: account_notify.AccountChange = if (std.mem.eql(u8, label, account_notify.LOGOUT_SENTINEL))
            .logout
        else
            .{ .login = label };
        const prefix = account_notify.Prefix{
            .nick = conn.session.displayName(),
            .user = conn.session.username(),
            .host = conn.session.host(),
        };
        var body_buf: [default_reply_bytes]u8 = undefined;
        const body = account_notify.buildAccountNotifyLine(&body_buf, prefix, change) catch return;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "{s}\r\n", .{body}) catch return;
        self.notifyCommonChannels(id, msg, .account_notify, id, conn.session.displayName()) catch {};
    }

    fn notifyCommonChannels(
        self: *LinuxServer,
        id: client_model.ClientId,
        msg: []const u8,
        cap: ?dispatch.CapId,
        except: client_model.ClientId,
        monitor_nick: ?[]const u8,
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
                const mconn = self.connFor(mid) orelse continue;
                if (cap) |c| {
                    if (!mconn.session.hasCap(c)) continue;
                }
                try self.deliver(mid, msg);
            }
        }
        // extended-monitor: also deliver to clients MONITORing this nick who do
        // NOT already share a channel (those are in `seen`) and negotiated the
        // cap. Keeps the no-duplicate guarantee against the channel fan-out.
        if (monitor_nick) |nick| {
            var watchers: [128]monitor.ClientId = undefined;
            const n = self.monitor.watchersOf(nick, &watchers);
            for (watchers[0..n]) |w| {
                const wid = clientIdFromMonitor(w);
                if (wid.eql(except)) continue;
                if (seen.contains(@as(u64, @bitCast(wid)))) continue;
                const wconn = self.connFor(wid) orelse continue;
                if (!wconn.session.hasCap(.extended_monitor)) continue;
                try self.deliver(wid, msg);
            }
        }
    }

    /// TAGMSG <target> — IRCv3 message-tags: relay the sender's client tags (no
    /// text body) to recipients that negotiated message-tags. A TAGMSG carrying
    /// no tags is a no-op. Delivered untagged-by-server (the client `@tags`
    /// segment is the whole tag set) — server-time-in-tags is a future merge.
    pub fn handleTagmsg(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) return;
        const tags = parsed.tags_raw orelse return; // nothing to relay
        const target = parsed.paramSlice()[0];

        // Stamp a server-minted msgid into the relayed tag segment (so a relayed
        // TAGMSG, like PRIVMSG/NOTICE, carries `@msgid=…` for message-redaction).
        var msgid_buf: [msgid_mod.id_len]u8 = undefined;
        const message_id = self.msgid_gen.next(&msgid_buf);

        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "@msgid={s};{s} :{s} TAGMSG {s}\r\n", .{
            message_id, tags, try clientPrefix(conn, &prefix_buf), target,
        }) catch return error.OutputTooSmall;
        const echo = conn.session.hasCap(.echo_message);

        if (world_model.isChannelName(target)) {
            if (!self.world.channelExists(target)) return;
            if (!self.world.isMember(target, worldIdFromClient(id))) return;
            var members = self.world.memberIterator(target) orelse return;
            while (members.next()) |member| {
                const mid = clientIdFromWorld(member.*);
                if (mid.eql(id) and !echo) continue;
                const mconn = self.connFor(mid) orelse continue;
                if (!mconn.session.hasCap(.message_tags)) continue;
                try self.deliver(mid, msg);
            }
            // #33: typing and reaction tags also feed the ACTIVITY stream.
            if (findTagValue(tags, "+typing")) |tv| self.pushTypingActivity(id, conn, target, tv) catch {};
            if (findTagValue(tags, "+draft/react")) |rv| {
                self.pushReactionActivity(id, conn, target, rv, findTagValue(tags, "+draft/reply")) catch {};
            }
            return;
        }
        const recipient = self.world.findNick(target) orelse return;
        const rconn = self.connFor(clientIdFromWorld(recipient)) orelse return;
        if (rconn.session.hasCap(.message_tags)) try self.deliver(clientIdFromWorld(recipient), msg);
        if (echo) try self.deliver(id, msg);
    }

    /// ACTIVITY SUBSCRIBE|UNSUBSCRIBE <#channel> — opt in/out of a channel's
    /// real-time activity stream (#33). A subscriber must be a channel member.
    pub fn handleActivity(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
        if (parsed.param_count < 2) {
            try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"ACTIVITY"}, "Not enough parameters");
            return;
        }
        const sub = parsed.paramSlice()[0];
        const channel = parsed.paramSlice()[1];
        if (!world_model.isChannelName(channel)) {
            try queueNumeric(conn, .ERR_NOSUCHCHANNEL, &.{channel}, "No such channel");
            return;
        }
        const cid = monitorIdFromClient(id);
        if (std.ascii.eqlIgnoreCase(sub, "SUBSCRIBE")) {
            if (!self.world.isMember(channel, worldIdFromClient(id))) {
                try queueNumeric(conn, .ERR_NOTONCHANNEL, &.{channel}, "You're not on that channel");
                return;
            }
            _ = self.activity_subs.subscribe(channel, cid) catch {
                try self.noticeTo(conn, "ACTIVITY: subscription limit reached");
                return;
            };
            var buf: [default_reply_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, "Subscribed to activity on {s}", .{channel}) catch return;
            try self.noticeTo(conn, line);
        } else if (std.ascii.eqlIgnoreCase(sub, "UNSUBSCRIBE")) {
            _ = self.activity_subs.unsubscribe(channel, cid);
            var buf: [default_reply_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, "Unsubscribed from activity on {s}", .{channel}) catch return;
            try self.noticeTo(conn, line);
        } else {
            try self.noticeTo(conn, "ACTIVITY: expected SUBSCRIBE or UNSUBSCRIBE");
        }
    }

    /// Push a typing ActivityEvent to a channel's activity-stream subscribers
    /// (server-relayed as `:<typer> ACTIVITY <#chan> typing <state>`), skipping
    /// the typer. Best-effort; an unknown typing value is dropped.
    fn pushTypingActivity(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, channel: []const u8, state_value: []const u8) !void {
        const subs = self.activity_subs.subscribers(channel);
        if (subs.len == 0) return;
        const state = activity.TypingState.parse(state_value) catch return;
        var prefix_buf: [256]u8 = undefined;
        var line_buf: [default_reply_bytes]u8 = undefined;
        const line = try formatMessage(&line_buf, try clientPrefix(conn, &prefix_buf), "ACTIVITY", &.{ channel, "typing", state.token() }, null);
        for (subs) |sid| {
            const cid = clientIdFromMonitor(sid);
            if (cid.eql(id)) continue;
            self.deliver(cid, line) catch continue;
        }
    }

    /// Push a reaction ActivityEvent (`:reactor ACTIVITY <#chan> react <msgid>
    /// <reaction>`) to subscribers. Requires a `+draft/reply` target msgid; an
    /// empty/oversized reaction is dropped.
    fn pushReactionActivity(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, channel: []const u8, react_value: []const u8, reply_target: ?[]const u8) !void {
        const subs = self.activity_subs.subscribers(channel);
        if (subs.len == 0) return;
        const r = activity.Reaction.fromTags(react_value, reply_target) catch return;
        var prefix_buf: [256]u8 = undefined;
        var line_buf: [default_reply_bytes]u8 = undefined;
        const line = try formatMessage(&line_buf, try clientPrefix(conn, &prefix_buf), "ACTIVITY", &.{ channel, "react", r.target_msgid, r.reaction }, null);
        for (subs) |sid| {
            const cid = clientIdFromMonitor(sid);
            if (cid.eql(id)) continue;
            self.deliver(cid, line) catch continue;
        }
    }

    /// Push a presence ActivityEvent to the activity-stream subscribers of every
    /// channel the client is in (`:client ACTIVITY <#chan> presence <state>`),
    /// on AWAY set/clear. Best-effort; skips the client itself.
    fn pushPresenceActivity(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, availability: activity.Availability) void {
        var prefix_buf: [256]u8 = undefined;
        const prefix = clientPrefix(conn, &prefix_buf) catch return;
        var line_buf: [default_reply_bytes]u8 = undefined;
        var it = self.world.channels.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.members.contains(worldIdFromClient(id))) continue;
            const chan = entry.key_ptr.*;
            const subs = self.activity_subs.subscribers(chan);
            if (subs.len == 0) continue;
            const line = formatMessage(&line_buf, prefix, "ACTIVITY", &.{ chan, "presence", availability.token() }, null) catch continue;
            for (subs) |sid| {
                const cid = clientIdFromMonitor(sid);
                if (cid.eql(id)) continue;
                self.deliver(cid, line) catch continue;
            }
        }
    }

    pub fn handleMessage(
        self: *LinuxServer,
        id: client_model.ClientId,
        conn: *ConnState,
        parsed: *const irc_line.LineView,
        command: []const u8,
    ) !void {
        // +z GAG (IRCX): the server silently discards a gagged user's messages.
        if (conn.gagged) return;
        // SHUN: a network-shunned (non-oper) sender's messages are silently
        // dropped before delivery.
        if (self.shuns.count() > 0 and !conn.session.isOper()) {
            var hm_buf: [320]u8 = undefined;
            if (clientPrefix(conn, &hm_buf)) |hm| {
                if (self.shuns.isShunned(hm, self.nowMs())) return;
            } else |_| {}
        }
        // NOTICE must never generate an automatic error reply (RFC 1459):
        // missing recipient/text is silently dropped to prevent bot reply loops.
        const is_notice = std.ascii.eqlIgnoreCase(command, "NOTICE");
        if (parsed.param_count < 2 or parsed.paramSlice()[1].len == 0) {
            if (!is_notice) {
                try queueNumeric(conn, .ERR_NEEDMOREPARAMS, &.{command}, "Not enough parameters");
            }
            return;
        }
        const text = parsed.paramSlice()[1];
        if (!try self.messageContentGates(id, conn, command, parsed.paramSlice()[0], text, is_notice)) return;

        // `PRIVMSG a,#b,c :text`: deliver to each comma-separated target.
        var targets = std.mem.splitScalar(u8, parsed.paramSlice()[0], ',');
        while (targets.next()) |target| {
            if (target.len == 0) continue;
            try self.messageOne(id, conn, command, target, text, parsed.tags_raw);
        }
    }

    /// Body-dependent veto gates shared by PRIVMSG/NOTICE and reassembled
    /// draft/multiline: the message_pre_deliver hook, utf8only, and the Koshi
    /// content filter. Returns true if delivery may proceed; on a drop it emits
    /// the appropriate FAIL (PRIVMSG) or stays silent (NOTICE) and returns
    /// false. Callers apply gag/shun and parameter checks beforehand.
    fn messageContentGates(
        self: *LinuxServer,
        id: client_model.ClientId,
        conn: *ConnState,
        command: []const u8,
        target: []const u8,
        text: []const u8,
        is_notice: bool,
    ) !bool {
        // message_pre_deliver typed hook (veto-capable): a subscribed module/plugin
        // may drop the message by clearing `approved`. No subscriber today =>
        // approved stays true => identical behavior. Errors never break delivery.
        {
            var mpd = mod_registry.MessagePreDeliverPayload{
                .source_id = @as(u64, @bitCast(id)),
                .target = target,
                .text = text,
            };
            const verdict = module_manifest.Live.callHook(.message_pre_deliver, self, &mpd) catch mod_registry.HookResult.continue_;
            _ = verdict;
            if (!mpd.approved) return false;
        }
        // utf8only: reject malformed UTF-8 bodies with a standard-replies FAIL and
        // drop the message (ISUPPORT advertises UTF8ONLY). NOTICE stays silent.
        if (!utf8_guard.isValidMessageBody(text)) {
            if (!is_notice) {
                var fail_buf: [128]u8 = undefined;
                if (utf8_guard.buildInvalidUtf8Fail(&fail_buf, command)) |line| {
                    var crlf: [160]u8 = undefined;
                    const out = std.fmt.bufPrint(&crlf, "{s}\r\n", .{line}) catch return false;
                    try appendToConn(conn, out);
                } else |_| {}
            }
            return false;
        }
        // Koshi content filter: block messages matching an oper-curated pattern.
        // Opers are exempt; NOTICE drops silently (no auto-reply), PRIVMSG FAILs.
        // Match both the raw text AND a formatting-stripped copy so a filtered
        // word can't be smuggled past Koshi via embedded mIRC color/format codes.
        if (!conn.session.isOper()) {
            var filtered = self.content_filter.matches(text);
            if (!filtered and color_strip.hasFormatting(text)) {
                var strip_buf: [1024]u8 = undefined;
                if (color_strip.stripFormatting(text, &strip_buf)) |clean| {
                    filtered = self.content_filter.matches(clean);
                } else |_| {}
            }
            if (filtered) {
                if (!is_notice) try self.failReply(conn, command, "MIZUCHI_FILTERED", "Message blocked by the content filter");
                return false;
            }
        }
        return true;
    }

    /// Route one line from a draft/multiline-capable client into the per-conn
    /// reassembler. Returns true when the line was consumed (a multiline BATCH
    /// open/close or a tagged chunk); false to let normal dispatch handle it.
    fn routeMultiline(
        self: *LinuxServer,
        id: client_model.ClientId,
        conn: *ConnState,
        parsed: *const irc_line.LineView,
        line: []const u8,
    ) !bool {
        const is_batch = std.ascii.eqlIgnoreCase(parsed.command, "BATCH");

        if (conn.multiline) |ms| {
            // A batch is open: a BATCH line is its close, anything tagged with
            // our reference is a chunk. Any assembler error aborts + FAILs.
            if (is_batch) {
                const msg = ms.assembler.finish(line, &ms.out) catch {
                    self.abortMultiline(conn);
                    try self.failReply(conn, "BATCH", "MULTILINE_INVALID", "Invalid multiline batch");
                    return true;
                };
                try self.deliverMultiline(id, conn, msg.command, msg.target, msg.value);
                self.abortMultiline(conn); // batch closed; release the buffer
                return true;
            }
            if (batchTagValue(parsed)) |ref| {
                if (std.mem.eql(u8, ref, ms.assembler.reference())) {
                    ms.assembler.append(line, &ms.out) catch {
                        self.abortMultiline(conn);
                        try self.failReply(conn, "BATCH", "MULTILINE_INVALID", "Invalid multiline batch");
                        return true;
                    };
                    return true;
                }
            }
            return false; // unrelated line; leave the open batch untouched
        }

        // No open batch: only consume a `BATCH +ref draft/multiline target` open.
        if (is_batch and isMultilineOpen(parsed)) {
            const ms = self.allocator.create(MultilineState) catch return false;
            ms.* = .{};
            ms.assembler.begin(line) catch {
                self.allocator.destroy(ms);
                try self.failReply(conn, "BATCH", "MULTILINE_INVALID", "Invalid multiline batch");
                return true;
            };
            conn.multiline = ms;
            return true;
        }
        return false;
    }

    /// Deliver a reassembled multiline message: split the joined value on the
    /// inter-chunk newline and emit each segment as an individual PRIVMSG/NOTICE
    /// (server-side splitting is spec-permitted for any recipient).
    fn deliverMultiline(
        self: *LinuxServer,
        id: client_model.ClientId,
        conn: *ConnState,
        command: multiline.PayloadCommand,
        target: []const u8,
        value: []const u8,
    ) !void {
        if (conn.gagged) return;
        if (self.shuns.count() > 0 and !conn.session.isOper()) {
            var hm_buf: [320]u8 = undefined;
            if (clientPrefix(conn, &hm_buf)) |hm| {
                if (self.shuns.isShunned(hm, self.nowMs())) return;
            } else |_| {}
        }
        const cmd = command.token();
        const is_notice = command == .notice;
        if (!try self.messageContentGates(id, conn, cmd, target, value, is_notice)) return;

        var it = std.mem.splitScalar(u8, value, '\n');
        while (it.next()) |segment| {
            try self.messageOne(id, conn, cmd, target, segment, null);
        }
    }

    /// Free and clear a connection's open multiline batch state, if any.
    fn abortMultiline(self: *LinuxServer, conn: *ConnState) void {
        if (conn.multiline) |ms| {
            self.allocator.destroy(ms);
            conn.multiline = null;
        }
    }

    fn messageOne(
        self: *LinuxServer,
        id: client_model.ClientId,
        conn: *ConnState,
        command: []const u8,
        target: []const u8,
        text: []const u8,
        client_tags: ?[]const u8,
    ) !void {
        var prefix_buf: [256]u8 = undefined;
        var msg_buf: [default_reply_bytes]u8 = undefined;
        const msg = try formatMessage(&msg_buf, try clientPrefix(conn, &prefix_buf), command, &.{target}, text);

        // Mint one IRCv3 msgid for this message; all recipients (and the echoing
        // sender) share it so message-redaction can reference a single id.
        var msgid_buf: [msgid_mod.id_len]u8 = undefined;
        const message_id = self.msgid_gen.next(&msgid_buf);

        // IRCv3 echo-message: a sender that negotiated the cap also receives its
        // own message back, byte-identical to what recipients see (`msg`).
        const echo = conn.session.hasCap(.echo_message);

        // RFC 1459: NOTICE must NEVER generate an error
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
            // +O opmoderate: instead of dropping a message blocked by +m/+M/+Z,
            // deliver it to channel ops only (so they can see & act). When set,
            // the moderation gates below route rather than reject.
            const opmod = self.world.channelHasExtFlag(chan, .opmoderate);
            var opmod_route = false;
            // +m moderated: only voiced (+v) or any operator tier may speak.
            if (self.world.channelHasFlag(chan, .moderated)) {
                const mm = self.world.memberModes(chan, worldIdFromClient(id)) orelse world_model.MemberModes.empty();
                if (!mm.canSpeakModerated()) {
                    if (opmod) {
                        opmod_route = true;
                    } else {
                        if (!is_notice) try queueNumeric(conn, .ERR_CANNOTSENDTOCHAN, &.{target}, "Cannot send to channel (+m)");
                        return;
                    }
                }
            }
            // +M moderate-unregistered: an unauthenticated member may speak only
            // if voiced-or-higher (like +m, scoped to non-account users).
            if (self.world.channelHasFlag(chan, .mod_reg) and conn.session.account() == null) {
                const mm = self.world.memberModes(chan, worldIdFromClient(id)) orelse world_model.MemberModes.empty();
                if (!mm.canSpeakModerated()) {
                    if (opmod) {
                        opmod_route = true;
                    } else {
                        if (!is_notice) try queueNumeric(conn, .ERR_CANNOTSENDTOCHAN, &.{target}, "Cannot send to channel (+M: identify to a registered account to speak)");
                        return;
                    }
                }
            }
            // +Z quiet (MUTE): a member whose mask matches a quiet entry (and is
            // not +e exempt) may not speak unless voiced-or-higher / oper.
            {
                const qm = self.world.memberModes(chan, worldIdFromClient(id)) orelse world_model.MemberModes.empty();
                if (!qm.canSpeakModerated() and !conn.session.isOper()) {
                    var qmask_buf: [256]u8 = undefined;
                    const qmask = clientPrefix(conn, &qmask_buf) catch "";
                    var qchan_buf: [64][]const u8 = undefined;
                    const quiet_ctx = banContextFor(self, conn, worldIdFromClient(id), qmask, &qchan_buf);
                    if (qmask.len != 0 and self.world.isMutedCtx(chan, quiet_ctx)) {
                        if (opmod) {
                            opmod_route = true;
                        } else {
                            if (!is_notice) try queueNumeric(conn, .ERR_CANNOTSENDTOCHAN, &.{target}, "Cannot send to channel (+Z: you are quieted)");
                            return;
                        }
                    }
                }
            }
            // Op-bypass gates (+C no-ctcp, +T no-notice). Ops/voiced-or-higher and
            // server opers are exempt; ACTION is never treated as blockable CTCP.
            const sender_op = (self.world.memberModes(chan, worldIdFromClient(id)) orelse world_model.MemberModes.empty()).isOperator() or conn.session.isOper();
            if (!sender_op and self.world.channelHasFlag(chan, .no_ctcp) and isBlockableCtcp(text)) {
                if (!is_notice) try queueNumeric(conn, .ERR_CANNOTSENDTOCHAN, &.{target}, "Cannot send to channel (+C: no CTCP)");
                return;
            }
            if (is_notice and !sender_op and self.world.channelHasFlag(chan, .no_notice)) {
                return; // +T: drop channel NOTICE from non-ops (NOTICE never auto-replies)
            }
            // STATUSMSG sender gate (chanop-or-voiced): only a
            // member who is voiced-or-higher may send to a status-prefixed target.
            if (min_rank > 0) {
                const sm = self.world.memberModes(chan, worldIdFromClient(id)) orelse world_model.MemberModes.empty();
                if (sm.rank() < 1) {
                    if (!is_notice) try queueNumeric(conn, .ERR_CHANOPRIVSNEEDED, &.{target}, "You're not channel operator");
                    return;
                }
            }
            var time_buf: [40]u8 = undefined;
            const ctags = MsgTags{ .time_value = serverTimeValue(&time_buf), .account = conn.session.account(), .client_tags = client_tags, .msgid = message_id };
            if (opmod_route) {
                // +O opmoderate: the sender was muted (+m/+M/+Z) but the channel
                // routes blocked messages to ops instead of dropping them. Deliver
                // to ops-and-above only (rank >= 2); no sender error, no echo, no
                // history, no cross-node relay — ops locally see what was attempted.
                try self.broadcastChannelMinRank(chan, ctags, msg, id, 2);
                return;
            }
            if (min_rank == 0) {
                try self.broadcastChannelTagged(chan, ctags, msg, id);
            } else {
                try self.broadcastChannelMinRank(chan, ctags, msg, id, min_rank);
            }
            if (echo) try self.deliverTagged(id, ctags, msg);
            // Cross-node relay: forward this channel message to mesh peers so
            // remote members of `chan` receive it. Loop-guarded; the far side
            // delivers only to its own local members. Best-effort.
            {
                var pbuf: [320]u8 = undefined;
                if (clientPrefix(conn, &pbuf)) |prefix| {
                    const hlc: u64 = @intCast(@max(@as(i64, 0), self.nowMs()));
                    _ = self.relay_seen.observe(self.config.node_id, hlc); // drop an echo back
                    _ = self.relayToPeers(.{
                        .verb = if (is_notice) .notice else .privmsg,
                        .target = chan,
                        .source_nick = conn.session.displayName(),
                        .source_prefix = prefix,
                        .account = conn.session.account() orelse "",
                        .tags = client_tags orelse "",
                        .text = text,
                        .origin_node = self.config.node_id,
                        .hlc = hlc,
                    }, .{ .channel = chan }); // route_table: only peers with members
                } else |_| {}
            }
            // Record into the CHATHISTORY ring (full status-prefix stripped: bare
            // chan). Only the message body + sender prefix are stored.
            if (min_rank == 0) self.recordHistory(chan, conn, text);
            return;
        }

        const recipient = self.world.findNick(target) orelse {
            // Not local: relay to mesh peers so the node that owns this nick can
            // deliver (loop-guarded; a truly-nonexistent nick is dropped far-side).
            if (self.hasEstablishedPeer()) {
                var pbuf2: [320]u8 = undefined;
                if (clientPrefix(conn, &pbuf2)) |prefix| {
                    const hlc: u64 = @intCast(@max(@as(i64, 0), self.nowMs()));
                    _ = self.relay_seen.observe(self.config.node_id, hlc);
                    const relay_msg = s2s_link.RelayMessage{
                        .verb = if (is_notice) .notice else .privmsg,
                        .target = target,
                        .source_nick = conn.session.displayName(),
                        .source_prefix = prefix,
                        .account = conn.session.account() orelse "",
                        .tags = client_tags orelse "",
                        .text = text,
                        .origin_node = self.config.node_id,
                        .hlc = hlc,
                    };
                    // route_table: send only to the peer that owns this nick; if the
                    // route isn't known yet, fall back to flooding all peers.
                    if (self.relayToPeers(relay_msg, .{ .nick = target }) == 0) {
                        _ = self.relayToPeers(relay_msg, .all);
                    }
                    if (echo) {
                        var et_buf: [40]u8 = undefined;
                        const etags = MsgTags{ .time_value = serverTimeValue(&et_buf), .account = conn.session.account(), .client_tags = client_tags };
                        self.deliverTagged(id, etags, msg) catch {};
                    }
                    return;
                } else |_| {}
            }
            if (!is_notice) try queueNumeric(conn, .ERR_NOSUCHNICK, &.{target}, "No such nick");
            return;
        };
        // +R regonly-pm: the recipient rejects PMs/notices from unauthenticated
        // senders. Logged-in senders and opers always pass.
        if (conn.session.account() == null and !conn.session.isOper()) {
            if (self.connFor(clientIdFromWorld(recipient))) |rconn| {
                if (rconn.session.umodes.contains(.regonly_pm)) {
                    if (!is_notice) try queueNumeric(conn, .ERR_NEEDREGGEDNICK, &.{target}, "Cannot message this user (+R: identify to a registered account)");
                    return;
                }
            }
        }
        // SILENCE: if the recipient has silenced a mask matching the sender, drop
        // the message silently (no error to the sender — ircu/charybdis behavior).
        {
            var smask_buf: [256]u8 = undefined;
            const sender_mask = try clientPrefix(conn, &smask_buf);
            if (self.silence.isSilenced(target, sender_mask)) return;
        }
        var time_buf: [40]u8 = undefined;
        const dtags = MsgTags{ .time_value = serverTimeValue(&time_buf), .account = conn.session.account(), .client_tags = client_tags, .msgid = message_id };
        try self.deliverTagged(clientIdFromWorld(recipient), dtags, msg);
        if (echo) try self.deliverTagged(id, dtags, msg);

        // RFC 1459: a PRIVMSG (not NOTICE) to an away user returns RPL_AWAY so
        // the sender sees the auto-reply. NOTICE never auto-responds.
        if (std.ascii.eqlIgnoreCase(command, "PRIVMSG")) {
            if (self.connFor(clientIdFromWorld(recipient))) |rconn| {
                if (rconn.session.awayMessage()) |reason| {
                    try queueNumeric(conn, .RPL_AWAY, &.{target}, reason);
                }
            }
        }
    }

    pub fn handleTopic(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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

    pub fn handleQuit(self: *LinuxServer, id: client_model.ClientId, conn: *ConnState, parsed: *const irc_line.LineView) !void {
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

    /// Map a member's channel-status modes to an auditorium visibility rank.
    fn auditoriumRank(mm: world_model.MemberModes) auditorium.Rank {
        if (mm.isOperator()) return .op;
        if (mm.contains(.voice)) return .voice;
        return .regular;
    }

    fn sendNames(self: *LinuxServer, conn: *ConnState, channel: []const u8) !void {
        // Render NAMES via the names_reply module: each member carries its status
        // prefixes (all of them when the requester negotiated multi-prefix, else
        // only the highest) and optionally nick!user@host (userhost-in-names).
        const max_members: usize = 128;
        var members_buf: [max_members]names_reply.Member = undefined;
        var prefix_buf: [max_members]chanmode.PrefixList = undefined;
        var count: usize = 0;

        // +x AUDITORIUM: regular members are hidden from each other; only ops and
        // voiced members are visible (plus the viewer always sees themselves).
        const is_auditorium = self.world.channelHasExtFlag(channel, .auditorium);
        const viewer_wid = self.world.findNick(conn.session.displayName());
        const viewer_rank = if (viewer_wid) |vw|
            auditoriumRank(self.world.memberModes(channel, vw) orelse world_model.MemberModes.empty())
        else
            auditorium.Rank.regular;

        var it = self.world.memberIterator(channel) orelse return error.NoSuchChannel;
        while (it.next()) |member| {
            if (count >= max_members) break;
            const nick = self.world.nickOf(member.*) orelse continue;
            const modes = self.world.memberModes(channel, member.*) orelse world_model.MemberModes.empty();
            if (is_auditorium) {
                const is_self = if (viewer_wid) |vw| member.*.eql(vw) else false;
                if (!is_self and !auditorium.visibleTo(viewer_rank, auditoriumRank(modes))) continue;
            }
            prefix_buf[count] = modes.allPrefixes();
            members_buf[count] = .{
                .prefixes = prefix_buf[count].asSlice(),
                .nick = nick,
                .user = usernameOf(self, member.*),
                .host = default_host,
            };
            count += 1;
        }

        // World projection (#6): merge remote members announced by established S2S
        // peers for this channel. Deduped against already-listed nicks; the stored
        // u4 status IS the MemberModes bitset, so prefixes/auditorium rank apply
        // uniformly. Host is the origin server name (placeholder user).
        for (self.rx().clients.slots.items) |*slot| {
            if (count >= max_members) break;
            if (!slot.occupied) continue;
            if (slot.value.s2s_secured) |link| {
                if (link.established()) count = self.addRemoteMembers(&members_buf, &prefix_buf, count, is_auditorium, viewer_rank, link.remoteName(), link.channelMembers(channel));
            } else if (slot.value.s2s) |link| {
                if (link.established()) count = self.addRemoteMembers(&members_buf, &prefix_buf, count, is_auditorium, viewer_rank, link.remoteName(), link.channelMembers(channel));
            }
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
    pub fn start(_: *PortableServer) void {}
    pub fn boundPort(_: *PortableServer) ServerError!u16 {
        return error.Unsupported;
    }
    pub fn s2sBoundPort(_: *PortableServer) ServerError!u16 {
        return error.Unsupported;
    }
    pub fn runOnce(_: *PortableServer) ServerError!void {
        return error.Unsupported;
    }
    /// Symbol parity with LinuxServer so the threaded end-to-end tests compile on
    /// non-Linux targets. Never reached: `init` returns Unsupported first, so the
    /// tests SkipZigTest before any thread is spawned.
    pub fn runThreaded(_: *PortableServer, _: *std.atomic.Value(bool)) void {}
    /// Symbol parity for the services → world +r bridge (see LinuxServer).
    pub fn markChannelRegistered(_: *PortableServer, _: []const u8, _: bool) std.mem.Allocator.Error!void {}
};

const CompletionHandler = struct {
    server: *LinuxServer,
    err: ?anyerror = null,

    fn onCompletion(self: *CompletionHandler, completion: ringlane.Completion) void {
        if (self.err != null) return;
        // World-lock boundary (multithreading Phase B): take the shared world's
        // write lock once around the whole completion so concurrent reactors
        // serialize all world (channel/nick/membership) reads + mutations + the
        // delivery they drive. This is the single outermost acquire — no handler
        // re-locks the world, so the non-recursive lock can never self-deadlock.
        // Per-instance state (clients table, send buffers, ring) is reactor-local
        // and needs no lock. Uncontended with one reactor (a couple of atomics).
        self.server.world.lockWrite();
        defer self.server.world.unlockWrite();
        switch (completion) {
            .accept => |event| self.server.handleAccept(event) catch |err| {
                self.err = err;
            },
            .recv => |event| self.server.handleRecv(event) catch |err| {
                self.recordOpErr(err);
            },
            .send => |event| self.server.handleSend(event) catch |err| {
                self.recordOpErr(err);
            },
            .connect => |event| self.server.handleConnect(event) catch |err| {
                self.recordOpErr(err);
            },
            .timeout => self.server.onTimerTick(),
            // poll: the cross-reactor wake eventfd became readable — drain it so
            // the loop ran (and, once sharded, drain this reactor's mailbox).
            .poll => |event| {
                if (event.token.slot == wake_token.slot) self.server.onWakePoll();
            },
            .other => {},
        }
    }

    /// Record a per-connection op error, tolerating completions that arrive for a
    /// connection whose slot was already freed (e.g. an in-flight recv reaping
    /// after `closeConn` drained and freed the slot). The generational slab makes
    /// such stale tokens impossible to alias a reused slot, so `ClientNotFound`
    /// here is a benign lifecycle event, not a fatal loop error.
    fn recordOpErr(self: *CompletionHandler, err: anyerror) void {
        if (err == error.ClientNotFound) return;
        self.err = err;
    }
};

fn tokenFromId(id: client_model.ClientId) ServerError!RingFdToken {
    if (id.gen > ((@as(u32, 1) << 28) - 1)) return error.TokenOutOfRange;
    return .{ .slot = id.slot, .gen = id.gen };
}

fn idFromToken(token: RingFdToken) client_model.ClientId {
    // A completion's token always names a connection on the reactor whose ring
    // produced it — i.e. the reactor bound to this thread. Stamp that reactor's
    // shard so the reconstructed id matches the slab that allocated it (the slab
    // is keyed by `shard`, so a 0 here would miss on any shard but 0). Off any
    // reactor thread (direct test calls), `current_reactor` is null and we fall
    // back to shard 0 — the single-reactor identity, exactly as before.
    const shard_id: u12 = if (current_reactor) |r| r.shard_id else 0;
    return .{ .shard = shard_id, .slot = @intCast(token.slot), .gen = token.gen };
}

fn worldIdFromClient(id: client_model.ClientId) world_model.ClientId {
    return .{ .shard = id.shard, .slot = id.slot, .gen = id.gen };
}

/// The USER-supplied username of the member behind a world client id, or "user".
fn usernameOf(self: *LinuxServer, world_id: world_model.ClientId) []const u8 {
    if (self.connFor(clientIdFromWorld(world_id))) |c| return c.session.username();
    return "user";
}

/// Find a tag's value in a raw IRCv3 tag segment (`a=1;+typing=active;b`).
/// Returns the value slice (may be empty), or null if the key is absent.
fn findTagValue(tags_raw: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, tags_raw, ';');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse {
            if (std.mem.eql(u8, pair, key)) return pair[0..0]; // bare key, no value
            continue;
        };
        if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
    }
    return null;
}

/// True if `nick` (ASCII case-insensitive) is already among the listed members —
/// used to dedupe remote mesh members against local ones in NAMES.
fn nameAlreadyListed(members: []const names_reply.Member, nick: []const u8) bool {
    for (members) |m| {
        if (std.ascii.eqlIgnoreCase(m.nick, nick)) return true;
    }
    return false;
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

/// MizuWasm host callbacks: route a plugin's granted hostcalls to the live
/// connection. `ctx` is the per-invocation `*module_core.Core`. A plugin reply is
/// framed as a server NOTICE to the requesting client.
fn wasmReplyCb(ctx: *anyopaque, text: []const u8) void {
    const core: *module_core.Core = @ptrCast(@alignCast(ctx));
    var buf: [600]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :{s}\r\n", .{ server_name, core.conn.session.displayName(), text }) catch return;
    appendToConn(core.conn, line) catch {};
}
fn wasmLogCb(_: *anyopaque, text: []const u8) void {
    std.debug.print("mizuchi: wasm-plugin: {s}\n", .{text});
}
fn wasmNowCb(_: *anyopaque) i64 {
    return platform.monotonicMillis();
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
    // Implicit-TLS: once the handshake is live, every app-layer write is encrypted
    // into TLS records before it reaches the wire buffer. Pre-handshake writes (the
    // server's own handshake flight, queued by driveTls) pass through untouched.
    if (conn.tls) |t| {
        if (t.handshakeDone()) {
            const ciphertext = t.write(bytes) catch return error.OutputTooSmall;
            return rawAppendToConn(conn, ciphertext);
        }
    }
    return rawAppendToConn(conn, bytes);
}

fn rawAppendToConn(conn: *ConnState, bytes: []const u8) ServerError!void {
    if (conn.send_len + bytes.len > conn.send_buf.len) {
        // Reclaim the already-sent prefix [0, send_offset) for a slow consumer by
        // sliding the unsent tail to the front. NEVER do this while a send SQE is
        // armed: the kernel is still reading send_buf[send_offset..send_len] for
        // the in-flight zero-copy send, so moving those bytes would corrupt the
        // wire. Appending fresh bytes at [send_len..] is always safe.
        if (conn.send_offset > 0 and !conn.send_armed) {
            const tail = conn.send_len - conn.send_offset;
            std.mem.copyForwards(u8, conn.send_buf[0..tail], conn.send_buf[conn.send_offset..conn.send_len]);
            conn.send_len = tail;
            conn.send_offset = 0;
        }
        if (conn.send_len + bytes.len > conn.send_buf.len) return error.OutputTooSmall;
    }
    @memcpy(conn.send_buf[conn.send_len .. conn.send_len + bytes.len], bytes);
    conn.send_len += bytes.len;
}

/// Format a server numeric line (`:<server> <code> <nick> <params> :<trailing>`)
/// into `line_buf`, returning the written slice. Factored out of `queueNumeric`
/// so a cross-shard delivery can build the recipient's numeric from a serialized
/// read of its display name without touching its send buffer.
fn formatNumericLine(
    line_buf: []u8,
    nick: []const u8,
    code: Numeric,
    params: []const []const u8,
    trailing: []const u8,
) ServerError![]const u8 {
    var out = Buf{ .storage = line_buf };
    var code_buf: [3]u8 = undefined;

    try out.appendByte(':');
    try out.append(server_name);
    try out.appendByte(' ');
    try out.append(formatNumericCode(code, &code_buf));
    try out.appendByte(' ');
    try out.append(nick);
    for (params) |param| {
        try out.appendByte(' ');
        try out.append(param);
    }
    try out.append(" :");
    try out.append(trailing);
    try out.append("\r\n");
    return out.written();
}

fn queueNumeric(
    conn: *ConnState,
    code: Numeric,
    params: []const []const u8,
    trailing: []const u8,
) ServerError!void {
    var line_buf: [default_reply_bytes]u8 = undefined;
    const line = try formatNumericLine(&line_buf, conn.session.displayName(), code, params, trailing);
    try appendToConn(conn, line);
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
        hostOf(conn),
    }) catch return error.OutputTooSmall;
}

/// Parse a dotted-quad IPv4 literal ("a.b.c.d") into 4 octets, or null if it is
/// not a well-formed IPv4 address.
fn parseIp4(s: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 4) return null;
        out[i] = std.fmt.parseInt(u8, part, 10) catch return null;
    }
    return if (i == 4) out else null;
}

/// Build the extended-ban evaluation context for `conn`. `host_mask` is the full
/// nick!user@host prefix (so plain +b masks still glob against it); `chan_buf`
/// backs the client's current channel list (for `$c:` bans). The returned
/// context borrows `host_mask` and `chan_buf`, so both must outlive its use.
fn banContextFor(
    self: *LinuxServer,
    conn: *const ConnState,
    wid: world_model.ClientId,
    host_mask: []const u8,
    chan_buf: [][]const u8,
) world_model.World.BanContext {
    const nchan = self.world.channelsOf(wid, chan_buf);
    return .{
        .account = conn.session.account(),
        .realname = conn.session.realname(),
        .host = host_mask,
        .country = null, // no GeoIP source yet; $g: bans never match
        .channels = chan_buf[0..nchan],
    };
}

/// Whether `text` is a CTCP request that `+C` should block — i.e. wrapped in
/// \x01 and NOT a CTCP ACTION (/me stays allowed).
fn isBlockableCtcp(text: []const u8) bool {
    if (text.len < 2 or text[0] != 0x01 or text[text.len - 1] != 0x01) return false;
    const body = text[1 .. text.len - 1];
    const action = "ACTION";
    if (body.len >= action.len and std.ascii.eqlIgnoreCase(body[0..action.len], action)) return false;
    return true;
}

/// The host to show for `conn`: its visible (cloaked/vhost) host, falling back
/// to the placeholder when no peer address was captured (e.g. AF_UNIX tests).
fn hostOf(conn: *const ConnState) []const u8 {
    const h = conn.session.host();
    return if (h.len == 0) default_host else h;
}

/// Format raw IPv6 bytes as eight colon-separated hex groups (matching the
/// cloak module's IPv6 rendering style).
fn formatIp6(out: []u8, address: [16]u8) ![]const u8 {
    var groups: [8]u16 = undefined;
    for (&groups, 0..) |*g, i| g.* = std.mem.readInt(u16, address[i * 2 ..][0..2], .big);
    return std.fmt.bufPrint(out, "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}", .{
        groups[0], groups[1], groups[2], groups[3],
        groups[4], groups[5], groups[6], groups[7],
    });
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

// --- SASL-oper test fixtures (oper is SASL-only) ---------------------------

/// Test PLAIN verifier: accepts the account "admin" / password "mizuchi".
fn testOperVerify(_: *anyopaque, creds: sasl.PlainCredentials) bool {
    return std.mem.eql(u8, creds.authcid, "admin") and std.mem.eql(u8, creds.password, "mizuchi");
}
var test_oper_anchor: u8 = 0;
const test_oper_checker = sasl.PlainChecker{ .ptr = &test_oper_anchor, .verifyFn = testOperVerify };
const test_oper_bindings = [_]oper_mod.OperBinding{
    .{ .account_name = "admin", .class_name = "netadmin", .privileges = oper_mod.OperPrivileges.full },
};

/// Config for the live oper tests: SASL PLAIN verifier + an oper binding for the
/// "admin" account, so a client that SASL-authenticates as admin is elevated.
fn operTestConfig(port: u16) Config {
    return .{
        .host = "127.0.0.1",
        .port = port,
        .sasl_checker = test_oper_checker,
        .oper_registry = oper_mod.OperRegistry.init(&test_oper_bindings) catch unreachable,
    };
}

/// Drive a live client through SASL PLAIN as the "admin" oper account. Call
/// before NICK/USER so the client is elevated automatically at registration.
fn saslAdminPrelude(fd: linux.fd_t) ServerError!void {
    var b64: [64]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&b64, "\x00admin\x00mizuchi");
    var line: [128]u8 = undefined;
    try writeAllFd(fd, "CAP REQ :sasl\r\n");
    try writeAllFd(fd, "AUTHENTICATE PLAIN\r\n");
    try writeAllFd(fd, std.fmt.bufPrint(&line, "AUTHENTICATE {s}\r\n", .{enc}) catch return error.OutputTooSmall);
    try writeAllFd(fd, "CAP END\r\n");
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
    // Force FIN to the peer and complete any in-flight recv NOW. An io_uring
    // recv SQE holds a reference to the socket's `struct file`, so a bare
    // close(fd) only drops the fd-table entry — the socket lingers (no FIN)
    // until that pending op is canceled. shutdown() releases it immediately:
    // the peer sees EOF and the pending recv reaps with res=0 (its slot is
    // already freed, so the completion is harmlessly ignored).
    _ = linux.shutdown(fd, linux.SHUT.RDWR);
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
    // Use a WALL-CLOCK deadline rather than a fixed poll count: under heavy
    // parallel-test CPU contention the reactor thread can be briefly starved, so
    // a count-based budget (poll returns early on data, burning iterations)
    // produced spurious TestTimeouts. `max_polls` now sets a lower bound on the
    // budget; we wait at least that long but cap at a generous 20s so genuine
    // bugs still fail in bounded time.
    const budget_ms: i64 = @max(@as(i64, @intCast(max_polls)) * 25, 20_000);
    const deadline = platform.monotonicMillis() + budget_ms;
    while (true) {
        if (std.mem.indexOf(u8, client.written(), needle) != null) return;
        if (platform.monotonicMillis() >= deadline) return error.TestTimeout;
        var fds = [_]posix.pollfd{.{ .fd = client.fd, .events = linux.POLL.IN, .revents = 0 }};
        const ready = posix.poll(&fds, 50) catch return error.Unexpected;
        if (ready == 0) continue;
        if ((fds[0].revents & linux.POLL.IN) == 0) continue;
        if (client.len == client.buf.len) return error.OutputTooSmall;
        const n = try readFd(client.fd, client.buf[client.len..]);
        if (n == 0) return error.ConnectionReset;
        client.len += n;
    }
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

test "threaded server: cross-shard PRIVMSG delivery (num_shards=2)" {
    // Two reactor threads, SO_REUSEPORT listeners — the kernel may place each
    // client on either reactor. Several clients in one channel raise the odds two
    // of them land on DIFFERENT shards; a PRIVMSG must still reach every member,
    // which exercises the cross-shard fabric handoff end to end. Repeated rounds
    // make a race-driven drop/dup fail rather than slip through.
    var server = Server.init(std.testing.allocator, .{
        .host = "127.0.0.1",
        .port = 0,
        .num_shards = 2,
    }) catch |err| switch (err) {
        // No io_uring / no perms / no SO_REUSEPORT in this sandbox: skip, don't fail.
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable, error.AddressInUse => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    // A single reactor (clamped, or fabric/pool unavailable) cannot test cross
    // shard; skip so this only asserts when the multi-reactor topology is live.
    if (server.reactors.len < 2) return error.SkipZigTest;
    const port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        // Clear the flag AND wake every reactor's wake eventfd. A SO_REUSEPORT
        // throwaway connection only nudges whichever reactor the kernel routes it
        // to; the other worker would stay blocked in submitAndWait forever and
        // pool.join() would hang. wakeAllReactors makes every blocked loop return,
        // observe run==false, and exit so the join (and this thread) completes.
        server.requestStop(&run);
        thr.join();
    }

    // Connect a handful of clients; with round-robin kernel placement across two
    // reactors this all-but-guarantees the channel spans both shards.
    const n_clients = 6;
    var fds: [n_clients]linux.fd_t = undefined;
    var clients: [n_clients]LiveClient = undefined;
    var connected: usize = 0;
    defer for (fds[0..connected]) |fd| closeFd(fd);
    for (0..n_clients) |i| {
        fds[i] = connectLoopback(port) catch |err| switch (err) {
            error.PermissionDenied, error.SocketUnavailable, error.ConnectionRefused => return error.SkipZigTest,
            else => return err,
        };
        connected += 1;
        clients[i] = LiveClient{ .fd = fds[i] };
    }

    // Register each client with a distinct nick and join the shared channel.
    var nick_buf: [n_clients][8]u8 = undefined;
    for (0..n_clients) |i| {
        const nick = std.fmt.bufPrint(&nick_buf[i], "U{d}", .{i}) catch unreachable;
        var reg_buf: [64]u8 = undefined;
        const reg = std.fmt.bufPrint(&reg_buf, "NICK {s}\r\nUSER u{d} 0 * :User {d}\r\n", .{ nick, i, i }) catch unreachable;
        try writeAllFd(fds[i], reg);
    }
    for (0..n_clients) |i| {
        var need: [12]u8 = undefined;
        const needle = std.fmt.bufPrint(&need, " 001 U{d} ", .{i}) catch unreachable;
        try recvUntil(&clients[i], needle, 400);
    }
    for (0..n_clients) |i| {
        try writeAllFd(fds[i], "JOIN #shard\r\n");
        var need: [20]u8 = undefined;
        const needle = std.fmt.bufPrint(&need, " 366 U{d} #shard ", .{i}) catch unreachable;
        try recvUntil(&clients[i], needle, 400);
    }

    // Several rounds: each round a different sender messages the channel; every
    // OTHER client must receive it. A line that crossed shards rode the fabric.
    const rounds = 4;
    for (0..rounds) |r| {
        const sender = r % n_clients;
        for (0..n_clients) |i| clients[i].reset();
        var line_buf: [48]u8 = undefined;
        const line = std.fmt.bufPrint(&line_buf, "PRIVMSG #shard :round{d}\r\n", .{r}) catch unreachable;
        try writeAllFd(fds[sender], line);

        var exp_buf: [40]u8 = undefined;
        const expected = std.fmt.bufPrint(&exp_buf, "PRIVMSG #shard :round{d}\r\n", .{r}) catch unreachable;
        for (0..n_clients) |i| {
            if (i == sender) continue;
            // Whether U{i} shares the sender's reactor or not, the message must
            // arrive — proving local AND cross-shard delivery in one assertion.
            try recvUntil(&clients[i], expected, 400);
        }
    }
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

test "threaded server: AWAY/SETNAME/EVENT-broadcast/INFO/USERS/LINKS/MAP end-to-end" {
    var server = Server.init(std.testing.allocator, operTestConfig(0)) catch |err| switch (err) {
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

    try saslAdminPrelude(fd_a); // A authenticates as the admin oper account
    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try recvUntil(&a, " 381 A ", 200); // A auto-elevated on SASL login
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

    // A non-oper (B) cannot use EVENT -> 481 (wallops is folded into EVENT).
    b.reset();
    try writeAllFd(fd_b, "EVENT BROADCAST :nope\r\n");
    try recvUntil(&b, " 481 B ", 200);
    // WHOIS now shows the operator line (313).
    a.reset();
    try writeAllFd(fd_a, "WHOIS A\r\n");
    try recvUntil(&a, " 313 A A ", 200);
    a.reset();
    // EVENT BROADCAST (the former WALLOPS) is delivered as an oper-visible Event
    // Spine announce: A, subscribed on elevation, receives NOTE EVENT ANNOUNCE.
    try writeAllFd(fd_a, "EVENT BROADCAST :hello opers\r\n");
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
    a.reset();
    b.reset();
    try writeAllFd(fd_a, "KILL B :spam\r\n");
    try recvUntil(&b, "KILL B :spam\r\n", 200);
    // Oper A (subscribed) also sees the KILL as an Event Spine notice.
    try recvUntil(&a, "NOTE EVENT KILL ", 200);
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

test "threaded server: server stamps @msgid on relayed PRIVMSG for message-tags holders" {
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

    // A negotiates message-tags; B does not.
    try writeAllFd(fd_a, "CAP REQ :message-tags\r\nNICK A\r\nUSER alice 0 * :Alice\r\nCAP END\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&b, " 001 B ", 200);

    try writeAllFd(fd_a, "JOIN #m\r\n");
    try recvUntil(&a, " 366 A #m ", 200);
    try writeAllFd(fd_b, "JOIN #m\r\n");
    try recvUntil(&b, " 366 B #m ", 200);

    // B messages the channel; A (message-tags holder) sees an @msgid= tag on the
    // relayed line. The id is opaque, so assert presence + the unchanged body.
    a.reset();
    try writeAllFd(fd_b, "PRIVMSG #m :hello\r\n");
    try recvUntil(&a, "PRIVMSG #m :hello\r\n", 200);
    try std.testing.expect(std.mem.indexOf(u8, a.written(), "@msgid=") != null);
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

test "buildTagPrefix stamps msgid only for message-tags recipients" {
    var buf: [256]u8 = undefined;
    const tags = LinuxServer.MsgTags{ .time_value = "", .account = null, .msgid = "0123456789ABCDEFGHJKMNPQRS" };

    // No message-tags cap -> msgid is withheld.
    var none = dispatch.ClientSession.init();
    try std.testing.expectEqualStrings("", buildTagPrefix(&none, tags, &buf));

    // message-tags negotiated -> msgid present as its own @-segment.
    var mt = dispatch.ClientSession.init();
    mt.addCap(.message_tags);
    try std.testing.expectEqualStrings("@msgid=0123456789ABCDEFGHJKMNPQRS ", buildTagPrefix(&mt, tags, &buf));

    // Coexists with server-time in one segment, semicolon-joined.
    mt.addCap(.server_time);
    const timed = LinuxServer.MsgTags{ .time_value = "2026-06-08T00:00:00.000Z", .account = null, .msgid = "0123456789ABCDEFGHJKMNPQRS" };
    try std.testing.expectEqualStrings(
        "@time=2026-06-08T00:00:00.000Z;msgid=0123456789ABCDEFGHJKMNPQRS ",
        buildTagPrefix(&mt, timed, &buf),
    );
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

    // A's tagged TAGMSG is relayed to B (message-tags peer) with a server-minted
    // @msgid stamped ahead of the relayed client tags.
    b.reset();
    try writeAllFd(fd_a, "@+typing=active TAGMSG #t\r\n");
    try recvUntil(&b, "+typing=active :A!alice@localhost TAGMSG #t\r\n", 200);
    try std.testing.expect(std.mem.indexOf(u8, b.written(), "@msgid=") != null);
    try std.testing.expect(std.mem.indexOf(u8, b.written(), ";+typing=active") != null);
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

test "threaded server: draft/multiline batch reassembles + splits to recipient" {
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

    // A negotiates draft/multiline; B is an ordinary member.
    try writeAllFd(fd_a, "CAP REQ :draft/multiline\r\nNICK A\r\nUSER alice 0 * :Alice\r\nCAP END\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&b, " 001 B ", 200);
    try writeAllFd(fd_a, "JOIN #m\r\n");
    try recvUntil(&a, " 366 A #m ", 200);
    try writeAllFd(fd_b, "JOIN #m\r\n");
    try recvUntil(&b, " 366 B #m ", 200);

    // chunk2 carries the concat tag so it joins chunk1 into one line; chunk3 is a
    // fresh line. The reassembled value is "Line1more\nLine2" and is delivered to
    // B as two separate PRIVMSGs.
    b.reset();
    try writeAllFd(fd_a,
        "BATCH +z draft/multiline #m\r\n" ++
        "@batch=z PRIVMSG #m :Line1\r\n" ++
        "@batch=z;draft/multiline-concat PRIVMSG #m :more\r\n" ++
        "@batch=z PRIVMSG #m :Line2\r\n" ++
        "BATCH -z\r\n");
    try recvUntil(&b, ":A!alice@localhost PRIVMSG #m :Line1more\r\n", 200);
    try recvUntil(&b, ":A!alice@localhost PRIVMSG #m :Line2\r\n", 200);
}

test "threaded server: external wakeReactor drives the running reactor loop" {
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    if (server.rx().wake == null) return error.SkipZigTest; // eventfd unavailable
    const plain_port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(plain_port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    // From this (foreign) thread, wake the reactor; the in-flight wake poll
    // completes, the loop runs, and onWakePoll bumps the counter.
    server.wakeReactor();
    var spins: usize = 0;
    while (server.rx().wake_count.load(.monotonic) == 0) : (spins += 1) {
        if (spins > 5_000_000) return error.TestUnexpectedResult;
        std.Thread.yield() catch {};
    }
    try std.testing.expect(server.rx().wake_count.load(.monotonic) >= 1);
}

test "ring: poll op fires a completion when a watched eventfd becomes readable" {
    var ring = RingCore.init(8, .{}) catch |err| {
        if (ringlane.isUnsupportedInitError(err)) return error.SkipZigTest;
        return err;
    };
    defer ring.deinit();

    const efd_rc = linux.eventfd(0, 0);
    if (posix.errno(efd_rc) != .SUCCESS) return error.SkipZigTest;
    const efd: linux.fd_t = @intCast(efd_rc);
    defer closeFd(efd);

    const tok = RingFdToken{ .slot = 7, .gen = 3 };
    try ring.submitPollAdd(tok, efd, linux.POLL.IN);

    // Make the eventfd readable, then reap: the poll completion must fire.
    var one: u64 = 1;
    _ = linux.write(efd, std.mem.asBytes(&one), @sizeOf(u64));

    const Sink = struct {
        got: bool = false,
        slot: u32 = 0,
        res: i32 = 0,
        fn onCompletion(self: *@This(), c: ringlane.Completion) void {
            switch (c) {
                .poll => |e| {
                    self.got = true;
                    self.slot = e.token.slot;
                    self.res = e.res;
                },
                else => {},
            }
        }
    };
    var sink = Sink{};
    _ = try ring.submitAndWait(1);
    var cqes: [8]linux.io_uring_cqe = undefined;
    try ring.reapCompletions(&cqes, 0, &sink);

    try std.testing.expect(sink.got);
    try std.testing.expectEqual(@as(u32, 7), sink.slot);
    try std.testing.expect(sink.res >= 0); // poll res carries the ready mask
}

test "threaded server: implicit-TLS client handshakes + registers over the wire" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const tls_client = @import("../crypto/tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    // Bootstrap a self-signed Ed25519 leaf with a SAN the client will accept.
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x51} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x51, 0x01 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });
    const chain = [_][]const u8{der};

    var server = Server.init(alloc, .{
        .host = "127.0.0.1",
        .port = 0,
        .tls_port = 0,
        .tls_cert_chain = &chain,
        .tls_signing_key = kp,
    }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const tls_port = try server.tlsBoundPort();
    const plain_port = try server.boundPort();

    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(plain_port)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    const fd = connectLoopback(tls_port) catch return error.SkipZigTest;
    defer closeFd(fd);

    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &chain });
    defer client.deinit();

    // TLS 1.3 handshake driven over the live socket.
    const ch = try client.start();
    defer alloc.free(ch);
    try writeAllFd(fd, ch);
    var rbuf: [4096]u8 = undefined;
    var guard: usize = 0;
    while (!client.handshakeDone()) : (guard += 1) {
        if (guard > 64) return error.TestUnexpectedResult;
        const n = try readFd(fd, &rbuf);
        if (n == 0) return error.TestUnexpectedResult;
        switch (try client.feed(rbuf[0..n])) {
            .bytes_to_send => |b| {
                defer alloc.free(b);
                try writeAllFd(fd, b);
            },
            .need_more => {},
        }
    }

    try std.testing.expect(client.handshakeDone());

    // Registration over the encrypted channel: send NICK/USER, then read the
    // welcome burst back, framing + decrypting TLS records until RPL_WELCOME.
    const reg = try client.encrypt("NICK T\r\nUSER t 0 * :Tester\r\n");
    defer alloc.free(reg);
    try writeAllFd(fd, reg);

    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(alloc);
    var cipher: std.ArrayList(u8) = .empty;
    defer cipher.deinit(alloc);
    guard = 0;
    while (std.mem.indexOf(u8, plain.items, " 001 T ") == null) : (guard += 1) {
        if (guard > 64) return error.TestUnexpectedResult;
        const n = try readFd(fd, &rbuf);
        if (n == 0) return error.TestUnexpectedResult;
        try cipher.appendSlice(alloc, rbuf[0..n]);
        // Drain every complete TLS record (5-byte header + big-endian length).
        while (cipher.items.len >= 5) {
            const body_len = std.mem.readInt(u16, cipher.items[3..5], .big);
            const wire_len = 5 + @as(usize, body_len);
            if (cipher.items.len < wire_len) break;
            switch (try client.decryptApp(cipher.items[0..wire_len])) {
                .application_data => |pt| {
                    defer alloc.free(pt);
                    try plain.appendSlice(alloc, pt);
                },
                .control => {},
            }
            std.mem.copyForwards(u8, cipher.items[0 .. cipher.items.len - wire_len], cipher.items[wire_len..]);
            cipher.shrinkRetainingCapacity(cipher.items.len - wire_len);
        }
    }
    try expectContains(plain.items, " 001 T ");
}

test "threaded server: empty NOTICE never returns ERR_NEEDMOREPARAMS" {
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
    a.reset();
    // A param-less NOTICE must be silently dropped; the trailing PING proves the
    // server kept processing and that no 461 was interleaved.
    try writeAllFd(fd_a, "NOTICE\r\nPING :tok\r\n");
    try recvUntil(&a, "PONG :tok", 200);
    try std.testing.expect(std.mem.indexOf(u8, a.written(), " 461 ") == null);
}

test "threaded server: utf8only advertised and invalid PRIVMSG rejected" {
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
    // ISUPPORT advertises the UTF8ONLY token.
    try recvUntil(&a, "UTF8ONLY", 200);
    a.reset();
    // Overlong-encoded slash (C0 AF) is invalid UTF-8 → FAIL ... INVALID_UTF8.
    try writeAllFd(fd_a, "PRIVMSG A :bad\xC0\xAF\r\n");
    try recvUntil(&a, "FAIL PRIVMSG INVALID_UTF8", 200);
}

test "threaded server: NAMES honors multi-prefix cap" {
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
    // Negotiate multi-prefix, register, become founder of #m, then self-op so the
    // member holds two tiers (~ founder + @ op).
    try writeAllFd(fd_a, "CAP REQ :multi-prefix\r\nNICK A\r\nUSER alice 0 * :Alice\r\nCAP END\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try writeAllFd(fd_a, "JOIN #m\r\n");
    try recvUntil(&a, " 366 A #m ", 200);
    try writeAllFd(fd_a, "MODE #m +o A\r\n");
    try recvUntil(&a, "MODE #m +o A", 200);
    a.reset();
    // With multi-prefix the NAMES entry carries every held prefix (~@), not just
    // the highest.
    try writeAllFd(fd_a, "NAMES #m\r\n");
    try recvUntil(&a, "~@A", 200);
}

test "threaded server: WHISPER delivers to channel co-member only" {
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
    const alloc = std.testing.allocator;
    const a = try alloc.create(LiveClient);
    defer alloc.destroy(a);
    const b = try alloc.create(LiveClient);
    defer alloc.destroy(b);
    a.* = .{ .fd = fd_a };
    b.* = .{ .fd = fd_b };
    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(a, " 001 A ", 200);
    try recvUntil(b, " 001 B ", 200);
    try writeAllFd(fd_a, "JOIN #w\r\n");
    try writeAllFd(fd_b, "JOIN #w\r\n");
    try recvUntil(a, " 366 A #w ", 200);
    try recvUntil(b, " 366 B #w ", 200);
    b.reset();
    // A whispers B on #w; B receives it.
    try writeAllFd(fd_a, "WHISPER #w B :psst\r\n");
    try recvUntil(b, ":A!alice@localhost WHISPER #w B :psst", 200);
    // Whispering a nonexistent nick yields ERR_NOSUCHNICK (401).
    a.reset();
    try writeAllFd(fd_a, "WHISPER #w Nobody :hi\r\n");
    try recvUntil(a, " 401 ", 200);
    // Founder sets +w NOWHISPER (IRCX extended channel flag); whispers are blocked.
    try writeAllFd(fd_a, "MODE #w +w\r\n");
    try recvUntil(a, "MODE #w +w", 200);
    a.reset();
    try writeAllFd(fd_a, "WHISPER #w B :blocked\r\n");
    try recvUntil(a, " 923 ", 200);
    // MODEX named-mode front-end: set AUTHONLY (-> +a), then query lists it (820/821).
    a.reset();
    try writeAllFd(fd_a, "MODEX #w +AUTHONLY\r\n");
    try recvUntil(a, "MODE #w +a", 200);
    a.reset();
    try writeAllFd(fd_a, "MODEX #w\r\n");
    try recvUntil(a, " 820 ", 200);
    try recvUntil(a, "AUTHONLY", 200);
    try recvUntil(a, " 821 ", 200);
}

test "threaded server: +x auditorium hides regular members in NAMES" {
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
    try writeAllFd(fd_a, "JOIN #aud\r\n"); // A founder (op rank)
    try recvUntil(a, " 366 A #aud ", 200);
    try writeAllFd(fd_b, "JOIN #aud\r\n"); // B regular
    try recvUntil(b, " 366 B #aud ", 200);
    try writeAllFd(fd_c, "JOIN #aud\r\n"); // C regular
    try recvUntil(c, " 366 C #aud ", 200);
    try writeAllFd(fd_a, "MODE #aud +x\r\n");
    try recvUntil(a, "MODE #aud +x", 200);
    // C (regular) sees the founder A and itself, but NOT the other regular B.
    c.reset();
    try writeAllFd(fd_c, "NAMES #aud\r\n");
    try recvUntil(c, " 366 C #aud ", 200);
    try std.testing.expect(std.mem.indexOf(u8, c.written(), "C") != null);
    try std.testing.expect(std.mem.indexOf(u8, c.written(), "~A") != null);
    try std.testing.expect(std.mem.indexOf(u8, c.written(), "B") == null);
}

test "threaded server: oper DEBUG dumps the flight recorder" {
    var server = Server.init(std.testing.allocator, operTestConfig(0)) catch |err| switch (err) {
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
    try saslAdminPrelude(fd_a);
    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try recvUntil(&a, " 381 A ", 200); // auto-elevated on SASL login
    // DEBUG dumps the structured flight recorder; OPER just recorded an event.
    a.reset();
    try writeAllFd(fd_a, "DEBUG\r\n");
    try recvUntil(&a, "End of DEBUG flight recorder", 200);
    try std.testing.expect(std.mem.indexOf(u8, a.written(), "operator elevated via SASL account") != null);
}

test "threaded server: IRCX/ISIRCX discovery emits RPL_IRCX 800" {
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
    // ISIRCX queries (state 0, not yet opted in).
    a.reset();
    try writeAllFd(fd_a, "ISIRCX\r\n");
    try recvUntil(&a, " 800 A 0 0 ", 200);
    // IRCX enables (state flips to 1) and reports the SASL package list.
    a.reset();
    try writeAllFd(fd_a, "IRCX\r\n");
    try recvUntil(&a, " 800 A 1 0 ", 200);
    try std.testing.expect(std.mem.indexOf(u8, a.written(), "SCRAM-SHA-256") != null);
    // MODE ISIRCX is the discovery alias — now reports enabled.
    a.reset();
    try writeAllFd(fd_a, "MODE ISIRCX\r\n");
    try recvUntil(&a, " 800 A 1 0 ", 200);
}

test "threaded server: PROP set/get gated by channel-op" {
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
    const alloc = std.testing.allocator;
    const a = try alloc.create(LiveClient);
    defer alloc.destroy(a);
    const b = try alloc.create(LiveClient);
    defer alloc.destroy(b);
    a.* = .{ .fd = fd_a };
    b.* = .{ .fd = fd_b };
    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(a, " 001 A ", 200);
    try recvUntil(b, " 001 B ", 200);
    try writeAllFd(fd_a, "JOIN #p\r\n");
    try recvUntil(a, " 366 A #p ", 200);
    // Founder A sets a channel property and reads it back (818 + 819).
    a.reset();
    try writeAllFd(fd_a, "PROP #p SUBJECT :hello\r\n");
    try recvUntil(a, " 818 A #p ", 200);
    try recvUntil(a, " 819 A #p ", 200);
    a.reset();
    try writeAllFd(fd_a, "PROP #p SUBJECT\r\n");
    try recvUntil(a, " 818 A #p ", 200);
    // B, not on the channel, cannot set channel props (ERR_NOACCESS 913).
    b.reset();
    try writeAllFd(fd_b, "PROP #p SUBJECT :nope\r\n");
    try recvUntil(b, " 913 ", 200);
    // A sets a SECRET key; B (no write access) must not be able to read it back —
    // the GET returns only the 819 end with no 818/value leak.
    a.reset();
    try writeAllFd(fd_a, "PROP #p OWNERKEY :sekret\r\n");
    try recvUntil(a, " 818 A #p ", 200);
    b.reset();
    try writeAllFd(fd_b, "PROP #p OWNERKEY\r\n");
    try recvUntil(b, " 819 B #p ", 200);
    try std.testing.expect(std.mem.indexOf(u8, b.written(), "sekret") == null);
    try std.testing.expect(std.mem.indexOf(u8, b.written(), " 818 ") == null);
}

test "threaded server: ACCESS add/list/delete gated by channel-op" {
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
    const alloc = std.testing.allocator;
    const a = try alloc.create(LiveClient);
    defer alloc.destroy(a);
    const b = try alloc.create(LiveClient);
    defer alloc.destroy(b);
    a.* = .{ .fd = fd_a };
    b.* = .{ .fd = fd_b };
    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(a, " 001 A ", 200);
    try recvUntil(b, " 001 B ", 200);
    try writeAllFd(fd_a, "JOIN #a\r\n");
    try recvUntil(a, " 366 A #a ", 200);
    // Founder A grants VOICE access, lists it, then deletes it (801/803-805/802).
    a.reset();
    try writeAllFd(fd_a, "ACCESS #a ADD VOICE *!*@trusted.example\r\n");
    try recvUntil(a, " 801 A #a VOICE *!*@trusted.example", 200);
    a.reset();
    try writeAllFd(fd_a, "ACCESS #a LIST\r\n");
    try recvUntil(a, " 803 A #a ", 200);
    try recvUntil(a, " 804 A ", 200);
    try recvUntil(a, " 805 A #a ", 200);
    a.reset();
    try writeAllFd(fd_a, "ACCESS #a DELETE VOICE *!*@trusted.example\r\n");
    try recvUntil(a, " 802 A #a VOICE *!*@trusted.example", 200);
    // B (not a channel operator) cannot manage the access list (482).
    b.reset();
    try writeAllFd(fd_b, "ACCESS #a ADD VOICE *!*@x\r\n");
    try recvUntil(b, " 482 ", 200);
    // Channel-recycle: A seeds a DENY entry, parts (channel destroyed as sole
    // member), then recreates #a — the stale DENY must NOT survive into the new
    // incarnation (only 803 start + 805 end, no 804 entry line).
    try writeAllFd(fd_a, "ACCESS #a ADD DENY *!*@evil.example\r\n");
    try recvUntil(a, " 801 A #a DENY ", 200);
    try writeAllFd(fd_a, "PART #a\r\n");
    try recvUntil(a, "PART #a", 200);
    try writeAllFd(fd_a, "JOIN #a\r\n");
    try recvUntil(a, " 366 A #a ", 200);
    a.reset();
    try writeAllFd(fd_a, "ACCESS #a LIST\r\n");
    try recvUntil(a, " 805 A #a ", 200);
    try std.testing.expect(std.mem.indexOf(u8, a.written(), "evil.example") == null);
    try std.testing.expect(std.mem.indexOf(u8, a.written(), " 804 ") == null);
}

test "threaded server: EVENT subscription managed by opers" {
    var server = Server.init(std.testing.allocator, operTestConfig(0)) catch |err| switch (err) {
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
    try saslAdminPrelude(fd_a);
    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try recvUntil(&a, " 381 A ", 200); // A auto-elevated on SASL login

    // A non-oper (no SASL oper binding) cannot use EVENT (ERR_NOPRIVILEGES 481).
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);
    var b = LiveClient{ .fd = fd_b };
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&b, " 001 B ", 200);
    try writeAllFd(fd_b, "EVENT LIST\r\n");
    try recvUntil(&b, " 481 ", 200);

    // A is oper (auto-subscribed to all categories); DEL KILL removes just one.
    // OPER status reflects +o in the user mode query (RPL_UMODEIS 221).
    a.reset();
    try writeAllFd(fd_a, "MODE A\r\n");
    try recvUntil(&a, " 221 A :+o", 200);
    try writeAllFd(fd_a, "EVENT DEL KILL\r\n");
    try recvUntil(&a, "EVENT LIST :End of event list", 200);
    a.reset();
    try writeAllFd(fd_a, "EVENT LIST\r\n");
    try recvUntil(&a, "EVENT LIST :End of event list", 200);
    try std.testing.expect(std.mem.indexOf(u8, a.written(), "EVENT LIST CONNECT") != null);
    try std.testing.expect(std.mem.indexOf(u8, a.written(), "EVENT LIST KILL") == null);
}

test "threaded server: REDACT broadcast + KLINE oper event" {
    var server = Server.init(std.testing.allocator, operTestConfig(0)) catch |err| switch (err) {
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
    try saslAdminPrelude(fd_a);
    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try recvUntil(&a, " 381 A ", 200); // auto-elevated on SASL login
    try writeAllFd(fd_a, "JOIN #r\r\n");
    try recvUntil(&a, " 366 A #r ", 200);

    // REDACT broadcasts to the channel (A is founder/op, sees its own).
    a.reset();
    try writeAllFd(fd_a, "REDACT #r 7 :gone\r\n");
    try recvUntil(&a, "REDACT #r 7 :gone", 200);

    // KLINE emits an oper-action Event Spine notice (A is subscribed).
    a.reset();
    try writeAllFd(fd_a, "WARD ADD mask bad!*@* expel :spam\r\n");
    try recvUntil(&a, "NOTE EVENT OPER_ACTION ", 200);
    // TRACE -> 205 user line + 262 end.
    a.reset();
    try writeAllFd(fd_a, "TRACE\r\n");
    try recvUntil(&a, " 205 ", 200);
    try recvUntil(&a, " 262 ", 200);
    // TESTLINE: a host matching the KLINE bad!*@* reports RPL_TESTLINE 725;
    // a non-matching host reports RPL_NOTESTLINE 726.
    a.reset();
    try writeAllFd(fd_a, "TESTLINE bad!user@host\r\n");
    try recvUntil(&a, " 725 ", 200);
    a.reset();
    try writeAllFd(fd_a, "TESTLINE good!user@host\r\n");
    try recvUntil(&a, " 726 ", 200);
    // TESTMASK counts connected clients matching the mask (A itself matches).
    a.reset();
    try writeAllFd(fd_a, "TESTMASK *!*@localhost\r\n");
    try recvUntil(&a, " 727 ", 200);
}

test "threaded server: ACCEPT add + list" {
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
    try writeAllFd(fd_a, "ACCEPT +bob\r\n");
    a.reset();
    try writeAllFd(fd_a, "ACCEPT\r\n");
    try recvUntil(&a, " 281 A bob", 200);
    try recvUntil(&a, " 282 A ", 200);
}

test "threaded server: METADATA set then get" {
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
    a.reset();
    try writeAllFd(fd_a, "METADATA * SET url :http://x\r\n");
    try recvUntil(&a, " 761 A * url ", 200);
    try recvUntil(&a, " 762 A ", 200);
    a.reset();
    try writeAllFd(fd_a, "METADATA * GET url\r\n");
    try recvUntil(&a, " 761 A * url * :http://x", 200);
    // Writing another user's metadata is denied (ERR_KEYNOPERMISSION 769).
    a.reset();
    try writeAllFd(fd_a, "METADATA Bob SET url :http://y\r\n");
    try recvUntil(&a, " 769 A Bob url ", 200);
    // A second client's `*` namespace is isolated from A's: B's GET misses (766),
    // proving `*` resolves per-client rather than into one shared bucket.
    const fd_b = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_b);
    var b = LiveClient{ .fd = fd_b };
    try writeAllFd(fd_b, "NICK B\r\nUSER bob 0 * :Bob\r\n");
    try recvUntil(&b, " 001 B ", 200);
    b.reset();
    try writeAllFd(fd_b, "METADATA * GET url\r\n");
    try recvUntil(&b, " 766 B * url ", 200);
}

test "threaded server: WHOX field-selected reply" {
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
    try writeAllFd(fd_a, "JOIN #w\r\n");
    try recvUntil(&a, " 366 A #w ", 200);
    a.reset();
    try writeAllFd(fd_a, "WHO #w %cnuhs\r\n");
    try recvUntil(&a, " 354 A ", 200);
    try recvUntil(&a, " 315 A #w ", 200);
}

test "threaded server: MODE multi-flag batching in one command" {
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
    try writeAllFd(fd_a, "JOIN #m\r\n");
    try recvUntil(&a, " 366 A #m ", 200);
    // Several flag modes set in one MODE command echo together.
    a.reset();
    try writeAllFd(fd_a, "MODE #m +nt\r\n");
    try recvUntil(&a, "MODE #m +nt", 200);
}

test "threaded server: +p private + +h hidden channel flags" {
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
    try writeAllFd(fd_a, "JOIN #ph\r\n");
    try recvUntil(&a, " 366 A #ph ", 200);
    a.reset();
    try writeAllFd(fd_a, "MODE #ph +ph\r\n");
    try recvUntil(&a, "MODE #ph +ph", 200);
    // query reflects both flags.
    a.reset();
    try writeAllFd(fd_a, "MODE #ph\r\n");
    try recvUntil(&a, " 324 A #ph +ph", 200);
    // +t topic-ops flag is echoed in RPL_CHANNELMODEIS too (item 31).
    try writeAllFd(fd_a, "MODE #ph +t\r\n");
    try recvUntil(&a, "MODE #ph +t", 200);
    a.reset();
    try writeAllFd(fd_a, "MODE #ph\r\n");
    try recvUntil(&a, " 324 A #ph +t", 200);
    // hidden channel is omitted from LIST.
    a.reset();
    try writeAllFd(fd_a, "LIST\r\n");
    try recvUntil(&a, " 323 ", 200); // RPL_LISTEND arrives; #ph hidden
}

test "threaded server: CREATE makes founder channel" {
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
    a.reset();
    try writeAllFd(fd_a, "CREATE #cr\r\n");
    try recvUntil(&a, " 366 A #cr ", 200);
    try recvUntil(&a, "~A", 200);
}

test "threaded server: HELP topic + unknown" {
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
    a.reset();
    try writeAllFd(fd_a, "HELP JOIN\r\n");
    try recvUntil(&a, " 704 A JOIN ", 200);
    try recvUntil(&a, " 706 A JOIN ", 200);
    a.reset();
    try writeAllFd(fd_a, "HELP NOPE\r\n");
    try recvUntil(&a, " 524 A NOPE ", 200);
}

test "threaded server: SILENCE add/list/remove" {
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

    a.reset();
    try writeAllFd(fd_a, "SILENCE +B!*@*\r\n");
    try recvUntil(&a, "SILENCE +B!*@*\r\n", 200);
    a.reset();
    try writeAllFd(fd_a, "SILENCE\r\n");
    try recvUntil(&a, " 271 A B!*@*", 200);
    try recvUntil(&a, " 272 A ", 200);
    a.reset();
    try writeAllFd(fd_a, "SILENCE -B!*@*\r\n");
    try recvUntil(&a, "SILENCE -B!*@*\r\n", 200);
}

test "threaded server: CHATHISTORY records + replays channel messages" {
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
    try writeAllFd(fd_a, "JOIN #h\r\n");
    try recvUntil(&a, " 366 A #h ", 200);
    try writeAllFd(fd_b, "JOIN #h\r\n");
    try recvUntil(&b, " 366 B #h ", 200);

    // B sends two channel messages (recorded into the CHATHISTORY ring).
    a.reset();
    try writeAllFd(fd_b, "PRIVMSG #h :msg-one\r\n");
    try recvUntil(&a, "PRIVMSG #h :msg-one", 200);
    try writeAllFd(fd_b, "PRIVMSG #h :msg-two\r\n");
    try recvUntil(&a, "PRIVMSG #h :msg-two", 200);

    // A replays: BATCH-wrapped history with both messages.
    a.reset();
    try writeAllFd(fd_a, "CHATHISTORY LATEST #h * 10\r\n");
    try recvUntil(&a, "BATCH +1 chathistory #h", 200);
    try recvUntil(&a, ":B!bob@localhost PRIVMSG #h :msg-one", 200);
    try recvUntil(&a, ":B!bob@localhost PRIVMSG #h :msg-two", 200);
    try recvUntil(&a, "BATCH -1", 200);
}

test "threaded server: MARKREAD set then get" {
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

    // SET advances the marker and echoes it.
    a.reset();
    try writeAllFd(fd_a, "MARKREAD #c timestamp=2026-06-04T12:00:00.000Z\r\n");
    try recvUntil(&a, "MARKREAD #c timestamp=2026-06-04T12:00:00.000Z\r\n", 200);
    // GET returns the stored marker.
    a.reset();
    try writeAllFd(fd_a, "MARKREAD #c\r\n");
    try recvUntil(&a, "MARKREAD #c timestamp=2026-06-04T12:00:00.000Z\r\n", 200);
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

test "threaded server: live S2S listener completes a peer handshake" {
    // Non-default mesh identity exercises the config-driven SID/node id path.
    var server = Server.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0, .s2s_port = 0, .node_id = 42 }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const s2s_port = server.s2sBoundPort() catch return error.SkipZigTest;
    var run = std.atomic.Value(bool).init(true);
    var thr = try std.Thread.spawn(.{}, Server.runThreaded, .{ &server, &run });
    defer {
        run.store(false, .release);
        if (connectLoopback(server.boundPort() catch 0)) |wfd| closeFd(wfd) else |_| {}
        thr.join();
    }

    // Connect to the S2S port as a remote peer and drive a real S2sLink over the
    // socket until our side reports the link established.
    const fd = connectLoopback(s2s_port) catch return error.SkipZigTest;
    defer closeFd(fd);

    const alloc = std.testing.allocator;
    const peer = try alloc.create(s2s_link.S2sLink);
    defer alloc.destroy(peer);
    try peer.init(.{
        .allocator = alloc,
        .local_node_id = 2,
        .remote_node_id = 1,
        .local_epoch_ms = 2000,
        .server_name = "peer.test",
    });
    defer peer.deinit();

    var now: u64 = 1;
    // The connecting side opens the handshake.
    try peer.start(now);
    if (peer.outbound().len != 0) {
        try writeAllFd(fd, peer.outbound());
        peer.clearOutbound();
    }

    var rx: [4096]u8 = undefined;
    var polls: usize = 0;
    while (polls < 200 and !peer.established()) : (polls += 1) {
        var fds = [_]posix.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        const ready = posix.poll(&fds, 25) catch return error.Unexpected;
        if (ready == 0) continue;
        if ((fds[0].revents & linux.POLL.IN) == 0) continue;
        const n = try readFd(fd, &rx);
        if (n == 0) return error.ConnectionReset;
        now += 1;
        try peer.feed(rx[0..n], now, 5);
        if (peer.outbound().len != 0) {
            try writeAllFd(fd, peer.outbound());
            peer.clearOutbound();
        }
    }
    try std.testing.expect(peer.established());
    try std.testing.expect(peer.knownServers() >= 2);

    // A local client's LINKS now reflects the established S2S peer by its name.
    const fd_c = connectLoopback(server.boundPort() catch 0) catch return error.SkipZigTest;
    defer closeFd(fd_c);
    var c = LiveClient{ .fd = fd_c };
    try writeAllFd(fd_c, "NICK C\r\nUSER carol 0 * :Carol\r\n");
    try recvUntil(&c, " 001 C ", 200);
    c.reset();
    try writeAllFd(fd_c, "LINKS\r\n");
    try recvUntil(&c, " 365 ", 200);
    try std.testing.expect(std.mem.indexOf(u8, c.written(), "peer.test") != null);
}

test "threaded server: oper CONNECT opens an outbound S2S link" {
    // A test-owned listener stands in for the remote peer; the server dials it.
    const listen_fd = createListener("127.0.0.1", 0, 8) catch return error.SkipZigTest;
    defer closeFd(listen_fd);
    const remote_port = socketPort(listen_fd) catch return error.SkipZigTest;

    var server = Server.init(std.testing.allocator, operTestConfig(0)) catch |err| switch (err) {
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

    // Oper client SASL-authenticates as the admin oper account, then CONNECTs.
    const fd_a = connectLoopback(port) catch return error.SkipZigTest;
    defer closeFd(fd_a);
    var a = LiveClient{ .fd = fd_a };
    try saslAdminPrelude(fd_a);
    try writeAllFd(fd_a, "NICK A\r\nUSER alice 0 * :Alice\r\n");
    try recvUntil(&a, " 001 A ", 200);
    try recvUntil(&a, " 381 A ", 200); // auto-elevated on SASL login
    var cmd_buf: [64]u8 = undefined;
    const cmd = try std.fmt.bufPrint(&cmd_buf, "CONNECT 127.0.0.1 {d}\r\n", .{remote_port});
    try writeAllFd(fd_a, cmd);

    // Accept the server's outbound connection on the test listener.
    var poll_listen = [_]posix.pollfd{.{ .fd = listen_fd, .events = linux.POLL.IN, .revents = 0 }};
    var waited: usize = 0;
    while (waited < 200) : (waited += 1) {
        const r = posix.poll(&poll_listen, 25) catch return error.Unexpected;
        if (r != 0 and (poll_listen[0].revents & linux.POLL.IN) != 0) break;
    }
    const accept_rc = linux.accept4(listen_fd, null, null, 0);
    const peer_fd: linux.fd_t = switch (posix.errno(accept_rc)) {
        .SUCCESS => @intCast(accept_rc),
        else => return error.SkipZigTest,
    };
    defer closeFd(peer_fd);

    // Drive a responding S2sLink (no start — the server opened the handshake).
    const alloc = std.testing.allocator;
    const peer = try alloc.create(s2s_link.S2sLink);
    defer alloc.destroy(peer);
    try peer.init(.{
        .allocator = alloc,
        .local_node_id = 2,
        .remote_node_id = 1,
        .local_epoch_ms = 3000,
        .server_name = "remote.test",
    });
    defer peer.deinit();

    var rx: [4096]u8 = undefined;
    var now: u64 = 1;
    var polls: usize = 0;
    while (polls < 200 and !peer.established()) : (polls += 1) {
        var fds = [_]posix.pollfd{.{ .fd = peer_fd, .events = linux.POLL.IN, .revents = 0 }};
        const ready = posix.poll(&fds, 25) catch return error.Unexpected;
        if (ready == 0) continue;
        if ((fds[0].revents & linux.POLL.IN) == 0) continue;
        const n = try readFd(peer_fd, &rx);
        if (n == 0) return error.ConnectionReset;
        now += 1;
        try peer.feed(rx[0..n], now, 3);
        if (peer.outbound().len != 0) {
            try writeAllFd(peer_fd, peer.outbound());
            peer.clearOutbound();
        }
    }
    try std.testing.expect(peer.established());
    try std.testing.expect(peer.knownServers() >= 2);

    // Deterministic readiness gate (no timing race): LINKS is idempotent and only
    // lists ESTABLISHED, handshake-NAMED peers. Poll it until 'remote.test'
    // appears — that is the observable signal the server learned the peer — THEN
    // SQUIT exactly once and require success. (Protocol convergence itself is
    // proven by the deterministic byte-loopback tests; this is the socket/reactor
    // integration smoke test, made non-flaky by gating on observable readiness.)
    var learned = false;
    var probes: usize = 0;
    while (probes < 60 and !learned) : (probes += 1) {
        a.reset();
        try writeAllFd(fd_a, "LINKS\r\n");
        recvUntil(&a, " 365 ", 80) catch {};
        if (std.mem.indexOf(u8, a.written(), "remote.test") != null) learned = true;
    }
    try std.testing.expect(learned);
    a.reset();
    try writeAllFd(fd_a, "SQUIT remote.test\r\n");
    try recvUntil(&a, "SQUIT complete", 200);
}

test {
    std.testing.refAllDecls(@This());
}
