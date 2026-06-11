//! Client command dispatch and preregistration pipeline.
//!
//! Transport code feeds already parsed IRC lines into this module. Dispatch
//! runs preregistration middleware, enforces command arity, calls typed
//! handlers, and writes replies into caller-owned storage for deterministic
//! tests and reactor integration.
const std = @import("std");
const sasl = @import("../proto/sasl.zig");
const sasl_mechrouter = @import("../proto/sasl_mechrouter.zig");
const scram_server = @import("../proto/sasl_scram_server.zig");
const usermode = @import("../proto/usermode.zig");
const protocol_inventory = @import("../proto/protocol_inventory.zig");
const sts_policy = @import("../proto/sts_policy.zig");
const event_spine = @import("event_spine.zig");
const oper = @import("oper.zig");
const session_snapshot = @import("helix/session_snapshot.zig");
const labeled_response = @import("../proto/labeled_response.zig");
const msgid = @import("../proto/msgid.zig");

pub const UserMode = usermode.UserMode;

pub const DispatchError = error{
    ControlByte,
    OutputTooSmall,
    TextTooLong,
};

const SERVER_NAME = "orochi.local";
const NETWORK_NAME = protocol_inventory.network_name;
const MAX_PARAMS: usize = 15;
const MAX_NICK_BYTES: usize = 64;
const MAX_UID_BYTES: usize = 16;
const MAX_REALNAME_BYTES: usize = 256;
const MAX_ACCOUNT_BYTES: usize = 64;
const MAX_CLASS_BYTES: usize = 32;
const MAX_OPER_TITLE_BYTES: usize = 64;
const MAX_AWAY_BYTES: usize = 256;
const MAX_HOST_BYTES: usize = 255;

/// ISUPPORT CHANMODES token. Every advertised letter MUST be enforced by the
/// channel-MODE handler (see `server.zig` handleChannelMode); this is the single
/// source of truth shared by the welcome burst and the honesty test below.
///   A (list, always param):   b e I Z   (ban, exempt, invex, MUTE quiet)
///   B (param to set/unset):   k         (key)
///   C (param to set only):    l f j     (limit, forward target, join throttle)
///   D (flag, never param):    i m n s t C T N M S g
/// `f`/`j`/`Z` live in the world layer (per-channel storage) rather than the
/// compact `chanmode.ChannelMode` enum, but are fully parsed and enforced.
/// Sourced from the shared protocol inventory (single source of truth).
pub const CHANMODES_TOKEN = protocol_inventory.chanmodes_token;

/// Max bytes retained for a captured `@label` value (post-unescape). Matches
/// the framing helper's `labeled_response.MAX_LABEL_LEN`; longer labels are
/// dropped (treated as no label) rather than truncated.
const MAX_LABEL_BYTES: usize = labeled_response.MAX_LABEL_LEN;

/// Parsed IRC line view. Slices borrow from the caller-owned input buffer,
/// except `label_store` which owns the unescaped inbound `@label` value.
pub const LineView = struct {
    command: []const u8,
    params: [MAX_PARAMS][]const u8 = [_][]const u8{""} ** MAX_PARAMS,
    param_count: usize = 0,
    /// Unescaped `@label=<x>` tag value captured from the client, or null.
    /// Backed by `label_store`; never borrows from the input buffer because the
    /// wire form may be escaped (e.g. `\s`, `\:`).
    label_store: [MAX_LABEL_BYTES]u8 = undefined,
    label_len: usize = 0,
    has_label: bool = false,

    pub fn paramSlice(self: *const LineView) []const []const u8 {
        return self.params[0..self.param_count];
    }

    /// The captured inbound label, or null when the client sent none.
    pub fn label(self: *const LineView) ?[]const u8 {
        if (!self.has_label) return null;
        return self.label_store[0..self.label_len];
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

    // IRCv3 message tags: a leading `@tags` segment terminated by a space.
    var captured_label: ?[]const u8 = null;
    var label_buf: [MAX_LABEL_BYTES]u8 = undefined;
    if (body[cursor] == '@') {
        const tags_end = findSpace(body, cursor) orelse return error.MissingCommand;
        captured_label = captureLabel(body[cursor + 1 .. tags_end], &label_buf);
        cursor = skipSpaces(body, tags_end);
        if (cursor >= body.len) return error.MissingCommand;
    }

    if (body[cursor] == ':') {
        cursor = skipSpaces(body, findSpace(body, cursor) orelse return error.MissingCommand);
    }

    const command_end = findSpace(body, cursor) orelse body.len;
    if (command_end == cursor) return error.MissingCommand;
    var line = LineView{ .command = body[cursor..command_end] };
    if (captured_label) |value| {
        @memcpy(line.label_store[0..value.len], value);
        line.label_len = value.len;
        line.has_label = true;
    }
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
    account_tag,
    orochi_bouncer,
    chghost,
    no_implicit_names,
    chathistory,
    message_redaction,
    message_editing,
    read_marker,
    typing,
    react,
    reply,
    batch,
    bot,
    channel_rename,
    extended_monitor,
    account_registration,
    metadata_2,
    standard_replies,
    cap_notify,
    labeled_response,
    pre_away,
    channel_context,
    multiline,
    sts,
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
    /// When set, the cap is omitted from CAP LS unless the session supplies a
    /// runtime policy value (see `StsPolicy`). This keeps honesty-gated caps
    /// like `sts` absent from the default build, where no policy is configured.
    requires_policy: bool = false,
};

const cap_specs = [_]CapSpec{
    .{ .id = .server_time, .name = "server-time" },
    .{ .id = .message_tags, .name = "message-tags" },
    .{ .id = .echo_message, .name = "echo-message" },
    // handleAuthenticate routes PLAIN, SCRAM-SHA-256, and EXTERNAL through the
    // mechrouter. The live server injects each checker from the account store
    // (PLAIN via PBKDF2, SCRAM-SHA-256 via the mirrored credential store + a
    // per-connection nonce, EXTERNAL via the account ⇄ certfp bindings over the
    // mutual-TLS client cert). Each fails closed when unconfigured, exactly like
    // PLAIN always has, so advertising all three never strands a client.
    .{ .id = .sasl, .name = "sasl", .value_302 = "PLAIN,EXTERNAL,SCRAM-SHA-256" },
    .{ .id = .multi_prefix, .name = "multi-prefix" },
    .{ .id = .userhost_in_names, .name = "userhost-in-names" },
    .{ .id = .away_notify, .name = "away-notify" },
    .{ .id = .setname, .name = "setname" },
    .{ .id = .extended_join, .name = "extended-join" },
    .{ .id = .invite_notify, .name = "invite-notify" },
    .{ .id = .account_tag, .name = "account-tag" },
    // orochi/bouncer: opt-in to automatic rewind (replay of missed channel
    // history on (re)join, bounded by the client's read marker). Multi-session
    // reclaim (SESSION RESUME) works without it; this only enables auto-replay.
    .{ .id = .orochi_bouncer, .name = "orochi/bouncer" },
    // chghost: receive a native CHGHOST line when a common user's host changes
    // (VHOST). Clients without it see the new host on the user's next message.
    .{ .id = .chghost, .name = "chghost" },
    // no-implicit-names: a capable client suppresses the automatic NAMES burst
    // sent on JOIN (it can still issue NAMES explicitly).
    .{ .id = .no_implicit_names, .name = "no-implicit-names" },
    // The following expose already-live command/relay paths to clients that
    // negotiate them. Each is backed by a verified handler or the client-only
    // message-tag relay, so advertising them cannot strand a client:
    //   draft/chathistory     -> CHATHISTORY command (emits a `chathistory` BATCH)
    //   draft/message-redaction -> REDACT command
    //   draft/message-editing -> EDIT command
    //   draft/read-marker     -> MARKREAD command
    //   draft/typing/react/reply -> relayed as client-only tags on TAGMSG
    //   batch                 -> server emits BATCH (chathistory, netsplit)
    //   bot                   -> +B bot flag surfaced in WHOIS (335)
    .{ .id = .chathistory, .name = "draft/chathistory" },
    .{ .id = .message_redaction, .name = "draft/message-redaction" },
    .{ .id = .message_editing, .name = "draft/message-editing" },
    .{ .id = .read_marker, .name = "draft/read-marker" },
    .{ .id = .typing, .name = "draft/typing" },
    .{ .id = .react, .name = "draft/react" },
    .{ .id = .reply, .name = "draft/reply" },
    .{ .id = .batch, .name = "batch" },
    .{ .id = .bot, .name = "bot" },
    // channel-rename: receive a native RENAME line when a common channel is
    // renamed; clients without it get a PART(old)+JOIN(new) fallback.
    .{ .id = .channel_rename, .name = "draft/channel-rename" },
    // extended-monitor: receive AWAY/SETNAME/CHGHOST/ACCOUNT changes for
    // MONITOR'd nicks even without a shared channel.
    .{ .id = .extended_monitor, .name = "extended-monitor" },
    // account-notify: receive an ACCOUNT line when a user in a common channel
    // logs in (IDENTIFY) or out (LOGOUT). The server emits these at the live
    // login/logout sites.
    .{ .id = .account_notify, .name = "account-notify" },
    // account-registration: REGISTER/VERIFY are live; advertising lets compliant
    // clients surface nick/account registration.
    .{ .id = .account_registration, .name = "draft/account-registration" },
    // metadata-2: METADATA GET/SET/LIST/CLEAR + RPL_KEYVALUE(761)/762/766 are live.
    .{ .id = .metadata_2, .name = "draft/metadata-2" },
    // standard-replies: FAIL/WARN/NOTE are emitted across the command surface.
    .{ .id = .standard_replies, .name = "standard-replies" },
    // cap-notify: the cap set is static, so CAP NEW/DEL never fire, but advertising
    // signals support and is required before some clients enable other caps.
    .{ .id = .cap_notify, .name = "cap-notify" },
    // labeled-response: when a client tags a command with @label=<x>, the
    // server echoes @label=<x> on the response (a single tagged line, a
    // labeled-response BATCH for multi-line replies, or a bare labeled ACK for
    // commands that emit nothing). Framing lives in proto/labeled_response.zig.
    .{ .id = .labeled_response, .name = "labeled-response" },
    // pre-away: a negotiating client may send AWAY during the registration
    // handshake (before the welcome burst). The away state is applied
    // immediately so the user is already marked away when registration
    // completes. Handled in processLiveLine's pre-registration branch.
    .{ .id = .pre_away, .name = "draft/pre-away" },
    // channel-context: a client-only `+draft/channel-context=<chan>` tag on a
    // direct message marks it as part of a channel's context. Carried by the
    // generic client-tag relay (mergeTags), so advertising is all that's needed.
    .{ .id = .channel_context, .name = "draft/channel-context" },
    // multiline: the server accepts an inbound `BATCH +ref draft/multiline`
    // (PRIVMSG/NOTICE chunks), reassembles it, and delivers the result. Limits
    // are advertised as the cap value and enforced by the per-conn assembler.
    .{ .id = .multiline, .name = "draft/multiline", .value_302 = "max-bytes=4096,max-lines=24" },
    // sts (Strict Transport Security): the modern, config-gated replacement for
    // STARTTLS (which this daemon deliberately never implements). The value is
    // NOT static: it is the wire policy ("duration=<s>,port=<p>[,preload]")
    // produced from operator config and supplied per-session at LS time. With
    // `requires_policy`, the cap is OMITTED entirely until a policy is present,
    // so a default build that has not enabled STS advertises nothing -- never
    // stranding a client by promising TLS that no listener serves.
    .{ .id = .sts, .name = "sts", .requires_policy = true },
};

/// Per-session STS advertisement policy.
///
/// DEFAULT OFF: a freshly initialized session has `enabled == false`, so the
/// `sts` cap is never advertised. An operator enables STS exactly once, after a
/// TLS listener is live, by building this from config and storing it on the
/// session's CAP layer before LS is answered.
///
/// Config wiring point (owned by config_*.zig / server.zig, not this file):
///   1. Parse the `[sts]` config fragment with `sts_policy.parseConfig`.
///   2. Build the wire value with `sts_policy.writeCapValue(policy, .combined, ..)`.
///   3. Call `ClientSession.enableSts(value)` so LS emits `sts=<value>`.
/// Until step 3 runs the default-off invariant holds.
pub const StsPolicy = struct {
    /// Whether STS is advertised at all. Stays false on the default path.
    enabled: bool = false,
    /// Backing storage for the formatted wire value (no protocol-path alloc).
    value_buf: [sts_policy.MAX_CAP_VALUE_LEN]u8 = undefined,
    value_len: usize = 0,

    /// The wire value (without the `sts=` name), or null when disabled.
    pub fn value(self: *const StsPolicy) ?[]const u8 {
        if (!self.enabled) return null;
        return self.value_buf[0..self.value_len];
    }
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
    /// STS advertisement policy. Default-constructed = disabled (see StsPolicy).
    sts: StsPolicy = .{},

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
            try emitCapLs(self.cap_302, self.sts.value(), sink);
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

/// Emit CAP LS, chunked across multiple `CAP * LS *` continuation lines when the
/// advertised set no longer fits one IRC message. Every chunk but the last is
/// flagged as a continuation (gets the trailing `*` parameter); the final chunk
/// closes the list. A space is left for the `:<server> CAP <nick> LS * :` framing
/// so each emitted line stays under the 512-byte wire limit.
fn emitCapLs(cap_302: bool, sts_value: ?[]const u8, sink: *CapReplySink) DispatchError!void {
    const seg_max: usize = 400;
    var seg: [seg_max]u8 = undefined;
    var len: usize = 0;
    for (cap_specs) |spec| {
        // Policy-gated caps (sts) are omitted entirely until the session
        // supplies a runtime value. This is the default-off honesty guard:
        // no policy -> the cap never reaches CAP LS.
        const policy_value: ?[]const u8 = if (spec.requires_policy) sts_value else null;
        if (spec.requires_policy and policy_value == null) continue;

        // 302 clients see values; bare LS suppresses them. A policy-gated cap's
        // value is the policy itself, surfaced regardless of 302 since its
        // presence is already the operator's explicit, actionable signal.
        const static_value = if (cap_302) spec.value_302 else null;
        const value = policy_value orelse static_value;
        const value_len: usize = if (value) |v| 1 + v.len else 0;
        const space_len: usize = if (len == 0) 0 else 1;
        if (len + space_len + spec.name.len + value_len > seg.len) {
            // The current chunk is full and at least one more cap follows, so it
            // is a continuation. Flush it and start a fresh chunk.
            try sink.append(.ls, true, seg[0..len]);
            len = 0;
        }
        if (len != 0) {
            seg[len] = ' ';
            len += 1;
        }
        @memcpy(seg[len .. len + spec.name.len], spec.name);
        len += spec.name.len;
        if (value) |v| {
            seg[len] = '=';
            len += 1;
            @memcpy(seg[len .. len + v.len], v);
            len += v.len;
        }
    }
    // Final chunk closes the list (also covers the empty-set case).
    try sink.append(.ls, false, seg[0..len]);
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

/// Scan a `key=value;key2=value2` tag segment for `label`, unescaping its value
/// into `out` per the IRCv3 message-tags value escape rules. Returns the
/// unescaped label slice, or null when absent, empty, or too long to retain.
fn captureLabel(tags: []const u8, out: []u8) ?[]const u8 {
    var cursor: usize = 0;
    while (cursor < tags.len) {
        const seg_end = std.mem.indexOfScalarPos(u8, tags, cursor, ';') orelse tags.len;
        const item = tags[cursor..seg_end];
        const eq = std.mem.indexOfScalar(u8, item, '=');
        const key = if (eq) |i| item[0..i] else item;
        if (std.mem.eql(u8, key, "label")) {
            const raw = if (eq) |i| item[i + 1 ..] else "";
            return unescapeTagValue(raw, out);
        }
        cursor = if (seg_end < tags.len) seg_end + 1 else tags.len;
    }
    return null;
}

/// Unescape an IRCv3 tag value (`\:`->`;`, `\s`->space, `\\`->`\`, `\r`, `\n`)
/// into `out`. Returns null if the result is empty or would exceed `out`.
fn unescapeTagValue(raw: []const u8, out: []u8) ?[]const u8 {
    var len: usize = 0;
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        var ch = raw[i];
        if (ch == '\\' and i + 1 < raw.len) {
            i += 1;
            ch = switch (raw[i]) {
                ':' => ';',
                's' => ' ',
                'r' => '\r',
                'n' => '\n',
                '\\' => '\\',
                else => raw[i],
            };
        } else if (ch == '\\') {
            // Trailing lone backslash: dropped per the spec.
            break;
        }
        if (len >= out.len) return null;
        out[len] = ch;
        len += 1;
    }
    if (len == 0) return null;
    return out[0..len];
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
    /// Injected EXTERNAL verifier (account ←→ TLS certfp). Null fails closed.
    sasl_external: ?sasl_mechrouter.ExternalLookup = null,
    /// Injected SCRAM-SHA-256 credential lookup. Null fails closed.
    sasl_scram256: ?sasl_mechrouter.Scram256Lookup = null,
    /// Per-session SASL mechanism router. Lazily initialized on the first
    /// AUTHENTICATE <mech> line so the heavy fixed buffers cost nothing for
    /// connections that never authenticate. Reset to null on abort/failure so a
    /// re-auth always starts from a clean exchange.
    sasl_router: ?sasl_mechrouter.Router = null,
    /// Hex-encoded TLS client-certificate fingerprint, set at accept when the
    /// connection presents a client cert. Drives SASL EXTERNAL; null = no cert.
    tls_certfp: ?[]const u8 = null,
    /// Server nonce for SCRAM challenges. Borrowed for the router's lifetime; the
    /// live server points this at `sasl_server_nonce_buf` via setSaslServerNonce.
    sasl_server_nonce: []const u8 = "",
    /// Stable per-connection backing for `sasl_server_nonce` (hex CSPRNG output).
    sasl_server_nonce_buf: [32]u8 = undefined,
    account_store: FixedString(MAX_ACCOUNT_BYTES) = .{},
    logged_in: bool = false,

    /// Real peer host/IP captured at accept (never shown to other users once a
    /// cloak/vhost is set). `host_store` is the *visible* host: the auto-cloak of
    /// the real host, or a VHOST/CHGHOST override. An empty visible host falls
    /// back to the real host, and an empty real host falls back to the caller's
    /// default at the prefix-building site.
    real_host_store: FixedString(MAX_HOST_BYTES) = .{},
    host_store: FixedString(MAX_HOST_BYTES) = .{},

    /// AWAY state (RFC 1459 / IRCv3 away-notify). `away_active` gates whether
    /// `away_store` holds a live message; cleared by a parameterless AWAY.
    away_store: FixedString(MAX_AWAY_BYTES) = .{},
    away_active: bool = false,
    /// Set once the client completes a successful OPER. Gates oper-only commands
    /// (WALLOPS, REHASH, KILL, ...) and the RPL_WHOISOPERATOR line.
    is_oper: bool = false,
    /// The granted operator privilege set + class name, captured at elevation.
    /// Empty for non-opers. Handlers gate sensitive actions on specific
    /// privileges via `hasPriv`; the registry still gates the coarse oper flag.
    oper_priv: oper.OperPrivileges = .{},
    oper_class_store: FixedString(MAX_CLASS_BYTES) = .{},
    /// Optional custom operator title (e.g. "Network Guardian"), shown in WHOIS.
    oper_title_store: FixedString(MAX_OPER_TITLE_BYTES) = .{},
    /// Quarantined by a Warden `quarantine` action: the client stays connected
    /// but may not JOIN channels or send PRIVMSG/NOTICE (network silence / SHUN).
    restricted: bool = false,
    /// User modes (+i invisible, +B bot, ...). Set via MODE on the own nick.
    umodes: usermode.UmodeSet = .{},
    /// IRCX Event Spine subscription mask. WALLOPS/SNOMASK/oper notices are
    /// delivered as typed events to sessions subscribed to the matching category
    /// (replacing the legacy +w umode). Opers are subscribed on OPER.
    event_mask: event_spine.CategoryMask = .{},

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

    /// Whether this operator holds a specific privilege. Non-opers never do.
    pub fn hasPriv(self: *const ClientSession, privilege: oper.Privilege) bool {
        return self.is_oper and self.oper_priv.has(privilege);
    }

    /// Whether this operator is a network administrator (server_admin).
    pub fn isAdmin(self: *const ClientSession) bool {
        return self.hasPriv(.server_admin);
    }

    /// The operator class name (empty for non-opers).
    pub fn operClass(self: *const ClientSession) []const u8 {
        return self.oper_class_store.slice();
    }

    /// The custom operator title, or empty when none is configured.
    pub fn operTitle(self: *const ClientSession) []const u8 {
        return self.oper_title_store.slice();
    }

    /// Record the operator grant captured at elevation.
    pub fn setOperGrant(self: *ClientSession, privileges: oper.OperPrivileges, class_name: []const u8, title: []const u8) void {
        self.is_oper = true;
        self.oper_priv = privileges;
        self.oper_class_store.set(class_name[0..@min(class_name.len, MAX_CLASS_BYTES)]) catch {};
        self.oper_title_store.set(title[0..@min(title.len, MAX_OPER_TITLE_BYTES)]) catch {};
    }

    /// Drop operator status. Because oper is SASL-account-derived, ending the
    /// account login that granted it must also revoke +o, the privilege set,
    /// class/title, and the oper-notice event subscriptions.
    pub fn clearOper(self: *ClientSession) void {
        self.is_oper = false;
        self.oper_priv = .{};
        self.oper_class_store = .{};
        self.oper_title_store = .{};
        self.event_mask = .{};
    }

    /// Whether the client is quarantined (Warden quarantine / SHUN): connected
    /// but barred from JOIN and PRIVMSG/NOTICE.
    pub fn isRestricted(self: *const ClientSession) bool {
        return self.restricted;
    }

    /// Set or clear the quarantine restriction.
    pub fn setRestricted(self: *ClientSession, on: bool) void {
        self.restricted = on;
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

    /// Whether the session is subscribed to an Event Spine category (oper notices).
    pub fn subscribesTo(self: *const ClientSession, category: event_spine.EventCategory) bool {
        return self.event_mask.contains(category);
    }

    /// Replace the session's Event Spine subscription mask.
    pub fn setEventMask(self: *ClientSession, mask: event_spine.CategoryMask) void {
        self.event_mask = mask;
    }

    /// Render active user modes as "+iB" into `out` (caller-owned, >= 16 bytes
    /// to hold '+', the derived 'o', and every catalog letter).
    pub fn umodeString(self: *const ClientSession, out: []u8) []const u8 {
        var n: usize = 0;
        if (n < out.len) {
            out[n] = '+';
            n += 1;
        }
        // +o operator: derived from is_oper (set by OPER, not client-settable).
        if (self.is_oper and n < out.len) {
            out[n] = 'o';
            n += 1;
        }
        // Catalog-driven so display always matches the parser's letters and
        // every settable mode (R/p/Q/H included) round-trips. The catalog is the
        // single source of truth for user-mode letters.
        for (usermode.default_specs) |spec| {
            if (self.umodes.contains(spec.mode) and n < out.len) {
                out[n] = spec.letter;
                n += 1;
            }
        }
        return out[0..n];
    }

    /// Authenticated account name, or null when not logged in (SASL).
    pub fn account(self: *const ClientSession) ?[]const u8 {
        return if (self.logged_in) self.account_store.slice() else null;
    }

    /// Mark the session logged in as `account` (callers should pass the canonical
    /// lowercased form). Truncates to the account-name capacity.
    pub fn loginAs(self: *ClientSession, account_name: []const u8) void {
        self.account_store.set(account_name) catch {
            // Over-capacity: store the prefix that fits rather than failing login.
            self.account_store.set(account_name[0..@min(account_name.len, MAX_ACCOUNT_BYTES)]) catch return;
        };
        self.logged_in = true;
    }

    pub fn logout(self: *ClientSession) void {
        self.logged_in = false;
        self.account_store.len = 0;
    }

    pub fn registered(self: ClientSession) bool {
        return self.registration.registered;
    }

    /// Capture this session's carry-over state for a Helix UPGRADE. The returned
    /// snapshot borrows the session's inline buffers (valid until the session is
    /// next mutated); callers serialize it immediately via session_snapshot.encode.
    pub fn snapshot(self: *const ClientSession) session_snapshot.Snapshot {
        return .{
            .nick = self.client.identity.nick.slice(),
            .realname = self.client.identity.realname.slice(),
            .account = self.account_store.slice(),
            .real_host = self.real_host_store.slice(),
            .host = self.host_store.slice(),
            .away = self.away_store.slice(),
            .logged_in = self.logged_in,
            .away_active = self.away_active,
            .is_oper = self.is_oper,
        };
    }

    /// Reconstruct a carried-over session from its snapshot (successor side). A
    /// restored session is registered by definition — only registered clients are
    /// snapshotted. Best-effort: a field that fails validation is left empty.
    pub fn restore(self: *ClientSession, snap: session_snapshot.Snapshot) void {
        self.client.identity.nick.set(snap.nick) catch {
            self.client.identity.nick.len = 0;
        };
        self.client.identity.realname.set(snap.realname) catch {
            self.client.identity.realname.len = 0;
        };
        self.real_host_store.set(snap.real_host) catch {
            self.real_host_store.len = 0;
        };
        self.host_store.set(snap.host) catch {
            self.host_store.len = 0;
        };
        if (snap.logged_in and snap.account.len > 0) self.loginAs(snap.account) else self.logout();
        if (snap.away_active) self.setAway(snap.away) else self.clearAway();
        self.is_oper = snap.is_oper;
        self.registration.registered = true;
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

    /// The client's *visible* host: the cloak/vhost if set, else the real host.
    /// Returns "" when neither is known (caller substitutes a default).
    pub fn host(self: *const ClientSession) []const u8 {
        const v = self.host_store.slice();
        if (v.len != 0) return v;
        return self.real_host_store.slice();
    }

    /// The client's real (uncloaked) host/IP, or "" if not captured. Oper-only
    /// surfaces (OPERSPY/WHOIS for opers) may show this.
    pub fn realHost(self: *const ClientSession) []const u8 {
        return self.real_host_store.slice();
    }

    /// Record the real peer host/IP (set once at accept). Truncates to capacity.
    pub fn setRealHost(self: *ClientSession, value: []const u8) void {
        self.real_host_store.set(value) catch {
            self.real_host_store.set(value[0..@min(value.len, MAX_HOST_BYTES)]) catch return;
        };
    }

    /// Set the visible host (auto-cloak result, or VHOST/CHGHOST override).
    pub fn setVisibleHost(self: *ClientSession, value: []const u8) void {
        self.host_store.set(value) catch {
            self.host_store.set(value[0..@min(value.len, MAX_HOST_BYTES)]) catch return;
        };
    }

    /// Whether this client negotiated `id` via CAP. Lets the message path apply
    /// per-recipient IRCv3 behavior (echo-message, extended-join, ...).
    pub fn hasCap(self: *const ClientSession, id: CapId) bool {
        return self.cap.negotiated.contains(id);
    }

    /// Force-enable a negotiated cap (used by the server's internal SASL grant
    /// and by tests; normal clients arrive here via CAP REQ).
    pub fn addCap(self: *ClientSession, id: CapId) void {
        self.cap.negotiated.add(id);
    }

    /// Point `sasl_server_nonce` at a stable per-connection copy of `nonce`
    /// (the server supplies fresh CSPRNG hex at accept). Truncated to the buffer.
    pub fn setSaslServerNonce(self: *ClientSession, nonce: []const u8) void {
        const n = @min(nonce.len, self.sasl_server_nonce_buf.len);
        @memcpy(self.sasl_server_nonce_buf[0..n], nonce[0..n]);
        self.sasl_server_nonce = self.sasl_server_nonce_buf[0..n];
    }

    /// Operator-facing STS enable: store the formatted wire value so the `sts`
    /// cap is advertised on the next CAP LS. This is the single flip that breaks
    /// the default-off invariant, and the server/config layer calls it only
    /// after a TLS listener is live. `wire_value` is the `sts=` value WITHOUT the
    /// name (e.g. "duration=2592000,port=6697"); build it with
    /// `sts_policy.writeCapValue(policy, .combined, ..)`.
    pub fn enableSts(self: *ClientSession, wire_value: []const u8) error{OutputTooSmall}!void {
        if (wire_value.len > self.cap.sts.value_buf.len) return error.OutputTooSmall;
        @memcpy(self.cap.sts.value_buf[0..wire_value.len], wire_value);
        self.cap.sts.value_len = wire_value.len;
        self.cap.sts.enabled = true;
    }

    /// Disable STS advertisement (policy removal / TLS listener taken down).
    pub fn disableSts(self: *ClientSession) void {
        self.cap.sts.enabled = false;
        self.cap.sts.value_len = 0;
    }
};

/// Caller-owned reply collector.
pub const ReplyCtx = struct {
    storage: []u8,
    used: usize = 0,
    server_name: []const u8 = SERVER_NAME,
    network_name: []const u8 = NETWORK_NAME,

    pub fn init(storage: []u8) ReplyCtx {
        // Pick up the configured network name (set once at boot) at runtime; the
        // field default stays comptime-known for struct initialization.
        return .{ .storage = storage, .network_name = protocol_inventory.currentNetworkName(), .server_name = protocol_inventory.currentServerName() };
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
///
/// When the client tagged the command with `@label=<x>` and negotiated the
/// `labeled-response` cap, every reply line this dispatch produces is reframed
/// under the label: a single tagged line, a `labeled-response` BATCH for
/// multi-line output, or a bare labeled ACK when the command emits nothing.
pub fn dispatchLine(
    session: *ClientSession,
    replies: *ReplyCtx,
    line: *const LineView,
) DispatchError!void {
    const active_label: ?[]const u8 = if (session.hasCap(.labeled_response)) line.label() else null;
    if (active_label) |label_value| {
        // Buffer the command's raw replies, then reframe under the label into
        // the caller's storage. The scratch must hold the un-framed lines.
        var scratch_buf: [LABELED_SCRATCH_BYTES]u8 = undefined;
        var scratch = ReplyCtx.init(&scratch_buf);
        scratch.server_name = replies.server_name;
        scratch.network_name = replies.network_name;
        try dispatchInner(session, &scratch, line);
        try emitLabeled(replies, label_value, scratch.written());
        return;
    }
    try dispatchInner(session, replies, line);
}

/// Scratch capacity for a single command's pre-framing reply bytes. Sized to
/// hold a full registration burst (the largest reply set produced here).
const LABELED_SCRATCH_BYTES: usize = 4096;

fn dispatchInner(
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

/// Reframe `raw` (zero or more CRLF-terminated reply lines) under `label` into
/// `out` using the labeled-response framing helper.
fn emitLabeled(out: *ReplyCtx, label: []const u8, raw: []const u8) DispatchError!void {
    var sink = ReplyCtxSink{ .ctx = out };
    var it = CrlfLineIterator{ .bytes = raw };
    labeled_response.emitIterator(&sink, label, LABELED_BATCH_REF, &it) catch
        return error.OutputTooSmall;
}

/// Batch reference used for labeled-response BATCH framing. Per-dispatch
/// uniqueness is not required by the spec since the open/close bracket the
/// label's own lines on a single connection.
const LABELED_BATCH_REF = "suzu-label";

/// Adapter exposing `ReplyCtx` as a labeled_response sink (`appendLine`).
const ReplyCtxSink = struct {
    ctx: *ReplyCtx,

    pub fn appendLine(self: *ReplyCtxSink, line: []const u8) DispatchError!void {
        try self.ctx.append(line);
    }
};

/// Iterates CRLF-terminated lines, yielding each line *including* its CRLF so
/// the framing helper sees complete wire lines.
const CrlfLineIterator = struct {
    bytes: []const u8,
    index: usize = 0,

    pub fn next(self: *CrlfLineIterator) ?[]const u8 {
        if (self.index >= self.bytes.len) return null;
        const rest = self.bytes[self.index..];
        const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse {
            // No terminator: yield the remainder as a final line.
            self.index = self.bytes.len;
            return rest;
        };
        const line = rest[0 .. nl + 1];
        self.index += nl + 1;
        return line;
    }
};

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
    // Enforce the configured NICKLEN (the pre-registration path reads it from the
    // boot-set runtime limits, since it has no server/config handle).
    if (nick.len > protocol_inventory.currentLimits().nicklen) {
        try ctx.replies.numeric(ctx.session, .ERR_ERRONEUSNICKNAME, &.{nick}, "Erroneous nickname (too long)");
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

    // Phase 1 — mechanism selection. No exchange is in progress, so this line
    // names the mechanism. Route the choice through the mechanism router; PLAIN,
    // EXTERNAL, and SCRAM-SHA-256 are all live (each fails closed if its checker
    // is not injected on this session).
    if (ctx.session.sasl_router == null) {
        if (std.mem.eql(u8, payload, "*")) {
            // Abort with no exchange in progress: nothing to tear down.
            ctx.session.client.registration.sasl = .failed;
            try ctx.replies.numeric(ctx.session, .ERR_SASLABORTED, &.{}, "SASL authentication aborted");
            return;
        }

        var router = sasl_mechrouter.Router.init(.{
            .plain = saslPlainAdapter(ctx.session),
            .external = ctx.session.sasl_external,
            .scram256 = ctx.session.sasl_scram256,
        }, ctx.session.sasl_server_nonce);
        router.tls_certfp = ctx.session.tls_certfp;

        switch (router.start(payload)) {
            .continue_ => |challenge| {
                // Starting a fresh exchange clears any prior login so a re-auth
                // can never leave logged_in set with a stale/failed account.
                ctx.session.logged_in = false;
                ctx.session.account_store.len = 0;
                ctx.session.sasl_pending = sasl.Mechanism.parse(payload);
                ctx.session.sasl_router = router;
                ctx.session.client.registration.sasl = .authenticating;
                try ctx.replies.message(null, "AUTHENTICATE", &.{challenge}, null);
                return;
            },
            .fail => return saslFail(ctx, "Unsupported SASL mechanism"),
            // start() only ever yields continue_/fail.
            .success => return saslFail(ctx, "SASL authentication failed"),
        }
    }

    // Phase 2+ — feed the response chunk into the in-progress exchange. The
    // router owns "*" abort, base64 decoding, and multi-step SCRAM challenges.
    var out_buf: [sasl_mechrouter.MAX_B64_MESSAGE]u8 = undefined;
    const outcome = ctx.session.sasl_router.?.receive(payload, &out_buf);
    switch (outcome) {
        .continue_ => |challenge| {
            // SCRAM emits a server-first challenge; await the client-final line.
            // A literal "+" / empty slice means "send empty and keep waiting".
            const reply = if (challenge.len == 0) "+" else challenge;
            try ctx.replies.message(null, "AUTHENTICATE", &.{reply}, null);
            return;
        },
        .fail => |failure| {
            ctx.session.sasl_router = null;
            ctx.session.sasl_pending = null;
            return switch (failure) {
                .aborted => saslAbort(ctx),
                else => saslFail(ctx, "SASL authentication failed"),
            };
        },
        .success => |result| {
            // `result.account` and `result.final_data` borrow from the router's
            // internal buffers, so copy everything out BEFORE clearing the router
            // (clearing the optional invalidates those slices).
            //
            // Store the CANONICAL (ASCII-lowercased) account name, matching how
            // the account store keys accounts (services.accountKey). Otherwise
            // account() would report the client's claimed casing ("Alice") while
            // authz uses the canonical form ("alice") — an identity mismatch.
            if (result.account.len > MAX_ACCOUNT_BYTES) return saslFail(ctx, "SASL authentication failed");
            var account_buf: [MAX_ACCOUNT_BYTES]u8 = undefined;
            const account = std.ascii.lowerString(account_buf[0..result.account.len], result.account);

            // SCRAM carries a server-final verifier the client checks before it
            // trusts the success; emit it as a final AUTHENTICATE before 900/903.
            // Copy it out of the router buffer before the router is cleared.
            var final_buf: [sasl_mechrouter.MAX_B64_MESSAGE]u8 = undefined;
            const final_copy: ?[]const u8 = if (result.final_data) |final| blk: {
                if (final.len > final_buf.len) break :blk null;
                @memcpy(final_buf[0..final.len], final);
                break :blk final_buf[0..final.len];
            } else null;

            ctx.session.sasl_router = null;
            ctx.session.sasl_pending = null;

            ctx.session.account_store.set(account) catch return saslFail(ctx, "SASL authentication failed");

            if (final_copy) |final| {
                const reply = if (final.len == 0) "+" else final;
                try ctx.replies.message(null, "AUTHENTICATE", &.{reply}, null);
            }

            ctx.session.logged_in = true;
            ctx.session.client.registration.sasl = .succeeded;
            try ctx.replies.numeric(ctx.session, .RPL_LOGGEDIN, &.{ ctx.session.displayName(), account }, "You are now logged in");
            try ctx.replies.numeric(ctx.session, .RPL_SASLSUCCESS, &.{}, "SASL authentication successful");
        },
    }
}

/// Adapt the session's bool-returning PLAIN checker to the router's
/// account-returning `PlainLookup`. Returns null when no PLAIN checker is
/// injected so PLAIN fails closed exactly as before.
fn saslPlainAdapter(session: *ClientSession) ?sasl_mechrouter.PlainLookup {
    if (session.sasl_plain == null) return null;
    return .{ .ptr = session, .verifyFn = saslPlainVerify };
}

/// `PlainLookup` shim: verify via the injected bool checker, then return the
/// authcid as the account name on success (the router copies it into its own
/// buffer, so borrowing from the decoded creds for the call is safe).
fn saslPlainVerify(ptr: *anyopaque, creds: sasl.PlainCredentials) ?[]const u8 {
    const session: *ClientSession = @ptrCast(@alignCast(ptr));
    const checker = session.sasl_plain orelse return null;
    if (!checker.verify(creds)) return null;
    return creds.authcid;
}

fn saslFail(ctx: DispatchCtx, message: []const u8) DispatchError!void {
    ctx.session.sasl_pending = null;
    ctx.session.sasl_router = null;
    ctx.session.logged_in = false;
    ctx.session.account_store.len = 0;
    ctx.session.client.registration.sasl = .failed;
    try ctx.replies.numeric(ctx.session, .ERR_SASLFAIL, &.{}, message);
}

fn saslAbort(ctx: DispatchCtx) DispatchError!void {
    ctx.session.sasl_pending = null;
    ctx.session.sasl_router = null;
    ctx.session.logged_in = false;
    ctx.session.account_store.len = 0;
    ctx.session.client.registration.sasl = .failed;
    try ctx.replies.numeric(ctx.session, .ERR_SASLABORTED, &.{}, "SASL authentication aborted");
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
    try replies.numeric(session, .RPL_WELCOME, &.{}, "Welcome to the Orochi IRC Network");
    var host_buf: [256]u8 = undefined;
    const host_line = std.fmt.bufPrint(&host_buf, "Your host is {s}, running Orochi", .{replies.server_name}) catch "Your host is this server, running Orochi";
    try replies.numeric(session, .RPL_YOURHOST, &.{}, host_line);
    try replies.numeric(session, .RPL_CREATED, &.{}, "This server is running Orochi");
    try replies.numeric(session, .RPL_MYINFO, &.{ replies.server_name, "orochi-0.1", "io", "ov" }, "are supported by this server");
    try replies.numeric(session, .RPL_ISUPPORT, protocol_inventory.currentIsupport(), "are supported by this server");
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

test "session snapshot -> encode -> decode -> restore round-trips" {
    var s = ClientSession.init();
    try s.setNick("alice");
    try s.setRealname("Alice Example");
    s.loginAs("alice");
    s.setRealHost("10.0.0.7");
    s.setVisibleHost("cloak-ab12.orochi");
    s.setAway("brb");
    s.is_oper = true;

    const allocator = std.testing.allocator;
    const bytes = try session_snapshot.encode(allocator, s.snapshot());
    defer allocator.free(bytes);
    const decoded = try session_snapshot.decode(bytes);

    var s2 = ClientSession.init();
    s2.restore(decoded);
    try std.testing.expectEqualStrings("alice", s2.displayName());
    try std.testing.expectEqualStrings("Alice Example", s2.client.identity.realname.slice());
    try std.testing.expect(s2.logged_in);
    try std.testing.expectEqualStrings("alice", s2.account().?);
    try std.testing.expectEqualStrings("10.0.0.7", s2.real_host_store.slice());
    try std.testing.expectEqualStrings("cloak-ab12.orochi", s2.host_store.slice());
    try std.testing.expectEqualStrings("brb", s2.awayMessage().?);
    try std.testing.expect(s2.isOper());
    try std.testing.expect(s2.registered());
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

    try dispatchText(&session, &replies, "USER kain 0 * :Kain Orochi");
    try std.testing.expect(session.registered());
    try expectCodesInOrder(replies.written(), &.{ " 001 ", " 002 ", " 003 ", " 004 ", " 005 " });
    // ISUPPORT advertises extended-ban support so clients enable $-typed bans.
    try expectContains(replies.written(), "EXTBAN=$,acgmrz");
    try expectContains(replies.written(), "CHANTYPES=#&");
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
    try dispatchText(&session, &replies, "USER kain 0 * :Kain Orochi");
    try std.testing.expect(!session.registered());
    try expectNotContains(replies.written(), " 001 ");

    try dispatchText(&session, &replies, "CAP END");
    try std.testing.expect(session.registered());
    try expectCodesInOrder(replies.written(), &.{ " 001 ", " 002 ", " 003 ", " 004 ", " 005 " });
}

test "default config never advertises the sts cap" {
    var session = ClientSession.init();
    var storage: [4096]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    // Honesty guard: a fresh session has STS disabled, so CAP LS (302 or bare)
    // must not promise TLS the default build does not serve.
    try dispatchText(&session, &replies, "CAP LS 302");
    try expectContains(replies.written(), " CAP * LS :");
    try expectNotContains(replies.written(), "sts=");
    try expectNotContains(replies.written(), " sts ");
    try expectNotContains(replies.written(), ":sts ");
    replies.clear();

    var bare = ClientSession.init();
    var bare_storage: [4096]u8 = undefined;
    var bare_replies = ReplyCtx.init(&bare_storage);
    try dispatchText(&bare, &bare_replies, "CAP LS");
    try expectNotContains(bare_replies.written(), "sts");
}

test "enabled sts policy advertises a well-formed value" {
    var session = ClientSession.init();
    var storage: [4096]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    // Operator wiring point: build the wire value from config, then flip it on.
    var value_buf: [sts_policy.MAX_CAP_VALUE_LEN]u8 = undefined;
    const policy = sts_policy.Policy{ .duration_seconds = 2_592_000, .port = 6697 };
    const wire = try sts_policy.writeCapValue(policy, .combined, &value_buf);
    try session.enableSts(wire);

    try dispatchText(&session, &replies, "CAP LS 302");
    try expectContains(replies.written(), "sts=duration=2592000,port=6697");

    // And the value parses back to the same policy (round-trip sanity).
    const parsed = try @import("../proto/sts.zig").parseValue(wire);
    try std.testing.expectEqual(@as(?u64, 2_592_000), parsed.duration_seconds);
    try std.testing.expectEqual(@as(?u16, 6697), parsed.port);

    // Disabling restores the default-off invariant.
    session.disableSts();
    replies.clear();
    try dispatchText(&session, &replies, "CAP LS 302");
    try expectNotContains(replies.written(), "sts=");
}

test "NICK rejects nicks longer than the configured NICKLEN" {
    protocol_inventory.setRuntimeLimits(.{ .nicklen = 8 });
    defer protocol_inventory.setRuntimeLimits(.{}); // restore default for other tests

    var session = ClientSession.init();
    var storage: [512]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    try dispatchText(&session, &replies, "NICK thisnickistoolong"); // 17 > 8
    try std.testing.expect(std.mem.indexOf(u8, replies.written(), " 432 ") != null);

    // A nick within the limit is accepted (no 432).
    replies.clear();
    try dispatchText(&session, &replies, "NICK shortn"); // 6 <= 8
    try std.testing.expect(std.mem.indexOf(u8, replies.written(), " 432 ") == null);
}

test "clearOper revokes operator status, privileges, and class" {
    var s = ClientSession.init();
    s.setOperGrant(oper.OperPrivileges.full, "netadmin", "Network Admin");
    try std.testing.expect(s.isOper());
    try std.testing.expect(s.hasPriv(.server_admin));
    try std.testing.expectEqualStrings("netadmin", s.operClass());

    s.clearOper();
    try std.testing.expect(!s.isOper());
    try std.testing.expect(!s.hasPriv(.server_admin));
    try std.testing.expectEqualStrings("", s.operClass());
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

test "ISUPPORT CHANMODES token is honest: every advertised letter is enforced" {
    const chanmode = @import("chanmode.zig");

    // The token must keep the four-class A,B,C,D shape.
    const eq = "CHANMODES=";
    try std.testing.expect(std.mem.startsWith(u8, CHANMODES_TOKEN, eq));
    const value = CHANMODES_TOKEN[eq.len..];
    var it = std.mem.splitScalar(u8, value, ',');
    const class_a = it.next().?;
    const class_b = it.next().?;
    const class_c = it.next().?;
    const class_d = it.next().?;
    try std.testing.expect(it.next() == null); // exactly four classes

    try std.testing.expectEqualStrings("beIZ", class_a);
    try std.testing.expectEqualStrings("k", class_b);
    try std.testing.expectEqualStrings("lfj", class_c);
    try std.testing.expectEqualStrings("imnstCTNMSgWOA", class_d);

    // Letters backed by the compact chanmode.ChannelMode enum must resolve in the
    // catalog with the matching protocol class.
    const enum_letters = "beIklimnstCTNMSgWOA";
    for (enum_letters) |letter| {
        const spec = chanmode.specFromLetter(letter) orelse {
            std.debug.print("CHANMODES advertises '{c}' but chanmode has no spec\n", .{letter});
            return error.TestUnexpectedResult;
        };
        try std.testing.expectEqual(letter, spec.letter);
    }

    // f, j, Z are enforced in the world layer (forward / throttle / quiet) and are
    // intentionally NOT in the compact enum, but are still real, handled modes.
    // Their absence from the enum must be deliberate, not an oversight.
    for ("fjZ") |letter| {
        try std.testing.expect(chanmode.specFromLetter(letter) == null);
    }

    // The advertisement must not leak any letter the handler does not enforce.
    // The full enforced set across both layers:
    const enforced = "beIZklfjimnstCTNMSgWOA";
    for (class_a) |c| try std.testing.expect(std.mem.indexOfScalar(u8, enforced, c) != null);
    for (class_b) |c| try std.testing.expect(std.mem.indexOfScalar(u8, enforced, c) != null);
    for (class_c) |c| try std.testing.expect(std.mem.indexOfScalar(u8, enforced, c) != null);
    for (class_d) |c| try std.testing.expect(std.mem.indexOfScalar(u8, enforced, c) != null);
}

test "parseLine captures and unescapes the @label tag value" {
    const line = try parseLine("@label=abc\\s123 PING :tok");
    try std.testing.expectEqualStrings("PING", line.command);
    try std.testing.expectEqualStrings("abc 123", line.label().?);
    try std.testing.expectEqualStrings("tok", line.paramSlice()[0]);
}

test "parseLine ignores other tags and reports no label when absent" {
    const line = try parseLine("@time=2026-06-08T00:00:00.000Z PING :tok");
    try std.testing.expectEqualStrings("PING", line.command);
    try std.testing.expect(line.label() == null);
}

test "labeled single-line reply echoes @label on the one line" {
    var session = ClientSession.init();
    session.addCap(.labeled_response);
    var storage: [512]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    try dispatchText(&session, &replies, "@label=ping-1 PING :tok");
    // Single line: tagged directly (no BATCH wrapper).
    try expectContains(replies.written(), "@label=ping-1 ");
    try expectContains(replies.written(), "PONG orochi.local :tok\r\n");
    try expectNotContains(replies.written(), "BATCH");
}

test "labeled multi-line reply is wrapped in a labeled-response BATCH" {
    var session = ClientSession.init();
    session.addCap(.labeled_response);
    var storage: [4096]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    // Drive registration so the final command emits the multi-numeric welcome
    // burst under one label -> BATCH framing.
    try dispatchText(&session, &replies, "NICK kain");
    replies.clear();
    try dispatchText(&session, &replies, "@label=reg-1 USER kain 0 * :Kain Orochi");
    try std.testing.expect(session.registered());

    const out = replies.written();
    try expectContains(out, "@label=reg-1 BATCH +");
    try expectContains(out, " labeled-response\r\n");
    try expectContains(out, "BATCH -");
    // Inner lines carry @batch=, not @label=.
    try expectContains(out, "@batch=");
}

test "labeled no-output command emits a bare labeled ACK" {
    var session = ClientSession.init();
    session.addCap(.labeled_response);
    var storage: [256]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    // PONG produces no reply; with a label this becomes an ACK.
    try dispatchText(&session, &replies, "@label=k1 PONG :tok");
    try std.testing.expectEqualStrings("@label=k1 ACK\r\n", replies.written());
}

test "label is ignored when the labeled-response cap is not negotiated" {
    var session = ClientSession.init();
    var storage: [256]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    try dispatchText(&session, &replies, "@label=ping-1 PING :tok");
    try expectNotContains(replies.written(), "@label=");
    try expectContains(replies.written(), "PONG orochi.local :tok\r\n");
}

const TestExternalChecker = struct {
    fn verify(_: *anyopaque, certfp: []const u8, authzid: []const u8) ?[]const u8 {
        if (!std.mem.eql(u8, certfp, "DEADBEEF")) return null;
        if (authzid.len != 0 and !std.mem.eql(u8, authzid, "alice")) return null;
        return "alice";
    }
};

test "sasl EXTERNAL logs in via matching certfp through the router" {
    var session = ClientSession.init();
    session.cap.negotiated.add(.sasl);
    var anchor: u8 = 0;
    session.sasl_external = .{ .ptr = &anchor, .verifyFn = TestExternalChecker.verify };
    session.tls_certfp = "DEADBEEF";

    var storage: [1024]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    try dispatchText(&session, &replies, "AUTHENTICATE EXTERNAL");
    try expectContains(replies.written(), "AUTHENTICATE +\r\n");

    // Empty authzid ("+") => use the certificate identity.
    replies.clear();
    try dispatchText(&session, &replies, "AUTHENTICATE +");
    try std.testing.expectEqualStrings("alice", session.account().?);
    try expectContains(replies.written(), " 900 ");
    try expectContains(replies.written(), " 903 ");
}

test "sasl EXTERNAL fails closed when no client certificate is present" {
    var session = ClientSession.init();
    session.cap.negotiated.add(.sasl);
    var anchor: u8 = 0;
    session.sasl_external = .{ .ptr = &anchor, .verifyFn = TestExternalChecker.verify };
    // No tls_certfp set: the mechanism must be unavailable per spec.

    var storage: [1024]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    try dispatchText(&session, &replies, "AUTHENTICATE EXTERNAL");
    try std.testing.expect(session.account() == null);
    try std.testing.expect(session.sasl_router == null);
    try expectContains(replies.written(), " 904 ");
}

const TestScramDb = struct {
    record: scram_server.Credential,

    fn lookup(ptr: *anyopaque, name: []const u8) ?scram_server.Credential {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        if (!std.mem.eql(u8, name, "user")) return null;
        return self.record;
    }
};

test "sasl SCRAM-SHA-256 full handshake through the router logs in" {
    const HmacSha256 = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256);
    const digest_len = std.crypto.hash.sha2.Sha256.digest_length;

    const salt = "saltSALTsalt";
    const iterations: u32 = 4096;
    const password = "pencil";

    var keys = try sasl.deriveScramKeys(password, salt, iterations);
    defer keys.wipe();
    var db = TestScramDb{ .record = .{
        .salt = salt,
        .iterations = iterations,
        .stored_key = keys.stored_key,
        .server_key = keys.server_key,
    } };

    var session = ClientSession.init();
    session.cap.negotiated.add(.sasl);
    session.sasl_scram256 = .{ .ptr = &db, .lookupFn = TestScramDb.lookup };
    session.sasl_server_nonce = "SERVERNONCE";

    var storage: [2048]u8 = undefined;
    var replies = ReplyCtx.init(&storage);

    // Mechanism selection.
    try dispatchText(&session, &replies, "AUTHENTICATE SCRAM-SHA-256");
    try expectContains(replies.written(), "AUTHENTICATE +\r\n");

    // client-first.
    var cf_b64: [128]u8 = undefined;
    const cf = std.base64.standard.Encoder.encode(&cf_b64, "n,,n=user,r=CLIENTNONCE");
    var line1: [256]u8 = undefined;
    replies.clear();
    try dispatchText(&session, &replies, try std.fmt.bufPrint(&line1, "AUTHENTICATE {s}", .{cf}));

    // Extract the server-first challenge the router emitted.
    const written1 = replies.written();
    const marker = "AUTHENTICATE ";
    const start = std.mem.indexOf(u8, written1, marker).? + marker.len;
    const end = std.mem.indexOfScalarPos(u8, written1, start, '\r').?;
    const server_first_b64 = written1[start..end];
    var server_first_raw: [sasl.MAX_SCRAM_MESSAGE]u8 = undefined;
    const sf_decoder = std.base64.standard.Decoder;
    const sf_len = try sf_decoder.calcSizeForSlice(server_first_b64);
    try sf_decoder.decode(server_first_raw[0..sf_len], server_first_b64);
    const server_first = server_first_raw[0..sf_len];
    const parsed_first = try scram_server.parseServerFirst(server_first);

    // Build the client-final with a correct proof.
    var without_proof_buf: [256]u8 = undefined;
    const without_proof = try std.fmt.bufPrint(&without_proof_buf, "c=biws,r={s}", .{parsed_first.nonce});
    var auth_message_buf: [768]u8 = undefined;
    const auth_message = try std.fmt.bufPrint(&auth_message_buf, "n=user,r=CLIENTNONCE,{s},{s}", .{ server_first, without_proof });
    var client_sig: [digest_len]u8 = undefined;
    HmacSha256.create(&client_sig, auth_message, &keys.stored_key);
    var proof: [digest_len]u8 = undefined;
    for (&proof, keys.client_key, client_sig) |*dst, ck, cs| dst.* = ck ^ cs;
    var proof_b64_buf: [std.base64.standard.Encoder.calcSize(digest_len)]u8 = undefined;
    const proof_b64 = std.base64.standard.Encoder.encode(&proof_b64_buf, &proof);
    var final_buf: [320]u8 = undefined;
    const client_final = try std.fmt.bufPrint(&final_buf, "{s},p={s}", .{ without_proof, proof_b64 });
    var final_b64_buf: [512]u8 = undefined;
    const final_b64 = std.base64.standard.Encoder.encode(&final_b64_buf, client_final);

    var line2: [640]u8 = undefined;
    replies.clear();
    try dispatchText(&session, &replies, try std.fmt.bufPrint(&line2, "AUTHENTICATE {s}", .{final_b64}));

    try std.testing.expectEqualStrings("user", session.account().?);
    try expectContains(replies.written(), " 900 ");
    try expectContains(replies.written(), " 903 ");

    // The router emits a base64 server-final (v=<verifier>) as an AUTHENTICATE
    // line before the 900/903; decode it and confirm it parses as a verifier.
    const written2 = replies.written();
    const m2 = "AUTHENTICATE ";
    const s2 = std.mem.indexOf(u8, written2, m2).? + m2.len;
    const e2 = std.mem.indexOfScalarPos(u8, written2, s2, '\r').?;
    var final_raw: [sasl.MAX_SCRAM_MESSAGE]u8 = undefined;
    const fd = std.base64.standard.Decoder;
    const fl = try fd.calcSizeForSlice(written2[s2..e2]);
    try fd.decode(final_raw[0..fl], written2[s2..e2]);
    _ = try scram_server.parseServerFinal(final_raw[0..fl]);
}

test "host accessor prefers visible host, falls back to real then empty" {
    var session = ClientSession.init();
    try std.testing.expectEqualStrings("", session.host()); // nothing captured yet
    session.setRealHost("203.0.113.7");
    try std.testing.expectEqualStrings("203.0.113.7", session.host()); // real fallback
    session.setVisibleHost("cloak-abcd.example");
    try std.testing.expectEqualStrings("cloak-abcd.example", session.host()); // cloak wins
    try std.testing.expectEqualStrings("203.0.113.7", session.realHost()); // real preserved
}

test "umodeString renders catalog letters for every settable mode, incl R/p/Q/H" {
    var session = ClientSession.init();
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("+", session.umodeString(&buf)); // none set

    // +o is derived from is_oper and leads the string.
    session.is_oper = true;
    _ = session.setUmode(.invisible, true);
    _ = session.setUmode(.regonly_pm, true); // R — was invisible in the old display
    _ = session.setUmode(.hide_chans, true); // p
    _ = session.setUmode(.no_forward, true); // Q
    _ = session.setUmode(.hide_oper, true); // H
    const s = session.umodeString(&buf);
    try std.testing.expect(std.mem.startsWith(u8, s, "+o"));
    inline for (.{ 'i', 'R', 'p', 'Q', 'H' }) |c| {
        try std.testing.expect(std.mem.indexOfScalar(u8, s, c) != null);
    }
    // Letters match the catalog/parser exactly: no_ctcp is C (not T).
    _ = session.setUmode(.no_ctcp, true);
    const s2 = session.umodeString(&buf);
    try std.testing.expect(std.mem.indexOfScalar(u8, s2, 'C') != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, s2, 'T') == null);
}
