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
const client_model = @import("client.zig");

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
            cursor = skipSpaces(body, findSpace(body, cursor) orelse return error.MissingCommand);
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
} || std.mem.Allocator.Error;

pub const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16,
    backlog: u31 = 128,
    ring_entries: u16 = 32,
    features: RingFeatureSet = RingFeatureSet.baseline,
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

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: Config,
    listener_fd: linux.fd_t,
    ring: RingCore,
    clients: ClientTable,
    accept_armed: bool = false,

    /// Create, bind, and listen on a TCP socket, then initialize the Ringlane
    /// ring used for accept/recv/send completions.
    pub fn init(allocator: std.mem.Allocator, config: Config) !Server {
        if (builtin.os.tag != .linux) return error.Unsupported;

        const listener_fd = try createListener(config.host, config.port, config.backlog);
        errdefer closeFd(listener_fd);

        var ring = RingCore.init(config.ring_entries, config.features) catch |err| {
            if (ringlane.isUnsupportedInitError(err)) return error.Unsupported;
            return err;
        };
        errdefer ring.deinit();

        return .{
            .allocator = allocator,
            .config = config,
            .listener_fd = listener_fd,
            .ring = ring,
            .clients = ClientTable.init(allocator, 0),
        };
    }

    pub fn deinit(self: *Server) void {
        for (self.clients.slots.items) |*slot| {
            if (slot.occupied) closeFd(slot.value.fd);
        }
        self.clients.deinit();
        self.ring.deinit();
        closeFd(self.listener_fd);
        self.* = undefined;
    }

    /// Arm the accept SQE if needed. Submission is batched by `runOnce`.
    pub fn armAccept(self: *Server) !void {
        if (self.accept_armed) return;
        try self.ring.submitAccept(listener_token, self.listener_fd);
        self.accept_armed = true;
    }

    /// Process at least one io_uring completion. Callers may loop this until
    /// their own stop condition is satisfied.
    pub fn runOnce(self: *Server) !void {
        try self.armAccept();
        _ = try self.ring.submitAndWait(1);

        var handler = CompletionHandler{ .server = self };
        var cqes: [ringlane.default_cqe_batch]linux.io_uring_cqe = undefined;
        _ = try self.ring.reapCompletions(&cqes, 0, &handler);
        if (handler.err) |err| return err;

        _ = try self.ring.submit();
    }

    pub fn boundPort(self: *Server) !u16 {
        return socketPort(self.listener_fd);
    }

    fn handleAccept(self: *Server, event: ringlane.AcceptEvent) !void {
        if (!event.more) self.accept_armed = false;
        if (event.res < 0) return error.BadCompletion;

        const fd: linux.fd_t = event.res;
        errdefer closeFd(fd);

        const id = try self.clients.alloc(ConnState.init(fd));
        const conn = self.clients.get(id).?;
        conn.token = try tokenFromId(id);
        try self.ring.submitRecv(conn.token, conn.fd, &conn.recv_buf);
    }

    fn handleRecv(self: *Server, event: ringlane.RecvEvent) !void {
        const conn = try self.connForToken(event.token);
        conn.closing = event.res <= 0;
        if (event.res > 0) {
            try feedBytes(conn, conn.recv_buf[0..@as(usize, @intCast(event.res))]);
            try self.armSendIfNeeded(conn);
            if (!conn.closing) {
                try self.ring.submitRecv(conn.token, conn.fd, &conn.recv_buf);
            }
        }
        if (conn.closing and !conn.send_armed and conn.send_len == conn.send_offset) {
            self.closeConn(event.token);
        }
    }

    fn handleSend(self: *Server, event: ringlane.SendEvent) !void {
        const conn = try self.connForToken(event.token);
        conn.send_armed = false;
        if (event.res < 0) {
            self.closeConn(event.token);
            return;
        }

        conn.send_offset += @as(usize, @intCast(event.res));
        if (conn.send_offset >= conn.send_len) {
            conn.send_offset = 0;
            conn.send_len = 0;
        }

        try self.armSendIfNeeded(conn);
        if (conn.closing and !conn.send_armed and conn.send_len == conn.send_offset) {
            self.closeConn(event.token);
        }
    }

    fn armSendIfNeeded(self: *Server, conn: *ConnState) !void {
        if (conn.send_armed) return;
        if (conn.send_offset >= conn.send_len) return;
        try self.ring.submitSend(conn.token, conn.fd, conn.send_buf[conn.send_offset..conn.send_len]);
        conn.send_armed = true;
    }

    fn connForToken(self: *Server, token: RingFdToken) ServerError!*ConnState {
        return self.clients.get(idFromToken(token)) orelse error.ClientNotFound;
    }

    fn closeConn(self: *Server, token: RingFdToken) void {
        const id = idFromToken(token);
        if (self.clients.get(id)) |conn| {
            closeFd(conn.fd);
            _ = self.clients.free(id);
        }
    }
};

const CompletionHandler = struct {
    server: *Server,
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

fn feedBytes(conn: *ConnState, bytes: []const u8) !void {
    for (bytes) |byte| {
        if (conn.line_len == conn.line_buf.len) {
            conn.closing = true;
            return error.LineTooLong;
        }
        conn.line_buf[conn.line_len] = byte;
        conn.line_len += 1;

        if (conn.line_len >= 2 and
            conn.line_buf[conn.line_len - 2] == '\r' and
            conn.line_buf[conn.line_len - 1] == '\n')
        {
            var sink = QueueSink{ .conn = conn };
            try processLine(conn, conn.line_buf[0..conn.line_len], &sink);
            conn.line_len = 0;
        }
    }
}

fn tokenFromId(id: client_model.ClientId) ServerError!RingFdToken {
    if (id.gen > ((@as(u32, 1) << 28) - 1)) return error.TokenOutOfRange;
    return .{ .slot = id.slot, .gen = id.gen };
}

fn idFromToken(token: RingFdToken) client_model.ClientId {
    return .{ .shard = 0, .slot = @intCast(token.slot), .gen = token.gen };
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

fn initServerOrSkip(allocator: std.mem.Allocator, config: Config) !Server {
    return Server.init(allocator, config) catch |err| switch (err) {
        error.Unsupported,
        error.PermissionDenied,
        error.SocketUnavailable,
        error.AddressInUse,
        => return error.SkipZigTest,
        else => return err,
    };
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

test "live loopback server accepts TCP client and answers PING" {
    var server = try initServerOrSkip(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0 });
    defer server.deinit();

    const port = try server.boundPort();
    const client_fd = connectLoopback(port) catch |err| switch (err) {
        error.PermissionDenied,
        error.SocketUnavailable,
        error.ConnectionRefused,
        => return error.SkipZigTest,
        else => return err,
    };
    defer closeFd(client_fd);

    try writeAllFd(client_fd, "PING :abc\r\n");

    try server.runOnce(); // accept
    try server.runOnce(); // recv + queue send
    try server.runOnce(); // send completion

    var buf: [128]u8 = undefined;
    const n = try readFd(client_fd, &buf);
    try std.testing.expectEqualStrings("PONG :abc\r\n", buf[0..n]);
}

test {
    std.testing.refAllDecls(@This());
}
