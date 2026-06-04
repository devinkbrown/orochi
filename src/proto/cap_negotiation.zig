//! IRCv3 CAP 3.2 negotiation FSM.
//!
//! This module owns only per-session negotiation state. Capability identity,
//! advertisement, and CAP 302 value validation come from `cap.zig` and
//! `cap_values.zig`.
const std = @import("std");
const cap = @import("cap.zig");
const cap_values = @import("cap_values.zig");

pub const MAX_REPLY_BODY: usize = cap.MAX_CAP_REPLY_BODY;
pub const MAX_WIRE_LINE: usize = "CAP * LS * :".len + MAX_REPLY_BODY + "\r\n".len;

pub const NegotiationError = cap_values.CapValuesError || error{
    InvalidCommand,
    MissingParameter,
};

pub const Phase = enum {
    idle,
    ls_sent,
    req_pending,
    acked,
    naked,
    ended,
};

pub const Options = struct {
    max_ls_body: usize = MAX_REPLY_BODY,
    values: []const cap_values.ValueSpec = &.{},
};

/// Caller-owned fixed storage for complete IRC wire lines, including CRLF.
pub const LineSink = struct {
    lines: [][]const u8,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,
    current_start: usize = 0,
    current_len: usize = 0,

    pub fn writeAll(self: *LineSink, bytes: []const u8) cap_values.CapValuesError!void {
        const saved = self.*;
        errdefer self.* = saved;

        for (bytes) |byte| {
            if (self.used >= self.storage.len) return error.OutputTooSmall;
            if (self.current_len >= MAX_WIRE_LINE) return error.OutputTooSmall;
            if (self.current_len == 0) self.current_start = self.used;

            self.storage[self.used] = byte;
            self.used += 1;
            self.current_len += 1;

            if (self.current_len >= 2 and
                self.storage[self.used - 2] == '\r' and
                self.storage[self.used - 1] == '\n')
            {
                if (self.count >= self.lines.len) return error.OutputTooSmall;
                self.lines[self.count] = self.storage[self.current_start..self.used];
                self.count += 1;
                self.current_start = self.used;
                self.current_len = 0;
            }
        }
    }

    pub fn slice(self: *const LineSink) []const []const u8 {
        return self.lines[0..self.count];
    }
};

pub const Session = struct {
    phase: Phase = .idle,
    negotiated: cap.CapSet = .{},
    requested_add: cap.CapSet = .{},
    requested_remove: cap.CapSet = .{},
    cap_302: bool = false,

    pub fn registrationHeld(self: Session) bool {
        return switch (self.phase) {
            .idle, .ended => false,
            .ls_sent, .req_pending, .acked, .naked => true,
        };
    }

    pub fn registrationComplete(self: Session) bool {
        return self.phase == .ended;
    }

    pub fn capNotifyActive(self: Session) bool {
        return self.negotiated.contains(.cap_notify);
    }

    pub fn mayReceiveCapNotify(self: Session) bool {
        return self.capNotifyActive();
    }

    pub fn handle(
        self: *Session,
        registry: cap.CapRegistry,
        subcommand: []const u8,
        params: []const []const u8,
        options: Options,
        sink: *LineSink,
    ) NegotiationError!void {
        if (std.ascii.eqlIgnoreCase(subcommand, "LS")) {
            const requested_302 = params.len != 0 and std.mem.eql(u8, params[0], "302");
            return self.handleLs(registry, requested_302, options, sink);
        }
        if (std.ascii.eqlIgnoreCase(subcommand, "LIST")) {
            return self.handleList(registry, sink);
        }
        if (std.ascii.eqlIgnoreCase(subcommand, "REQ")) {
            if (params.len == 0) return error.MissingParameter;
            return self.handleReq(registry, params[0], options, sink);
        }
        if (std.ascii.eqlIgnoreCase(subcommand, "END")) {
            self.handleEnd();
            return;
        }
        return error.InvalidCommand;
    }

    pub fn handleLs(
        self: *Session,
        registry: cap.CapRegistry,
        requested_302: bool,
        options: Options,
        sink: *LineSink,
    ) NegotiationError!void {
        const before = self.*;
        errdefer self.* = before;

        self.phase = .ls_sent;
        self.cap_302 = self.cap_302 or requested_302;
        try cap_values.emitLs(registry, .{
            .cap_302 = self.cap_302,
            .max_body = options.max_ls_body,
            .values = options.values,
        }, sink);
    }

    pub fn handleReq(
        self: *Session,
        registry: cap.CapRegistry,
        raw_list: []const u8,
        options: Options,
        sink: *LineSink,
    ) NegotiationError!void {
        const before = self.*;
        errdefer self.* = before;

        self.phase = .req_pending;
        self.requested_add = .{};
        self.requested_remove = .{};

        const body = reqBody(raw_list);
        const requested = cap_values.parseReq(
            registry,
            .{ .values = options.values },
            body,
            null,
        ) catch |err| switch (err) {
            error.InvalidRequest, error.UnsupportedValue => {
                try writeReqReply(sink, "NAK", body);
                self.phase = .naked;
                return;
            },
            else => return err,
        };

        self.requested_add = requested.add;
        self.requested_remove = requested.remove;
        try writeReqReply(sink, "ACK", body);
        self.negotiated.unionWith(requested.add);
        self.negotiated.subtract(requested.remove);
        self.phase = .acked;
    }

    pub fn handleList(
        self: *Session,
        registry: cap.CapRegistry,
        sink: *LineSink,
    ) NegotiationError!void {
        var body: [MAX_REPLY_BODY]u8 = undefined;
        const names = try writeSetNames(registry, self.negotiated, &body);
        try sink.writeAll("CAP * LIST :");
        try sink.writeAll(names);
        try sink.writeAll("\r\n");
    }

    pub fn handleEnd(self: *Session) void {
        self.phase = .ended;
        self.requested_add = .{};
        self.requested_remove = .{};
    }
};

fn reqBody(raw_list: []const u8) []const u8 {
    var body = std.mem.trim(u8, raw_list, " ");
    if (body.len != 0 and body[0] == ':') body = body[1..];
    return body;
}

fn writeReqReply(sink: *LineSink, verb: []const u8, body: []const u8) cap_values.CapValuesError!void {
    if (body.len > MAX_REPLY_BODY) return error.OutputTooSmall;
    try sink.writeAll("CAP * ");
    try sink.writeAll(verb);
    try sink.writeAll(" :");
    try sink.writeAll(body);
    try sink.writeAll("\r\n");
}

fn writeSetNames(registry: cap.CapRegistry, set: cap.CapSet, out: []u8) cap_values.CapValuesError![]const u8 {
    var len: usize = 0;
    for (registry.specs) |spec| {
        if (spec.kind != .client or !set.contains(spec.id)) continue;

        const extra_space: usize = if (len == 0) 0 else 1;
        if (len + extra_space + spec.name.len > out.len) return error.OutputTooSmall;
        if (len != 0) {
            out[len] = ' ';
            len += 1;
        }
        @memcpy(out[len .. len + spec.name.len], spec.name);
        len += spec.name.len;
    }
    return out[0..len];
}

const test_specs = [_]cap.CapSpec{
    .{ .id = .cap_notify, .name = "cap-notify" },
    .{ .id = .sasl, .name = "sasl", .value_302 = "PLAIN,EXTERNAL" },
    .{ .id = .sts, .name = "sts", .value_302 = "duration=604800" },
    .{ .id = .multiline, .name = "multiline" },
};

const test_values = [_]cap_values.ValueSpec{
    .{ .id = .sasl, .value = "PLAIN,EXTERNAL,SCRAM-SHA-256" },
    .{ .id = .multiline, .value = "max-lines=64" },
};

fn testRegistry() cap.CapRegistry {
    return .{ .specs = &test_specs };
}

fn makeSink(line_count: usize, storage_len: usize) !struct {
    lines: [][]const u8,
    storage: []u8,
    sink: LineSink,
} {
    const allocator = std.testing.allocator;
    const lines = try allocator.alloc([]const u8, line_count);
    errdefer allocator.free(lines);
    const storage = try allocator.alloc(u8, storage_len);
    errdefer allocator.free(storage);
    return .{
        .lines = lines,
        .storage = storage,
        .sink = .{ .lines = lines, .storage = storage },
    };
}

fn freeSink(ctx: anytype) void {
    const allocator = std.testing.allocator;
    allocator.free(ctx.storage);
    allocator.free(ctx.lines);
}

fn collect(sink: *const LineSink) !std.ArrayList(u8) {
    const allocator = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    for (sink.slice()) |line| try out.appendSlice(allocator, line);
    return out;
}

test "LS 302 with values emits bounded multiline replies" {
    var ctx = try makeSink(8, 1024);
    defer freeSink(ctx);
    var session = Session{};

    try session.handleLs(testRegistry(), true, .{
        .max_ls_body = 35,
        .values = &test_values,
    }, &ctx.sink);
    var out = try collect(&ctx.sink);
    defer out.deinit(std.testing.allocator);

    try std.testing.expectEqual(Phase.ls_sent, session.phase);
    try std.testing.expect(session.cap_302);
    try std.testing.expect(session.registrationHeld());
    try std.testing.expectEqualStrings(
        "CAP * LS * :cap-notify\r\n" ++
            "CAP * LS * :sasl=PLAIN,EXTERNAL,SCRAM-SHA-256\r\n" ++
            "CAP * LS * :sts=duration=604800\r\n" ++
            "CAP * LS :multiline=max-lines=64\r\n",
        out.items,
    );
}

test "REQ ACK and NAK update state atomically" {
    var ctx = try makeSink(4, 1024);
    defer freeSink(ctx);
    var session = Session{};
    session.negotiated.add(.sts);

    try session.handleReq(testRegistry(), "cap-notify sasl=EXTERNAL -sts", .{
        .values = &test_values,
    }, &ctx.sink);

    try std.testing.expectEqual(Phase.acked, session.phase);
    try std.testing.expect(session.negotiated.contains(.cap_notify));
    try std.testing.expect(session.negotiated.contains(.sasl));
    try std.testing.expect(!session.negotiated.contains(.sts));
    try std.testing.expect(session.capNotifyActive());
    const after_ack = session.negotiated;

    try session.handleReq(testRegistry(), "sasl=OAUTHBEARER", .{
        .values = &test_values,
    }, &ctx.sink);
    try std.testing.expectEqual(Phase.naked, session.phase);
    try std.testing.expectEqual(after_ack.bits, session.negotiated.bits);

    var out = try collect(&ctx.sink);
    defer out.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(
        "CAP * ACK :cap-notify sasl=EXTERNAL -sts\r\n" ++
            "CAP * NAK :sasl=OAUTHBEARER\r\n",
        out.items,
    );
}

test "END completes registration gating" {
    var ctx = try makeSink(4, 512);
    defer freeSink(ctx);
    var session = Session{};

    try std.testing.expect(!session.registrationHeld());
    try session.handleLs(testRegistry(), false, .{}, &ctx.sink);
    try std.testing.expect(session.registrationHeld());
    try session.handleReq(testRegistry(), "cap-notify", .{}, &ctx.sink);
    try std.testing.expect(session.registrationHeld());

    session.handleEnd();
    try std.testing.expectEqual(Phase.ended, session.phase);
    try std.testing.expect(!session.registrationHeld());
    try std.testing.expect(session.registrationComplete());
}

test "unknown cap NAK does not change negotiated set" {
    var ctx = try makeSink(2, 512);
    defer freeSink(ctx);
    var session = Session{};
    session.negotiated.add(.cap_notify);
    const before = session.negotiated;

    try session.handleReq(testRegistry(), "cap-notify unknown-cap sasl", .{
        .values = &test_values,
    }, &ctx.sink);
    try std.testing.expectEqual(Phase.naked, session.phase);
    try std.testing.expectEqual(before.bits, session.negotiated.bits);
    try std.testing.expect(!session.negotiated.contains(.sasl));

    var out = try collect(&ctx.sink);
    defer out.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(
        "CAP * NAK :cap-notify unknown-cap sasl\r\n",
        out.items,
    );
}
