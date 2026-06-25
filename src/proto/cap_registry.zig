// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub const default_line_limit: usize = 510;

pub const Error = error{
    CapabilityNotFound,
    EmptyCapabilityName,
    InvalidRequest,
    LineTooLong,
};

pub const Capability = struct {
    name: []const u8,
    value: ?[]const u8 = null,
    needs_ack: bool = false,
};

pub const Messages = struct {
    lines: [][]u8,

    pub fn deinit(self: *Messages, allocator: std.mem.Allocator) void {
        for (self.lines) |line| {
            allocator.free(line);
        }
        allocator.free(self.lines);
        self.lines = &[_][]u8{};
    }
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    target: []const u8,
    negotiating: bool,
    enabled: std.StringHashMap(void),

    pub fn init(allocator: std.mem.Allocator, target: []const u8) Session {
        return .{
            .allocator = allocator,
            .target = target,
            .negotiating = true,
            .enabled = std.StringHashMap(void).init(allocator),
        };
    }

    pub fn deinit(self: *Session) void {
        // The session OWNS copies of its enabled cap names (they must not borrow
        // Registry-owned memory, which can be unregistered out from under us).
        var it = self.enabled.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.enabled.deinit();
    }

    /// Enable a cap, taking an owned copy of the name (idempotent).
    pub fn enable(self: *Session, name: []const u8) !void {
        if (self.enabled.contains(name)) return;
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        try self.enabled.put(owned, {});
    }

    /// Disable a cap, freeing the owned name copy.
    pub fn disable(self: *Session, name: []const u8) void {
        if (self.enabled.fetchRemove(name)) |kv| self.allocator.free(kv.key);
    }

    pub fn isEnabled(self: *const Session, name: []const u8) bool {
        return self.enabled.contains(name);
    }

    pub fn end(self: *Session) void {
        self.negotiating = false;
    }
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    caps: std.ArrayList(Capability),
    index: std.StringHashMap(usize),

    pub fn init(allocator: std.mem.Allocator) Registry {
        return .{
            .allocator = allocator,
            .caps = .empty,
            .index = std.StringHashMap(usize).init(allocator),
        };
    }

    pub fn deinit(self: *Registry) void {
        for (self.caps.items) |cap| {
            self.allocator.free(cap.name);
            if (cap.value) |value| self.allocator.free(value);
        }
        self.caps.deinit(self.allocator);
        self.index.deinit();
    }

    pub fn register(
        self: *Registry,
        name: []const u8,
        value: ?[]const u8,
        needs_ack: bool,
    ) !void {
        if (name.len == 0) return Error.EmptyCapabilityName;

        if (self.index.get(name)) |slot| {
            if (self.caps.items[slot].value) |old_value| {
                self.allocator.free(old_value);
            }
            self.caps.items[slot].value = if (value) |v| try self.allocator.dupe(u8, v) else null;
            self.caps.items[slot].needs_ack = needs_ack;
            return;
        }

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);

        const owned_value = if (value) |v| try self.allocator.dupe(u8, v) else null;
        errdefer if (owned_value) |v| self.allocator.free(v);

        try self.caps.append(self.allocator, .{
            .name = owned_name,
            .value = owned_value,
            .needs_ack = needs_ack,
        });
        errdefer _ = self.caps.pop();

        try self.index.put(owned_name, self.caps.items.len - 1);
    }

    pub fn unregister(self: *Registry, name: []const u8) bool {
        const slot = self.index.get(name) orelse return false;
        _ = self.index.remove(name);

        const removed = self.caps.orderedRemove(slot);
        self.allocator.free(removed.name);
        if (removed.value) |value| self.allocator.free(value);

        var i: usize = slot;
        while (i < self.caps.items.len) : (i += 1) {
            self.index.getPtr(self.caps.items[i].name).?.* = i;
        }
        return true;
    }

    pub fn has(self: *const Registry, name: []const u8) bool {
        return self.index.contains(name);
    }

    pub fn get(self: *const Registry, name: []const u8) ?Capability {
        const slot = self.index.get(name) orelse return null;
        return self.caps.items[slot];
    }

    pub fn ls(self: *const Registry, allocator: std.mem.Allocator, target: []const u8) !Messages {
        return self.lsWithLimit(allocator, target, default_line_limit);
    }

    pub fn lsWithLimit(
        self: *const Registry,
        allocator: std.mem.Allocator,
        target: []const u8,
        line_limit: usize,
    ) !Messages {
        var tokens: std.ArrayList([]u8) = .empty;
        defer {
            for (tokens.items) |token| allocator.free(token);
            tokens.deinit(allocator);
        }

        for (self.caps.items) |cap| {
            try tokens.append(allocator, try renderCapabilityToken(allocator, cap));
        }

        return packCapLines(allocator, target, "LS", tokens.items, line_limit);
    }

    pub fn request(
        self: *const Registry,
        allocator: std.mem.Allocator,
        session: *Session,
        request_payload: []const u8,
    ) ![]u8 {
        const trimmed = std.mem.trim(u8, request_payload, " ");
        if (trimmed.len == 0) return capMessage(allocator, session.target, "NAK", false, trimmed);

        var validator = std.mem.tokenizeAny(u8, trimmed, " ");
        while (validator.next()) |raw| {
            const parsed = parseRequestToken(raw) orelse {
                return capMessage(allocator, session.target, "NAK", false, trimmed);
            };
            if (!self.has(parsed.name)) {
                return capMessage(allocator, session.target, "NAK", false, trimmed);
            }
        }

        var applier = std.mem.tokenizeAny(u8, trimmed, " ");
        while (applier.next()) |raw| {
            const parsed = parseRequestToken(raw).?;
            const cap = self.get(parsed.name).?;
            if (parsed.enable) {
                try session.enable(cap.name);
            } else {
                session.disable(cap.name);
            }
        }

        return capMessage(allocator, session.target, "ACK", false, trimmed);
    }

    pub fn list(
        self: *const Registry,
        allocator: std.mem.Allocator,
        session: *const Session,
    ) ![]u8 {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(allocator);

        for (self.caps.items) |cap| {
            if (!session.isEnabled(cap.name)) continue;
            if (body.items.len != 0) try body.append(allocator, ' ');
            try appendCapabilityToken(&body, allocator, cap);
        }

        return capMessage(allocator, session.target, "LIST", false, body.items);
    }

    pub fn notifyNew(
        self: *const Registry,
        allocator: std.mem.Allocator,
        target: []const u8,
        name: []const u8,
    ) ![]u8 {
        const cap = self.get(name) orelse return Error.CapabilityNotFound;
        const token = try renderCapabilityToken(allocator, cap);
        defer allocator.free(token);
        return capMessage(allocator, target, "NEW", false, token);
    }

    pub fn notifyDel(
        self: *const Registry,
        allocator: std.mem.Allocator,
        target: []const u8,
        name: []const u8,
    ) ![]u8 {
        _ = self;
        return capMessage(allocator, target, "DEL", false, name);
    }
};

const RequestToken = struct {
    name: []const u8,
    enable: bool,
};

fn parseRequestToken(raw: []const u8) ?RequestToken {
    if (raw.len == 0) return null;

    if (raw[0] == '-') {
        const name = raw[1..];
        if (name.len == 0 or std.mem.indexOfScalar(u8, name, '=') != null) return null;
        return .{ .name = name, .enable = false };
    }

    if (std.mem.indexOfScalar(u8, raw, '=') != null) return null;
    return .{ .name = raw, .enable = true };
}

fn renderCapabilityToken(allocator: std.mem.Allocator, cap: Capability) ![]u8 {
    var token: std.ArrayList(u8) = .empty;
    errdefer token.deinit(allocator);
    try appendCapabilityToken(&token, allocator, cap);
    return token.toOwnedSlice(allocator);
}

fn appendCapabilityToken(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    cap: Capability,
) !void {
    if (cap.needs_ack) try out.append(allocator, '~');
    try out.appendSlice(allocator, cap.name);
    if (cap.value) |value| {
        try out.append(allocator, '=');
        try out.appendSlice(allocator, value);
    }
}

fn capLineLength(target: []const u8, subcmd: []const u8, continuation: bool, body_len: usize) usize {
    return "CAP ".len + target.len + " ".len + subcmd.len +
        (if (continuation) " * :".len else " :".len) + body_len;
}

fn capMessage(
    allocator: std.mem.Allocator,
    target: []const u8,
    subcmd: []const u8,
    continuation: bool,
    body: []const u8,
) ![]u8 {
    if (continuation) {
        return std.fmt.allocPrint(allocator, "CAP {s} {s} * :{s}", .{ target, subcmd, body });
    }
    return std.fmt.allocPrint(allocator, "CAP {s} {s} :{s}", .{ target, subcmd, body });
}

fn appendPackedLine(
    out: *std.ArrayList([]u8),
    allocator: std.mem.Allocator,
    target: []const u8,
    subcmd: []const u8,
    continuation: bool,
    body: []const u8,
    line_limit: usize,
) !void {
    if (capLineLength(target, subcmd, continuation, body.len) > line_limit) {
        return Error.LineTooLong;
    }
    try out.append(allocator, try capMessage(allocator, target, subcmd, continuation, body));
}

fn packCapLines(
    allocator: std.mem.Allocator,
    target: []const u8,
    subcmd: []const u8,
    tokens: []const []const u8,
    line_limit: usize,
) !Messages {
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |line| allocator.free(line);
        out.deinit(allocator);
    }

    if (tokens.len == 0) {
        try appendPackedLine(&out, allocator, target, subcmd, false, "", line_limit);
        return .{ .lines = try out.toOwnedSlice(allocator) };
    }

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);

    for (tokens, 0..) |token, i| {
        if (body.items.len == 0) {
            const continuation = i + 1 < tokens.len;
            if (capLineLength(target, subcmd, continuation, token.len) > line_limit) {
                return Error.LineTooLong;
            }
            try body.appendSlice(allocator, token);
            continue;
        }

        const proposed_len = body.items.len + 1 + token.len;
        const would_continue = i + 1 < tokens.len;
        if (capLineLength(target, subcmd, would_continue, proposed_len) <= line_limit) {
            try body.append(allocator, ' ');
            try body.appendSlice(allocator, token);
            continue;
        }

        try appendPackedLine(&out, allocator, target, subcmd, true, body.items, line_limit);
        body.clearRetainingCapacity();

        const continuation = i + 1 < tokens.len;
        if (capLineLength(target, subcmd, continuation, token.len) > line_limit) {
            return Error.LineTooLong;
        }
        try body.appendSlice(allocator, token);
    }

    try appendPackedLine(&out, allocator, target, subcmd, false, body.items, line_limit);
    return .{ .lines = try out.toOwnedSlice(allocator) };
}

test "LS lists registered caps with values" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.register("multi-prefix", null, false);
    try registry.register("sasl", "PLAIN,EXTERNAL", false);

    var messages = try registry.ls(allocator, "*");
    defer messages.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), messages.lines.len);
    try std.testing.expectEqualStrings(
        "CAP * LS :multi-prefix sasl=PLAIN,EXTERNAL",
        messages.lines[0],
    );
}

test "multiline LS split marks continuation with star" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.register("account-tag", null, false);
    try registry.register("extended-join", null, false);
    try registry.register("server-time", null, false);

    var messages = try registry.lsWithLimit(allocator, "*", 32);
    defer messages.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 3), messages.lines.len);
    try std.testing.expectEqualStrings("CAP * LS * :account-tag", messages.lines[0]);
    try std.testing.expectEqualStrings("CAP * LS * :extended-join", messages.lines[1]);
    try std.testing.expectEqualStrings("CAP * LS :server-time", messages.lines[2]);
}

test "REQ all-known ACKs and enables atomically" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.register("multi-prefix", null, false);
    try registry.register("sasl", "PLAIN", false);

    var session = Session.init(allocator, "*");
    defer session.deinit();

    const reply = try registry.request(allocator, &session, "multi-prefix sasl");
    defer allocator.free(reply);

    try std.testing.expectEqualStrings("CAP * ACK :multi-prefix sasl", reply);
    try std.testing.expect(session.isEnabled("multi-prefix"));
    try std.testing.expect(session.isEnabled("sasl"));
}

test "REQ with one unknown NAKs and enables nothing" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.register("multi-prefix", null, false);

    var session = Session.init(allocator, "*");
    defer session.deinit();

    const reply = try registry.request(allocator, &session, "multi-prefix unknown-cap");
    defer allocator.free(reply);

    try std.testing.expectEqualStrings("CAP * NAK :multi-prefix unknown-cap", reply);
    try std.testing.expect(!session.isEnabled("multi-prefix"));
    try std.testing.expect(!session.isEnabled("unknown-cap"));
}

test "LIST reflects enabled capabilities" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.register("multi-prefix", null, false);
    try registry.register("sasl", "PLAIN", false);

    var session = Session.init(allocator, "*");
    defer session.deinit();

    const ack = try registry.request(allocator, &session, "sasl");
    defer allocator.free(ack);

    const reply = try registry.list(allocator, &session);
    defer allocator.free(reply);

    try std.testing.expectEqualStrings("CAP * LIST :sasl=PLAIN", reply);
}

test "cap-notify NEW advertises registered capability" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.register("message-tags", null, false);

    const reply = try registry.notifyNew(allocator, "*", "message-tags");
    defer allocator.free(reply);

    try std.testing.expectEqualStrings("CAP * NEW :message-tags", reply);
}

test "END finishes negotiation" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator, "*");
    defer session.deinit();

    try std.testing.expect(session.negotiating);
    session.end();
    try std.testing.expect(!session.negotiating);
}
