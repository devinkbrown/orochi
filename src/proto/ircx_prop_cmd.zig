//! Pure IRCX PROP command parser and reply builder.
//!
//! This module is the command-surface layer over `ircx_prop_store`: it owns no
//! property state, returns borrowed parse slices, and renders store `EntryView`
//! values into caller-owned reply buffers.
const std = @import("std");
const prop_store = @import("ircx_prop_store.zig");

pub const Params = prop_store.Params;
pub const PropError = prop_store.PropError;
pub const Entity = prop_store.Entity;
pub const EntityKind = prop_store.EntityKind;
pub const EntryView = prop_store.EntryView;
pub const QueryRequest = prop_store.QueryRequest;
pub const MutationRequest = prop_store.MutationRequest;
pub const KeyRequest = prop_store.KeyRequest;
pub const StoreRequest = prop_store.Request;

pub const Operation = enum {
    list,
    get,
    set,
    delete,

    pub fn token(self: Operation) []const u8 {
        return switch (self) {
            .list => "LIST",
            .get => "GET",
            .set => "SET",
            .delete => "DELETE",
        };
    }
};

pub const Request = union(Operation) {
    list: Entity,
    get: QueryRequest,
    set: MutationRequest,
    delete: KeyRequest,

    pub fn operation(self: Request) Operation {
        return std.meta.activeTag(self);
    }

    pub fn entity(self: Request) Entity {
        return switch (self) {
            .list => |value| value,
            .get => |value| value.entity,
            .set => |value| value.entity,
            .delete => |value| value.entity,
        };
    }

    pub fn fromStore(request: StoreRequest) Request {
        return switch (request) {
            .list => |entity_value| .{ .list = entity_value },
            .get => |query| .{ .get = query },
            .set => |mutation| .{ .set = mutation },
            .delete => |key| .{ .delete = key },
        };
    }

    pub fn toStore(self: Request) StoreRequest {
        return switch (self) {
            .list => |entity_value| .{ .list = entity_value },
            .get => |query| .{ .get = query },
            .set => |mutation| .{ .set = mutation },
            .delete => |key| .{ .delete = key },
        };
    }
};

pub const ReplyContext = struct {
    server: []const u8,
    nick: []const u8,
};

/// Parse a raw `PROP <entity> [key [value]]` IRC line.
pub fn parse(line: []const u8) PropError!Request {
    return parseWith(.{}, line);
}

/// Parse a raw PROP IRC line with caller-selected compile-time limits.
pub fn parseWith(comptime params: Params, line: []const u8) PropError!Request {
    return Request.fromStore(try prop_store.parseLineBounded(params, line));
}

/// Parse PROP parameters excluding the command name.
pub fn parseParams(params_slice: []const []const u8, had_trailing: bool) PropError!Request {
    return parseParamsWith(.{}, params_slice, had_trailing);
}

/// Parse PROP parameters with caller-selected compile-time limits.
pub fn parseParamsWith(comptime params: Params, params_slice: []const []const u8, had_trailing: bool) PropError!Request {
    return Request.fromStore(try prop_store.parseParamsBounded(params, params_slice, had_trailing));
}

pub const ReplyBuilder = struct {
    writer: BufferWriter,

    pub fn init(out: []u8) ReplyBuilder {
        return .{ .writer = BufferWriter.init(out) };
    }

    pub fn slice(self: *const ReplyBuilder) []const u8 {
        return self.writer.slice();
    }

    /// Write one RPL_PROPLIST line per entry, then RPL_PROPEND.
    pub fn writeList(self: *ReplyBuilder, ctx: ReplyContext, entity_value: Entity, entries: []const EntryView) PropError![]const u8 {
        for (entries) |entry| {
            try requireSameEntity(entity_value, entry.entity);
            const line = try prop_store.buildPropListReply(ctx.server, ctx.nick, entry, self.writer.remaining());
            self.writer.advance(line.len);
            try self.writer.crlf();
        }

        const end = try prop_store.buildPropEndReply(ctx.server, ctx.nick, entity_value, self.writer.remaining());
        self.writer.advance(end.len);
        try self.writer.crlf();
        return self.slice();
    }

    /// GET replies use the same IRCX 818/819 wire shape as a filtered LIST.
    pub fn writeGet(self: *ReplyBuilder, ctx: ReplyContext, request: QueryRequest, entries: []const EntryView) PropError![]const u8 {
        return self.writeList(ctx, request.entity, entries);
    }
};

pub fn buildListReply(out: []u8, ctx: ReplyContext, entity_value: Entity, entries: []const EntryView) PropError![]const u8 {
    var builder = ReplyBuilder.init(out);
    return builder.writeList(ctx, entity_value, entries);
}

pub fn buildGetReply(out: []u8, ctx: ReplyContext, request: QueryRequest, entries: []const EntryView) PropError![]const u8 {
    var builder = ReplyBuilder.init(out);
    return builder.writeGet(ctx, request, entries);
}

fn requireSameEntity(expected: Entity, actual: Entity) PropError!void {
    if (expected.kind != actual.kind) return error.InvalidEntity;
    if (!std.ascii.eqlIgnoreCase(expected.id, actual.id)) return error.InvalidEntity;
}

const BufferWriter = struct {
    out: []u8,
    len: usize = 0,

    fn init(out: []u8) BufferWriter {
        return .{ .out = out };
    }

    fn slice(self: *const BufferWriter) []const u8 {
        return self.out[0..self.len];
    }

    fn remaining(self: *BufferWriter) []u8 {
        return self.out[self.len..];
    }

    fn advance(self: *BufferWriter, len: usize) void {
        self.len += len;
    }

    fn crlf(self: *BufferWriter) PropError!void {
        if (self.len > self.out.len or self.out.len - self.len < 2) return error.OutputTooSmall;
        self.out[self.len] = '\r';
        self.out[self.len + 1] = '\n';
        self.len += 2;
    }
};

test "parse each PROP request form" {
    const list = try parse("PROP #chan");
    try std.testing.expectEqual(Operation.list, list.operation());
    try std.testing.expectEqual(EntityKind.channel, list.entity().kind);
    try std.testing.expectEqualStrings("#chan", list.list.id);

    const get = try parse("PROP nick AWAY");
    try std.testing.expectEqual(Operation.get, get.operation());
    try std.testing.expectEqual(EntityKind.user, get.entity().kind);
    try std.testing.expectEqualStrings("AWAY", get.get.keys);

    const set = try parse("PROP #chan TOPIC :hello world\r\n");
    try std.testing.expectEqual(Operation.set, set.operation());
    try std.testing.expectEqualStrings("#chan", set.set.entity.id);
    try std.testing.expectEqualStrings("TOPIC", set.set.key);
    try std.testing.expectEqualStrings("hello world", set.set.value);

    const del = try parse("PROP nick AWAY :");
    try std.testing.expectEqual(Operation.delete, del.operation());
    try std.testing.expectEqualStrings("nick", del.delete.entity.id);
    try std.testing.expectEqualStrings("AWAY", del.delete.key);
}

test "parse parameters preserves borrowed store payloads" {
    const raw = [_][]const u8{ "#chan", "TOPIC", "stored value" };
    const set = try parseParams(&raw, true);

    try std.testing.expectEqual(Operation.set, set.operation());
    try std.testing.expectEqualStrings(raw[0], set.set.entity.id);
    try std.testing.expectEqualStrings(raw[1], set.set.key);
    try std.testing.expectEqualStrings(raw[2], set.set.value);
    try std.testing.expectEqual(StoreRequest.set, @as(std.meta.Tag(StoreRequest), set.toStore()));
}

test "build LIST reply bytes from store entries" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity_value = try Entity.fromId("#reply");
    _ = try store.setProp(entity_value, "TOPIC", "hello", .{ .id = "oper", .access = .owner });
    _ = try store.setProp(entity_value, "SUBJECT", "zig", .{ .id = "oper", .access = .owner });

    var entries_buf: [4]EntryView = undefined;
    const entries = try store.listProps(entity_value, &entries_buf);

    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 256);
    defer allocator.free(out);

    const reply = try buildListReply(out, .{ .server = "irc.example", .nick = "alice" }, entity_value, entries);
    try std.testing.expectEqualStrings(
        ":irc.example 818 alice #reply SUBJECT :zig\r\n" ++
            ":irc.example 818 alice #reply TOPIC :hello\r\n" ++
            ":irc.example 819 alice #reply :End of properties\r\n",
        reply,
    );
}

test "build GET reply bytes from store entry" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const request = (try parse("PROP #reply TOPIC")).get;
    _ = try store.setProp(request.entity, "TOPIC", "hello", .{ .id = "oper", .access = .owner });
    const entry = try store.getProp(request.entity, request.keys);

    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 160);
    defer allocator.free(out);

    const reply = try buildGetReply(out, .{ .server = "irc.example", .nick = "alice" }, request, &.{entry});
    try std.testing.expectEqualStrings(
        ":irc.example 818 alice #reply TOPIC :hello\r\n" ++
            ":irc.example 819 alice #reply :End of properties\r\n",
        reply,
    );
}

test "build empty GET reply ends the property list" {
    const request = (try parse("PROP #empty TOPIC")).get;

    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 96);
    defer allocator.free(out);

    const reply = try buildGetReply(out, .{ .server = "irc.example", .nick = "alice" }, request, &.{});
    try std.testing.expectEqualStrings(":irc.example 819 alice #empty :End of properties\r\n", reply);
}

test "parse and build error cases" {
    try std.testing.expectError(error.InvalidCommand, parse("PRIVMSG #chan :no"));
    try std.testing.expectError(error.NeedMoreParams, parse("PROP"));
    try std.testing.expectError(error.TooManyParams, parse("PROP #chan A B C"));
    try std.testing.expectError(error.InvalidKey, parse("PROP #chan bad,key :value"));

    const entity_value = try Entity.fromId("#reply");
    const other_entity = try Entity.fromId("#other");
    const entry = EntryView{
        .entity = other_entity,
        .key = "TOPIC",
        .value = "hello",
        .owner = "oper",
        .access = .owner,
    };

    var tiny: [16]u8 = undefined;
    try std.testing.expectError(
        error.InvalidEntity,
        buildListReply(&tiny, .{ .server = "irc.example", .nick = "alice" }, entity_value, &.{entry}),
    );

    const matching = EntryView{
        .entity = entity_value,
        .key = "TOPIC",
        .value = "hello",
        .owner = "oper",
        .access = .owner,
    };
    try std.testing.expectError(
        error.OutputTooSmall,
        buildListReply(&tiny, .{ .server = "irc.example", .nick = "alice" }, entity_value, &.{matching}),
    );
}
