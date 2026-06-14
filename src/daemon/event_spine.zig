//! Event Spine typed oper event bus.
//!
//! Daemon subsystems publish typed events here, while oper sessions subscribe
//! by `EventCategory` mask. The spine owns no allocation and keeps no global
//! state: callers provide subscriber storage, publish sinks, and render buffers.
const std = @import("std");

/// Orochi event categories. These replace untyped oper broadcast channels.
pub const EventCategory = enum(u6) {
    connect,
    disconnect,
    server_link,
    flood,
    @"error",
    announce,
    oper_action,
    kill,
    spam,
    debug,
    policy,
    service,
    security,

    pub fn token(self: EventCategory) []const u8 {
        return @tagName(self);
    }

    pub fn code(self: EventCategory) []const u8 {
        return switch (self) {
            .connect => "CONNECT",
            .disconnect => "DISCONNECT",
            .server_link => "SERVER_LINK",
            .flood => "FLOOD",
            .@"error" => "ERROR",
            .announce => "ANNOUNCE",
            .oper_action => "OPER_ACTION",
            .kill => "KILL",
            .spam => "SPAM",
            .debug => "DEBUG",
            .policy => "POLICY",
            .service => "SERVICE",
            .security => "SECURITY",
        };
    }
};

/// Event severity used for routing presentation and structured wire tags.
pub const EventSeverity = enum {
    debug,
    info,
    notice,
    warn,
    @"error",
    critical,

    pub fn token(self: EventSeverity) []const u8 {
        return @tagName(self);
    }
};

/// Bit mask over `EventCategory`.
pub const CategoryMask = struct {
    bits: u64 = 0,

    pub fn empty() CategoryMask {
        return .{};
    }

    pub fn all() CategoryMask {
        var out = CategoryMask.empty();
        inline for (@typeInfo(EventCategory).@"enum".fields) |field| {
            out.add(@field(EventCategory, field.name));
        }
        return out;
    }

    pub fn only(category: EventCategory) CategoryMask {
        return .{ .bits = bit(category) };
    }

    pub fn fromCategories(categories: []const EventCategory) CategoryMask {
        var out = CategoryMask.empty();
        for (categories) |category| out.add(category);
        return out;
    }

    pub fn add(self: *CategoryMask, category: EventCategory) void {
        self.bits |= bit(category);
    }

    pub fn remove(self: *CategoryMask, category: EventCategory) void {
        self.bits &= ~bit(category);
    }

    pub fn include(self: CategoryMask, other: CategoryMask) CategoryMask {
        return .{ .bits = self.bits | other.bits };
    }

    pub fn exclude(self: CategoryMask, other: CategoryMask) CategoryMask {
        return .{ .bits = self.bits & ~other.bits };
    }

    pub fn contains(self: CategoryMask, category: EventCategory) bool {
        return (self.bits & bit(category)) != 0;
    }

    pub fn intersects(self: CategoryMask, other: CategoryMask) bool {
        return (self.bits & other.bits) != 0;
    }

    pub fn isEmpty(self: CategoryMask) bool {
        return self.bits == 0;
    }

    fn bit(category: EventCategory) u64 {
        return @as(u64, 1) << @intFromEnum(category);
    }
};

/// Borrowed event payload. `timestamp_ms` is supplied by the caller.
pub const Event = struct {
    category: EventCategory,
    severity: EventSeverity,
    timestamp_ms: i64,
    message: []const u8,
};

/// One oper subscription slot. `id` and `mask` are caller-owned values.
pub const Subscriber = struct {
    id: []const u8 = "",
    mask: CategoryMask = .{},
};

/// One selected event delivery.
pub const Delivery = struct {
    subscriber_id: []const u8,
    event: Event,
};

/// Caller-owned sink filled by `EventSpine.publish`.
pub const PublishSink = struct {
    deliveries: []Delivery,
    count: usize = 0,

    pub fn init(deliveries: []Delivery) PublishSink {
        return .{ .deliveries = deliveries };
    }

    pub fn reset(self: *PublishSink) void {
        self.count = 0;
    }

    pub fn slice(self: *const PublishSink) []const Delivery {
        return self.deliveries[0..self.count];
    }

    fn remaining(self: *const PublishSink) usize {
        return self.deliveries.len - self.count;
    }

    fn append(self: *PublishSink, delivery: Delivery) PublishError!void {
        if (self.count >= self.deliveries.len) return error.OutputTooSmall;
        self.deliveries[self.count] = delivery;
        self.count += 1;
    }
};

pub const SubscriptionError = error{
    EmptyMask,
    InvalidSubscriberId,
    TooManySubscribers,
};

pub const PublishError = error{
    OutputTooSmall,
};

pub const RenderError = error{
    InvalidMessage,
    InvalidServerName,
    InvalidTimestamp,
    MessageTooLong,
    OutputTooSmall,
};

/// Event Spine over caller-owned subscriber slots.
pub const EventSpine = struct {
    subscribers: []Subscriber,
    count: usize = 0,

    pub fn init(subscribers: []Subscriber) EventSpine {
        return .{ .subscribers = subscribers };
    }

    pub fn subscriberSlice(self: *const EventSpine) []const Subscriber {
        return self.subscribers[0..self.count];
    }

    /// Add or replace one subscriber's category mask.
    pub fn subscribe(
        self: *EventSpine,
        subscriber_id: []const u8,
        mask: CategoryMask,
    ) SubscriptionError!void {
        try validateSubscriberId(subscriber_id);
        if (mask.isEmpty()) return error.EmptyMask;

        if (self.findIndex(subscriber_id)) |index| {
            self.subscribers[index].mask = mask;
            return;
        }

        if (self.count >= self.subscribers.len) return error.TooManySubscribers;
        self.subscribers[self.count] = .{ .id = subscriber_id, .mask = mask };
        self.count += 1;
    }

    /// Remove categories from a subscriber. The subscriber is dropped when its
    /// mask becomes empty. Missing subscribers are a successful no-op.
    pub fn unsubscribe(
        self: *EventSpine,
        subscriber_id: []const u8,
        mask: CategoryMask,
    ) SubscriptionError!bool {
        try validateSubscriberId(subscriber_id);
        if (mask.isEmpty()) return error.EmptyMask;

        const index = self.findIndex(subscriber_id) orelse return false;
        const next = self.subscribers[index].mask.exclude(mask);
        if (next.isEmpty()) {
            self.removeAt(index);
        } else {
            self.subscribers[index].mask = next;
        }
        return true;
    }

    /// Remove a subscriber entirely. Missing subscribers are a successful no-op.
    pub fn unsubscribeAll(self: *EventSpine, subscriber_id: []const u8) SubscriptionError!bool {
        try validateSubscriberId(subscriber_id);
        const index = self.findIndex(subscriber_id) orelse return false;
        self.removeAt(index);
        return true;
    }

    /// Select subscribers whose masks include the event category into `sink`.
    pub fn publish(self: *const EventSpine, event: Event, sink: *PublishSink) PublishError![]const Delivery {
        const needed = self.matchCount(event.category);
        if (needed > sink.remaining()) return error.OutputTooSmall;

        const event_mask = CategoryMask.only(event.category);
        for (self.subscriberSlice()) |subscriber| {
            if (!subscriber.mask.intersects(event_mask)) continue;
            try sink.append(.{ .subscriber_id = subscriber.id, .event = event });
        }
        return sink.slice();
    }

    fn matchCount(self: *const EventSpine, category: EventCategory) usize {
        const event_mask = CategoryMask.only(category);
        var count: usize = 0;
        for (self.subscriberSlice()) |subscriber| {
            if (subscriber.mask.intersects(event_mask)) count += 1;
        }
        return count;
    }

    fn findIndex(self: *const EventSpine, subscriber_id: []const u8) ?usize {
        for (self.subscriberSlice(), 0..) |subscriber, index| {
            if (std.mem.eql(u8, subscriber.id, subscriber_id)) return index;
        }
        return null;
    }

    fn removeAt(self: *EventSpine, index: usize) void {
        var cursor = index;
        while (cursor + 1 < self.count) : (cursor += 1) {
            self.subscribers[cursor] = self.subscribers[cursor + 1];
        }
        self.count -= 1;
        self.subscribers[self.count] = .{};
    }
};

/// Render one structured oper event wire line with IRCv3-style message tags.
pub const RenderOptions = struct {
    server_name: []const u8,
    event: Event,
    max_line_len: usize = 8191,
    include_tags: bool = true,
};

/// Build `[ @event-* ] :server NOTE EVENT <CATEGORY> :message\r\n` into `out`.
pub fn renderOperNote(options: RenderOptions, out: []u8) RenderError![]const u8 {
    try validateServerName(options.server_name);
    try validateEvent(options.event);

    const needed = try renderedLen(options);
    if (needed > options.max_line_len) return error.MessageTooLong;
    if (out.len < needed) return error.OutputTooSmall;

    var writer = SliceWriter{ .buf = out };
    if (options.include_tags) {
        try writer.append("@event-category=");
        try writer.append(options.event.category.token());
        try writer.append(";event-severity=");
        try writer.append(options.event.severity.token());
        try writer.append(";event-timestamp-ms=");
        try writer.appendInt(options.event.timestamp_ms);
        try writer.append(" ");
    }
    try writer.append(":");
    try writer.append(options.server_name);
    try writer.append(" NOTE EVENT ");
    try writer.append(options.event.category.code());
    try writer.append(" :");
    try writer.append(options.event.message);
    try writer.append("\r\n");
    return out[0..writer.len];
}

fn renderedLen(options: RenderOptions) RenderError!usize {
    var total: usize = 0;
    if (options.include_tags) {
        try addLen(&total, "@event-category=".len);
        try addLen(&total, options.event.category.token().len);
        try addLen(&total, ";event-severity=".len);
        try addLen(&total, options.event.severity.token().len);
        try addLen(&total, ";event-timestamp-ms=".len);
        try addLen(&total, decimalLen(@intCast(options.event.timestamp_ms)));
        try addLen(&total, " ".len);
    }
    try addLen(&total, ":".len);
    try addLen(&total, options.server_name.len);
    try addLen(&total, " NOTE EVENT ".len);
    try addLen(&total, options.event.category.code().len);
    try addLen(&total, " :".len);
    try addLen(&total, options.event.message.len);
    try addLen(&total, "\r\n".len);
    return total;
}

fn validateSubscriberId(id: []const u8) SubscriptionError!void {
    if (!validAtom(id)) return error.InvalidSubscriberId;
}

fn validateServerName(name: []const u8) RenderError!void {
    if (!validAtom(name)) return error.InvalidServerName;
}

fn validateEvent(event: Event) RenderError!void {
    if (event.timestamp_ms < 0) return error.InvalidTimestamp;
    if (event.message.len == 0) return error.InvalidMessage;
    for (event.message) |ch| {
        if (unsafeTextByte(ch)) return error.InvalidMessage;
    }
}

fn validAtom(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |ch| {
        if (ch <= ' ' or ch == 0x7f or ch == ':' or ch == ';') return false;
    }
    return true;
}

fn unsafeTextByte(ch: u8) bool {
    return ch < ' ' or ch == 0x7f;
}

fn decimalLen(value: u64) usize {
    var remaining = value;
    var len: usize = 1;
    while (remaining >= 10) {
        remaining /= 10;
        len += 1;
    }
    return len;
}

fn addLen(total: *usize, amount: usize) RenderError!void {
    if (amount > std.math.maxInt(usize) - total.*) return error.MessageTooLong;
    total.* += amount;
}

const SliceWriter = struct {
    buf: []u8,
    len: usize = 0,

    fn append(self: *SliceWriter, bytes: []const u8) RenderError!void {
        if (bytes.len > self.buf.len - self.len) return error.OutputTooSmall;
        @memcpy(self.buf[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendInt(self: *SliceWriter, value: i64) RenderError!void {
        const written = std.fmt.bufPrint(self.buf[self.len..], "{}", .{value}) catch {
            return error.OutputTooSmall;
        };
        self.len += written.len;
    }
};

test "category masks add remove and combine categories" {
    var mask = CategoryMask.empty();
    try std.testing.expect(mask.isEmpty());

    mask.add(.connect);
    mask.add(.flood);
    try std.testing.expect(mask.contains(.connect));
    try std.testing.expect(mask.contains(.flood));
    try std.testing.expect(!mask.contains(.debug));

    mask.remove(.connect);
    try std.testing.expect(!mask.contains(.connect));
    try std.testing.expect(mask.contains(.flood));

    const combined = mask.include(CategoryMask.fromCategories(&.{ .debug, .@"error" }));
    try std.testing.expect(combined.contains(.flood));
    try std.testing.expect(combined.contains(.debug));
    try std.testing.expect(combined.contains(.@"error"));
}

test "multi-subscriber fan-out preserves subscription order" {
    var subscribers: [4]Subscriber = [_]Subscriber{.{}} ** 4;
    var spine = EventSpine.init(&subscribers);

    try spine.subscribe("oper-a", CategoryMask.fromCategories(&.{ .connect, .flood }));
    try spine.subscribe("oper-b", CategoryMask.only(.flood));
    try spine.subscribe("oper-c", CategoryMask.only(.debug));

    var deliveries: [4]Delivery = undefined;
    var sink = PublishSink.init(&deliveries);
    const selected = try spine.publish(.{
        .category = .flood,
        .severity = .warn,
        .timestamp_ms = 1200,
        .message = "Flood limiter tripped",
    }, &sink);

    try std.testing.expectEqual(@as(usize, 2), selected.len);
    try std.testing.expectEqualStrings("oper-a", selected[0].subscriber_id);
    try std.testing.expectEqualStrings("oper-b", selected[1].subscriber_id);
    try std.testing.expectEqual(EventCategory.flood, selected[0].event.category);
    try std.testing.expectEqual(EventSeverity.warn, selected[1].event.severity);
}

test "unsubscribe removes selected categories and drops empty subscribers" {
    var subscribers: [3]Subscriber = [_]Subscriber{.{}} ** 3;
    var spine = EventSpine.init(&subscribers);

    try spine.subscribe("oper-a", CategoryMask.fromCategories(&.{ .connect, .flood }));
    try std.testing.expect(try spine.unsubscribe("oper-a", CategoryMask.only(.connect)));
    try std.testing.expectEqual(@as(usize, 1), spine.subscriberSlice().len);
    try std.testing.expect(!spine.subscriberSlice()[0].mask.contains(.connect));
    try std.testing.expect(spine.subscriberSlice()[0].mask.contains(.flood));

    try std.testing.expect(try spine.unsubscribe("oper-a", CategoryMask.only(.flood)));
    try std.testing.expectEqual(@as(usize, 0), spine.subscriberSlice().len);
    try std.testing.expect(!try spine.unsubscribeAll("oper-a"));
}

test "render output is structured NOTE event line with tags" {
    var out: [256]u8 = undefined;
    const line = try renderOperNote(.{
        .server_name = "orochi.local",
        .event = .{
            .category = .server_link,
            .severity = .notice,
            .timestamp_ms = 17000042,
            .message = "mesh link established",
        },
    }, &out);

    try std.testing.expectEqualStrings(
        "@event-category=server_link;event-severity=notice;event-timestamp-ms=17000042 :orochi.local NOTE EVENT SERVER_LINK :mesh link established\r\n",
        line,
    );
}

test "render output can omit message-tags prefix" {
    var out: [256]u8 = undefined;
    const line = try renderOperNote(.{
        .server_name = "orochi.local",
        .event = .{
            .category = .announce,
            .severity = .notice,
            .timestamp_ms = 17000042,
            .message = "oper announcement",
        },
        .include_tags = false,
    }, &out);

    try std.testing.expectEqualStrings(
        ":orochi.local NOTE EVENT ANNOUNCE :oper announcement\r\n",
        line,
    );
}

test "publish with no matching subscribers returns empty selection" {
    var subscribers: [2]Subscriber = [_]Subscriber{.{}} ** 2;
    var spine = EventSpine.init(&subscribers);

    try spine.subscribe("oper-a", CategoryMask.only(.debug));

    var deliveries: [2]Delivery = undefined;
    var sink = PublishSink.init(&deliveries);
    const selected = try spine.publish(.{
        .category = .kill,
        .severity = .notice,
        .timestamp_ms = 33,
        .message = "user removed",
    }, &sink);

    try std.testing.expectEqual(@as(usize, 0), selected.len);
    try std.testing.expectEqual(@as(usize, 0), sink.count);
}

test "publish reports too-small sinks before partial fan-out" {
    var subscribers: [2]Subscriber = [_]Subscriber{.{}} ** 2;
    var spine = EventSpine.init(&subscribers);

    try spine.subscribe("oper-a", CategoryMask.only(.announce));
    try spine.subscribe("oper-b", CategoryMask.only(.announce));

    var deliveries: [1]Delivery = undefined;
    var sink = PublishSink.init(&deliveries);

    try std.testing.expectError(error.OutputTooSmall, spine.publish(.{
        .category = .announce,
        .severity = .info,
        .timestamp_ms = 50,
        .message = "maintenance window",
    }, &sink));
    try std.testing.expectEqual(@as(usize, 0), sink.count);
}

test "renderer validates unsafe wire text and caller-owned output size" {
    var out: [64]u8 = undefined;

    try std.testing.expectError(error.InvalidMessage, renderOperNote(.{
        .server_name = "orochi.local",
        .event = .{
            .category = .@"error",
            .severity = .@"error",
            .timestamp_ms = 1,
            .message = "bad\nline",
        },
    }, &out));

    try std.testing.expectError(error.OutputTooSmall, renderOperNote(.{
        .server_name = "orochi.local",
        .event = .{
            .category = .connect,
            .severity = .info,
            .timestamp_ms = 1,
            .message = "connected",
        },
    }, out[0..8]));
}
