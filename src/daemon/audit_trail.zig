const std = @import("std");

pub const AuditTrail = struct {
    pub const cap: usize = 1024;

    pub const Record = struct {
        seq: u64,
        actor: []u8,
        event: []u8,
        at_ms: i64,
    };

    allocator: std.mem.Allocator,
    records: [cap]?Record,
    start: usize,
    count: usize,
    next_seq: u64,

    pub fn init(allocator: std.mem.Allocator) AuditTrail {
        return .{
            .allocator = allocator,
            .records = [_]?Record{null} ** cap,
            .start = 0,
            .count = 0,
            .next_seq = 1,
        };
    }

    pub fn deinit(self: *AuditTrail) void {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const index = (self.start + i) % cap;
            if (self.records[index]) |record| {
                self.freeRecord(record);
                self.records[index] = null;
            }
        }
        self.count = 0;
    }

    pub fn append(self: *AuditTrail, actor: []const u8, event: []const u8, at_ms: i64) !u64 {
        const owned_actor = try self.allocator.dupe(u8, actor);
        errdefer self.allocator.free(owned_actor);

        const owned_event = try self.allocator.dupe(u8, event);
        errdefer self.allocator.free(owned_event);

        const seq = self.next_seq;
        self.next_seq = std.math.add(u64, self.next_seq, 1) catch std.math.maxInt(u64);

        var index: usize = undefined;
        if (self.count < cap) {
            index = (self.start + self.count) % cap;
            self.count += 1;
        } else {
            index = self.start;
            if (self.records[index]) |old| self.freeRecord(old);
            self.start = (self.start + 1) % cap;
        }

        self.records[index] = .{
            .seq = seq,
            .actor = owned_actor,
            .event = owned_event,
            .at_ms = at_ms,
        };
        return seq;
    }

    pub fn since(self: *AuditTrail, seq: u64, out: []Record) usize {
        var written: usize = 0;
        var i: usize = 0;
        while (i < self.count and written < out.len) : (i += 1) {
            const index = (self.start + i) % cap;
            const record = self.records[index] orelse continue;
            if (record.seq > seq) {
                out[written] = record;
                written += 1;
            }
        }
        return written;
    }

    pub fn latestSeq(self: *AuditTrail) u64 {
        if (self.next_seq == 0) return std.math.maxInt(u64);
        return self.next_seq - 1;
    }

    fn freeRecord(self: *AuditTrail, record: Record) void {
        self.allocator.free(record.actor);
        self.allocator.free(record.event);
    }
};

test "AuditTrail appends records with increasing sequences" {
    var trail = AuditTrail.init(std.testing.allocator);
    defer trail.deinit();

    const first = try trail.append("alice", "login", 10);
    const second = try trail.append("alice", "join", 20);

    try std.testing.expectEqual(@as(u64, 1), first);
    try std.testing.expectEqual(@as(u64, 2), second);
    try std.testing.expectEqual(second, trail.latestSeq());
}

test "AuditTrail returns records after sequence" {
    var trail = AuditTrail.init(std.testing.allocator);
    defer trail.deinit();

    _ = try trail.append("alice", "one", 1);
    _ = try trail.append("bob", "two", 2);
    _ = try trail.append("carol", "three", 3);

    var out: [2]AuditTrail.Record = undefined;
    const count = trail.since(1, out[0..]);

    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("bob", out[0].actor);
    try std.testing.expectEqualStrings("three", out[1].event);
}

test "AuditTrail ring keeps newest records" {
    var trail = AuditTrail.init(std.testing.allocator);
    defer trail.deinit();

    var i: usize = 0;
    while (i < AuditTrail.cap + 2) : (i += 1) {
        _ = try trail.append("actor", "event", @intCast(i));
    }

    var out: [AuditTrail.cap]AuditTrail.Record = undefined;
    const count = trail.since(0, out[0..]);

    try std.testing.expectEqual(@as(usize, AuditTrail.cap), count);
    try std.testing.expectEqual(@as(u64, 3), out[0].seq);
    try std.testing.expectEqual(trail.latestSeq(), out[count - 1].seq);
}

