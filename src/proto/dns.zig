//! DNS wire codec and resolver cache.
//!
//! The codec is intentionally transport-free: callers provide complete DNS
//! messages and output buffers. Live UDP resolution belongs behind the reactor
//! I/O seam and is left as a documented TODO below.
const std = @import("std");

pub const max_message_len: usize = 512;
pub const max_domain_text_len: usize = 253;
pub const max_cache_addrs: usize = 8;
pub const class_in: u16 = 1;

pub const EncodeError = error{
    OutputTooSmall,
    NameTooLong,
    InvalidName,
    TooManyQuestions,
    TooManyAnswers,
    UnsupportedType,
};

pub const DecodeError = error{
    TruncatedMessage,
    OversizeMessage,
    InvalidName,
    NameTooLong,
    CompressionLoop,
    TooManyQuestions,
    TooManyAnswers,
    UnsupportedType,
    UnsupportedClass,
    UnsupportedSection,
    MalformedRData,
    TrailingBytes,
};

pub const CacheError = error{
    TooManyAddresses,
} || std.mem.Allocator.Error;

pub const LiveUdpError = error{
    LiveUdpResolverTodo,
};

pub const RecordType = enum(u16) {
    a = 1,
    ptr = 12,
    aaaa = 28,

    pub fn fromInt(value: u16) DecodeError!RecordType {
        return switch (value) {
            1 => .a,
            12 => .ptr,
            28 => .aaaa,
            else => error.UnsupportedType,
        };
    }
};

pub const Header = struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,

    pub fn isResponse(self: Header) bool {
        return (self.flags & 0x8000) != 0;
    }

    pub fn rcode(self: Header) u4 {
        return @intCast(self.flags & 0x000f);
    }
};

pub const Name = struct {
    bytes: [max_domain_text_len]u8 = [_]u8{0} ** max_domain_text_len,
    len: usize = 0,

    pub fn fromSlice(text: []const u8) EncodeError!Name {
        if (text.len > max_domain_text_len) return error.NameTooLong;
        var name = Name{};
        @memcpy(name.bytes[0..text.len], text);
        name.len = text.len;
        return name;
    }

    pub fn slice(self: *const Name) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Address = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,

    fn key(self: Address) AddressKey {
        var out = AddressKey{ .family = .ipv4, .bytes = [_]u8{0} ** 16 };
        switch (self) {
            .ipv4 => |bytes| {
                out.family = .ipv4;
                @memcpy(out.bytes[0..4], &bytes);
            },
            .ipv6 => |bytes| {
                out.family = .ipv6;
                @memcpy(out.bytes[0..16], &bytes);
            },
        }
        return out;
    }
};

pub const Question = struct {
    name: Name,
    qtype: RecordType,
    qclass: u16 = class_in,
};

pub const RData = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,
    ptr: Name,
};

pub const ResourceRecord = struct {
    name: Name,
    rr_type: RecordType,
    class: u16,
    ttl: u32,
    data: RData,
};

pub const Query = struct {
    name: []const u8,
    qtype: RecordType,
    qclass: u16 = class_in,
};

pub const AnswerData = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,
    ptr: []const u8,
};

pub const Answer = struct {
    name: []const u8,
    rr_type: RecordType,
    class: u16 = class_in,
    ttl: u32,
    data: AnswerData,
};

pub const BuildMessage = struct {
    id: u16,
    response: bool = false,
    recursion_desired: bool = true,
    recursion_available: bool = false,
    rcode: u4 = 0,
    questions: []const Query = &[_]Query{},
    answers: []const Answer = &[_]Answer{},
};

pub fn Message(comptime max_questions: usize, comptime max_answers: usize) type {
    return struct {
        header: Header,
        questions: [max_questions]Question = undefined,
        question_count: usize = 0,
        answers: [max_answers]ResourceRecord = undefined,
        answer_count: usize = 0,

        pub fn questionSlice(self: *const @This()) []const Question {
            return self.questions[0..self.question_count];
        }

        pub fn answerSlice(self: *const @This()) []const ResourceRecord {
            return self.answers[0..self.answer_count];
        }
    };
}

/// Encode any supported query/response message without name compression.
pub fn encodeMessage(out: []u8, msg: BuildMessage) EncodeError![]const u8 {
    if (msg.questions.len > std.math.maxInt(u16)) return error.TooManyQuestions;
    if (msg.answers.len > std.math.maxInt(u16)) return error.TooManyAnswers;

    var w = Writer{ .buf = out };
    try w.putU16(msg.id);
    var flags: u16 = @as(u16, msg.rcode);
    if (msg.response) flags |= 0x8000;
    if (msg.recursion_desired) flags |= 0x0100;
    if (msg.recursion_available) flags |= 0x0080;
    try w.putU16(flags);
    try w.putU16(@intCast(msg.questions.len));
    try w.putU16(@intCast(msg.answers.len));
    try w.putU16(0);
    try w.putU16(0);

    for (msg.questions) |question| {
        try encodeName(&w, question.name);
        try w.putU16(@intFromEnum(question.qtype));
        try w.putU16(question.qclass);
    }

    for (msg.answers) |answer| {
        try encodeName(&w, answer.name);
        try w.putU16(@intFromEnum(answer.rr_type));
        try w.putU16(answer.class);
        try w.putU32(answer.ttl);
        const rdlen_at = w.pos;
        try w.putU16(0);
        const rdata_start = w.pos;
        switch (answer.data) {
            .a => |bytes| {
                if (answer.rr_type != .a) return error.UnsupportedType;
                try w.putBytes(&bytes);
            },
            .aaaa => |bytes| {
                if (answer.rr_type != .aaaa) return error.UnsupportedType;
                try w.putBytes(&bytes);
            },
            .ptr => |ptr| {
                if (answer.rr_type != .ptr) return error.UnsupportedType;
                try encodeName(&w, ptr);
            },
        }
        std.mem.writeInt(u16, out[rdlen_at..][0..2], @intCast(w.pos - rdata_start), .big);
    }

    return out[0..w.pos];
}

/// Encode a single-question DNS query.
pub fn encodeQuery(out: []u8, id: u16, name: []const u8, qtype: RecordType) EncodeError![]const u8 {
    const question = Query{ .name = name, .qtype = qtype };
    return encodeMessage(out, .{ .id = id, .questions = (&question)[0..1] });
}

/// Encode a PTR query for an IPv4 or IPv6 reverse-DNS name.
pub fn encodePtrQuery(out: []u8, id: u16, address: Address) EncodeError![]const u8 {
    var name_buf: [max_domain_text_len]u8 = undefined;
    const name = try reverseName(&name_buf, address);
    return encodeQuery(out, id, name, .ptr);
}

/// Parse a DNS message into fixed-capacity caller-selected storage.
pub fn parseMessage(
    comptime max_questions: usize,
    comptime max_answers: usize,
    packet: []const u8,
) DecodeError!Message(max_questions, max_answers) {
    if (packet.len > max_message_len) return error.OversizeMessage;
    if (packet.len < 12) return error.TruncatedMessage;

    const header = Header{
        .id = readU16(packet, 0),
        .flags = readU16(packet, 2),
        .qdcount = readU16(packet, 4),
        .ancount = readU16(packet, 6),
        .nscount = readU16(packet, 8),
        .arcount = readU16(packet, 10),
    };
    // Authority/additional sections are tolerated: we parse the answer section
    // and ignore the rest. This lets us extract A/AAAA records from CNAME-chained
    // or EDNS responses (recursive resolvers return the resolved address records
    // alongside CNAME records the answer section).
    if (header.qdcount > max_questions) return error.TooManyQuestions;

    var msg = Message(max_questions, max_answers){
        .header = header,
        .question_count = header.qdcount,
        .answer_count = header.ancount,
    };
    var pos: usize = 12;

    if (max_questions > 0) {
        var qi: usize = 0;
        while (qi < msg.question_count) : (qi += 1) {
            var name = Name{};
            pos = try decodeName(packet, pos, &name);
            if (pos + 4 > packet.len) return error.TruncatedMessage;
            const qtype = try RecordType.fromInt(readU16(packet, pos));
            const qclass = readU16(packet, pos + 2);
            if (qclass != class_in) return error.UnsupportedClass;
            msg.questions[qi] = .{ .name = name, .qtype = qtype, .qclass = qclass };
            pos += 4;
        }
    }

    // Walk every answer record to keep `pos` correct, but only STORE the record
    // types we model (A/AAAA/PTR). Unknown types (e.g. CNAME) are skipped, so a
    // CNAME chain still yields its terminal address records.
    var stored: usize = 0;
    var ai: usize = 0;
    while (ai < header.ancount) : (ai += 1) {
        var name = Name{};
        pos = try decodeName(packet, pos, &name);
        if (pos + 10 > packet.len) return error.TruncatedMessage;

        const raw_type = readU16(packet, pos);
        const class = readU16(packet, pos + 2);
        const ttl = readU32(packet, pos + 4);
        const rdlen = readU16(packet, pos + 8);
        pos += 10;
        if (pos + rdlen > packet.len) return error.TruncatedMessage;
        const rdata_start = pos;
        const rdata_end = pos + rdlen;
        pos = rdata_end;

        const rr_type = RecordType.fromInt(raw_type) catch continue; // skip unknown (CNAME, ...)
        if (class != class_in) continue;
        if (max_answers == 0 or stored >= max_answers) continue;

        const data = switch (rr_type) {
            .a => blk: {
                if (rdlen != 4) return error.MalformedRData;
                break :blk RData{ .a = packet[rdata_start..][0..4].* };
            },
            .aaaa => blk: {
                if (rdlen != 16) return error.MalformedRData;
                break :blk RData{ .aaaa = packet[rdata_start..][0..16].* };
            },
            .ptr => blk: {
                var ptr_name = Name{};
                const ptr_next = try decodeName(packet, rdata_start, &ptr_name);
                if (ptr_next != rdata_end) return error.MalformedRData;
                break :blk RData{ .ptr = ptr_name };
            },
        };

        msg.answers[stored] = .{
            .name = name,
            .rr_type = rr_type,
            .class = class,
            .ttl = ttl,
            .data = data,
        };
        stored += 1;
    }
    msg.answer_count = stored;

    return msg;
}

/// Build the canonical reverse-DNS name for an address into caller storage.
pub fn reverseName(out: []u8, address: Address) EncodeError![]const u8 {
    var w = Writer{ .buf = out };
    switch (address) {
        .ipv4 => |bytes| {
            try w.print("{d}.{d}.{d}.{d}.in-addr.arpa", .{ bytes[3], bytes[2], bytes[1], bytes[0] });
        },
        .ipv6 => |bytes| {
            const hex = "0123456789abcdef";
            var i: usize = 16;
            while (i > 0) {
                i -= 1;
                const b = bytes[i];
                try w.putByte(hex[b & 0x0f]);
                try w.putByte('.');
                try w.putByte(hex[b >> 4]);
                try w.putByte('.');
            }
            try w.putBytes("ip6.arpa");
        },
    }
    return out[0..w.pos];
}

/// Placeholder for the real resolver transport.
///
/// TODO: send encoded queries through the reactor UDP backend once Ringlane
/// exposes datagram I/O. Tests intentionally exercise only pure build/parse and
/// cache behavior.
pub fn sendUdpQueryTodo(_: []const u8, _: []u8) LiveUdpError![]const u8 {
    return error.LiveUdpResolverTodo;
}

pub const HostCacheEntry = struct {
    addrs: [max_cache_addrs]Address = undefined,
    addrs_len: usize = 0,
    expires_ms: i64 = 0,

    pub fn addressSlice(self: *const HostCacheEntry) []const Address {
        return self.addrs[0..self.addrs_len];
    }
};

pub const PtrCacheEntry = struct {
    ptr: []const u8,
    expires_ms: i64,
};

/// TTL cache for forward and reverse resolver results.
pub const Cache = struct {
    allocator: std.mem.Allocator,
    hosts: std.StringHashMap(HostCacheEntry),
    ptrs: std.AutoHashMap(AddressKey, PtrCacheEntry),

    pub fn init(allocator: std.mem.Allocator) Cache {
        return .{
            .allocator = allocator,
            .hosts = std.StringHashMap(HostCacheEntry).init(allocator),
            .ptrs = std.AutoHashMap(AddressKey, PtrCacheEntry).init(allocator),
        };
    }

    pub fn deinit(self: *Cache) void {
        var hit = self.hosts.iterator();
        while (hit.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.hosts.deinit();

        var pit = self.ptrs.iterator();
        while (pit.next()) |entry| {
            self.allocator.free(entry.value_ptr.ptr);
        }
        self.ptrs.deinit();
    }

    pub fn putHost(
        self: *Cache,
        now_ms: i64,
        host: []const u8,
        addrs: []const Address,
        ttl_seconds: u32,
    ) CacheError!void {
        if (addrs.len > max_cache_addrs) return error.TooManyAddresses;

        var value = HostCacheEntry{ .addrs_len = addrs.len, .expires_ms = expiresAt(now_ms, ttl_seconds) };
        for (addrs, 0..) |addr, i| value.addrs[i] = addr;

        const gop = try self.hosts.getOrPut(host);
        if (gop.found_existing) {
            gop.value_ptr.* = value;
            return;
        }

        gop.key_ptr.* = try self.allocator.dupe(u8, host);
        errdefer {
            const owned_key = gop.key_ptr.*;
            _ = self.hosts.remove(owned_key);
            self.allocator.free(owned_key);
        }
        gop.value_ptr.* = value;
    }

    pub fn getHost(self: *Cache, now_ms: i64, host: []const u8) ?HostCacheEntry {
        const entry = self.hosts.getEntry(host) orelse return null;
        if (isExpired(now_ms, entry.value_ptr.expires_ms)) {
            const owned_key = entry.key_ptr.*;
            _ = self.hosts.remove(owned_key);
            self.allocator.free(owned_key);
            return null;
        }
        return entry.value_ptr.*;
    }

    pub fn putPtr(
        self: *Cache,
        now_ms: i64,
        address: Address,
        ptr: []const u8,
        ttl_seconds: u32,
    ) CacheError!void {
        const key = address.key();
        const value = PtrCacheEntry{
            .ptr = try self.allocator.dupe(u8, ptr),
            .expires_ms = expiresAt(now_ms, ttl_seconds),
        };
        errdefer self.allocator.free(value.ptr);

        const gop = try self.ptrs.getOrPut(key);
        if (gop.found_existing) {
            self.allocator.free(gop.value_ptr.ptr);
            gop.value_ptr.* = value;
            return;
        }
        gop.value_ptr.* = value;
    }

    pub fn getPtr(self: *Cache, now_ms: i64, address: Address) ?[]const u8 {
        const key = address.key();
        const entry = self.ptrs.getEntry(key) orelse return null;
        if (isExpired(now_ms, entry.value_ptr.expires_ms)) {
            const removed = self.ptrs.fetchRemove(key).?;
            self.allocator.free(removed.value.ptr);
            return null;
        }
        return entry.value_ptr.ptr;
    }

    pub fn pruneExpired(self: *Cache, now_ms: i64) void {
        var host_keys: [32][]const u8 = undefined;
        while (true) {
            var count: usize = 0;
            var it = self.hosts.iterator();
            while (it.next()) |entry| {
                if (isExpired(now_ms, entry.value_ptr.expires_ms)) {
                    host_keys[count] = entry.key_ptr.*;
                    count += 1;
                    if (count == host_keys.len) break;
                }
            }
            if (count == 0) break;
            for (host_keys[0..count]) |key| {
                _ = self.hosts.remove(key);
                self.allocator.free(key);
            }
        }

        var ptr_keys: [32]AddressKey = undefined;
        while (true) {
            var count: usize = 0;
            var it = self.ptrs.iterator();
            while (it.next()) |entry| {
                if (isExpired(now_ms, entry.value_ptr.expires_ms)) {
                    ptr_keys[count] = entry.key_ptr.*;
                    count += 1;
                    if (count == ptr_keys.len) break;
                }
            }
            if (count == 0) break;
            for (ptr_keys[0..count]) |key| {
                const removed = self.ptrs.fetchRemove(key).?;
                self.allocator.free(removed.value.ptr);
            }
        }
    }
};

const AddressFamily = enum { ipv4, ipv6 };

const AddressKey = struct {
    family: AddressFamily,
    bytes: [16]u8,
};

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn putByte(self: *Writer, byte: u8) EncodeError!void {
        if (self.pos >= self.buf.len) return error.OutputTooSmall;
        self.buf[self.pos] = byte;
        self.pos += 1;
    }

    fn putBytes(self: *Writer, bytes: []const u8) EncodeError!void {
        if (self.pos + bytes.len > self.buf.len) return error.OutputTooSmall;
        @memcpy(self.buf[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    fn putU16(self: *Writer, value: u16) EncodeError!void {
        if (self.pos + 2 > self.buf.len) return error.OutputTooSmall;
        std.mem.writeInt(u16, self.buf[self.pos..][0..2], value, .big);
        self.pos += 2;
    }

    fn putU32(self: *Writer, value: u32) EncodeError!void {
        if (self.pos + 4 > self.buf.len) return error.OutputTooSmall;
        std.mem.writeInt(u32, self.buf[self.pos..][0..4], value, .big);
        self.pos += 4;
    }

    fn print(self: *Writer, comptime fmt: []const u8, args: anytype) EncodeError!void {
        const written = std.fmt.bufPrint(self.buf[self.pos..], fmt, args) catch return error.OutputTooSmall;
        self.pos += written.len;
    }
};

fn encodeName(w: *Writer, raw_name: []const u8) EncodeError!void {
    var name = raw_name;
    if (name.len == 0) return error.InvalidName;
    if (name.len == 1 and name[0] == '.') {
        try w.putByte(0);
        return;
    }
    if (name[name.len - 1] == '.') name = name[0 .. name.len - 1];
    if (name.len == 0 or name.len > max_domain_text_len) return error.NameTooLong;

    var wire_len: usize = 1;
    var cursor: usize = 0;
    while (cursor <= name.len) {
        const next = findByte(name, cursor, '.') orelse name.len;
        if (next == cursor) return error.InvalidName;
        const label = name[cursor..next];
        if (label.len > 63) return error.NameTooLong;
        for (label) |ch| {
            if (!isLabelByte(ch)) return error.InvalidName;
        }
        wire_len += 1 + label.len;
        if (wire_len > 255) return error.NameTooLong;
        try w.putByte(@intCast(label.len));
        try w.putBytes(label);
        if (next == name.len) break;
        cursor = next + 1;
    }
    try w.putByte(0);
}

fn decodeName(packet: []const u8, start: usize, out: *Name) DecodeError!usize {
    if (start >= packet.len) return error.TruncatedMessage;

    var seen = [_]bool{false} ** max_message_len;
    var cursor = start;
    var next_offset: ?usize = null;
    var wire_len: usize = 0;
    var text_len: usize = 0;

    while (true) {
        if (cursor >= packet.len) return error.TruncatedMessage;
        if (seen[cursor]) return error.CompressionLoop;
        seen[cursor] = true;

        const len = packet[cursor];
        if ((len & 0xc0) == 0xc0) {
            if (cursor + 1 >= packet.len) return error.TruncatedMessage;
            const ptr = (@as(usize, len & 0x3f) << 8) | packet[cursor + 1];
            if (ptr >= packet.len) return error.InvalidName;
            if (next_offset == null) next_offset = cursor + 2;
            wire_len += 2;
            if (wire_len > 255) return error.NameTooLong;
            cursor = ptr;
            continue;
        }
        if ((len & 0xc0) != 0) return error.InvalidName;

        cursor += 1;
        wire_len += 1 + len;
        if (wire_len > 255) return error.NameTooLong;
        if (len == 0) {
            if (text_len == 0) {
                out.bytes[0] = '.';
                out.len = 1;
            } else {
                out.len = text_len;
            }
            return next_offset orelse cursor;
        }
        if (len > 63) return error.NameTooLong;
        if (cursor + len > packet.len) return error.TruncatedMessage;
        for (packet[cursor..][0..len]) |ch| {
            if (!isLabelByte(ch)) return error.InvalidName;
        }

        if (text_len != 0) {
            if (text_len >= out.bytes.len) return error.NameTooLong;
            out.bytes[text_len] = '.';
            text_len += 1;
        }
        if (text_len + len > out.bytes.len) return error.NameTooLong;
        @memcpy(out.bytes[text_len..][0..len], packet[cursor..][0..len]);
        text_len += len;
        cursor += len;
    }
}

fn isLabelByte(ch: u8) bool {
    return switch (ch) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '_' => true,
        else => false,
    };
}

fn findByte(bytes: []const u8, start: usize, needle: u8) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
}

fn readU16(bytes: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, bytes[offset..][0..2], .big);
}

fn readU32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .big);
}

fn expiresAt(now_ms: i64, ttl_seconds: u32) i64 {
    return now_ms + @as(i64, @intCast(ttl_seconds)) * 1000;
}

fn isExpired(now_ms: i64, expires_ms: i64) bool {
    return now_ms >= expires_ms;
}

test "encodes and parses A query and response round trip" {
    var buf: [max_message_len]u8 = undefined;
    const query = try encodeQuery(&buf, 0x1234, "example.com", .a);
    const parsed_query = try parseMessage(1, 0, query);
    try std.testing.expectEqual(@as(u16, 0x1234), parsed_query.header.id);
    try std.testing.expect(!parsed_query.header.isResponse());
    try std.testing.expectEqualStrings("example.com", parsed_query.questions[0].name.slice());
    try std.testing.expectEqual(RecordType.a, parsed_query.questions[0].qtype);

    const q = Query{ .name = "example.com", .qtype = .a };
    const answer = Answer{
        .name = "example.com",
        .rr_type = .a,
        .ttl = 60,
        .data = .{ .a = .{ 93, 184, 216, 34 } },
    };
    const response = try encodeMessage(&buf, .{
        .id = 0x1234,
        .response = true,
        .recursion_available = true,
        .questions = (&q)[0..1],
        .answers = (&answer)[0..1],
    });
    const parsed_response = try parseMessage(1, 1, response);
    try std.testing.expect(parsed_response.header.isResponse());
    try std.testing.expectEqual(@as(u32, 60), parsed_response.answers[0].ttl);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 93, 184, 216, 34 }, &parsed_response.answers[0].data.a);
}

test "encodes and parses PTR query and response round trip" {
    var buf: [max_message_len]u8 = undefined;
    const query = try encodePtrQuery(&buf, 7, .{ .ipv4 = .{ 127, 0, 0, 1 } });
    const parsed_query = try parseMessage(1, 0, query);
    try std.testing.expectEqualStrings("1.0.0.127.in-addr.arpa", parsed_query.questions[0].name.slice());
    try std.testing.expectEqual(RecordType.ptr, parsed_query.questions[0].qtype);

    const q = Query{ .name = "1.0.0.127.in-addr.arpa", .qtype = .ptr };
    const answer = Answer{
        .name = "1.0.0.127.in-addr.arpa",
        .rr_type = .ptr,
        .ttl = 300,
        .data = .{ .ptr = "localhost" },
    };
    const response = try encodeMessage(&buf, .{
        .id = 7,
        .response = true,
        .questions = (&q)[0..1],
        .answers = (&answer)[0..1],
    });
    const parsed_response = try parseMessage(1, 1, response);
    try std.testing.expectEqualStrings("localhost", parsed_response.answers[0].data.ptr.slice());
}

test "parses compressed answer name and rejects compression loops" {
    const packet = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x2a, 0x00, 0x04, 192,  0,    2,    1,
    };
    const parsed = try parseMessage(1, 1, &packet);
    try std.testing.expectEqualStrings("example.com", parsed.answers[0].name.slice());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, &parsed.answers[0].data.a);

    const loop = [_]u8{
        0xaa, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
    };
    try std.testing.expectError(error.CompressionLoop, parseMessage(1, 0, &loop));
}

test "skips CNAME records and returns the terminal A record" {
    // Header: id=0x1234, response, qd=1, an=2 (CNAME + A), ns=0, ar=0.
    const packet = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        // question: example.com A IN
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
        // answer 1: name=ptr(0x0c), type CNAME(5), IN, ttl, rdlen=2, rdata=ptr(0x0c)
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x2a, 0x00, 0x02, 0xc0, 0x0c,
        // answer 2: name=ptr(0x0c), type A(1), IN, ttl, rdlen=4, rdata=192.0.2.1
        0xc0, 0x0c, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x04, 192,  0,    2,    1,
    };
    const parsed = try parseMessage(1, max_cache_addrs, &packet);
    try std.testing.expectEqual(@as(usize, 1), parsed.answer_count);
    try std.testing.expectEqual(RecordType.a, parsed.answers[0].rr_type);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, &parsed.answers[0].data.a);
}

test "tolerates additional/authority records after the answer section" {
    // an=1 (A) followed by ar=1 (an A-shaped record we should ignore safely).
    const packet = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
        // answer: A 192.0.2.1
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x2a, 0x00, 0x04, 192,  0,    2,    1,
        // additional: (ignored) A 203.0.113.9
           0xc0, 0x0c, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x04, 203,  0,    113,
        9,
    };
    const parsed = try parseMessage(1, max_cache_addrs, &packet);
    try std.testing.expectEqual(@as(usize, 1), parsed.answer_count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, &parsed.answers[0].data.a);
}

test "rejects truncated and oversize messages" {
    try std.testing.expectError(error.TruncatedMessage, parseMessage(1, 1, &[_]u8{ 1, 2, 3 }));

    var oversize = [_]u8{0} ** (max_message_len + 1);
    try std.testing.expectError(error.OversizeMessage, parseMessage(1, 1, &oversize));

    const bad_name = [_]u8{
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 't',  'e',
    };
    try std.testing.expectError(error.TruncatedMessage, parseMessage(1, 0, &bad_name));
}

test "cache returns hits and expires forward and reverse entries" {
    var cache = Cache.init(std.testing.allocator);
    defer cache.deinit();

    const addrs = [_]Address{
        .{ .ipv4 = .{ 127, 0, 0, 1 } },
        .{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
    };
    try cache.putHost(1000, "localhost", &addrs, 2);
    const hit = cache.getHost(1999, "localhost").?;
    try std.testing.expectEqual(@as(usize, 2), hit.addrs_len);
    try std.testing.expect(cache.getHost(3000, "localhost") == null);

    try cache.putPtr(4000, addrs[0], "localhost", 1);
    try std.testing.expectEqualStrings("localhost", cache.getPtr(4999, addrs[0]).?);
    try std.testing.expect(cache.getPtr(5000, addrs[0]) == null);
}
