const std = @import("std");

pub const Variant = enum {
    ncs,
    rfc9562,
    microsoft,
    future,
};

pub const ParseError = error{
    InvalidLength,
    InvalidHyphen,
    InvalidCharacter,
};

pub const Uuid = struct {
    bytes: [16]u8,

    pub fn toString(self: Uuid) [36]u8 {
        return formatBytes(self.bytes);
    }

    pub fn parse(text: []const u8) ParseError!Uuid {
        return parseText(text);
    }

    pub fn version(self: Uuid) u4 {
        return @intCast(self.bytes[6] >> 4);
    }

    pub fn variant(self: Uuid) Variant {
        const octet = self.bytes[8];
        if ((octet & 0x80) == 0x00) return .ncs;
        if ((octet & 0xc0) == 0x80) return .rfc9562;
        if ((octet & 0xe0) == 0xc0) return .microsoft;
        return .future;
    }

    pub fn unixMilliseconds(self: Uuid) ?u64 {
        if (self.version() != 7) return null;

        var ms: u64 = 0;
        for (self.bytes[0..6]) |byte| {
            ms = (ms << 8) | byte;
        }
        return ms;
    }

    pub fn eql(self: Uuid, other: Uuid) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    pub fn compare(self: Uuid, other: Uuid) std.math.Order {
        return std.mem.order(u8, &self.bytes, &other.bytes);
    }
};

const max_unix_ms: u64 = (1 << 48) - 1;
const random_prefix_mask: u74 = (1 << 42) - 1;
const sequence_mask: u74 = (1 << 32) - 1;

var v7_mutex: std.atomic.Mutex = .unlocked;
var v7_has_last: bool = false;
var v7_last_ms: u64 = 0;
var v7_counter: u74 = 0;

pub fn v4(random: std.Random) Uuid {
    var uuid: Uuid = .{ .bytes = undefined };
    random.bytes(&uuid.bytes);
    uuid.bytes[6] = (uuid.bytes[6] & 0x0f) | 0x40;
    uuid.bytes[8] = (uuid.bytes[8] & 0x3f) | 0x80;
    return uuid;
}

pub fn v7(unix_ms: u64, random: std.Random) Uuid {
    const ms = unix_ms & max_unix_ms;
    const counter = nextV7Counter(ms, random);

    var uuid: Uuid = .{ .bytes = undefined };
    uuid.bytes[0] = @intCast((ms >> 40) & 0xff);
    uuid.bytes[1] = @intCast((ms >> 32) & 0xff);
    uuid.bytes[2] = @intCast((ms >> 24) & 0xff);
    uuid.bytes[3] = @intCast((ms >> 16) & 0xff);
    uuid.bytes[4] = @intCast((ms >> 8) & 0xff);
    uuid.bytes[5] = @intCast(ms & 0xff);

    const rand_a: u12 = @intCast(counter >> 62);
    const rand_b: u62 = @intCast(counter & ((@as(u74, 1) << 62) - 1));

    uuid.bytes[6] = 0x70 | @as(u8, @intCast(rand_a >> 8));
    uuid.bytes[7] = @intCast(rand_a & 0xff);
    uuid.bytes[8] = 0x80 | @as(u8, @intCast(rand_b >> 56));
    uuid.bytes[9] = @intCast((rand_b >> 48) & 0xff);
    uuid.bytes[10] = @intCast((rand_b >> 40) & 0xff);
    uuid.bytes[11] = @intCast((rand_b >> 32) & 0xff);
    uuid.bytes[12] = @intCast((rand_b >> 24) & 0xff);
    uuid.bytes[13] = @intCast((rand_b >> 16) & 0xff);
    uuid.bytes[14] = @intCast((rand_b >> 8) & 0xff);
    uuid.bytes[15] = @intCast(rand_b & 0xff);

    return uuid;
}

pub fn toString(uuid: Uuid) [36]u8 {
    return uuid.toString();
}

pub fn parse(text: []const u8) ParseError!Uuid {
    return parseText(text);
}

fn parseText(text: []const u8) ParseError!Uuid {
    if (text.len != 36) return ParseError.InvalidLength;

    if (text[8] != '-' or text[13] != '-' or text[18] != '-' or text[23] != '-') {
        return ParseError.InvalidHyphen;
    }

    var uuid: Uuid = .{ .bytes = undefined };
    var text_index: usize = 0;
    var byte_index: usize = 0;
    while (byte_index < uuid.bytes.len) : (byte_index += 1) {
        if (text_index == 8 or text_index == 13 or text_index == 18 or text_index == 23) {
            text_index += 1;
        }

        const hi = try hexValue(text[text_index]);
        const lo = try hexValue(text[text_index + 1]);
        uuid.bytes[byte_index] = (hi << 4) | lo;
        text_index += 2;
    }

    return uuid;
}

fn nextV7Counter(unix_ms: u64, random: std.Random) u74 {
    lockV7State();
    defer v7_mutex.unlock();

    if (!v7_has_last or v7_last_ms != unix_ms) {
        v7_has_last = true;
        v7_last_ms = unix_ms;
        v7_counter = @as(u74, random.int(u42)) << 32;
        return v7_counter;
    }

    if ((v7_counter & sequence_mask) == sequence_mask) {
        const prefix = v7_counter >> 32;
        v7_counter = if (prefix == random_prefix_mask)
            std.math.maxInt(u74)
        else
            (prefix + 1) << 32;
    } else {
        v7_counter += 1;
    }
    return v7_counter;
}

fn lockV7State() void {
    while (!v7_mutex.tryLock()) {
        std.atomic.spinLoopHint();
    }
}

fn formatBytes(bytes: [16]u8) [36]u8 {
    var out: [36]u8 = undefined;
    var out_index: usize = 0;

    for (bytes, 0..) |byte, byte_index| {
        if (byte_index == 4 or byte_index == 6 or byte_index == 8 or byte_index == 10) {
            out[out_index] = '-';
            out_index += 1;
        }

        out[out_index] = hexDigit(byte >> 4);
        out[out_index + 1] = hexDigit(byte & 0x0f);
        out_index += 2;
    }

    return out;
}

fn hexDigit(value: u8) u8 {
    return if (value < 10) '0' + value else 'a' + (value - 10);
}

fn hexValue(byte: u8) ParseError!u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => ParseError.InvalidCharacter,
    };
}

fn resetV7StateForTest() void {
    lockV7State();
    defer v7_mutex.unlock();
    v7_has_last = false;
    v7_last_ms = 0;
    v7_counter = 0;
}

test "v4 has correct version and RFC 9562 variant bits" {
    var prng = std.Random.DefaultPrng.init(0x1234);
    const uuid = v4(prng.random());

    try std.testing.expectEqual(@as(u4, 4), uuid.version());
    try std.testing.expectEqual(Variant.rfc9562, uuid.variant());
    try std.testing.expectEqual(@as(u8, 0x40), uuid.bytes[6] & 0xf0);
    try std.testing.expectEqual(@as(u8, 0x80), uuid.bytes[8] & 0xc0);
}

test "v7 timestamp is recoverable and UUIDs sort lexicographically by time" {
    resetV7StateForTest();
    var prng = std.Random.DefaultPrng.init(0x5678);
    const random = prng.random();

    const earlier = v7(1_700_000_000_000, random);
    const later = v7(1_700_000_000_001, random);

    try std.testing.expectEqual(@as(u4, 7), earlier.version());
    try std.testing.expectEqual(Variant.rfc9562, earlier.variant());
    try std.testing.expectEqual(@as(?u64, 1_700_000_000_000), earlier.unixMilliseconds());
    try std.testing.expectEqual(@as(?u64, 1_700_000_000_001), later.unixMilliseconds());
    try std.testing.expectEqual(std.math.Order.lt, earlier.compare(later));

    const earlier_text = earlier.toString();
    const later_text = later.toString();
    try std.testing.expect(std.mem.lessThan(u8, &earlier_text, &later_text));
}

test "toString and parse round-trip lower-case canonical UUID text" {
    const uuid = try parse("01890f6d-7a60-7abc-8123-456789abcdef");
    const text = uuid.toString();
    const parsed = try parse(&text);

    try std.testing.expect(uuid.eql(parsed));
    try std.testing.expectEqualStrings("01890f6d-7a60-7abc-8123-456789abcdef", &text);
}

test "parse accepts upper-case hex and canonicalizes on format" {
    const uuid = try parse("01890F6D-7A60-7ABC-8123-456789ABCDEF");
    const text = toString(uuid);

    try std.testing.expectEqualStrings("01890f6d-7a60-7abc-8123-456789abcdef", &text);
}

test "parse rejects malformed UUID strings" {
    try std.testing.expectError(ParseError.InvalidLength, parse(""));
    try std.testing.expectError(ParseError.InvalidLength, parse("01890f6d-7a60-7abc-8123-456789abcde"));
    try std.testing.expectError(ParseError.InvalidHyphen, parse("01890f6d_7a60-7abc-8123-456789abcdef"));
    try std.testing.expectError(ParseError.InvalidHyphen, parse("01890f6d-7a60_7abc-8123-456789abcdef"));
    try std.testing.expectError(ParseError.InvalidCharacter, parse("01890f6d-7a60-7abc-8123-456789abcdeg"));
}

test "v7 is monotonic within the same millisecond" {
    resetV7StateForTest();
    var prng = std.Random.DefaultPrng.init(0x9abc);
    const random = prng.random();
    const unix_ms: u64 = 1_750_000_000_000;

    var previous = v7(unix_ms, random);
    var i: usize = 0;
    while (i < 512) : (i += 1) {
        const current = v7(unix_ms, random);
        try std.testing.expectEqual(@as(?u64, unix_ms), current.unixMilliseconds());
        try std.testing.expectEqual(std.math.Order.lt, previous.compare(current));
        previous = current;
    }
}

test "v4 and v7 are deterministic with seeded RNGs" {
    resetV7StateForTest();
    var prng_a = std.Random.DefaultPrng.init(0xd00d);
    const v4_a = v4(prng_a.random());
    const v7_a = v7(1_800_000_000_000, prng_a.random());
    const v7_a_next = v7(1_800_000_000_000, prng_a.random());

    resetV7StateForTest();
    var prng_b = std.Random.DefaultPrng.init(0xd00d);
    const v4_b = v4(prng_b.random());
    const v7_b = v7(1_800_000_000_000, prng_b.random());
    const v7_b_next = v7(1_800_000_000_000, prng_b.random());

    try std.testing.expect(v4_a.eql(v4_b));
    try std.testing.expect(v7_a.eql(v7_b));
    try std.testing.expect(v7_a_next.eql(v7_b_next));
}
