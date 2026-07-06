// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! ULID: Universally Unique Lexicographically Sortable Identifier.
//!
//! A ULID is 16 bytes: a 48-bit millisecond timestamp followed by 80 bits of
//! randomness. Its canonical text form is 26 Crockford base32 characters.

const std = @import("std");

const testing = std.testing;

pub const encoded_len = 26;
pub const byte_len = 16;
pub const random_len = 10;
pub const max_timestamp: u64 = 0x0000_ffff_ffff_ffff;

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub const Error = error{
    InvalidCharacter,
    InvalidLength,
    RandomOverflow,
    TimestampOverflow,
};

pub const Ulid = struct {
    bytes: [byte_len]u8,

    pub fn encode(self: Ulid) [encoded_len]u8 {
        return encodeBytes(self.bytes);
    }

    pub fn timestamp(self: Ulid) u64 {
        var out: u64 = 0;
        for (self.bytes[0..6]) |byte| {
            out = (out << 8) | byte;
        }
        return out;
    }

    pub fn random(self: Ulid) [random_len]u8 {
        var out: [random_len]u8 = undefined;
        @memcpy(out[0..], self.bytes[6..]);
        return out;
    }
};

pub const MonotonicGenerator = struct {
    const Self = @This();

    last_ms: ?u64 = null,
    last_random: [random_len]u8 = @splat(0),

    pub fn init() Self {
        return .{};
    }

    pub fn next(self: *Self, unix_ms: u64, rng: std.Random) Error!Ulid {
        if (unix_ms > max_timestamp) return error.TimestampOverflow;

        if (self.last_ms) |last_ms| {
            if (unix_ms <= last_ms) {
                try incrementRandom(&self.last_random);
                return fromParts(last_ms, self.last_random);
            }
        }

        rng.bytes(self.last_random[0..]);
        self.last_ms = unix_ms;
        return fromParts(unix_ms, self.last_random);
    }
};

pub fn generate(unix_ms: u64, rng: std.Random) Ulid {
    std.debug.assert(unix_ms <= max_timestamp);

    var random_bytes: [random_len]u8 = undefined;
    rng.bytes(random_bytes[0..]);
    return fromParts(unix_ms, random_bytes);
}

pub fn encode(ulid: Ulid) [encoded_len]u8 {
    return ulid.encode();
}

pub fn decode(text: []const u8) Error!Ulid {
    if (text.len != encoded_len) return error.InvalidLength;

    var values: [encoded_len]u8 = undefined;
    for (text, 0..) |char, i| {
        values[i] = try decodeChar(char);
    }
    if (values[0] > 7) return error.InvalidCharacter;

    var bytes: [byte_len]u8 = @splat(0);
    for (0..(byte_len * 8)) |data_bit| {
        const stream_bit = data_bit + 2;
        const value_index = stream_bit / 5;
        const value_bit: u3 = @intCast(4 - (stream_bit % 5));
        const bit = (values[value_index] >> value_bit) & 1;
        if (bit != 0) {
            bytes[data_bit / 8] |= @as(u8, 1) << @intCast(7 - (data_bit % 8));
        }
    }

    return .{ .bytes = bytes };
}

pub fn timestamp(ulid: Ulid) u64 {
    return ulid.timestamp();
}

fn fromParts(unix_ms: u64, random_bytes: [random_len]u8) Ulid {
    std.debug.assert(unix_ms <= max_timestamp);

    var bytes: [byte_len]u8 = undefined;
    bytes[0] = @intCast((unix_ms >> 40) & 0xff);
    bytes[1] = @intCast((unix_ms >> 32) & 0xff);
    bytes[2] = @intCast((unix_ms >> 24) & 0xff);
    bytes[3] = @intCast((unix_ms >> 16) & 0xff);
    bytes[4] = @intCast((unix_ms >> 8) & 0xff);
    bytes[5] = @intCast(unix_ms & 0xff);
    @memcpy(bytes[6..], random_bytes[0..]);
    return .{ .bytes = bytes };
}

fn encodeBytes(bytes: [byte_len]u8) [encoded_len]u8 {
    var out: [encoded_len]u8 = undefined;
    for (0..encoded_len) |char_index| {
        out[char_index] = alphabet[encodedValue(bytes, char_index)];
    }
    return out;
}

fn encodedValue(bytes: [byte_len]u8, char_index: usize) u8 {
    var value: u8 = 0;
    for (0..5) |bit_offset| {
        value <<= 1;

        const stream_bit = char_index * 5 + bit_offset;
        if (stream_bit < 2) continue;

        const data_bit = stream_bit - 2;
        const byte_index = data_bit / 8;
        const byte_bit: u3 = @intCast(7 - (data_bit % 8));
        value |= (bytes[byte_index] >> byte_bit) & 1;
    }
    return value;
}

fn decodeChar(char: u8) Error!u8 {
    const upper = if (char >= 'a' and char <= 'z') char - ('a' - 'A') else char;
    return switch (upper) {
        '0'...'9' => upper - '0',
        'A' => 10,
        'B' => 11,
        'C' => 12,
        'D' => 13,
        'E' => 14,
        'F' => 15,
        'G' => 16,
        'H' => 17,
        'J' => 18,
        'K' => 19,
        'M' => 20,
        'N' => 21,
        'P' => 22,
        'Q' => 23,
        'R' => 24,
        'S' => 25,
        'T' => 26,
        'V' => 27,
        'W' => 28,
        'X' => 29,
        'Y' => 30,
        'Z' => 31,
        else => error.InvalidCharacter,
    };
}

fn incrementRandom(random_bytes: *[random_len]u8) Error!void {
    var i: usize = random_len;
    while (i > 0) {
        i -= 1;
        if (random_bytes[i] != 0xff) {
            random_bytes[i] += 1;
            @memset(random_bytes[i + 1 ..], 0);
            return;
        }
    }
    return error.RandomOverflow;
}

test "encode and decode round-trip to 26 Crockford base32 characters" {
    var prng = std.Random.DefaultPrng.init(0x1234_5678_9abc_def0);
    const original = generate(1_469_918_176_385, prng.random());
    const text = original.encode();

    try testing.expectEqual(@as(usize, encoded_len), text.len);
    for (text) |char| {
        try testing.expect(std.mem.indexOfScalar(u8, alphabet, char) != null);
        try testing.expect(char != 'I');
        try testing.expect(char != 'L');
        try testing.expect(char != 'O');
        try testing.expect(char != 'U');
    }

    const parsed = try decode(text[0..]);
    try testing.expectEqualSlices(u8, original.bytes[0..], parsed.bytes[0..]);
    try testing.expectEqual(original.timestamp(), parsed.timestamp());
}

test "known minimum and maximum encodings are canonical" {
    const zero = Ulid{ .bytes = @as([byte_len]u8, @splat(0)) };
    const max = Ulid{ .bytes = @as([byte_len]u8, @splat(0xff)) };

    const zero_text = zero.encode();
    const max_text = max.encode();

    try testing.expectEqualStrings("00000000000000000000000000", zero_text[0..]);
    try testing.expectEqualStrings("7ZZZZZZZZZZZZZZZZZZZZZZZZZ", max_text[0..]);
    try testing.expectEqualSlices(u8, zero.bytes[0..], (try decode(zero_text[0..])).bytes[0..]);
    try testing.expectEqualSlices(u8, max.bytes[0..], (try decode(max_text[0..])).bytes[0..]);
}

test "ULIDs sort lexicographically by timestamp" {
    const earlier = fromParts(42, @as([random_len]u8, @splat(0xff)));
    const later = fromParts(43, @as([random_len]u8, @splat(0)));
    const much_later = fromParts(4_294_967_296, @as([random_len]u8, @splat(0)));

    const earlier_text = earlier.encode();
    const later_text = later.encode();
    const much_later_text = much_later.encode();

    try testing.expect(std.mem.order(u8, earlier_text[0..], later_text[0..]) == .lt);
    try testing.expect(std.mem.order(u8, later_text[0..], much_later_text[0..]) == .lt);
}

test "timestamp is recoverable from generated and decoded ULIDs" {
    const expected_ms: u64 = 0x1234_5678_9abc;
    var prng = std.Random.DefaultPrng.init(0xfeed_face_cafe_beef);

    const ulid = generate(expected_ms, prng.random());
    const encoded = ulid.encode();
    const decoded = try decode(encoded[0..]);

    try testing.expectEqual(expected_ms, ulid.timestamp());
    try testing.expectEqual(expected_ms, timestamp(ulid));
    try testing.expectEqual(expected_ms, decoded.timestamp());
}

test "monotonic generator increments randomness within the same millisecond" {
    var prng = std.Random.DefaultPrng.init(0x5555_aaaa_7777_bbbb);
    var generator = MonotonicGenerator.init();

    const first = try generator.next(99, prng.random());
    const second = try generator.next(99, prng.random());
    const third = try generator.next(99, prng.random());

    const first_text = first.encode();
    const second_text = second.encode();
    const third_text = third.encode();

    try testing.expectEqual(@as(u64, 99), first.timestamp());
    try testing.expectEqual(@as(u64, 99), second.timestamp());
    try testing.expectEqual(@as(u64, 99), third.timestamp());
    try testing.expect(std.mem.order(u8, first_text[0..], second_text[0..]) == .lt);
    try testing.expect(std.mem.order(u8, second_text[0..], third_text[0..]) == .lt);

    var expected = first.random();
    try incrementRandom(&expected);
    try testing.expectEqualSlices(u8, expected[0..], second.random()[0..]);
    try incrementRandom(&expected);
    try testing.expectEqualSlices(u8, expected[0..], third.random()[0..]);
}

test "monotonic generator keeps order when the clock repeats or moves backward" {
    var prng = std.Random.DefaultPrng.init(0x1111_2222_3333_4444);
    var generator = MonotonicGenerator.init();

    const first = try generator.next(1_000, prng.random());
    const repeated = try generator.next(1_000, prng.random());
    const backwards = try generator.next(999, prng.random());
    const advanced = try generator.next(1_001, prng.random());

    const first_text = first.encode();
    const repeated_text = repeated.encode();
    const backwards_text = backwards.encode();
    const advanced_text = advanced.encode();

    try testing.expectEqual(@as(u64, 1_000), backwards.timestamp());
    try testing.expect(std.mem.order(u8, first_text[0..], repeated_text[0..]) == .lt);
    try testing.expect(std.mem.order(u8, repeated_text[0..], backwards_text[0..]) == .lt);
    try testing.expect(std.mem.order(u8, backwards_text[0..], advanced_text[0..]) == .lt);
}

test "monotonic generator reports 80-bit random overflow" {
    var prng = std.Random.DefaultPrng.init(0);
    var generator = MonotonicGenerator{
        .last_ms = 7,
        .last_random = @as([random_len]u8, @splat(0xff)),
    };

    try testing.expectError(error.RandomOverflow, generator.next(7, prng.random()));
    try testing.expectEqualSlices(u8, (&@as([random_len]u8, @splat(0xff)))[0..], generator.last_random[0..]);
}

test "decode rejects malformed input and invalid characters" {
    try testing.expectError(error.InvalidLength, decode(""));
    try testing.expectError(error.InvalidLength, decode("0000000000000000000000000"));
    try testing.expectError(error.InvalidLength, decode("000000000000000000000000000"));

    try testing.expectError(error.InvalidCharacter, decode("80000000000000000000000000"));
    try testing.expectError(error.InvalidCharacter, decode("0000000000000000000000000I"));
    try testing.expectError(error.InvalidCharacter, decode("0000000000000000000000000L"));
    try testing.expectError(error.InvalidCharacter, decode("0000000000000000000000000O"));
    try testing.expectError(error.InvalidCharacter, decode("0000000000000000000000000U"));
    try testing.expectError(error.InvalidCharacter, decode("0000000000000000000000000?"));
}

test "decode accepts lowercase Crockford symbols except excluded letters" {
    const text = "01aryz6s41abcdefghjkmnpqrs";
    const upper = "01ARYZ6S41ABCDEFGHJKMNPQRS";

    const lower_decoded = try decode(text);
    const upper_decoded = try decode(upper);

    try testing.expectEqualSlices(u8, lower_decoded.bytes[0..], upper_decoded.bytes[0..]);
    try testing.expectError(error.InvalidCharacter, decode("0000000000000000000000000i"));
    try testing.expectError(error.InvalidCharacter, decode("0000000000000000000000000l"));
    try testing.expectError(error.InvalidCharacter, decode("0000000000000000000000000o"));
    try testing.expectError(error.InvalidCharacter, decode("0000000000000000000000000u"));
}

test "seeded rng produces deterministic ULIDs" {
    var prng_a = std.Random.DefaultPrng.init(0xdecaf_bad);
    var prng_b = std.Random.DefaultPrng.init(0xdecaf_bad);
    var prng_c = std.Random.DefaultPrng.init(0xdecaf_bae);

    const a = generate(123_456, prng_a.random());
    const b = generate(123_456, prng_b.random());
    const c = generate(123_456, prng_c.random());

    const a_text = a.encode();
    const b_text = b.encode();
    const c_text = c.encode();

    try testing.expectEqualSlices(u8, a.bytes[0..], b.bytes[0..]);
    try testing.expectEqualStrings(a_text[0..], b_text[0..]);
    try testing.expect(!std.mem.eql(u8, a.bytes[0..], c.bytes[0..]));
    try testing.expect(!std.mem.eql(u8, a_text[0..], c_text[0..]));
}
