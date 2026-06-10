const std = @import("std");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const media_label = "orochi/media";

pub const key_len: usize = 16;
pub const salt_len: usize = 14;

pub const MediaKeys = struct {
    key: [key_len]u8,
    salt: [salt_len]u8,
};

pub fn deriveSender(group_secret: []const u8, epoch: u64, sender_id: u64) MediaKeys {
    var info: [media_label.len + 16]u8 = undefined;
    @memcpy(info[0..media_label.len], media_label);
    std.mem.writeInt(u64, info[media_label.len..][0..8], epoch, .big);
    std.mem.writeInt(u64, info[media_label.len + 8 ..][0..8], sender_id, .big);

    const prk = HkdfSha256.extract("", group_secret);
    var out: [key_len + salt_len]u8 = undefined;
    HkdfSha256.expand(&out, &info, prk);

    return .{
        .key = out[0..key_len].*,
        .salt = out[key_len..][0..salt_len].*,
    };
}

pub const Ladder = struct {
    group_secret: [32]u8,
    epoch: u64,

    pub fn init(secret: [32]u8) Ladder {
        return .{
            .group_secret = secret,
            .epoch = 0,
        };
    }

    pub fn bump(self: *Ladder) void {
        self.epoch +%= 1;
    }

    pub fn keysFor(self: Ladder, sender_id: u64) MediaKeys {
        return deriveSender(&self.group_secret, self.epoch, sender_id);
    }
};

fn mediaKeysEqual(a: MediaKeys, b: MediaKeys) bool {
    return std.mem.eql(u8, &a.key, &b.key) and std.mem.eql(u8, &a.salt, &b.salt);
}

test "deriveSender is deterministic" {
    const group_secret = "call group secret";
    const a = deriveSender(group_secret, 7, 42);
    const b = deriveSender(group_secret, 7, 42);

    try std.testing.expect(mediaKeysEqual(a, b));
}

test "different epoch or sender produces different keys" {
    const group_secret = "call group secret";
    const base = deriveSender(group_secret, 7, 42);
    const other_epoch = deriveSender(group_secret, 8, 42);
    const other_sender = deriveSender(group_secret, 7, 43);

    try std.testing.expect(!mediaKeysEqual(base, other_epoch));
    try std.testing.expect(!mediaKeysEqual(base, other_sender));
}

test "key and salt lengths are correct" {
    const keys = deriveSender("call group secret", 7, 42);

    try std.testing.expectEqual(key_len, keys.key.len);
    try std.testing.expectEqual(salt_len, keys.salt.len);
}

test "Ladder.bump changes derived keys" {
    var secret = [_]u8{0} ** 32;
    secret[0] = 1;
    var ladder = Ladder.init(secret);

    const before = ladder.keysFor(42);
    ladder.bump();
    const after = ladder.keysFor(42);

    try std.testing.expect(!mediaKeysEqual(before, after));
}

test "distinct group secrets produce distinct keys" {
    var first = [_]u8{0} ** 32;
    var second = [_]u8{0} ** 32;
    first[0] = 1;
    second[0] = 2;

    const first_keys = deriveSender(&first, 7, 42);
    const second_keys = deriveSender(&second, 7, 42);

    try std.testing.expect(!mediaKeysEqual(first_keys, second_keys));
}
