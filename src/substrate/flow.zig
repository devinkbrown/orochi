// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const us_per_sec: u128 = 1_000_000;

fn scaledTokens(tokens: u64) u128 {
    return @as(u128, tokens) * us_per_sec;
}

pub const TokenBucket = struct {
    capacity: u64,
    refill_per_sec: u64,
    tokens_scaled: u128,
    last_refill_us: u64,

    pub fn init(capacity: u64, refill_per_sec: u64, now_us: u64) TokenBucket {
        return .{
            .capacity = capacity,
            .refill_per_sec = refill_per_sec,
            .tokens_scaled = scaledTokens(capacity),
            .last_refill_us = now_us,
        };
    }

    pub fn available(self: *TokenBucket, now_us: u64) u64 {
        self.refill(now_us);
        return @intCast(self.tokens_scaled / us_per_sec);
    }

    pub fn take(self: *TokenBucket, now_us: u64, n: u64) bool {
        self.refill(now_us);

        const needed = scaledTokens(n);
        if (needed > self.tokens_scaled) return false;

        self.tokens_scaled -= needed;
        return true;
    }

    fn refill(self: *TokenBucket, now_us: u64) void {
        const capacity_scaled = scaledTokens(self.capacity);
        if (self.tokens_scaled >= capacity_scaled) {
            self.tokens_scaled = capacity_scaled;
            self.last_refill_us = now_us;
            return;
        }

        if (now_us <= self.last_refill_us or self.refill_per_sec == 0) return;

        const elapsed_us = @as(u128, now_us - self.last_refill_us);
        const gained = elapsed_us * @as(u128, self.refill_per_sec);
        const room = capacity_scaled - self.tokens_scaled;

        if (gained >= room) {
            self.tokens_scaled = capacity_scaled;
        } else {
            self.tokens_scaled += gained;
        }
        self.last_refill_us = now_us;
    }
};

pub const CreditWindow = struct {
    max: u64,
    credit: u64,

    pub fn init(max: u64) CreditWindow {
        return .{
            .max = max,
            .credit = max,
        };
    }

    pub fn available(self: CreditWindow) u64 {
        return self.credit;
    }

    pub fn consume(self: *CreditWindow, n: u64) bool {
        if (n > self.credit) return false;

        self.credit -= n;
        return true;
    }

    pub fn replenish(self: *CreditWindow, n: u64) void {
        const room = self.max - self.credit;
        if (n >= room) {
            self.credit = self.max;
        } else {
            self.credit += n;
        }
    }
};

test "token bucket refills over elapsed time" {
    var bucket = TokenBucket.init(10, 2, 0);

    try std.testing.expect(bucket.take(0, 10));
    try std.testing.expectEqual(@as(u64, 0), bucket.available(0));
    try std.testing.expectEqual(@as(u64, 1), bucket.available(500_000));
    try std.testing.expectEqual(@as(u64, 2), bucket.available(1_000_000));
    try std.testing.expect(bucket.take(1_000_000, 2));
    try std.testing.expectEqual(@as(u64, 0), bucket.available(1_000_000));
}

test "token bucket blocks bursts beyond capacity" {
    var bucket = TokenBucket.init(5, 100, 0);

    try std.testing.expect(!bucket.take(0, 6));
    try std.testing.expectEqual(@as(u64, 5), bucket.available(0));
    try std.testing.expect(bucket.take(0, 5));
    try std.testing.expect(!bucket.take(0, 1));
    try std.testing.expectEqual(@as(u64, 5), bucket.available(1_000_000));
    try std.testing.expect(!bucket.take(1_000_000, 6));
}

test "token bucket zero capacity edge" {
    var bucket = TokenBucket.init(0, 100, 0);

    try std.testing.expectEqual(@as(u64, 0), bucket.available(0));
    try std.testing.expect(!bucket.take(0, 1));
    try std.testing.expectEqual(@as(u64, 0), bucket.available(10_000_000));
    try std.testing.expect(!bucket.take(10_000_000, 1));
    try std.testing.expect(bucket.take(10_000_000, 0));
}

test "token bucket large burst edge" {
    var bucket = TokenBucket.init(100, 50, 0);

    try std.testing.expect(!bucket.take(0, 101));
    try std.testing.expect(bucket.take(0, 100));
    try std.testing.expect(!bucket.take(0, 1));
    try std.testing.expect(!bucket.take(500_000, 26));
    try std.testing.expect(bucket.take(500_000, 25));
}

test "token bucket is deterministic for supplied timestamps" {
    var a = TokenBucket.init(8, 4, 10);
    var b = TokenBucket.init(8, 4, 10);

    try std.testing.expect(a.take(10, 6));
    try std.testing.expect(b.take(10, 6));
    try std.testing.expectEqual(a.available(250_010), b.available(250_010));
    try std.testing.expect(a.take(500_010, 2));
    try std.testing.expect(b.take(500_010, 2));
    try std.testing.expectEqual(a.available(750_010), b.available(750_010));
}

test "credit window blocks at zero and unblocks on replenish" {
    var window = CreditWindow.init(4);

    try std.testing.expect(window.consume(4));
    try std.testing.expectEqual(@as(u64, 0), window.available());
    try std.testing.expect(!window.consume(1));
    window.replenish(2);
    try std.testing.expectEqual(@as(u64, 2), window.available());
    try std.testing.expect(window.consume(2));
    try std.testing.expectEqual(@as(u64, 0), window.available());
}

test "credit window replenish cannot exceed max" {
    var window = CreditWindow.init(10);

    try std.testing.expect(window.consume(7));
    try std.testing.expectEqual(@as(u64, 3), window.available());
    window.replenish(100);
    try std.testing.expectEqual(@as(u64, 10), window.available());
}

test "credit window zero max edge" {
    var window = CreditWindow.init(0);

    try std.testing.expectEqual(@as(u64, 0), window.available());
    try std.testing.expect(!window.consume(1));
    try std.testing.expect(window.consume(0));
    window.replenish(10);
    try std.testing.expectEqual(@as(u64, 0), window.available());
}

test "credit window large burst edge" {
    var window = CreditWindow.init(1_000_000);

    try std.testing.expect(!window.consume(1_000_001));
    try std.testing.expectEqual(@as(u64, 1_000_000), window.available());
    try std.testing.expect(window.consume(999_999));
    try std.testing.expect(!window.consume(2));
    try std.testing.expect(window.consume(1));
    try std.testing.expectEqual(@as(u64, 0), window.available());
}
