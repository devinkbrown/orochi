// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! CSPRNG and per-instance ChaCha20 DRBG.
//!
//! Entropy enters through Linux `getrandom(2)` with EINTR retry and explicit
//! errno handling. Hot-path generation is allocation-free: each `Drbg` owns a
//! ChaCha20 state, reseeds from the OS on request, and detects fork/snapshot
//! reuse by tracking the process id before every generated stream.
const std = @import("std");
const Secret = @import("secret.zig").Secret;
const platform = @import("../substrate/platform.zig");

const ChaCha20 = std.crypto.stream.chacha.ChaCha20With64BitNonce;

/// Errors surfaced by the random layer.
pub const Error = error{
    /// Kernel entropy was unavailable or returned an impossible short result.
    RandomSourceFailed,
    /// The requested random stream would exhaust the ChaCha counter space.
    StreamExhausted,
    /// A bounded integer request used an empty or negative bound.
    InvalidBound,
};

/// ChaCha20 DRBG key size in bytes.
pub const key_len = ChaCha20.key_length;
/// ChaCha20 DRBG nonce size in bytes.
pub const nonce_len = ChaCha20.nonce_length;
/// One ChaCha20 block in bytes.
pub const block_len = ChaCha20.block_length;
/// OS seed material: key || nonce.
pub const seed_len = key_len + nonce_len;

/// Fill `buf` directly from Linux `getrandom(2)`, retrying EINTR and handling
/// short reads. This is the slow root entropy source; hot callers should keep a
/// `Drbg` instance and use its fill methods.
pub fn fillOsEntropy(buf: []u8) Error!void {
    platform.fillOsEntropy(buf) catch return Error.RandomSourceFailed;
}

/// Fast per-instance DRBG. The state is fork/snapshot-aware and rekeys after
/// every non-empty fill so a later state compromise does not reveal prior
/// output bytes.
pub const Drbg = struct {
    key: Secret([key_len]u8),
    nonce: [nonce_len]u8,
    counter: u64,
    owner_pid: i32,

    /// Seed a new DRBG from the OS CSPRNG.
    pub fn init() Error!Drbg {
        var self = Drbg{
            .key = Secret([key_len]u8).init(@as([key_len]u8, @splat(0))),
            .nonce = @as([nonce_len]u8, @splat(0)),
            .counter = 0,
            .owner_pid = platform.currentPid(),
        };
        try self.reseed();
        return self;
    }

    /// Zeroize key material. Call with `defer rng.deinit()` for long-lived
    /// instances.
    pub fn deinit(self: *Drbg) void {
        self.key.wipe();
        secureZero(&self.nonce);
        self.counter = 0;
        self.owner_pid = 0;
    }

    /// Reseed from the OS CSPRNG and reset the stream counter.
    pub fn reseed(self: *Drbg) Error!void {
        var seed: [seed_len]u8 = undefined;
        defer secureZero(&seed);

        try fillOsEntropy(&seed);
        var next_key: [key_len]u8 = undefined;
        @memcpy(&next_key, seed[0..key_len]);
        self.key.wipe();
        self.key = Secret([key_len]u8).init(next_key);
        @memcpy(&self.nonce, seed[key_len..][0..nonce_len]);
        self.counter = 0;
        self.owner_pid = platform.currentPid();
    }

    /// Fill public/non-secret bytes from the DRBG.
    pub fn fillPublic(self: *Drbg, buf: []u8) Error!void {
        try self.ensureCurrentProcess();
        if (buf.len == 0) return;
        try self.stream(buf);
        try self.rekey();
    }

    /// Fill a `Secret(T)` wrapper's backing bytes from the DRBG.
    ///
    /// `T` must be an inline value (for example `[32]u8` or `u64`), not a
    /// pointer or slice. Filling a pointer-shaped secret would only randomize
    /// the pointer metadata, not the pointed-to key bytes.
    pub fn fillSecret(self: *Drbg, secret: anytype) Error!void {
        comptime {
            const ptr_info = @typeInfo(@TypeOf(secret));
            if (ptr_info != .pointer) @compileError("fillSecret expects *Secret(T)");
            const child = ptr_info.pointer.child;
            if (!@hasField(child, "value")) @compileError("fillSecret expects *Secret(T)");
            const value_info = @typeInfo(@TypeOf(secret.*.value));
            if (value_info == .pointer) @compileError("fillSecret refuses pointer-shaped Secret(T)");
        }
        try self.fillPublic(std.mem.asBytes(&secret.*.value));
    }

    /// Return a uniformly random `u64`.
    pub fn randomU64(self: *Drbg) Error!u64 {
        return self.randomInt(u64);
    }

    /// Return a uniformly random integer of type `T`.
    pub fn randomInt(self: *Drbg, comptime T: type) Error!T {
        comptime {
            if (@typeInfo(T) != .int) @compileError("randomInt requires an integer type");
            if (@typeInfo(T).int.bits == 0) @compileError("randomInt requires a non-zero-width integer type");
        }

        const info = @typeInfo(T).int;
        const bits = info.bits;
        const byte_len = comptime (bits + 7) / 8;
        const Unsigned = @Int(.unsigned, bits);
        const ByteAligned = @Int(.unsigned, byte_len * 8);

        var bytes: [byte_len]u8 = undefined;
        defer secureZero(&bytes);
        try self.fillPublic(&bytes);

        const wide = std.mem.readInt(ByteAligned, &bytes, .little);
        const unsigned: Unsigned = @truncate(wide);
        return @bitCast(unsigned);
    }

    /// Return an unbiased integer in `[0, upper_bound)`.
    ///
    /// `upper_bound == 1` always returns zero. Zero or negative bounds are
    /// rejected explicitly instead of panicking.
    pub fn boundedInt(self: *Drbg, comptime T: type, upper_bound: T) Error!T {
        comptime {
            if (@typeInfo(T) != .int) @compileError("boundedInt requires an integer type");
            if (@typeInfo(T).int.bits == 0) @compileError("boundedInt requires a non-zero-width integer type");
        }

        const info = @typeInfo(T).int;
        if (info.signedness == .signed) {
            if (upper_bound <= 0) return Error.InvalidBound;
        } else {
            if (upper_bound == 0) return Error.InvalidBound;
        }
        if (upper_bound == 1) return 0;

        const Unsigned = @Int(.unsigned, info.bits);
        const bound: Unsigned = @intCast(upper_bound);
        const threshold: Unsigned = (0 -% bound) % bound;

        while (true) {
            const x = try self.randomInt(Unsigned);
            if (x >= threshold) return @intCast(x % bound);
        }
    }

    /// Return an unbiased integer in `[at_least, less_than)`.
    pub fn rangeLessThan(self: *Drbg, comptime T: type, at_least: T, less_than: T) Error!T {
        comptime {
            if (@typeInfo(T) != .int) @compileError("rangeLessThan requires an integer type");
        }
        if (at_least >= less_than) return Error.InvalidBound;

        const info = @typeInfo(T).int;
        if (info.signedness == .signed) {
            const Unsigned = @Int(.unsigned, info.bits);
            const lo: Unsigned = @bitCast(at_least);
            const hi: Unsigned = @bitCast(less_than);
            const offset = try self.boundedInt(Unsigned, hi -% lo);
            return @bitCast(lo +% offset);
        }
        return at_least + try self.boundedInt(T, less_than - at_least);
    }

    fn ensureCurrentProcess(self: *Drbg) Error!void {
        const pid = platform.currentPid();
        if (self.owner_pid != pid) try self.reseed();
    }

    fn stream(self: *Drbg, out: []u8) Error!void {
        const blocks = blocksFor(out.len);
        if (blocks == 0) return;
        if (blocks > std.math.maxInt(u64) - self.counter) return Error.StreamExhausted;

        const key = self.key.declassify();
        ChaCha20.stream(out, self.counter, key, self.nonce);
        self.counter += blocks;
    }

    fn rekey(self: *Drbg) Error!void {
        var next_key: [key_len]u8 = undefined;
        defer secureZero(&next_key);
        try self.stream(&next_key);
        self.key.wipe();
        self.key = Secret([key_len]u8).init(next_key);
        self.counter = 0;
    }
};

fn blocksFor(len: usize) u64 {
    if (len == 0) return 0;
    return @intCast((len + block_len - 1) / block_len);
}

fn secureZero(ptr: anytype) void {
    const bytes = std.mem.asBytes(ptr);
    for (bytes) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

fn testDrbg(seed: [seed_len]u8) Drbg {
    var key: [key_len]u8 = undefined;
    var nonce: [nonce_len]u8 = undefined;
    @memcpy(&key, seed[0..key_len]);
    @memcpy(&nonce, seed[key_len..][0..nonce_len]);
    return .{
        .key = Secret([key_len]u8).init(key),
        .nonce = nonce,
        .counter = 0,
        .owner_pid = platform.currentPid(),
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "getrandom fills a buffer" {
    var buf: [32]u8 = @splat(0);
    try fillOsEntropy(&buf);

    var any_nonzero = false;
    for (buf) |b| any_nonzero = any_nonzero or b != 0;
    try testing.expect(any_nonzero);
}

test "DRBG emits distinct consecutive outputs" {
    var rng = testDrbg(@as([seed_len]u8, @splat(0xA5)));
    defer rng.deinit();

    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    try rng.fillPublic(&a);
    try rng.fillPublic(&b);

    try testing.expect(!std.mem.eql(u8, &a, &b));
}

test "reseed changes the stream" {
    var rng = testDrbg(@as([seed_len]u8, @splat(0x11)));
    defer rng.deinit();

    var before: [64]u8 = undefined;
    try rng.fillPublic(&before);
    try rng.reseed();

    var after: [64]u8 = undefined;
    try rng.fillPublic(&after);
    try testing.expect(!std.mem.eql(u8, &before, &after));
}

test "snapshot pid mismatch forces reseed before output" {
    var rng = testDrbg(@as([seed_len]u8, @splat(0x22)));
    defer rng.deinit();

    rng.owner_pid = 0;
    var out: [16]u8 = undefined;
    try rng.fillPublic(&out);
    try testing.expectEqual(platform.currentPid(), rng.owner_pid);
}

test "fillSecret writes through Secret backing storage" {
    var rng = testDrbg(@as([seed_len]u8, @splat(0x33)));
    defer rng.deinit();

    var secret = Secret([32]u8).init(@as([32]u8, @splat(0)));
    defer secret.wipe();
    try rng.fillSecret(&secret);

    const value = secret.declassify();
    try testing.expect(!std.mem.eql(u8, &value, &(@as([32]u8, @splat(0)))));
}

test "randomU64 produces changing values" {
    var rng = testDrbg(@as([seed_len]u8, @splat(0x44)));
    defer rng.deinit();

    const a = try rng.randomU64();
    const b = try rng.randomU64();
    try testing.expect(a != b);
}

test "boundedInt validates range and stays within bound" {
    var rng = testDrbg(@as([seed_len]u8, @splat(0x55)));
    defer rng.deinit();

    try testing.expectError(Error.InvalidBound, rng.boundedInt(u32, 0));
    try testing.expectEqual(@as(u32, 0), try rng.boundedInt(u32, 1));

    var i: usize = 0;
    while (i < 512) : (i += 1) {
        const v = try rng.boundedInt(u16, 37);
        try testing.expect(v < 37);
    }
}

test "boundedInt has no visible modulo bias on small ranges" {
    var rng = testDrbg(@as([seed_len]u8, @splat(0x66)));
    defer rng.deinit();

    var counts = [_]usize{ 0, 0, 0 };
    var i: usize = 0;
    while (i < 30_000) : (i += 1) {
        const v = try rng.boundedInt(u8, 3);
        counts[v] += 1;
    }

    for (counts) |count| {
        try testing.expect(count > 9500);
        try testing.expect(count < 10_500);
    }
}

test "rangeLessThan handles signed ranges" {
    var rng = testDrbg(@as([seed_len]u8, @splat(0x77)));
    defer rng.deinit();

    var i: usize = 0;
    while (i < 256) : (i += 1) {
        const v = try rng.rangeLessThan(i16, -7, 9);
        try testing.expect(v >= -7);
        try testing.expect(v < 9);
    }
    try testing.expectError(Error.InvalidBound, rng.rangeLessThan(i16, 4, 4));
}

test {
    testing.refAllDecls(@This());
}
