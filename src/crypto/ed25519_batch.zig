//! Batch Ed25519 verification helpers.
//!
//! Zig 0.16 exposes `std.crypto.sign.Ed25519.verifyBatch` for compile-time
//! sized arrays. This module uses that fast path when possible and falls back
//! to per-signature verification whenever indices are needed.
const std = @import("std");

const Allocator = std.mem.Allocator;
const StdEd25519 = std.crypto.sign.Ed25519;

pub const public_key_len = StdEd25519.PublicKey.encoded_length;
pub const signature_len = StdEd25519.Signature.encoded_length;

pub const PublicKey = [public_key_len]u8;
pub const Signature = [signature_len]u8;

pub const Element = struct {
    message: []const u8,
    signature: Signature,
    public_key: PublicKey,
};

pub const Result = union(enum) {
    all_valid,
    failures: []usize,

    pub fn deinit(self: Result, allocator: Allocator) void {
        switch (self) {
            .all_valid => {},
            .failures => |indices| allocator.free(indices),
        }
    }

    pub fn isAllValid(self: Result) bool {
        return switch (self) {
            .all_valid => true,
            .failures => false,
        };
    }

    pub fn failureCount(self: Result) usize {
        return switch (self) {
            .all_valid => 0,
            .failures => |indices| indices.len,
        };
    }
};

pub const VerifyBatchError = Allocator.Error;

/// Verify a compile-time sized batch.
///
/// If Zig's stdlib batch verifier accepts the whole batch, this returns
/// `.all_valid`. If the batch verifier is unavailable or rejects the batch,
/// each tuple is verified individually to return the full set of failing
/// indices.
pub fn verifyBatch(
    allocator: Allocator,
    io: std.Io,
    comptime count: usize,
    entries: [count]Element,
) VerifyBatchError!Result {
    if (count == 0) return .all_valid;

    if (comptime @hasDecl(StdEd25519, "verifyBatch")) {
        var native_entries: [count]StdEd25519.BatchElement = undefined;
        for (entries, 0..) |entry, i| {
            native_entries[i] = toNative(entry) catch {
                return collectFailures(allocator, entries[0..]);
            };
        }

        StdEd25519.verifyBatch(io, count, native_entries) catch {
            return collectFailures(allocator, entries[0..]);
        };
        return .all_valid;
    }

    return collectFailures(allocator, entries[0..]);
}

/// Verify a runtime-sized batch with the same result shape as `verifyBatch`.
///
/// Zig 0.16's native batch verifier requires a compile-time array length, so
/// slices use per-signature verification.
pub fn verifyBatchSlice(
    allocator: Allocator,
    entries: []const Element,
) VerifyBatchError!Result {
    if (entries.len == 0) return .all_valid;
    return collectFailures(allocator, entries);
}

fn collectFailures(allocator: Allocator, entries: []const Element) Allocator.Error!Result {
    var failures: std.ArrayList(usize) = .empty;
    errdefer failures.deinit(allocator);

    for (entries, 0..) |entry, i| {
        if (!verifyOne(entry)) {
            try failures.append(allocator, i);
        }
    }

    if (failures.items.len == 0) {
        failures.deinit(allocator);
        return .all_valid;
    }

    return .{ .failures = try failures.toOwnedSlice(allocator) };
}

fn verifyOne(entry: Element) bool {
    const public_key = StdEd25519.PublicKey.fromBytes(entry.public_key) catch return false;
    const signature = StdEd25519.Signature.fromBytes(entry.signature);
    signature.verify(entry.message, public_key) catch return false;
    return true;
}

fn toNative(entry: Element) !StdEd25519.BatchElement {
    return .{
        .sig = StdEd25519.Signature.fromBytes(entry.signature),
        .msg = entry.message,
        .public_key = try StdEd25519.PublicKey.fromBytes(entry.public_key),
    };
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn signedElement(kp: StdEd25519.KeyPair, message: []const u8) !Element {
    const signature = try kp.sign(message, null);
    return .{
        .message = message,
        .signature = signature.toBytes(),
        .public_key = kp.public_key.toBytes(),
    };
}

test "all-valid batch passes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const kp1 = StdEd25519.KeyPair.generate(io);
    const kp2 = StdEd25519.KeyPair.generate(io);
    const entries = [_]Element{
        try signedElement(kp1, "mizuchi batch one"),
        try signedElement(kp2, "mizuchi batch two"),
        try signedElement(kp1, "mizuchi batch three"),
    };

    const result = try verifyBatch(allocator, io, entries.len, entries);
    defer result.deinit(allocator);
    try std.testing.expect(result.isAllValid());
    try std.testing.expectEqual(@as(usize, 0), result.failureCount());
}

test "one tampered signature is detected" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const kp = StdEd25519.KeyPair.generate(io);
    var entries = [_]Element{
        try signedElement(kp, "valid before tamper"),
        try signedElement(kp, "tamper target"),
        try signedElement(kp, "valid after tamper"),
    };
    entries[1].signature[17] ^= 0x80;

    const result = try verifyBatch(allocator, io, entries.len, entries);
    defer result.deinit(allocator);
    try std.testing.expect(!result.isAllValid());
    try std.testing.expectEqual(@as(usize, 1), result.failureCount());
    try std.testing.expectEqual(@as(usize, 1), result.failures[0]);
}

test "empty batch passes" {
    const allocator = std.testing.allocator;
    const entries = [_]Element{};

    const result = try verifyBatch(allocator, std.testing.io, entries.len, entries);
    defer result.deinit(allocator);
    try std.testing.expect(result.isAllValid());
}

test "known std Ed25519 vectors verify in batch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var cofactored_msg = hex("65643235353139766563746f72732033");
    const entries = [_]Element{
        .{
            .message = "test",
            .public_key = hex("2d6f7455d97b4a3a10d7293909d1a4f2058cb9a370e43fa8154bb280db839083"),
            .signature = hex("10a442b4a80cc4225b154f43bef28d2472ca80221951262eb8e0df9091575e26" ++
                "87cc486e77263c3418c757522d54f84b0359236abbbd4acd20dc297fdca66808"),
        },
        .{
            .message = &cofactored_msg,
            .public_key = hex("86e72f5c2a7215151059aa151c0ee6f8e2155d301402f35d7498f078629a8f79"),
            .signature = hex("fa9dde274f4820efb19a890f8ba2d8791710a4303ceef4aedf9dddc4e81a1f1" ++
                "1701a598b9a02ae60505dd0c2938a1a0c2d6ffd4676cfb49125b19e9cb358da06"),
        },
    };

    const result = try verifyBatch(allocator, io, entries.len, entries);
    defer result.deinit(allocator);
    try std.testing.expect(result.isAllValid());
}

test "runtime slice returns all failure indices" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const kp = StdEd25519.KeyPair.generate(io);
    var entries = [_]Element{
        try signedElement(kp, "slice ok"),
        try signedElement(kp, "slice bad sig"),
        try signedElement(kp, "slice bad key"),
    };
    entries[1].signature[4] ^= 0x01;
    entries[2].public_key = [_]u8{0xff} ** public_key_len;

    const result = try verifyBatchSlice(allocator, entries[0..]);
    defer result.deinit(allocator);
    try std.testing.expect(!result.isAllValid());
    try std.testing.expectEqual(@as(usize, 2), result.failureCount());
    try std.testing.expectEqual(@as(usize, 1), result.failures[0]);
    try std.testing.expectEqual(@as(usize, 2), result.failures[1]);
}

test {
    std.testing.refAllDecls(@This());
}
