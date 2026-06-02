//! Deterministic property and known-answer tests for the TSUMUGI ratchet.
//!
//! These tests exercise the public ratchet API with fixed-seed generated traffic
//! and attacker-controlled frame views. They deliberately inspect Secret-backed
//! keys only at assertion points to verify structural key advancement.
const std = @import("std");
const tsumugi = @import("tsumugi.zig");

const testing = std.testing;

const key_len = 32;
const nonce_base_len = 8;
const outer_header_len = 8;
const max_plain_len = 96;
const seed: u64 = 0x7473_756d_7567_6931;

const in_order_iterations = 384;
const attacker_iterations = 768;

const Pair = struct {
    initiator: tsumugi.State,
    responder: tsumugi.State,

    fn deinit(self: *Pair) void {
        self.initiator.deinit();
        self.responder.deinit();
    }
};

fn fixedRoot(byte: u8) [key_len]u8 {
    return [_]u8{byte} ** key_len;
}

fn fixedNonceBase(byte: u8) [nonce_base_len]u8 {
    return [_]u8{byte} ** nonce_base_len;
}

fn testOuterHeader() [outer_header_len]u8 {
    return .{ 0xa2, 0x00, 0x25, 0x00, 0xef, 0xcd, 0xab, 0x10 };
}

fn randomRoot(random: std.Random) [key_len]u8 {
    var out: [key_len]u8 = undefined;
    random.bytes(&out);
    return out;
}

fn randomNonceBase(random: std.Random) [nonce_base_len]u8 {
    var out: [nonce_base_len]u8 = undefined;
    random.bytes(&out);
    return out;
}

fn makePair(
    root_secret: [key_len]u8,
    initiator_nonce: [nonce_base_len]u8,
    responder_nonce: [nonce_base_len]u8,
    generation: u32,
    epoch_seconds: u64,
) !Pair {
    const initiator_role: tsumugi.Role = .initiator;
    const responder_role: tsumugi.Role = .responder;
    return .{
        .initiator = try tsumugi.State.init(root_secret, initiator_role, initiator_nonce, generation, epoch_seconds),
        .responder = try tsumugi.State.init(root_secret, responder_role, responder_nonce, generation, epoch_seconds),
    };
}

fn toEncrypted(sealed: tsumugi.SealedFrame) tsumugi.EncryptedFrame {
    return .{
        .generation = sealed.generation,
        .counter = sealed.counter,
        .nonce = sealed.nonce,
        .tag = sealed.tag,
        .ciphertext = sealed.ciphertext,
    };
}

fn expectOpenError(err: tsumugi.Error) !void {
    switch (err) {
        error.AuthFailed,
        error.BufferTooSmall,
        error.CounterExhausted,
        error.GenerationMismatch,
        error.InvalidOuterHeader,
        error.NonceCounterMismatch,
        error.Replay,
        error.TooFarAhead,
        => {},
    }
}

fn variedPlainLen(random: std.Random, iteration: usize) usize {
    return switch (iteration % 17) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 15,
        4 => 16,
        5 => 31,
        6 => 32,
        7 => max_plain_len,
        else => random.intRangeAtMost(usize, 0, max_plain_len),
    };
}

fn fillPlain(random: std.Random, buf: []u8, iteration: usize) void {
    random.bytes(buf);
    const interesting = [_]u8{ 0x00, 0x01, 0x7f, 0x80, 0xff, '\r', '\n', ' ', ':', '@' };
    for (interesting, 0..) |byte, i| {
        if (buf.len == 0) break;
        buf[(iteration * 19 + i * 7) % buf.len] = byte;
    }
}

fn openOkOrTypedError(
    state: *tsumugi.State,
    options: tsumugi.OpenOptions,
    encrypted: tsumugi.EncryptedFrame,
    out: []u8,
) !void {
    const opened = state.open(options, encrypted, out) catch |err| {
        try expectOpenError(err);
        return;
    };
    try testing.expectEqual(encrypted.ciphertext.len, opened.plaintext.len);
    try testing.expect(opened.plaintext.ptr == out.ptr or opened.plaintext.len == 0);
}

test "KAT fixed initial seal output and open recovery" {
    const outer = [_]u8{ 0xa2, 0x00, 0x0f, 0x00, 0xef, 0xcd, 0xab, 0x10 };
    const plaintext = "tsumugi fixed known-answer frame";
    const expected_nonce: tsumugi.Nonce = .{ 34, 34, 34, 34, 34, 34, 34, 34, 0, 0, 0, 0 };
    const expected_tag: tsumugi.Tag = .{
        250, 135, 29,  50, 149, 82,  133, 212,
        180, 80,  127, 57, 164, 212, 216, 67,
    };
    const expected_ciphertext = [_]u8{
        170, 16,  24,  139, 1,   236, 252, 196,
        67,  51,  242, 1,   62,  243, 59,  17,
        148, 196, 206, 156, 201, 211, 44,  248,
        41,  146, 148, 172, 18,  255, 91,  167,
    };

    var pair = try makePair(fixedRoot(0x11), fixedNonceBase(0x22), fixedNonceBase(0x33), 0x01020304, 1234);
    defer pair.deinit();

    var ciphertext: [plaintext.len]u8 = undefined;
    const sealed = try pair.initiator.seal(
        tsumugi.SealOptions{ .outer_header = &outer },
        plaintext,
        &ciphertext,
    );

    try testing.expectEqual(@as(u32, 0x01020304), sealed.generation);
    try testing.expectEqual(@as(u32, 0), sealed.counter);
    try testing.expectEqualSlices(u8, &expected_nonce, &sealed.nonce);
    try testing.expectEqualSlices(u8, &expected_tag, &sealed.tag);
    try testing.expectEqualSlices(u8, &expected_ciphertext, sealed.ciphertext);

    var recovered: [plaintext.len]u8 = undefined;
    const opened = try pair.responder.open(
        tsumugi.OpenOptions{ .outer_header = &outer },
        toEncrypted(sealed),
        &recovered,
    );
    try testing.expectEqualSlices(u8, plaintext, opened.plaintext);
}

test "in-order bidirectional seal open recovers plaintext across many frames" {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var pair = try makePair(randomRoot(random), randomNonceBase(random), randomNonceBase(random), 9, 77);
    defer pair.deinit();

    const outer = testOuterHeader();
    const seal_options = tsumugi.SealOptions{ .outer_header = &outer };
    const open_options = tsumugi.OpenOptions{ .outer_header = &outer };

    var initiator_plain: [max_plain_len]u8 = undefined;
    var responder_plain: [max_plain_len]u8 = undefined;
    var initiator_ciphertext: [max_plain_len]u8 = undefined;
    var responder_ciphertext: [max_plain_len]u8 = undefined;
    var recovered: [max_plain_len]u8 = undefined;

    var i: usize = 0;
    while (i < in_order_iterations) : (i += 1) {
        const initiator_len = variedPlainLen(random, i);
        fillPlain(random, initiator_plain[0..initiator_len], i);

        const sealed_from_initiator = try pair.initiator.seal(
            seal_options,
            initiator_plain[0..initiator_len],
            &initiator_ciphertext,
        );
        try testing.expectEqual(@as(u32, @intCast(i)), sealed_from_initiator.counter);

        const opened_by_responder = try pair.responder.open(
            open_options,
            toEncrypted(sealed_from_initiator),
            &recovered,
        );
        try testing.expectEqualSlices(u8, initiator_plain[0..initiator_len], opened_by_responder.plaintext);

        const responder_len = variedPlainLen(random, i + 5);
        fillPlain(random, responder_plain[0..responder_len], i + 0x100);

        const sealed_from_responder = try pair.responder.seal(
            seal_options,
            responder_plain[0..responder_len],
            &responder_ciphertext,
        );
        try testing.expectEqual(@as(u32, @intCast(i)), sealed_from_responder.counter);

        const opened_by_initiator = try pair.initiator.open(
            open_options,
            toEncrypted(sealed_from_responder),
            &recovered,
        );
        try testing.expectEqualSlices(u8, responder_plain[0..responder_len], opened_by_initiator.plaintext);
    }

    try testing.expectEqual(@as(u32, in_order_iterations), pair.initiator.send_counter);
    try testing.expectEqual(@as(u32, in_order_iterations), pair.initiator.recv_counter);
    try testing.expectEqual(@as(u32, in_order_iterations), pair.responder.send_counter);
    try testing.expectEqual(@as(u32, in_order_iterations), pair.responder.recv_counter);
}

test "chain keys advance per frame and frame N fails under frame N plus one key" {
    const outer = testOuterHeader();
    var pair = try makePair(fixedRoot(0x42), fixedNonceBase(0xa1), fixedNonceBase(0xb2), 3, 0);
    defer pair.deinit();

    const initial_send_chain = pair.initiator.send_chain_key.declassify();
    const initial_recv_chain = pair.responder.recv_chain_key.declassify();
    try testing.expectEqualSlices(u8, &initial_send_chain, &initial_recv_chain);

    var ct0: ["frame-zero".len]u8 = undefined;
    var ct1: ["frame-one!".len]u8 = undefined;
    const sealed0 = try pair.initiator.seal(.{ .outer_header = &outer }, "frame-zero", &ct0);
    const after_first_send_chain = pair.initiator.send_chain_key.declassify();
    const sealed1 = try pair.initiator.seal(.{ .outer_header = &outer }, "frame-one!", &ct1);
    const after_second_send_chain = pair.initiator.send_chain_key.declassify();

    try testing.expect(!std.mem.eql(u8, &initial_send_chain, &after_first_send_chain));
    try testing.expect(!std.mem.eql(u8, &after_first_send_chain, &after_second_send_chain));
    try testing.expectEqual(@as(u32, 0), sealed0.counter);
    try testing.expectEqual(@as(u32, 1), sealed1.counter);
    try testing.expect(!std.mem.eql(u8, sealed0.ciphertext, sealed1.ciphertext));

    var wrong_key_receiver = try tsumugi.State.init(fixedRoot(0x42), .responder, fixedNonceBase(0xb2), 3, 0);
    defer wrong_key_receiver.deinit();
    wrong_key_receiver.recv_chain_key = pair.initiator.send_chain_key;

    var out: ["frame-zero".len]u8 = undefined;
    try testing.expectError(
        error.AuthFailed,
        wrong_key_receiver.open(.{ .outer_header = &outer }, toEncrypted(sealed0), &out),
    );
}

test "out of order frames inside max skip open and beyond max skip fails closed" {
    const outer = testOuterHeader();
    const options = tsumugi.OpenOptions{ .outer_header = &outer };
    const msg = "skip-window frame";

    var pair = try makePair(fixedRoot(0x53), fixedNonceBase(0xc1), fixedNonceBase(0xd2), 4, 0);
    defer pair.deinit();

    var ciphertexts: [tsumugi.max_skip + 1][msg.len]u8 = undefined;
    var sealed: [tsumugi.max_skip + 1]tsumugi.SealedFrame = undefined;
    var i: usize = 0;
    while (i <= tsumugi.max_skip) : (i += 1) {
        sealed[i] = try pair.initiator.seal(.{ .outer_header = &outer }, msg, &ciphertexts[i]);
        try testing.expectEqual(@as(u32, @intCast(i)), sealed[i].counter);
    }

    var out: [msg.len]u8 = undefined;
    const opened_last = try pair.responder.open(options, toEncrypted(sealed[tsumugi.max_skip]), &out);
    try testing.expectEqualSlices(u8, msg, opened_last.plaintext);
    try testing.expectEqual(@as(u32, @intCast(tsumugi.max_skip + 1)), pair.responder.recv_counter);

    const opened_zero = try pair.responder.open(options, toEncrypted(sealed[0]), &out);
    try testing.expectEqualSlices(u8, msg, opened_zero.plaintext);

    const opened_middle = try pair.responder.open(options, toEncrypted(sealed[tsumugi.max_skip / 2]), &out);
    try testing.expectEqualSlices(u8, msg, opened_middle.plaintext);

    try testing.expectError(error.Replay, pair.responder.open(options, toEncrypted(sealed[0]), &out));

    var far_pair = try makePair(fixedRoot(0x54), fixedNonceBase(0xc2), fixedNonceBase(0xd3), 5, 0);
    defer far_pair.deinit();

    var far_ct: [msg.len]u8 = undefined;
    var far_sealed: tsumugi.SealedFrame = undefined;
    i = 0;
    while (i <= tsumugi.max_skip + 1) : (i += 1) {
        far_sealed = try far_pair.initiator.seal(.{ .outer_header = &outer }, msg, &far_ct);
    }

    try testing.expectError(error.TooFarAhead, far_pair.responder.open(options, toEncrypted(far_sealed), &out));
    try testing.expectEqual(@as(u32, 0), far_pair.responder.recv_counter);
}

test "tampered ciphertext tag nonce base and outer header fail authentication" {
    const outer = testOuterHeader();
    const msg = "authenticated frame material";
    var pair = try makePair(fixedRoot(0x64), fixedNonceBase(0xe1), fixedNonceBase(0xf2), 6, 0);
    defer pair.deinit();

    var ciphertext: [msg.len]u8 = undefined;
    const sealed = try pair.initiator.seal(.{ .outer_header = &outer }, msg, &ciphertext);
    var out: [msg.len]u8 = undefined;

    const before_counter = pair.responder.recv_counter;
    const before_chain = pair.responder.recv_chain_key.declassify();

    var bad_ct = ciphertext;
    bad_ct[0] ^= 0x01;
    var bad = toEncrypted(sealed);
    bad.ciphertext = &bad_ct;
    try testing.expectError(error.AuthFailed, pair.responder.open(.{ .outer_header = &outer }, bad, &out));
    try testing.expectEqual(before_counter, pair.responder.recv_counter);
    try testing.expectEqualSlices(u8, &before_chain, &pair.responder.recv_chain_key.declassify());

    bad = toEncrypted(sealed);
    bad.tag[0] ^= 0x01;
    try testing.expectError(error.AuthFailed, pair.responder.open(.{ .outer_header = &outer }, bad, &out));
    try testing.expectEqual(before_counter, pair.responder.recv_counter);
    try testing.expectEqualSlices(u8, &before_chain, &pair.responder.recv_chain_key.declassify());

    bad = toEncrypted(sealed);
    bad.nonce[0] ^= 0x01;
    try testing.expectError(error.AuthFailed, pair.responder.open(.{ .outer_header = &outer }, bad, &out));
    try testing.expectEqual(before_counter, pair.responder.recv_counter);
    try testing.expectEqualSlices(u8, &before_chain, &pair.responder.recv_chain_key.declassify());

    var bad_outer = outer;
    bad_outer[0] ^= 0x01;
    try testing.expectError(error.AuthFailed, pair.responder.open(.{ .outer_header = &bad_outer }, toEncrypted(sealed), &out));
    try testing.expectEqual(before_counter, pair.responder.recv_counter);
    try testing.expectEqualSlices(u8, &before_chain, &pair.responder.recv_chain_key.declassify());

    const opened = try pair.responder.open(.{ .outer_header = &outer }, toEncrypted(sealed), &out);
    try testing.expectEqualSlices(u8, msg, opened.plaintext);
}

test "replay of already opened in order frame fails closed" {
    const outer = testOuterHeader();
    const msg = "single use frame";
    var pair = try makePair(fixedRoot(0x75), fixedNonceBase(0x91), fixedNonceBase(0x92), 7, 0);
    defer pair.deinit();

    var ciphertext: [msg.len]u8 = undefined;
    var out: [msg.len]u8 = undefined;
    const sealed = try pair.initiator.seal(.{ .outer_header = &outer }, msg, &ciphertext);

    const opened = try pair.responder.open(.{ .outer_header = &outer }, toEncrypted(sealed), &out);
    try testing.expectEqualSlices(u8, msg, opened.plaintext);
    try testing.expectError(error.Replay, pair.responder.open(.{ .outer_header = &outer }, toEncrypted(sealed), &out));
}

test "open returns typed errors or valid plaintext for arbitrary attacker frame bytes" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0xa77a_c6e5);
    const random = prng.random();

    var state = try tsumugi.State.init(randomRoot(random), .responder, randomNonceBase(random), 0x0100_0001, 10);
    defer state.deinit();

    var outer_storage = testOuterHeader();
    var ciphertext_storage: [max_plain_len]u8 = undefined;
    var plaintext_storage: [max_plain_len]u8 = undefined;

    var i: usize = 0;
    while (i < attacker_iterations) : (i += 1) {
        const ciphertext_len = variedPlainLen(random, i);
        random.bytes(ciphertext_storage[0..ciphertext_len]);

        var nonce: tsumugi.Nonce = undefined;
        var tag: tsumugi.Tag = undefined;
        random.bytes(&nonce);
        random.bytes(&tag);

        var generation = random.int(u32);
        if (i % 9 == 0) generation = 0x0100_0001;

        const counter = switch (i % 11) {
            0 => state.recv_counter,
            1 => state.recv_counter +| 1,
            2 => state.recv_counter +| @as(u32, @intCast(tsumugi.max_skip)),
            3 => state.recv_counter +| @as(u32, @intCast(tsumugi.max_skip + 1)),
            else => random.int(u32),
        };
        if (i % 5 == 0) {
            std.mem.writeInt(u32, nonce[nonce_base_len..][0..4], counter, .big);
        }

        random.bytes(&outer_storage);
        const outer_len = if (i % 13 == 0)
            random.intRangeAtMost(usize, 0, outer_header_len - 1)
        else
            outer_header_len;

        try openOkOrTypedError(
            &state,
            tsumugi.OpenOptions{ .outer_header = outer_storage[0..outer_len] },
            .{
                .generation = generation,
                .counter = counter,
                .nonce = nonce,
                .tag = tag,
                .ciphertext = ciphertext_storage[0..ciphertext_len],
            },
            plaintext_storage[0..ciphertext_len],
        );
    }
}

test {
    testing.refAllDecls(@This());
}
