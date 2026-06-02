//! TSUMUGI ratchet transport state.
//!
//! This module implements the protocol-level symmetric ratchet used after the
//! SUIMYAKU/kx layer has already authenticated the peer and produced a shared
//! hybrid root secret. It does not perform X25519, ML-KEM, or identity work.
const std = @import("std");

const frame = @import("frame.zig");
const Secret = @import("../crypto/secret.zig").Secret;

pub const max_skip: usize = 256;
pub const rekey_frame_interval: u32 = 50_000;
pub const rekey_epoch_seconds: u64 = 300;

const key_len = 32;
const nonce_base_len = 8;
const tag_len = 16;

const ChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const RootKey = Secret([key_len]u8);
pub const ChainKey = Secret([key_len]u8);
pub const MessageKey = Secret([key_len]u8);
pub const Nonce = [12]u8;
pub const Tag = [tag_len]u8;

pub const Error = error{
    AuthFailed,
    BufferTooSmall,
    CounterExhausted,
    GenerationMismatch,
    InvalidOuterHeader,
    NonceCounterMismatch,
    Replay,
    TooFarAhead,
};

/// Direction used to split the root secret into opposite send/receive chains.
pub const Role = enum {
    initiator,
    responder,
};

/// Public scheduling signal returned by seal/open.
pub const RekeySignal = struct {
    frames: bool = false,
    epoch: bool = false,
    counter_exhaustion: bool = false,

    pub fn any(self: RekeySignal) bool {
        return self.frames or self.epoch or self.counter_exhaustion;
    }
};

pub const SealOptions = struct {
    outer_header: []const u8,
    frame_kind: frame.FrameType = .tsumugi_ratchet,
    current_epoch_seconds: u64 = 0,
};

pub const OpenOptions = struct {
    outer_header: []const u8,
    frame_kind: frame.FrameType = .tsumugi_ratchet,
    current_epoch_seconds: u64 = 0,
};

/// Metadata for an encrypted TSUMUGI_RATCHET payload. `ciphertext` lives in the
/// caller-owned output buffer passed to `seal`.
pub const SealedFrame = struct {
    generation: u32,
    counter: u32,
    nonce: Nonce,
    tag: Tag,
    ciphertext: []const u8,
    rekey: RekeySignal,
};

/// Caller-owned encrypted frame view passed to `open`.
pub const EncryptedFrame = struct {
    generation: u32,
    counter: u32,
    nonce: Nonce,
    tag: Tag,
    ciphertext: []const u8,
};

pub const OpenedFrame = struct {
    plaintext: []const u8,
    rekey: RekeySignal,
};

/// Active TSUMUGI symmetric ratchet. Key material is `Secret([32]u8)` through the
/// HKDF PRK type; public protocol counters and generation stay ordinary ints.
pub const State = struct {
    root_key: RootKey,
    send_chain_key: ChainKey,
    recv_chain_key: ChainKey,
    nonce_base: [nonce_base_len]u8,
    send_counter: u32,
    recv_counter: u32,
    generation: u32,

    skipped: SkippedKeys = .{},
    frames_since_rekey: u32 = 0,
    rekey_epoch_start: u64 = 0,
    send_counter_exhausted: bool = false,
    recv_counter_exhausted: bool = false,

    /// Initialize TSUMUGI from the root secret supplied by the kx layer. This is a
    /// symmetric chain split only; no DH or KEM work happens here.
    pub fn init(
        root_secret: [key_len]u8,
        role: Role,
        nonce_base: [nonce_base_len]u8,
        generation: u32,
        current_epoch_seconds: u64,
    ) Error!State {
        var root = RootKey.init(root_secret);
        errdefer root.wipe();

        var initiator_chain: [key_len]u8 = undefined;
        var responder_chain: [key_len]u8 = undefined;
        errdefer secureZero(&initiator_chain);
        errdefer secureZero(&responder_chain);

        hkdfExpand(&root, "tsumugi-init-send", &initiator_chain);
        hkdfExpand(&root, "tsumugi-resp-send", &responder_chain);

        const send_bytes = switch (role) {
            .initiator => initiator_chain,
            .responder => responder_chain,
        };
        const recv_bytes = switch (role) {
            .initiator => responder_chain,
            .responder => initiator_chain,
        };

        const self = State{
            .root_key = root,
            .send_chain_key = ChainKey.init(send_bytes),
            .recv_chain_key = ChainKey.init(recv_bytes),
            .nonce_base = nonce_base,
            .send_counter = 0,
            .recv_counter = 0,
            .generation = generation,
            .rekey_epoch_start = current_epoch_seconds,
        };

        secureZero(&initiator_chain);
        secureZero(&responder_chain);
        return self;
    }

    pub fn deinit(self: *State) void {
        self.root_key.wipe();
        self.send_chain_key.wipe();
        self.recv_chain_key.wipe();
        secureZero(&self.nonce_base);
        self.skipped.wipe();
        self.* = undefined;
    }

    /// Replace the root key with a new kx-provided root and reset chains for a
    /// fresh ratchet generation.
    pub fn applyRekey(
        self: *State,
        root_secret: [key_len]u8,
        role: Role,
        nonce_base: [nonce_base_len]u8,
        generation: u32,
        current_epoch_seconds: u64,
    ) Error!void {
        var fresh = try State.init(root_secret, role, nonce_base, generation, current_epoch_seconds);
        errdefer fresh.deinit();
        self.deinit();
        self.* = fresh;
    }

    /// Encrypt one complete inner SUIMYAKU wire frame into `out`.
    pub fn seal(
        self: *State,
        options: SealOptions,
        inner_suimyaku_frame: []const u8,
        out: []u8,
    ) Error!SealedFrame {
        if (out.len < inner_suimyaku_frame.len) return error.BufferTooSmall;
        if (options.outer_header.len != frame.header_len) return error.InvalidOuterHeader;
        if (self.send_counter_exhausted) return error.CounterExhausted;

        const counter = self.send_counter;
        const nonce = makeNonce(self.nonce_base, counter);

        var msg_key: MessageKey = undefined;
        var next_chain: ChainKey = undefined;
        try deriveStep(&self.send_chain_key, &msg_key, &next_chain);
        defer msg_key.wipe();

        var aad_buf: AadBuffer = undefined;
        const aad = buildAad(
            &aad_buf,
            options.outer_header,
            self.generation,
            counter,
            options.frame_kind,
        );

        const ciphertext = out[0..inner_suimyaku_frame.len];
        const tag = sealAead(&msg_key, nonce, aad, inner_suimyaku_frame, ciphertext);

        self.send_chain_key.wipe();
        self.send_chain_key = next_chain;
        if (counter == std.math.maxInt(u32)) {
            self.send_counter_exhausted = true;
        } else {
            self.send_counter = counter + 1;
        }
        self.frames_since_rekey +|= 1;

        return .{
            .generation = self.generation,
            .counter = counter,
            .nonce = nonce,
            .tag = tag,
            .ciphertext = ciphertext,
            .rekey = self.rekeySignal(options.current_epoch_seconds, counter == std.math.maxInt(u32)),
        };
    }

    /// Decrypt one encrypted TSUMUGI frame. Receive-chain state and skipped-key
    /// cache mutations are committed only after AEAD authentication succeeds.
    pub fn open(
        self: *State,
        options: OpenOptions,
        encrypted: EncryptedFrame,
        out: []u8,
    ) Error!OpenedFrame {
        if (out.len < encrypted.ciphertext.len) return error.BufferTooSmall;
        if (options.outer_header.len != frame.header_len) return error.InvalidOuterHeader;
        if (encrypted.generation != self.generation) return error.GenerationMismatch;
        if (std.mem.readInt(u32, encrypted.nonce[nonce_base_len..][0..4], .big) != encrypted.counter)
            return error.NonceCounterMismatch;

        if (self.recv_counter_exhausted and encrypted.counter >= self.recv_counter) return error.Replay;
        if (encrypted.counter < self.recv_counter) {
            return self.openSkipped(options, encrypted, out);
        }
        return self.openForward(options, encrypted, out);
    }

    fn openSkipped(
        self: *State,
        options: OpenOptions,
        encrypted: EncryptedFrame,
        out: []u8,
    ) Error!OpenedFrame {
        const idx = self.skipped.find(encrypted.generation, encrypted.counter) orelse return error.Replay;
        const msg_key = self.skipped.slots[idx].key;

        var aad_buf: AadBuffer = undefined;
        const aad = buildAad(
            &aad_buf,
            options.outer_header,
            encrypted.generation,
            encrypted.counter,
            options.frame_kind,
        );

        const plaintext = out[0..encrypted.ciphertext.len];
        try openAead(&msg_key, encrypted.nonce, aad, encrypted.ciphertext, encrypted.tag, plaintext);

        self.skipped.consume(idx);
        self.frames_since_rekey +|= 1;
        return .{
            .plaintext = plaintext,
            .rekey = self.rekeySignal(options.current_epoch_seconds, false),
        };
    }

    fn openForward(
        self: *State,
        options: OpenOptions,
        encrypted: EncryptedFrame,
        out: []u8,
    ) Error!OpenedFrame {
        const gap = encrypted.counter - self.recv_counter;
        if (gap > max_skip) return error.TooFarAhead;

        var staged = StagedSkipped{};
        defer staged.wipe();

        var working_chain = self.recv_chain_key;
        errdefer working_chain.wipe();

        var c = self.recv_counter;
        while (c < encrypted.counter) : (c += 1) {
            var skipped_key: MessageKey = undefined;
            var next_chain: ChainKey = undefined;
            try deriveStep(&working_chain, &skipped_key, &next_chain);
            working_chain.wipe();
            working_chain = next_chain;
            staged.append(encrypted.generation, c, skipped_key);
        }

        var msg_key: MessageKey = undefined;
        var next_chain: ChainKey = undefined;
        try deriveStep(&working_chain, &msg_key, &next_chain);
        working_chain.wipe();
        defer msg_key.wipe();

        var aad_buf: AadBuffer = undefined;
        const aad = buildAad(
            &aad_buf,
            options.outer_header,
            encrypted.generation,
            encrypted.counter,
            options.frame_kind,
        );

        const plaintext = out[0..encrypted.ciphertext.len];
        try openAead(&msg_key, encrypted.nonce, aad, encrypted.ciphertext, encrypted.tag, plaintext);

        try self.skipped.commitStaged(&staged);
        staged.markCommitted();
        self.recv_chain_key.wipe();
        self.recv_chain_key = next_chain;
        const counter_exhausted = encrypted.counter == std.math.maxInt(u32);
        if (counter_exhausted) {
            self.recv_counter_exhausted = true;
            self.recv_counter = encrypted.counter;
        } else {
            self.recv_counter = encrypted.counter + 1;
        }
        self.frames_since_rekey +|= 1;

        return .{
            .plaintext = plaintext,
            .rekey = self.rekeySignal(options.current_epoch_seconds, counter_exhausted),
        };
    }

    fn rekeySignal(self: *const State, current_epoch_seconds: u64, counter_exhausted: bool) RekeySignal {
        const epoch_elapsed = current_epoch_seconds >= self.rekey_epoch_start and
            current_epoch_seconds - self.rekey_epoch_start >= rekey_epoch_seconds;
        return .{
            .frames = self.frames_since_rekey >= rekey_frame_interval,
            .epoch = epoch_elapsed,
            .counter_exhaustion = counter_exhausted,
        };
    }
};

fn deriveStep(chain: *const ChainKey, msg_key: *MessageKey, next_chain: *ChainKey) Error!void {
    var msg_bytes: [key_len]u8 = undefined;
    var chain_bytes: [key_len]u8 = undefined;
    errdefer secureZero(&msg_bytes);
    errdefer secureZero(&chain_bytes);

    hkdfExpand(chain, "tsumugi-msg", &msg_bytes);
    hkdfExpand(chain, "tsumugi-chain", &chain_bytes);

    msg_key.* = MessageKey.init(msg_bytes);
    next_chain.* = ChainKey.init(chain_bytes);
    secureZero(&msg_bytes);
    secureZero(&chain_bytes);
}

fn sealAead(
    msg_key: *const MessageKey,
    nonce: Nonce,
    aad: []const u8,
    plaintext: []const u8,
    out: []u8,
) Tag {
    var key = msg_key.declassify();
    defer secureZero(&key);
    var tag: Tag = undefined;
    ChaCha.encrypt(out, &tag, plaintext, aad, nonce, key);
    return tag;
}

fn openAead(
    msg_key: *const MessageKey,
    nonce: Nonce,
    aad: []const u8,
    ciphertext: []const u8,
    tag: Tag,
    out: []u8,
) Error!void {
    var key = msg_key.declassify();
    defer secureZero(&key);
    ChaCha.decrypt(out, ciphertext, tag, aad, nonce, key) catch {
        return error.AuthFailed;
    };
}

fn hkdfExpand(prk: *const ChainKey, info: []const u8, out: []u8) void {
    const Hmac = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256);
    var prk_bytes = prk.declassify();
    defer secureZero(&prk_bytes);

    var t: [key_len]u8 = undefined;
    defer secureZero(&t);
    var t_len: usize = 0;
    var written: usize = 0;
    var block: u8 = 1;

    while (written < out.len) : (block += 1) {
        var mac = Hmac.init(&prk_bytes);
        if (t_len != 0) mac.update(t[0..t_len]);
        mac.update(info);
        mac.update(&[_]u8{block});
        mac.final(&t);

        const take = @min(key_len, out.len - written);
        @memcpy(out[written..][0..take], t[0..take]);
        written += take;
        t_len = key_len;
    }
}

fn makeNonce(base: [nonce_base_len]u8, counter: u32) Nonce {
    var nonce: Nonce = undefined;
    @memcpy(nonce[0..nonce_base_len], &base);
    std.mem.writeInt(u32, nonce[nonce_base_len..][0..4], counter, .big);
    return nonce;
}

const aad_fixed_len = 4 + 4 + 1;
const AadBuffer = [@as(usize, frame.header_len) + aad_fixed_len]u8;

fn buildAad(
    out: *AadBuffer,
    outer_header: []const u8,
    generation: u32,
    counter: u32,
    frame_kind: frame.FrameType,
) []const u8 {
    const header_len: usize = frame.header_len;
    @memcpy(out[0..header_len], outer_header[0..header_len]);
    var n: usize = header_len;
    std.mem.writeInt(u32, out[n..][0..4], generation, .big);
    n += 4;
    std.mem.writeInt(u32, out[n..][0..4], counter, .big);
    n += 4;
    out[n] = frame_kind.byte();
    n += 1;
    return out[0..n];
}

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

const SkippedSlot = struct {
    present: bool = false,
    generation: u32 = 0,
    counter: u32 = 0,
    key: MessageKey = MessageKey.init([_]u8{0} ** key_len),
};

const SkippedKeys = struct {
    slots: [max_skip]SkippedSlot = [_]SkippedSlot{.{}} ** max_skip,
    next_evict: usize = 0,

    fn wipe(self: *SkippedKeys) void {
        for (&self.slots) |*slot| {
            if (slot.present) slot.key.wipe();
            slot.* = .{};
        }
        self.next_evict = 0;
    }

    fn find(self: *const SkippedKeys, generation: u32, counter: u32) ?usize {
        for (self.slots, 0..) |slot, idx| {
            if (slot.present and slot.generation == generation and slot.counter == counter) return idx;
        }
        return null;
    }

    fn consume(self: *SkippedKeys, idx: usize) void {
        self.slots[idx].key.wipe();
        self.slots[idx] = .{};
    }

    fn put(self: *SkippedKeys, generation: u32, counter: u32, key: MessageKey) void {
        const idx = self.next_evict;
        if (self.slots[idx].present) self.slots[idx].key.wipe();
        self.slots[idx] = .{
            .present = true,
            .generation = generation,
            .counter = counter,
            .key = key,
        };
        self.next_evict = (idx + 1) % max_skip;
    }

    fn commitStaged(self: *SkippedKeys, staged: *StagedSkipped) Error!void {
        var i: usize = 0;
        while (i < staged.len) : (i += 1) {
            self.put(staged.entries[i].generation, staged.entries[i].counter, staged.entries[i].key);
            staged.entries[i].key.wipe();
            staged.entries[i].present = false;
        }
    }
};

const StagedSkipped = struct {
    entries: [max_skip]SkippedSlot = [_]SkippedSlot{.{}} ** max_skip,
    len: usize = 0,

    fn append(self: *StagedSkipped, generation: u32, counter: u32, key: MessageKey) void {
        self.entries[self.len] = .{
            .present = true,
            .generation = generation,
            .counter = counter,
            .key = key,
        };
        self.len += 1;
    }

    fn markCommitted(self: *StagedSkipped) void {
        self.len = 0;
    }

    fn wipe(self: *StagedSkipped) void {
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            if (self.entries[i].present) self.entries[i].key.wipe();
            self.entries[i] = .{};
        }
        self.len = 0;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn rootSecret(byte: u8) [key_len]u8 {
    return [_]u8{byte} ** key_len;
}

fn nonceBase(byte: u8) [nonce_base_len]u8 {
    return [_]u8{byte} ** nonce_base_len;
}

fn testOuterHeader() [frame.header_len]u8 {
    var out: [frame.header_len]u8 = undefined;
    _ = (frame.Frame{
        .type = .tsumugi_ratchet,
        .ctrl = frame.Ctrl.init(0, .control, false),
    }).encode(&out) catch unreachable;
    return out;
}

fn makePair() !struct { initiator: State, responder: State } {
    return .{
        .initiator = try State.init(rootSecret(0x42), .initiator, nonceBase(0xa1), 7, 10),
        .responder = try State.init(rootSecret(0x42), .responder, nonceBase(0xb2), 7, 10),
    };
}

test "in-order seal/open round-trip" {
    const allocator = testing.allocator;
    var pair = try makePair();
    defer pair.initiator.deinit();
    defer pair.responder.deinit();

    const outer = testOuterHeader();
    const inner = "complete inner SUIMYAKU frame bytes";
    const ct = try allocator.alloc(u8, inner.len);
    defer allocator.free(ct);
    const pt = try allocator.alloc(u8, inner.len);
    defer allocator.free(pt);

    const sealed = try pair.initiator.seal(.{ .outer_header = &outer }, inner, ct);
    const opened = try pair.responder.open(.{ .outer_header = &outer }, .{
        .generation = sealed.generation,
        .counter = sealed.counter,
        .nonce = sealed.nonce,
        .tag = sealed.tag,
        .ciphertext = sealed.ciphertext,
    }, pt);

    try testing.expectEqualSlices(u8, inner, opened.plaintext);
    try testing.expect(!sealed.rekey.any());
    try testing.expect(!opened.rekey.any());
}

test "reordered frames within the 256 window recover" {
    const allocator = testing.allocator;
    var pair = try makePair();
    defer pair.initiator.deinit();
    defer pair.responder.deinit();

    const outer = testOuterHeader();
    const a = "frame zero";
    const b = "frame one";
    const c = "frame two";
    const max_plain_len = @max(a.len, @max(b.len, c.len));

    const ct_a = try allocator.alloc(u8, a.len);
    defer allocator.free(ct_a);
    const ct_b = try allocator.alloc(u8, b.len);
    defer allocator.free(ct_b);
    const ct_c = try allocator.alloc(u8, c.len);
    defer allocator.free(ct_c);
    var pt = try allocator.alloc(u8, max_plain_len);
    defer allocator.free(pt);

    const sealed_a = try pair.initiator.seal(.{ .outer_header = &outer }, a, ct_a);
    const sealed_b = try pair.initiator.seal(.{ .outer_header = &outer }, b, ct_b);
    const sealed_c = try pair.initiator.seal(.{ .outer_header = &outer }, c, ct_c);

    const opened_c = try pair.responder.open(.{ .outer_header = &outer }, toEncrypted(sealed_c), pt);
    try testing.expectEqualSlices(u8, c, opened_c.plaintext);
    try testing.expectEqual(@as(u32, 3), pair.responder.recv_counter);

    const opened_a = try pair.responder.open(.{ .outer_header = &outer }, toEncrypted(sealed_a), pt[0..a.len]);
    try testing.expectEqualSlices(u8, a, opened_a.plaintext);

    const opened_b = try pair.responder.open(.{ .outer_header = &outer }, toEncrypted(sealed_b), pt[0..b.len]);
    try testing.expectEqualSlices(u8, b, opened_b.plaintext);
}

test "replayed and too-old frames are rejected" {
    const allocator = testing.allocator;
    var pair = try makePair();
    defer pair.initiator.deinit();
    defer pair.responder.deinit();

    const outer = testOuterHeader();
    const msg = "replay me once";
    const ct = try allocator.alloc(u8, msg.len);
    defer allocator.free(ct);
    const pt = try allocator.alloc(u8, msg.len);
    defer allocator.free(pt);

    const sealed = try pair.initiator.seal(.{ .outer_header = &outer }, msg, ct);
    _ = try pair.responder.open(.{ .outer_header = &outer }, toEncrypted(sealed), pt);
    try testing.expectError(error.Replay, pair.responder.open(.{ .outer_header = &outer }, toEncrypted(sealed), pt));
}

test "AEAD failure leaves recv state unchanged" {
    const allocator = testing.allocator;
    var pair = try makePair();
    defer pair.initiator.deinit();
    defer pair.responder.deinit();

    const outer = testOuterHeader();
    const msg = "auth failure must not advance";
    const ct = try allocator.alloc(u8, msg.len);
    defer allocator.free(ct);
    const pt = try allocator.alloc(u8, msg.len);
    defer allocator.free(pt);

    const sealed = try pair.initiator.seal(.{ .outer_header = &outer }, msg, ct);
    var bad = toEncrypted(sealed);
    bad.tag[0] ^= 0x01;

    const before_counter = pair.responder.recv_counter;
    const before_chain = pair.responder.recv_chain_key.declassify();
    try testing.expectError(error.AuthFailed, pair.responder.open(.{ .outer_header = &outer }, bad, pt));
    try testing.expectEqual(before_counter, pair.responder.recv_counter);
    try testing.expectEqualSlices(u8, &before_chain, &pair.responder.recv_chain_key.declassify());

    const opened = try pair.responder.open(.{ .outer_header = &outer }, toEncrypted(sealed), pt);
    try testing.expectEqualSlices(u8, msg, opened.plaintext);
}

test "counter exhaustion forces rekey signal" {
    var pair = try makePair();
    defer pair.initiator.deinit();
    defer pair.responder.deinit();

    const outer = testOuterHeader();
    var ct: [1]u8 = undefined;
    pair.initiator.send_counter = std.math.maxInt(u32);

    const sealed = try pair.initiator.seal(.{ .outer_header = &outer }, "x", &ct);
    try testing.expect(sealed.rekey.counter_exhaustion);
    try testing.expect(sealed.rekey.any());
    try testing.expectError(error.CounterExhausted, pair.initiator.seal(.{ .outer_header = &outer }, "x", &ct));
}

test "max counter frame replay is rejected after successful open" {
    var pair = try makePair();
    defer pair.initiator.deinit();
    defer pair.responder.deinit();

    const outer = testOuterHeader();
    var ct: [1]u8 = undefined;
    var pt: [1]u8 = undefined;
    pair.initiator.send_counter = std.math.maxInt(u32);
    pair.responder.recv_counter = std.math.maxInt(u32);

    const sealed = try pair.initiator.seal(.{ .outer_header = &outer }, "x", &ct);
    const opened = try pair.responder.open(.{ .outer_header = &outer }, toEncrypted(sealed), &pt);
    try testing.expectEqualSlices(u8, "x", opened.plaintext);
    try testing.expectError(error.Replay, pair.responder.open(.{ .outer_header = &outer }, toEncrypted(sealed), &pt));
}

test "forward gap larger than TSUMUGI_MAX_SKIP is rejected without commit" {
    const allocator = testing.allocator;
    var pair = try makePair();
    defer pair.initiator.deinit();
    defer pair.responder.deinit();

    const outer = testOuterHeader();
    const msg = "too far";
    var sealed: SealedFrame = undefined;
    const ct = try allocator.alloc(u8, msg.len);
    defer allocator.free(ct);

    var i: usize = 0;
    while (i <= max_skip + 1) : (i += 1) {
        sealed = try pair.initiator.seal(.{ .outer_header = &outer }, msg, ct);
    }

    const pt = try allocator.alloc(u8, msg.len);
    defer allocator.free(pt);
    try testing.expectError(error.TooFarAhead, pair.responder.open(.{ .outer_header = &outer }, toEncrypted(sealed), pt));
    try testing.expectEqual(@as(u32, 0), pair.responder.recv_counter);
}

test "AAD binds frame kind generation and counter" {
    var pair = try makePair();
    defer pair.initiator.deinit();
    defer pair.responder.deinit();

    const outer = testOuterHeader();
    const msg = "aad-bound";
    var ct: [msg.len]u8 = undefined;
    var pt: [msg.len]u8 = undefined;

    const sealed = try pair.initiator.seal(.{ .outer_header = &outer }, msg, &ct);
    try testing.expectError(error.AuthFailed, pair.responder.open(.{
        .outer_header = &outer,
        .frame_kind = .tsumugi_group_key,
    }, toEncrypted(sealed), &pt));
    try testing.expectEqual(@as(u32, 0), pair.responder.recv_counter);

    var wrong_generation = toEncrypted(sealed);
    wrong_generation.generation += 1;
    try testing.expectError(error.GenerationMismatch, pair.responder.open(.{ .outer_header = &outer }, wrong_generation, &pt));

    var wrong_nonce = toEncrypted(sealed);
    wrong_nonce.nonce[nonce_base_len + 3] ^= 0x01;
    try testing.expectError(error.NonceCounterMismatch, pair.responder.open(.{ .outer_header = &outer }, wrong_nonce, &pt));
}

test "rekey schedule hooks signal frame and epoch rotation" {
    var pair = try makePair();
    defer pair.initiator.deinit();
    defer pair.responder.deinit();

    const outer = testOuterHeader();
    var ct: [1]u8 = undefined;

    pair.initiator.frames_since_rekey = rekey_frame_interval - 1;
    const by_frame = try pair.initiator.seal(.{ .outer_header = &outer }, "x", &ct);
    try testing.expect(by_frame.rekey.frames);

    pair.initiator.frames_since_rekey = 0;
    const by_epoch = try pair.initiator.seal(.{
        .outer_header = &outer,
        .current_epoch_seconds = 10 + rekey_epoch_seconds,
    }, "x", &ct);
    try testing.expect(by_epoch.rekey.epoch);
}

test "TSUMUGI key fields use canonical inline-array Secret" {
    const CanonicalSecret = @import("../crypto/secret.zig").Secret;
    comptime {
        if (RootKey != CanonicalSecret([key_len]u8)) @compileError("RootKey must use canonical Secret([32]u8)");
        if (ChainKey != CanonicalSecret([key_len]u8)) @compileError("ChainKey must use canonical Secret([32]u8)");
        if (MessageKey != CanonicalSecret([key_len]u8)) @compileError("MessageKey must use canonical Secret([32]u8)");
    }
}

fn toEncrypted(sealed: SealedFrame) EncryptedFrame {
    return .{
        .generation = sealed.generation,
        .counter = sealed.counter,
        .nonce = sealed.nonce,
        .tag = sealed.tag,
        .ciphertext = sealed.ciphertext,
    };
}

test {
    testing.refAllDecls(@This());
}
