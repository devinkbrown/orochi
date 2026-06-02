//! SUIMYAKU S2S mesh peer state machine.
//!
//! This module is pure transport logic: callers own sockets, buffering,
//! randomness, and output storage.  The peer consumes decoded SUIMYAKU frames
//! and writes encoded response frames into caller-provided buffers.
const std = @import("std");
const frame = @import("frame.zig");
const coilpack = @import("coilpack.zig");
const sign = @import("../crypto/sign.zig");
const kx = @import("../crypto/kx.zig");
const hash = @import("../crypto/hash.zig");

pub const protocol_major: u8 = 1;
pub const protocol_minor: u8 = 1;
pub const server_id_len = 3;
pub const max_server_name_len = 255;
pub const confirm_len = hash.HmacSha256.tag_len;
pub const max_hello_payload_len = 1 + 1 + 2 + max_server_name_len +
    1 + server_id_len + 8 + 8 + sign.public_key_len;
pub const max_auth_body_len = 1 + sign.public_key_len + @max(
    kx.X25519Kx.public_len + kx.HybridKx.mlkem_public_len,
    kx.X25519Kx.public_len + kx.HybridKx.mlkem_ciphertext_len,
);
pub const max_auth_payload_len = max_auth_body_len + sign.signature_len;

const auth_domain = "suimyaku-peer-auth-v1";
const auth_ok_domain = "suimyaku-peer-auth-ok-v1";
const kx_domain = "suimyaku-peer-kx-v1";

pub const State = enum {
    none,
    hello_sent,
    hello_recv,
    auth_sent,
    established,
    closing,
};

pub const Event = enum {
    none,
    send,
    send_and_established,
    established,
    accepted,
    dropped,
    closing,
};

pub const Role = enum {
    unknown,
    initiator,
    responder,
};

pub const AuthKind = enum(u8) {
    public_share = 1,
    encapsulated_share = 2,
};

pub const Action = struct {
    event: Event = .none,
    send_len: usize = 0,

    pub fn hasFrame(self: Action) bool {
        return self.send_len != 0;
    }
};

pub const Options = struct {
    server_name: []const u8,
    server_id: []const u8,
    capabilities: u64 = 0,
    epoch_ms: u64 = 0,
    identity: *const sign.KeyPair,
    hybrid_kx: kx.HybridKx.KeyPair,
    encapsulation_seed: ?([kx.HybridKx.encaps_seed_len]u8) = null,
};

const PeerInfo = struct {
    server_name: [max_server_name_len]u8 = [_]u8{0} ** max_server_name_len,
    server_name_len: u8 = 0,
    server_id: [server_id_len]u8 = [_]u8{0} ** server_id_len,
    capabilities: u64 = 0,
    epoch_ms: u64 = 0,
    identity_public_key: sign.PublicKey = [_]u8{0} ** sign.public_key_len,

    fn name(self: *const PeerInfo) []const u8 {
        return self.server_name[0..self.server_name_len];
    }

    fn sid(self: *const PeerInfo) []const u8 {
        return self.server_id[0..server_id_len];
    }
};

const AuthBody = struct {
    bytes: [max_auth_body_len]u8 = [_]u8{0} ** max_auth_body_len,
    len: usize = 0,

    fn slice(self: *const AuthBody) []const u8 {
        return self.bytes[0..self.len];
    }

    fn set(self: *AuthBody, body: []const u8) void {
        self.len = body.len;
        @memcpy(self.bytes[0..body.len], body);
    }
};

pub const Peer = struct {
    state: State = .none,
    role: Role = .unknown,
    local: PeerInfo,
    remote: PeerInfo = .{},
    identity: *const sign.KeyPair,
    hybrid_kx: kx.HybridKx.KeyPair,
    encapsulation_seed: ?([kx.HybridKx.encaps_seed_len]u8),
    credit: frame.CreditWindow = frame.CreditWindow.init(),
    local_hello_hash: hash.Sha256.Digest = [_]u8{0} ** hash.Sha256.digest_len,
    remote_hello_hash: hash.Sha256.Digest = [_]u8{0} ** hash.Sha256.digest_len,
    initiator_auth: AuthBody = .{},
    responder_auth: AuthBody = .{},
    shared_secret: ?kx.SharedSecret = null,

    pub fn init(options: Options) !Peer {
        var local: PeerInfo = .{};
        try fillPeerInfo(
            &local,
            options.server_name,
            options.server_id,
            options.capabilities,
            options.epoch_ms,
            options.identity.public_key,
        );

        return .{
            .local = local,
            .identity = options.identity,
            .hybrid_kx = options.hybrid_kx,
            .encapsulation_seed = options.encapsulation_seed,
        };
    }

    pub fn deinit(self: *Peer) void {
        self.hybrid_kx.wipe();
        if (self.shared_secret) |*secret| secret.wipe();
        self.shared_secret = null;
    }

    pub fn start(self: *Peer, out: []u8) !Action {
        if (self.state != .none) return error.InvalidState;
        const send_len = try self.emitHello(out);
        self.state = .hello_sent;
        return .{ .event = .send, .send_len = send_len };
    }

    pub fn feed(self: *Peer, in: frame.Frame, out: []u8) !Action {
        if (self.state == .closing) return .{ .event = .dropped };

        if (frame.gateFrame(self.state == .established, in.type) == .drop) {
            return .{ .event = .dropped };
        }

        switch (in.type) {
            .hello => return self.recvHello(in.payload, out),
            .auth => return self.recvAuth(in.payload, out),
            .auth_ok => return self.recvAuthOk(in.payload),
            .auth_fail, .err, .disconnect => {
                self.closeAndWipe();
                return .{ .event = .closing };
            },
            .credit => {
                const grant = try decodeCredit(in.payload);
                try self.credit.applyCredit(grant);
                return .{};
            },
            else => {
                if (self.state != .established) return .{ .event = .dropped };
                if (try self.credit.debitReceive(in)) |grant| {
                    return .{
                        .event = .send,
                        .send_len = try emitCredit(grant, out),
                    };
                }
                return .{ .event = .accepted };
            },
        }
    }

    pub fn sendFrame(
        self: *Peer,
        frame_type: frame.FrameType,
        payload: []const u8,
        out: []u8,
    ) !usize {
        if (frame.gateFrame(self.state == .established, frame_type) == .drop) {
            return error.NotEstablished;
        }

        const f = frame.Frame{
            .type = frame_type,
            .ctrl = frame.Ctrl.init(0, frame_type.defaultPriority(), false),
            .payload = payload,
        };
        try self.credit.debitSend(f);
        return f.encode(out);
    }

    pub fn rootSecret(self: *const Peer) ?[32]u8 {
        const secret = self.shared_secret orelse return null;
        return secret.declassify();
    }

    fn emitHello(self: *Peer, out: []u8) !usize {
        var payload: [max_hello_payload_len]u8 = undefined;
        var w = coilpack.Cbb.init(&payload);
        _ = try w.writeU8(protocol_major);
        _ = try w.writeU8(protocol_minor);
        _ = try w.writeBytes(self.local.name());
        _ = try w.writeBytes(self.local.sid());
        _ = try w.writeU64Le(self.local.capabilities);
        _ = try w.writeU64Le(self.local.epoch_ms);
        try writeAll(&w, &self.local.identity_public_key);
        const written = w.written();
        self.local_hello_hash = hash.Sha256.hash(written);
        return emitFrame(.hello, written, out);
    }

    fn recvHello(self: *Peer, payload: []const u8, out: []u8) !Action {
        if (self.state != .hello_sent) return self.fail(out, "unexpected hello");

        self.remote = decodeHello(payload) catch return self.fail(out, "bad hello");
        self.remote_hello_hash = hash.Sha256.hash(payload);
        if (!versionCompatible(payload)) return self.fail(out, "version mismatch");

        self.role = chooseRole(&self.local, &self.remote);
        self.state = .hello_recv;
        if (self.role == .initiator) {
            const send_len = try self.sendAuthPublicShare(out);
            self.state = .auth_sent;
            return .{ .event = .send, .send_len = send_len };
        }
        return .{};
    }

    fn recvAuth(self: *Peer, payload: []const u8, out: []u8) !Action {
        if (self.state != .hello_recv and self.state != .auth_sent) {
            return self.fail(out, "unexpected auth");
        }
        if (payload.len < 1 + sign.public_key_len + sign.signature_len) {
            return self.fail(out, "bad auth");
        }

        const body = payload[0 .. payload.len - sign.signature_len];
        const sig = payload[payload.len - sign.signature_len ..][0..sign.signature_len].*;
        if (!std.mem.eql(u8, body[1..][0..sign.public_key_len], &self.remote.identity_public_key)) {
            return self.fail(out, "auth key mismatch");
        }
        if (!try self.verifyAuthBody(body, sig)) {
            return self.fail(out, "bad signature");
        }

        const kind: AuthKind = switch (body[0]) {
            @intFromEnum(AuthKind.public_share) => .public_share,
            @intFromEnum(AuthKind.encapsulated_share) => .encapsulated_share,
            else => return self.fail(out, "bad auth kind"),
        };

        switch (kind) {
            .public_share => {
                if (self.role != .responder or self.state != .hello_recv) {
                    return self.fail(out, "unexpected public auth");
                }
                self.initiator_auth.set(body);
                const remote_share = try decodePublicShareBody(body);
                var transcript = self.kxTranscript();
                var seed = self.encapsulation_seed orelse return error.MissingEntropy;
                defer secureZero(&seed);
                var enc = try kx.HybridKx.encapsulateDeterministic(
                    &self.hybrid_kx.x25519,
                    remote_share,
                    &transcript,
                    &seed,
                );
                defer enc.wipe();
                self.replaceSharedSecret(enc.shared_secret);

                const send_len = try self.sendAuthEncapsulated(enc.share, out);
                self.state = .auth_sent;
                return .{ .event = .send, .send_len = send_len };
            },
            .encapsulated_share => {
                if (self.role != .initiator or self.state != .auth_sent) {
                    return self.fail(out, "unexpected encapsulated auth");
                }
                self.responder_auth.set(body);
                const remote_enc = try decodeEncapsulatedBody(body);
                var transcript = self.kxTranscript();
                const secret = try kx.HybridKx.decapsulate(&self.hybrid_kx, remote_enc, &transcript);
                self.replaceSharedSecret(secret);

                const confirm = try self.computeConfirm();
                const send_len = try emitFrame(.auth_ok, &confirm, out);
                self.state = .established;
                return .{ .event = .send_and_established, .send_len = send_len };
            },
        }
    }

    fn recvAuthOk(self: *Peer, payload: []const u8) !Action {
        if (self.role != .responder or self.state != .auth_sent) {
            self.closeAndWipe();
            return .{ .event = .closing };
        }
        if (payload.len != confirm_len) {
            self.closeAndWipe();
            return .{ .event = .closing };
        }
        const expected = try self.computeConfirm();
        const got = payload[0..confirm_len].*;
        if (!std.crypto.timing_safe.eql([confirm_len]u8, expected, got)) {
            self.closeAndWipe();
            return .{ .event = .closing };
        }
        self.state = .established;
        return .{ .event = .established };
    }

    fn sendAuthPublicShare(self: *Peer, out: []u8) !usize {
        const share = self.hybrid_kx.publicShare();
        var body: [max_auth_body_len]u8 = undefined;
        const body_len = try encodePublicShareBody(
            share,
            self.local.identity_public_key,
            &body,
        );
        self.initiator_auth.set(body[0..body_len]);
        return self.signAndEmitAuth(body[0..body_len], out);
    }

    fn sendAuthEncapsulated(
        self: *Peer,
        share: kx.HybridKx.EncapsulatedShare,
        out: []u8,
    ) !usize {
        var body: [max_auth_body_len]u8 = undefined;
        const body_len = try encodeEncapsulatedBody(
            share,
            self.local.identity_public_key,
            &body,
        );
        self.responder_auth.set(body[0..body_len]);
        return self.signAndEmitAuth(body[0..body_len], out);
    }

    fn signAndEmitAuth(self: *Peer, body: []const u8, out: []u8) !usize {
        var msg_buf: [2048]u8 = undefined;
        const msg = try self.authMessage(body, &msg_buf, true);
        const sig = try self.identity.signCtx(auth_domain, msg);

        var payload: [max_auth_payload_len]u8 = undefined;
        @memcpy(payload[0..body.len], body);
        @memcpy(payload[body.len..][0..sign.signature_len], &sig);
        secureZero(msg_buf[0..msg.len]);
        return emitFrame(.auth, payload[0 .. body.len + sign.signature_len], out);
    }

    fn verifyAuthBody(self: *Peer, body: []const u8, sig: sign.Signature) !bool {
        var msg_buf: [2048]u8 = undefined;
        const msg = try self.authMessage(body, &msg_buf, false);
        defer secureZero(msg_buf[0..msg.len]);
        return sign.verifyCtx(auth_domain, msg, sig, self.remote.identity_public_key);
    }

    fn authMessage(
        self: *const Peer,
        body: []const u8,
        out: []u8,
        local_signer: bool,
    ) ![]const u8 {
        var w = coilpack.Cbb.init(out);
        try writeAll(&w, auth_domain);
        _ = try w.writeU8(body[0]);
        if (local_signer) {
            try writeAll(&w, &self.local.identity_public_key);
            try writeAll(&w, &self.remote.identity_public_key);
            try writeAll(&w, &self.local_hello_hash);
            try writeAll(&w, &self.remote_hello_hash);
        } else {
            try writeAll(&w, &self.remote.identity_public_key);
            try writeAll(&w, &self.local.identity_public_key);
            try writeAll(&w, &self.remote_hello_hash);
            try writeAll(&w, &self.local_hello_hash);
        }
        _ = try w.writeBytes(body);
        return w.written();
    }

    fn kxTranscript(self: *const Peer) [2 * hash.Sha256.digest_len + kx_domain.len]u8 {
        var out: [2 * hash.Sha256.digest_len + kx_domain.len]u8 = undefined;
        @memcpy(out[0..kx_domain.len], kx_domain);
        if (self.role == .initiator) {
            @memcpy(out[kx_domain.len..][0..hash.Sha256.digest_len], &self.local_hello_hash);
            @memcpy(out[kx_domain.len + hash.Sha256.digest_len ..], &self.remote_hello_hash);
        } else {
            @memcpy(out[kx_domain.len..][0..hash.Sha256.digest_len], &self.remote_hello_hash);
            @memcpy(out[kx_domain.len + hash.Sha256.digest_len ..], &self.local_hello_hash);
        }
        return out;
    }

    fn computeConfirm(self: *const Peer) ![confirm_len]u8 {
        const secret = self.shared_secret orelse return error.MissingSharedSecret;
        var key = secret.declassify();
        defer secureZero(&key);

        var mac = hash.HmacSha256.init(&key);
        mac.update(auth_ok_domain);
        if (self.role == .initiator) {
            mac.update(&self.local_hello_hash);
            mac.update(&self.remote_hello_hash);
        } else {
            mac.update(&self.remote_hello_hash);
            mac.update(&self.local_hello_hash);
        }
        mac.update(self.initiator_auth.slice());
        mac.update(self.responder_auth.slice());
        return mac.final();
    }

    fn replaceSharedSecret(self: *Peer, secret: kx.SharedSecret) void {
        if (self.shared_secret) |*old| old.wipe();
        self.shared_secret = secret;
    }

    fn fail(self: *Peer, out: []u8, reason: []const u8) !Action {
        self.closeAndWipe();
        return .{
            .event = .closing,
            .send_len = emitFrame(.auth_fail, reason, out) catch 0,
        };
    }

    fn closeAndWipe(self: *Peer) void {
        self.state = .closing;
        if (self.shared_secret) |*secret| secret.wipe();
        self.shared_secret = null;
    }
};

fn fillPeerInfo(
    info: *PeerInfo,
    server_name: []const u8,
    server_id: []const u8,
    capabilities: u64,
    epoch_ms: u64,
    identity_public_key: sign.PublicKey,
) !void {
    if (server_name.len == 0 or server_name.len > max_server_name_len) return error.InvalidServerName;
    if (server_id.len != server_id_len) return error.InvalidServerId;
    info.server_name_len = @intCast(server_name.len);
    @memcpy(info.server_name[0..server_name.len], server_name);
    @memcpy(&info.server_id, server_id);
    info.capabilities = capabilities;
    info.epoch_ms = epoch_ms;
    info.identity_public_key = identity_public_key;
}

fn decodeHello(payload: []const u8) !PeerInfo {
    var r = coilpack.Cbs.init(payload);
    const major = try r.readU8();
    const minor = try r.readU8();
    _ = minor;
    if (major != protocol_major) return error.VersionMismatch;
    const name = try r.readBytes();
    const sid = try r.readBytes();
    const caps = try r.readU64Le();
    const epoch_ms = try r.readU64Le();
    if (r.remaining() < sign.public_key_len) return error.Truncated;
    const pk = r.buf[r.pos..][0..sign.public_key_len].*;
    r.pos += sign.public_key_len;
    if (!r.done()) return error.TrailingBytes;

    var info: PeerInfo = .{};
    try fillPeerInfo(&info, name, sid, caps, epoch_ms, pk);
    return info;
}

fn versionCompatible(payload: []const u8) bool {
    if (payload.len < 2) return false;
    return payload[0] == protocol_major and payload[1] <= protocol_minor;
}

fn chooseRole(local: *const PeerInfo, remote: *const PeerInfo) Role {
    const sid_order = std.mem.order(u8, local.sid(), remote.sid());
    if (sid_order == .lt) return .initiator;
    if (sid_order == .gt) return .responder;
    return switch (std.mem.order(u8, local.name(), remote.name())) {
        .lt, .eq => .initiator,
        .gt => .responder,
    };
}

fn encodePublicShareBody(
    share: kx.HybridKx.PublicShare,
    identity_public_key: sign.PublicKey,
    out: []u8,
) !usize {
    var w = coilpack.Cbb.init(out);
    _ = try w.writeU8(@intFromEnum(AuthKind.public_share));
    try writeAll(&w, &identity_public_key);
    try writeAll(&w, &share.x25519_public_key);
    try writeAll(&w, &share.mlkem_public_key);
    return w.bytesWritten();
}

fn encodeEncapsulatedBody(
    share: kx.HybridKx.EncapsulatedShare,
    identity_public_key: sign.PublicKey,
    out: []u8,
) !usize {
    var w = coilpack.Cbb.init(out);
    _ = try w.writeU8(@intFromEnum(AuthKind.encapsulated_share));
    try writeAll(&w, &identity_public_key);
    try writeAll(&w, &share.x25519_public_key);
    try writeAll(&w, &share.mlkem_ciphertext);
    return w.bytesWritten();
}

fn decodePublicShareBody(body: []const u8) !kx.HybridKx.PublicShare {
    const need = 1 + sign.public_key_len + kx.X25519Kx.public_len +
        kx.HybridKx.mlkem_public_len;
    if (body.len != need or body[0] != @intFromEnum(AuthKind.public_share)) {
        return error.InvalidAuth;
    }
    var pos: usize = 1 + sign.public_key_len;
    const x = body[pos..][0..kx.X25519Kx.public_len].*;
    pos += kx.X25519Kx.public_len;
    return .{
        .x25519_public_key = x,
        .mlkem_public_key = body[pos..][0..kx.HybridKx.mlkem_public_len].*,
    };
}

fn decodeEncapsulatedBody(body: []const u8) !kx.HybridKx.EncapsulatedShare {
    const need = 1 + sign.public_key_len + kx.X25519Kx.public_len +
        kx.HybridKx.mlkem_ciphertext_len;
    if (body.len != need or body[0] != @intFromEnum(AuthKind.encapsulated_share)) {
        return error.InvalidAuth;
    }
    var pos: usize = 1 + sign.public_key_len;
    const x = body[pos..][0..kx.X25519Kx.public_len].*;
    pos += kx.X25519Kx.public_len;
    return .{
        .x25519_public_key = x,
        .mlkem_ciphertext = body[pos..][0..kx.HybridKx.mlkem_ciphertext_len].*,
    };
}

fn emitFrame(frame_type: frame.FrameType, payload: []const u8, out: []u8) !usize {
    const f = frame.Frame{
        .type = frame_type,
        .ctrl = frame.Ctrl.init(0, frame_type.defaultPriority(), false),
        .payload = payload,
    };
    return f.encode(out);
}

fn emitCredit(grant: u32, out: []u8) !usize {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, grant, .little);
    return emitFrame(.credit, &payload, out);
}

fn decodeCredit(payload: []const u8) !u32 {
    if (payload.len != 4) return error.InvalidCredit;
    return std.mem.readInt(u32, payload[0..4], .little);
}

fn writeAll(w: *coilpack.Cbb, bytes: []const u8) !void {
    if (bytes.len > w.remaining()) return error.BufferTooSmall;
    @memcpy(w.buf[w.pos..][0..bytes.len], bytes);
    w.pos += bytes.len;
}

fn secureZero(value: anytype) void {
    const bytes = switch (@typeInfo(@TypeOf(value))) {
        .pointer => std.mem.sliceAsBytes(value),
        else => std.mem.asBytes(&value),
    };
    for (bytes) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn deterministicHybrid(byte: u8) !kx.HybridKx.KeyPair {
    var seed: [kx.HybridKx.seed_len]u8 = undefined;
    @memset(&seed, byte);
    return kx.HybridKx.generateDeterministic(seed);
}

const TestPeer = struct {
    identity: sign.KeyPair = undefined,
    peer: Peer = undefined,
    initialized: bool = false,

    fn init(
        self: *TestPeer,
        name: []const u8,
        sid: []const u8,
        sign_seed: sign.Seed,
        kx_seed_byte: u8,
        enc_seed_byte: u8,
    ) !void {
        self.identity = try sign.KeyPair.fromSeed(sign_seed);
        errdefer self.identity.deinit();

        const hybrid = try deterministicHybrid(kx_seed_byte);
        var enc_seed: [kx.HybridKx.encaps_seed_len]u8 = undefined;
        @memset(&enc_seed, enc_seed_byte);
        self.peer = try Peer.init(.{
            .server_name = name,
            .server_id = sid,
            .capabilities = 0x05,
            .epoch_ms = 42,
            .identity = &self.identity,
            .hybrid_kx = hybrid,
            .encapsulation_seed = enc_seed,
        });
        self.initialized = true;
    }

    fn deinit(self: *TestPeer) void {
        if (!self.initialized) return;
        self.peer.deinit();
        self.identity.deinit();
        self.initialized = false;
    }
};

fn driveFullHandshake(a: *Peer, b: *Peer) !void {
    var a_to_b: [4096]u8 = undefined;
    var b_to_a: [4096]u8 = undefined;

    const a_hello = try a.start(&a_to_b);
    const b_hello = try b.start(&b_to_a);

    const b_auth = try b.feed(try frame.Frame.decode(a_to_b[0..a_hello.send_len]), &b_to_a);
    try std.testing.expectEqual(Event.none, b_auth.event);

    const a_auth = try a.feed(try frame.Frame.decode(b_to_a[0..b_hello.send_len]), &a_to_b);
    try std.testing.expect(a_auth.hasFrame());
    try std.testing.expectEqual(Event.send, a_auth.event);

    const b_auth_resp = try b.feed(try frame.Frame.decode(a_to_b[0..a_auth.send_len]), &b_to_a);
    try std.testing.expect(b_auth_resp.hasFrame());
    try std.testing.expectEqual(Event.send, b_auth_resp.event);

    const a_ok = try a.feed(try frame.Frame.decode(b_to_a[0..b_auth_resp.send_len]), &a_to_b);
    try std.testing.expect(a_ok.hasFrame());
    try std.testing.expectEqual(Event.send_and_established, a_ok.event);

    const b_ok = try b.feed(try frame.Frame.decode(a_to_b[0..a_ok.send_len]), &b_to_a);
    try std.testing.expectEqual(Event.established, b_ok.event);
}

test "full handshake establishes both peers and derives same secret" {
    var left: TestPeer = .{};
    try left.init(
        "alpha.example.net",
        "001",
        hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        0x11,
        0x21,
    );
    defer left.deinit();

    var right: TestPeer = .{};
    try right.init(
        "beta.example.net",
        "002",
        hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
        0x12,
        0x22,
    );
    defer right.deinit();

    try driveFullHandshake(&left.peer, &right.peer);

    try std.testing.expectEqual(State.established, left.peer.state);
    try std.testing.expectEqual(State.established, right.peer.state);
    try std.testing.expectEqualSlices(u8, &left.peer.rootSecret().?, &right.peer.rootSecret().?);
}

test "bad signature is rejected" {
    var left: TestPeer = .{};
    try left.init(
        "alpha.example.net",
        "001",
        hex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
        0x31,
        0x41,
    );
    defer left.deinit();

    var right: TestPeer = .{};
    try right.init(
        "beta.example.net",
        "002",
        hex("303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
        0x32,
        0x42,
    );
    defer right.deinit();

    var a_to_b: [4096]u8 = undefined;
    var b_to_a: [4096]u8 = undefined;
    const a_hello = try left.peer.start(&a_to_b);
    const b_hello = try right.peer.start(&b_to_a);
    _ = try right.peer.feed(try frame.Frame.decode(a_to_b[0..a_hello.send_len]), &b_to_a);
    const a_auth = try left.peer.feed(try frame.Frame.decode(b_to_a[0..b_hello.send_len]), &a_to_b);

    a_to_b[a_auth.send_len - 1] ^= 0x01;
    const rejected = try right.peer.feed(try frame.Frame.decode(a_to_b[0..a_auth.send_len]), &b_to_a);
    try std.testing.expectEqual(Event.closing, rejected.event);
    try std.testing.expectEqual(State.closing, right.peer.state);
}

test "data frame before established is dropped" {
    var left: TestPeer = .{};
    try left.init(
        "alpha.example.net",
        "001",
        hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),
        0x51,
        0x61,
    );
    defer left.deinit();

    var out: [128]u8 = undefined;
    _ = try left.peer.start(&out);
    const act = try left.peer.feed(.{
        .type = .privmsg,
        .ctrl = frame.Ctrl.init(0, .normal, false),
        .payload = "not yet",
    }, &out);
    try std.testing.expectEqual(Event.dropped, act.event);
    try std.testing.expectEqual(State.hello_sent, left.peer.state);
}

test "version mismatch is rejected" {
    var left: TestPeer = .{};
    try left.init(
        "alpha.example.net",
        "001",
        hex("505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"),
        0x71,
        0x81,
    );
    defer left.deinit();

    var out: [512]u8 = undefined;
    _ = try left.peer.start(&out);

    var bad_payload: [max_hello_payload_len]u8 = undefined;
    var w = coilpack.Cbb.init(&bad_payload);
    _ = try w.writeU8(protocol_major + 1);
    _ = try w.writeU8(protocol_minor);
    _ = try w.writeBytes("bad.example.net");
    _ = try w.writeBytes("002");
    _ = try w.writeU64Le(0);
    _ = try w.writeU64Le(1);
    try writeAll(&w, &left.identity.public_key);

    const act = try left.peer.feed(.{
        .type = .hello,
        .ctrl = frame.Ctrl.init(0, .control, false),
        .payload = w.written(),
    }, &out);
    try std.testing.expectEqual(Event.closing, act.event);
    try std.testing.expectEqual(State.closing, left.peer.state);
}

test {
    std.testing.refAllDecls(@This());
}
