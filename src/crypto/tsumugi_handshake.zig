//! Tsumugi S2S secure-channel handshake.
//!
//! This is a compact Noise-IK-shaped AKE for Mizuchi S2S. Ed25519 is the
//! static node identity and signs transport prekeys plus transcripts; X-Wing
//! transport prekeys provide the hybrid KEM entropy. The initiator node id and
//! MeshPass bytes are only present inside encrypted M1.
const std = @import("std");

const hash = @import("hash.zig");
const Secret = @import("secret.zig").Secret;
const sign = @import("sign.zig");
const xwing = @import("xwing.zig");
const toml = @import("../proto/toml.zig");

const Allocator = std.mem.Allocator;
const Blake3 = std.crypto.hash.Blake3;
const ChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Hkdf = hash.HkdfSha256;

pub const NodeId = [20]u8;
pub const RealmId = [32]u8;
pub const RootKey = Secret([32]u8);
pub const ChainKey = Secret([ChaCha.key_length]u8);
pub const Nonce96 = [ChaCha.nonce_length]u8;

pub const protocol_version: u16 = 1;

/// Historic default for the maximum accepted mesh-password length.
pub const default_max_meshpass_len: usize = 4096;

/// Operationally tunable max Tsumugi mesh-password length accepted in the
/// handshake. Overridable via `[tls].tsumugi_max_meshpass_len`; defaults
/// preserve prior behavior.
pub var max_meshpass_len: usize = default_max_meshpass_len;

/// Overlay `[tls].tsumugi_max_meshpass_len` onto the module-level meshpass cap.
/// Absent or zero values leave the current cap unchanged (behavior preserved).
pub fn applyToml(doc: *const toml.Document) void {
    if (doc.getUint("tls.tsumugi_max_meshpass_len")) |v| {
        if (v != 0) max_meshpass_len = @intCast(v);
    }
}

const magic = "MZTH";
const msg_m1: u8 = 1;
const msg_m2: u8 = 2;
const schema_m1: u16 = 0x3002;
const schema_m2: u16 = 0x3003;
const prekey_domain = "tsumugi-prekey-v1";
const m1_sig_domain = "tsumugi-m1-v1";
const m2_sig_domain = "tsumugi-m2-v1";

pub const State = enum { idle, m1_sent, m1_recv, m2_sent, established };

pub const Error = error{
    InvalidState,
    InvalidMessage,
    UnsupportedVersion,
    WrongPrekey,
    RealmMismatch,
    PrekeyExpired,
    IdentityMismatch,
    BadSignature,
    AuthFailed,
    DowngradeAttempt,
    NoCommonBands,
    MeshPassTooLarge,
} || Allocator.Error || xwing.Error || sign.SignError || sign.VerifyError || hash.HkdfError;

pub const Config = struct {
    realm: RealmId,
    supported_bands: u128,
    supported_features: u128 = 0,
    mesh_pass: []const u8 = &.{},
    now_ms: u64 = 0,
};

pub const Established = struct {
    root_key: RootKey,
    send_key: ChainKey,
    recv_key: ChainKey,
    send_nonce: Nonce96,
    recv_nonce: Nonce96,
    peer_node_id: NodeId,
    /// The peer's authenticated raw Ed25519 signing public key (verified against
    /// `peer_node_id` during the AKE). Used to verify peer-signed artifacts such
    /// as cross-mesh operator grants.
    peer_node_key: sign.PublicKey,
    accepted_bands: u128,
    accepted_features: u128,

    pub fn deinit(self: *Established) void {
        self.root_key.wipe();
        self.send_key.wipe();
        self.recv_key.wipe();
    }
};

pub const SignedPrekey = struct {
    realm: RealmId,
    node_key: sign.PublicKey,
    node_id: NodeId,
    prekey_id: u64,
    public_key: xwing.PublicKey,
    not_before_ms: u64,
    not_after_ms: u64,
    usage_bits: u16,
    supported_bands: u128,
    supported_features: u128,
    sig: sign.Signature,

    pub fn create(
        node: *const sign.KeyPair,
        kem: *const xwing.KeyPair,
        realm: RealmId,
        prekey_id: u64,
        now_ms: u64,
        ttl_ms: u64,
        usage_bits: u16,
        supported_bands: u128,
        supported_features: u128,
    ) Error!SignedPrekey {
        var out = SignedPrekey{
            .realm = realm,
            .node_key = node.public_key,
            .node_id = nodeIdFromKey(node.public_key),
            .prekey_id = prekey_id,
            .public_key = kem.public_key,
            .not_before_ms = now_ms,
            .not_after_ms = now_ms + ttl_ms,
            .usage_bits = usage_bits,
            .supported_bands = supported_bands,
            .supported_features = supported_features,
            .sig = [_]u8{0} ** sign.signature_len,
        };
        const digest = prekeyDigest(&out);
        out.sig = try node.signCtx(prekey_domain, &digest);
        return out;
    }

    pub fn verify(self: *const SignedPrekey, now_ms: u64) Error!void {
        if (!std.mem.eql(u8, &self.node_id, &nodeIdFromKey(self.node_key))) return error.IdentityMismatch;
        if (now_ms < self.not_before_ms or now_ms > self.not_after_ms) return error.PrekeyExpired;
        const digest = prekeyDigest(self);
        if (!try sign.verifyCtx(prekey_domain, &digest, self.sig, self.node_key)) return error.BadSignature;
    }
};

pub const Initiator = struct {
    allocator: Allocator,
    local_node: *const sign.KeyPair,
    local_prekey: SignedPrekey,
    local_prekey_secret: *const xwing.SecretKey,
    responder_prekey: SignedPrekey,
    cfg: Config,
    state: State = .idle,
    m1_wire: []u8 = &.{},
    first_secret: ?xwing.SharedSecret = null,

    pub fn init(
        allocator: Allocator,
        local_node: *const sign.KeyPair,
        local_prekey: SignedPrekey,
        local_prekey_secret: *const xwing.SecretKey,
        responder_prekey: SignedPrekey,
        cfg: Config,
    ) Initiator {
        return .{
            .allocator = allocator,
            .local_node = local_node,
            .local_prekey = local_prekey,
            .local_prekey_secret = local_prekey_secret,
            .responder_prekey = responder_prekey,
            .cfg = cfg,
        };
    }

    pub fn deinit(self: *Initiator) void {
        self.allocator.free(self.m1_wire);
        if (self.first_secret) |*s| s.wipe();
    }

    pub fn start(self: *Initiator, rng: std.Io) Error![]u8 {
        if (self.state != .idle) return error.InvalidState;
        try self.responder_prekey.verify(self.cfg.now_ms);
        try self.local_prekey.verify(self.cfg.now_ms);
        if (!std.mem.eql(u8, &self.cfg.realm, &self.responder_prekey.realm)) return error.RealmMismatch;
        if (self.cfg.mesh_pass.len > max_meshpass_len) return error.MeshPassTooLarge;

        var enc = try xwing.encapsulate(self.responder_prekey.public_key, rng);
        errdefer enc.wipe();

        var prefix = std.ArrayList(u8).empty;
        defer prefix.deinit(self.allocator);
        try writeHeader(&prefix, self.allocator, msg_m1, protocol_version);
        try writeU64(&prefix, self.allocator, self.responder_prekey.prekey_id);
        try prefix.appendSlice(self.allocator, &enc.ciphertext);
        const nonce = nonceFrom("M1 nonce", &enc.shared, prefix.items);
        try prefix.appendSlice(self.allocator, &nonce);

        const payload = try self.buildM1Payload(prefix.items);
        defer self.allocator.free(payload);
        const sealed = try sealPayload(self.allocator, &enc.shared, "M1 key", prefix.items, payload);
        defer self.allocator.free(sealed);

        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, prefix.items);
        try writeU16(&out, self.allocator, @intCast(sealed.len - ChaCha.tag_length));
        try out.appendSlice(self.allocator, sealed);

        self.m1_wire = try self.allocator.dupe(u8, out.items);
        self.first_secret = enc.shared;
        self.state = .m1_sent;
        return out.toOwnedSlice(self.allocator);
    }

    pub fn recv(self: *Initiator, bytes: []const u8) Error!Established {
        if (self.state != .m1_sent) return error.InvalidState;
        var first = self.first_secret orelse return error.InvalidState;
        defer first.wipe();
        self.first_secret = null;

        const m2 = try parseM2(bytes);
        var second = try xwing.decapsulate(self.local_prekey_secret, m2.ct);
        defer second.wipe();

        var m2_secret = m2Secret(&first, &second, self.m1_wire, m2.prefix);
        const plaintext = try openPayload(self.allocator, &m2_secret, "M2 key", m2.prefix, m2.enc, m2.tag);
        defer self.allocator.free(plaintext);
        defer m2_secret.wipe();

        const body = try decodeM2Payload(plaintext);
        if (!std.mem.eql(u8, &body.node_id, &nodeIdFromKey(body.node_key))) return error.IdentityMismatch;
        if (!std.mem.eql(u8, &body.node_id, &self.responder_prekey.node_id)) return error.IdentityMismatch;
        const expected_bands = self.cfg.supported_bands & self.responder_prekey.supported_bands;
        const expected_features = self.cfg.supported_features & self.responder_prekey.supported_features;
        if (expected_bands == 0) return error.NoCommonBands;
        if (body.accepted_bands != expected_bands or body.accepted_features != expected_features) return error.DowngradeAttempt;
        const sig_digest = digest2(self.m1_wire, m2.prefix, body.signed);
        if (!try sign.verifyCtx(m2_sig_domain, &sig_digest, body.sig, body.node_key)) return error.BadSignature;

        self.state = .established;
        return deriveEstablished(.initiator, &first, &second, self.m1_wire, bytes, body.node_id, body.node_key, body.accepted_bands, body.accepted_features);
    }

    fn buildM1Payload(self: *Initiator, prefix: []const u8) Error![]u8 {
        const expected_bands = self.cfg.supported_bands & self.responder_prekey.supported_bands;
        if (expected_bands == 0) return error.NoCommonBands;

        var body = std.ArrayList(u8).empty;
        errdefer body.deinit(self.allocator);
        try writeU16(&body, self.allocator, schema_m1);
        try body.appendSlice(self.allocator, &nodeIdFromKey(self.local_node.public_key));
        try body.appendSlice(self.allocator, &self.local_node.public_key);
        try encodePrekey(&body, self.allocator, &self.local_prekey);
        try writeU128(&body, self.allocator, expected_bands);
        try writeU128(&body, self.allocator, self.cfg.supported_features & self.responder_prekey.supported_features);
        try writeU64(&body, self.allocator, self.cfg.now_ms);
        try writeBytes16(&body, self.allocator, self.cfg.mesh_pass);

        const sig_digest = digest2(prefix, body.items, "");
        const sig = try self.local_node.signCtx(m1_sig_domain, &sig_digest);
        try body.appendSlice(self.allocator, &sig);
        return body.toOwnedSlice(self.allocator);
    }
};

pub const Responder = struct {
    allocator: Allocator,
    local_node: *const sign.KeyPair,
    local_prekey: SignedPrekey,
    local_prekey_secret: *const xwing.SecretKey,
    cfg: Config,
    state: State = .idle,
    established: ?Established = null,

    pub fn init(
        allocator: Allocator,
        local_node: *const sign.KeyPair,
        local_prekey: SignedPrekey,
        local_prekey_secret: *const xwing.SecretKey,
        cfg: Config,
    ) Responder {
        return .{ .allocator = allocator, .local_node = local_node, .local_prekey = local_prekey, .local_prekey_secret = local_prekey_secret, .cfg = cfg };
    }

    pub fn deinit(self: *Responder) void {
        if (self.established) |*e| e.deinit();
    }

    pub fn recv(self: *Responder, bytes: []const u8, rng: std.Io) Error![]u8 {
        if (self.state != .idle) return error.InvalidState;
        try self.local_prekey.verify(self.cfg.now_ms);
        const m1 = try parseM1(bytes);
        if (m1.version != protocol_version) return error.UnsupportedVersion;
        if (m1.prekey_id != self.local_prekey.prekey_id) return error.WrongPrekey;

        var first = try xwing.decapsulate(self.local_prekey_secret, m1.ct);
        defer first.wipe();
        const plaintext = try openPayload(self.allocator, &first, "M1 key", m1.prefix, m1.enc, m1.tag);
        defer self.allocator.free(plaintext);
        const body = try decodeM1Payload(plaintext);
        try body.prekey.verify(self.cfg.now_ms);
        if (!std.mem.eql(u8, &body.prekey.realm, &self.cfg.realm)) return error.RealmMismatch;
        if (!std.mem.eql(u8, &body.node_id, &nodeIdFromKey(body.node_key))) return error.IdentityMismatch;
        if (!std.mem.eql(u8, &body.node_id, &body.prekey.node_id)) return error.IdentityMismatch;
        const expected_bands = self.local_prekey.supported_bands & body.prekey.supported_bands;
        const expected_features = self.local_prekey.supported_features & body.prekey.supported_features;
        if (expected_bands == 0) return error.NoCommonBands;
        if (body.requested_bands != expected_bands or body.requested_features != expected_features) return error.DowngradeAttempt;
        const sig_digest = digest2(m1.prefix, body.signed, "");
        if (!try sign.verifyCtx(m1_sig_domain, &sig_digest, body.sig, body.node_key)) return error.BadSignature;

        self.state = .m1_recv;
        var enc2 = try xwing.encapsulate(body.prekey.public_key, rng);
        defer enc2.wipe();
        var prefix = std.ArrayList(u8).empty;
        defer prefix.deinit(self.allocator);
        try writeHeader(&prefix, self.allocator, msg_m2, protocol_version);
        try prefix.appendSlice(self.allocator, &enc2.ciphertext);
        const nonce = nonceFrom("M2 nonce", &enc2.shared, prefix.items);
        try prefix.appendSlice(self.allocator, &nonce);
        const m2_secret_value = m2Secret(&first, &enc2.shared, bytes, prefix.items);
        var m2_secret = m2_secret_value;
        defer m2_secret.wipe();

        const payload = try self.buildM2Payload(prefix.items, bytes, body.node_id, expected_bands, expected_features);
        defer self.allocator.free(payload);
        const sealed = try sealPayload(self.allocator, &m2_secret, "M2 key", prefix.items, payload);
        defer self.allocator.free(sealed);

        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, prefix.items);
        try writeU16(&out, self.allocator, @intCast(sealed.len - ChaCha.tag_length));
        try out.appendSlice(self.allocator, sealed);
        const wire = try out.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(wire);
        self.established = try deriveEstablished(.responder, &first, &enc2.shared, bytes, wire, body.node_id, body.node_key, expected_bands, expected_features);
        self.state = .m2_sent;
        return wire;
    }

    fn buildM2Payload(
        self: *Responder,
        prefix: []const u8,
        m1_wire: []const u8,
        peer: NodeId,
        bands: u128,
        features: u128,
    ) Error![]u8 {
        _ = peer;
        var body = std.ArrayList(u8).empty;
        errdefer body.deinit(self.allocator);
        try writeU16(&body, self.allocator, schema_m2);
        try body.appendSlice(self.allocator, &nodeIdFromKey(self.local_node.public_key));
        try body.appendSlice(self.allocator, &self.local_node.public_key);
        try writeU128(&body, self.allocator, bands);
        try writeU128(&body, self.allocator, features);
        try writeU64(&body, self.allocator, self.cfg.now_ms);
        try writeU32(&body, self.allocator, 0);
        try writeU32(&body, self.allocator, 0);
        const sig_digest = digest2(m1_wire, prefix, body.items);
        const sig = try self.local_node.signCtx(m2_sig_domain, &sig_digest);
        try body.appendSlice(self.allocator, &sig);
        return body.toOwnedSlice(self.allocator);
    }
};

const Role = enum { initiator, responder };
const ParsedM1 = struct { version: u16, prekey_id: u64, ct: xwing.Ciphertext, prefix: []const u8, enc: []const u8, tag: [ChaCha.tag_length]u8 };
const ParsedM2 = struct { ct: xwing.Ciphertext, prefix: []const u8, enc: []const u8, tag: [ChaCha.tag_length]u8 };
const M1Body = struct { signed: []const u8, node_id: NodeId, node_key: sign.PublicKey, prekey: SignedPrekey, requested_bands: u128, requested_features: u128, sig: sign.Signature };
const M2Body = struct { signed: []const u8, node_id: NodeId, node_key: sign.PublicKey, accepted_bands: u128, accepted_features: u128, sig: sign.Signature };

fn nodeIdFromKey(pk: sign.PublicKey) NodeId {
    var full: [Blake3.digest_length]u8 = undefined;
    Blake3.hash(&pk, &full, .{});
    return full[0..20].*;
}

fn prekeyDigest(p: *const SignedPrekey) [32]u8 {
    var h = Blake3.init(.{});
    h.update("MZ-TSUMUGI-PREKEY-v1");
    h.update(&p.realm);
    h.update(&p.node_key);
    h.update(&p.node_id);
    updateInt(u64, &h, p.prekey_id);
    h.update(&p.public_key);
    updateInt(u64, &h, p.not_before_ms);
    updateInt(u64, &h, p.not_after_ms);
    updateInt(u16, &h, p.usage_bits);
    updateInt(u128, &h, p.supported_bands);
    updateInt(u128, &h, p.supported_features);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn digest2(a: []const u8, b: []const u8, c: []const u8) [32]u8 {
    var h = Blake3.init(.{});
    h.update("MZ-TSUMUGI-TRANSCRIPT-v1");
    h.update(a);
    h.update(b);
    h.update(c);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn updateInt(comptime T: type, h: *Blake3, value: T) void {
    var b: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
    std.mem.writeInt(T, &b, value, .little);
    h.update(&b);
}

fn deriveEstablished(role: Role, first: *const xwing.SharedSecret, second: *const xwing.SharedSecret, m1: []const u8, m2: []const u8, peer: NodeId, peer_key: sign.PublicKey, bands: u128, features: u128) Error!Established {
    var hs: [32]u8 = undefined;
    var h = Blake3.init(.{});
    h.update("MZ-TSUMUGI-XWING-IK-v1");
    h.update(&first.declassify());
    h.update(&second.declassify());
    h.update(m1);
    h.update(m2);
    h.final(&hs);
    var root = Hkdf.extractRaw("MZ root", &hs);
    secureZero(&hs);

    var c2s_key: [32]u8 = undefined;
    var s2c_key: [32]u8 = undefined;
    var c2s_nonce: [12]u8 = undefined;
    var s2c_nonce: [12]u8 = undefined;
    try Hkdf.expand(&root, "c2s aead key gen0", &c2s_key);
    try Hkdf.expand(&root, "s2c aead key gen0", &s2c_key);
    try Hkdf.expand(&root, "c2s nonce gen0", &c2s_nonce);
    try Hkdf.expand(&root, "s2c nonce gen0", &s2c_nonce);

    return switch (role) {
        .initiator => .{ .root_key = root, .send_key = ChainKey.init(c2s_key), .recv_key = ChainKey.init(s2c_key), .send_nonce = c2s_nonce, .recv_nonce = s2c_nonce, .peer_node_id = peer, .peer_node_key = peer_key, .accepted_bands = bands, .accepted_features = features },
        .responder => .{ .root_key = root, .send_key = ChainKey.init(s2c_key), .recv_key = ChainKey.init(c2s_key), .send_nonce = s2c_nonce, .recv_nonce = c2s_nonce, .peer_node_id = peer, .peer_node_key = peer_key, .accepted_bands = bands, .accepted_features = features },
    };
}

fn m2Secret(first: *const xwing.SharedSecret, second: *const xwing.SharedSecret, m1: []const u8, prefix: []const u8) xwing.SharedSecret {
    var h = Blake3.init(.{});
    h.update("MZ-TSUMUGI-M2-SECRET-v1");
    h.update(&first.declassify());
    h.update(&second.declassify());
    h.update(m1);
    h.update(prefix);
    var out: [32]u8 = undefined;
    h.final(&out);
    return xwing.SharedSecret.init(out);
}

fn nonceFrom(comptime label: []const u8, secret: *const xwing.SharedSecret, aad: []const u8) [12]u8 {
    var h = Blake3.init(.{});
    h.update(label);
    h.update(&secret.declassify());
    h.update(aad);
    var full: [32]u8 = undefined;
    h.final(&full);
    return full[0..12].*;
}

fn sealPayload(allocator: Allocator, secret: *const xwing.SharedSecret, comptime label: []const u8, aad: []const u8, pt: []const u8) Error![]u8 {
    var key: [32]u8 = undefined;
    deriveHandshakeKey(secret, label, aad, &key);
    defer secureZero(&key);
    var out = try allocator.alloc(u8, pt.len + ChaCha.tag_length);
    errdefer allocator.free(out);
    const nonce = nonceFrom(label ++ " nonce", secret, aad);
    ChaCha.encrypt(out[0..pt.len], out[pt.len..][0..ChaCha.tag_length], pt, aad, nonce, key);
    return out;
}

fn openPayload(allocator: Allocator, secret: *const xwing.SharedSecret, comptime label: []const u8, aad: []const u8, ct: []const u8, tag: [ChaCha.tag_length]u8) Error![]u8 {
    var key: [32]u8 = undefined;
    deriveHandshakeKey(secret, label, aad, &key);
    defer secureZero(&key);
    const out = try allocator.alloc(u8, ct.len);
    errdefer allocator.free(out);
    const nonce = nonceFrom(label ++ " nonce", secret, aad);
    ChaCha.decrypt(out, ct, tag, aad, nonce, key) catch return error.AuthFailed;
    return out;
}

fn deriveHandshakeKey(secret: *const xwing.SharedSecret, comptime label: []const u8, aad: []const u8, out: *[32]u8) void {
    var salt: [32]u8 = undefined;
    var h = Blake3.init(.{});
    h.update(label);
    h.update(aad);
    h.final(&salt);
    var prk = Hkdf.extractRaw(&salt, &secret.declassify());
    defer prk.wipe();
    Hkdf.expand(&prk, label, out) catch unreachable;
}

fn writeHeader(out: *std.ArrayList(u8), allocator: Allocator, typ: u8, version: u16) Error!void {
    try out.appendSlice(allocator, magic);
    try out.append(allocator, typ);
    try writeU16(out, allocator, version);
}

fn writeU16(out: *std.ArrayList(u8), allocator: Allocator, v: u16) Error!void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .little);
    try out.appendSlice(allocator, &b);
}
fn writeU32(out: *std.ArrayList(u8), allocator: Allocator, v: u32) Error!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try out.appendSlice(allocator, &b);
}
fn writeU64(out: *std.ArrayList(u8), allocator: Allocator, v: u64) Error!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    try out.appendSlice(allocator, &b);
}
fn writeU128(out: *std.ArrayList(u8), allocator: Allocator, v: u128) Error!void {
    var b: [16]u8 = undefined;
    std.mem.writeInt(u128, &b, v, .little);
    try out.appendSlice(allocator, &b);
}
fn writeBytes16(out: *std.ArrayList(u8), allocator: Allocator, bytes: []const u8) Error!void {
    if (bytes.len > std.math.maxInt(u16)) return error.MeshPassTooLarge;
    try writeU16(out, allocator, @intCast(bytes.len));
    try out.appendSlice(allocator, bytes);
}

/// Serialize a signed prekey to a standalone byte buffer (caller owns it). Used
/// by the S2S TOFU preamble, where the responder announces its prekey before the
/// IK handshake so the initiator need not know it in advance.
pub fn encodeSignedPrekey(allocator: Allocator, p: *const SignedPrekey) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try encodePrekey(&out, allocator, p);
    return out.toOwnedSlice(allocator);
}

/// Parse a signed prekey from bytes produced by `encodeSignedPrekey`. The caller
/// MUST then `verify` it (signature + validity window) before trusting it.
pub fn decodeSignedPrekey(bytes: []const u8) Error!SignedPrekey {
    var r = Reader{ .buf = bytes };
    const p = try decodePrekey(&r);
    if (r.pos != bytes.len) return error.InvalidMessage;
    return p;
}

fn encodePrekey(out: *std.ArrayList(u8), allocator: Allocator, p: *const SignedPrekey) Error!void {
    try out.appendSlice(allocator, &p.realm);
    try out.appendSlice(allocator, &p.node_key);
    try out.appendSlice(allocator, &p.node_id);
    try writeU64(out, allocator, p.prekey_id);
    try out.appendSlice(allocator, &p.public_key);
    try writeU64(out, allocator, p.not_before_ms);
    try writeU64(out, allocator, p.not_after_ms);
    try writeU16(out, allocator, p.usage_bits);
    try writeU128(out, allocator, p.supported_bands);
    try writeU128(out, allocator, p.supported_features);
    try out.appendSlice(allocator, &p.sig);
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,
    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.buf.len) return error.InvalidMessage;
        defer self.pos += n;
        return self.buf[self.pos..][0..n];
    }
    fn readU16(self: *Reader) Error!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .little);
    }
    fn readU32(self: *Reader) Error!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }
    fn readU64(self: *Reader) Error!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }
    fn readU128(self: *Reader) Error!u128 {
        return std.mem.readInt(u128, (try self.take(16))[0..16], .little);
    }
};

fn parseM1(bytes: []const u8) Error!ParsedM1 {
    var r = Reader{ .buf = bytes };
    if (!std.mem.eql(u8, try r.take(4), magic)) return error.InvalidMessage;
    if ((try r.take(1))[0] != msg_m1) return error.InvalidMessage;
    const version = try r.readU16();
    const prekey_id = try r.readU64();
    const ct = (try r.take(xwing.ciphertext_len))[0..xwing.ciphertext_len].*;
    _ = try r.take(12);
    const prefix_len = r.pos;
    const enc_len = try r.readU16();
    const enc = try r.take(enc_len);
    const tag = (try r.take(ChaCha.tag_length))[0..ChaCha.tag_length].*;
    if (r.pos != bytes.len) return error.InvalidMessage;
    return .{ .version = version, .prekey_id = prekey_id, .ct = ct, .prefix = bytes[0..prefix_len], .enc = enc, .tag = tag };
}

fn parseM2(bytes: []const u8) Error!ParsedM2 {
    var r = Reader{ .buf = bytes };
    if (!std.mem.eql(u8, try r.take(4), magic)) return error.InvalidMessage;
    if ((try r.take(1))[0] != msg_m2) return error.InvalidMessage;
    if (try r.readU16() != protocol_version) return error.UnsupportedVersion;
    const ct = (try r.take(xwing.ciphertext_len))[0..xwing.ciphertext_len].*;
    _ = try r.take(12);
    const prefix_len = r.pos;
    const enc_len = try r.readU16();
    const enc = try r.take(enc_len);
    const tag = (try r.take(ChaCha.tag_length))[0..ChaCha.tag_length].*;
    if (r.pos != bytes.len) return error.InvalidMessage;
    return .{ .ct = ct, .prefix = bytes[0..prefix_len], .enc = enc, .tag = tag };
}

fn decodePrekey(r: *Reader) Error!SignedPrekey {
    var p: SignedPrekey = undefined;
    p.realm = (try r.take(32))[0..32].*;
    p.node_key = (try r.take(sign.public_key_len))[0..sign.public_key_len].*;
    p.node_id = (try r.take(20))[0..20].*;
    p.prekey_id = try r.readU64();
    p.public_key = (try r.take(xwing.public_key_len))[0..xwing.public_key_len].*;
    p.not_before_ms = try r.readU64();
    p.not_after_ms = try r.readU64();
    p.usage_bits = try r.readU16();
    p.supported_bands = try r.readU128();
    p.supported_features = try r.readU128();
    p.sig = (try r.take(sign.signature_len))[0..sign.signature_len].*;
    return p;
}

fn decodeM1Payload(bytes: []const u8) Error!M1Body {
    var r = Reader{ .buf = bytes };
    if (try r.readU16() != schema_m1) return error.InvalidMessage;
    const node_id = (try r.take(20))[0..20].*;
    const node_key = (try r.take(sign.public_key_len))[0..sign.public_key_len].*;
    const prekey = try decodePrekey(&r);
    const requested_bands = try r.readU128();
    const requested_features = try r.readU128();
    _ = try r.readU64();
    const pass_len = try r.readU16();
    _ = try r.take(pass_len);
    const signed = bytes[0..r.pos];
    const sig = (try r.take(sign.signature_len))[0..sign.signature_len].*;
    if (r.pos != bytes.len) return error.InvalidMessage;
    return .{ .signed = signed, .node_id = node_id, .node_key = node_key, .prekey = prekey, .requested_bands = requested_bands, .requested_features = requested_features, .sig = sig };
}

fn decodeM2Payload(bytes: []const u8) Error!M2Body {
    var r = Reader{ .buf = bytes };
    if (try r.readU16() != schema_m2) return error.InvalidMessage;
    const node_id = (try r.take(20))[0..20].*;
    const node_key = (try r.take(sign.public_key_len))[0..sign.public_key_len].*;
    const accepted_bands = try r.readU128();
    const accepted_features = try r.readU128();
    _ = try r.readU64();
    _ = try r.readU32();
    _ = try r.readU32();
    const signed = bytes[0..r.pos];
    const sig = (try r.take(sign.signature_len))[0..sign.signature_len].*;
    if (r.pos != bytes.len) return error.InvalidMessage;
    return .{ .signed = signed, .node_id = node_id, .node_key = node_key, .accepted_bands = accepted_bands, .accepted_features = accepted_features, .sig = sig };
}

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

fn makeFixture(allocator: Allocator) !struct {
    i_node: sign.KeyPair,
    r_node: sign.KeyPair,
    i_kem: xwing.KeyPair,
    r_kem: xwing.KeyPair,
    i_pre: SignedPrekey,
    r_pre: SignedPrekey,
    cfg_i: Config,
    cfg_r: Config,
    allocator: Allocator,
    fn deinit(self: *@This()) void {
        self.i_node.deinit();
        self.r_node.deinit();
        self.i_kem.wipe();
        self.r_kem.wipe();
    }
} {
    const realm = [_]u8{0xA1} ** 32;
    var i_node = try sign.KeyPair.fromSeed([_]u8{0x11} ** 32);
    var r_node = try sign.KeyPair.fromSeed([_]u8{0x22} ** 32);
    var i_kem = try xwing.KeyPair.generateDeterministic([_]u8{0x33} ** 32);
    var r_kem = try xwing.KeyPair.generateDeterministic([_]u8{0x44} ** 32);
    const bands: u128 = 0b1111;
    const features: u128 = 0b101;
    return .{
        .i_node = i_node,
        .r_node = r_node,
        .i_kem = i_kem,
        .r_kem = r_kem,
        .i_pre = try SignedPrekey.create(&i_node, &i_kem, realm, 1, 10, 1000, 1, bands, features),
        .r_pre = try SignedPrekey.create(&r_node, &r_kem, realm, 2, 10, 1000, 1, bands, features),
        .cfg_i = .{ .realm = realm, .supported_bands = bands, .supported_features = features, .mesh_pass = "meshpass secret", .now_ms = 20 },
        .cfg_r = .{ .realm = realm, .supported_bands = bands, .supported_features = features, .now_ms = 20 },
        .allocator = allocator,
    };
}

const DeterministicIo = struct {
    s: u64,
    fn io(self: *DeterministicIo) std.Io {
        return .{ .userdata = self, .vtable = &vtable };
    }
    fn random(userdata: ?*anyopaque, buffer: []u8) void {
        var self: *DeterministicIo = @ptrCast(@alignCast(userdata.?));
        for (buffer) |*b| {
            self.s = self.s *% 6364136223846793005 +% 1442695040888963407;
            b.* = @truncate(self.s >> 56);
        }
    }
    const vtable: std.Io.VTable = blk: {
        var vt = std.Io.failing.vtable.*;
        vt.random = random;
        break :blk vt;
    };
};

test "two parties complete Tsumugi handshake and derive crossed keys" {
    var fx = try makeFixture(std.testing.allocator);
    defer fx.deinit();
    var rng = DeterministicIo{ .s = 0x1234 };
    var initr = Initiator.init(std.testing.allocator, &fx.i_node, fx.i_pre, &fx.i_kem.secret_key, fx.r_pre, fx.cfg_i);
    defer initr.deinit();
    var respr = Responder.init(std.testing.allocator, &fx.r_node, fx.r_pre, &fx.r_kem.secret_key, fx.cfg_r);
    defer respr.deinit();

    const m1 = try initr.start(rng.io());
    defer std.testing.allocator.free(m1);
    const m2 = try respr.recv(m1, rng.io());
    defer std.testing.allocator.free(m2);
    var est_i = try initr.recv(m2);
    defer est_i.deinit();
    const est_r = &respr.established.?;

    try std.testing.expectEqualSlices(u8, &est_i.send_key.declassify(), &est_r.recv_key.declassify());
    try std.testing.expectEqualSlices(u8, &est_i.recv_key.declassify(), &est_r.send_key.declassify());
    try std.testing.expectEqualSlices(u8, &fx.r_pre.node_id, &est_i.peer_node_id);
    try std.testing.expectEqualSlices(u8, &fx.i_pre.node_id, &est_r.peer_node_id);
}

test "signed prekey encode/decode round-trips, verifies, and rejects truncation" {
    var fx = try makeFixture(std.testing.allocator);
    defer fx.deinit();
    const bytes = try encodeSignedPrekey(std.testing.allocator, &fx.i_pre);
    defer std.testing.allocator.free(bytes);

    const decoded = try decodeSignedPrekey(bytes);
    try decoded.verify(500); // within the prekey's [10, 1010] validity window
    try std.testing.expectEqualSlices(u8, &fx.i_pre.node_id, &decoded.node_id);
    try std.testing.expectError(error.InvalidMessage, decodeSignedPrekey(bytes[0 .. bytes.len - 1]));
}

test "tampered transcript signature fails" {
    var fx = try makeFixture(std.testing.allocator);
    defer fx.deinit();
    var rng = DeterministicIo{ .s = 0x5555 };
    var initr = Initiator.init(std.testing.allocator, &fx.i_node, fx.i_pre, &fx.i_kem.secret_key, fx.r_pre, fx.cfg_i);
    defer initr.deinit();
    var respr = Responder.init(std.testing.allocator, &fx.r_node, fx.r_pre, &fx.r_kem.secret_key, fx.cfg_r);
    defer respr.deinit();
    const m1 = try initr.start(rng.io());
    defer std.testing.allocator.free(m1);
    var m2 = try respr.recv(m1, rng.io());
    defer std.testing.allocator.free(m2);
    m2[m2.len - 1] ^= 1;
    try std.testing.expectError(error.AuthFailed, initr.recv(m2));
}

test "downgrade attempt fails" {
    var fx = try makeFixture(std.testing.allocator);
    defer fx.deinit();
    var rng = DeterministicIo{ .s = 0x7777 };
    fx.cfg_i.supported_bands = 0b0011;
    var initr = Initiator.init(std.testing.allocator, &fx.i_node, fx.i_pre, &fx.i_kem.secret_key, fx.r_pre, fx.cfg_i);
    defer initr.deinit();
    var respr = Responder.init(std.testing.allocator, &fx.r_node, fx.r_pre, &fx.r_kem.secret_key, fx.cfg_r);
    defer respr.deinit();
    const m1 = try initr.start(rng.io());
    defer std.testing.allocator.free(m1);
    try std.testing.expectError(error.DowngradeAttempt, respr.recv(m1, rng.io()));
}

test "initiator identity and MeshPass are not cleartext in M1" {
    var fx = try makeFixture(std.testing.allocator);
    defer fx.deinit();
    var rng = DeterministicIo{ .s = 0x9999 };
    var initr = Initiator.init(std.testing.allocator, &fx.i_node, fx.i_pre, &fx.i_kem.secret_key, fx.r_pre, fx.cfg_i);
    defer initr.deinit();
    const m1 = try initr.start(rng.io());
    defer std.testing.allocator.free(m1);
    try std.testing.expect(!contains(m1, &fx.i_pre.node_id));
    try std.testing.expect(!contains(m1, &fx.i_node.public_key));
    try std.testing.expect(!contains(m1, fx.cfg_i.mesh_pass));
}

test "applyToml overrides tsumugi_max_meshpass_len and restores cleanly" {
    const saved = max_meshpass_len;
    defer max_meshpass_len = saved; // never leak the override into other tests
    const allocator = std.testing.allocator;

    var doc = try toml.parse(allocator, "[tls]\ntsumugi_max_meshpass_len = 512\n");
    defer doc.deinit(allocator);
    applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 512), max_meshpass_len);

    // Absent / zero leaves the current value unchanged.
    max_meshpass_len = default_max_meshpass_len;
    var zero = try toml.parse(allocator, "[tls]\ntsumugi_max_meshpass_len = 0\n");
    defer zero.deinit(allocator);
    applyToml(&zero);
    try std.testing.expectEqual(default_max_meshpass_len, max_meshpass_len);
}
