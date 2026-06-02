//! Operator authentication and typed privilege grants.
//!
//! OPER is deliberately a small boundary: select an operator declaration by
//! name and host mask, verify one configured credential, then return typed
//! privileges. Password verification supports PBKDF2-HMAC-SHA256 hashes in the
//! form `pbkdf2-sha256$rounds$salt_hex$derived_key_hex`; public-key proofs use
//! a fixed `oper-auth-v1` Ed25519 context prefix.
const std = @import("std");

const config = @import("config.zig");

const StdEd25519 = std.crypto.sign.Ed25519;

pub const PublicKey = [StdEd25519.PublicKey.encoded_length]u8;
pub const Signature = [StdEd25519.Signature.encoded_length]u8;

pub const default_params = Params{};

/// Compile-time bounds for stack buffers and attacker-controlled inputs.
pub const Params = struct {
    max_name_len: usize = 64,
    max_host_len: usize = 255,
    max_password_len: usize = 512,
    max_salt_len: usize = 64,
    max_challenge_len: usize = 256,
};

/// Errors surfaced by the oper authenticator.
pub const AuthError = error{
    HostMaskMismatch,
    InvalidCredential,
    InvalidInput,
    InvalidPasswordHash,
    MissingCredential,
    NoSuchOper,
    PublicKeyMismatch,
    UnsupportedPasswordHash,
    UnknownPrivilege,
};

/// Individual oper privileges. Unknown string flags are rejected before grant.
pub const Privilege = enum {
    rehash,
    die,
    restart,
    kill,
    connect,
    squit,
    wallops,
    operwall,
    services,
    admin,
    netadmin,
};

/// Typed privilege set granted after successful authentication.
pub const Privileges = packed struct(u16) {
    rehash: bool = false,
    die: bool = false,
    restart: bool = false,
    kill: bool = false,
    connect: bool = false,
    squit: bool = false,
    wallops: bool = false,
    operwall: bool = false,
    services: bool = false,
    admin: bool = false,
    netadmin: bool = false,
    _pad: u5 = 0,

    pub fn empty() Privileges {
        return .{};
    }

    pub fn fromFlags(flags: []const []const u8) AuthError!Privileges {
        var out = Privileges.empty();
        for (flags) |flag| try out.addName(flag);
        return out;
    }

    pub fn add(self: *Privileges, priv: Privilege) void {
        switch (priv) {
            .rehash => self.rehash = true,
            .die => self.die = true,
            .restart => self.restart = true,
            .kill => self.kill = true,
            .connect => self.connect = true,
            .squit => self.squit = true,
            .wallops => self.wallops = true,
            .operwall => self.operwall = true,
            .services => self.services = true,
            .admin => self.admin = true,
            .netadmin => self.netadmin = true,
        }
    }

    pub fn addName(self: *Privileges, flag: []const u8) AuthError!void {
        self.add(try privilegeFromName(flag));
    }

    pub fn has(self: Privileges, priv: Privilege) bool {
        return switch (priv) {
            .rehash => self.rehash,
            .die => self.die,
            .restart => self.restart,
            .kill => self.kill,
            .connect => self.connect,
            .squit => self.squit,
            .wallops => self.wallops,
            .operwall => self.operwall,
            .services => self.services,
            .admin => self.admin,
            .netadmin => self.netadmin,
        };
    }
};

/// Operator declaration consumed by the authenticator. Slices are borrowed.
pub const OperRecord = struct {
    name: []const u8,
    host_mask: []const u8 = "*",
    flags: []const []const u8 = &.{},
    pwhash: ?[]const u8 = null,
    certfp: ?[]const u8 = null,
    public_key: ?PublicKey = null,

    pub fn fromConfig(oper: config.Oper, host_mask: []const u8) OperRecord {
        return .{
            .name = oper.name,
            .host_mask = host_mask,
            .flags = oper.flags,
            .pwhash = oper.pwhash,
            .certfp = oper.certfp,
        };
    }
};

/// Authentication request for an attempted OPER.
pub const AuthRequest = struct {
    name: []const u8,
    host: []const u8,
    credential: Credential,
};

/// Credential presented by the client.
pub const Credential = union(enum) {
    password: []const u8,
    certfp: []const u8,
    ed25519: Ed25519Proof,
};

/// Ed25519 challenge proof. `challenge` must be server-generated freshness.
pub const Ed25519Proof = struct {
    public_key: PublicKey,
    signature: Signature,
    challenge: []const u8,
};

/// Successful OPER grant.
pub const Grant = struct {
    name: []const u8,
    privileges: Privileges,
};

/// Default authenticator entry point.
pub fn authenticate(records: []const OperRecord, request: AuthRequest) AuthError!Grant {
    return Authenticator(default_params).authenticate(records, request);
}

/// Alloc-free authenticator specialized by input limits.
pub fn Authenticator(comptime params: Params) type {
    return struct {
        pub fn authenticate(records: []const OperRecord, request: AuthRequest) AuthError!Grant {
            try validateName(request.name, params.max_name_len);
            try validateHost(request.host, params.max_host_len);
            try validateCredential(params, request.credential);

            var name_seen = false;
            var host_seen = false;
            for (records) |record| {
                try validateRecord(params, record);
                if (!std.mem.eql(u8, record.name, request.name)) continue;

                name_seen = true;
                if (!matchHostMask(record.host_mask, request.host)) continue;

                host_seen = true;
                if (!try verifyCredential(params, record, request.credential)) continue;

                return .{
                    .name = record.name,
                    .privileges = try Privileges.fromFlags(record.flags),
                };
            }

            if (host_seen) return error.InvalidCredential;
            if (name_seen) return error.HostMaskMismatch;
            return error.NoSuchOper;
        }
    };
}

fn validateRecord(comptime params: Params, record: OperRecord) AuthError!void {
    try validateName(record.name, params.max_name_len);
    try validateHostMask(record.host_mask, params.max_host_len);
    if (record.pwhash == null and record.certfp == null and record.public_key == null) {
        return error.MissingCredential;
    }
    if (record.pwhash) |pwhash| _ = try parsePasswordHash(params, pwhash);
    if (record.certfp) |certfp| try validateCertfp(certfp);
    _ = try Privileges.fromFlags(record.flags);
}

fn validateCredential(comptime params: Params, credential: Credential) AuthError!void {
    switch (credential) {
        .password => |password| {
            if (password.len == 0 or password.len > params.max_password_len) return error.InvalidInput;
            try validateNoControl(password);
        },
        .certfp => |certfp| try validateCertfp(certfp),
        .ed25519 => |proof| {
            if (proof.challenge.len == 0 or proof.challenge.len > params.max_challenge_len) {
                return error.InvalidInput;
            }
            try validateNoControl(proof.challenge);
        },
    }
}

fn verifyCredential(
    comptime params: Params,
    record: OperRecord,
    credential: Credential,
) AuthError!bool {
    return switch (credential) {
        .password => |password| blk: {
            const pwhash = record.pwhash orelse break :blk false;
            break :blk try verifyPassword(params, pwhash, password);
        },
        .certfp => |certfp| blk: {
            const expected = record.certfp orelse break :blk false;
            break :blk try verifyCertfp(expected, certfp);
        },
        .ed25519 => |proof| verifyEd25519Proof(record, proof),
    };
}

const derived_key_len = 32;
const Pbkdf2Digest = [derived_key_len]u8;

fn PasswordHash(comptime params: Params) type {
    return struct {
        rounds: u32,
        salt: [params.max_salt_len]u8,
        salt_len: usize,
        digest: Pbkdf2Digest,
    };
}

fn parsePasswordHash(comptime params: Params, text: []const u8) AuthError!PasswordHash(params) {
    var parts = std.mem.splitScalar(u8, text, '$');
    const alg = parts.next() orelse return error.InvalidPasswordHash;
    const rounds_text = parts.next() orelse return error.InvalidPasswordHash;
    const salt_hex = parts.next() orelse return error.InvalidPasswordHash;
    const digest_hex = parts.next() orelse return error.InvalidPasswordHash;
    if (parts.next() != null) return error.InvalidPasswordHash;

    if (!std.mem.eql(u8, alg, "pbkdf2-sha256")) return error.UnsupportedPasswordHash;
    const rounds = std.fmt.parseInt(u32, rounds_text, 10) catch return error.InvalidPasswordHash;
    if (rounds == 0) return error.InvalidPasswordHash;
    if (salt_hex.len == 0 or salt_hex.len % 2 != 0) return error.InvalidPasswordHash;
    if (salt_hex.len / 2 > params.max_salt_len) return error.InvalidPasswordHash;
    if (digest_hex.len != derived_key_len * 2) return error.InvalidPasswordHash;

    var out: PasswordHash(params) = .{
        .rounds = rounds,
        .salt = [_]u8{0} ** params.max_salt_len,
        .salt_len = salt_hex.len / 2,
        .digest = undefined,
    };
    _ = std.fmt.hexToBytes(out.salt[0..out.salt_len], salt_hex) catch return error.InvalidPasswordHash;
    _ = std.fmt.hexToBytes(&out.digest, digest_hex) catch return error.InvalidPasswordHash;
    return out;
}

fn verifyPassword(comptime params: Params, pwhash: []const u8, password: []const u8) AuthError!bool {
    const parsed = try parsePasswordHash(params, pwhash);
    var derived: Pbkdf2Digest = undefined;
    defer secureZero(&derived);

    std.crypto.pwhash.pbkdf2(
        &derived,
        password,
        parsed.salt[0..parsed.salt_len],
        parsed.rounds,
        std.crypto.auth.hmac.sha2.HmacSha256,
    ) catch return error.InvalidPasswordHash;

    return std.crypto.timing_safe.eql(Pbkdf2Digest, derived, parsed.digest);
}

fn verifyCertfp(expected: []const u8, offered: []const u8) AuthError!bool {
    var expected_bytes: [64]u8 = [_]u8{0} ** 64;
    var offered_bytes: [64]u8 = [_]u8{0} ** 64;
    const expected_len = try decodeCertfp(&expected_bytes, expected);
    const offered_len = try decodeCertfp(&offered_bytes, offered);

    return expected_len == offered_len and
        std.crypto.timing_safe.eql([64]u8, expected_bytes, offered_bytes);
}

fn verifyEd25519Proof(record: OperRecord, proof: Ed25519Proof) AuthError!bool {
    const pk = StdEd25519.PublicKey.fromBytes(proof.public_key) catch return false;
    const sig = StdEd25519.Signature.fromBytes(proof.signature);
    var verifier = sig.verifier(pk) catch return false;
    const prefix = ed25519DomainPrefix("oper-auth-v1");
    verifier.update(&prefix);
    verifier.update(proof.challenge);
    verifier.verify() catch return false;

    if (record.public_key) |expected_pk| {
        if (!std.crypto.timing_safe.eql(PublicKey, expected_pk, proof.public_key)) {
            return error.PublicKeyMismatch;
        }
        return true;
    }

    const expected_fp = record.certfp orelse return false;
    return verifyPublicKeyFingerprint(expected_fp, proof.public_key);
}

fn verifyPublicKeyFingerprint(expected: []const u8, public_key: PublicKey) AuthError!bool {
    try validateCertfp(expected);
    if (expected.len == 64) {
        var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&public_key, &digest, .{});
        var expected_bytes: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&expected_bytes, expected) catch return error.InvalidInput;
        return std.crypto.timing_safe.eql([32]u8, expected_bytes, digest);
    }

    var digest: [std.crypto.hash.sha2.Sha512.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(&public_key, &digest, .{});
    var expected_bytes: [64]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected_bytes, expected) catch return error.InvalidInput;
    return std.crypto.timing_safe.eql([64]u8, expected_bytes, digest);
}

fn decodeCertfp(out: *[64]u8, text: []const u8) AuthError!usize {
    try validateCertfp(text);
    const len = text.len / 2;
    _ = std.fmt.hexToBytes(out[0..len], text) catch return error.InvalidInput;
    return len;
}

fn validateName(name: []const u8, max_len: usize) AuthError!void {
    if (name.len == 0 or name.len > max_len) return error.InvalidInput;
    for (name) |ch| {
        const ok = (ch >= 'A' and ch <= 'Z') or
            (ch >= 'a' and ch <= 'z') or
            (ch >= '0' and ch <= '9') or
            ch == '_' or ch == '-' or ch == '.';
        if (!ok) return error.InvalidInput;
    }
}

fn validateHost(host: []const u8, max_len: usize) AuthError!void {
    if (host.len == 0 or host.len > max_len) return error.InvalidInput;
    try validatePrintableNoSpace(host);
}

fn validateHostMask(mask: []const u8, max_len: usize) AuthError!void {
    if (mask.len == 0 or mask.len > max_len) return error.InvalidInput;
    try validatePrintableNoSpace(mask);
}

fn validateNoControl(text: []const u8) AuthError!void {
    for (text) |ch| {
        if (ch == 0 or ch == '\r' or ch == '\n' or ch < 0x20) return error.InvalidInput;
    }
}

fn validatePrintableNoSpace(text: []const u8) AuthError!void {
    for (text) |ch| {
        if (ch <= 0x20 or ch == 0x7f) return error.InvalidInput;
    }
}

fn validateCertfp(text: []const u8) AuthError!void {
    if (text.len != 64 and text.len != 128) return error.InvalidInput;
    for (text) |ch| {
        if (!isHex(ch)) return error.InvalidInput;
    }
}

fn isHex(ch: u8) bool {
    return (ch >= '0' and ch <= '9') or
        (ch >= 'a' and ch <= 'f') or
        (ch >= 'A' and ch <= 'F');
}

fn privilegeFromName(name: []const u8) AuthError!Privilege {
    inline for (@typeInfo(Privilege).@"enum".fields) |field| {
        if (std.mem.eql(u8, name, field.name)) {
            return @field(Privilege, field.name);
        }
    }
    return error.UnknownPrivilege;
}

fn matchHostMask(mask: []const u8, host: []const u8) bool {
    var mask_index: usize = 0;
    var host_index: usize = 0;
    var star_index: ?usize = null;
    var retry_host: usize = 0;

    while (host_index < host.len) {
        if (mask_index < mask.len and
            (mask[mask_index] == '?' or asciiLower(mask[mask_index]) == asciiLower(host[host_index])))
        {
            mask_index += 1;
            host_index += 1;
        } else if (mask_index < mask.len and mask[mask_index] == '*') {
            star_index = mask_index;
            mask_index += 1;
            retry_host = host_index;
        } else if (star_index) |star| {
            mask_index = star + 1;
            retry_host += 1;
            host_index = retry_host;
        } else {
            return false;
        }
    }

    while (mask_index < mask.len and mask[mask_index] == '*') mask_index += 1;
    return mask_index == mask.len;
}

fn asciiLower(ch: u8) u8 {
    if (ch >= 'A' and ch <= 'Z') return ch + ('a' - 'A');
    return ch;
}

const ed25519_domain_magic = "mizuchi-ed25519ctx-v1";

fn ed25519DomainPrefix(comptime domain: []const u8) [ed25519_domain_magic.len + 1 + domain.len]u8 {
    comptime {
        if (domain.len == 0) @compileError("Ed25519 domain label must not be empty");
        if (domain.len > std.math.maxInt(u8)) @compileError("Ed25519 domain label exceeds 255 bytes");
    }

    var out: [ed25519_domain_magic.len + 1 + domain.len]u8 = undefined;
    @memcpy(out[0..ed25519_domain_magic.len], ed25519_domain_magic);
    out[ed25519_domain_magic.len] = @intCast(domain.len);
    @memcpy(out[ed25519_domain_magic.len + 1 ..], domain);
    return out;
}

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

fn writePbkdf2Sha256Hash(
    buf: []u8,
    password: []const u8,
    salt: []const u8,
    rounds: u32,
) ![]const u8 {
    var digest: Pbkdf2Digest = undefined;
    defer secureZero(&digest);
    try std.crypto.pwhash.pbkdf2(
        &digest,
        password,
        salt,
        rounds,
        std.crypto.auth.hmac.sha2.HmacSha256,
    );

    var salt_hex: [128]u8 = undefined;
    var digest_hex: [derived_key_len * 2]u8 = undefined;
    bytesToLowerHex(salt_hex[0 .. salt.len * 2], salt);
    bytesToLowerHex(&digest_hex, &digest);
    return std.fmt.bufPrint(
        buf,
        "pbkdf2-sha256${d}${s}${s}",
        .{ rounds, salt_hex[0 .. salt.len * 2], &digest_hex },
    );
}

fn bytesToLowerHex(out: []u8, bytes: []const u8) void {
    const hex_chars = std.fmt.hex_charset;
    for (bytes, 0..) |byte, index| {
        out[index * 2] = hex_chars[byte >> 4];
        out[index * 2 + 1] = hex_chars[byte & 0x0f];
    }
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "correct password grants typed privileges" {
    var pwhash_buf: [160]u8 = undefined;
    const pwhash = try writePbkdf2Sha256Hash(&pwhash_buf, "open sesame", "salty", 1);
    const flags = [_][]const u8{ "rehash", "die", "operwall" };
    const records = [_]OperRecord{.{
        .name = "root",
        .host_mask = "*.staff.example",
        .flags = &flags,
        .pwhash = pwhash,
    }};

    const grant = try authenticate(&records, .{
        .name = "root",
        .host = "box.staff.example",
        .credential = .{ .password = "open sesame" },
    });

    try std.testing.expectEqualStrings("root", grant.name);
    try std.testing.expect(grant.privileges.has(.rehash));
    try std.testing.expect(grant.privileges.has(.die));
    try std.testing.expect(grant.privileges.has(.operwall));
    try std.testing.expect(!grant.privileges.has(.kill));
}

test "wrong password is rejected after constant-time derived-key compare" {
    var pwhash_buf: [160]u8 = undefined;
    const pwhash = try writePbkdf2Sha256Hash(&pwhash_buf, "correct", "pepper", 1);
    const records = [_]OperRecord{.{
        .name = "root",
        .host_mask = "*",
        .pwhash = pwhash,
    }};

    try std.testing.expectError(error.InvalidCredential, authenticate(&records, .{
        .name = "root",
        .host = "host.example",
        .credential = .{ .password = "wrong" },
    }));

    const parsed = try parsePasswordHash(default_params, pwhash);
    var wrong_digest = parsed.digest;
    wrong_digest[0] ^= 1;
    try std.testing.expect(!std.crypto.timing_safe.eql(Pbkdf2Digest, parsed.digest, wrong_digest));
    try std.testing.expect(std.crypto.timing_safe.eql(Pbkdf2Digest, parsed.digest, parsed.digest));
}

test "host-mask mismatch is rejected before credential grant" {
    var pwhash_buf: [160]u8 = undefined;
    const pwhash = try writePbkdf2Sha256Hash(&pwhash_buf, "correct", "salty", 1);
    const records = [_]OperRecord{.{
        .name = "root",
        .host_mask = "*.staff.example",
        .pwhash = pwhash,
    }};

    try std.testing.expectError(error.HostMaskMismatch, authenticate(&records, .{
        .name = "root",
        .host = "dialup.example",
        .credential = .{ .password = "correct" },
    }));
}

test "certfp path grants matching operator" {
    const certfp = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const records = [_]OperRecord{.{
        .name = "tlsroot",
        .host_mask = "*.staff.example",
        .flags = &[_][]const u8{"services"},
        .certfp = certfp,
    }};

    const grant = try authenticate(&records, .{
        .name = "tlsroot",
        .host = "laptop.staff.example",
        .credential = .{ .certfp = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
    });
    try std.testing.expect(grant.privileges.has(.services));

    try std.testing.expectError(error.InvalidCredential, authenticate(&records, .{
        .name = "tlsroot",
        .host = "laptop.staff.example",
        .credential = .{ .certfp = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
    }));
}

test "ed25519 proof can be pinned by public-key fingerprint" {
    const kp = try StdEd25519.KeyPair.generateDeterministic(hex("4ccd089b28ff96da9db6c346ec114e0f" ++
        "5b8a319f35aba624da8cf6ed4fb8a6fb"));

    const public_key = kp.public_key.toBytes();
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&public_key, &digest, .{});
    var fp: [64]u8 = undefined;
    bytesToLowerHex(&fp, &digest);
    const challenge = "server nonce";
    const prefix = ed25519DomainPrefix("oper-auth-v1");
    var msg: [prefix.len + challenge.len]u8 = undefined;
    @memcpy(msg[0..prefix.len], &prefix);
    @memcpy(msg[prefix.len..], challenge);
    const sig = (try kp.sign(&msg, null)).toBytes();

    const records = [_]OperRecord{.{
        .name = "sigroot",
        .host_mask = "trusted.example",
        .flags = &[_][]const u8{"admin"},
        .certfp = &fp,
    }};

    const grant = try authenticate(&records, .{
        .name = "sigroot",
        .host = "trusted.example",
        .credential = .{ .ed25519 = .{
            .public_key = public_key,
            .signature = sig,
            .challenge = challenge,
        } },
    });
    try std.testing.expect(grant.privileges.has(.admin));

    var bad_sig = sig;
    bad_sig[0] ^= 1;
    try std.testing.expectError(error.InvalidCredential, authenticate(&records, .{
        .name = "sigroot",
        .host = "trusted.example",
        .credential = .{ .ed25519 = .{
            .public_key = public_key,
            .signature = bad_sig,
            .challenge = challenge,
        } },
    }));
}

test {
    std.testing.refAllDecls(@This());
}
