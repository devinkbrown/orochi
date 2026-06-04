//! Server-side SCRAM-SHA-256 responder (RFC 5802 / RFC 7677).
//!
//! This file is intentionally a protocol library only. It consumes raw SCRAM
//! messages and produces raw SCRAM messages; callers own SASL framing,
//! credential lookup, random nonce generation, and I/O.
const std = @import("std");

const sasl = @import("sasl.zig");

const crypto_hash = struct {
    const Sha256 = struct {
        pub const digest_len = std.crypto.hash.sha2.Sha256.digest_length;

        pub fn hash(msg: []const u8) [Sha256.digest_len]u8 {
            var out: [Sha256.digest_len]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(msg, &out, .{});
            return out;
        }
    };

    const HmacSha256 = struct {
        const Impl = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256);

        pub fn create(key: []const u8, msg: []const u8) [Sha256.digest_len]u8 {
            var out: [Sha256.digest_len]u8 = undefined;
            Impl.create(&out, msg, key);
            return out;
        }
    };
};

pub const Credential = sasl.ScramRecord;
pub const digest_len = crypto_hash.Sha256.digest_len;

pub const MAX_MESSAGE = sasl.MAX_SCRAM_MESSAGE;
pub const MAX_USERNAME = sasl.MAX_SCRAM_USERNAME;
pub const MAX_NONCE = sasl.MAX_SCRAM_NONCE;
pub const MAX_SALT = sasl.MAX_SCRAM_SALT;
const MAX_GS2_HEADER: usize = 256;

pub const AuthError = error{
    UnexpectedMessage,
    MalformedMessage,
    MessageTooLarge,
    OutputTooSmall,
    UnsupportedChannelBinding,
    ReservedExtension,
    DuplicateAttribute,
    MissingAttribute,
    InvalidAttribute,
    InvalidUsername,
    InvalidNonce,
    InvalidCredential,
    InvalidBase64,
    ProofMismatch,
};

pub const Step = enum {
    client_first,
    client_final,
    complete,
};

pub const FirstResponse = struct {
    username: []const u8,
    client_nonce: []const u8,
    combined_nonce: []const u8,
    server_first: []const u8,
};

pub const FinalResponse = struct {
    server_final: []const u8,
};

pub const ClientFirst = struct {
    gs2_header: []const u8,
    client_first_bare: []const u8,
    username: []const u8,
    nonce: []const u8,
};

pub const ClientFinal = struct {
    channel_binding: []const u8,
    nonce: []const u8,
    proof: []const u8,
    without_proof: []const u8,
};

pub const ServerFirst = struct {
    nonce: []const u8,
    salt_b64: []const u8,
    iterations: u32,
};

pub const ServerFinal = struct {
    verifier: []const u8,
};

pub const Server = struct {
    step: Step = .client_first,
    gs2_header_buf: [MAX_GS2_HEADER]u8 = undefined,
    gs2_header_len: usize = 0,
    client_first_bare_buf: [MAX_MESSAGE]u8 = undefined,
    client_first_bare_len: usize = 0,
    server_first_buf: [MAX_MESSAGE]u8 = undefined,
    server_first_len: usize = 0,
    username_buf: [MAX_USERNAME]u8 = undefined,
    username_len: usize = 0,
    client_nonce_len: usize = 0,
    nonce_buf: [MAX_NONCE]u8 = undefined,
    nonce_len: usize = 0,
    stored_key: [digest_len]u8 = undefined,
    server_key: [digest_len]u8 = undefined,

    pub fn init() Server {
        return .{};
    }

    pub fn username(self: *const Server) []const u8 {
        return self.username_buf[0..self.username_len];
    }

    pub fn combinedNonce(self: *const Server) []const u8 {
        return self.nonce_buf[0..self.nonce_len];
    }

    pub fn reset(self: *Server) void {
        self.* = .{};
    }

    pub fn receiveClientFirst(
        self: *Server,
        client_first_message: []const u8,
        credential: Credential,
        server_nonce: []const u8,
        out: []u8,
    ) AuthError!FirstResponse {
        if (self.step != .client_first) return error.UnexpectedMessage;
        if (client_first_message.len > MAX_MESSAGE) return error.MessageTooLarge;
        if (!validNonce(server_nonce)) return error.InvalidNonce;
        if (credential.iterations == 0 or credential.salt.len == 0 or credential.salt.len > MAX_SALT) {
            return error.InvalidCredential;
        }

        const parsed = try parseClientFirst(client_first_message, &self.username_buf);
        if (parsed.gs2_header.len > self.gs2_header_buf.len) return error.MessageTooLarge;
        if (parsed.client_first_bare.len > self.client_first_bare_buf.len) return error.MessageTooLarge;
        if (parsed.nonce.len + server_nonce.len > self.nonce_buf.len) return error.InvalidNonce;

        @memcpy(self.gs2_header_buf[0..parsed.gs2_header.len], parsed.gs2_header);
        self.gs2_header_len = parsed.gs2_header.len;
        @memcpy(self.client_first_bare_buf[0..parsed.client_first_bare.len], parsed.client_first_bare);
        self.client_first_bare_len = parsed.client_first_bare.len;
        self.username_len = parsed.username.len;
        @memcpy(self.nonce_buf[0..parsed.nonce.len], parsed.nonce);
        @memcpy(self.nonce_buf[parsed.nonce.len..][0..server_nonce.len], server_nonce);
        self.client_nonce_len = parsed.nonce.len;
        self.nonce_len = parsed.nonce.len + server_nonce.len;
        self.stored_key = credential.stored_key;
        self.server_key = credential.server_key;

        var salt_b64_buf: [std.base64.standard.Encoder.calcSize(MAX_SALT)]u8 = undefined;
        const salt_b64 = std.base64.standard.Encoder.encode(&salt_b64_buf, credential.salt);
        const server_first = std.fmt.bufPrint(
            out,
            "r={s},s={s},i={d}",
            .{ self.combinedNonce(), salt_b64, credential.iterations },
        ) catch return error.OutputTooSmall;
        if (server_first.len > self.server_first_buf.len) return error.MessageTooLarge;
        @memcpy(self.server_first_buf[0..server_first.len], server_first);
        self.server_first_len = server_first.len;
        self.step = .client_final;

        return .{
            .username = self.username(),
            .client_nonce = self.nonce_buf[0..self.client_nonce_len],
            .combined_nonce = self.combinedNonce(),
            .server_first = server_first,
        };
    }

    pub fn receiveClientFinal(
        self: *Server,
        client_final_message: []const u8,
        out: []u8,
    ) AuthError!FinalResponse {
        if (self.step != .client_final) return error.UnexpectedMessage;
        if (client_final_message.len > MAX_MESSAGE) return error.MessageTooLarge;

        const parsed = try parseClientFinal(client_final_message);
        if (!std.mem.eql(u8, parsed.nonce, self.combinedNonce())) return error.InvalidNonce;

        var cb_buf: [MAX_GS2_HEADER]u8 = undefined;
        const cb = decodeBase64(parsed.channel_binding, &cb_buf) catch return error.InvalidBase64;
        if (!std.mem.eql(u8, cb, self.gs2_header_buf[0..self.gs2_header_len])) {
            return error.InvalidAttribute;
        }

        var proof: [digest_len]u8 = undefined;
        const proof_decoded = decodeBase64(parsed.proof, &proof) catch return error.InvalidBase64;
        if (proof_decoded.len != proof.len) return error.InvalidBase64;

        var auth_message_buf: [MAX_MESSAGE * 3]u8 = undefined;
        const auth_message = std.fmt.bufPrint(
            &auth_message_buf,
            "{s},{s},{s}",
            .{
                self.client_first_bare_buf[0..self.client_first_bare_len],
                self.server_first_buf[0..self.server_first_len],
                parsed.without_proof,
            },
        ) catch return error.MessageTooLarge;

        var client_sig = crypto_hash.HmacSha256.create(&self.stored_key, auth_message);
        var client_key: [digest_len]u8 = undefined;
        for (&client_key, proof, client_sig) |*dst, proof_byte, sig_byte| {
            dst.* = proof_byte ^ sig_byte;
        }
        var stored_check = crypto_hash.Sha256.hash(&client_key);
        const proof_ok = std.crypto.timing_safe.eql([digest_len]u8, stored_check, self.stored_key);
        secureZero(&stored_check);
        secureZero(&client_key);
        secureZero(&client_sig);
        secureZero(&proof);
        if (!proof_ok) return error.ProofMismatch;

        var server_sig = crypto_hash.HmacSha256.create(&self.server_key, auth_message);
        defer secureZero(&server_sig);
        var verifier_b64_buf: [std.base64.standard.Encoder.calcSize(digest_len)]u8 = undefined;
        const verifier_b64 = std.base64.standard.Encoder.encode(&verifier_b64_buf, &server_sig);
        const server_final = std.fmt.bufPrint(out, "v={s}", .{verifier_b64}) catch return error.OutputTooSmall;
        self.step = .complete;
        return .{ .server_final = server_final };
    }
};

pub fn parseClientFirst(raw: []const u8, username_out: []u8) AuthError!ClientFirst {
    const header_len = try gs2HeaderLen(raw);
    const bare = raw[header_len..];
    if (bare.len == 0) return error.MalformedMessage;

    var username: ?[]const u8 = null;
    var nonce: ?[]const u8 = null;
    var seen_n = false;
    var seen_r = false;
    var it = std.mem.splitScalar(u8, bare, ',');
    while (it.next()) |attr| {
        const parsed = try splitAttr(attr);
        switch (parsed.name) {
            'n' => {
                if (seen_n) return error.DuplicateAttribute;
                seen_n = true;
                const n = try decodeSaslName(parsed.value, username_out);
                if (n == 0) return error.InvalidUsername;
                username = username_out[0..n];
            },
            'r' => {
                if (seen_r) return error.DuplicateAttribute;
                seen_r = true;
                if (!validNonce(parsed.value)) return error.InvalidNonce;
                nonce = parsed.value;
            },
            'm' => return error.ReservedExtension,
            'c', 'p', 's', 'i', 'v' => return error.InvalidAttribute,
            else => {},
        }
    }

    return .{
        .gs2_header = raw[0..header_len],
        .client_first_bare = bare,
        .username = username orelse return error.MissingAttribute,
        .nonce = nonce orelse return error.MissingAttribute,
    };
}

pub fn parseClientFinal(raw: []const u8) AuthError!ClientFinal {
    if (raw.len == 0) return error.MalformedMessage;
    const proof_marker = std.mem.indexOf(u8, raw, ",p=") orelse return error.MissingAttribute;
    const without_proof = raw[0..proof_marker];
    if (without_proof.len == 0) return error.MalformedMessage;

    var cb: ?[]const u8 = null;
    var nonce: ?[]const u8 = null;
    var proof: ?[]const u8 = null;
    var seen_c = false;
    var seen_r = false;
    var seen_p = false;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |attr| {
        const parsed = try splitAttr(attr);
        switch (parsed.name) {
            'c' => {
                if (seen_c) return error.DuplicateAttribute;
                seen_c = true;
                if (parsed.value.len == 0) return error.InvalidBase64;
                _ = try decodedBase64Size(parsed.value);
                cb = parsed.value;
            },
            'r' => {
                if (seen_r) return error.DuplicateAttribute;
                seen_r = true;
                if (!validNonce(parsed.value)) return error.InvalidNonce;
                nonce = parsed.value;
            },
            'p' => {
                if (seen_p) return error.DuplicateAttribute;
                seen_p = true;
                if (raw[proof_marker + 1 ..].ptr != attr.ptr) return error.InvalidAttribute;
                if (@intFromPtr(attr.ptr) + attr.len != @intFromPtr(raw.ptr) + raw.len) {
                    return error.InvalidAttribute;
                }
                if (parsed.value.len == 0) return error.InvalidBase64;
                if (try decodedBase64Size(parsed.value) != digest_len) return error.InvalidBase64;
                proof = parsed.value;
            },
            'm' => return error.ReservedExtension,
            'n', 's', 'i', 'v' => return error.InvalidAttribute,
            else => {},
        }
    }

    return .{
        .channel_binding = cb orelse return error.MissingAttribute,
        .nonce = nonce orelse return error.MissingAttribute,
        .proof = proof orelse return error.MissingAttribute,
        .without_proof = without_proof,
    };
}

pub fn parseServerFirst(raw: []const u8) AuthError!ServerFirst {
    var nonce: ?[]const u8 = null;
    var salt: ?[]const u8 = null;
    var iterations: ?u32 = null;
    var seen_r = false;
    var seen_s = false;
    var seen_i = false;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |attr| {
        const parsed = try splitAttr(attr);
        switch (parsed.name) {
            'r' => {
                if (seen_r) return error.DuplicateAttribute;
                seen_r = true;
                if (!validNonce(parsed.value)) return error.InvalidNonce;
                nonce = parsed.value;
            },
            's' => {
                if (seen_s) return error.DuplicateAttribute;
                seen_s = true;
                if (parsed.value.len == 0) return error.InvalidBase64;
                const salt_len = try decodedBase64Size(parsed.value);
                if (salt_len == 0 or salt_len > MAX_SALT) return error.InvalidBase64;
                salt = parsed.value;
            },
            'i' => {
                if (seen_i) return error.DuplicateAttribute;
                seen_i = true;
                iterations = parseIterations(parsed.value) catch return error.InvalidAttribute;
            },
            'm' => return error.ReservedExtension,
            'n', 'c', 'p', 'v' => return error.InvalidAttribute,
            else => {},
        }
    }
    return .{
        .nonce = nonce orelse return error.MissingAttribute,
        .salt_b64 = salt orelse return error.MissingAttribute,
        .iterations = iterations orelse return error.MissingAttribute,
    };
}

pub fn parseServerFinal(raw: []const u8) AuthError!ServerFinal {
    var verifier: ?[]const u8 = null;
    var seen_v = false;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |attr| {
        const parsed = try splitAttr(attr);
        switch (parsed.name) {
            'v' => {
                if (seen_v) return error.DuplicateAttribute;
                seen_v = true;
                if (parsed.value.len == 0) return error.InvalidBase64;
                if (try decodedBase64Size(parsed.value) != digest_len) return error.InvalidBase64;
                verifier = parsed.value;
            },
            'm' => return error.ReservedExtension,
            'n', 'r', 's', 'i', 'c', 'p' => return error.InvalidAttribute,
            else => {},
        }
    }
    return .{ .verifier = verifier orelse return error.MissingAttribute };
}

pub fn deriveCredentialFromPassword(
    password: []const u8,
    salt: []const u8,
    iterations: u32,
) (AuthError || std.crypto.errors.WeakParametersError || std.crypto.errors.OutputTooLongError)!Credential {
    if (iterations == 0 or salt.len == 0 or salt.len > MAX_SALT) return error.InvalidCredential;
    var salted_password: [digest_len]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(
        &salted_password,
        password,
        salt,
        iterations,
        std.crypto.auth.hmac.sha2.HmacSha256,
    );
    defer secureZero(&salted_password);

    var client_key = crypto_hash.HmacSha256.create(&salted_password, "Client Key");
    defer secureZero(&client_key);
    const stored_key = crypto_hash.Sha256.hash(&client_key);
    const server_key = crypto_hash.HmacSha256.create(&salted_password, "Server Key");
    return .{
        .salt = salt,
        .iterations = iterations,
        .stored_key = stored_key,
        .server_key = server_key,
    };
}

const Attr = struct {
    name: u8,
    value: []const u8,
};

fn splitAttr(attr: []const u8) AuthError!Attr {
    if (attr.len < 3 or attr[1] != '=') return error.MalformedMessage;
    if (!std.ascii.isAlphabetic(attr[0])) return error.InvalidAttribute;
    return .{ .name = attr[0], .value = attr[2..] };
}

fn gs2HeaderLen(raw: []const u8) AuthError!usize {
    if (raw.len < 3) return error.MalformedMessage;
    switch (raw[0]) {
        'n', 'y' => {},
        'p' => return error.UnsupportedChannelBinding,
        else => return error.MalformedMessage,
    }
    if (raw[1] != ',') return error.MalformedMessage;
    if (raw[2] == ',') return 3;
    if (!std.mem.startsWith(u8, raw[2..], "a=")) return error.MalformedMessage;
    const comma_rel = std.mem.indexOfScalar(u8, raw[2..], ',') orelse return error.MalformedMessage;
    const authzid = raw[4 .. 2 + comma_rel];
    var decoded: [MAX_USERNAME]u8 = undefined;
    if (try decodeSaslName(authzid, &decoded) == 0) return error.InvalidUsername;
    return 2 + comma_rel + 1;
}

fn decodeSaslName(raw: []const u8, out: []u8) AuthError!usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < raw.len) {
        if (n == out.len) return error.InvalidUsername;
        if (raw[i] == ',') return error.InvalidUsername;
        if (raw[i] != '=') {
            out[n] = raw[i];
            n += 1;
            i += 1;
            continue;
        }
        if (i + 2 >= raw.len) return error.InvalidUsername;
        if (raw[i + 1] == '2' and raw[i + 2] == 'C') {
            out[n] = ',';
        } else if (raw[i + 1] == '3' and raw[i + 2] == 'D') {
            out[n] = '=';
        } else {
            return error.InvalidUsername;
        }
        n += 1;
        i += 3;
    }
    return n;
}

fn validNonce(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (byte < 0x21 or byte > 0x7e or byte == ',') return false;
    }
    return true;
}

fn parseIterations(value: []const u8) !u32 {
    if (value.len == 0) return error.InvalidCharacter;
    const parsed = try std.fmt.parseInt(u32, value, 10);
    if (parsed == 0) return error.ZeroIterations;
    return parsed;
}

fn decodedBase64Size(src: []const u8) AuthError!usize {
    if (std.base64.standard.Decoder.calcSizeForSlice(src)) |size| {
        return size;
    } else |_| {
        return std.base64.standard_no_pad.Decoder.calcSizeForSlice(src) catch return error.InvalidBase64;
    }
}

fn decodeBase64(src: []const u8, out: []u8) ![]const u8 {
    const padded_size = std.base64.standard.Decoder.calcSizeForSlice(src) catch null;
    if (padded_size) |size| {
        if (size > out.len) return error.NoSpaceLeft;
        try std.base64.standard.Decoder.decode(out[0..size], src);
        return out[0..size];
    }
    const size = try std.base64.standard_no_pad.Decoder.calcSizeForSlice(src);
    if (size > out.len) return error.NoSpaceLeft;
    try std.base64.standard_no_pad.Decoder.decode(out[0..size], src);
    return out[0..size];
}

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

test "RFC 7677 SCRAM-SHA-256 vector accepts proof and computes server signature" {
    const allocator = std.testing.allocator;
    const salt_b64 = "W22ZaJ0SNY7soEsUEjb6gQ==";
    const salt_len = try std.base64.standard.Decoder.calcSizeForSlice(salt_b64);
    const salt = try allocator.alloc(u8, salt_len);
    defer allocator.free(salt);
    try std.base64.standard.Decoder.decode(salt, salt_b64);

    const credential = try deriveCredentialFromPassword("pencil", salt, 4096);
    const client_first = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
    const server_nonce = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    const expected_server_first =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," ++
        "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const client_final =
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," ++
        "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const expected_server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    var server = Server.init();
    var first_buf: [MAX_MESSAGE]u8 = undefined;
    const first = try server.receiveClientFirst(client_first, credential, server_nonce, &first_buf);
    try std.testing.expectEqualStrings("user", first.username);
    try std.testing.expectEqualStrings(expected_server_first, first.server_first);

    const parsed_first = try parseServerFirst(first.server_first);
    try std.testing.expectEqualStrings(first.combined_nonce, parsed_first.nonce);
    try std.testing.expectEqualStrings(salt_b64, parsed_first.salt_b64);
    try std.testing.expectEqual(@as(u32, 4096), parsed_first.iterations);

    var final_buf: [MAX_MESSAGE]u8 = undefined;
    const final = try server.receiveClientFinal(client_final, &final_buf);
    try std.testing.expectEqualStrings(expected_server_final, final.server_final);

    const parsed_final = try parseServerFinal(final.server_final);
    try std.testing.expectEqualStrings(expected_server_final["v=".len..], parsed_final.verifier);
}

test "RFC 7677 SCRAM-SHA-256 vector rejects a tampered proof" {
    const allocator = std.testing.allocator;
    const salt_b64 = "W22ZaJ0SNY7soEsUEjb6gQ==";
    const salt_len = try std.base64.standard.Decoder.calcSizeForSlice(salt_b64);
    const salt = try allocator.alloc(u8, salt_len);
    defer allocator.free(salt);
    try std.base64.standard.Decoder.decode(salt, salt_b64);

    const credential = try deriveCredentialFromPassword("pencil", salt, 4096);
    var server = Server.init();
    var first_buf: [MAX_MESSAGE]u8 = undefined;
    _ = try server.receiveClientFirst(
        "n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
        credential,
        "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
        &first_buf,
    );

    var final_buf: [MAX_MESSAGE]u8 = undefined;
    const bad_final =
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," ++
        "p=dXzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    try std.testing.expectError(error.ProofMismatch, server.receiveClientFinal(bad_final, &final_buf));
}

test "defensive parser rejects malformed SCRAM attributes" {
    var name_buf: [MAX_USERNAME]u8 = undefined;
    try std.testing.expectError(error.DuplicateAttribute, parseClientFirst("n,,n=user,n=other,r=abc", &name_buf));
    try std.testing.expectError(error.ReservedExtension, parseClientFirst("n,,m=x,n=user,r=abc", &name_buf));
    try std.testing.expectError(error.UnsupportedChannelBinding, parseClientFirst("p=tls-exporter,,n=user,r=abc", &name_buf));
    try std.testing.expectError(error.InvalidNonce, parseClientFinal("c=biws,r=bad nonce,p=abcd"));
    try std.testing.expectError(error.DuplicateAttribute, parseServerFirst("r=abc,s=abcd,i=4096,i=4097"));
    try std.testing.expectError(error.MissingAttribute, parseServerFinal("e=bad"));
}

test {
    std.testing.refAllDecls(@This());
}
