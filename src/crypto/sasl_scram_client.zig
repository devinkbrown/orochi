//! Self-contained client-side SCRAM-SHA-256 (RFC 5802 / RFC 7677).
//!
//! This module consumes and produces raw SCRAM messages. SASL framing,
//! nonce generation, credential storage, and I/O stay with the caller.
const std = @import("std");

const Allocator = std.mem.Allocator;
const Sha256Impl = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const digest_len = Sha256Impl.digest_length;
pub const gs2_header = "n,,";

pub const ScramError = error{
    MalformedMessage,
    DuplicateAttribute,
    MissingAttribute,
    InvalidAttribute,
    InvalidUsername,
    InvalidNonce,
    InvalidBase64,
    InvalidIterations,
    ServerSignatureMismatch,
    ServerRejected,
    ProofMismatch,
};

pub const State = struct {
    allocator: Allocator,
    client_first_bare: []u8,
    client_nonce: []u8,

    pub fn deinit(self: *State) void {
        self.allocator.free(self.client_first_bare);
        self.allocator.free(self.client_nonce);
        self.* = undefined;
    }
};

pub const First = struct {
    message: []u8,
    state: State,

    pub fn deinit(self: *First) void {
        self.state.allocator.free(self.message);
        self.state.deinit();
        self.* = undefined;
    }
};

pub const Final = struct {
    message: []u8,
    server_signature: [digest_len]u8,

    pub fn deinit(self: *Final, allocator: Allocator) void {
        allocator.free(self.message);
        self.* = undefined;
    }

    pub fn verifyServerFinal(self: *const Final, server_final: []const u8) !void {
        try verifyServerFinalSignature(server_final, self.server_signature);
    }
};

pub fn clientFirst(allocator: Allocator, username: []const u8, nonce: []const u8) !First {
    if (!validNonce(nonce)) return error.InvalidNonce;

    const escaped = try escapeSaslName(allocator, username);
    defer allocator.free(escaped);

    const bare = try std.fmt.allocPrint(allocator, "n={s},r={s}", .{ escaped, nonce });
    errdefer allocator.free(bare);
    const message = try std.fmt.allocPrint(allocator, "{s}{s}", .{ gs2_header, bare });
    errdefer allocator.free(message);
    const nonce_copy = try allocator.dupe(u8, nonce);
    errdefer allocator.free(nonce_copy);

    return .{
        .message = message,
        .state = .{
            .allocator = allocator,
            .client_first_bare = bare,
            .client_nonce = nonce_copy,
        },
    };
}

pub fn clientFinal(
    allocator: Allocator,
    state: *const State,
    server_first: []const u8,
    password: []const u8,
) !Final {
    const parsed = try parseServerFirst(server_first);
    if (!std.mem.startsWith(u8, parsed.nonce, state.client_nonce) or
        parsed.nonce.len <= state.client_nonce.len)
    {
        return error.InvalidNonce;
    }

    const salt = try decodeBase64Alloc(allocator, parsed.salt_b64);
    defer allocator.free(salt);

    var salted_password: [digest_len]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&salted_password, password, salt, parsed.iterations, HmacSha256);
    defer secureZero(&salted_password);

    var client_key: [digest_len]u8 = undefined;
    HmacSha256.create(&client_key, "Client Key", &salted_password);
    defer secureZero(&client_key);

    var stored_key: [digest_len]u8 = undefined;
    Sha256Impl.hash(&client_key, &stored_key, .{});
    defer secureZero(&stored_key);

    var cb_b64_buf: [std.base64.standard.Encoder.calcSize(gs2_header.len)]u8 = undefined;
    const cb_b64 = std.base64.standard.Encoder.encode(&cb_b64_buf, gs2_header);
    const without_proof = try std.fmt.allocPrint(allocator, "c={s},r={s}", .{ cb_b64, parsed.nonce });
    defer allocator.free(without_proof);

    const auth_message = try std.fmt.allocPrint(
        allocator,
        "{s},{s},{s}",
        .{ state.client_first_bare, server_first, without_proof },
    );
    defer allocator.free(auth_message);

    var client_signature: [digest_len]u8 = undefined;
    HmacSha256.create(&client_signature, auth_message, &stored_key);
    defer secureZero(&client_signature);

    var proof: [digest_len]u8 = undefined;
    defer secureZero(&proof);
    for (&proof, client_key, client_signature) |*dst, key_byte, sig_byte| {
        dst.* = key_byte ^ sig_byte;
    }

    var server_key: [digest_len]u8 = undefined;
    HmacSha256.create(&server_key, "Server Key", &salted_password);
    defer secureZero(&server_key);

    var server_signature: [digest_len]u8 = undefined;
    HmacSha256.create(&server_signature, auth_message, &server_key);

    var proof_b64_buf: [std.base64.standard.Encoder.calcSize(digest_len)]u8 = undefined;
    const proof_b64 = std.base64.standard.Encoder.encode(&proof_b64_buf, &proof);
    const message = try std.fmt.allocPrint(allocator, "{s},p={s}", .{ without_proof, proof_b64 });
    errdefer allocator.free(message);

    return .{ .message = message, .server_signature = server_signature };
}

pub fn verifyServerFinalSignature(server_final: []const u8, expected: [digest_len]u8) !void {
    const verifier_b64 = try parseServerFinal(server_final);
    var verifier: [digest_len]u8 = undefined;
    const decoded = try decodeBase64Into(verifier_b64, &verifier);
    if (decoded.len != digest_len) return error.InvalidBase64;
    if (!std.crypto.timing_safe.eql([digest_len]u8, expected, verifier)) {
        return error.ServerSignatureMismatch;
    }
}

const ServerFirst = struct {
    nonce: []const u8,
    salt_b64: []const u8,
    iterations: u32,
};

fn parseServerFirst(raw: []const u8) ScramError!ServerFirst {
    if (raw.len == 0) return error.MalformedMessage;

    var nonce: ?[]const u8 = null;
    var salt_b64: ?[]const u8 = null;
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
                _ = decodedBase64Size(parsed.value) catch return error.InvalidBase64;
                salt_b64 = parsed.value;
            },
            'i' => {
                if (seen_i) return error.DuplicateAttribute;
                seen_i = true;
                const value = std.fmt.parseUnsigned(u32, parsed.value, 10) catch {
                    return error.InvalidIterations;
                };
                if (value == 0) return error.InvalidIterations;
                iterations = value;
            },
            'm' => return error.InvalidAttribute,
            'c', 'p', 'v', 'n' => return error.InvalidAttribute,
            else => {},
        }
    }

    return .{
        .nonce = nonce orelse return error.MissingAttribute,
        .salt_b64 = salt_b64 orelse return error.MissingAttribute,
        .iterations = iterations orelse return error.MissingAttribute,
    };
}

fn parseServerFinal(raw: []const u8) ScramError![]const u8 {
    if (raw.len == 0) return error.MalformedMessage;

    var verifier: ?[]const u8 = null;
    var seen_v = false;
    var seen_e = false;

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |attr| {
        const parsed = try splitAttr(attr);
        switch (parsed.name) {
            'v' => {
                if (seen_v) return error.DuplicateAttribute;
                seen_v = true;
                if (parsed.value.len == 0) return error.InvalidBase64;
                _ = decodedBase64Size(parsed.value) catch return error.InvalidBase64;
                verifier = parsed.value;
            },
            'e' => {
                if (seen_e) return error.DuplicateAttribute;
                seen_e = true;
                return error.ServerRejected;
            },
            else => return error.InvalidAttribute,
        }
    }

    return verifier orelse error.MissingAttribute;
}

const Attr = struct {
    name: u8,
    value: []const u8,
};

fn splitAttr(raw: []const u8) ScramError!Attr {
    if (raw.len < 3 or raw[1] != '=') return error.MalformedMessage;
    return .{ .name = raw[0], .value = raw[2..] };
}

fn escapeSaslName(allocator: Allocator, username: []const u8) ![]u8 {
    if (username.len == 0) return error.InvalidUsername;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (username) |c| {
        switch (c) {
            0 => return error.InvalidUsername,
            ',' => try out.appendSlice(allocator, "=2C"),
            '=' => try out.appendSlice(allocator, "=3D"),
            else => try out.append(allocator, c),
        }
    }
    return out.toOwnedSlice(allocator);
}

fn validNonce(nonce: []const u8) bool {
    if (nonce.len == 0) return false;
    for (nonce) |c| {
        if (c == ',' or c < 0x21 or c > 0x7e) return false;
    }
    return true;
}

fn decodedBase64Size(encoded: []const u8) std.base64.Error!usize {
    return std.base64.standard.Decoder.calcSizeForSlice(encoded);
}

fn decodeBase64Into(encoded: []const u8, out: []u8) ![]const u8 {
    const size = decodedBase64Size(encoded) catch return error.InvalidBase64;
    if (size > out.len) return error.InvalidBase64;
    std.base64.standard.Decoder.decode(out[0..size], encoded) catch return error.InvalidBase64;
    return out[0..size];
}

fn decodeBase64Alloc(allocator: Allocator, encoded: []const u8) ![]u8 {
    const size = decodedBase64Size(encoded) catch return error.InvalidBase64;
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    std.base64.standard.Decoder.decode(out, encoded) catch return error.InvalidBase64;
    return out;
}

fn secureZero(bytes: []u8) void {
    @memset(bytes, 0);
    std.mem.doNotOptimizeAway(bytes.ptr);
}

const ParsedClientFirst = struct {
    client_first_bare: []const u8,
    nonce: []const u8,
};

fn parseClientFirstForTest(raw: []const u8) ScramError!ParsedClientFirst {
    if (!std.mem.startsWith(u8, raw, gs2_header)) return error.MalformedMessage;
    const bare = raw[gs2_header.len..];
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
                if (parsed.value.len == 0) return error.InvalidUsername;
            },
            'r' => {
                if (seen_r) return error.DuplicateAttribute;
                seen_r = true;
                if (!validNonce(parsed.value)) return error.InvalidNonce;
                nonce = parsed.value;
            },
            else => return error.InvalidAttribute,
        }
    }

    return .{
        .client_first_bare = bare,
        .nonce = nonce orelse return error.MissingAttribute,
    };
}

const ParsedClientFinal = struct {
    nonce: []const u8,
    proof_b64: []const u8,
    without_proof: []const u8,
};

fn parseClientFinalForTest(raw: []const u8) ScramError!ParsedClientFinal {
    const proof_marker = std.mem.indexOf(u8, raw, ",p=") orelse return error.MissingAttribute;
    const without_proof = raw[0..proof_marker];
    var nonce: ?[]const u8 = null;
    var proof: ?[]const u8 = null;

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |attr| {
        const parsed = try splitAttr(attr);
        switch (parsed.name) {
            'c' => {
                var cb_buf: [gs2_header.len]u8 = undefined;
                const cb = try decodeBase64Into(parsed.value, &cb_buf);
                if (!std.mem.eql(u8, cb, gs2_header)) return error.InvalidAttribute;
            },
            'r' => {
                if (!validNonce(parsed.value)) return error.InvalidNonce;
                nonce = parsed.value;
            },
            'p' => {
                if (@intFromPtr(attr.ptr) + attr.len != @intFromPtr(raw.ptr) + raw.len) {
                    return error.InvalidAttribute;
                }
                proof = parsed.value;
            },
            else => return error.InvalidAttribute,
        }
    }

    return .{
        .nonce = nonce orelse return error.MissingAttribute,
        .proof_b64 = proof orelse return error.MissingAttribute,
        .without_proof = without_proof,
    };
}

const ServerKeys = struct {
    stored_key: [digest_len]u8,
    server_key: [digest_len]u8,
};

fn deriveServerKeys(password: []const u8, salt: []const u8, iterations: u32) !ServerKeys {
    var salted: [digest_len]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&salted, password, salt, iterations, HmacSha256);
    defer secureZero(&salted);

    var client_key: [digest_len]u8 = undefined;
    HmacSha256.create(&client_key, "Client Key", &salted);
    defer secureZero(&client_key);

    var stored_key: [digest_len]u8 = undefined;
    Sha256Impl.hash(&client_key, &stored_key, .{});

    var server_key: [digest_len]u8 = undefined;
    HmacSha256.create(&server_key, "Server Key", &salted);

    return .{ .stored_key = stored_key, .server_key = server_key };
}

const StubServer = struct {
    allocator: Allocator,
    client_first_bare: []u8,
    server_first: []u8,
    nonce: []u8,
    keys: ServerKeys,

    fn init(
        allocator: Allocator,
        client_first: []const u8,
        password: []const u8,
        salt: []const u8,
        iterations: u32,
        server_nonce: []const u8,
    ) !StubServer {
        const parsed = try parseClientFirstForTest(client_first);
        const combined_nonce = try std.fmt.allocPrint(allocator, "{s}{s}", .{ parsed.nonce, server_nonce });
        errdefer allocator.free(combined_nonce);

        var salt_b64_buf: [std.base64.standard.Encoder.calcSize(128)]u8 = undefined;
        const salt_b64 = std.base64.standard.Encoder.encode(&salt_b64_buf, salt);
        const server_first = try std.fmt.allocPrint(
            allocator,
            "r={s},s={s},i={d}",
            .{ combined_nonce, salt_b64, iterations },
        );
        errdefer allocator.free(server_first);

        const bare = try allocator.dupe(u8, parsed.client_first_bare);
        errdefer allocator.free(bare);

        return .{
            .allocator = allocator,
            .client_first_bare = bare,
            .server_first = server_first,
            .nonce = combined_nonce,
            .keys = try deriveServerKeys(password, salt, iterations),
        };
    }

    fn deinit(self: *StubServer) void {
        self.allocator.free(self.client_first_bare);
        self.allocator.free(self.server_first);
        self.allocator.free(self.nonce);
        self.* = undefined;
    }

    fn verify(self: *const StubServer, client_final: []const u8) ![]u8 {
        const parsed = try parseClientFinalForTest(client_final);
        if (!std.mem.eql(u8, parsed.nonce, self.nonce)) return error.InvalidNonce;

        var proof: [digest_len]u8 = undefined;
        const proof_decoded = try decodeBase64Into(parsed.proof_b64, &proof);
        if (proof_decoded.len != digest_len) return error.InvalidBase64;
        defer secureZero(&proof);

        const auth_message = try std.fmt.allocPrint(
            self.allocator,
            "{s},{s},{s}",
            .{ self.client_first_bare, self.server_first, parsed.without_proof },
        );
        defer self.allocator.free(auth_message);

        var client_signature: [digest_len]u8 = undefined;
        HmacSha256.create(&client_signature, auth_message, &self.keys.stored_key);
        defer secureZero(&client_signature);

        var client_key: [digest_len]u8 = undefined;
        for (&client_key, proof, client_signature) |*dst, proof_byte, sig_byte| {
            dst.* = proof_byte ^ sig_byte;
        }
        defer secureZero(&client_key);

        var stored_check: [digest_len]u8 = undefined;
        Sha256Impl.hash(&client_key, &stored_check, .{});
        defer secureZero(&stored_check);

        if (!std.crypto.timing_safe.eql([digest_len]u8, stored_check, self.keys.stored_key)) {
            return error.ProofMismatch;
        }

        var server_signature: [digest_len]u8 = undefined;
        HmacSha256.create(&server_signature, auth_message, &self.keys.server_key);
        defer secureZero(&server_signature);

        var verifier_b64_buf: [std.base64.standard.Encoder.calcSize(digest_len)]u8 = undefined;
        const verifier_b64 = std.base64.standard.Encoder.encode(&verifier_b64_buf, &server_signature);
        return std.fmt.allocPrint(self.allocator, "v={s}", .{verifier_b64});
    }
};

test "full exchange with inline server stub authenticates" {
    const allocator = std.testing.allocator;
    var first = try clientFirst(allocator, "announce", "clientNonce");
    defer first.deinit();
    try std.testing.expectEqualStrings("n,,n=announce,r=clientNonce", first.message);

    var server = try StubServer.init(allocator, first.message, "correct horse", "salty bytes", 4096, "SERVER");
    defer server.deinit();

    var final = try clientFinal(allocator, &first.state, server.server_first, "correct horse");
    defer final.deinit(allocator);

    const server_final = try server.verify(final.message);
    defer allocator.free(server_final);
    try final.verifyServerFinal(server_final);
}

test "wrong password produces proof the server rejects" {
    const allocator = std.testing.allocator;
    var first = try clientFirst(allocator, "announce", "clientNonce2");
    defer first.deinit();
    var server = try StubServer.init(allocator, first.message, "right password", "salty bytes", 4096, "SERVER");
    defer server.deinit();

    var final = try clientFinal(allocator, &first.state, server.server_first, "wrong password");
    defer final.deinit(allocator);

    try std.testing.expectError(error.ProofMismatch, server.verify(final.message));
}

test "server signature verification rejects tampering" {
    const allocator = std.testing.allocator;
    var first = try clientFirst(allocator, "announce", "clientNonce3");
    defer first.deinit();
    var server = try StubServer.init(allocator, first.message, "password", "salty bytes", 4096, "SERVER");
    defer server.deinit();
    var final = try clientFinal(allocator, &first.state, server.server_first, "password");
    defer final.deinit(allocator);

    const server_final = try server.verify(final.message);
    defer allocator.free(server_final);
    const tampered = try allocator.dupe(u8, server_final);
    defer allocator.free(tampered);
    tampered[2] = if (tampered[2] == 'A') 'B' else 'A';

    try std.testing.expectError(error.ServerSignatureMismatch, final.verifyServerFinal(tampered));
}

test "gs2 n header is encoded and server nonce must extend client nonce" {
    const allocator = std.testing.allocator;
    var first = try clientFirst(allocator, "user,name=1", "abc123");
    defer first.deinit();
    try std.testing.expectEqualStrings("n,,n=user=2Cname=3D1,r=abc123", first.message);

    var salt_b64_buf: [std.base64.standard.Encoder.calcSize(4)]u8 = undefined;
    const salt_b64 = std.base64.standard.Encoder.encode(&salt_b64_buf, "salt");
    const bad_server_first = try std.fmt.allocPrint(allocator, "r=wrong,s={s},i=4096", .{salt_b64});
    defer allocator.free(bad_server_first);

    try std.testing.expectError(
        error.InvalidNonce,
        clientFinal(allocator, &first.state, bad_server_first, "pencil"),
    );

    const server_first = try std.fmt.allocPrint(allocator, "r=abc123XYZ,s={s},i=4096", .{salt_b64});
    defer allocator.free(server_first);
    var final = try clientFinal(allocator, &first.state, server_first, "pencil");
    defer final.deinit(allocator);
    try std.testing.expect(std.mem.startsWith(u8, final.message, "c=biws,r=abc123XYZ,p="));
}

test "rfc 7677 scram-sha-256 vector" {
    const allocator = std.testing.allocator;
    var first = try clientFirst(allocator, "user", "rOprNGfwEbeRWgbNEkqO");
    defer first.deinit();
    try std.testing.expectEqualStrings("n,,n=user,r=rOprNGfwEbeRWgbNEkqO", first.message);

    const server_first =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," ++
        "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    var final = try clientFinal(allocator, &first.state, server_first, "pencil");
    defer final.deinit(allocator);

    try std.testing.expectEqualStrings(
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," ++
            "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
        final.message,
    );
    try final.verifyServerFinal("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
}
