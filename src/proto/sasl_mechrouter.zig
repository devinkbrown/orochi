//! SASL mechanism router.
//!
//! This module is protocol-only. It consumes AUTHENTICATE base64 chunks and
//! dispatches to the selected responder without doing I/O or daemon work.
const std = @import("std");

const sasl = @import("sasl.zig");
const scram256 = @import("sasl_scram_server.zig");
const scram512 = @import("sasl_scram512_server.zig");

pub const SUPPORTED_MECHANISMS = "PLAIN EXTERNAL SCRAM-SHA-256 SCRAM-SHA-512";
pub const MAX_AUTHENTICATE_CHUNK: usize = 400;
pub const MAX_RAW_MESSAGE: usize = sasl.MAX_SCRAM_MESSAGE;
pub const MAX_B64_MESSAGE: usize = std.base64.standard.Encoder.calcSize(MAX_RAW_MESSAGE);
pub const MAX_ACCOUNT: usize = sasl.MAX_SCRAM_USERNAME;

pub const Mechanism = enum {
    plain,
    external,
    scram_sha_256,
    scram_sha_512,

    pub fn parse(name_text: []const u8) ?Mechanism {
        if (std.ascii.eqlIgnoreCase(name_text, "PLAIN")) return .plain;
        if (std.ascii.eqlIgnoreCase(name_text, "EXTERNAL")) return .external;
        if (std.ascii.eqlIgnoreCase(name_text, "SCRAM-SHA-256")) return .scram_sha_256;
        if (std.ascii.eqlIgnoreCase(name_text, "SCRAM-SHA-512")) return .scram_sha_512;
        return null;
    }

    pub fn name(self: Mechanism) []const u8 {
        return switch (self) {
            .plain => "PLAIN",
            .external => "EXTERNAL",
            .scram_sha_256 => "SCRAM-SHA-256",
            .scram_sha_512 => "SCRAM-SHA-512",
        };
    }
};

pub const Failure = enum {
    unknown_mechanism,
    unavailable,
    invalid_state,
    invalid_message,
    invalid_credentials,
    too_long,
    output_too_small,
    aborted,
};

pub const Success = struct {
    account: []const u8,
    final_data: ?[]const u8 = null,
};

pub const Outcome = union(enum) {
    /// AUTHENTICATE payload for the caller to send. The literal "+" means an
    /// empty challenge; an empty slice means the router is awaiting more input
    /// chunks before producing an outbound payload.
    continue_: []const u8,
    success: Success,
    fail: Failure,
};

pub const PlainLookup = struct {
    ptr: *anyopaque,
    verifyFn: *const fn (ptr: *anyopaque, creds: sasl.PlainCredentials) ?[]const u8,

    pub fn verify(self: PlainLookup, creds: sasl.PlainCredentials) ?[]const u8 {
        return self.verifyFn(self.ptr, creds);
    }
};

pub const ExternalLookup = struct {
    ptr: *anyopaque,
    verifyFn: *const fn (ptr: *anyopaque, certfp: []const u8, authzid: []const u8) ?[]const u8,

    pub fn verify(self: ExternalLookup, certfp: []const u8, authzid: []const u8) ?[]const u8 {
        return self.verifyFn(self.ptr, certfp, authzid);
    }
};

pub const Scram256Lookup = struct {
    ptr: *anyopaque,
    lookupFn: *const fn (ptr: *anyopaque, username: []const u8) ?scram256.Credential,

    pub fn lookup(self: Scram256Lookup, username: []const u8) ?scram256.Credential {
        return self.lookupFn(self.ptr, username);
    }
};

pub const Scram512Lookup = struct {
    ptr: *anyopaque,
    lookupFn: *const fn (ptr: *anyopaque, username: []const u8) ?scram512.Credential,

    pub fn lookup(self: Scram512Lookup, username: []const u8) ?scram512.Credential {
        return self.lookupFn(self.ptr, username);
    }
};

pub const Callbacks = struct {
    plain: ?PlainLookup = null,
    external: ?ExternalLookup = null,
    scram256: ?Scram256Lookup = null,
    scram512: ?Scram512Lookup = null,
};

pub const Router = struct {
    callbacks: Callbacks,
    server_nonce: []const u8,
    tls_certfp: ?[]const u8 = null,
    state: State = .idle,
    pending_b64: [MAX_B64_MESSAGE]u8 = undefined,
    pending_len: usize = 0,
    decode_buf: [MAX_RAW_MESSAGE]u8 = undefined,
    account_buf: [MAX_ACCOUNT]u8 = undefined,
    account_len: usize = 0,

    const State = union(enum) {
        idle,
        plain,
        external,
        scram256: scram256.Server,
        scram512: scram512.Server,
    };

    pub fn init(callbacks: Callbacks, server_nonce: []const u8) Router {
        return .{
            .callbacks = callbacks,
            .server_nonce = server_nonce,
        };
    }

    pub fn mechanismList() []const u8 {
        return SUPPORTED_MECHANISMS;
    }

    pub fn start(self: *Router, mechanism_name: []const u8) Outcome {
        const mechanism = Mechanism.parse(mechanism_name) orelse {
            self.resetExchange();
            return .{ .fail = .unknown_mechanism };
        };
        if (!self.enabled(mechanism)) {
            self.resetExchange();
            return .{ .fail = .unavailable };
        }
        self.pending_len = 0;
        self.account_len = 0;
        self.state = switch (mechanism) {
            .plain => .plain,
            .external => .external,
            .scram_sha_256 => .{ .scram256 = scram256.Server.init() },
            .scram_sha_512 => .{ .scram512 = scram512.Server.init() },
        };
        return .{ .continue_ = "+" };
    }

    pub fn abort(self: *Router) Outcome {
        self.resetExchange();
        return .{ .fail = .aborted };
    }

    pub fn receive(self: *Router, client_chunk_b64: []const u8, out: []u8) Outcome {
        if (std.mem.eql(u8, client_chunk_b64, "*")) return self.abort();
        if (client_chunk_b64.len > MAX_AUTHENTICATE_CHUNK) return self.failReset(.too_long);
        if (self.pending_len + client_chunk_b64.len > self.pending_b64.len) return self.failReset(.too_long);

        @memcpy(self.pending_b64[self.pending_len..][0..client_chunk_b64.len], client_chunk_b64);
        self.pending_len += client_chunk_b64.len;
        if (client_chunk_b64.len == MAX_AUTHENTICATE_CHUNK) return .{ .continue_ = "" };

        const pending = self.pending_b64[0..self.pending_len];
        const raw = decodeBase64(pending, &self.decode_buf) catch return self.failReset(.invalid_message);
        self.pending_len = 0;

        return switch (self.state) {
            .idle => self.failReset(.invalid_state),
            .plain => self.stepPlain(raw),
            .external => self.stepExternal(raw),
            .scram256 => |*server| self.stepScram256(server, raw, out),
            .scram512 => |*server| self.stepScram512(server, raw, out),
        };
    }

    fn enabled(self: *const Router, mechanism: Mechanism) bool {
        return switch (mechanism) {
            .plain => self.callbacks.plain != null,
            .external => self.callbacks.external != null and self.tls_certfp != null,
            .scram_sha_256 => self.callbacks.scram256 != null and self.server_nonce.len != 0,
            .scram_sha_512 => self.callbacks.scram512 != null and self.server_nonce.len != 0,
        };
    }

    fn stepPlain(self: *Router, raw: []const u8) Outcome {
        const checker = self.callbacks.plain orelse return self.failReset(.unavailable);
        const creds = sasl.parsePlain(raw) catch return self.failReset(.invalid_message);
        const account = checker.verify(creds) orelse return self.failReset(.invalid_credentials);
        const copied = self.copyAccount(account) orelse return self.failReset(.invalid_message);
        self.state = .idle;
        return .{ .success = .{ .account = copied } };
    }

    fn stepExternal(self: *Router, raw: []const u8) Outcome {
        const certfp = self.tls_certfp orelse return self.failReset(.unavailable);
        const checker = self.callbacks.external orelse return self.failReset(.unavailable);
        const account = checker.verify(certfp, raw) orelse return self.failReset(.invalid_credentials);
        const copied = self.copyAccount(account) orelse return self.failReset(.invalid_message);
        self.state = .idle;
        return .{ .success = .{ .account = copied } };
    }

    fn stepScram256(self: *Router, server: *scram256.Server, raw: []const u8, out: []u8) Outcome {
        switch (server.step) {
            .client_first => {
                var username_buf: [scram256.MAX_USERNAME]u8 = undefined;
                const parsed = scram256.parseClientFirst(raw, &username_buf) catch return self.failReset(.invalid_message);
                const lookup = self.callbacks.scram256 orelse return self.failReset(.unavailable);
                const credential = lookup.lookup(parsed.username) orelse return self.failReset(.invalid_credentials);
                var raw_out: [scram256.MAX_MESSAGE]u8 = undefined;
                const first = server.receiveClientFirst(raw, credential, self.server_nonce, &raw_out) catch {
                    return self.failReset(.invalid_message);
                };
                const encoded = encodeBase64(first.server_first, out) catch return self.failReset(.output_too_small);
                return .{ .continue_ = encoded };
            },
            .client_final => {
                var raw_out: [scram256.MAX_MESSAGE]u8 = undefined;
                const final = server.receiveClientFinal(raw, &raw_out) catch return self.failReset(.invalid_credentials);
                const account = self.copyAccount(server.username()) orelse return self.failReset(.invalid_message);
                const encoded = encodeBase64(final.server_final, out) catch return self.failReset(.output_too_small);
                self.state = .idle;
                return .{ .success = .{ .account = account, .final_data = encoded } };
            },
            .complete => return self.failReset(.invalid_state),
        }
    }

    fn stepScram512(self: *Router, server: *scram512.Server, raw: []const u8, out: []u8) Outcome {
        switch (server.step) {
            .client_first => {
                var username_buf: [scram512.MAX_USERNAME]u8 = undefined;
                const parsed = scram512.parseClientFirst(raw, &username_buf) catch return self.failReset(.invalid_message);
                const lookup = self.callbacks.scram512 orelse return self.failReset(.unavailable);
                const credential = lookup.lookup(parsed.username) orelse return self.failReset(.invalid_credentials);
                var raw_out: [scram512.MAX_MESSAGE]u8 = undefined;
                const first = server.receiveClientFirst(raw, credential, self.server_nonce, &raw_out) catch {
                    return self.failReset(.invalid_message);
                };
                const encoded = encodeBase64(first.server_first, out) catch return self.failReset(.output_too_small);
                return .{ .continue_ = encoded };
            },
            .client_final => {
                var raw_out: [scram512.MAX_MESSAGE]u8 = undefined;
                const final = server.receiveClientFinal(raw, &raw_out) catch return self.failReset(.invalid_credentials);
                const account = self.copyAccount(server.username()) orelse return self.failReset(.invalid_message);
                const encoded = encodeBase64(final.server_final, out) catch return self.failReset(.output_too_small);
                self.state = .idle;
                return .{ .success = .{ .account = account, .final_data = encoded } };
            },
            .complete => return self.failReset(.invalid_state),
        }
    }

    fn copyAccount(self: *Router, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > self.account_buf.len) return null;
        @memcpy(self.account_buf[0..account.len], account);
        self.account_len = account.len;
        return self.account_buf[0..self.account_len];
    }

    fn failReset(self: *Router, failure: Failure) Outcome {
        self.resetExchange();
        return .{ .fail = failure };
    }

    fn resetExchange(self: *Router) void {
        self.state = .idle;
        self.pending_len = 0;
        self.account_len = 0;
    }
};

fn decodeBase64(src: []const u8, out: []u8) ![]const u8 {
    if (std.mem.eql(u8, src, "+")) return out[0..0];
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

fn encodeBase64(src: []const u8, out: []u8) ![]const u8 {
    const size = std.base64.standard.Encoder.calcSize(src.len);
    if (size > out.len) return error.NoSpaceLeft;
    return std.base64.standard.Encoder.encode(out[0..size], src);
}

fn secureZero(buf: []u8) void {
    for (buf) |*byte| {
        const vp: *volatile u8 = @ptrCast(byte);
        vp.* = 0;
    }
}

fn hmacSha256(key: []const u8, msg: []const u8) [scram256.digest_len]u8 {
    var out: [scram256.digest_len]u8 = undefined;
    std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256).create(&out, msg, key);
    return out;
}

fn b64(comptime text: []const u8) [std.base64.standard.Encoder.calcSize(text.len)]u8 {
    var out: [std.base64.standard.Encoder.calcSize(text.len)]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, text);
    return out;
}

test "PLAIN accepts and rejects through router" {
    const Db = struct {
        accept: bool,

        fn verify(ptr: *anyopaque, creds: sasl.PlainCredentials) ?[]const u8 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!self.accept) return null;
            if (!std.mem.eql(u8, creds.authcid, "kain")) return null;
            if (!std.mem.eql(u8, creds.password, "correct")) return null;
            return "kain";
        }
    };

    var db = Db{ .accept = true };
    var router = Router.init(.{ .plain = .{ .ptr = &db, .verifyFn = Db.verify } }, "serverNonce");
    try std.testing.expectEqualStrings("+", router.start("PLAIN").continue_);

    var out: [MAX_B64_MESSAGE]u8 = undefined;
    const good = b64("authz\x00kain\x00correct");
    const accepted = router.receive(&good, &out);
    try std.testing.expectEqualStrings("kain", accepted.success.account);

    db.accept = false;
    try std.testing.expectEqualStrings("+", router.start("plain").continue_);
    const rejected = router.receive(&good, &out);
    try std.testing.expectEqual(Failure.invalid_credentials, rejected.fail);
}

test "SCRAM-SHA-256 round trip accepts and rejects tampered proof through router" {
    const allocator = std.testing.allocator;
    const salt = try allocator.dupe(u8, "known-scram-sha-256-salt");
    defer allocator.free(salt);

    var keys = try sasl.deriveScramKeys("pencil", salt, 4096);
    defer keys.wipe();

    const Db = struct {
        credential: scram256.Credential,

        fn lookup(ptr: *anyopaque, username: []const u8) ?scram256.Credential {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!std.mem.eql(u8, username, "user")) return null;
            return self.credential;
        }
    };
    var db = Db{
        .credential = .{
            .salt = salt,
            .iterations = 4096,
            .stored_key = keys.stored_key,
            .server_key = keys.server_key,
        },
    };
    var router = Router.init(.{ .scram256 = .{ .ptr = &db, .lookupFn = Db.lookup } }, "serverNonce256");
    try std.testing.expectEqualStrings("+", router.start("SCRAM-SHA-256").continue_);

    var out: [MAX_B64_MESSAGE]u8 = undefined;
    const client_first = b64("n,,n=user,r=clientNonce256");
    const first_out = router.receive(&client_first, &out);
    const server_first_b64 = first_out.continue_;
    var server_first_raw_buf: [scram256.MAX_MESSAGE]u8 = undefined;
    const server_first = try decodeBase64(server_first_b64, &server_first_raw_buf);
    const parsed_first = try scram256.parseServerFirst(server_first);
    try std.testing.expectEqualStrings("clientNonce256serverNonce256", parsed_first.nonce);

    const client_final_without_proof = try std.fmt.allocPrint(
        allocator,
        "c=biws,r={s}",
        .{parsed_first.nonce},
    );
    defer allocator.free(client_final_without_proof);
    const auth_message = try std.fmt.allocPrint(
        allocator,
        "n=user,r=clientNonce256,{s},{s}",
        .{ server_first, client_final_without_proof },
    );
    defer allocator.free(auth_message);

    var client_sig = hmacSha256(&keys.stored_key, auth_message);
    defer secureZero(&client_sig);
    var client_proof: [scram256.digest_len]u8 = undefined;
    defer secureZero(&client_proof);
    for (&client_proof, keys.client_key, client_sig) |*dst, key_byte, sig_byte| {
        dst.* = key_byte ^ sig_byte;
    }

    var proof_b64_buf: [std.base64.standard.Encoder.calcSize(scram256.digest_len)]u8 = undefined;
    const proof_b64 = std.base64.standard.Encoder.encode(&proof_b64_buf, &client_proof);
    const client_final = try std.fmt.allocPrint(
        allocator,
        "{s},p={s}",
        .{ client_final_without_proof, proof_b64 },
    );
    defer allocator.free(client_final);

    const client_final_b64 = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(client_final.len));
    defer allocator.free(client_final_b64);
    _ = std.base64.standard.Encoder.encode(client_final_b64, client_final);
    const accepted = router.receive(client_final_b64, &out);
    try std.testing.expectEqualStrings("user", accepted.success.account);
    const final_data = accepted.success.final_data orelse return error.MissingFinalData;
    var server_final_raw_buf: [scram256.MAX_MESSAGE]u8 = undefined;
    const server_final = try decodeBase64(final_data, &server_final_raw_buf);
    _ = try scram256.parseServerFinal(server_final);

    try std.testing.expectEqualStrings("+", router.start("SCRAM-SHA-256").continue_);
    _ = router.receive(&client_first, &out);
    client_proof[0] ^= 1;
    const bad_proof_b64 = std.base64.standard.Encoder.encode(&proof_b64_buf, &client_proof);
    const bad_final = try std.fmt.allocPrint(
        allocator,
        "{s},p={s}",
        .{ client_final_without_proof, bad_proof_b64 },
    );
    defer allocator.free(bad_final);
    const bad_final_b64 = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(bad_final.len));
    defer allocator.free(bad_final_b64);
    _ = std.base64.standard.Encoder.encode(bad_final_b64, bad_final);
    const rejected = router.receive(bad_final_b64, &out);
    try std.testing.expectEqual(Failure.invalid_credentials, rejected.fail);
}

test "EXTERNAL accepts through router" {
    const Db = struct {
        fn verify(_: *anyopaque, certfp: []const u8, authzid: []const u8) ?[]const u8 {
            if (!std.mem.eql(u8, certfp, "ABCD")) return null;
            if (!std.mem.eql(u8, authzid, "kain")) return null;
            return "kain";
        }
    };
    var token: u8 = 0;
    var router = Router.init(.{ .external = .{ .ptr = &token, .verifyFn = Db.verify } }, "serverNonce");
    router.tls_certfp = "ABCD";
    try std.testing.expectEqualStrings("+", router.start("EXTERNAL").continue_);

    var out: [MAX_B64_MESSAGE]u8 = undefined;
    const authzid = b64("kain");
    const accepted = router.receive(&authzid, &out);
    try std.testing.expectEqualStrings("kain", accepted.success.account);
}

test "unknown mechanism rejects" {
    var router = Router.init(.{}, "serverNonce");
    const rejected = router.start("NOT-A-MECH");
    try std.testing.expectEqual(Failure.unknown_mechanism, rejected.fail);
}

test "mechanism list string advertises supported mechanisms" {
    try std.testing.expectEqualStrings(
        "PLAIN EXTERNAL SCRAM-SHA-256 SCRAM-SHA-512",
        Router.mechanismList(),
    );
    try std.testing.expectEqualStrings(SUPPORTED_MECHANISMS, Router.mechanismList());
}

test {
    std.testing.refAllDecls(@This());
}
