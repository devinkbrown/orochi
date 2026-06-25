// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Property and fuzz-style tests for SASL protocol parsing.
//!
//! These tests intentionally exercise only the public `sasl.zig` API. SCRAM
//! parser internals and base64 helpers are reached through `Dispatcher.receive`.
const std = @import("std");
const sasl = @import("sasl.zig");

const seed: u64 = 0x4d495a5543484955;

const mechanism_iterations: usize = 640;
const plain_random_iterations: usize = 768;
const plain_structured_iterations: usize = 512;
const scram_client_first_iterations: usize = 500;
const scram_client_final_iterations: usize = 300;
const base64_payload_iterations: usize = 500;

test "mechanism parser is total over attacker bytes and names round trip" {
    inline for (.{ sasl.Mechanism.plain, sasl.Mechanism.external, sasl.Mechanism.scram_sha_256 }) |mech| {
        try std.testing.expectEqual(mech, sasl.Mechanism.parse(mech.name()).?);
    }

    var prng = std.Random.DefaultPrng.init(seed ^ 0x1001);
    const random = prng.random();
    var input_buf: [96]u8 = undefined;

    for (0..mechanism_iterations) |i| {
        const input = attackerSlice(random, &input_buf, i);
        const parsed = sasl.Mechanism.parse(input);
        if (parsed) |mech| {
            try std.testing.expectEqual(mech, sasl.Mechanism.parse(mech.name()).?);
            try std.testing.expect(parsedNameMatchesInput(mech, input));
        }
    }
}

test "PLAIN parser is total over random bytes and successful slices stay in input" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x2002);
    const random = prng.random();
    var input_buf: [sasl.MAX_AUTHENTICATE_PAYLOAD]u8 = undefined;

    for (0..plain_random_iterations) |i| {
        const raw = attackerSlice(random, &input_buf, i);
        const parsed = sasl.parsePlain(raw) catch |err| {
            try std.testing.expectEqual(error.InvalidMessage, err);
            continue;
        };

        try expectSliceWithin(raw, parsed.authzid);
        try expectSliceWithin(raw, parsed.authcid);
        try expectSliceWithin(raw, parsed.password);
        try std.testing.expect(parsed.authcid.len > 0);
        try std.testing.expect(std.mem.indexOfScalar(u8, parsed.password, 0) == null);
        try expectPlainCanonical(raw, parsed);
    }
}

test "PLAIN structured credentials reject embedded NULs beyond the two separators" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x3003);
    const random = prng.random();
    var authzid_buf: [48]u8 = undefined;
    var authcid_buf: [48]u8 = undefined;
    var password_buf: [48]u8 = undefined;
    var raw_buf: [authzid_buf.len + authcid_buf.len + password_buf.len + 2]u8 = undefined;

    for (0..plain_structured_iterations) |i| {
        const authzid = randomField(random, &authzid_buf, i, true);
        const authcid = randomField(random, &authcid_buf, i + 17, false);
        const password = randomField(random, &password_buf, i + 31, false);
        const raw = makePlain(authzid, authcid, password, &raw_buf);
        const should_accept = !hasNul(authzid) and !hasNul(authcid) and !hasNul(password) and authcid.len != 0;

        const parsed = sasl.parsePlain(raw) catch |err| {
            try std.testing.expectEqual(error.InvalidMessage, err);
            try std.testing.expect(!should_accept);
            continue;
        };

        try std.testing.expect(should_accept);
        try std.testing.expectEqualStrings(authzid, parsed.authzid);
        try std.testing.expectEqualStrings(authcid, parsed.authcid);
        try std.testing.expectEqualStrings(password, parsed.password);
        try expectPlainCanonical(raw, parsed);
    }
}

test "base64 authenticate payloads fail cleanly through dispatcher decoding" {
    const Db = struct {
        fn verify(_: *anyopaque, creds: sasl.PlainCredentials) bool {
            return creds.authcid.len != 0;
        }
    };

    var token: u8 = 0;
    var prng = std.Random.DefaultPrng.init(seed ^ 0x4004);
    const random = prng.random();
    var payload_buf: [768]u8 = undefined;
    var decode_buf: [sasl.MAX_AUTHENTICATE_PAYLOAD]u8 = undefined;
    var out: [sasl.MAX_AUTHENTICATE_PAYLOAD]u8 = undefined;

    for (0..base64_payload_iterations) |i| {
        var dispatcher = sasl.Dispatcher.init(.{ .plain = .{ .ptr = &token, .verifyFn = Db.verify } }, "server");
        try std.testing.expectEqualStrings("+", dispatcher.start(.plain).continue_);
        const payload = attackerSlice(random, &payload_buf, i);
        const decision = try dispatcher.receive(payload, &decode_buf, &out);
        try expectDecisionWellFormed(decision);
    }

    var dispatcher = sasl.Dispatcher.init(.{ .plain = .{ .ptr = &token, .verifyFn = Db.verify } }, "server");
    _ = dispatcher.start(.plain);
    const plus = try dispatcher.receive("+", &decode_buf, &out);
    try std.testing.expectEqual(sasl.Numeric.ERR_SASLFAIL, plus.failure);
}

test "SCRAM client-first parser is total over base64-wrapped random bytes" {
    const Db = struct {
        record: sasl.ScramRecord,

        fn lookup(ptr: *anyopaque, _: []const u8) ?sasl.ScramRecord {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.record;
        }
    };

    var db = Db{ .record = try sasl.recordFromPassword("p", "salt", 1) };
    var prng = std.Random.DefaultPrng.init(seed ^ 0x5005);
    const random = prng.random();
    var raw_buf: [sasl.MAX_SCRAM_MESSAGE]u8 = undefined;
    var payload_buf: [std.base64.standard.Encoder.calcSize(sasl.MAX_SCRAM_MESSAGE)]u8 = undefined;
    var decode_buf: [sasl.MAX_AUTHENTICATE_PAYLOAD]u8 = undefined;
    var out: [sasl.MAX_AUTHENTICATE_PAYLOAD]u8 = undefined;

    for (0..scram_client_first_iterations) |i| {
        var dispatcher = sasl.Dispatcher.init(.{ .scram = .{ .ptr = &db, .lookupFn = Db.lookup } }, "srv");
        try std.testing.expectEqualStrings("+", dispatcher.start(.scram_sha_256).continue_);
        const raw = attackerSlice(random, &raw_buf, i);
        const payload = try encodeStandardBase64(raw, &payload_buf);
        const decision = dispatcher.receive(payload, &decode_buf, &out) catch |err| {
            try std.testing.expectEqual(error.OutputTooSmall, err);
            continue;
        };
        try expectDecisionWellFormed(decision);
        if (decision == .continue_) {
            try std.testing.expect(decision.continue_.len <= out.len);
        }
    }
}

test "SCRAM rejects malformed nonce salt iteration and final-message fields" {
    const Db = struct {
        record: sasl.ScramRecord,

        fn lookup(ptr: *anyopaque, username: []const u8) ?sasl.ScramRecord {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!std.mem.eql(u8, username, "user")) return null;
            return self.record;
        }
    };

    var db = Db{ .record = try sasl.recordFromPassword("pencil", "saltSALTsalt", 1) };
    var decode_buf: [sasl.MAX_AUTHENTICATE_PAYLOAD]u8 = undefined;
    var out: [sasl.MAX_AUTHENTICATE_PAYLOAD]u8 = undefined;
    var payload_buf: [std.base64.standard.Encoder.calcSize(sasl.MAX_SCRAM_MESSAGE)]u8 = undefined;
    var decoded: [sasl.MAX_SCRAM_MESSAGE]u8 = undefined;

    const malformed_first = [_][]const u8{
        "",
        "n,,",
        "n,,n=,r=nonce",
        "n,,n=user,r=",
        "n,,n=user",
        "n,,r=nonce",
        "n,,m=x,n=user,r=nonce",
        "n,,n=user,r=nonce,=bad",
        "n,,n=user,r=nonce,bad",
        "n,,n=user=2X,r=nonce",
        "n,a=user,n=user,r=nonce",
    };

    for (malformed_first) |raw| {
        var dispatcher = sasl.Dispatcher.init(.{ .scram = .{ .ptr = &db, .lookupFn = Db.lookup } }, "SERVER");
        _ = dispatcher.start(.scram_sha_256);
        const payload = try encodeStandardBase64(raw, &payload_buf);
        const decision = try dispatcher.receive(payload, &decode_buf, &out);
        try std.testing.expectEqual(sasl.Numeric.ERR_SASLFAIL, decision.failure);
    }

    var zero_iter = Db{ .record = db.record };
    zero_iter.record.iterations = 0;
    try expectScramFirstFailure(Db, &zero_iter, "SERVER", "n,,n=user,r=nonce", &payload_buf, &decode_buf, &out);

    var too_much_salt: [sasl.MAX_SCRAM_SALT + 1]u8 = undefined;
    @memset(&too_much_salt, 's');
    var over_salted = Db{ .record = db.record };
    over_salted.record.salt = &too_much_salt;
    try expectScramFirstFailure(Db, &over_salted, "SERVER", "n,,n=user,r=nonce", &payload_buf, &decode_buf, &out);

    var dispatcher = sasl.Dispatcher.init(.{ .scram = .{ .ptr = &db, .lookupFn = Db.lookup } }, "SERVER");
    _ = dispatcher.start(.scram_sha_256);
    const first_payload = try encodeStandardBase64("n,,n=user,r=CLIENT", &payload_buf);
    const first = try dispatcher.receive(first_payload, &decode_buf, &out);
    const server_first = try decodeStandardBase64(first.continue_, &decoded);
    try std.testing.expectEqualStrings("r=CLIENTSERVER,s=c2FsdFNBTFRzYWx0,i=1", server_first);

    const malformed_final = [_][]const u8{
        "",
        "c=biws",
        "r=CLIENTSERVER,p=AAAA",
        "c=biws,r=WRONG,p=AAAA",
        "c=@@@@,r=CLIENTSERVER,p=AAAA",
        "c=biws,r=CLIENTSERVER,p=@@@@",
        "c=biws,r=CLIENTSERVER,p=AA==",
        "bad,c=biws,r=CLIENTSERVER,p=AAAA",
    };

    for (malformed_final) |raw| {
        var d = sasl.Dispatcher.init(.{ .scram = .{ .ptr = &db, .lookupFn = Db.lookup } }, "SERVER");
        _ = d.start(.scram_sha_256);
        _ = try d.receive(first_payload, &decode_buf, &out);
        const final_payload = try encodeStandardBase64(raw, &payload_buf);
        const decision = try d.receive(final_payload, &decode_buf, &out);
        try std.testing.expectEqual(sasl.Numeric.ERR_SASLFAIL, decision.failure);
    }
}

test "SCRAM client-final parser is total over random proof-bearing bytes" {
    const Db = struct {
        record: sasl.ScramRecord,

        fn lookup(ptr: *anyopaque, username: []const u8) ?sasl.ScramRecord {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!std.mem.eql(u8, username, "user")) return null;
            return self.record;
        }
    };

    var db = Db{ .record = try sasl.recordFromPassword("pencil", "saltSALTsalt", 1) };
    var prng = std.Random.DefaultPrng.init(seed ^ 0x6006);
    const random = prng.random();
    var raw_buf: [sasl.MAX_SCRAM_MESSAGE]u8 = undefined;
    var payload_buf: [std.base64.standard.Encoder.calcSize(sasl.MAX_SCRAM_MESSAGE)]u8 = undefined;
    var decode_buf: [sasl.MAX_AUTHENTICATE_PAYLOAD]u8 = undefined;
    var out: [sasl.MAX_AUTHENTICATE_PAYLOAD]u8 = undefined;

    for (0..scram_client_final_iterations) |i| {
        var dispatcher = sasl.Dispatcher.init(.{ .scram = .{ .ptr = &db, .lookupFn = Db.lookup } }, "SERVER");
        _ = dispatcher.start(.scram_sha_256);
        const first_payload = try encodeStandardBase64("n,,n=user,r=CLIENT", &payload_buf);
        _ = try dispatcher.receive(first_payload, &decode_buf, &out);

        const raw = attackerSlice(random, &raw_buf, i);
        const payload = try encodeStandardBase64(raw, &payload_buf);
        const decision = dispatcher.receive(payload, &decode_buf, &out) catch |err| {
            try std.testing.expectEqual(error.OutputTooSmall, err);
            continue;
        };
        try expectDecisionWellFormed(decision);
    }
}

test "SCRAM valid exchange serializes canonical server messages and rejects bad proof" {
    const Db = struct {
        record: sasl.ScramRecord,

        fn lookup(ptr: *anyopaque, username: []const u8) ?sasl.ScramRecord {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!std.mem.eql(u8, username, "user")) return null;
            return self.record;
        }
    };

    const password = "pencil";
    const salt = "saltSALTsalt";
    const iterations: u32 = 1;
    var db = Db{ .record = try sasl.recordFromPassword(password, salt, iterations) };
    var dispatcher = sasl.Dispatcher.init(.{ .scram = .{ .ptr = &db, .lookupFn = Db.lookup } }, "SERVER");
    var payload_buf: [std.base64.standard.Encoder.calcSize(sasl.MAX_SCRAM_MESSAGE)]u8 = undefined;
    var decode_buf: [sasl.MAX_AUTHENTICATE_PAYLOAD]u8 = undefined;
    var out: [sasl.MAX_AUTHENTICATE_PAYLOAD]u8 = undefined;
    var decoded: [sasl.MAX_SCRAM_MESSAGE]u8 = undefined;

    try std.testing.expectEqualStrings("+", dispatcher.start(.scram_sha_256).continue_);
    const first_payload = try encodeStandardBase64("n,,n=user,r=CLIENT", &payload_buf);
    const first = try dispatcher.receive(first_payload, &decode_buf, &out);
    const server_first = try decodeStandardBase64(first.continue_, &decoded);
    try std.testing.expectEqualStrings("r=CLIENTSERVER,s=c2FsdFNBTFRzYWx0,i=1", server_first);

    const final_payload = try makeClientFinal(
        password,
        salt,
        iterations,
        "n=user,r=CLIENT",
        server_first,
        "n,,",
        "CLIENTSERVER",
        false,
        &out,
    );
    const ok = try dispatcher.receive(final_payload, &decode_buf, &out);
    const server_final = try decodeStandardBase64(ok.success.final_data.?, &decoded);
    try std.testing.expect(std.mem.startsWith(u8, server_final, "v="));

    var rejected_dispatcher = sasl.Dispatcher.init(.{ .scram = .{ .ptr = &db, .lookupFn = Db.lookup } }, "SERVER");
    _ = rejected_dispatcher.start(.scram_sha_256);
    _ = try rejected_dispatcher.receive(first_payload, &decode_buf, &out);
    const bad_final_payload = try makeClientFinal(
        password,
        salt,
        iterations,
        "n=user,r=CLIENT",
        server_first,
        "n,,",
        "CLIENTSERVER",
        true,
        &out,
    );
    const rejected = try rejected_dispatcher.receive(bad_final_payload, &decode_buf, &out);
    try std.testing.expectEqual(sasl.Numeric.ERR_SASLFAIL, rejected.failure);
}

fn parsedNameMatchesInput(mech: sasl.Mechanism, input: []const u8) bool {
    return std.ascii.eqlIgnoreCase(input, mech.name());
}

fn attackerSlice(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = switch (iteration % 9) {
        0 => 0,
        1 => 1,
        2 => @min(buf.len, 2),
        3 => @min(buf.len, 3),
        4 => @min(buf.len, 8),
        5 => @min(buf.len, 31),
        6 => @min(buf.len, 127),
        7 => buf.len,
        else => random.intRangeAtMost(usize, 0, buf.len),
    };
    random.bytes(buf[0..len]);
    sprinkleDelimiters(buf[0..len], iteration);
    return buf[0..len];
}

fn randomField(random: std.Random, buf: []u8, iteration: usize, allow_empty: bool) []const u8 {
    const min_len: usize = if (allow_empty) 0 else 1;
    const len = switch (iteration % 8) {
        0 => min_len,
        1 => @max(min_len, @min(buf.len, 1)),
        2 => @max(min_len, @min(buf.len, 2)),
        3 => @max(min_len, @min(buf.len, 7)),
        4 => @max(min_len, @min(buf.len, 13)),
        5 => buf.len,
        else => random.intRangeAtMost(usize, min_len, buf.len),
    };
    random.bytes(buf[0..len]);
    sprinkleDelimiters(buf[0..len], iteration);
    return buf[0..len];
}

fn sprinkleDelimiters(buf: []u8, iteration: usize) void {
    if (buf.len == 0) return;
    buf[iteration % buf.len] = switch (iteration % 12) {
        0 => 0,
        1 => ',',
        2 => '=',
        3 => '+',
        4 => '/',
        5 => 0xff,
        6 => 0xc3,
        7 => 0x80,
        else => buf[iteration % buf.len],
    };
    if (buf.len > 2 and iteration % 5 == 0) buf[(iteration + 1) % buf.len] = 0;
    if (buf.len > 4 and iteration % 7 == 0) buf[(iteration + 3) % buf.len] = ',';
}

fn makePlain(authzid: []const u8, authcid: []const u8, password: []const u8, out: []u8) []const u8 {
    var n: usize = 0;
    @memcpy(out[n..][0..authzid.len], authzid);
    n += authzid.len;
    out[n] = 0;
    n += 1;
    @memcpy(out[n..][0..authcid.len], authcid);
    n += authcid.len;
    out[n] = 0;
    n += 1;
    @memcpy(out[n..][0..password.len], password);
    n += password.len;
    return out[0..n];
}

fn hasNul(value: []const u8) bool {
    return std.mem.indexOfScalar(u8, value, 0) != null;
}

fn expectSliceWithin(input: []const u8, slice: []const u8) !void {
    const base = @intFromPtr(input.ptr);
    const end = base + input.len;
    const ptr = @intFromPtr(slice.ptr);
    try std.testing.expect(ptr >= base);
    try std.testing.expect(ptr <= end);
    try std.testing.expect(slice.len <= end - ptr);
}

fn expectPlainCanonical(raw: []const u8, creds: sasl.PlainCredentials) !void {
    const first = std.mem.indexOfScalar(u8, raw, 0).?;
    const rest = raw[first + 1 ..];
    const second_rel = std.mem.indexOfScalar(u8, rest, 0).?;
    const second = first + 1 + second_rel;
    try std.testing.expectEqualStrings(raw[0..first], creds.authzid);
    try std.testing.expectEqualStrings(raw[first + 1 .. second], creds.authcid);
    try std.testing.expectEqualStrings(raw[second + 1 ..], creds.password);
}

fn expectDecisionWellFormed(decision: sasl.Decision) !void {
    switch (decision) {
        .continue_ => |payload| try std.testing.expect(payload.len <= sasl.MAX_AUTHENTICATE_PAYLOAD),
        .success => |success| {
            try std.testing.expect(success.identity.authcid.len <= sasl.MAX_SCRAM_USERNAME);
            if (success.identity.authzid) |authzid| try std.testing.expect(authzid.len <= sasl.MAX_AUTHENTICATE_PAYLOAD);
            if (success.final_data) |final_data| try std.testing.expect(final_data.len <= sasl.MAX_AUTHENTICATE_PAYLOAD);
        },
        .failure => {},
        .mechanisms => |mechanisms| try std.testing.expect(mechanisms.len <= 64),
    }
}

fn expectScramFirstFailure(
    comptime Db: type,
    db: *Db,
    server_nonce: []const u8,
    raw: []const u8,
    payload_buf: []u8,
    decode_buf: []u8,
    out: []u8,
) !void {
    const Lookup = struct {
        fn lookup(ptr: *anyopaque, username: []const u8) ?sasl.ScramRecord {
            const self: *Db = @ptrCast(@alignCast(ptr));
            if (!std.mem.eql(u8, username, "user")) return null;
            return self.record;
        }
    };

    var dispatcher = sasl.Dispatcher.init(.{ .scram = .{ .ptr = db, .lookupFn = Lookup.lookup } }, server_nonce);
    _ = dispatcher.start(.scram_sha_256);
    const payload = try encodeStandardBase64(raw, payload_buf);
    const decision = try dispatcher.receive(payload, decode_buf, out);
    try std.testing.expectEqual(sasl.Numeric.ERR_SASLFAIL, decision.failure);
}

fn encodeStandardBase64(src: []const u8, out: []u8) ![]const u8 {
    const size = std.base64.standard.Encoder.calcSize(src.len);
    if (size > out.len) return error.NoSpaceLeft;
    return std.base64.standard.Encoder.encode(out[0..size], src);
}

fn decodeStandardBase64(src: []const u8, out: []u8) ![]const u8 {
    const size = try std.base64.standard.Decoder.calcSizeForSlice(src);
    if (size > out.len) return error.NoSpaceLeft;
    try std.base64.standard.Decoder.decode(out[0..size], src);
    return out[0..size];
}

fn makeClientFinal(
    password: []const u8,
    salt: []const u8,
    iterations: u32,
    client_first_bare: []const u8,
    server_first: []const u8,
    gs2_header: []const u8,
    nonce: []const u8,
    corrupt: bool,
    out: []u8,
) ![]const u8 {
    var keys = try sasl.deriveScramKeys(password, salt, iterations);
    var cb_buf: [std.base64.standard.Encoder.calcSize(32)]u8 = undefined;
    const cb = try encodeStandardBase64(gs2_header, &cb_buf);
    var without_proof_buf: [sasl.MAX_SCRAM_MESSAGE]u8 = undefined;
    const without_proof = try std.fmt.bufPrint(&without_proof_buf, "c={s},r={s}", .{ cb, nonce });
    var auth_message_buf: [sasl.MAX_SCRAM_MESSAGE * 3]u8 = undefined;
    const auth_message = try std.fmt.bufPrint(&auth_message_buf, "{s},{s},{s}", .{ client_first_bare, server_first, without_proof });
    const sig = hmacSha256(&keys.stored_key, auth_message);
    var proof = keys.client_key;
    for (&proof, sig) |*p, s| p.* ^= s;
    if (corrupt) proof[0] ^= 0x01;
    var proof_b64_buf: [std.base64.standard.Encoder.calcSize(32)]u8 = undefined;
    const proof_b64 = try encodeStandardBase64(&proof, &proof_b64_buf);
    var final_buf: [sasl.MAX_SCRAM_MESSAGE]u8 = undefined;
    const final = try std.fmt.bufPrint(&final_buf, "{s},p={s}", .{ without_proof, proof_b64 });
    keys.wipe();
    return encodeStandardBase64(final, out);
}

fn hmacSha256(key: []const u8, msg: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256).create(&out, msg, key);
    return out;
}
