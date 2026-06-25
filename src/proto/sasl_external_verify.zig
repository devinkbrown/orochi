// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure SASL EXTERNAL account-to-CERTFP verification.
//!
//! Callers provide the client certificate fingerprint and the account-to-CERTFP
//! map. This module does no I/O and owns no daemon/server state.
const std = @import("std");

const sasl = @import("sasl.zig");
const root = @import("root");
const x509_verify = if (@hasDecl(root, "crypto")) root.crypto.x509_verify else StandaloneX509Verify;

const StandaloneX509Verify = struct {
    pub const digest_len = std.crypto.hash.sha2.Sha256.digest_length;
    pub const Digest = [digest_len]u8;
    pub const Error = error{X509VerifyUnavailable};

    pub fn certfp(_: []const u8) Error!Digest {
        return error.X509VerifyUnavailable;
    }
};

pub const Certfp = x509_verify.Digest;
pub const certfp_len = x509_verify.digest_len;

pub const AccountCertfp = struct {
    account: []const u8,
    certfp: Certfp,
};

pub const Request = struct {
    certfp: Certfp,
    /// The raw SASL EXTERNAL authzid. Empty means "use the certificate
    /// identity", represented here by the account that owns this CERTFP.
    authzid: []const u8 = "",
};

pub fn verify(request: Request, mapping: []const AccountCertfp) sasl.Decision {
    const account = if (request.authzid.len == 0)
        findAccountByCertfp(mapping, &request.certfp)
    else
        findAccountCertfp(mapping, request.authzid, &request.certfp);

    const accepted = account orelse return fail();
    if (accepted.len == 0) return fail();
    return success(accepted, request.authzid);
}

pub fn verifyDer(
    cert_der: []const u8,
    authzid: []const u8,
    mapping: []const AccountCertfp,
) x509_verify.Error!sasl.Decision {
    return verify(.{
        .certfp = try x509_verify.certfp(cert_der),
        .authzid = authzid,
    }, mapping);
}

pub fn certfpEqual(a: *const Certfp, b: *const Certfp) bool {
    return std.crypto.timing_safe.eql(Certfp, a.*, b.*);
}

fn findAccountCertfp(
    mapping: []const AccountCertfp,
    account: []const u8,
    certfp: *const Certfp,
) ?[]const u8 {
    var found: ?[]const u8 = null;
    var ok = false;

    for (mapping) |entry| {
        if (!std.mem.eql(u8, entry.account, account)) continue;
        found = entry.account;
        ok = ok or certfpEqual(&entry.certfp, certfp);
    }

    return if (ok) found else null;
}

fn findAccountByCertfp(mapping: []const AccountCertfp, certfp: *const Certfp) ?[]const u8 {
    var found: ?[]const u8 = null;

    for (mapping) |entry| {
        const matches = certfpEqual(&entry.certfp, certfp);
        if (matches and found == null) found = entry.account;
    }

    return found;
}

fn success(account: []const u8, authzid: []const u8) sasl.Decision {
    return .{ .success = .{
        .identity = .{
            .authcid = account,
            .authzid = if (authzid.len == 0) null else authzid,
        },
    } };
}

fn fail() sasl.Decision {
    return .{ .failure = .ERR_SASLFAIL };
}

fn digest(comptime seed: []const u8) Certfp {
    var out: Certfp = undefined;
    std.crypto.hash.sha2.Sha256.hash(seed, &out, .{});
    return out;
}

fn expectSuccess(decision: sasl.Decision, account: []const u8, authzid: ?[]const u8) !void {
    try std.testing.expectEqual(sasl.Numeric.RPL_SASLSUCCESS, decision.success.complete);
    try std.testing.expectEqualStrings(account, decision.success.identity.authcid);
    if (authzid) |value| {
        try std.testing.expect(decision.success.identity.authzid != null);
        try std.testing.expectEqualStrings(value, decision.success.identity.authzid.?);
    } else {
        try std.testing.expect(decision.success.identity.authzid == null);
    }
}

test "EXTERNAL accept with matching certfp" {
    const allocator = std.testing.allocator;
    const fp = digest("alice certificate");
    const entries = try allocator.alloc(AccountCertfp, 1);
    defer allocator.free(entries);
    entries[0] = .{ .account = "alice", .certfp = fp };

    const decision = verify(.{ .certfp = fp, .authzid = "alice" }, entries);
    try expectSuccess(decision, "alice", "alice");
}

test "EXTERNAL reject mismatch with timing-safe certfp compare" {
    const allocator = std.testing.allocator;
    const allowed = digest("allowed certificate");
    const presented = digest("presented certificate");
    const entries = try allocator.alloc(AccountCertfp, 1);
    defer allocator.free(entries);
    entries[0] = .{ .account = "alice", .certfp = allowed };

    try std.testing.expect(!certfpEqual(&allowed, &presented));
    const decision = verify(.{ .certfp = presented, .authzid = "alice" }, entries);
    try std.testing.expectEqual(sasl.Numeric.ERR_SASLFAIL, decision.failure);
}

test "empty authzid uses cert identity" {
    const allocator = std.testing.allocator;
    const alice_fp = digest("alice certificate");
    const bob_fp = digest("bob certificate");
    const entries = try allocator.alloc(AccountCertfp, 2);
    defer allocator.free(entries);
    entries[0] = .{ .account = "alice", .certfp = alice_fp };
    entries[1] = .{ .account = "bob", .certfp = bob_fp };

    const decision = verify(.{ .certfp = bob_fp, .authzid = "" }, entries);
    try expectSuccess(decision, "bob", null);
}

test {
    std.testing.refAllDecls(@This());
}
