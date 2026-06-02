//! Bridge: expose the in-process account `Services` as a SASL PLAIN verifier.
//!
//! The dispatch SASL handler (`dispatch.zig`) takes an injected
//! `sasl.PlainChecker`; this adapts the account store to that interface so the
//! live server can authenticate PLAIN credentials against registered accounts.
//! Verification delegates to `Services.identifyAccount`, which runs PBKDF2 + a
//! constant-time hash compare and a dummy PBKDF2 on missing accounts (no
//! username-enumeration timing oracle — see services.zig).
const std = @import("std");
const sasl = @import("../proto/sasl.zig");
const services_mod = @import("services.zig");
const Services = services_mod.Services;

/// Adapter holding a `*Services`. Hand `checker()` to `ClientSession.sasl_plain`
/// (typically via `server.Config.sasl_checker`) so AUTHENTICATE PLAIN verifies
/// against the account store.
///
/// LIFETIME: each connection copies the returned fat pointer, so this
/// `ServicesPlainChecker` (and the `Services` + `MizuStore` it points at) MUST
/// outlive every connection — own it in the same scope as the `Server`, never a
/// stack temporary.
pub const ServicesPlainChecker = struct {
    services: *Services,

    pub fn checker(self: *ServicesPlainChecker) sasl.PlainChecker {
        return .{ .ptr = self, .verifyFn = verify };
    }

    fn verify(ptr: *anyopaque, creds: sasl.PlainCredentials) bool {
        const self: *ServicesPlainChecker = @ptrCast(@alignCast(ptr));
        // Defense-in-depth: refuse empty credentials at the adapter boundary so
        // the guarantee is local here, not an emergent property of the account
        // password policy downstream.
        if (creds.authcid.len == 0 or creds.password.len == 0) return false;
        // Identity assumption (logging in as an account other than authcid) is
        // not supported: a non-empty authzid must equal authcid.
        if (creds.authzid.len != 0 and !std.mem.eql(u8, creds.authzid, creds.authcid)) return false;
        const result = self.services.identifyAccount(creds.authcid, creds.password) catch return false;
        return switch (result) {
            .identified => true,
            else => false,
        };
    }
};

test "services-backed PLAIN checker verifies registered accounts" {
    const MizuStore = services_mod.MizuStore;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try MizuStore.open(std.testing.allocator, std.testing.io, tmp.dir, "sasl-bridge.wal");
    defer store.deinit();

    var services = Services.init(&store, null);
    var scratch: [768]u8 = undefined;
    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);

    var bridge = ServicesPlainChecker{ .services = &services };
    const chk = bridge.checker();

    // Correct credentials authenticate.
    try std.testing.expect(chk.verify(.{ .authzid = "", .authcid = "alice", .password = "correct horse battery staple" }));
    // Wrong password is rejected.
    try std.testing.expect(!chk.verify(.{ .authzid = "", .authcid = "alice", .password = "wrong" }));
    // Unknown account is rejected (and runs a dummy PBKDF2 internally).
    try std.testing.expect(!chk.verify(.{ .authzid = "", .authcid = "nobody", .password = "whatever" }));
    // Identity assumption (authzid != authcid) is refused.
    try std.testing.expect(!chk.verify(.{ .authzid = "bob", .authcid = "alice", .password = "correct horse battery staple" }));
}
