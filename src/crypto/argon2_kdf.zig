//! mizuchi-crypto — Argon2id password hashing for account credentials.
//!
//! This is the modern upgrade path away from PBKDF2 for storing account
//! passwords. Argon2id is a memory-hard KDF (winner of the Password Hashing
//! Competition) that resists both GPU/ASIC brute-forcing (the data-dependent
//! Argon2d half) and side-channel cache-timing attacks (the data-independent
//! Argon2i half). It is the OWASP-recommended default for password storage.
//!
//! Hashes are emitted in the standard PHC string format, e.g.
//!   $argon2id$v=19$m=65536,t=2,p=1$<b64-salt>$<b64-hash>
//! which is self-describing: the salt and all cost parameters travel with the
//! hash, so `verify` needs only the stored string and the candidate password.
//!
//! The salt is generated internally via the OS CSPRNG by the std
//! implementation, so callers never manage salts directly.
//!
//! Usage:
//!   const phc = try argon2_kdf.hash(allocator, "hunter2", argon2_kdf.default_params);
//!   defer allocator.free(phc);
//!   const ok = try argon2_kdf.verify(allocator, "hunter2", phc); // true

const std = @import("std");
const pwhash = std.crypto.pwhash;
const argon2 = pwhash.argon2;

/// PHC-format parameters for Argon2id.
///   t — time cost (iterations)
///   m — memory cost in KiB
///   p — parallelism (lanes)
pub const Params = argon2.Params;

/// Sensible interactive-login defaults: t=2 iterations, m=64 MiB, p=1.
///
/// 64 MiB (m = 65536 KiB) keeps per-attempt cost high enough to be painful for
/// an offline attacker while staying comfortable for a login path. For
/// background/offline hashing you can raise `m` and `t`.
pub const default_params: Params = .{ .t = 2, .m = 64 * 1024, .p = 1 };

/// Maximum length of a PHC-format Argon2id string we will emit. Real strings
/// are well under 100 bytes; 128 gives generous headroom for the b64 salt and
/// hash plus the parameter prefix.
const max_phc_len = 128;

/// `pwhash.Error` already includes `Allocator.Error` (via its KdfError member),
/// so it covers the internal `dupe` allocation as well as the KDF itself.
pub const HashError = pwhash.Error;
pub const VerifyError = pwhash.Error;

/// One process-wide threaded I/O instance is required by the std argon2 API
/// (it dispatches the memory-fill passes across lanes). We build it lazily on
/// first use with a failing allocator: for our parameters (p small, no async
/// fan-out needed beyond what the pool already provides) the threaded backend
/// runs the work synchronously and never needs to allocate from `gpa`.
var io_instance: std.Io.Threaded = undefined;
var io_ready = std.atomic.Value(bool).init(false);
var io_init_lock: std.Io.Mutex = .init;

fn getIo() std.Io {
    if (!io_ready.load(.acquire)) {
        // Lock-free CAS guard: only one initializer wins; latecomers spin
        // until the winner publishes `io_ready`. Initialization is a one-time
        // event on a cold path, so a brief spin is acceptable.
        if (io_init_lock.tryLock()) {
            if (!io_ready.load(.acquire)) {
                io_instance = std.Io.Threaded.init(std.heap.smp_allocator, .{});
                io_ready.store(true, .release);
            }
        } else {
            while (!io_ready.load(.acquire)) std.atomic.spinLoopHint();
        }
    }
    return io_instance.io();
}

/// Hash `password` with Argon2id using `params`, returning an owned PHC string.
///
/// The returned slice is allocated with `allocator`; the caller must free it.
/// A random salt is generated internally, so two calls with the same password
/// produce different strings.
pub fn hash(allocator: std.mem.Allocator, password: []const u8, params: Params) HashError![]u8 {
    const io = getIo();
    var buf: [max_phc_len]u8 = undefined;
    const phc = try argon2.strHash(
        password,
        .{ .allocator = allocator, .params = params, .mode = .argon2id },
        &buf,
        io,
    );
    // `phc` points into the stack buffer; hand back an owned copy.
    return allocator.dupe(u8, phc);
}

/// Verify `password` against a stored PHC-format Argon2 string.
///
/// Returns `true` on a match, `false` on a mismatch. Malformed PHC strings or
/// unsupported encodings surface as an error rather than a silent `false`, so
/// corrupted storage is never mistaken for a wrong password.
pub fn verify(allocator: std.mem.Allocator, password: []const u8, phc: []const u8) VerifyError!bool {
    const io = getIo();
    argon2.strVerify(phc, password, .{ .allocator = allocator }, io) catch |err| switch (err) {
        error.PasswordVerificationFailed => return false,
        else => return err,
    };
    return true;
}

// ---------------------------------------------------------------------------
// Tests — use TINY memory/time parameters so the suite stays fast. These are
// NOT acceptable for production; production callers use `default_params`.
// ---------------------------------------------------------------------------

const test_params: Params = .{ .t = 1, .m = 64, .p = 1 };

test "hash then verify succeeds for correct password" {
    const allocator = std.testing.allocator;
    const password = "correct horse battery staple";

    const phc = try hash(allocator, password, test_params);
    defer allocator.free(phc);

    try std.testing.expect(std.mem.startsWith(u8, phc, "$argon2id$"));
    try std.testing.expect(try verify(allocator, password, phc));
}

test "verify fails for wrong password" {
    const allocator = std.testing.allocator;

    const phc = try hash(allocator, "the-real-secret", test_params);
    defer allocator.free(phc);

    try std.testing.expect(!try verify(allocator, "not-the-secret", phc));
}

test "verify fails for empty candidate against non-empty password" {
    const allocator = std.testing.allocator;

    const phc = try hash(allocator, "nonempty", test_params);
    defer allocator.free(phc);

    try std.testing.expect(!try verify(allocator, "", phc));
}

test "distinct salts produce distinct hashes for same password" {
    const allocator = std.testing.allocator;
    const password = "same-input";

    const phc1 = try hash(allocator, password, test_params);
    defer allocator.free(phc1);
    const phc2 = try hash(allocator, password, test_params);
    defer allocator.free(phc2);

    // Different random salts => different PHC strings, yet both verify.
    try std.testing.expect(!std.mem.eql(u8, phc1, phc2));
    try std.testing.expect(try verify(allocator, password, phc1));
    try std.testing.expect(try verify(allocator, password, phc2));
}

test "empty password round-trips" {
    const allocator = std.testing.allocator;

    const phc = try hash(allocator, "", test_params);
    defer allocator.free(phc);

    try std.testing.expect(try verify(allocator, "", phc));
    try std.testing.expect(!try verify(allocator, "x", phc));
}
