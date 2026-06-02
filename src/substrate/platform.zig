//! Cross-platform OS primitives (CROSS-PLATFORM MANDATE, docs/dev/zig016-notes.md).
//!
//! Every OS-specific syscall the portable parts of the daemon need is funneled
//! through this one comptime `switch (builtin.os.tag)`, so the rest of the tree
//! never reaches for `std.os.linux.*` directly. Linux uses raw syscalls (no
//! libc); macOS/BSD use libc (`getentropy`, libc `clock_gettime`, `getpid`);
//! Windows uses ntdll/advapi32 externs. Linux-only fast paths (io_uring) live
//! elsewhere and are comptime-gated at their own use sites — never here.
const std = @import("std");
const builtin = @import("builtin");

const os_tag = builtin.os.tag;

/// Raised when the OS entropy source is unavailable or returns short.
pub const EntropyError = error{RandomSourceFailed};

// Windows system RNG (RtlGenRandom). std has no public wrapper, so declare the
// stable advapi32 alias ourselves. Returns 0 (FALSE) on failure.
extern "advapi32" fn SystemFunction036(buffer: [*]u8, length: u32) callconv(.winapi) u8;

/// Monotonic clock in milliseconds. Never wall-clock; safe for intervals and
/// timeouts across suspend. Sourced per-target so no `std.os.linux` leaks into
/// non-Linux builds.
pub fn monotonicMillis() i64 {
    switch (os_tag) {
        .linux => {
            var ts: std.os.linux.timespec = undefined;
            _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
            return tsToMillis(@intCast(ts.sec), @intCast(ts.nsec));
        },
        .windows => {
            var freq: i64 = 0;
            var cnt: i64 = 0;
            _ = std.os.windows.ntdll.RtlQueryPerformanceFrequency(&freq);
            _ = std.os.windows.ntdll.RtlQueryPerformanceCounter(&cnt);
            if (freq == 0) return 0;
            return @intCast(@divTrunc(@as(i128, cnt) * 1000, @as(i128, freq)));
        },
        else => {
            // macOS / *BSD via libc.
            var ts: std.c.timespec = undefined;
            _ = std.c.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
            return tsToMillis(@intCast(ts.sec), @intCast(ts.nsec));
        },
    }
}

fn tsToMillis(sec: i64, nsec: i64) i64 {
    return sec * 1000 + @divTrunc(nsec, 1_000_000);
}

/// Process id, used for fork/snapshot detection in the RNG layer. Returns the
/// real pid on POSIX and the process id on Windows (where fork() does not
/// exist, so the value simply stays stable for the process lifetime).
pub fn currentPid() i32 {
    return switch (os_tag) {
        .linux => @intCast(std.os.linux.getpid()),
        // DWORD (u32) -> i32: @bitCast so a high pid can't trip the safe-build
        // @intCast overflow check (fork detection is moot on Windows anyway).
        .windows => @bitCast(std.os.windows.GetCurrentProcessId()),
        else => @intCast(std.c.getpid()),
    };
}

/// Fill `buf` from the OS CSPRNG. This is the slow root entropy source; hot
/// callers keep a per-instance DRBG and reseed from this.
pub fn fillOsEntropy(buf: []u8) EntropyError!void {
    switch (os_tag) {
        .linux => {
            var filled: usize = 0;
            while (filled < buf.len) {
                const rc = std.os.linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
                switch (std.os.linux.errno(rc)) {
                    .SUCCESS => {
                        if (rc == 0) return EntropyError.RandomSourceFailed;
                        filled += rc;
                    },
                    .INTR => continue,
                    else => return EntropyError.RandomSourceFailed,
                }
            }
        },
        .windows => {
            var filled: usize = 0;
            while (filled < buf.len) {
                const want: u32 = @intCast(@min(buf.len - filled, @as(usize, std.math.maxInt(u32))));
                if (SystemFunction036(buf.ptr + filled, want) == 0) return EntropyError.RandomSourceFailed;
                filled += want;
            }
        },
        else => {
            // macOS / *BSD: arc4random_buf is the std-public CSPRNG (std.c
            // exposes it for these targets, unlike getentropy which is `{}`).
            // It always fills the whole buffer and cannot fail.
            std.c.arc4random_buf(buf.ptr, buf.len);
        },
    }
}

test "monotonic clock is non-negative and non-decreasing" {
    const a = monotonicMillis();
    const b = monotonicMillis();
    try std.testing.expect(a >= 0);
    try std.testing.expect(b >= a);
}

test "currentPid is stable within a process" {
    try std.testing.expectEqual(currentPid(), currentPid());
}

test "fillOsEntropy yields non-zero bytes" {
    var buf: [48]u8 = [_]u8{0} ** 48;
    try fillOsEntropy(&buf);
    var any: bool = false;
    for (buf) |x| any = any or x != 0;
    try std.testing.expect(any);
}
