// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operational daemon logging. One line: route boot/runtime notices to stderr in
//! a real daemon, but stay SILENT under `zig test`.
//!
//! Why silent in tests: zig 0.16's `--listen=-` test runner reads the test
//! binary's stderr, and ANY stderr output from a test (even a single line) makes
//! `zig build test` print a spurious "failed command" — the step and the whole
//! build still succeed (verified: `--summary all` reports success, every test
//! passes, the process exits 0), but the noise is misleading. Daemon code that
//! booted real servers in threaded tests flooded stderr with these notices, so
//! the default test run always showed it. Suppressing operational logs in test
//! builds keeps the output clean without changing production behaviour.

const std = @import("std");
const builtin = @import("builtin");

/// Print an operational log line to stderr, or nothing when running under a test
/// binary. Same signature as `std.debug.print`.
pub fn log(comptime fmt: []const u8, args: anytype) void {
    if (builtin.is_test) return;
    std.debug.print(fmt, args);
}
