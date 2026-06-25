// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.3 transcript-hash accumulator (RFC 8446 §4.4.1) over SHA-256.
//!
//! The handshake transcript is the running hash of every handshake message
//! in order of appearance. TLS needs the *current* transcript hash at several
//! points (after ServerHello, after EncryptedExtensions/Certificate, after
//! Finished, ...) while still appending later messages. A one-shot hash over a
//! concatenated buffer cannot express that, so this module wraps an incremental
//! SHA-256 state and exposes a `current()` snapshot that clones the hasher
//! rather than finalizing it.
//!
//! Pure: SHA-256 only. No sockets, files, clock, or RNG.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Length of a SHA-256 digest in bytes.
pub const digest_len = Sha256.digest_length;

/// Incremental TLS 1.3 transcript-hash accumulator.
///
/// Feed each handshake message via `update` in wire order, then read the
/// running Transcript-Hash with `current()` as often as needed. `current()`
/// never consumes the accumulator, so updates may continue afterwards.
pub const Transcript = struct {
    hasher: Sha256,

    /// Create an empty transcript (no messages fed yet).
    pub fn init() Transcript {
        return .{ .hasher = Sha256.init(.{}) };
    }

    /// Append one handshake message's bytes to the transcript, in order.
    pub fn update(self: *Transcript, bytes: []const u8) void {
        self.hasher.update(bytes);
    }

    /// Return the running Transcript-Hash over all messages fed so far,
    /// WITHOUT consuming the accumulator. Internally clones the SHA-256 state
    /// and finalizes the clone, so the live accumulator can keep updating.
    pub fn current(self: *const Transcript) [digest_len]u8 {
        var clone = self.hasher;
        var out: [digest_len]u8 = undefined;
        clone.final(&out);
        return out;
    }

    /// Convenience: Transcript-Hash over a sequence of messages, equivalent to
    /// hashing their in-order concatenation. Allocation-free.
    pub fn hashOf(messages: []const []const u8) [digest_len]u8 {
        var t = Transcript.init();
        for (messages) |m| t.update(m);
        return t.current();
    }
};

const testing = std.testing;

test "hashOf of messages equals Sha256 of their concatenation" {
    // Arrange
    const a = "ClientHello-bytes";
    const b = "ServerHello-bytes";
    const c = "EncryptedExtensions";
    const messages = [_][]const u8{ a, b, c };

    var direct: [digest_len]u8 = undefined;
    {
        var h = Sha256.init(.{});
        h.update(a);
        h.update(b);
        h.update(c);
        h.final(&direct);
    }

    // Act
    const got = Transcript.hashOf(&messages);

    // Assert
    try testing.expectEqualSlices(u8, &direct, &got);
}

test "incremental update + current() at two points matches hashOf of the prefix" {
    // Arrange
    const m0 = "first handshake message";
    const m1 = "second handshake message";
    const m2 = "third handshake message";

    // Act
    var t = Transcript.init();
    t.update(m0);
    const snap_after_m0 = t.current();
    t.update(m1);
    const snap_after_m1 = t.current();
    t.update(m2);
    const snap_after_m2 = t.current();

    // Assert
    try testing.expectEqualSlices(
        u8,
        &Transcript.hashOf(&[_][]const u8{m0}),
        &snap_after_m0,
    );
    try testing.expectEqualSlices(
        u8,
        &Transcript.hashOf(&[_][]const u8{ m0, m1 }),
        &snap_after_m1,
    );
    try testing.expectEqualSlices(
        u8,
        &Transcript.hashOf(&[_][]const u8{ m0, m1, m2 }),
        &snap_after_m2,
    );
}

test "current() does not disturb later updates" {
    // Arrange — two transcripts fed identical messages, one of which is
    // probed repeatedly with current() between updates.
    const m0 = "alpha";
    const m1 = "beta";
    const m2 = "gamma";

    // Act
    var probed = Transcript.init();
    probed.update(m0);
    _ = probed.current();
    _ = probed.current();
    probed.update(m1);
    _ = probed.current();
    probed.update(m2);
    _ = probed.current();
    const probed_final = probed.current();

    var clean = Transcript.init();
    clean.update(m0);
    clean.update(m1);
    clean.update(m2);
    const clean_final = clean.current();

    // Assert — probing must not have altered the accumulated state.
    try testing.expectEqualSlices(u8, &clean_final, &probed_final);
    try testing.expectEqualSlices(
        u8,
        &Transcript.hashOf(&[_][]const u8{ m0, m1, m2 }),
        &probed_final,
    );
}

test "empty transcript current() equals Sha256 of empty input" {
    // Arrange
    var direct: [digest_len]u8 = undefined;
    Sha256.hash("", &direct, .{});

    // Act
    const t = Transcript.init();
    const got = t.current();
    const conv = Transcript.hashOf(&[_][]const u8{});

    // Assert
    try testing.expectEqualSlices(u8, &direct, &got);
    try testing.expectEqualSlices(u8, &direct, &conv);
}

test "current() is repeatable and idempotent" {
    // Arrange
    var t = Transcript.init();
    t.update("payload one");
    t.update("payload two");

    // Act
    const first = t.current();
    const second = t.current();

    // Assert
    try testing.expectEqualSlices(u8, &first, &second);
}
