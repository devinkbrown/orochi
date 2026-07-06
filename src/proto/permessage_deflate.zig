// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! WebSocket permessage-deflate (RFC 7692) framing helper.
//!
//! permessage-deflate lets WebSocket peers DEFLATE-compress message payloads.
//! The wire trick defined by RFC 7692 section 7.2.1 is:
//!
//!   * To compress: raw-DEFLATE the message, then strip the trailing four
//!     octets `0x00 0x00 0xff 0xff` (the empty stored block / "sync flush"
//!     marker that a DEFLATE flush emits at the end of the stream).
//!   * To decompress: append those same four octets `0x00 0x00 0xff 0xff`
//!     back onto the received payload, then raw-INFLATE.
//!
//! The four-octet tail is the BFINAL=0 empty stored block followed by the
//! deflate sync-flush marker; removing/re-adding it keeps the compressed
//! frame as small as possible while still forming a valid DEFLATE stream.
//!
//! This module wraps `std.compress.flate` (Zig 0.16) configured with the
//! `.raw` container (no zlib/gzip header or footer) so the output is the bare
//! DEFLATE bitstream that RFC 7692 expects.
//!
//! Limitation: Zig 0.16's `flate.Compress` does not expose an explicit
//! `Z_SYNC_FLUSH` that reliably emits a trailing `00 00 ff ff` marker; its
//! `finish` ends the stream with a BFINAL=1 block, and its `flush` byte-aligns
//! with fixed/stored padding rather than a guaranteed sync marker. We therefore
//! call `finish` and strip the sync marker only when it happens to be present.
//! This is still interoperable: `decompressMessage` always re-appends
//! `00 00 ff ff`, and a conforming inflater stops at the BFINAL block, so the
//! re-appended marker is harmless. Peers that strictly require the BFINAL=0 +
//! sync-flush framing on the *send* side would need an explicit sync-flush API
//! that this stdlib release does not provide.
//!
//! Only the simplest negotiation is handled: it recognises a
//! `permessage-deflate` offer and responds with a header value that does not
//! request context takeover (`server_no_context_takeover;
//! client_no_context_takeover`), which is always safe because each call here
//! compresses/decompresses a single message with a fresh window.

const std = @import("std");
const flate = std.compress.flate;
const testing = std.testing;

/// The DEFLATE sync-flush / empty-stored-block tail that RFC 7692 strips on
/// compression and re-appends before decompression.
pub const tail = [4]u8{ 0x00, 0x00, 0xff, 0xff };

/// The extension token this helper negotiates.
pub const extension_token = "permessage-deflate";

/// Server response header value advertised when an offer is accepted.
/// We decline context takeover in both directions so every message is an
/// independent DEFLATE stream, matching how `compressMessage` operates.
pub const response_value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover";

/// Conservative fallback when a caller has not supplied its negotiated message
/// cap. Call `decompressMessageBounded` with the connection's actual limit when
/// one is available.
pub const default_max_decompressed_message_bytes: usize = 16 * 1024 * 1024;

/// Parse a client `Sec-WebSocket-Extensions` offer and, if it contains a
/// `permessage-deflate` extension, return the server response header value.
///
/// `offer_extensions` is the raw value of the client's
/// `Sec-WebSocket-Extensions` header (it may list several comma-separated
/// extensions, each with semicolon-separated parameters). Returns `null` when
/// permessage-deflate is not offered.
pub fn negotiateResponse(offer_extensions: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, offer_extensions, ',');
    while (it.next()) |raw_ext| {
        // The first semicolon-delimited token is the extension name.
        var params = std.mem.splitScalar(u8, raw_ext, ';');
        const name = std.mem.trim(u8, params.next() orelse continue, " \t");
        if (std.ascii.eqlIgnoreCase(name, extension_token)) {
            return response_value;
        }
    }
    return null;
}

/// Raw-DEFLATE `payload` and strip the trailing four bytes
/// `0x00 0x00 0xff 0xff` per RFC 7692.
///
/// Caller owns the returned slice and must free it with `allocator`.
pub fn compressMessage(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    // Accumulate the raw DEFLATE output here. `Compress.init` asserts the
    // backing writer already has spare capacity (its bit writer writes
    // directly into the output buffer), so seed it instead of starting empty.
    var out: std.Io.Writer.Allocating = try .initCapacity(allocator, payload.len + 64);
    defer out.deinit();

    // The compressor requires a window buffer of at least `max_window_len`.
    const window = try allocator.alloc(u8, flate.max_window_len);
    defer allocator.free(window);

    var comp = try flate.Compress.init(&out.writer, window, .raw, flate.Compress.Options.level_6);
    try comp.writer.writeAll(payload);
    try comp.finish();

    const raw = out.writer.buffered();

    // RFC 7692: an empty / already-flushed payload may produce only the tail
    // marker (or a marker-terminated stream). Strip the trailing sync marker.
    if (std.mem.endsWith(u8, raw, &tail)) {
        return allocator.dupe(u8, raw[0 .. raw.len - tail.len]);
    }
    return allocator.dupe(u8, raw);
}

/// Append `0x00 0x00 0xff 0xff` to `payload` then raw-INFLATE it, per RFC 7692.
///
/// Caller owns the returned slice and must free it with `allocator`.
pub fn decompressMessage(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    return decompressMessageBounded(allocator, payload, default_max_decompressed_message_bytes);
}

/// Append `0x00 0x00 0xff 0xff` to `payload` then raw-INFLATE it, per RFC 7692.
/// Decompression is capped to the negotiated message limit.
///
/// Caller owns the returned slice and must free it with `allocator`.
pub fn decompressMessageBounded(
    allocator: std.mem.Allocator,
    payload: []const u8,
    max_decompressed_bytes: usize,
) ![]u8 {
    // Rebuild the full DEFLATE stream by re-appending the stripped tail.
    if (payload.len > std.math.maxInt(usize) - tail.len) return error.MessageTooLarge;
    const framed = try allocator.alloc(u8, payload.len + tail.len);
    defer allocator.free(framed);
    @memcpy(framed[0..payload.len], payload);
    @memcpy(framed[payload.len..], &tail);

    var in: std.Io.Reader = .fixed(framed);

    // Decompressor history window.
    const window = try allocator.alloc(u8, flate.max_window_len);
    defer allocator.free(window);

    var decomp = flate.Decompress.init(&in, .raw, window);
    if (max_decompressed_bytes == std.math.maxInt(usize)) {
        return decomp.reader.allocRemaining(allocator, .unlimited);
    }
    const limit = max_decompressed_bytes + 1;
    const decoded = decomp.reader.allocRemaining(allocator, .limited(limit)) catch |err| switch (err) {
        error.StreamTooLong => return error.MessageTooLarge,
        else => |e| return e,
    };
    errdefer allocator.free(decoded);
    if (decoded.len > max_decompressed_bytes) return error.MessageTooLarge;
    return decoded;
}

test "compress then decompress round-trips the original payload" {
    const allocator = testing.allocator;
    const original = &repeatBytes("Hello, permessage-deflate! ", 16);

    const compressed = try compressMessage(allocator, original);
    defer allocator.free(compressed);

    const restored = try decompressMessage(allocator, compressed);
    defer allocator.free(restored);

    try testing.expectEqualSlices(u8, original, restored);
}

test "compression actually shrinks repetitive data" {
    const allocator = testing.allocator;
    const original = &repeatBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 8);

    const compressed = try compressMessage(allocator, original);
    defer allocator.free(compressed);

    try testing.expect(compressed.len < original.len);
}

test "compressed output never ends with the RFC 7692 sync marker" {
    const allocator = testing.allocator;
    const original = "some moderately sized payload that gets deflated";

    const compressed = try compressMessage(allocator, original);
    defer allocator.free(compressed);

    // The tail must have been stripped.
    try testing.expect(!std.mem.endsWith(u8, compressed, &tail));
}

test "decompress re-appends the tail to inflate a marker-stripped stream" {
    const allocator = testing.allocator;

    // Construct a raw-DEFLATE stream that ends with the RFC 7692 sync marker
    // (the canonical on-the-wire receive case), strip the marker as a sending
    // peer would, and confirm decompressMessage recovers it by re-appending.
    const original = "round trip via manual tail handling";

    var out: std.Io.Writer.Allocating = try .initCapacity(allocator, original.len + 64);
    defer out.deinit();
    const window = try allocator.alloc(u8, flate.max_window_len);
    defer allocator.free(window);
    var comp = try flate.Compress.init(&out.writer, window, .raw, flate.Compress.Options.level_6);
    try comp.writer.writeAll(original);
    try comp.finish();

    var raw = out.writer.buffered();
    // Force the marker form so we can exercise the strip/re-append path even
    // though `finish` may not emit it: append the marker if it is not already
    // there, mirroring a sync-flushed sender.
    var marker_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer marker_buf.deinit(allocator);
    if (!std.mem.endsWith(u8, raw, &tail)) {
        try marker_buf.appendSlice(allocator, raw);
        try marker_buf.appendSlice(allocator, &tail);
        raw = marker_buf.items;
    }
    try testing.expect(std.mem.endsWith(u8, raw, &tail));

    const stripped = raw[0 .. raw.len - tail.len];
    const restored = try decompressMessage(allocator, stripped);
    defer allocator.free(restored);
    try testing.expectEqualSlices(u8, original, restored);
}

test "empty payload survives a compress/decompress round trip" {
    const allocator = testing.allocator;

    const compressed = try compressMessage(allocator, "");
    defer allocator.free(compressed);

    const restored = try decompressMessage(allocator, compressed);
    defer allocator.free(restored);

    try testing.expectEqual(@as(usize, 0), restored.len);
}

test "negotiateResponse accepts a bare permessage-deflate offer" {
    const resp = negotiateResponse("permessage-deflate");
    try testing.expect(resp != null);
    try testing.expectEqualStrings(response_value, resp.?);
}

test "negotiateResponse accepts an offer carrying parameters" {
    const resp = negotiateResponse("permessage-deflate; client_max_window_bits");
    try testing.expect(resp != null);
    try testing.expectEqualStrings(response_value, resp.?);
}

test "negotiateResponse picks permessage-deflate from a multi-extension offer" {
    const resp = negotiateResponse("x-webkit-deflate-frame, permessage-deflate; client_max_window_bits");
    try testing.expect(resp != null);
}

test "negotiateResponse is case-insensitive on the extension token" {
    const resp = negotiateResponse("PerMessage-Deflate");
    try testing.expect(resp != null);
}

test "negotiateResponse returns null when the extension is absent" {
    try testing.expectEqual(@as(?[]const u8, null), negotiateResponse("permessage-bzip2"));
    try testing.expectEqual(@as(?[]const u8, null), negotiateResponse(""));
}

fn repeatBytes(comptime s: []const u8, comptime n: usize) [s.len * n]u8 {
    var b: [s.len * n]u8 = undefined;
    for (0..n) |i| @memcpy(b[i * s.len ..][0..s.len], s);
    return b;
}
