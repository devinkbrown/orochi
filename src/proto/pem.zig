//! Pure PEM codec (RFC 7468) for loading TLS certificates and keys from text.
//!
//! This module performs no I/O of any kind: the caller supplies the PEM text and
//! the output buffers. It locates textual encapsulation boundaries
//! (`-----BEGIN <label>-----` / `-----END <label>-----`), base64-decodes the body
//! into caller storage, and can wrap raw DER back into a PEM block.
//!
//! Whitespace (spaces, tabs, CR, LF) between and within base64 lines is ignored
//! during decode, so both CRLF and LF line endings are tolerated.

const std = @import("std");

/// Errors produced by the PEM codec. All decode/encode failures map here so
/// callers never have to reason about raw base64 error sets.
pub const Error = error{
    /// No `-----BEGIN <label>-----` line was found for the requested label.
    BeginNotFound,
    /// A BEGIN line was found but the matching `-----END <label>-----` was not.
    EndNotFound,
    /// The base64 body contained characters outside the standard alphabet.
    InvalidBase64,
    /// The destination buffer was too small for the decoded/encoded result.
    NoSpaceLeft,
};

/// Standard PEM textual boundaries (RFC 7468 section 2).
const begin_prefix = "-----BEGIN ";
const begin_suffix = "-----";
const end_prefix = "-----END ";
const end_suffix = "-----";

/// Base64 characters that may appear as separators between/within body lines.
const ws_ignore = " \t\r\n";

/// Maximum base64 characters per line on encode (RFC 7468: 64).
const wrap_width = 64;

/// Result of decoding the first PEM block of any label.
pub const FirstBlock = struct {
    /// The label text captured from the BEGIN line (slice into `text`).
    label: []const u8,
    /// The decoded DER bytes (slice into the caller-provided `out` buffer).
    der: []const u8,
};

/// Locate the `-----BEGIN <label>-----` boundary for `label` in `text`, returning
/// the index just past the BEGIN line's trailing `-----` (start of the body).
fn findBegin(text: []const u8, label: []const u8) ?usize {
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, text, search_from, begin_prefix)) |pos| {
        const after_prefix = pos + begin_prefix.len;
        if (after_prefix + label.len + begin_suffix.len <= text.len and
            std.mem.eql(u8, text[after_prefix .. after_prefix + label.len], label) and
            std.mem.eql(u8, text[after_prefix + label.len .. after_prefix + label.len + begin_suffix.len], begin_suffix))
        {
            return after_prefix + label.len + begin_suffix.len;
        }
        search_from = after_prefix;
    }
    return null;
}

/// Decode the base64 body bounded by the BEGIN of `label` and its matching END.
/// `body_start` is the index returned by `findBegin`.
fn decodeBody(text: []const u8, label: []const u8, body_start: usize, out: []u8) Error![]const u8 {
    // Build the exact END line we require, e.g. "-----END CERTIFICATE-----".
    var end_buf: [end_prefix.len + 64 + end_suffix.len]u8 = undefined;
    if (end_prefix.len + label.len + end_suffix.len > end_buf.len) return Error.EndNotFound;
    @memcpy(end_buf[0..end_prefix.len], end_prefix);
    @memcpy(end_buf[end_prefix.len .. end_prefix.len + label.len], label);
    @memcpy(end_buf[end_prefix.len + label.len .. end_prefix.len + label.len + end_suffix.len], end_suffix);
    const end_marker = end_buf[0 .. end_prefix.len + label.len + end_suffix.len];

    const rel_end = std.mem.indexOf(u8, text[body_start..], end_marker) orelse return Error.EndNotFound;
    const body = text[body_start .. body_start + rel_end];

    const decoder = std.base64.standard.decoderWithIgnore(ws_ignore);
    if (decoder.calcSizeUpperBound(body.len) > out.len) return Error.NoSpaceLeft;
    const written = decoder.decode(out, body) catch |err| switch (err) {
        error.InvalidCharacter, error.InvalidPadding => return Error.InvalidBase64,
        error.NoSpaceLeft => return Error.NoSpaceLeft,
    };
    return out[0..written];
}

/// Decode the PEM block identified by `label` into `out`, returning the DER bytes.
///
/// Searches `text` for `-----BEGIN <label>-----` followed by a matching END line,
/// base64-decoding everything in between. Whitespace between base64 lines (CRLF
/// or LF) is ignored. Returns a slice into `out`.
pub fn decode(text: []const u8, label: []const u8, out: []u8) Error![]const u8 {
    const body_start = findBegin(text, label) orelse return Error.BeginNotFound;
    return decodeBody(text, label, body_start, out);
}

/// Decode the first PEM block of any label found in `text` into `out`.
///
/// Returns the captured label (slice into `text`) and the decoded DER bytes
/// (slice into `out`).
pub fn decodeFirst(text: []const u8, out: []u8) Error!FirstBlock {
    const pos = std.mem.indexOf(u8, text, begin_prefix) orelse return Error.BeginNotFound;
    const label_start = pos + begin_prefix.len;
    const rel_suffix = std.mem.indexOf(u8, text[label_start..], begin_suffix) orelse return Error.BeginNotFound;
    const label = text[label_start .. label_start + rel_suffix];
    const body_start = label_start + rel_suffix + begin_suffix.len;
    const der = try decodeBody(text, label, body_start, out);
    return .{ .label = label, .der = der };
}

/// Compute the exact byte length `encode` will write for a block wrapping
/// `der_len` DER bytes under `label`.
pub fn encodedLen(label: []const u8, der_len: usize) usize {
    const b64_len = std.base64.standard.Encoder.calcSize(der_len);
    const line_count = if (b64_len == 0) 0 else (b64_len + wrap_width - 1) / wrap_width;
    // BEGIN line + body lines (each + "\n") + END line + "\n".
    const begin_line = begin_prefix.len + label.len + begin_suffix.len + 1;
    const end_line = end_prefix.len + label.len + end_suffix.len + 1;
    return begin_line + b64_len + line_count + end_line;
}

/// Encode `der` as a PEM block under `label` into `out`, with 64-char base64 line
/// wrapping. Returns the written slice (which always ends in a trailing newline).
pub fn encode(out: []u8, label: []const u8, der: []const u8) Error![]const u8 {
    const total = encodedLen(label, der.len);
    if (total > out.len) return Error.NoSpaceLeft;

    var idx: usize = 0;
    const writeStr = struct {
        fn run(dst: []u8, at: *usize, s: []const u8) void {
            @memcpy(dst[at.* .. at.* + s.len], s);
            at.* += s.len;
        }
    }.run;

    writeStr(out, &idx, begin_prefix);
    writeStr(out, &idx, label);
    writeStr(out, &idx, begin_suffix);
    writeStr(out, &idx, "\n");

    // Encode the full body into the tail of the buffer, then re-emit with wraps.
    const b64_len = std.base64.standard.Encoder.calcSize(der.len);
    var scratch_buf: [4 * ((1 << 16) / 3 + 1)]u8 = undefined;
    if (b64_len > scratch_buf.len) return Error.NoSpaceLeft;
    const b64 = std.base64.standard.Encoder.encode(scratch_buf[0..b64_len], der);

    var off: usize = 0;
    while (off < b64.len) {
        const remaining = b64.len - off;
        const take = if (remaining < wrap_width) remaining else wrap_width;
        writeStr(out, &idx, b64[off .. off + take]);
        writeStr(out, &idx, "\n");
        off += take;
    }

    writeStr(out, &idx, end_prefix);
    writeStr(out, &idx, label);
    writeStr(out, &idx, end_suffix);
    writeStr(out, &idx, "\n");

    return out[0..idx];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "encode then decode round-trips DER bytes" {
    // Arrange
    const der = [_]u8{ 0x30, 0x82, 0x01, 0x0a, 0xde, 0xad, 0xbe, 0xef, 0x00, 0xff, 0x42 };
    var pem_buf: [256]u8 = undefined;
    var der_buf: [64]u8 = undefined;

    // Act
    const pem = try encode(&pem_buf, "CERTIFICATE", &der);
    const decoded = try decode(pem, "CERTIFICATE", &der_buf);

    // Assert
    try std.testing.expectEqualSlices(u8, &der, decoded);
}

test "decode parses a realistic CERTIFICATE block" {
    // Arrange: body is base64 of the 4 bytes {0xDE,0xAD,0xBE,0xEF} = "3q2+7w==".
    const text =
        \\-----BEGIN CERTIFICATE-----
        \\3q2+7w==
        \\-----END CERTIFICATE-----
        \\
    ;
    var out: [16]u8 = undefined;

    // Act
    const der = try decode(text, "CERTIFICATE", &out);

    // Assert
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, der);
}

test "decode tolerates CRLF line endings and inner whitespace" {
    // Arrange: same payload split across two CRLF-terminated body lines.
    const text = "-----BEGIN PRIVATE KEY-----\r\n3q2+\r\n7w==\r\n-----END PRIVATE KEY-----\r\n";
    var out: [16]u8 = undefined;

    // Act
    const der = try decode(text, "PRIVATE KEY", &out);

    // Assert
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, der);
}

test "decode returns BeginNotFound when label is absent" {
    // Arrange
    const text =
        \\-----BEGIN CERTIFICATE-----
        \\3q2+7w==
        \\-----END CERTIFICATE-----
    ;
    var out: [16]u8 = undefined;

    // Act + Assert: a different label must not match.
    try std.testing.expectError(Error.BeginNotFound, decode(text, "PRIVATE KEY", &out));
}

test "decode returns EndNotFound when terminator is missing" {
    // Arrange
    const text = "-----BEGIN CERTIFICATE-----\n3q2+7w==\n";
    var out: [16]u8 = undefined;

    // Act + Assert
    try std.testing.expectError(Error.EndNotFound, decode(text, "CERTIFICATE", &out));
}

test "decode rejects invalid base64 body" {
    // Arrange
    const text = "-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n";
    var out: [16]u8 = undefined;

    // Act + Assert
    try std.testing.expectError(Error.InvalidBase64, decode(text, "CERTIFICATE", &out));
}

test "decode returns NoSpaceLeft when output buffer is too small" {
    // Arrange
    const text = "-----BEGIN CERTIFICATE-----\n3q2+7w==\n-----END CERTIFICATE-----\n";
    var out: [2]u8 = undefined;

    // Act + Assert: payload is 4 bytes, buffer holds 2.
    try std.testing.expectError(Error.NoSpaceLeft, decode(text, "CERTIFICATE", &out));
}

test "decodeFirst captures label and DER of the first block" {
    // Arrange
    const text =
        \\preamble noise
        \\-----BEGIN EC PRIVATE KEY-----
        \\3q2+7w==
        \\-----END EC PRIVATE KEY-----
        \\-----BEGIN CERTIFICATE-----
        \\AAAA
        \\-----END CERTIFICATE-----
    ;
    var out: [16]u8 = undefined;

    // Act
    const block = try decodeFirst(text, &out);

    // Assert
    try std.testing.expectEqualStrings("EC PRIVATE KEY", block.label);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, block.der);
}

test "encode wraps base64 at 64 characters per line" {
    // Arrange: 48 DER bytes -> 64 base64 chars (one full line), plus more to force a wrap.
    var der: [60]u8 = undefined;
    for (&der, 0..) |*b, i| b.* = @intCast(i & 0xff);
    var pem_buf: [512]u8 = undefined;

    // Act
    const pem = try encode(&pem_buf, "CERTIFICATE", &der);

    // Assert: every base64 body line is at most 64 chars; at least one is exactly 64.
    var lines = std.mem.splitScalar(u8, pem, '\n');
    var saw_full_line = false;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "-----")) continue;
        try std.testing.expect(line.len <= wrap_width);
        if (line.len == wrap_width) saw_full_line = true;
    }
    try std.testing.expect(saw_full_line);
}

test "encodedLen matches the actual encoded length" {
    // Arrange
    const der = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    var pem_buf: [256]u8 = undefined;

    // Act
    const pem = try encode(&pem_buf, "CERTIFICATE", &der);

    // Assert
    try std.testing.expectEqual(encodedLen("CERTIFICATE", der.len), pem.len);
}

test "encode then decodeFirst round-trips with an arbitrary label" {
    // Arrange
    const der = [_]u8{ 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34 };
    var pem_buf: [256]u8 = undefined;
    var der_buf: [64]u8 = undefined;

    // Act
    const pem = try encode(&pem_buf, "RSA PRIVATE KEY", &der);
    const block = try decodeFirst(pem, &der_buf);

    // Assert
    try std.testing.expectEqualStrings("RSA PRIVATE KEY", block.label);
    try std.testing.expectEqualSlices(u8, &der, block.der);
}
