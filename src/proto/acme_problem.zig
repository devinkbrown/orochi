//! ACME / RFC 7807 "problem document" parsing and error classification.
//!
//! ACME servers report failures as `application/problem+json` documents
//! (RFC 7807) whose `type` field is a URN of the form
//! `urn:ietf:params:acme:error:<code>` (RFC 8555 section 6.7). This module
//! parses the `{type, detail, status}` fields and classifies the URN suffix
//! into a stable `ProblemType` so callers can decide retry behaviour.
//!
//! Pure: only `std` + `std.json`. No sockets, clock, or RNG. The parser takes
//! an allocator solely for the transient `std.json` parse tree; the returned
//! `Problem` owns no heap memory (strings are copied into fixed inline buffers),
//! so there is nothing for the caller to free.
const std = @import("std");

const Allocator = std.mem.Allocator;

/// Maximum bytes retained for the `type` URN and `detail` text. Longer values
/// are truncated rather than rejected, since a problem document is diagnostic.
pub const max_urn_len = 256;
pub const max_detail_len = 512;

/// ACME error URN prefix per RFC 8555 section 6.7.
const acme_error_prefix = "urn:ietf:params:acme:error:";

/// Classification of an ACME error URN suffix. Non-exhaustive in spirit:
/// any unmapped suffix (or a non-ACME URN) becomes `.unknown`.
pub const ProblemType = enum {
    bad_nonce,
    rate_limited,
    unauthorized,
    malformed,
    order_not_ready,
    connection,
    dns,
    tls,
    server_internal,
    unknown,
};

/// A parsed RFC 7807 problem document. Strings are copied into inline buffers
/// so the struct is self-contained and copyable with no allocator lifetime.
pub const Problem = struct {
    type_urn_buf: [max_urn_len]u8 = undefined,
    type_urn_len: usize = 0,
    detail_buf: [max_detail_len]u8 = undefined,
    detail_len: usize = 0,
    status: u16 = 0,
    kind: ProblemType = .unknown,

    /// The `type` URN as a slice into the inline buffer.
    pub fn typeUrn(self: *const Problem) []const u8 {
        return self.type_urn_buf[0..self.type_urn_len];
    }

    /// The human-readable `detail` text as a slice into the inline buffer.
    pub fn detail(self: *const Problem) []const u8 {
        return self.detail_buf[0..self.detail_len];
    }
};

pub const ParseError = error{
    /// Input was not valid JSON or was not a JSON object.
    InvalidJson,
} || Allocator.Error;

/// Map an ACME error URN to a `ProblemType`. Accepts either the full
/// `urn:ietf:params:acme:error:<code>` URN or a bare `<code>` suffix.
/// Unrecognised input classifies as `.unknown`.
pub fn classify(type_urn: []const u8) ProblemType {
    const suffix = if (std.mem.startsWith(u8, type_urn, acme_error_prefix))
        type_urn[acme_error_prefix.len..]
    else
        type_urn;

    const Pair = struct { code: []const u8, kind: ProblemType };
    const table = [_]Pair{
        .{ .code = "badNonce", .kind = .bad_nonce },
        .{ .code = "rateLimited", .kind = .rate_limited },
        .{ .code = "unauthorized", .kind = .unauthorized },
        .{ .code = "malformed", .kind = .malformed },
        .{ .code = "orderNotReady", .kind = .order_not_ready },
        .{ .code = "connection", .kind = .connection },
        .{ .code = "dns", .kind = .dns },
        .{ .code = "tls", .kind = .tls },
        .{ .code = "serverInternal", .kind = .server_internal },
    };

    for (table) |pair| {
        if (std.mem.eql(u8, suffix, pair.code)) return pair.kind;
    }
    return .unknown;
}

/// Whether an error of this kind is worth retrying. Transient or
/// server-side conditions are retryable; client-fault conditions are not.
pub fn isRetryable(kind: ProblemType) bool {
    return switch (kind) {
        .bad_nonce, .rate_limited, .connection, .server_internal => true,
        .unauthorized, .malformed, .order_not_ready, .dns, .tls, .unknown => false,
    };
}

/// Copy `src` into `dst`, truncating at `dst.len`. Returns the copied length.
fn copyTruncate(dst: []u8, src: []const u8) usize {
    const n = @min(dst.len, src.len);
    @memcpy(dst[0..n], src[0..n]);
    return n;
}

/// Parse an RFC 7807 problem document. Missing fields are tolerated:
/// absent `type`/`detail` yield empty strings and `kind == .unknown`,
/// absent `status` yields `0`. Returns `error.InvalidJson` only when the
/// payload is not a JSON object.
pub fn parse(allocator: Allocator, json_bytes: []const u8) ParseError!Problem {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch
        return error.InvalidJson;
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidJson;
    const obj = parsed.value.object;

    var problem: Problem = .{};

    if (obj.get("type")) |v| {
        if (v == .string) {
            problem.type_urn_len = copyTruncate(&problem.type_urn_buf, v.string);
        }
    }

    if (obj.get("detail")) |v| {
        if (v == .string) {
            problem.detail_len = copyTruncate(&problem.detail_buf, v.string);
        }
    }

    if (obj.get("status")) |v| {
        problem.status = statusValue(v);
    }

    problem.kind = classify(problem.typeUrn());
    return problem;
}

/// Extract an HTTP status as `u16`. RFC 7807 says `status` is a number, but
/// be lenient and accept a numeric string too. Out-of-range or wrong-typed
/// values fall back to `0`.
fn statusValue(value: std.json.Value) u16 {
    return switch (value) {
        .integer => |n| if (n >= 0 and n <= std.math.maxInt(u16)) @intCast(n) else 0,
        .number_string, .string => |s| std.fmt.parseInt(u16, s, 10) catch 0,
        else => 0,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parse badNonce problem document" {
    // Arrange
    const json =
        \\{"type":"urn:ietf:params:acme:error:badNonce",
        \\ "detail":"JWS has an invalid anti-replay nonce",
        \\ "status":400}
    ;

    // Act
    const problem = try parse(testing.allocator, json);

    // Assert
    try testing.expectEqualStrings(
        "urn:ietf:params:acme:error:badNonce",
        problem.typeUrn(),
    );
    try testing.expectEqualStrings(
        "JWS has an invalid anti-replay nonce",
        problem.detail(),
    );
    try testing.expectEqual(@as(u16, 400), problem.status);
    try testing.expectEqual(ProblemType.bad_nonce, problem.kind);
    try testing.expect(isRetryable(problem.kind));
}

test "classify maps the urn suffix for several types" {
    // Arrange / Act / Assert
    try testing.expectEqual(
        ProblemType.bad_nonce,
        classify("urn:ietf:params:acme:error:badNonce"),
    );
    try testing.expectEqual(
        ProblemType.rate_limited,
        classify("urn:ietf:params:acme:error:rateLimited"),
    );
    try testing.expectEqual(
        ProblemType.unauthorized,
        classify("urn:ietf:params:acme:error:unauthorized"),
    );
    try testing.expectEqual(
        ProblemType.malformed,
        classify("urn:ietf:params:acme:error:malformed"),
    );
    try testing.expectEqual(
        ProblemType.order_not_ready,
        classify("urn:ietf:params:acme:error:orderNotReady"),
    );
    try testing.expectEqual(
        ProblemType.connection,
        classify("urn:ietf:params:acme:error:connection"),
    );
    try testing.expectEqual(
        ProblemType.dns,
        classify("urn:ietf:params:acme:error:dns"),
    );
    try testing.expectEqual(
        ProblemType.tls,
        classify("urn:ietf:params:acme:error:tls"),
    );
    try testing.expectEqual(
        ProblemType.server_internal,
        classify("urn:ietf:params:acme:error:serverInternal"),
    );
}

test "classify accepts bare suffix and rejects unknowns" {
    // Arrange / Act / Assert
    try testing.expectEqual(ProblemType.bad_nonce, classify("badNonce"));
    try testing.expectEqual(ProblemType.unknown, classify("badGateway"));
    try testing.expectEqual(ProblemType.unknown, classify(""));
    try testing.expectEqual(
        ProblemType.unknown,
        classify("urn:ietf:params:acme:error:somethingNew"),
    );
}

test "isRetryable distinguishes transient from client faults" {
    // Arrange / Act / Assert
    try testing.expect(isRetryable(.bad_nonce));
    try testing.expect(isRetryable(.rate_limited));
    try testing.expect(isRetryable(.connection));
    try testing.expect(isRetryable(.server_internal));

    try testing.expect(!isRetryable(.unauthorized));
    try testing.expect(!isRetryable(.malformed));
    try testing.expect(!isRetryable(.order_not_ready));
    try testing.expect(!isRetryable(.dns));
    try testing.expect(!isRetryable(.tls));
    try testing.expect(!isRetryable(.unknown));
}

test "missing fields are tolerated" {
    // Arrange: empty object, no type/detail/status
    const json = "{}";

    // Act
    const problem = try parse(testing.allocator, json);

    // Assert
    try testing.expectEqualStrings("", problem.typeUrn());
    try testing.expectEqualStrings("", problem.detail());
    try testing.expectEqual(@as(u16, 0), problem.status);
    try testing.expectEqual(ProblemType.unknown, problem.kind);
    try testing.expect(!isRetryable(problem.kind));
}

test "partial document with only detail keeps status zero and unknown kind" {
    // Arrange
    const json =
        \\{"detail":"the server experienced an internal error"}
    ;

    // Act
    const problem = try parse(testing.allocator, json);

    // Assert
    try testing.expectEqualStrings("", problem.typeUrn());
    try testing.expectEqualStrings(
        "the server experienced an internal error",
        problem.detail(),
    );
    try testing.expectEqual(@as(u16, 0), problem.status);
    try testing.expectEqual(ProblemType.unknown, problem.kind);
}

test "status accepts numeric string and rejects out-of-range" {
    // Arrange
    const json_str =
        \\{"type":"urn:ietf:params:acme:error:rateLimited","status":"429"}
    ;
    const json_big =
        \\{"type":"urn:ietf:params:acme:error:malformed","status":99999}
    ;

    // Act
    const p_str = try parse(testing.allocator, json_str);
    const p_big = try parse(testing.allocator, json_big);

    // Assert
    try testing.expectEqual(@as(u16, 429), p_str.status);
    try testing.expectEqual(ProblemType.rate_limited, p_str.kind);
    try testing.expectEqual(@as(u16, 0), p_big.status); // 99999 > u16 max -> 0
    try testing.expectEqual(ProblemType.malformed, p_big.kind);
}

test "non-object json is rejected" {
    // Arrange / Act / Assert
    try testing.expectError(error.InvalidJson, parse(testing.allocator, "[1,2,3]"));
    try testing.expectError(error.InvalidJson, parse(testing.allocator, "not json"));
}

test "overlong type urn is truncated, not rejected" {
    // Arrange: build a type field longer than max_urn_len.
    const overlong_len = max_urn_len + 50;
    var buf: [max_urn_len + 128]u8 = undefined;
    @memcpy(buf[0..9], "{\"type\":\"");
    @memset(buf[9 .. 9 + overlong_len], 'a');
    @memcpy(buf[9 + overlong_len .. 9 + overlong_len + 2], "\"}");
    const json = buf[0 .. 9 + overlong_len + 2];

    // Act
    const problem = try parse(testing.allocator, json);

    // Assert
    try testing.expectEqual(max_urn_len, problem.typeUrn().len);
    try testing.expectEqual(ProblemType.unknown, problem.kind);
}
