//! Operator introspection query and formatting helpers.
//!
//! This module is intentionally pure: it has no network access and no view of
//! the live world. Command handlers gather small, borrowed snapshot structs and
//! hand them to the helpers here, which apply permission gates, glob/mask
//! filtering, and line formatting. Keeping the logic separate from the running
//! daemon makes every operator command (OPERSPY, SCAN, ETRACE) fully testable
//! against deterministic inputs.
//!
//! All formatting writes into caller-provided buffers. No heap allocation is
//! performed by the query/formatting paths; callers that need owned output copy
//! the returned slices themselves.
const std = @import("std");

/// Reply numerics used by the operator query commands.
///
/// The values are stable, widely-deployed IRC numerics:
///   * The RPL_TRACE* family (204/205/262) carries ETRACE output, matching the
///     conventional extended-trace reply shape.
///   * The RPL_STATS* family (249/219) carries SCAN and OPERSPY listings, which
///     are operator-only diagnostics analogous to STATS output.
/// `u16` is wide enough for every three-digit IRC numeric.
pub const OperQueryNumeric = enum(u16) {
    /// Extended trace line describing an operator client.
    RPL_TRACEOPERATOR = 204,
    /// Extended trace line describing an ordinary user client.
    RPL_TRACEUSER = 205,
    /// Terminator emitted after a TRACE/ETRACE listing.
    RPL_ENDOFTRACE = 262,
    /// Free-form operator diagnostic line (SCAN and OPERSPY rows).
    RPL_STATSDEBUG = 249,
    /// Terminator emitted after a STATS-style listing (SCAN/OPERSPY).
    RPL_ENDOFSTATS = 219,

    /// The bare three-digit numeric code as an integer.
    pub fn code(self: OperQueryNumeric) u16 {
        return @intFromEnum(self);
    }

    /// Format the numeric as a zero-padded three-digit string into `buf`.
    /// `buf` must be at least three bytes; returns the written slice.
    pub fn format(self: OperQueryNumeric, buf: []u8) FormatError![]const u8 {
        if (buf.len < 3) return error.OutputTooSmall;
        const value = @intFromEnum(self);
        buf[0] = '0' + @as(u8, @intCast((value / 100) % 10));
        buf[1] = '0' + @as(u8, @intCast((value / 10) % 10));
        buf[2] = '0' + @as(u8, @intCast(value % 10));
        return buf[0..3];
    }
};

/// Compile-time-free bounds shared by the formatters.
pub const Params = struct {
    /// Maximum bytes a single rendered reply line may occupy (incl. CRLF).
    max_line_bytes: usize = 512,
    /// Maximum length of a nick!user@host mask the matcher will accept.
    max_mask_bytes: usize = 256,
};

/// Default bounds for callers that do not need custom limits.
pub const default_params = Params{};

/// Errors returned by the formatting helpers.
pub const FormatError = error{
    /// The caller buffer was too small to hold the rendered output.
    OutputTooSmall,
    /// A mask exceeded `Params.max_mask_bytes`.
    MaskTooLong,
};

/// A borrowed, read-only view of a single client for operator tooling.
///
/// Every slice is borrowed from the caller and must outlive any returned
/// formatted output that references it. `real_host` is the uncloaked host an
/// operator is permitted to see; `host` is the (possibly cloaked) public host.
pub const ClientSnapshot = struct {
    /// Current nickname.
    nick: []const u8,
    /// Username / ident portion.
    user: []const u8,
    /// Public (possibly cloaked) hostname.
    host: []const u8,
    /// Real, uncloaked hostname visible only to operators.
    real_host: []const u8,
    /// Logged-in account name, or null if unauthenticated.
    account: ?[]const u8 = null,
    /// Whether this client currently holds operator status.
    is_oper: bool = false,
    /// Idle time in whole seconds.
    idle_secs: u32 = 0,
    /// Unix timestamp (seconds) at which the client signed on.
    signon_ts: i64 = 0,
    /// Mode-letter string applied to the client (no leading '+').
    modes: []const u8 = "",
    /// Real-name (GECOS) field; defaults empty when unknown.
    gecos: []const u8 = "",
};

/// Minimal privilege view this module needs to gate operator spy commands.
///
/// Command handlers project their richer privilege model onto this struct so
/// the gate stays standalone and trivially testable.
pub const SpyPrivileges = struct {
    /// Whether the operator may observe otherwise-hidden client detail.
    can_spy: bool = false,
    /// Whether the operator may read the uncloaked real host.
    can_see_real_host: bool = false,
};

/// Permission gate for OPERSPY-class commands.
///
/// Returns true only when the operator is explicitly granted spy access.
pub fn canOperspy(privs: SpyPrivileges) bool {
    return privs.can_spy;
}

/// A nick!user@host mask split into its three glob components.
pub const Mask = struct {
    /// Glob pattern matched against a nick.
    nick: []const u8,
    /// Glob pattern matched against a user/ident.
    user: []const u8,
    /// Glob pattern matched against a host.
    host: []const u8,

    /// Parse a `nick!user@host` mask string into its components.
    ///
    /// Missing separators default the absent components to `*`:
    ///   * "nick"            -> nick, "*", "*"
    ///   * "nick@host"       -> nick, "*", host
    ///   * "nick!user"       -> nick, user, "*"
    ///   * "nick!user@host"  -> all three
    pub fn parse(raw: []const u8) FormatError!Mask {
        if (raw.len > default_params.max_mask_bytes) return error.MaskTooLong;
        return parseBounded(default_params, raw);
    }

    /// `parse` with explicit length bounds.
    pub fn parseBounded(comptime params: Params, raw: []const u8) FormatError!Mask {
        if (raw.len > params.max_mask_bytes) return error.MaskTooLong;

        var nick_part = raw;
        var user_part: []const u8 = "*";
        var host_part: []const u8 = "*";

        if (std.mem.indexOfScalar(u8, raw, '@')) |at| {
            const head = raw[0..at];
            host_part = if (at + 1 <= raw.len) raw[at + 1 ..] else "";
            nick_part = head;
        }
        if (std.mem.indexOfScalar(u8, nick_part, '!')) |bang| {
            user_part = nick_part[bang + 1 ..];
            nick_part = nick_part[0..bang];
        }

        return .{
            .nick = if (nick_part.len == 0) "*" else nick_part,
            .user = if (user_part.len == 0) "*" else user_part,
            .host = if (host_part.len == 0) "*" else host_part,
        };
    }

    /// Render the canonical `nick!user@host` form into `out`.
    pub fn build(self: Mask, out: []u8) FormatError![]const u8 {
        var writer = BufferWriter.init(out);
        try writer.bytes(self.nick);
        try writer.byte('!');
        try writer.bytes(self.user);
        try writer.byte('@');
        try writer.bytes(self.host);
        return writer.slice();
    }

    /// Test whether a client snapshot satisfies every mask component.
    ///
    /// Matching is case-insensitive and uses the public `host`. Callers that
    /// have spy access can match against the real host with `matchesReal`.
    pub fn matches(self: Mask, snap: ClientSnapshot) bool {
        return globMatch(self.nick, snap.nick) and
            globMatch(self.user, snap.user) and
            globMatch(self.host, snap.host);
    }

    /// Like `matches` but tests against the uncloaked `real_host`.
    pub fn matchesReal(self: Mask, snap: ClientSnapshot) bool {
        return globMatch(self.nick, snap.nick) and
            globMatch(self.user, snap.user) and
            globMatch(self.host, snap.real_host);
    }
};

/// Case-insensitive glob matcher supporting `*` (zero or more) and `?` (exactly
/// one) wildcards. Implemented iteratively with backtracking so it never
/// recurses and runs in linear-ish time for typical IRC masks.
pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var star_t: usize = 0;

    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or
            asciiLower(pattern[p]) == asciiLower(text[t])))
        {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            star_t = t;
            p += 1;
        } else if (star) |star_pos| {
            p = star_pos + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

/// Result of filtering a snapshot slice by a mask.
pub const ScanResult = struct {
    /// Matching snapshots, a sub-view borrowed into the caller buffer.
    matches: []const ClientSnapshot,
    /// True if the buffer filled before scanning finished.
    truncated: bool,
};

/// Filter `clients` by a glob mask over `nick!user@host`, copying matches into
/// `out`. Stops early (and marks `truncated`) when `out` fills. Uses the public
/// host unless `use_real_host` is set (an OPERSPY-gated capability).
pub fn scan(
    mask: Mask,
    clients: []const ClientSnapshot,
    out: []ClientSnapshot,
    use_real_host: bool,
) ScanResult {
    var count: usize = 0;
    var truncated = false;
    for (clients) |snap| {
        const hit = if (use_real_host) mask.matchesReal(snap) else mask.matches(snap);
        if (!hit) continue;
        if (count >= out.len) {
            truncated = true;
            break;
        }
        out[count] = snap;
        count += 1;
    }
    return .{ .matches = out[0..count], .truncated = truncated };
}

/// Formats operator-query reply lines into caller buffers.
///
/// The formatter holds only borrowed identity slices (the local server name and
/// the requesting operator's nick) and performs no allocation.
pub const Formatter = struct {
    /// Name of the local server, used as the message source.
    server_name: []const u8,
    /// Nick of the operator receiving the replies.
    requester_nick: []const u8,
    /// Active line-length bounds.
    params: Params = default_params,

    /// Construct a formatter with default bounds.
    pub fn init(server_name: []const u8, requester_nick: []const u8) Formatter {
        return .{ .server_name = server_name, .requester_nick = requester_nick };
    }

    /// Construct a formatter with explicit bounds.
    pub fn initWithParams(
        params: Params,
        server_name: []const u8,
        requester_nick: []const u8,
    ) Formatter {
        return .{
            .server_name = server_name,
            .requester_nick = requester_nick,
            .params = params,
        };
    }

    /// Format an ETRACE line for a single client into `out`.
    ///
    /// Shape: `:server <num> <reqnick> <oper|user> <nick> <user>@<real_host>
    /// <account> <idle> :<gecos>` where `<num>` is RPL_TRACEOPERATOR for
    /// operators and RPL_TRACEUSER otherwise. The real (uncloaked) host is used
    /// because ETRACE is an operator-only diagnostic.
    pub fn etrace(self: Formatter, out: []u8, snap: ClientSnapshot) FormatError![]const u8 {
        const reply: OperQueryNumeric = if (snap.is_oper)
            .RPL_TRACEOPERATOR
        else
            .RPL_TRACEUSER;

        var writer = BufferWriter.init(out);
        try self.header(&writer, reply);
        try writer.byte(' ');
        try writer.bytes(if (snap.is_oper) "oper" else "user");
        try writer.byte(' ');
        try writer.bytes(snap.nick);
        try writer.byte(' ');
        try writer.bytes(snap.user);
        try writer.byte('@');
        try writer.bytes(snap.real_host);
        try writer.byte(' ');
        try writer.bytes(snap.account orelse "*");
        try writer.byte(' ');
        try writer.number(snap.idle_secs);
        try writer.bytes(" :");
        try writer.bytes(if (snap.gecos.len == 0) "<unknown>" else snap.gecos);
        try writer.bytes("\r\n");
        try self.checkLine(&writer);
        return writer.slice();
    }

    /// Format the RPL_ENDOFTRACE terminator into `out`.
    pub fn endOfTrace(self: Formatter, out: []u8, target: []const u8) FormatError![]const u8 {
        var writer = BufferWriter.init(out);
        try self.header(&writer, .RPL_ENDOFTRACE);
        try writer.byte(' ');
        try writer.bytes(if (target.len == 0) "*" else target);
        try writer.bytes(" :End of TRACE\r\n");
        try self.checkLine(&writer);
        return writer.slice();
    }

    /// Format one SCAN row for a matching client into `out`.
    ///
    /// Shape: `:server <num> <reqnick> :<nick> <user>@<host> [account]
    /// modes=<modes>`. The host shown is the real host only when the operator
    /// passed the OPERSPY gate (`reveal_real_host`).
    pub fn scanLine(
        self: Formatter,
        out: []u8,
        snap: ClientSnapshot,
        reveal_real_host: bool,
    ) FormatError![]const u8 {
        var writer = BufferWriter.init(out);
        try self.header(&writer, .RPL_STATSDEBUG);
        try writer.bytes(" :");
        try writer.bytes(snap.nick);
        try writer.byte(' ');
        try writer.bytes(snap.user);
        try writer.byte('@');
        try writer.bytes(if (reveal_real_host) snap.real_host else snap.host);
        try writer.byte(' ');
        try writer.bytes(snap.account orelse "*");
        try writer.bytes(" modes=");
        try writer.bytes(if (snap.modes.len == 0) "-" else snap.modes);
        try writer.bytes("\r\n");
        try self.checkLine(&writer);
        return writer.slice();
    }

    /// Format one OPERSPY result row into `out`.
    ///
    /// Mirrors `scanLine` but always reveals the real host, since OPERSPY is
    /// the spy-gated command. Callers MUST verify `canOperspy` first.
    pub fn operspyLine(self: Formatter, out: []u8, snap: ClientSnapshot) FormatError![]const u8 {
        return self.scanLine(out, snap, true);
    }

    /// Format the RPL_ENDOFSTATS terminator for SCAN/OPERSPY into `out`.
    pub fn endOfStats(self: Formatter, out: []u8, label: []const u8) FormatError![]const u8 {
        var writer = BufferWriter.init(out);
        try self.header(&writer, .RPL_ENDOFSTATS);
        try writer.byte(' ');
        try writer.bytes(if (label.len == 0) "*" else label);
        try writer.bytes(" :End of operator query\r\n");
        try self.checkLine(&writer);
        return writer.slice();
    }

    fn header(self: Formatter, writer: *BufferWriter, reply: OperQueryNumeric) FormatError!void {
        var code_buf: [3]u8 = undefined;
        const num = try reply.format(&code_buf);
        try writer.byte(':');
        try writer.bytes(self.server_name);
        try writer.byte(' ');
        try writer.bytes(num);
        try writer.byte(' ');
        try writer.bytes(self.requester_nick);
    }

    fn checkLine(self: Formatter, writer: *const BufferWriter) FormatError!void {
        if (writer.len > self.params.max_line_bytes) return error.OutputTooSmall;
    }
};

fn asciiLower(byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte + 32 else byte;
}

/// Minimal bounds-checked sink that appends bytes into a fixed caller buffer.
const BufferWriter = struct {
    out: []u8,
    len: usize = 0,

    fn init(out: []u8) BufferWriter {
        return .{ .out = out };
    }

    fn slice(self: *const BufferWriter) []const u8 {
        return self.out[0..self.len];
    }

    fn bytes(self: *BufferWriter, data: []const u8) FormatError!void {
        if (self.len > self.out.len or data.len > self.out.len - self.len) {
            return error.OutputTooSmall;
        }
        @memcpy(self.out[self.len .. self.len + data.len], data);
        self.len += data.len;
    }

    fn byte(self: *BufferWriter, value: u8) FormatError!void {
        if (self.len >= self.out.len) return error.OutputTooSmall;
        self.out[self.len] = value;
        self.len += 1;
    }

    fn number(self: *BufferWriter, value: u32) FormatError!void {
        var digits: [10]u8 = undefined;
        var n = value;
        var index: usize = digits.len;
        if (n == 0) {
            index -= 1;
            digits[index] = '0';
        } else {
            while (n > 0) {
                index -= 1;
                digits[index] = '0' + @as(u8, @intCast(n % 10));
                n /= 10;
            }
        }
        try self.bytes(digits[index..]);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn sampleClient() ClientSnapshot {
    return .{
        .nick = "Alice",
        .user = "alice",
        .host = "cloak-1234.example.test",
        .real_host = "home.alice.example.test",
        .account = "alice",
        .is_oper = false,
        .idle_secs = 42,
        .signon_ts = 1_700_000_000,
        .modes = "iw",
        .gecos = "Alice Liddell",
    };
}

test "glob matching covers prefix suffix middle question and case" {
    // Arrange / Act / Assert
    try testing.expect(globMatch("ali*", "alice"));
    try testing.expect(globMatch("*ice", "alice"));
    try testing.expect(globMatch("a*e", "alice"));
    try testing.expect(globMatch("al?ce", "alice"));
    try testing.expect(globMatch("*", ""));
    try testing.expect(globMatch("ALICE", "alice"));
    try testing.expect(globMatch("a*c?", "aBBBce"));

    try testing.expect(!globMatch("ali?", "alice"));
    try testing.expect(!globMatch("bob*", "alice"));
    try testing.expect(!globMatch("a?", "alice"));
    try testing.expect(!globMatch("", "alice"));
}

test "mask parse defaults missing components to star" {
    // Arrange / Act
    const bare = try Mask.parse("Alice");
    const at_host = try Mask.parse("Alice@*.example.test");
    const bang_user = try Mask.parse("Alice!ali*");
    const full = try Mask.parse("Ali*!*li*@*.test");

    // Assert
    try testing.expectEqualStrings("Alice", bare.nick);
    try testing.expectEqualStrings("*", bare.user);
    try testing.expectEqualStrings("*", bare.host);

    try testing.expectEqualStrings("*.example.test", at_host.host);
    try testing.expectEqualStrings("*", at_host.user);

    try testing.expectEqualStrings("ali*", bang_user.user);
    try testing.expectEqualStrings("*", bang_user.host);

    try testing.expectEqualStrings("Ali*", full.nick);
    try testing.expectEqualStrings("*li*", full.user);
    try testing.expectEqualStrings("*.test", full.host);
}

test "mask build renders canonical form and rejects oversize" {
    // Arrange
    const mask = try Mask.parse("Alice!ali*@*.example.test");
    var out: [128]u8 = undefined;

    // Act
    const rendered = try mask.build(&out);

    // Assert
    try testing.expectEqualStrings("Alice!ali*@*.example.test", rendered);

    const Small = Params{ .max_mask_bytes = 4 };
    try testing.expectError(error.MaskTooLong, Mask.parseBounded(Small, "Alice!u@h"));

    var tiny: [4]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, mask.build(&tiny));
}

test "mask matches public and real host distinctly" {
    // Arrange
    const snap = sampleClient();
    const public_mask = try Mask.parse("*!*@cloak-*.example.test");
    const real_mask = try Mask.parse("*!*@home.*.example.test");

    // Act / Assert
    try testing.expect(public_mask.matches(snap));
    try testing.expect(!public_mask.matchesReal(snap));
    try testing.expect(real_mask.matchesReal(snap));
    try testing.expect(!real_mask.matches(snap));
}

test "scan filters snapshots and reports truncation" {
    // Arrange
    const clients = [_]ClientSnapshot{
        .{ .nick = "Alice", .user = "alice", .host = "h.test", .real_host = "h.test" },
        .{ .nick = "Albert", .user = "al", .host = "h.test", .real_host = "h.test" },
        .{ .nick = "Bob", .user = "bob", .host = "h.test", .real_host = "h.test" },
    };
    const mask = try Mask.parse("Al*");

    // Act
    var out: [4]ClientSnapshot = undefined;
    const full = scan(mask, &clients, &out, false);

    var small: [1]ClientSnapshot = undefined;
    const limited = scan(mask, &clients, &small, false);

    // Assert
    try testing.expectEqual(@as(usize, 2), full.matches.len);
    try testing.expect(!full.truncated);
    try testing.expectEqualStrings("Alice", full.matches[0].nick);
    try testing.expectEqualStrings("Albert", full.matches[1].nick);

    try testing.expectEqual(@as(usize, 1), limited.matches.len);
    try testing.expect(limited.truncated);
}

test "scan can match on real host when spy gated" {
    // Arrange
    const clients = [_]ClientSnapshot{
        .{ .nick = "Alice", .user = "a", .host = "cloak.test", .real_host = "secret.lan" },
    };
    const mask = try Mask.parse("*!*@*.lan");

    // Act
    var out: [2]ClientSnapshot = undefined;
    const public_pass = scan(mask, &clients, &out, false);
    const real_pass = scan(mask, &clients, &out, true);

    // Assert
    try testing.expectEqual(@as(usize, 0), public_pass.matches.len);
    try testing.expectEqual(@as(usize, 1), real_pass.matches.len);
}

test "canOperspy gates only on explicit grant" {
    // Arrange / Act / Assert
    try testing.expect(canOperspy(.{ .can_spy = true }));
    try testing.expect(!canOperspy(.{ .can_spy = false }));
    try testing.expect(!canOperspy(.{ .can_spy = false, .can_see_real_host = true }));
}

test "etrace line content for user and operator" {
    // Arrange
    const fmt = Formatter.init("orochi.test", "rootoper");
    var out: [512]u8 = undefined;

    // Act
    const user_line = try fmt.etrace(&out, sampleClient());

    // Assert
    try testing.expectEqualStrings(
        ":orochi.test 205 rootoper user Alice alice@home.alice.example.test alice 42 :Alice Liddell\r\n",
        user_line,
    );

    var oper_snap = sampleClient();
    oper_snap.is_oper = true;
    oper_snap.account = null;
    oper_snap.gecos = "";
    oper_snap.idle_secs = 0;
    var out2: [512]u8 = undefined;
    const oper_line = try fmt.etrace(&out2, oper_snap);
    try testing.expectEqualStrings(
        ":orochi.test 204 rootoper oper Alice alice@home.alice.example.test * 0 :<unknown>\r\n",
        oper_line,
    );
}

test "scan and operspy lines reveal hosts per gate" {
    // Arrange
    const fmt = Formatter.init("orochi.test", "rootoper");
    const snap = sampleClient();
    var out: [512]u8 = undefined;

    // Act
    const public_line = try fmt.scanLine(&out, snap, false);
    try testing.expectEqualStrings(
        ":orochi.test 249 rootoper :Alice alice@cloak-1234.example.test alice modes=iw\r\n",
        public_line,
    );

    var out2: [512]u8 = undefined;
    const spy_line = try fmt.operspyLine(&out2, snap);
    try testing.expectEqualStrings(
        ":orochi.test 249 rootoper :Alice alice@home.alice.example.test alice modes=iw\r\n",
        spy_line,
    );
}

test "terminator lines format correctly" {
    // Arrange
    const fmt = Formatter.init("orochi.test", "rootoper");
    var out: [256]u8 = undefined;

    // Act / Assert
    const trace_end = try fmt.endOfTrace(&out, "Al*");
    try testing.expectEqualStrings(
        ":orochi.test 262 rootoper Al* :End of TRACE\r\n",
        trace_end,
    );

    var out2: [256]u8 = undefined;
    const stats_end = try fmt.endOfStats(&out2, "");
    try testing.expectEqualStrings(
        ":orochi.test 219 rootoper * :End of operator query\r\n",
        stats_end,
    );
}

test "numeric format pads to three digits" {
    // Arrange
    var buf: [3]u8 = undefined;

    // Act / Assert
    try testing.expectEqualStrings("204", try OperQueryNumeric.RPL_TRACEOPERATOR.format(&buf));
    try testing.expectEqualStrings("219", try OperQueryNumeric.RPL_ENDOFSTATS.format(&buf));
    try testing.expectEqual(@as(u16, 262), OperQueryNumeric.RPL_ENDOFTRACE.code());

    var tiny: [2]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, OperQueryNumeric.RPL_TRACEUSER.format(&tiny));
}

test "formatter respects line byte bound and small buffers" {
    // Arrange
    const fmt = Formatter.initWithParams(.{ .max_line_bytes = 16 }, "orochi.test", "rootoper");
    var out: [512]u8 = undefined;

    // Act / Assert: the rendered line exceeds the 16-byte cap.
    try testing.expectError(error.OutputTooSmall, fmt.etrace(&out, sampleClient()));

    // A too-small output buffer also reports OutputTooSmall.
    const ok_fmt = Formatter.init("orochi.test", "rootoper");
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, ok_fmt.scanLine(&tiny, sampleClient(), false));
}
