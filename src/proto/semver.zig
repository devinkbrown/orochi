//! Semantic Versioning 2.0.0 parsing, precedence comparison, and minimal
//! comparator ranges for client feature gates.
//!
//! `Version` values borrow slices from the caller-provided input. This module
//! does not allocate; callers only need to keep the input bytes alive for as
//! long as a parsed version or comparator is used.

const std = @import("std");

/// Tunable parser limits for Semantic Versioning tokens.
pub const Params = struct {
    /// Maximum accepted byte length of the whole version string.
    max_version_bytes: usize = 256,
    /// Maximum accepted byte length of the prerelease suffix.
    max_prerelease_bytes: usize = 128,
    /// Maximum accepted byte length of the build metadata suffix.
    max_build_bytes: usize = 128,
    /// Maximum accepted byte length of one dot-separated identifier.
    max_identifier_bytes: usize = 64,
};

/// Errors surfaced by Semantic Versioning parsing and range evaluation.
pub const SemVerError = error{
    /// The supplied version string or range string was empty.
    EmptyInput,
    /// The supplied version exceeded `Params.max_version_bytes`.
    VersionTooLong,
    /// The supplied range string did not contain a supported comparator.
    InvalidRange,
    /// The `major.minor.patch` core was malformed.
    InvalidCore,
    /// A numeric core identifier was malformed.
    InvalidNumber,
    /// A numeric core identifier did not fit in `u64`.
    NumberOverflow,
    /// A numeric identifier used a leading zero.
    LeadingZero,
    /// A prerelease marker was present without identifiers.
    MissingPrerelease,
    /// A build marker was present without identifiers.
    MissingBuild,
    /// The prerelease suffix exceeded `Params.max_prerelease_bytes`.
    PrereleaseTooLong,
    /// The build metadata suffix exceeded `Params.max_build_bytes`.
    BuildTooLong,
    /// A dot-separated identifier was empty.
    EmptyIdentifier,
    /// A dot-separated identifier exceeded `Params.max_identifier_bytes`.
    IdentifierTooLong,
    /// A dot-separated identifier contained a byte outside `[0-9A-Za-z-]`.
    InvalidIdentifier,
};

/// Parsed Semantic Versioning 2.0.0 value.
///
/// `prerelease` and `build` borrow from the source string. Empty slices mean the
/// corresponding suffix was absent. Build metadata is retained but ignored by
/// precedence comparison, as required by the specification.
pub const Version = struct {
    /// Major version component.
    major: u64,
    /// Minor version component.
    minor: u64,
    /// Patch version component.
    patch: u64,
    /// Prerelease identifiers without the leading `-`, or empty when absent.
    prerelease: []const u8 = "",
    /// Build identifiers without the leading `+`, or empty when absent.
    build: []const u8 = "",
};

/// Minimal single-comparator range operator.
pub const RangeOperator = enum(u3) {
    /// Left version must be greater than the range version.
    greater_than,
    /// Left version must be greater than or equal to the range version.
    greater_or_equal,
    /// Left version must be less than the range version.
    less_than,
    /// Left version must be less than or equal to the range version.
    less_or_equal,
    /// Left version must equal the range version.
    equal,
};

/// Parsed minimal range comparator.
///
/// The embedded `Version` borrows from the range string passed to
/// `parseComparator`.
pub const Comparator = struct {
    /// Comparator relation to evaluate.
    operator: RangeOperator,
    /// Right-hand version used by the comparator.
    version: Version,
};

/// Allocation-free Semantic Versioning parser and range gate.
pub const Gate = struct {
    params: Params,

    /// Create a parser with caller-selected limits.
    pub fn init(params: Params) Gate {
        return .{ .params = params };
    }

    /// Release parser state.
    ///
    /// `Gate` owns no memory, so this only marks the value as no longer usable.
    pub fn deinit(self: *Gate) void {
        self.* = undefined;
    }

    /// Parse one Semantic Versioning 2.0.0 string.
    pub fn parse(self: *const Gate, input: []const u8) SemVerError!Version {
        if (input.len == 0) return error.EmptyInput;
        if (input.len > self.params.max_version_bytes) return error.VersionTooLong;

        var core_and_pre = input;
        var build: []const u8 = "";
        if (std.mem.indexOfScalar(u8, input, '+')) |plus_index| {
            build = input[plus_index + 1 ..];
            core_and_pre = input[0..plus_index];
            if (build.len == 0) return error.MissingBuild;
            if (build.len > self.params.max_build_bytes) return error.BuildTooLong;
            try validateIdentifierList(self.params, build, .build);
        }

        var core = core_and_pre;
        var prerelease: []const u8 = "";
        if (std.mem.indexOfScalar(u8, core_and_pre, '-')) |dash_index| {
            prerelease = core_and_pre[dash_index + 1 ..];
            core = core_and_pre[0..dash_index];
            if (prerelease.len == 0) return error.MissingPrerelease;
            if (prerelease.len > self.params.max_prerelease_bytes) return error.PrereleaseTooLong;
            try validateIdentifierList(self.params, prerelease, .prerelease);
        }

        var parts = std.mem.splitScalar(u8, core, '.');
        const major_token = parts.next() orelse return error.InvalidCore;
        const minor_token = parts.next() orelse return error.InvalidCore;
        const patch_token = parts.next() orelse return error.InvalidCore;
        if (parts.next() != null) return error.InvalidCore;

        return .{
            .major = try parseCoreNumber(major_token),
            .minor = try parseCoreNumber(minor_token),
            .patch = try parseCoreNumber(patch_token),
            .prerelease = prerelease,
            .build = build,
        };
    }

    /// Parse one minimal range comparator.
    ///
    /// Supported forms are `>1.2.3`, `>=1.2.3`, `<1.2.3`, `<=1.2.3`,
    /// `=1.2.3`, and bare exact versions such as `1.2.3`.
    pub fn parseComparator(self: *const Gate, range: []const u8) SemVerError!Comparator {
        const trimmed = std.mem.trim(u8, range, " \t\r\n");
        if (trimmed.len == 0) return error.EmptyInput;

        var operator: RangeOperator = .equal;
        var version_text = trimmed;

        if (std.mem.startsWith(u8, trimmed, ">=")) {
            operator = .greater_or_equal;
            version_text = trimmed[2..];
        } else if (std.mem.startsWith(u8, trimmed, "<=")) {
            operator = .less_or_equal;
            version_text = trimmed[2..];
        } else if (std.mem.startsWith(u8, trimmed, ">")) {
            operator = .greater_than;
            version_text = trimmed[1..];
        } else if (std.mem.startsWith(u8, trimmed, "<")) {
            operator = .less_than;
            version_text = trimmed[1..];
        } else if (std.mem.startsWith(u8, trimmed, "=")) {
            operator = .equal;
            version_text = trimmed[1..];
        }

        version_text = std.mem.trim(u8, version_text, " \t\r\n");
        if (version_text.len == 0) return error.InvalidRange;

        return .{
            .operator = operator,
            .version = try self.parse(version_text),
        };
    }

    /// Compare two parsed versions using Semantic Versioning precedence.
    pub fn compare(self: *const Gate, left: Version, right: Version) std.math.Order {
        _ = self;
        return compareVersions(left, right);
    }

    /// Return true when `version` satisfies one minimal range comparator.
    pub fn satisfies(self: *const Gate, version: Version, range: []const u8) SemVerError!bool {
        const comparator = try self.parseComparator(range);
        const order = self.compare(version, comparator.version);
        return switch (comparator.operator) {
            .greater_than => order == .gt,
            .greater_or_equal => order != .lt,
            .less_than => order == .lt,
            .less_or_equal => order != .gt,
            .equal => order == .eq,
        };
    }
};

/// Parse one Semantic Versioning 2.0.0 string using default limits.
pub fn parse(input: []const u8) SemVerError!Version {
    return parseBounded(.{}, input);
}

/// Parse one Semantic Versioning 2.0.0 string using caller-selected limits.
pub fn parseBounded(params: Params, input: []const u8) SemVerError!Version {
    var gate = Gate.init(params);
    defer gate.deinit();
    return gate.parse(input);
}

/// Parse one minimal range comparator using default limits.
pub fn parseComparator(range: []const u8) SemVerError!Comparator {
    return parseComparatorBounded(.{}, range);
}

/// Parse one minimal range comparator using caller-selected limits.
pub fn parseComparatorBounded(params: Params, range: []const u8) SemVerError!Comparator {
    var gate = Gate.init(params);
    defer gate.deinit();
    return gate.parseComparator(range);
}

/// Compare two parsed versions using Semantic Versioning precedence.
pub fn compare(left: Version, right: Version) std.math.Order {
    return compareVersions(left, right);
}

/// Return true when `version` satisfies one minimal range comparator.
pub fn satisfies(version: Version, range: []const u8) SemVerError!bool {
    var gate = Gate.init(.{});
    defer gate.deinit();
    return gate.satisfies(version, range);
}

const IdentifierKind = enum(u1) {
    prerelease,
    build,
};

fn parseCoreNumber(token: []const u8) SemVerError!u64 {
    if (token.len == 0) return error.InvalidNumber;
    if (token.len > 1 and token[0] == '0') return error.LeadingZero;
    for (token) |byte| {
        if (!isDigit(byte)) return error.InvalidNumber;
    }
    return std.fmt.parseInt(u64, token, 10) catch |err| switch (err) {
        error.Overflow => error.NumberOverflow,
        error.InvalidCharacter => error.InvalidNumber,
    };
}

fn validateIdentifierList(params: Params, list: []const u8, kind: IdentifierKind) SemVerError!void {
    var it = std.mem.splitScalar(u8, list, '.');
    while (it.next()) |identifier| {
        try validateIdentifier(params, identifier, kind);
    }
}

fn validateIdentifier(params: Params, identifier: []const u8, kind: IdentifierKind) SemVerError!void {
    if (identifier.len == 0) return error.EmptyIdentifier;
    if (identifier.len > params.max_identifier_bytes) return error.IdentifierTooLong;

    var all_digits = true;
    for (identifier) |byte| {
        if (!isIdentifierByte(byte)) return error.InvalidIdentifier;
        if (!isDigit(byte)) all_digits = false;
    }

    switch (kind) {
        .prerelease => {
            if (all_digits and identifier.len > 1 and identifier[0] == '0') return error.LeadingZero;
        },
        .build => {},
    }
}

fn compareVersions(left: Version, right: Version) std.math.Order {
    const major_order = compareU64(left.major, right.major);
    if (major_order != .eq) return major_order;

    const minor_order = compareU64(left.minor, right.minor);
    if (minor_order != .eq) return minor_order;

    const patch_order = compareU64(left.patch, right.patch);
    if (patch_order != .eq) return patch_order;

    return comparePrerelease(left.prerelease, right.prerelease);
}

fn comparePrerelease(left: []const u8, right: []const u8) std.math.Order {
    if (left.len == 0 and right.len == 0) return .eq;
    if (left.len == 0) return .gt;
    if (right.len == 0) return .lt;

    var left_it = std.mem.splitScalar(u8, left, '.');
    var right_it = std.mem.splitScalar(u8, right, '.');

    while (true) {
        const left_identifier = left_it.next();
        const right_identifier = right_it.next();

        if (left_identifier == null and right_identifier == null) return .eq;
        if (left_identifier == null) return .lt;
        if (right_identifier == null) return .gt;

        const identifier_order = comparePrereleaseIdentifier(left_identifier.?, right_identifier.?);
        if (identifier_order != .eq) return identifier_order;
    }
}

fn comparePrereleaseIdentifier(left: []const u8, right: []const u8) std.math.Order {
    const left_numeric = isNumericIdentifier(left);
    const right_numeric = isNumericIdentifier(right);

    if (left_numeric and right_numeric) return compareNumericIdentifier(left, right);
    if (left_numeric and !right_numeric) return .lt;
    if (!left_numeric and right_numeric) return .gt;
    return std.mem.order(u8, left, right);
}

fn compareNumericIdentifier(left: []const u8, right: []const u8) std.math.Order {
    const left_trimmed = trimLeadingZeroes(left);
    const right_trimmed = trimLeadingZeroes(right);

    if (left_trimmed.len < right_trimmed.len) return .lt;
    if (left_trimmed.len > right_trimmed.len) return .gt;
    return std.mem.order(u8, left_trimmed, right_trimmed);
}

fn compareU64(left: u64, right: u64) std.math.Order {
    if (left < right) return .lt;
    if (left > right) return .gt;
    return .eq;
}

fn trimLeadingZeroes(input: []const u8) []const u8 {
    var index: usize = 0;
    while (index + 1 < input.len and input[index] == '0') : (index += 1) {}
    return input[index..];
}

fn isNumericIdentifier(input: []const u8) bool {
    if (input.len == 0) return false;
    for (input) |byte| {
        if (!isDigit(byte)) return false;
    }
    return true;
}

fn isIdentifierByte(byte: u8) bool {
    return isDigit(byte) or
        (byte >= 'A' and byte <= 'Z') or
        (byte >= 'a' and byte <= 'z') or
        byte == '-';
}

fn isDigit(byte: u8) bool {
    return byte >= '0' and byte <= '9';
}

test "parse accepts core prerelease and build metadata" {
    // Arrange.
    const allocator = std.testing.allocator;
    const input = try allocator.dupe(u8, "1.2.3-rc.1+build.5");
    defer allocator.free(input);

    // Act.
    const version = try parse(input);

    // Assert.
    try std.testing.expectEqual(@as(u64, 1), version.major);
    try std.testing.expectEqual(@as(u64, 2), version.minor);
    try std.testing.expectEqual(@as(u64, 3), version.patch);
    try std.testing.expectEqualStrings("rc.1", version.prerelease);
    try std.testing.expectEqualStrings("build.5", version.build);
}

test "parse accepts release version without optional suffixes" {
    // Arrange.
    const allocator = std.testing.allocator;
    const input = try allocator.dupe(u8, "10.20.30");
    defer allocator.free(input);

    // Act.
    const version = try parse(input);

    // Assert.
    try std.testing.expectEqual(@as(u64, 10), version.major);
    try std.testing.expectEqual(@as(u64, 20), version.minor);
    try std.testing.expectEqual(@as(u64, 30), version.patch);
    try std.testing.expectEqualStrings("", version.prerelease);
    try std.testing.expectEqualStrings("", version.build);
}

test "parse rejects malformed semantic versions" {
    // Arrange.
    const allocator = std.testing.allocator;
    const leading_zero = try allocator.dupe(u8, "01.2.3");
    defer allocator.free(leading_zero);
    const missing_patch = try allocator.dupe(u8, "1.2");
    defer allocator.free(missing_patch);
    const empty_pre = try allocator.dupe(u8, "1.2.3-");
    defer allocator.free(empty_pre);
    const empty_build = try allocator.dupe(u8, "1.2.3+");
    defer allocator.free(empty_build);
    const invalid_identifier = try allocator.dupe(u8, "1.2.3-alpha_1");
    defer allocator.free(invalid_identifier);

    // Act and assert.
    try std.testing.expectError(error.LeadingZero, parse(leading_zero));
    try std.testing.expectError(error.InvalidCore, parse(missing_patch));
    try std.testing.expectError(error.MissingPrerelease, parse(empty_pre));
    try std.testing.expectError(error.MissingBuild, parse(empty_build));
    try std.testing.expectError(error.InvalidIdentifier, parse(invalid_identifier));
}

test "parse enforces caller supplied length limits" {
    // Arrange.
    const allocator = std.testing.allocator;
    const input = try allocator.dupe(u8, "1.2.3-alpha");
    defer allocator.free(input);
    var gate = Gate.init(.{
        .max_version_bytes = 32,
        .max_prerelease_bytes = 4,
        .max_build_bytes = 32,
        .max_identifier_bytes = 32,
    });
    defer gate.deinit();

    // Act and assert.
    try std.testing.expectError(error.PrereleaseTooLong, gate.parse(input));
}

test "compare follows semantic version prerelease precedence order" {
    // Arrange.
    const allocator = std.testing.allocator;
    const inputs = [_][]const u8{
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    };
    var owned: [inputs.len][]u8 = undefined;
    for (inputs, 0..) |input, index| {
        owned[index] = try allocator.dupe(u8, input);
    }
    defer for (owned) |input| allocator.free(input);

    var versions: [inputs.len]Version = undefined;
    for (owned, 0..) |input, index| {
        versions[index] = try parse(input);
    }

    // Act and assert.
    for (versions[0 .. versions.len - 1], 0..) |version, index| {
        try std.testing.expectEqual(std.math.Order.lt, compare(version, versions[index + 1]));
    }
}

test "compare ignores build metadata and orders numeric core fields" {
    // Arrange.
    const allocator = std.testing.allocator;
    const left_input = try allocator.dupe(u8, "1.2.3+build.1");
    defer allocator.free(left_input);
    const right_input = try allocator.dupe(u8, "1.2.3+build.2");
    defer allocator.free(right_input);
    const newer_input = try allocator.dupe(u8, "1.3.0");
    defer allocator.free(newer_input);

    const left = try parse(left_input);
    const right = try parse(right_input);
    const newer = try parse(newer_input);

    // Act and assert.
    try std.testing.expectEqual(std.math.Order.eq, compare(left, right));
    try std.testing.expectEqual(std.math.Order.lt, compare(left, newer));
}

test "satisfies evaluates minimal comparator ranges" {
    // Arrange.
    const allocator = std.testing.allocator;
    const version_input = try allocator.dupe(u8, "1.2.3");
    defer allocator.free(version_input);
    const version = try parse(version_input);

    // Act and assert.
    try std.testing.expect(try satisfies(version, ">=1.2.0"));
    try std.testing.expect(try satisfies(version, ">1.2.2"));
    try std.testing.expect(try satisfies(version, "<=1.2.3"));
    try std.testing.expect(try satisfies(version, "=1.2.3+build.9"));
    try std.testing.expect(try satisfies(version, "1.2.3"));
    try std.testing.expect(!try satisfies(version, ">1.2.3"));
    try std.testing.expect(!try satisfies(version, "<1.2.3"));
}

test "satisfies treats prerelease as lower than release" {
    // Arrange.
    const allocator = std.testing.allocator;
    const release_input = try allocator.dupe(u8, "1.2.3");
    defer allocator.free(release_input);
    const pre_input = try allocator.dupe(u8, "1.2.3-rc.1");
    defer allocator.free(pre_input);
    const release = try parse(release_input);
    const prerelease = try parse(pre_input);

    // Act and assert.
    try std.testing.expect(!try satisfies(prerelease, ">=1.2.3"));
    try std.testing.expect(try satisfies(prerelease, "<1.2.3"));
    try std.testing.expect(try satisfies(release, ">1.2.3-rc.1"));
}

test "parseComparator accepts whitespace around one comparator" {
    // Arrange.
    const allocator = std.testing.allocator;
    const range = try allocator.dupe(u8, "  >= 2.0.0-alpha.1+build  ");
    defer allocator.free(range);

    // Act.
    const comparator = try parseComparator(range);

    // Assert.
    try std.testing.expectEqual(RangeOperator.greater_or_equal, comparator.operator);
    try std.testing.expectEqual(@as(u64, 2), comparator.version.major);
    try std.testing.expectEqualStrings("alpha.1", comparator.version.prerelease);
    try std.testing.expectEqualStrings("build", comparator.version.build);
}
