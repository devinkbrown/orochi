//! Pure in-memory connection-class policy registry.
//!
//! A connection class describes limits for a group of clients. Matchers assign
//! hostnames or addresses to classes with ordered, case-insensitive glob masks.

const std = @import("std");

/// Numeric identifiers for connection-class policy diagnostics.
pub const ConnectionClassNumeric = enum(u8) {
    /// A connection class was found for a host or address.
    class_matched = 1,
    /// No matcher fired and the fallback class was selected.
    default_selected = 2,
    /// A named class is already at its total live-connection cap.
    class_full = 3,
};

/// Bounded registry limits used to reject unreasonable policy entries.
pub const Params = struct {
    /// Maximum number of classes held by the registry.
    max_classes: usize = 256,
    /// Maximum number of ordered matchers held by the registry.
    max_matchers: usize = 1024,
    /// Maximum byte length for class names.
    max_class_name_bytes: usize = 64,
    /// Maximum byte length for host/address glob patterns.
    max_pattern_bytes: usize = 255,
};

/// Errors returned by connection-class registry operations.
pub const RegistryError = std.mem.Allocator.Error || error{
    EmptyClassName,
    ClassNameTooLong,
    EmptyPattern,
    PatternTooLong,
    TooManyClasses,
    TooManyMatchers,
    UnknownClass,
    CountOverflow,
};

/// Per-class connection limits.
pub const Class = struct {
    /// Stable class name used by matchers and counter operations.
    name: []const u8,
    /// Maximum clients intended for this class on the local daemon.
    max_clients: u32,
    /// Maximum clients from one address for consumers that track per-address state.
    max_per_ip: u16,
    /// Client ping cadence in seconds.
    ping_frequency_secs: u32,
    /// Outbound queue limit in bytes.
    sendq_bytes: u64,
    /// Inbound queue limit in bytes.
    recvq_bytes: u64,
    /// Total live connections permitted for this class.
    max_connections_total: u32,
};

/// Ordered host/address matcher.
pub const Matcher = struct {
    /// Case-insensitive glob pattern over a hostname or textual address.
    pattern: []const u8,
    /// Name of the class selected when `pattern` matches.
    class_name: []const u8,
};

/// Owned connection-class registry with ordered matcher evaluation.
pub const Registry = struct {
    /// Allocator used for all owned keys and matcher strings.
    allocator: std.mem.Allocator,
    /// Runtime bounds enforced by mutating operations.
    params: Params,
    classes: std.StringHashMap(ClassState),
    matchers: std.ArrayListUnmanaged(OwnedMatcher) = .empty,
    default_name: ?[]const u8 = null,

    const ClassState = struct {
        class: Class,
        live_count: u32 = 0,
    };

    const OwnedMatcher = struct {
        matcher: Matcher,

        fn deinit(self: *OwnedMatcher, allocator: std.mem.Allocator) void {
            allocator.free(self.matcher.pattern);
            allocator.free(self.matcher.class_name);
            self.* = undefined;
        }
    };

    /// Initialize a registry with default bounds.
    pub fn init(allocator: std.mem.Allocator) Registry {
        return initWithParams(allocator, .{});
    }

    /// Initialize a registry with explicit bounds.
    pub fn initWithParams(allocator: std.mem.Allocator, params: Params) Registry {
        return .{
            .allocator = allocator,
            .params = params,
            .classes = std.StringHashMap(ClassState).init(allocator),
        };
    }

    /// Release all owned class and matcher strings.
    pub fn deinit(self: *Registry) void {
        self.clearMatchers();

        var it = self.classes.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.classes.deinit();
        self.* = undefined;
    }

    /// Add or replace a class definition, preserving the live counter.
    pub fn addClass(self: *Registry, class: Class) RegistryError!void {
        try self.validateClass(class);

        if (self.classes.getEntry(class.name)) |entry| {
            entry.value_ptr.class = withOwnedName(entry.key_ptr.*, class);
            if (std.ascii.eqlIgnoreCase(class.name, "default")) {
                self.default_name = entry.key_ptr.*;
            }
            return;
        }

        if (self.classes.count() >= self.params.max_classes) return error.TooManyClasses;

        const owned_name = try self.allocator.dupe(u8, class.name);
        errdefer self.allocator.free(owned_name);

        try self.classes.putNoClobber(owned_name, .{ .class = withOwnedName(owned_name, class) });

        if (self.default_name == null or std.ascii.eqlIgnoreCase(owned_name, "default")) {
            self.default_name = owned_name;
        }
    }

    /// Add an ordered matcher. First matching matcher wins.
    pub fn addMatcher(self: *Registry, pattern: []const u8, class_name: []const u8) RegistryError!void {
        try self.validatePattern(pattern);
        try self.validateClassName(class_name);
        if (!self.classes.contains(class_name)) return error.UnknownClass;
        if (self.matchers.items.len >= self.params.max_matchers) return error.TooManyMatchers;

        const owned_pattern = try self.allocator.dupe(u8, pattern);
        errdefer self.allocator.free(owned_pattern);
        const owned_class_name = try self.allocator.dupe(u8, class_name);
        errdefer self.allocator.free(owned_class_name);

        try self.matchers.append(self.allocator, .{
            .matcher = .{
                .pattern = owned_pattern,
                .class_name = owned_class_name,
            },
        });
    }

    /// Return the first matched class for a host/address, or the default class.
    pub fn classFor(self: *const Registry, host_or_ip: []const u8) ?*const Class {
        for (self.matchers.items) |*owned| {
            if (globMatch(owned.matcher.pattern, host_or_ip)) {
                if (self.get(owned.matcher.class_name)) |class| return class;
            }
        }

        const name = self.default_name orelse return null;
        return self.get(name);
    }

    /// Increment the live connection count for a class.
    pub fn incr(self: *Registry, class_name: []const u8) RegistryError!void {
        const state = self.classes.getPtr(class_name) orelse return error.UnknownClass;
        if (state.live_count == std.math.maxInt(u32)) return error.CountOverflow;
        state.live_count += 1;
    }

    /// Decrement the live connection count for a class.
    pub fn decr(self: *Registry, class_name: []const u8) RegistryError!void {
        const state = self.classes.getPtr(class_name) orelse return error.UnknownClass;
        if (state.live_count > 0) state.live_count -= 1;
    }

    /// Return true when another live connection would exceed the class cap.
    pub fn wouldExceed(self: *const Registry, class_name: []const u8) bool {
        const state = self.classes.getPtr(class_name) orelse return true;
        return state.live_count >= state.class.max_connections_total;
    }

    /// Return the class definition for a name.
    pub fn get(self: *const Registry, name: []const u8) ?*const Class {
        const state = self.classes.getPtr(name) orelse return null;
        return &state.class;
    }

    /// Return the current live connection count for a name.
    pub fn count(self: *const Registry, name: []const u8) ?u32 {
        const state = self.classes.getPtr(name) orelse return null;
        return state.live_count;
    }

    fn validateClass(self: *const Registry, class: Class) RegistryError!void {
        try self.validateClassName(class.name);
    }

    fn validateClassName(self: *const Registry, name: []const u8) RegistryError!void {
        if (name.len == 0) return error.EmptyClassName;
        if (name.len > self.params.max_class_name_bytes) return error.ClassNameTooLong;
    }

    fn validatePattern(self: *const Registry, pattern: []const u8) RegistryError!void {
        if (pattern.len == 0) return error.EmptyPattern;
        if (pattern.len > self.params.max_pattern_bytes) return error.PatternTooLong;
    }

    fn clearMatchers(self: *Registry) void {
        for (self.matchers.items) |*owned| {
            owned.deinit(self.allocator);
        }
        self.matchers.deinit(self.allocator);
    }
};

fn withOwnedName(owned_name: []const u8, class: Class) Class {
    return .{
        .name = owned_name,
        .max_clients = class.max_clients,
        .max_per_ip = class.max_per_ip,
        .ping_frequency_secs = class.ping_frequency_secs,
        .sendq_bytes = class.sendq_bytes,
        .recvq_bytes = class.recvq_bytes,
        .max_connections_total = class.max_connections_total,
    };
}

fn globMatch(pattern: []const u8, text: []const u8) bool {
    var pattern_i: usize = 0;
    var text_i: usize = 0;
    var star_i: ?usize = null;
    var retry_text_i: usize = 0;

    while (text_i < text.len) {
        if (pattern_i < pattern.len and (pattern[pattern_i] == '?' or asciiEqual(pattern[pattern_i], text[text_i]))) {
            pattern_i += 1;
            text_i += 1;
        } else if (pattern_i < pattern.len and pattern[pattern_i] == '*') {
            star_i = pattern_i;
            pattern_i += 1;
            retry_text_i = text_i;
        } else if (star_i) |star| {
            pattern_i = star + 1;
            retry_text_i += 1;
            text_i = retry_text_i;
        } else {
            return false;
        }
    }

    while (pattern_i < pattern.len and pattern[pattern_i] == '*') {
        pattern_i += 1;
    }

    return pattern_i == pattern.len;
}

fn asciiEqual(a: u8, b: u8) bool {
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

fn testClass(name: []const u8, cap: u32) Class {
    return .{
        .name = name,
        .max_clients = cap,
        .max_per_ip = 2,
        .ping_frequency_secs = 120,
        .sendq_bytes = 1024 * 1024,
        .recvq_bytes = 64 * 1024,
        .max_connections_total = cap,
    };
}

test "matcher ordering returns the first matching class" {
    // Arrange
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.addClass(testClass("default", 10));
    try registry.addClass(testClass("general", 20));
    try registry.addClass(testClass("staff", 30));
    try registry.addMatcher("*.example.test", "general");
    try registry.addMatcher("staff.example.test", "staff");

    // Act
    const class = registry.classFor("staff.example.test").?;

    // Assert
    try std.testing.expectEqualStrings("general", class.name);
}

test "default fallback returns the first added class" {
    // Arrange
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.addClass(testClass("fallback", 42));
    try registry.addClass(testClass("other", 7));

    // Act
    const class = registry.classFor("unmatched.example.test").?;

    // Assert
    try std.testing.expectEqualStrings("fallback", class.name);
    try std.testing.expectEqual(@as(u32, 42), class.max_connections_total);
}

test "class named default becomes fallback" {
    // Arrange
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.addClass(testClass("first", 1));
    try registry.addClass(testClass("default", 9));

    // Act
    const class = registry.classFor("unmatched.example.test").?;

    // Assert
    try std.testing.expectEqualStrings("default", class.name);
}

test "per-class counts reach cap and decr reopens capacity" {
    // Arrange
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.addClass(testClass("limited", 2));

    // Act and assert
    try std.testing.expect(!registry.wouldExceed("limited"));
    try registry.incr("limited");
    try std.testing.expectEqual(@as(?u32, 1), registry.count("limited"));
    try std.testing.expect(!registry.wouldExceed("limited"));
    try registry.incr("limited");
    try std.testing.expectEqual(@as(?u32, 2), registry.count("limited"));
    try std.testing.expect(registry.wouldExceed("limited"));
    try registry.decr("limited");
    try std.testing.expectEqual(@as(?u32, 1), registry.count("limited"));
    try std.testing.expect(!registry.wouldExceed("limited"));
}

test "glob host matching supports star question and case folding" {
    // Arrange
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.addClass(testClass("default", 1));
    try registry.addClass(testClass("ipv4", 2));
    try registry.addClass(testClass("host", 3));
    try registry.addMatcher("203.0.113.?", "ipv4");
    try registry.addMatcher("*.Example.NET", "host");

    // Act
    const ip_class = registry.classFor("203.0.113.7").?;
    const host_class = registry.classFor("Client.EXAMPLE.net").?;
    const fallback_class = registry.classFor("203.0.113.77").?;

    // Assert
    try std.testing.expectEqualStrings("ipv4", ip_class.name);
    try std.testing.expectEqualStrings("host", host_class.name);
    try std.testing.expectEqualStrings("default", fallback_class.name);
}

test "classes and matchers own caller strings" {
    // Arrange
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    var class_name = [_]u8{ 'e', 'd', 'g', 'e' };
    var pattern = [_]u8{ '*', '.', 'e', 'd', 'g', 'e' };
    try registry.addClass(testClass(class_name[0..], 5));
    try registry.addMatcher(pattern[0..], class_name[0..]);
    @memset(class_name[0..], 'x');
    @memset(pattern[0..], 'x');

    // Act
    const class = registry.classFor("client.edge").?;

    // Assert
    try std.testing.expectEqualStrings("edge", class.name);
}

test "invalid entries return typed errors" {
    // Arrange
    const allocator = std.testing.allocator;
    var registry = Registry.initWithParams(allocator, .{
        .max_classes = 1,
        .max_matchers = 1,
        .max_class_name_bytes = 4,
        .max_pattern_bytes = 8,
    });
    defer registry.deinit();

    // Act and assert
    try std.testing.expectError(error.EmptyClassName, registry.addClass(testClass("", 1)));
    try std.testing.expectError(error.ClassNameTooLong, registry.addClass(testClass("longer", 1)));
    try registry.addClass(testClass("main", 1));
    try std.testing.expectError(error.TooManyClasses, registry.addClass(testClass("next", 1)));
    try std.testing.expectError(error.EmptyPattern, registry.addMatcher("", "main"));
    try std.testing.expectError(error.PatternTooLong, registry.addMatcher("too-long-pattern", "main"));
    try std.testing.expectError(error.UnknownClass, registry.addMatcher("*", "none"));
    try registry.addMatcher("*", "main");
    try std.testing.expectError(error.TooManyMatchers, registry.addMatcher("?", "main"));
}

test "unknown counters fail closed without mutating known classes" {
    // Arrange
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.addClass(testClass("known", 1));

    // Act and assert
    try std.testing.expect(registry.wouldExceed("missing"));
    try std.testing.expectError(error.UnknownClass, registry.incr("missing"));
    try std.testing.expectError(error.UnknownClass, registry.decr("missing"));
    try std.testing.expectEqual(@as(?u32, 0), registry.count("known"));
}
