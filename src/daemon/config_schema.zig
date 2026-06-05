//! config_schema — typed configuration schema, parser, and validation layer.
//! Format: `[section]` headers, `key = value`, `# comments`, quoted strings
//! with `\"` and `\\` escapes, lists `key = [a, b, c]`, and
//! `${VAR}` / `${VAR:-default}` interpolation.
//! Build a `Schema`, call `parse` → `ParsedDoc`, call `Schema.validate`
//! → `ValidatedConfig` or a `Diagnostic` list with line/column positions.
//! Self-contained: imports only `std`. No sibling files.

const std = @import("std");

/// The canonical type tag for a config value declared in a Schema.
pub const ValueTag = enum { string, int, bool, duration, size, @"enum", list };

/// A parsed, unvalidated raw value with source location.
pub const RawValue = struct { text: []const u8, loc: Loc };

/// Source location (1-based).
pub const Loc = struct { line: u32, col: u32 };

/// One section in the parsed document.
/// Keys/values are arena-owned; bucket storage uses the outer allocator.
pub const ParsedSection = struct {
    name: []const u8,
    loc: Loc,
    entries: std.StringHashMap(RawValue),

    fn init(ha: std.mem.Allocator, name: []const u8, loc: Loc) ParsedSection {
        return .{ .name = name, .loc = loc, .entries = std.StringHashMap(RawValue).init(ha) };
    }
    fn deinit(self: *ParsedSection) void {
        self.entries.deinit();
    }
};

/// Top-level parse result. Call `deinit` to free.
pub const ParsedDoc = struct {
    arena: std.heap.ArenaAllocator,
    outer_alloc: std.mem.Allocator,
    sections: std.ArrayList(ParsedSection),

    pub fn deinit(self: *ParsedDoc) void {
        for (self.sections.items) |*s| s.deinit();
        self.sections.deinit(self.outer_alloc);
        self.arena.deinit();
    }
};

pub const ParseError = error{
    OutOfMemory,
    UnterminatedString,
    InvalidEscape,
    UnterminatedEnvVar,
    UnsetEnvVar,
    DuplicateKey,
    DuplicateSection,
    MissingEquals,
    InvalidList,
    EmptyKey,
};

/// Parse a config document.
/// `env_lookup`: called for `${VAR}` references; pass `null` to skip
/// interpolation. Unresolved vars with no `:-default` → `error.UnsetEnvVar`.
pub fn parse(
    outer_allocator: std.mem.Allocator,
    input: []const u8,
    env_lookup: ?*const fn ([]const u8) ?[]const u8,
) ParseError!ParsedDoc {
    var doc = ParsedDoc{
        .arena = std.heap.ArenaAllocator.init(outer_allocator),
        .outer_alloc = outer_allocator,
        .sections = std.ArrayList(ParsedSection).empty,
    };
    errdefer {
        for (doc.sections.items) |*s| s.deinit();
        doc.sections.deinit(outer_allocator);
        doc.arena.deinit();
    }
    const arena = doc.arena.allocator();
    var current: ?*ParsedSection = null;
    var line_no: u32 = 0;
    var iter = std.mem.splitScalar(u8, input, '\n');

    while (iter.next()) |raw_line| {
        line_no += 1;
        const trimmed = std.mem.trim(u8, stripComment(trimRight(raw_line)), " \t");
        if (trimmed.len == 0) continue;

        if (trimmed[0] == '[') {
            if (!std.mem.endsWith(u8, trimmed, "]")) return error.MissingEquals;
            const name = std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t");
            for (doc.sections.items) |*s| {
                if (std.mem.eql(u8, s.name, name)) return error.DuplicateSection;
            }
            const owned = try arena.dupe(u8, name);
            try doc.sections.append(outer_allocator, ParsedSection.init(outer_allocator, owned, .{ .line = line_no, .col = 1 }));
            current = &doc.sections.items[doc.sections.items.len - 1];
        } else {
            const eq = std.mem.indexOfScalar(u8, trimmed, '=') orelse return error.MissingEquals;
            const key = std.mem.trim(u8, trimmed[0..eq], " \t");
            if (key.len == 0) return error.EmptyKey;
            const raw_val = std.mem.trim(u8, trimmed[eq + 1 ..], " \t");
            const val_col: u32 = @intCast(eq + 2);
            const cooked = try interpolate(arena, raw_val, env_lookup);
            const owned_key = try arena.dupe(u8, key);
            if (current == null) {
                try doc.sections.append(outer_allocator, ParsedSection.init(outer_allocator, try arena.dupe(u8, ""), .{ .line = line_no, .col = 1 }));
                current = &doc.sections.items[doc.sections.items.len - 1];
            }
            const gop = try current.?.entries.getOrPut(owned_key);
            if (gop.found_existing) return error.DuplicateKey;
            gop.value_ptr.* = .{ .text = cooked, .loc = .{ .line = line_no, .col = val_col } };
        }
    }
    return doc;
}

fn stripComment(line: []const u8) []const u8 {
    var in_q = false;
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        switch (line[i]) {
            '"' => in_q = !in_q,
            '\\' => if (in_q) {
                i += 1;
            },
            '#' => if (!in_q) return line[0..i],
            else => {},
        }
    }
    return line;
}

fn trimRight(s: []const u8) []const u8 {
    var e = s.len;
    while (e > 0 and (s[e - 1] == '\r' or s[e - 1] == ' ' or s[e - 1] == '\t')) e -= 1;
    return s[0..e];
}

fn interpolate(
    arena: std.mem.Allocator,
    raw: []const u8,
    lookup: ?*const fn ([]const u8) ?[]const u8,
) ParseError![]const u8 {
    if (std.mem.indexOf(u8, raw, "${") == null) return processToken(arena, raw);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(arena);
    var i: usize = 0;
    while (i < raw.len) {
        if (i + 1 < raw.len and raw[i] == '$' and raw[i + 1] == '{') {
            const start = i + 2;
            const end = std.mem.indexOfScalarPos(u8, raw, start, '}') orelse return error.UnterminatedEnvVar;
            const spec = raw[start..end];
            var var_name: []const u8 = spec;
            var fallback: ?[]const u8 = null;
            if (std.mem.indexOf(u8, spec, ":-")) |dash| {
                var_name = spec[0..dash];
                fallback = spec[dash + 2 ..];
            }
            const value: []const u8 = blk: {
                if (lookup) |lf| if (lf(var_name)) |v| break :blk v;
                if (fallback) |fb| break :blk fb;
                return error.UnsetEnvVar;
            };
            try out.appendSlice(arena, value);
            i = end + 1;
        } else if (raw[i] == '"') {
            const seg = try decodeQuoted(arena, raw[i..]);
            try out.appendSlice(arena, seg.text);
            i += seg.consumed;
        } else {
            try out.append(arena, raw[i]);
            i += 1;
        }
    }
    return out.toOwnedSlice(arena);
}

const QuoteResult = struct { text: []const u8, consumed: usize };

fn decodeQuoted(arena: std.mem.Allocator, raw: []const u8) ParseError!QuoteResult {
    if (raw.len < 2 or raw[0] != '"')
        return .{ .text = try arena.dupe(u8, raw), .consumed = raw.len };
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(arena);
    var i: usize = 1;
    while (i < raw.len) {
        switch (raw[i]) {
            '"' => {
                i += 1;
                return .{ .text = try buf.toOwnedSlice(arena), .consumed = i };
            },
            '\\' => {
                i += 1;
                if (i >= raw.len) return error.InvalidEscape;
                switch (raw[i]) {
                    '"' => try buf.append(arena, '"'),
                    '\\' => try buf.append(arena, '\\'),
                    'n' => try buf.append(arena, '\n'),
                    'r' => try buf.append(arena, '\r'),
                    't' => try buf.append(arena, '\t'),
                    else => return error.InvalidEscape,
                }
                i += 1;
            },
            else => {
                try buf.append(arena, raw[i]);
                i += 1;
            },
        }
    }
    return error.UnterminatedString;
}

fn processToken(arena: std.mem.Allocator, raw: []const u8) ParseError![]const u8 {
    if (raw.len >= 2 and raw[0] == '"') return (try decodeQuoted(arena, raw)).text;
    return arena.dupe(u8, raw);
}

// ── Duration and Size helpers ─────────────────────────────────────────────────

pub const DurationError = error{ InvalidDuration, Overflow };
pub const SizeError = error{ InvalidSize, Overflow };

/// Parse a duration string into milliseconds. Units: ms, s, m, h.
pub fn parseDuration(s: []const u8) DurationError!i64 {
    if (s.len == 0) return error.InvalidDuration;
    if (std.mem.endsWith(u8, s, "ms"))
        return std.fmt.parseInt(i64, s[0 .. s.len - 2], 10) catch error.InvalidDuration;
    if (std.mem.endsWith(u8, s, "s")) {
        const n = std.fmt.parseInt(i64, s[0 .. s.len - 1], 10) catch return error.InvalidDuration;
        return std.math.mul(i64, n, 1_000) catch error.Overflow;
    }
    if (std.mem.endsWith(u8, s, "m")) {
        const n = std.fmt.parseInt(i64, s[0 .. s.len - 1], 10) catch return error.InvalidDuration;
        return std.math.mul(i64, n, 60_000) catch error.Overflow;
    }
    if (std.mem.endsWith(u8, s, "h")) {
        const n = std.fmt.parseInt(i64, s[0 .. s.len - 1], 10) catch return error.InvalidDuration;
        return std.math.mul(i64, n, 3_600_000) catch error.Overflow;
    }
    return error.InvalidDuration;
}

/// Parse a size string into bytes. Units: b, kb, mb, gb (case-insensitive).
pub fn parseSize(s: []const u8) SizeError!i64 {
    if (s.len == 0) return error.InvalidSize;
    var lb: [16]u8 = undefined;
    const ll = @min(s.len, lb.len);
    for (s[0..ll], 0..) |c, j| lb[j] = std.ascii.toLower(c);
    const lower = lb[0..ll];
    const mul: i64, const de: usize = blk: {
        if (std.mem.endsWith(u8, lower, "gb")) break :blk .{ 1024 * 1024 * 1024, s.len - 2 };
        if (std.mem.endsWith(u8, lower, "mb")) break :blk .{ 1024 * 1024, s.len - 2 };
        if (std.mem.endsWith(u8, lower, "kb")) break :blk .{ 1024, s.len - 2 };
        if (std.mem.endsWith(u8, lower, "b")) break :blk .{ 1, s.len - 1 };
        if (std.fmt.parseInt(i64, s, 10)) |_| break :blk .{ 1, s.len } else |_| return error.InvalidSize;
    };
    const n = std.fmt.parseInt(i64, s[0..de], 10) catch return error.InvalidSize;
    return std.math.mul(i64, n, mul) catch error.Overflow;
}

// ── List parser ───────────────────────────────────────────────────────────────

/// Parse `["a", "b"]` or `[bare, tokens]` into arena-owned string slice.
pub fn parseList(arena: std.mem.Allocator, raw: []const u8) ParseError![]const []const u8 {
    const s = std.mem.trim(u8, raw, " \t");
    if (s.len < 2 or s[0] != '[' or s[s.len - 1] != ']') return error.InvalidList;
    const body = s[1 .. s.len - 1];
    var items: std.ArrayList([]const u8) = .empty;
    errdefer items.deinit(arena);
    var i: usize = 0;
    while (i < body.len) {
        i = skipWs(body, i);
        if (i >= body.len) break;
        if (body[i] == '"') {
            const res = try decodeQuoted(arena, body[i..]);
            try items.append(arena, res.text);
            i += res.consumed;
        } else if (body[i] == ',') {
            return error.InvalidList;
        } else {
            const start = i;
            while (i < body.len and body[i] != ',' and body[i] != ' ' and body[i] != '\t') i += 1;
            if (i == start) return error.InvalidList;
            try items.append(arena, try arena.dupe(u8, body[start..i]));
        }
        i = skipWs(body, i);
        if (i < body.len) {
            if (body[i] == ',') i += 1 else return error.InvalidList;
        }
    }
    return items.toOwnedSlice(arena);
}

fn skipWs(s: []const u8, start: usize) usize {
    var i = start;
    while (i < s.len and (s[i] == ' ' or s[i] == '\t')) i += 1;
    return i;
}

// ── Schema ────────────────────────────────────────────────────────────────────

/// Default value for a schema key.
pub const Default = union(ValueTag) {
    string: []const u8,
    int: i64,
    bool: bool,
    duration: i64,
    size: i64,
    @"enum": []const u8,
    list: []const []const u8,
};

/// Descriptor for one config key within a section.
pub const KeyDesc = struct {
    name: []const u8,
    tag: ValueTag,
    required: bool = false,
    default: ?Default = null,
    int_min: ?i64 = null, // inclusive; null = unbounded
    int_max: ?i64 = null,
    allowed_enum: []const []const u8 = &.{},
};

/// Descriptor for a config section.
pub const SectionDesc = struct {
    name: []const u8,
    keys: []const KeyDesc,
};

/// Diagnostic severity / category.
pub const DiagKind = enum { unknown_section, unknown_key, missing_required, type_mismatch, out_of_range, bad_enum };

pub const Diagnostic = struct { loc: Loc, kind: DiagKind, message: []const u8 };

/// Free the diagnostic messages (each allocated with the same allocator passed
/// to `validate`) and the list. Messages are caller-owned because `diags`
/// outlives `validate`'s internal arena, which is released on the failure path.
pub fn freeDiagnostics(alloc: std.mem.Allocator, diags: *std.ArrayList(Diagnostic)) void {
    for (diags.items) |d| alloc.free(d.message);
    diags.deinit(alloc);
}

/// Full schema: a slice of section descriptors.
pub const Schema = struct {
    sections: []const SectionDesc,

    /// Validate `doc` against this schema.
    /// On success returns a `ValidatedConfig`. On failure appends diagnostics
    /// to `diags` and returns `error.ValidationFailed`.
    pub fn validate(
        self: Schema,
        doc: *const ParsedDoc,
        outer_alloc: std.mem.Allocator,
        diags: *std.ArrayList(Diagnostic),
    ) (error{ValidationFailed} || std.mem.Allocator.Error)!ValidatedConfig {
        var arena = std.heap.ArenaAllocator.init(outer_alloc);
        errdefer arena.deinit();
        const a = arena.allocator();
        var sections = std.StringHashMap(SectionValues).init(a);

        // Unknown sections
        for (doc.sections.items) |*ps| {
            if (ps.name.len == 0) continue;
            const ok = for (self.sections) |sd| {
                if (std.mem.eql(u8, sd.name, ps.name)) break true;
            } else false;
            if (!ok) try diags.append(outer_alloc, .{
                .loc = ps.loc,
                .kind = .unknown_section,
                .message = try std.fmt.allocPrint(outer_alloc, "unknown section '{s}'", .{ps.name}),
            });
        }

        for (self.sections) |sd| {
            const ps_opt: ?*const ParsedSection = for (doc.sections.items) |*ps| {
                if (std.mem.eql(u8, ps.name, sd.name)) break ps;
            } else null;

            var sv = SectionValues.init(a);

            for (sd.keys) |kd| {
                const rv_opt: ?RawValue = if (ps_opt) |ps| ps.entries.get(kd.name) else null;
                if (rv_opt == null) {
                    if (kd.required and kd.default == null) {
                        const loc = if (ps_opt) |ps| ps.loc else Loc{ .line = 0, .col = 0 };
                        try diags.append(outer_alloc, .{
                            .loc = loc,
                            .kind = .missing_required,
                            .message = try std.fmt.allocPrint(outer_alloc, "section '{s}': missing required key '{s}'", .{ sd.name, kd.name }),
                        });
                        continue;
                    }
                    if (kd.default) |d| try sv.put(kd.name, .{ .tag = kd.tag, .data = defaultToData(d) });
                    continue;
                }
                if (try coerceValue(a, outer_alloc, rv_opt.?, kd, diags)) |cv| try sv.put(kd.name, cv);
            }

            // Unknown keys
            if (ps_opt) |ps| {
                var kit = ps.entries.iterator();
                while (kit.next()) |e| {
                    const key = e.key_ptr.*;
                    const known = for (sd.keys) |kd| {
                        if (std.mem.eql(u8, kd.name, key)) break true;
                    } else false;
                    if (!known) try diags.append(outer_alloc, .{
                        .loc = e.value_ptr.loc,
                        .kind = .unknown_key,
                        .message = try std.fmt.allocPrint(outer_alloc, "section '{s}': unknown key '{s}'", .{ sd.name, key }),
                    });
                }
            }
            try sections.put(try a.dupe(u8, sd.name), sv);
        }

        if (diags.items.len > 0) return error.ValidationFailed;
        return ValidatedConfig{ .arena = arena, .sections = sections };
    }
};

fn defaultToData(d: Default) CoercedData {
    return switch (d) {
        .string => |v| .{ .string = v },
        .int => |v| .{ .int = v },
        .bool => |v| .{ .bool = v },
        .duration => |v| .{ .duration = v },
        .size => |v| .{ .size = v },
        .@"enum" => |v| .{ .@"enum" = v },
        .list => |v| .{ .list = v },
    };
}

fn coerceValue(
    a: std.mem.Allocator,
    da: std.mem.Allocator,
    rv: RawValue,
    kd: KeyDesc,
    diags: *std.ArrayList(Diagnostic),
) std.mem.Allocator.Error!?CoercedValue {
    switch (kd.tag) {
        .string => return CoercedValue{ .tag = .string, .data = .{ .string = rv.text } },
        .int => {
            const n = std.fmt.parseInt(i64, rv.text, 10) catch {
                try diags.append(da, .{ .loc = rv.loc, .kind = .type_mismatch, .message = try std.fmt.allocPrint(da, "key '{s}': expected integer, got '{s}'", .{ kd.name, rv.text }) });
                return null;
            };
            if (kd.int_min) |mn| if (n < mn) {
                try diags.append(da, .{ .loc = rv.loc, .kind = .out_of_range, .message = try std.fmt.allocPrint(da, "key '{s}': {d} < min {d}", .{ kd.name, n, mn }) });
                return null;
            };
            if (kd.int_max) |mx| if (n > mx) {
                try diags.append(da, .{ .loc = rv.loc, .kind = .out_of_range, .message = try std.fmt.allocPrint(da, "key '{s}': {d} > max {d}", .{ kd.name, n, mx }) });
                return null;
            };
            return CoercedValue{ .tag = .int, .data = .{ .int = n } };
        },
        .bool => {
            if (std.mem.eql(u8, rv.text, "true")) return CoercedValue{ .tag = .bool, .data = .{ .bool = true } };
            if (std.mem.eql(u8, rv.text, "false")) return CoercedValue{ .tag = .bool, .data = .{ .bool = false } };
            try diags.append(da, .{ .loc = rv.loc, .kind = .type_mismatch, .message = try std.fmt.allocPrint(da, "key '{s}': expected bool, got '{s}'", .{ kd.name, rv.text }) });
            return null;
        },
        .duration => {
            const ms = parseDuration(rv.text) catch {
                try diags.append(da, .{ .loc = rv.loc, .kind = .type_mismatch, .message = try std.fmt.allocPrint(da, "key '{s}': invalid duration '{s}'", .{ kd.name, rv.text }) });
                return null;
            };
            return CoercedValue{ .tag = .duration, .data = .{ .duration = ms } };
        },
        .size => {
            const bytes = parseSize(rv.text) catch {
                try diags.append(da, .{ .loc = rv.loc, .kind = .type_mismatch, .message = try std.fmt.allocPrint(da, "key '{s}': invalid size '{s}'", .{ kd.name, rv.text }) });
                return null;
            };
            return CoercedValue{ .tag = .size, .data = .{ .size = bytes } };
        },
        .@"enum" => {
            for (kd.allowed_enum) |al| if (std.mem.eql(u8, rv.text, al)) return CoercedValue{ .tag = .@"enum", .data = .{ .@"enum" = rv.text } };
            try diags.append(da, .{ .loc = rv.loc, .kind = .bad_enum, .message = try std.fmt.allocPrint(da, "key '{s}': '{s}' not allowed", .{ kd.name, rv.text }) });
            return null;
        },
        .list => {
            const items = parseList(a, rv.text) catch {
                try diags.append(da, .{ .loc = rv.loc, .kind = .type_mismatch, .message = try std.fmt.allocPrint(da, "key '{s}': invalid list", .{kd.name}) });
                return null;
            };
            return CoercedValue{ .tag = .list, .data = .{ .list = items } };
        },
    }
}

// ── Validated config ──────────────────────────────────────────────────────────

const CoercedData = union(ValueTag) {
    string: []const u8,
    int: i64,
    bool: bool,
    duration: i64,
    size: i64,
    @"enum": []const u8,
    list: []const []const u8,
};
const CoercedValue = struct { tag: ValueTag, data: CoercedData };
const SectionValues = std.StringHashMap(CoercedValue);

/// Successfully validated configuration. Call `deinit` to free.
pub const ValidatedConfig = struct {
    arena: std.heap.ArenaAllocator,
    sections: std.StringHashMap(SectionValues),

    pub fn deinit(self: *ValidatedConfig) void {
        self.arena.deinit();
    }

    fn get(self: *const ValidatedConfig, sec: []const u8, key: []const u8) ?CoercedValue {
        const sv = self.sections.get(sec) orelse return null;
        return sv.get(key);
    }

    pub fn getString(self: *const ValidatedConfig, sec: []const u8, key: []const u8) ?[]const u8 {
        const cv = self.get(sec, key) orelse return null;
        return if (cv.tag == .string) cv.data.string else null;
    }
    pub fn getInt(self: *const ValidatedConfig, sec: []const u8, key: []const u8) ?i64 {
        const cv = self.get(sec, key) orelse return null;
        return if (cv.tag == .int) cv.data.int else null;
    }
    pub fn getBool(self: *const ValidatedConfig, sec: []const u8, key: []const u8) ?bool {
        const cv = self.get(sec, key) orelse return null;
        return if (cv.tag == .bool) cv.data.bool else null;
    }
    pub fn getDuration(self: *const ValidatedConfig, sec: []const u8, key: []const u8) ?i64 {
        const cv = self.get(sec, key) orelse return null;
        return if (cv.tag == .duration) cv.data.duration else null;
    }
    pub fn getSize(self: *const ValidatedConfig, sec: []const u8, key: []const u8) ?i64 {
        const cv = self.get(sec, key) orelse return null;
        return if (cv.tag == .size) cv.data.size else null;
    }
    pub fn getEnum(self: *const ValidatedConfig, sec: []const u8, key: []const u8) ?[]const u8 {
        const cv = self.get(sec, key) orelse return null;
        return if (cv.tag == .@"enum") cv.data.@"enum" else null;
    }
    pub fn getList(self: *const ValidatedConfig, sec: []const u8, key: []const u8) ?[]const []const u8 {
        const cv = self.get(sec, key) orelse return null;
        return if (cv.tag == .list) cv.data.list else null;
    }
};

// ── Tests ─────────────────────────────────────────────────────────────────────

test "parse representative multi-section config" {
    const alloc = std.testing.allocator;
    const input =
        \\# Mizuchi config example
        \\[server]
        \\name = "irc.mizuchi.test"
        \\port = 6667
        \\tls = false
        \\[tls]
        \\cert = "/etc/ssl/cert.pem"
        \\timeout = 30s
        \\[limits]
        \\max_clients = 4096
        \\sendq = 1mb
    ;
    var doc = try parse(alloc, input, null);
    defer doc.deinit();
    try std.testing.expectEqual(@as(usize, 3), doc.sections.items.len);
    try std.testing.expectEqualStrings("irc.mizuchi.test", doc.sections.items[0].entries.get("name").?.text);
    try std.testing.expectEqualStrings("6667", doc.sections.items[0].entries.get("port").?.text);
    try std.testing.expectEqualStrings("/etc/ssl/cert.pem", doc.sections.items[1].entries.get("cert").?.text);
    try std.testing.expectEqualStrings("30s", doc.sections.items[1].entries.get("timeout").?.text);
    try std.testing.expectEqualStrings("1mb", doc.sections.items[2].entries.get("sendq").?.text);
    try std.testing.expectEqual(@as(u32, 2), doc.sections.items[0].loc.line);
}

test "comments and blank lines ignored; trailing comment stripped" {
    const alloc = std.testing.allocator;
    var doc = try parse(alloc,
        \\# top
        \\
        \\[net]
        \\host = "127.0.0.1" # trailing
        \\
    , null);
    defer doc.deinit();
    try std.testing.expectEqual(@as(usize, 1), doc.sections.items.len);
    try std.testing.expectEqualStrings("127.0.0.1", doc.sections.items[0].entries.get("host").?.text);
}

test "quoted string escape sequences" {
    const alloc = std.testing.allocator;
    var doc = try parse(alloc,
        \\[msg]
        \\text = "hello \"world\""
        \\path = "C:\\Users\\kain"
        \\tab = "col1\tcol2"
    , null);
    defer doc.deinit();
    const s = doc.sections.items[0];
    try std.testing.expectEqualStrings("hello \"world\"", s.entries.get("text").?.text);
    try std.testing.expectEqualStrings("C:\\Users\\kain", s.entries.get("path").?.text);
    try std.testing.expectEqualStrings("col1\tcol2", s.entries.get("tab").?.text);
}

test "list parsing: quoted and bare tokens, empty" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const q = try parseList(a, "[\"rehash\", \"die\"]");
    try std.testing.expectEqual(@as(usize, 2), q.len);
    try std.testing.expectEqualStrings("rehash", q[0]);
    try std.testing.expectEqualStrings("die", q[1]);

    const b = try parseList(a, "[alpha, beta, gamma]");
    try std.testing.expectEqual(@as(usize, 3), b.len);
    try std.testing.expectEqualStrings("alpha", b[0]);

    const empty = try parseList(a, "[]");
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "duration parsing valid and invalid" {
    try std.testing.expectEqual(@as(i64, 500), try parseDuration("500ms"));
    try std.testing.expectEqual(@as(i64, 30_000), try parseDuration("30s"));
    try std.testing.expectEqual(@as(i64, 300_000), try parseDuration("5m"));
    try std.testing.expectEqual(@as(i64, 3_600_000), try parseDuration("1h"));
    try std.testing.expectEqual(@as(i64, 7_200_000), try parseDuration("2h"));
    try std.testing.expectError(error.InvalidDuration, parseDuration("10x"));
    try std.testing.expectError(error.InvalidDuration, parseDuration("5days"));
    try std.testing.expectError(error.InvalidDuration, parseDuration(""));
}

test "size parsing valid and invalid" {
    try std.testing.expectEqual(@as(i64, 65536), try parseSize("64kb"));
    try std.testing.expectEqual(@as(i64, 65536), try parseSize("64KB"));
    try std.testing.expectEqual(@as(i64, 10 * 1024 * 1024), try parseSize("10mb"));
    try std.testing.expectEqual(@as(i64, 1024 * 1024 * 1024), try parseSize("1gb"));
    try std.testing.expectEqual(@as(i64, 512), try parseSize("512b"));
    try std.testing.expectEqual(@as(i64, 1024), try parseSize("1024"));
    try std.testing.expectError(error.InvalidSize, parseSize("10tb"));
    try std.testing.expectError(error.InvalidSize, parseSize(""));
    try std.testing.expectError(error.InvalidSize, parseSize("abc"));
}

test "env interpolation: lookup, default fallback, unset error" {
    const alloc = std.testing.allocator;
    const Env = struct {
        fn lookup(name: []const u8) ?[]const u8 {
            if (std.mem.eql(u8, name, "HOST")) return "irc.example.com";
            return null;
        }
    };
    // Successful lookup
    var doc = try parse(alloc, "[s]\nname = ${HOST}\nport = ${MISSING:-6697}", &Env.lookup);
    defer doc.deinit();
    try std.testing.expectEqualStrings("irc.example.com", doc.sections.items[0].entries.get("name").?.text);
    try std.testing.expectEqualStrings("6697", doc.sections.items[0].entries.get("port").?.text);
    // Unset with no fallback
    const NoEnv = struct {
        fn lookup(name: []const u8) ?[]const u8 {
            _ = name;
            return null;
        }
    };
    try std.testing.expectError(error.UnsetEnvVar, parse(alloc, "[s]\nx = ${GONE}", &NoEnv.lookup));
}

test "parse errors: duplicate key, duplicate section, missing equals, unterminated string, bad escape" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.DuplicateKey, parse(alloc, "[s]\np = 1\np = 2", null));
    try std.testing.expectError(error.DuplicateSection, parse(alloc, "[s]\n[s]", null));
    try std.testing.expectError(error.MissingEquals, parse(alloc, "[s]\nbadline", null));
    try std.testing.expectError(error.UnterminatedString, parse(alloc, "[s]\nn = \"oops", null));
    try std.testing.expectError(error.InvalidEscape, parse(alloc, "[s]\nn = \"bad\\q\"", null));
}

test "whitespace: leading/trailing around section and key" {
    const alloc = std.testing.allocator;
    var doc = try parse(alloc, "   [net]\n  host  =   \"127.0.0.1\"", null);
    defer doc.deinit();
    try std.testing.expectEqualStrings("net", doc.sections.items[0].name);
    try std.testing.expectEqualStrings("127.0.0.1", doc.sections.items[0].entries.get("host").?.text);
}

test "schema validation: full happy path with all value types" {
    const alloc = std.testing.allocator;
    const schema = Schema{ .sections = &.{.{ .name = "server", .keys = &.{
        .{ .name = "name", .tag = .string, .required = true },
        .{ .name = "port", .tag = .int, .required = true, .int_min = 1, .int_max = 65535 },
        .{ .name = "tls", .tag = .bool, .default = .{ .bool = false } },
        .{ .name = "timeout", .tag = .duration, .default = .{ .duration = 30_000 } },
        .{ .name = "sendq", .tag = .size, .default = .{ .size = 1024 * 1024 } },
        .{ .name = "level", .tag = .@"enum", .default = .{ .@"enum" = "info" }, .allowed_enum = &.{ "debug", "info", "warn" } },
        .{ .name = "tags", .tag = .list, .default = .{ .list = &.{} } },
    } }} };
    const input =
        \\[server]
        \\name = "irc.mizuchi.test"
        \\port = 6697
        \\tls = true
        \\timeout = 45s
        \\sendq = 2mb
        \\level = debug
        \\tags = ["alpha", "beta"]
    ;
    var doc = try parse(alloc, input, null);
    defer doc.deinit();
    var diags: std.ArrayList(Diagnostic) = .empty;
    defer freeDiagnostics(alloc, &diags);
    var cfg = try schema.validate(&doc, alloc, &diags);
    defer cfg.deinit();
    try std.testing.expectEqualStrings("irc.mizuchi.test", cfg.getString("server", "name").?);
    try std.testing.expectEqual(@as(i64, 6697), cfg.getInt("server", "port").?);
    try std.testing.expectEqual(true, cfg.getBool("server", "tls").?);
    try std.testing.expectEqual(@as(i64, 45_000), cfg.getDuration("server", "timeout").?);
    try std.testing.expectEqual(@as(i64, 2 * 1024 * 1024), cfg.getSize("server", "sendq").?);
    try std.testing.expectEqualStrings("debug", cfg.getEnum("server", "level").?);
    try std.testing.expectEqual(@as(usize, 2), cfg.getList("server", "tags").?.len);
}

test "schema validation: unknown key" {
    const alloc = std.testing.allocator;
    const schema = Schema{ .sections = &.{.{ .name = "s", .keys = &.{.{ .name = "a", .tag = .string, .required = true }} }} };
    var doc = try parse(alloc, "[s]\na = \"x\"\nunknown = 99", null);
    defer doc.deinit();
    var diags: std.ArrayList(Diagnostic) = .empty;
    defer freeDiagnostics(alloc, &diags);
    try std.testing.expectError(error.ValidationFailed, schema.validate(&doc, alloc, &diags));
    try std.testing.expectEqual(DiagKind.unknown_key, diags.items[0].kind);
}

test "schema validation: missing required key" {
    const alloc = std.testing.allocator;
    const schema = Schema{ .sections = &.{.{ .name = "s", .keys = &.{.{ .name = "name", .tag = .string, .required = true }} }} };
    var doc = try parse(alloc, "[s]\nport = 6667", null);
    defer doc.deinit();
    var diags: std.ArrayList(Diagnostic) = .empty;
    defer freeDiagnostics(alloc, &diags);
    try std.testing.expectError(error.ValidationFailed, schema.validate(&doc, alloc, &diags));
    var got_missing = false;
    for (diags.items) |d| if (d.kind == .missing_required) {
        got_missing = true;
    };
    try std.testing.expect(got_missing);
}

test "schema validation: type mismatch (int instead of bool)" {
    const alloc = std.testing.allocator;
    const schema = Schema{ .sections = &.{.{ .name = "s", .keys = &.{.{ .name = "tls", .tag = .bool, .required = true }} }} };
    var doc = try parse(alloc, "[s]\ntls = 42", null);
    defer doc.deinit();
    var diags: std.ArrayList(Diagnostic) = .empty;
    defer freeDiagnostics(alloc, &diags);
    try std.testing.expectError(error.ValidationFailed, schema.validate(&doc, alloc, &diags));
    try std.testing.expectEqual(DiagKind.type_mismatch, diags.items[0].kind);
}

test "schema validation: bad enum value with correct line number" {
    const alloc = std.testing.allocator;
    const schema = Schema{ .sections = &.{.{ .name = "logging", .keys = &.{.{
        .name = "level",
        .tag = .@"enum",
        .required = true,
        .allowed_enum = &.{ "debug", "info", "warn" },
    }} }} };
    var doc = try parse(alloc, "# line 1\n\n[logging]\nlevel = verbose", null);
    defer doc.deinit();
    var diags: std.ArrayList(Diagnostic) = .empty;
    defer freeDiagnostics(alloc, &diags);
    try std.testing.expectError(error.ValidationFailed, schema.validate(&doc, alloc, &diags));
    try std.testing.expectEqual(DiagKind.bad_enum, diags.items[0].kind);
    try std.testing.expectEqual(@as(u32, 4), diags.items[0].loc.line);
}

test "schema validation: out-of-range int and defaults" {
    const alloc = std.testing.allocator;
    const schema = Schema{ .sections = &.{.{ .name = "s", .keys = &.{
        .{ .name = "port", .tag = .int, .required = true, .int_min = 1, .int_max = 65535 },
        .{ .name = "tls", .tag = .bool, .default = .{ .bool = false } },
    } }} };
    // Out-of-range port
    {
        var doc = try parse(alloc, "[s]\nport = 99999", null);
        defer doc.deinit();
        var diags: std.ArrayList(Diagnostic) = .empty;
        defer freeDiagnostics(alloc, &diags);
        try std.testing.expectError(error.ValidationFailed, schema.validate(&doc, alloc, &diags));
        try std.testing.expectEqual(DiagKind.out_of_range, diags.items[0].kind);
    }
    // Defaults applied when key absent
    {
        var doc = try parse(alloc, "[s]\nport = 6667", null);
        defer doc.deinit();
        var diags: std.ArrayList(Diagnostic) = .empty;
        defer freeDiagnostics(alloc, &diags);
        var cfg = try schema.validate(&doc, alloc, &diags);
        defer cfg.deinit();
        try std.testing.expectEqual(false, cfg.getBool("s", "tls").?);
    }
}
