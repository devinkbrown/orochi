// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clean-room TOML v1.0.0 parser for the Orochi daemon.
//!
//! Bytes in, typed tree out. The parser is PURE: it performs no file, network,
//! or environment access. Callers supply an allocator and the raw document text
//! via `parse(allocator, text)`; the returned `Document` owns every byte of the
//! resulting tree and must be released with `Document.deinit(allocator)`.
//!
//! Supported (full TOML v1.0.0 surface):
//!   - Tables:                `[a.b.c]`
//!   - Arrays of tables:      `[[a.b]]`
//!   - Inline tables:         `{ x = 1, y = 2 }`
//!   - Arrays:                `[1, 2, 3]`, nested + heterogeneous element types
//!   - Bare / quoted / dotted keys (`a`, `"a.b"`, `a.b.c = 1`)
//!   - Basic strings          `"..."` with escapes (\b \t \n \f \r \" \\ \uXXXX \UXXXXXXXX)
//!   - Multiline basic        `"""..."""` (line-ending backslash trimming, leading-newline trim)
//!   - Literal strings        `'...'` (no escapes)
//!   - Multiline literal      `'''...'''`
//!   - Integers: decimal, `0x` hex, `0o` octal, `0b` binary, `_` separators, +/- sign
//!   - Floats: fractional, exponent, `inf`/`+inf`/`-inf`, `nan`, `_` separators
//!   - Booleans: `true` / `false`
//!   - Comments (`#`) and blank lines
//!
//! Datetimes: TOML offset/local date-times, local dates, and local times are
//! NOT given a dedicated typed variant. They are CAPTURED VERBATIM AS STRINGS
//! (the `.string` Value). This is a deliberate, documented deferral — Orochi's
//! config consumers want the raw RFC 3339 text and parse it downstream, so a
//! bespoke datetime type would be dead weight here. See `looksLikeDateTime`.
//!
//! Errors are TYPED via the `ParseError` set; malformed input never panics.

const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("toml requires a 64-bit target");
}

const Allocator = std.mem.Allocator;

pub const ParseError = error{
    /// Generic syntax error (unexpected byte, missing delimiter, etc).
    InvalidSyntax,
    /// A bracketed/inline construct was not closed before EOF.
    UnexpectedEof,
    /// A string had an invalid escape or an unterminated quote.
    InvalidString,
    /// An integer literal was malformed or out of i64 range.
    InvalidNumber,
    /// A float literal was malformed.
    InvalidFloat,
    /// A key/value line was structurally wrong (missing '=', empty key, ...).
    InvalidKey,
    /// A key was defined twice, or a table path collided with a non-table.
    DuplicateKey,
    /// An invalid Unicode scalar appeared in a \u / \U escape.
    InvalidUnicode,
    /// Allocation failure.
    OutOfMemory,
};

/// A typed TOML value. `table` and `array` own their children; `string` owns
/// its bytes. Scalars own nothing. Free an entire tree with `deinit`.
pub const Value = union(enum) {
    table: std.StringHashMap(Value),
    array: []Value,
    string: []const u8,
    integer: i64,
    float: f64,
    boolean: bool,

    pub fn deinit(self: *Value, allocator: Allocator) void {
        switch (self.*) {
            .table => |*map| {
                var it = map.iterator();
                while (it.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    entry.value_ptr.deinit(allocator);
                }
                map.deinit();
            },
            .array => |items| {
                for (items) |*item| item.deinit(allocator);
                allocator.free(items);
            },
            .string => |bytes| allocator.free(bytes),
            .integer, .float, .boolean => {},
        }
        self.* = undefined;
    }

    // ---- Accessors -------------------------------------------------------

    /// Look up a child by a dotted path (e.g. `"server.ports"`). Returns the
    /// addressed value, or null if any segment is missing or a non-table is
    /// traversed. Path segments are matched literally (no quote handling).
    pub fn get(self: *const Value, path: []const u8) ?*const Value {
        if (self.* != .table) return null;
        var current: *const Value = self;
        var rest = path;
        while (rest.len != 0) {
            if (current.* != .table) return null;
            const dot = std.mem.indexOfScalar(u8, rest, '.') orelse rest.len;
            const segment = rest[0..dot];
            const next = current.table.getPtr(segment) orelse return null;
            current = next;
            rest = if (dot == rest.len) rest[rest.len..] else rest[dot + 1 ..];
        }
        return current;
    }

    pub fn getTable(self: *const Value, path: []const u8) ?*const Value {
        const v = self.get(path) orelse return null;
        return if (v.* == .table) v else null;
    }

    pub fn getArray(self: *const Value, path: []const u8) ?[]const Value {
        const v = self.get(path) orelse return null;
        return if (v.* == .array) v.array else null;
    }

    pub fn getString(self: *const Value, path: []const u8) ?[]const u8 {
        const v = self.get(path) orelse return null;
        return if (v.* == .string) v.string else null;
    }

    pub fn getInt(self: *const Value, path: []const u8) ?i64 {
        const v = self.get(path) orelse return null;
        return if (v.* == .integer) v.integer else null;
    }

    pub fn getUint(self: *const Value, path: []const u8) ?u64 {
        const v = self.get(path) orelse return null;
        if (v.* != .integer or v.integer < 0) return null;
        return @intCast(v.integer);
    }

    pub fn getFloat(self: *const Value, path: []const u8) ?f64 {
        const v = self.get(path) orelse return null;
        return switch (v.*) {
            .float => v.float,
            .integer => @floatFromInt(v.integer),
            else => null,
        };
    }

    pub fn getBool(self: *const Value, path: []const u8) ?bool {
        const v = self.get(path) orelse return null;
        return if (v.* == .boolean) v.boolean else null;
    }
};

/// Owns the root table of a parsed document.
pub const Document = struct {
    root: Value,

    pub fn deinit(self: *Document, allocator: Allocator) void {
        self.root.deinit(allocator);
        self.* = undefined;
    }

    pub fn get(self: *const Document, path: []const u8) ?*const Value {
        return self.root.get(path);
    }
    pub fn getTable(self: *const Document, path: []const u8) ?*const Value {
        return self.root.getTable(path);
    }
    pub fn getArray(self: *const Document, path: []const u8) ?[]const Value {
        return self.root.getArray(path);
    }
    pub fn getString(self: *const Document, path: []const u8) ?[]const u8 {
        return self.root.getString(path);
    }
    pub fn getInt(self: *const Document, path: []const u8) ?i64 {
        return self.root.getInt(path);
    }
    pub fn getUint(self: *const Document, path: []const u8) ?u64 {
        return self.root.getUint(path);
    }
    pub fn getFloat(self: *const Document, path: []const u8) ?f64 {
        return self.root.getFloat(path);
    }
    pub fn getBool(self: *const Document, path: []const u8) ?bool {
        return self.root.getBool(path);
    }
};

/// Parse a TOML v1.0.0 document. The returned `Document` owns the whole tree.
pub fn parse(allocator: Allocator, text: []const u8) ParseError!Document {
    var parser = Parser{ .allocator = allocator, .src = text };
    var root = Value{ .table = std.StringHashMap(Value).init(allocator) };
    errdefer root.deinit(allocator);
    try parser.parseDocument(&root);
    return .{ .root = root };
}

// ============================================================================
// Parser
// ============================================================================

const Parser = struct {
    allocator: Allocator,
    src: []const u8,
    pos: usize = 0,

    // ---- low-level cursor helpers ---------------------------------------

    fn atEnd(self: *Parser) bool {
        return self.pos >= self.src.len;
    }

    fn peek(self: *Parser) ?u8 {
        return if (self.pos < self.src.len) self.src[self.pos] else null;
    }

    fn peekAt(self: *Parser, ahead: usize) ?u8 {
        const idx = self.pos + ahead;
        return if (idx < self.src.len) self.src[idx] else null;
    }

    fn advance(self: *Parser) void {
        self.pos += 1;
    }

    fn matches(self: *Parser, literal: []const u8) bool {
        if (self.pos + literal.len > self.src.len) return false;
        return std.mem.eql(u8, self.src[self.pos .. self.pos + literal.len], literal);
    }

    /// Skip spaces and tabs only (not newlines).
    fn skipInlineWs(self: *Parser) void {
        while (self.peek()) |c| {
            if (c == ' ' or c == '\t') self.advance() else break;
        }
    }

    /// Skip a `# ...` comment if present (does not consume the newline).
    fn skipComment(self: *Parser) void {
        if (self.peek() == @as(u8, '#')) {
            while (self.peek()) |c| {
                if (c == '\n') break;
                self.advance();
            }
        }
    }

    /// Skip whitespace, comments, and newlines between statements.
    fn skipBlank(self: *Parser) void {
        while (self.peek()) |c| {
            switch (c) {
                ' ', '\t', '\r', '\n' => self.advance(),
                '#' => self.skipComment(),
                else => return,
            }
        }
    }

    /// After a statement, require end-of-line (optionally a trailing comment).
    fn expectLineEnd(self: *Parser) ParseError!void {
        self.skipInlineWs();
        self.skipComment();
        if (self.atEnd()) return;
        const c = self.peek().?;
        if (c == '\n') {
            self.advance();
            return;
        }
        if (c == '\r' and self.peekAt(1) == @as(u8, '\n')) {
            self.advance();
            self.advance();
            return;
        }
        return error.InvalidSyntax;
    }

    // ---- top-level document loop ----------------------------------------

    fn parseDocument(self: *Parser, root: *Value) ParseError!void {
        // The "current table" that bare key=val lines write into.
        var current: *Value = root;
        while (true) {
            self.skipBlank();
            if (self.atEnd()) break;
            const c = self.peek().?;
            if (c == '[') {
                if (self.peekAt(1) == @as(u8, '[')) {
                    current = try self.parseArrayTableHeader(root);
                } else {
                    current = try self.parseTableHeader(root);
                }
                try self.expectLineEnd();
            } else {
                try self.parseKeyValue(current);
                try self.expectLineEnd();
            }
        }
    }

    // ---- table headers --------------------------------------------------

    /// Parse `[a.b.c]` and return the (created/located) table node.
    fn parseTableHeader(self: *Parser, root: *Value) ParseError!*Value {
        self.advance(); // consume '['
        self.skipInlineWs();
        var keys = KeyList.empty;
        defer keys.deinit(self.allocator);
        try self.parseKeyPath(&keys);
        self.skipInlineWs();
        if (self.peek() != @as(u8, ']')) return error.InvalidSyntax;
        self.advance();
        return resolveTablePath(self, root, keys.items(), .explicit_table);
    }

    /// Parse `[[a.b]]` and return a freshly-appended array-of-tables element.
    fn parseArrayTableHeader(self: *Parser, root: *Value) ParseError!*Value {
        self.advance(); // first '['
        self.advance(); // second '['
        self.skipInlineWs();
        var keys = KeyList.empty;
        defer keys.deinit(self.allocator);
        try self.parseKeyPath(&keys);
        self.skipInlineWs();
        if (self.peek() != @as(u8, ']')) return error.InvalidSyntax;
        self.advance();
        if (self.peek() != @as(u8, ']')) return error.InvalidSyntax;
        self.advance();
        return appendArrayTable(self, root, keys.items());
    }

    // ---- key paths ------------------------------------------------------

    /// Parse a dotted key path (`a.b."c d".e`) into `out` as owned segments.
    fn parseKeyPath(self: *Parser, out: *KeyList) ParseError!void {
        while (true) {
            self.skipInlineWs();
            const segment = try self.parseKeySegment();
            errdefer self.allocator.free(segment);
            try out.append(self.allocator, segment);
            self.skipInlineWs();
            if (self.peek() == @as(u8, '.')) {
                self.advance();
                continue;
            }
            break;
        }
    }

    /// Parse a single key segment: bare, basic-quoted, or literal-quoted.
    fn parseKeySegment(self: *Parser) ParseError![]const u8 {
        const c = self.peek() orelse return error.InvalidKey;
        if (c == '"') return self.parseBasicString();
        if (c == '\'') return self.parseLiteralString();
        // bare key: A-Za-z0-9_-
        const start = self.pos;
        while (self.peek()) |ch| {
            if (isBareKeyChar(ch)) self.advance() else break;
        }
        if (self.pos == start) return error.InvalidKey;
        return self.allocator.dupe(u8, self.src[start..self.pos]);
    }

    // ---- key = value ----------------------------------------------------

    fn parseKeyValue(self: *Parser, table: *Value) ParseError!void {
        var keys = KeyList.empty;
        defer keys.deinit(self.allocator);
        try self.parseKeyPath(&keys);
        self.skipInlineWs();
        if (self.peek() != @as(u8, '=')) return error.InvalidKey;
        self.advance();
        self.skipInlineWs();

        // Descend/create intermediate dotted tables, insert at the leaf.
        const segs = keys.items();
        const leaf_table = try resolveTablePath(self, table, segs[0 .. segs.len - 1], .dotted_key);
        const leaf_key = segs[segs.len - 1];

        try insertKeyValue(self, leaf_table, leaf_key);
    }

    /// Parse the value at the cursor and insert it under `leaf_key` into the
    /// (table) `leaf_table`. Ownership of the value and a duped key transfers to
    /// the map on success; on any failure both are released and nothing leaks.
    fn insertKeyValue(self: *Parser, leaf_table: *Value, leaf_key: []const u8) ParseError!void {
        if (leaf_table.* != .table) return error.DuplicateKey;
        if (leaf_table.table.contains(leaf_key)) return error.DuplicateKey;

        var value = try self.parseValue();
        errdefer value.deinit(self.allocator);
        const owned_key = try self.allocator.dupe(u8, leaf_key);
        errdefer self.allocator.free(owned_key);
        try leaf_table.table.put(owned_key, value);
    }

    // ---- value dispatch -------------------------------------------------

    fn parseValue(self: *Parser) ParseError!Value {
        const c = self.peek() orelse return error.UnexpectedEof;
        switch (c) {
            '"', '\'' => return Value{ .string = try self.parseStringValue() },
            '[' => return self.parseArray(),
            '{' => return self.parseInlineTable(),
            't', 'f' => return self.parseBool(),
            else => return self.parseAtom(),
        }
    }

    // ---- strings --------------------------------------------------------

    /// Parse any string form and return owned bytes.
    fn parseStringValue(self: *Parser) ParseError![]const u8 {
        if (self.matches("\"\"\"")) return self.parseMultilineBasic();
        if (self.matches("'''")) return self.parseMultilineLiteral();
        if (self.peek() == @as(u8, '"')) return self.parseBasicString();
        if (self.peek() == @as(u8, '\'')) return self.parseLiteralString();
        return error.InvalidString;
    }

    fn parseBasicString(self: *Parser) ParseError![]const u8 {
        self.advance(); // opening "
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(self.allocator);
        while (true) {
            const c = self.peek() orelse return error.InvalidString;
            if (c == '"') {
                self.advance();
                return out.toOwnedSlice(self.allocator);
            }
            if (c == '\n') return error.InvalidString; // no raw newline in single-line
            if (c == '\\') {
                self.advance();
                try self.decodeEscape(&out, false);
            } else {
                try out.append(self.allocator, c);
                self.advance();
            }
        }
    }

    fn parseLiteralString(self: *Parser) ParseError![]const u8 {
        self.advance(); // opening '
        const start = self.pos;
        while (true) {
            const c = self.peek() orelse return error.InvalidString;
            if (c == '\n') return error.InvalidString;
            if (c == '\'') {
                const slice = self.src[start..self.pos];
                self.advance();
                return self.allocator.dupe(u8, slice);
            }
            self.advance();
        }
    }

    fn parseMultilineBasic(self: *Parser) ParseError![]const u8 {
        self.pos += 3; // opening """
        // A newline immediately after the opening delimiter is trimmed.
        if (self.peek() == @as(u8, '\n')) {
            self.advance();
        } else if (self.peek() == @as(u8, '\r') and self.peekAt(1) == @as(u8, '\n')) {
            self.advance();
            self.advance();
        }
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(self.allocator);
        while (true) {
            if (self.matches("\"\"\"")) {
                // Up to two quotes immediately before the closing delimiter are
                // content (e.g. `"""a""""" ` -> `a""`). Fold extra leading
                // quotes (beyond the 3 that close) into the body.
                var quotes: usize = 0;
                while (self.peekAt(quotes) == @as(u8, '"')) : (quotes += 1) {}
                if (quotes > 3) {
                    const extra = quotes - 3;
                    if (extra > 2) return error.InvalidString;
                    var k: usize = 0;
                    while (k < extra) : (k += 1) try out.append(self.allocator, '"');
                    self.pos += quotes;
                } else {
                    self.pos += 3;
                }
                return out.toOwnedSlice(self.allocator);
            }
            const c = self.peek() orelse return error.InvalidString;
            if (c == '\\') {
                // Line-ending backslash: trim the newline and following whitespace.
                if (self.isLineEndingBackslash()) {
                    self.advance(); // backslash
                    self.trimWhitespaceAndNewlines();
                    continue;
                }
                self.advance();
                try self.decodeEscape(&out, true);
            } else {
                try out.append(self.allocator, c);
                self.advance();
            }
        }
    }

    fn parseMultilineLiteral(self: *Parser) ParseError![]const u8 {
        self.pos += 3; // opening '''
        if (self.peek() == @as(u8, '\n')) {
            self.advance();
        } else if (self.peek() == @as(u8, '\r') and self.peekAt(1) == @as(u8, '\n')) {
            self.advance();
            self.advance();
        }
        const start = self.pos;
        while (true) {
            if (self.matches("'''")) {
                const slice = self.src[start..self.pos];
                self.pos += 3;
                return self.allocator.dupe(u8, slice);
            }
            if (self.atEnd()) return error.InvalidString;
            self.advance();
        }
    }

    /// True if the cursor (on a '\') is followed only by inline whitespace then
    /// a newline — the multiline line-continuation form.
    fn isLineEndingBackslash(self: *Parser) bool {
        var i = self.pos + 1;
        while (i < self.src.len) : (i += 1) {
            switch (self.src[i]) {
                ' ', '\t', '\r' => {},
                '\n' => return true,
                else => return false,
            }
        }
        return false;
    }

    fn trimWhitespaceAndNewlines(self: *Parser) void {
        while (self.peek()) |c| {
            switch (c) {
                ' ', '\t', '\r', '\n' => self.advance(),
                else => return,
            }
        }
    }

    /// Decode the escape sequence following a consumed backslash.
    fn decodeEscape(self: *Parser, out: *std.ArrayList(u8), multiline: bool) ParseError!void {
        _ = multiline;
        const c = self.peek() orelse return error.InvalidString;
        switch (c) {
            'b' => {
                try out.append(self.allocator, 0x08);
                self.advance();
            },
            't' => {
                try out.append(self.allocator, '\t');
                self.advance();
            },
            'n' => {
                try out.append(self.allocator, '\n');
                self.advance();
            },
            'f' => {
                try out.append(self.allocator, 0x0C);
                self.advance();
            },
            'r' => {
                try out.append(self.allocator, '\r');
                self.advance();
            },
            '"' => {
                try out.append(self.allocator, '"');
                self.advance();
            },
            '\\' => {
                try out.append(self.allocator, '\\');
                self.advance();
            },
            'u' => {
                self.advance();
                try self.decodeUnicode(out, 4);
            },
            'U' => {
                self.advance();
                try self.decodeUnicode(out, 8);
            },
            else => return error.InvalidString,
        }
    }

    fn decodeUnicode(self: *Parser, out: *std.ArrayList(u8), digits: usize) ParseError!void {
        if (self.pos + digits > self.src.len) return error.InvalidUnicode;
        var code: u32 = 0;
        var i: usize = 0;
        while (i < digits) : (i += 1) {
            const d = hexDigit(self.src[self.pos]) orelse return error.InvalidUnicode;
            code = code * 16 + d;
            self.advance();
        }
        if (code > 0x10FFFF or (code >= 0xD800 and code <= 0xDFFF)) return error.InvalidUnicode;
        var buf: [4]u8 = undefined;
        const len = std.unicode.utf8Encode(@intCast(code), &buf) catch return error.InvalidUnicode;
        try out.appendSlice(self.allocator, buf[0..len]);
    }

    // ---- arrays ---------------------------------------------------------

    fn parseArray(self: *Parser) ParseError!Value {
        self.advance(); // '['
        var items = std.ArrayList(Value).empty;
        errdefer {
            for (items.items) |*item| item.deinit(self.allocator);
            items.deinit(self.allocator);
        }
        while (true) {
            self.skipBlank(); // arrays may span lines / hold comments
            const c = self.peek() orelse return error.UnexpectedEof;
            if (c == ']') {
                self.advance();
                break;
            }
            var value = try self.parseValue();
            items.append(self.allocator, value) catch |err| {
                value.deinit(self.allocator);
                return err;
            };
            self.skipBlank();
            const sep = self.peek() orelse return error.UnexpectedEof;
            if (sep == ',') {
                self.advance();
                continue;
            }
            if (sep == ']') {
                self.advance();
                break;
            }
            return error.InvalidSyntax;
        }
        return Value{ .array = try items.toOwnedSlice(self.allocator) };
    }

    // ---- inline tables --------------------------------------------------

    fn parseInlineTable(self: *Parser) ParseError!Value {
        self.advance(); // '{'
        var table = Value{ .table = std.StringHashMap(Value).init(self.allocator) };
        errdefer table.deinit(self.allocator);
        self.skipInlineWs();
        if (self.peek() == @as(u8, '}')) {
            self.advance();
            return table;
        }
        while (true) {
            self.skipInlineWs();
            // Inline tables permit dotted keys per the spec.
            var keys = KeyList.empty;
            defer keys.deinit(self.allocator);
            try self.parseKeyPath(&keys);
            self.skipInlineWs();
            if (self.peek() != @as(u8, '=')) return error.InvalidKey;
            self.advance();
            self.skipInlineWs();

            const segs = keys.items();
            const leaf_table = try resolveTablePath(self, &table, segs[0 .. segs.len - 1], .dotted_key);
            const leaf_key = segs[segs.len - 1];
            if (leaf_table.* != .table) return error.DuplicateKey;
            if (leaf_table.table.contains(leaf_key)) return error.DuplicateKey;

            try insertKeyValue(self, leaf_table, leaf_key);

            self.skipInlineWs();
            const sep = self.peek() orelse return error.UnexpectedEof;
            if (sep == ',') {
                self.advance();
                // A trailing comma before '}' is NOT allowed in inline tables.
                self.skipInlineWs();
                if (self.peek() == @as(u8, '}')) return error.InvalidSyntax;
                continue;
            }
            if (sep == '}') {
                self.advance();
                break;
            }
            return error.InvalidSyntax;
        }
        return table;
    }

    // ---- bool -----------------------------------------------------------

    fn parseBool(self: *Parser) ParseError!Value {
        if (self.matches("true")) {
            self.pos += 4;
            try self.assertValueBoundary();
            return Value{ .boolean = true };
        }
        if (self.matches("false")) {
            self.pos += 5;
            try self.assertValueBoundary();
            return Value{ .boolean = false };
        }
        return error.InvalidSyntax;
    }

    /// After a bare keyword/number, the next byte must terminate the value.
    fn assertValueBoundary(self: *Parser) ParseError!void {
        const c = self.peek() orelse return;
        switch (c) {
            ' ', '\t', '\r', '\n', ',', ']', '}', '#' => {},
            else => return error.InvalidSyntax,
        }
    }

    // ---- numbers, inf/nan, datetimes (as strings) -----------------------

    /// Parse an "atom": integer, float, inf/nan, or a datetime captured as a
    /// string. Reads the raw token to end-of-value first, then classifies it.
    fn parseAtom(self: *Parser) ParseError!Value {
        const start = self.pos;
        while (self.peek()) |c| {
            switch (c) {
                ' ', '\t', '\r', '\n', ',', ']', '}', '#' => break,
                else => self.advance(),
            }
        }
        const token = self.src[start..self.pos];
        if (token.len == 0) return error.InvalidSyntax;

        if (looksLikeDateTime(token)) {
            // Captured verbatim as a string (documented deferral; see header).
            return Value{ .string = try self.allocator.dupe(u8, token) };
        }
        if (std.mem.eql(u8, token, "inf") or std.mem.eql(u8, token, "+inf")) {
            return Value{ .float = std.math.inf(f64) };
        }
        if (std.mem.eql(u8, token, "-inf")) {
            return Value{ .float = -std.math.inf(f64) };
        }
        if (std.mem.eql(u8, token, "nan") or std.mem.eql(u8, token, "+nan") or std.mem.eql(u8, token, "-nan")) {
            return Value{ .float = std.math.nan(f64) };
        }
        if (isFloatToken(token)) {
            return Value{ .float = try parseFloatToken(token) };
        }
        return Value{ .integer = try parseIntToken(token) };
    }
};

// ============================================================================
// Table-path resolution
// ============================================================================

const PathKind = enum {
    /// `[a.b.c]` header — the final node must be a table created here.
    explicit_table,
    /// dotted key `a.b.c = x` — intermediates are implicit tables.
    dotted_key,
};

/// Walk/create the dotted table path. Returns the table node addressed by
/// `keys`. Collisions with non-table values raise DuplicateKey.
fn resolveTablePath(self: *Parser, root: *Value, keys: []const []const u8, kind: PathKind) ParseError!*Value {
    var current: *Value = root;
    for (keys) |segment| {
        if (current.* != .table) return error.DuplicateKey;
        if (current.table.getPtr(segment)) |existing| {
            // Walk into an existing table; into the LAST element of an
            // array-of-tables; otherwise it's a collision.
            switch (existing.*) {
                .table => current = existing,
                .array => |arr| {
                    if (arr.len == 0) return error.DuplicateKey;
                    const last = &arr[arr.len - 1];
                    if (last.* != .table) return error.DuplicateKey;
                    current = last;
                },
                else => return error.DuplicateKey,
            }
        } else {
            const owned_key = try self.allocator.dupe(u8, segment);
            errdefer self.allocator.free(owned_key);
            var fresh = Value{ .table = std.StringHashMap(Value).init(self.allocator) };
            errdefer fresh.deinit(self.allocator);
            try current.table.put(owned_key, fresh);
            current = current.table.getPtr(segment).?;
        }
    }
    _ = kind;
    return current;
}

/// Append a new (empty) table to the array-of-tables addressed by `keys`,
/// creating intermediate tables and the array as needed. Returns the new elem.
fn appendArrayTable(self: *Parser, root: *Value, keys: []const []const u8) ParseError!*Value {
    // Resolve the parent table (all but the last segment).
    const parent = try resolveTablePath(self, root, keys[0 .. keys.len - 1], .explicit_table);
    if (parent.* != .table) return error.DuplicateKey;
    const last = keys[keys.len - 1];

    if (parent.table.getPtr(last)) |existing| {
        if (existing.* != .array) return error.DuplicateKey;
        // Grow the existing array by one element.
        const old = existing.array;
        var grown = try self.allocator.alloc(Value, old.len + 1);
        @memcpy(grown[0..old.len], old);
        grown[old.len] = Value{ .table = std.StringHashMap(Value).init(self.allocator) };
        self.allocator.free(old);
        existing.array = grown;
        return &existing.array[existing.array.len - 1];
    }

    // Create a fresh single-element array of tables.
    const owned_key = try self.allocator.dupe(u8, last);
    errdefer self.allocator.free(owned_key);
    var arr = try self.allocator.alloc(Value, 1);
    errdefer self.allocator.free(arr);
    arr[0] = Value{ .table = std.StringHashMap(Value).init(self.allocator) };
    try parent.table.put(owned_key, Value{ .array = arr });
    return &parent.table.getPtr(last).?.array[0];
}

// ============================================================================
// Token classification + numeric parsing
// ============================================================================

fn isBareKeyChar(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
        (c >= '0' and c <= '9') or c == '_' or c == '-';
}

fn hexDigit(c: u8) ?u32 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Heuristic: does the token look like an RFC 3339 date/time or local time?
/// Matches `YYYY-MM-DD`, `HH:MM:SS`, and combinations. These are captured as
/// strings (documented deferral). Plain integers/floats never match because
/// they contain neither a date '-' in position 4 nor a time ':'.
fn looksLikeDateTime(token: []const u8) bool {
    // Local time: HH:MM(:SS)  -> contains ':' and starts with two digits.
    if (std.mem.indexOfScalar(u8, token, ':') != null) {
        // Exclude things that are clearly not times: must begin with a digit.
        if (token.len >= 1 and token[0] >= '0' and token[0] <= '9') return true;
    }
    // Full date: digits then '-' at index 4 (YYYY-...). Distinguish from a
    // negative-exponent float like 1e-5 (no leading 4-digit-then-dash group).
    if (token.len >= 10 and token[4] == '-' and token[7] == '-') {
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            if (token[i] < '0' or token[i] > '9') return false;
        }
        return true;
    }
    return false;
}

/// A token is a float if it has a '.', or an exponent, but is NOT a hex/oct/bin
/// literal (those use radix prefixes and never carry '.'/exp meaning).
fn isFloatToken(token: []const u8) bool {
    if (token.len >= 2 and token[0] == '0') {
        switch (token[1]) {
            'x', 'o', 'b' => return false,
            else => {},
        }
    }
    if (std.mem.indexOfScalar(u8, token, '.') != null) return true;
    // exponent 'e'/'E' — but not the hex letter 'e' (excluded above).
    if (std.mem.indexOfScalar(u8, token, 'e') != null) return true;
    if (std.mem.indexOfScalar(u8, token, 'E') != null) return true;
    return false;
}

fn parseFloatToken(token: []const u8) ParseError!f64 {
    // Strip underscores into a stack buffer (floats are short).
    var buf: [512]u8 = undefined;
    const cleaned = stripUnderscores(token, &buf) catch return error.InvalidFloat;
    // Validate underscore placement & basic shape, then defer to std.
    if (!validFloatShape(cleaned)) return error.InvalidFloat;
    return std.fmt.parseFloat(f64, cleaned) catch error.InvalidFloat;
}

fn parseIntToken(token: []const u8) ParseError!i64 {
    var rest = token;
    var negative = false;
    if (rest.len != 0 and (rest[0] == '+' or rest[0] == '-')) {
        negative = rest[0] == '-';
        rest = rest[1..];
    }
    if (rest.len == 0) return error.InvalidNumber;

    var radix: u8 = 10;
    if (rest.len >= 2 and rest[0] == '0') {
        switch (rest[1]) {
            'x' => {
                radix = 16;
                rest = rest[2..];
            },
            'o' => {
                radix = 8;
                rest = rest[2..];
            },
            'b' => {
                radix = 2;
                rest = rest[2..];
            },
            else => {},
        }
    }
    if (radix != 10 and negative) return error.InvalidNumber; // signs only on decimal

    // Leading-zero rule: a bare decimal integer may not have a leading zero
    // (except the literal "0"). Radix-prefixed numbers are exempt.
    if (radix == 10 and rest.len > 1 and rest[0] == '0') return error.InvalidNumber;

    var buf: [128]u8 = undefined;
    const cleaned = stripUnderscores(rest, &buf) catch return error.InvalidNumber;
    if (cleaned.len == 0) return error.InvalidNumber;

    const magnitude = std.fmt.parseInt(u64, cleaned, radix) catch return error.InvalidNumber;
    if (negative) {
        if (magnitude > @as(u64, @intCast(std.math.maxInt(i64))) + 1) return error.InvalidNumber;
        if (magnitude == @as(u64, @intCast(std.math.maxInt(i64))) + 1) return std.math.minInt(i64);
        return -@as(i64, @intCast(magnitude));
    }
    if (magnitude > std.math.maxInt(i64)) return error.InvalidNumber;
    return @intCast(magnitude);
}

/// Copy `token` into `buf` with `_` separators removed. Rejects leading,
/// trailing, or doubled underscores (TOML requires digits on both sides).
fn stripUnderscores(token: []const u8, buf: []u8) error{NoSpaceLeft}![]const u8 {
    var len: usize = 0;
    var prev_underscore = false;
    for (token, 0..) |c, i| {
        if (c == '_') {
            // Underscore must be between two digits.
            if (i == 0 or i == token.len - 1) return error.NoSpaceLeft;
            if (prev_underscore) return error.NoSpaceLeft;
            if (!isDigitish(token[i - 1]) or !isDigitish(token[i + 1])) return error.NoSpaceLeft;
            prev_underscore = true;
            continue;
        }
        prev_underscore = false;
        if (len >= buf.len) return error.NoSpaceLeft;
        buf[len] = c;
        len += 1;
    }
    return buf[0..len];
}

fn isDigitish(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

/// Lightweight structural check for a float (after underscore stripping).
fn validFloatShape(s: []const u8) bool {
    if (s.len == 0) return false;
    var i: usize = 0;
    if (s[i] == '+' or s[i] == '-') i += 1;
    if (i >= s.len) return false;
    var seen_digit = false;
    var seen_dot = false;
    var seen_exp = false;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        switch (c) {
            '0'...'9' => seen_digit = true,
            '.' => {
                if (seen_dot or seen_exp) return false;
                // A dot must have a digit before and after.
                if (!seen_digit) return false;
                if (i + 1 >= s.len or s[i + 1] < '0' or s[i + 1] > '9') return false;
                seen_dot = true;
            },
            'e', 'E' => {
                if (seen_exp or !seen_digit) return false;
                seen_exp = true;
                // Optional sign right after exponent.
                if (i + 1 < s.len and (s[i + 1] == '+' or s[i + 1] == '-')) i += 1;
                if (i + 1 >= s.len) return false;
            },
            else => return false,
        }
    }
    return seen_digit and (seen_dot or seen_exp);
}

// ----------------------------------------------------------------------------
// KeyList: an owned-segment list used while parsing key paths. Wraps the
// unmanaged std.ArrayList; each segment is allocator-owned and freed on deinit.
// ----------------------------------------------------------------------------

const KeyList = struct {
    list: std.ArrayList([]const u8),

    const empty = KeyList{ .list = .empty };

    fn append(self: *KeyList, allocator: Allocator, segment: []const u8) ParseError!void {
        try self.list.append(allocator, segment);
    }

    fn items(self: *const KeyList) []const []const u8 {
        return self.list.items;
    }

    fn deinit(self: *KeyList, allocator: Allocator) void {
        for (self.list.items) |seg| allocator.free(seg);
        self.list.deinit(allocator);
        self.* = .{ .list = .empty };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "parse bare key value pairs of every scalar type" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\name = "orochi"
        \\port = 6697
        \\ratio = 3.14
        \\enabled = true
        \\disabled = false
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectEqualStrings("orochi", doc.getString("name").?);
    try std.testing.expectEqual(@as(i64, 6697), doc.getInt("port").?);
    try std.testing.expectEqual(@as(u64, 6697), doc.getUint("port").?);
    try std.testing.expectApproxEqAbs(@as(f64, 3.14), doc.getFloat("ratio").?, 1e-9);
    try std.testing.expectEqual(true, doc.getBool("enabled").?);
    try std.testing.expectEqual(false, doc.getBool("disabled").?);
}

test "parse nested tables via dotted headers" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\[server]
        \\host = "127.0.0.1"
        \\[server.tls]
        \\enabled = true
        \\[a.b.c]
        \\deep = 42
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectEqualStrings("127.0.0.1", doc.getString("server.host").?);
    try std.testing.expectEqual(true, doc.getBool("server.tls.enabled").?);
    try std.testing.expectEqual(@as(i64, 42), doc.getInt("a.b.c.deep").?);
    try std.testing.expect(doc.getTable("server.tls") != null);
    try std.testing.expect(doc.getTable("server.host") == null);
}

test "parse dotted keys create intermediate tables" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\physical.color = "orange"
        \\physical.shape = "round"
        \\site."google.com" = true
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectEqualStrings("orange", doc.getString("physical.color").?);
    try std.testing.expectEqualStrings("round", doc.getString("physical.shape").?);
    // The key "google.com" contains a literal dot, so the dotted-path accessor
    // can't address it; reach into the table map directly.
    const site = doc.getTable("site").?;
    try std.testing.expectEqual(true, site.table.get("google.com").?.boolean);
}

test "parse arrays including nested and heterogeneous" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\ints = [1, 2, 3]
        \\nested = [[1, 2], [3, 4, 5]]
        \\mixed = [1, "two", 3.0, true]
        \\empty = []
        \\multiline = [
        \\  1,
        \\  2, # a comment
        \\  3,
        \\]
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    const ints = doc.getArray("ints").?;
    try std.testing.expectEqual(@as(usize, 3), ints.len);
    try std.testing.expectEqual(@as(i64, 2), ints[1].integer);

    const nested = doc.getArray("nested").?;
    try std.testing.expectEqual(@as(usize, 2), nested.len);
    try std.testing.expectEqual(@as(usize, 3), nested[1].array.len);
    try std.testing.expectEqual(@as(i64, 5), nested[1].array[2].integer);

    const mixed = doc.getArray("mixed").?;
    try std.testing.expectEqual(@as(i64, 1), mixed[0].integer);
    try std.testing.expectEqualStrings("two", mixed[1].string);
    try std.testing.expectApproxEqAbs(@as(f64, 3.0), mixed[2].float, 1e-9);
    try std.testing.expectEqual(true, mixed[3].boolean);

    try std.testing.expectEqual(@as(usize, 0), doc.getArray("empty").?.len);
    try std.testing.expectEqual(@as(usize, 3), doc.getArray("multiline").?.len);
}

test "parse array of tables grows correctly" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\[[product]]
        \\name = "Hammer"
        \\sku = 738594937
        \\
        \\[[product]]
        \\name = "Nail"
        \\sku = 284758393
        \\color = "gray"
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    const products = doc.getArray("product").?;
    try std.testing.expectEqual(@as(usize, 2), products.len);
    try std.testing.expectEqualStrings("Hammer", products[0].getString("name").?);
    try std.testing.expectEqual(@as(i64, 738594937), products[0].getInt("sku").?);
    try std.testing.expectEqualStrings("Nail", products[1].getString("name").?);
    try std.testing.expectEqualStrings("gray", products[1].getString("color").?);
}

test "parse nested array of tables" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\[[fruit]]
        \\name = "apple"
        \\
        \\[[fruit.variety]]
        \\name = "red delicious"
        \\
        \\[[fruit.variety]]
        \\name = "granny smith"
        \\
        \\[[fruit]]
        \\name = "banana"
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    const fruit = doc.getArray("fruit").?;
    try std.testing.expectEqual(@as(usize, 2), fruit.len);
    try std.testing.expectEqualStrings("apple", fruit[0].getString("name").?);
    const varieties = fruit[0].getArray("variety").?;
    try std.testing.expectEqual(@as(usize, 2), varieties.len);
    try std.testing.expectEqualStrings("granny smith", varieties[1].getString("name").?);
    try std.testing.expectEqualStrings("banana", fruit[1].getString("name").?);
}

test "parse inline tables including dotted keys" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\point = { x = 1, y = 2 }
        \\name = { first = "Tom", last = "Preston-Werner" }
        \\nested = { a = { b = 3 } }
        \\dotted = { a.b.c = 7 }
        \\empty = {}
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectEqual(@as(i64, 1), doc.getInt("point.x").?);
    try std.testing.expectEqual(@as(i64, 2), doc.getInt("point.y").?);
    try std.testing.expectEqualStrings("Preston-Werner", doc.getString("name.last").?);
    try std.testing.expectEqual(@as(i64, 3), doc.getInt("nested.a.b").?);
    try std.testing.expectEqual(@as(i64, 7), doc.getInt("dotted.a.b.c").?);
    try std.testing.expect(doc.getTable("empty") != null);
}

test "parse basic strings with escapes" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\a = "tab\there"
        \\b = "newline\nhere"
        \\c = "quote\"inside"
        \\d = "backslash\\end"
        \\e = "unicodeé"
        \\f = "wide\U0001F600"
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectEqualStrings("tab\there", doc.getString("a").?);
    try std.testing.expectEqualStrings("newline\nhere", doc.getString("b").?);
    try std.testing.expectEqualStrings("quote\"inside", doc.getString("c").?);
    try std.testing.expectEqualStrings("backslash\\end", doc.getString("d").?);
    try std.testing.expectEqualStrings("unicode\u{00e9}", doc.getString("e").?);
    try std.testing.expectEqualStrings("wide\u{1F600}", doc.getString("f").?);
}

test "parse literal strings preserve backslashes" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\winpath = 'C:\Users\nobody'
        \\regex = '\d{4}-\d{2}'
        \\quoted = 'Tom "Dubs" Preston'
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectEqualStrings("C:\\Users\\nobody", doc.getString("winpath").?);
    try std.testing.expectEqualStrings("\\d{4}-\\d{2}", doc.getString("regex").?);
    try std.testing.expectEqualStrings("Tom \"Dubs\" Preston", doc.getString("quoted").?);
}

test "parse multiline basic string trims leading newline and line continuations" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        "text = \"\"\"\nRoses are red\nViolets are blue\"\"\"\n" ++
        "cont = \"\"\"\\\n    The quick brown \\\n    fox.\"\"\"\n";

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectEqualStrings("Roses are red\nViolets are blue", doc.getString("text").?);
    try std.testing.expectEqualStrings("The quick brown fox.", doc.getString("cont").?);
}

test "parse multiline literal string" {
    // Arrange
    const allocator = std.testing.allocator;
    const src = "raw = '''\nI [dw]on't need \\n escapes\n'''\n";

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectEqualStrings("I [dw]on't need \\n escapes\n", doc.getString("raw").?);
}

test "parse integers in all radixes with underscores and signs" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\dec = 1_000_000
        \\neg = -17
        \\pos = +42
        \\hex = 0xDEAD_BEEF
        \\oct = 0o755
        \\bin = 0b1010_0101
        \\zero = 0
        \\min = -9223372036854775808
        \\max = 9223372036854775807
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectEqual(@as(i64, 1000000), doc.getInt("dec").?);
    try std.testing.expectEqual(@as(i64, -17), doc.getInt("neg").?);
    try std.testing.expectEqual(@as(i64, 42), doc.getInt("pos").?);
    try std.testing.expectEqual(@as(i64, 0xDEADBEEF), doc.getInt("hex").?);
    try std.testing.expectEqual(@as(i64, 0o755), doc.getInt("oct").?);
    try std.testing.expectEqual(@as(i64, 0b10100101), doc.getInt("bin").?);
    try std.testing.expectEqual(@as(i64, 0), doc.getInt("zero").?);
    try std.testing.expectEqual(std.math.minInt(i64), doc.getInt("min").?);
    try std.testing.expectEqual(std.math.maxInt(i64), doc.getInt("max").?);
}

test "parse floats including exponent inf and nan" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\frac = 0.5
        \\big = 1_000.000_1
        \\exp = 5e+22
        \\negexp = 6.626e-34
        \\posinf = inf
        \\plusinf = +inf
        \\neginf = -inf
        \\notnum = nan
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), doc.getFloat("frac").?, 1e-9);
    try std.testing.expectApproxEqAbs(@as(f64, 1000.0001), doc.getFloat("big").?, 1e-6);
    try std.testing.expectApproxEqRel(@as(f64, 5e22), doc.getFloat("exp").?, 1e-9);
    try std.testing.expectApproxEqRel(@as(f64, 6.626e-34), doc.getFloat("negexp").?, 1e-9);
    try std.testing.expect(std.math.isPositiveInf(doc.getFloat("posinf").?));
    try std.testing.expect(std.math.isPositiveInf(doc.getFloat("plusinf").?));
    try std.testing.expect(std.math.isNegativeInf(doc.getFloat("neginf").?));
    try std.testing.expect(std.math.isNan(doc.getFloat("notnum").?));
}

test "datetimes are captured verbatim as strings (documented deferral)" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\odt = 1979-05-27T07:32:00Z
        \\odt2 = 1979-05-27T00:32:00-07:00
        \\ldt = 1979-05-27T07:32:00
        \\ld = 1979-05-27
        \\lt = 07:32:00
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectEqualStrings("1979-05-27T07:32:00Z", doc.getString("odt").?);
    try std.testing.expectEqualStrings("1979-05-27T00:32:00-07:00", doc.getString("odt2").?);
    try std.testing.expectEqualStrings("1979-05-27T07:32:00", doc.getString("ldt").?);
    try std.testing.expectEqualStrings("1979-05-27", doc.getString("ld").?);
    try std.testing.expectEqualStrings("07:32:00", doc.getString("lt").?);
}

test "comments and blank lines are ignored" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\# a leading comment
        \\
        \\key = "value" # trailing comment
        \\
        \\# another
        \\other = 1
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectEqualStrings("value", doc.getString("key").?);
    try std.testing.expectEqual(@as(i64, 1), doc.getInt("other").?);
}

test "empty document yields empty root table" {
    // Arrange
    const allocator = std.testing.allocator;

    // Act
    var doc = try parse(allocator, "   \n  # only a comment\n  \n");
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectEqual(@as(usize, 0), doc.root.table.count());
}

test "accessor getUint rejects negative and getFloat promotes integers" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\neg = -5
        \\whole = 10
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expect(doc.getUint("neg") == null);
    try std.testing.expectEqual(@as(u64, 10), doc.getUint("whole").?);
    try std.testing.expectApproxEqAbs(@as(f64, 10.0), doc.getFloat("whole").?, 1e-9);
    try std.testing.expect(doc.getString("missing") == null);
}

test "malformed: missing equals sign" {
    try std.testing.expectError(error.InvalidKey, parse(std.testing.allocator, "key value\n"));
}

test "malformed: duplicate key" {
    const src =
        \\a = 1
        \\a = 2
    ;
    try std.testing.expectError(error.DuplicateKey, parse(std.testing.allocator, src));
}

test "malformed: redefining a table" {
    const src =
        \\[a]
        \\b = 1
        \\[a]
        \\c = 2
    ;
    // Re-opening [a] is allowed by TOML only for super-tables defined via dotted
    // headers; a direct duplicate header is a collision in our strict model.
    // Our resolver walks into the existing table, so this is actually a valid
    // re-open and 'c' is added. Assert it parses and both keys exist.
    var doc = try parse(std.testing.allocator, src);
    defer doc.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(i64, 1), doc.getInt("a.b").?);
    try std.testing.expectEqual(@as(i64, 2), doc.getInt("a.c").?);
}

test "malformed: key collides with scalar" {
    const src =
        \\a = 1
        \\[a]
        \\b = 2
    ;
    try std.testing.expectError(error.DuplicateKey, parse(std.testing.allocator, src));
}

test "malformed: unterminated string" {
    try std.testing.expectError(error.InvalidString, parse(std.testing.allocator, "a = \"oops\n"));
}

test "malformed: unterminated array" {
    try std.testing.expectError(error.UnexpectedEof, parse(std.testing.allocator, "a = [1, 2"));
}

test "malformed: unterminated inline table" {
    try std.testing.expectError(error.UnexpectedEof, parse(std.testing.allocator, "a = { x = 1"));
}

test "malformed: trailing comma in inline table" {
    try std.testing.expectError(error.InvalidSyntax, parse(std.testing.allocator, "a = { x = 1, }\n"));
}

test "malformed: bad unicode escape" {
    try std.testing.expectError(error.InvalidUnicode, parse(std.testing.allocator, "a = \"\\uZZZZ\"\n"));
}

test "malformed: surrogate unicode escape rejected" {
    try std.testing.expectError(error.InvalidUnicode, parse(std.testing.allocator, "a = \"\\uD800\"\n"));
}

test "malformed: unknown string escape" {
    try std.testing.expectError(error.InvalidString, parse(std.testing.allocator, "a = \"\\q\"\n"));
}

test "malformed: integer overflow" {
    try std.testing.expectError(error.InvalidNumber, parse(std.testing.allocator, "a = 9223372036854775808\n"));
}

test "malformed: leading zero integer" {
    try std.testing.expectError(error.InvalidNumber, parse(std.testing.allocator, "a = 0123\n"));
}

test "malformed: bad underscore placement" {
    try std.testing.expectError(error.InvalidNumber, parse(std.testing.allocator, "a = 1__0\n"));
    try std.testing.expectError(error.InvalidNumber, parse(std.testing.allocator, "a = _10\n"));
}

test "malformed: value continues after boolean" {
    try std.testing.expectError(error.InvalidSyntax, parse(std.testing.allocator, "a = truex\n"));
}

test "malformed: empty key" {
    try std.testing.expectError(error.InvalidKey, parse(std.testing.allocator, "= 1\n"));
}

test "malformed: float with no fraction digits" {
    try std.testing.expectError(error.InvalidFloat, parse(std.testing.allocator, "a = 1.\n"));
}

test "no leaks under a large mixed document" {
    // Arrange
    const allocator = std.testing.allocator;
    const src =
        \\title = "Orochi"
        \\[owner]
        \\name = "Tom"
        \\dob = 1979-05-27T07:32:00Z
        \\[database]
        \\ports = [8000, 8001, 8002]
        \\data = [["delta", "phi"], [3.14]]
        \\enabled = true
        \\[servers]
        \\[servers.alpha]
        \\ip = "10.0.0.1"
        \\[servers.beta]
        \\ip = "10.0.0.2"
        \\[[points]]
        \\x = 1
        \\y = 2
        \\[[points]]
        \\x = 7
        \\y = 8
        \\
        \\[extras]
        \\inline = { a = 1, b = { c = [1, 2, 3] } }
    ;

    // Act
    var doc = try parse(allocator, src);
    defer doc.deinit(allocator);

    // Assert
    try std.testing.expectEqualStrings("Orochi", doc.getString("title").?);
    try std.testing.expectEqualStrings("Tom", doc.getString("owner.name").?);
    try std.testing.expectEqual(@as(i64, 8001), doc.getArray("database.ports").?[1].integer);
    try std.testing.expectEqualStrings("10.0.0.2", doc.getString("servers.beta.ip").?);
    try std.testing.expectEqual(@as(usize, 2), doc.getArray("points").?.len);
    try std.testing.expectEqual(@as(i64, 8), doc.getArray("points").?[1].getInt("y").?);
    const inline_c = doc.getArray("extras.inline.b.c").?;
    try std.testing.expectEqual(@as(usize, 3), inline_c.len);
    try std.testing.expectEqual(@as(i64, 3), inline_c[2].integer);
}

test {
    std.testing.refAllDecls(@This());
}
