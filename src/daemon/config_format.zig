//! Mizuchi daemon configuration format.
//!
//! This is a strict, clean-room text format: `[section]` headers, `key = value`
//! assignments, comments (`#` or `//` outside strings), and typed values. The
//! parser is pure: callers supply bytes and optional env/file lookup callbacks.
const std = @import("std");

pub const ValueKind = enum { string, int, bool, duration, list, port };

pub const Field = struct {
    section: []const u8,
    key: []const u8,
    kind: ValueKind,
    required: bool = false,
    default: ?[]const u8 = null,
    min: ?u64 = null,
    max: ?u64 = null,
};

pub const Schema = struct {
    pub const fields = [_]Field{
        .{ .section = "node", .key = "id", .kind = .int, .required = true, .min = 1 },
        .{ .section = "node", .key = "public_key", .kind = .string },
        .{ .section = "node", .key = "secret_key", .kind = .string },
        .{ .section = "listen", .key = "host", .kind = .string, .default = "127.0.0.1" },
        .{ .section = "listen", .key = "irc", .kind = .port, .required = true, .min = 1, .max = 65535 },
        .{ .section = "listen", .key = "ws", .kind = .port, .default = "0", .max = 65535 },
        .{ .section = "listen", .key = "webtransport", .kind = .port, .default = "0", .max = 65535 },
        .{ .section = "listen", .key = "s2s", .kind = .port, .default = "0", .max = 65535 },
        .{ .section = "oper", .key = "account", .kind = .string, .required = true },
        .{ .section = "oper", .key = "class", .kind = .string, .default = "operator" },
        .{ .section = "mesh", .key = "realm", .kind = .string, .default = "local" },
        .{ .section = "mesh", .key = "trust_roots", .kind = .list },
        .{ .section = "mesh", .key = "mesh_pass", .kind = .string },
        .{ .section = "limits", .key = "backlog", .kind = .int, .default = "128", .min = 1, .max = 32767 },
        .{ .section = "limits", .key = "max_clients", .kind = .int, .default = "1024", .min = 1, .max = 32767 },
        .{ .section = "limits", .key = "handshake_timeout", .kind = .duration, .default = "30s", .min = 1000 },
        .{ .section = "limits", .key = "ping_interval", .kind = .duration, .default = "120s", .min = 1000 },
        .{ .section = "limits", .key = "ping_timeout", .kind = .duration, .default = "60s", .min = 1000 },
        .{ .section = "media", .key = "enabled", .kind = .bool, .default = "false" },
        .{ .section = "media", .key = "max_upload_bytes", .kind = .int, .default = "16777216", .max = 1073741824 },
        .{ .section = "media", .key = "max_frame_bytes", .kind = .int, .default = "65536", .max = 16777216 },
        .{ .section = "sasl", .key = "enabled", .kind = .bool, .default = "false" },
        .{ .section = "sasl", .key = "realm", .kind = .string },
        .{ .section = "sasl", .key = "account_db", .kind = .string },
        .{ .section = "cloak", .key = "secret", .kind = .string },
    };

    pub fn find(section: []const u8, key: []const u8) ?Field {
        for (fields) |field| {
            if (std.mem.eql(u8, field.section, section) and std.mem.eql(u8, field.key, key)) return field;
        }
        return null;
    }
};

pub const Diagnostic = struct {
    line: usize = 1,
    col: usize = 1,
    message: []const u8 = "",
};

pub const LookupFn = *const fn (?*anyopaque, std.mem.Allocator, []const u8) anyerror![]const u8;

pub const Resolver = struct {
    ctx: ?*anyopaque = null,
    env: ?LookupFn = null,
    file: ?LookupFn = null,
};

pub const Config = struct {
    node: Node = .{},
    listen: Listen = .{},
    opers: []Oper = &.{},
    mesh: Mesh = .{},
    limits: Limits = .{},
    media: Media = .{},
    sasl: Sasl = .{},
    cloak: Cloak = .{},

    pub const Node = struct {
        id: u64 = 0,
        public_key: ?[]const u8 = null,
        secret_key: ?[]const u8 = null,
    };

    pub const Listen = struct {
        host: []const u8 = "",
        irc: u16 = 0,
        ws: u16 = 0,
        webtransport: u16 = 0,
        s2s: u16 = 0,
    };

    /// An operator binding. Mizuchi grants oper SASL-only: `account` is the SASL
    /// account that is elevated on login (no password — SASL is the auth), and
    /// `class` names its privilege class. There is no OPER-password credential.
    pub const Oper = struct {
        account: []const u8 = "",
        class: []const u8 = "",
    };

    pub const Mesh = struct {
        realm: []const u8 = "",
        trust_roots: []const []const u8 = &.{},
        mesh_pass: ?[]const u8 = null,
    };

    pub const Limits = struct {
        backlog: u31 = 128,
        max_clients: u31 = 1024,
        handshake_timeout_ms: u64 = 30_000,
        ping_interval_ms: u64 = 120_000,
        ping_timeout_ms: u64 = 60_000,
    };

    pub const Media = struct {
        enabled: bool = false,
        max_upload_bytes: u64 = 16 * 1024 * 1024,
        max_frame_bytes: u64 = 64 * 1024,
    };

    pub const Sasl = struct {
        enabled: bool = false,
        realm: ?[]const u8 = null,
        /// Path (relative to the daemon cwd) of the WAL-backed account store. When
        /// set, the daemon opens it and verifies SASL credentials against it.
        account_db: ?[]const u8 = null,
    };

    pub const Cloak = struct {
        /// Secret passphrase for hostname cloaking. Hashed to a 32-byte key at
        /// boot; when set, every client's real IP is HMAC-cloaked. When absent,
        /// the daemon generates a random per-boot key (privacy on by default).
        secret: ?[]const u8 = null,
    };

    pub fn initDefaults(allocator: std.mem.Allocator) !Config {
        return .{
            .listen = .{ .host = try allocator.dupe(u8, "127.0.0.1") },
            .mesh = .{ .realm = try allocator.dupe(u8, "local") },
        };
    }

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        if (self.node.public_key) |value| allocator.free(value);
        if (self.node.secret_key) |value| allocator.free(value);
        allocator.free(self.listen.host);
        for (self.opers) |oper| {
            allocator.free(oper.account);
            allocator.free(oper.class);
        }
        allocator.free(self.opers);
        allocator.free(self.mesh.realm);
        for (self.mesh.trust_roots) |root| allocator.free(root);
        allocator.free(self.mesh.trust_roots);
        if (self.mesh.mesh_pass) |value| allocator.free(value);
        if (self.sasl.realm) |value| allocator.free(value);
        if (self.sasl.account_db) |value| allocator.free(value);
        if (self.cloak.secret) |value| allocator.free(value);
        self.* = .{};
    }
};

const Section = enum { none, node, listen, oper, mesh, limits, media, sasl, cloak };

pub const Parser = struct {
    allocator: std.mem.Allocator,
    source: []const u8,
    resolver: Resolver = .{},
    diagnostic: ?Diagnostic = null,
    diag_storage: [192]u8 = undefined,

    pub fn init(allocator: std.mem.Allocator, source: []const u8, resolver: Resolver) Parser {
        return .{ .allocator = allocator, .source = source, .resolver = resolver };
    }

    pub fn parse(self: *Parser) !Config {
        var cfg = try Config.initDefaults(self.allocator);
        errdefer cfg.deinit(self.allocator);

        var opers: std.ArrayList(Config.Oper) = .empty;
        errdefer {
            for (opers.items) |oper| {
                self.allocator.free(oper.account);
                self.allocator.free(oper.class);
            }
            opers.deinit(self.allocator);
        }

        var section: Section = .none;
        var line_no: usize = 1;
        var offset: usize = 0;
        while (offset <= self.source.len) : (line_no += 1) {
            const next = std.mem.indexOfScalarPos(u8, self.source, offset, '\n') orelse self.source.len;
            var line = self.source[offset..next];
            if (line.len != 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
            offset = next + 1;

            const uncommented = stripComment(line);
            const trimmed = std.mem.trim(u8, uncommented, " \t");
            if (trimmed.len == 0) {
                if (next == self.source.len) break;
                continue;
            }

            const leading = line.len - std.mem.trimStart(u8, uncommented, " \t").len;
            if (trimmed[0] == '[') {
                section = try self.parseSection(trimmed, line_no, leading + 1, &opers);
            } else {
                try self.parseAssignment(trimmed, line_no, leading + 1, section, &cfg, &opers);
            }
            if (next == self.source.len) break;
        }

        cfg.opers = try opers.toOwnedSlice(self.allocator);
        try self.validate(&cfg);
        return cfg;
    }

    fn parseSection(
        self: *Parser,
        text: []const u8,
        line: usize,
        col: usize,
        opers: *std.ArrayList(Config.Oper),
    ) !Section {
        if (text[text.len - 1] != ']') return self.fail(line, col + text.len - 1, "expected closing ']'", .{});
        const inner = std.mem.trim(u8, text[1 .. text.len - 1], " \t");
        if (std.mem.eql(u8, inner, "node")) return .node;
        if (std.mem.eql(u8, inner, "listen")) return .listen;
        if (std.mem.eql(u8, inner, "mesh")) return .mesh;
        if (std.mem.eql(u8, inner, "limits")) return .limits;
        if (std.mem.eql(u8, inner, "media")) return .media;
        if (std.mem.eql(u8, inner, "sasl")) return .sasl;
        if (std.mem.eql(u8, inner, "cloak")) return .cloak;
        if (std.mem.eql(u8, inner, "oper")) {
            try opers.append(self.allocator, .{});
            return .oper;
        }
        if (std.mem.startsWith(u8, inner, "oper.")) {
            const account = inner["oper.".len..];
            if (account.len == 0) return self.fail(line, col + 1, "expected oper account name", .{});
            try opers.append(self.allocator, .{ .account = try self.allocator.dupe(u8, account) });
            return .oper;
        }
        if (std.mem.startsWith(u8, inner, "oper ")) {
            const account = try self.parseStringValue(std.mem.trim(u8, inner["oper ".len..], " \t"), line, col + 6);
            try opers.append(self.allocator, .{ .account = account });
            return .oper;
        }
        return self.fail(line, col + 1, "unknown section '{s}'", .{inner});
    }

    fn parseAssignment(
        self: *Parser,
        text: []const u8,
        line: usize,
        col: usize,
        section: Section,
        cfg: *Config,
        opers: *std.ArrayList(Config.Oper),
    ) !void {
        if (section == .none) return self.fail(line, col, "expected a section header before assignments", .{});
        const eq = std.mem.indexOfScalar(u8, text, '=') orelse return self.fail(line, col, "expected '=' after key", .{});
        const key = std.mem.trim(u8, text[0..eq], " \t");
        const value = std.mem.trim(u8, text[eq + 1 ..], " \t");
        if (key.len == 0) return self.fail(line, col, "expected key before '='", .{});
        if (value.len == 0) return self.fail(line, col + eq + 2, "expected value after '='", .{});

        const section_name = sectionName(section);
        if (Schema.find(section_name, key) == null) return self.fail(line, col, "unknown key '{s}' in [{s}]", .{ key, section_name });

        switch (section) {
            .node => try self.setNode(line, col + eq + 2, key, value, &cfg.node),
            .listen => try self.setListen(line, col + eq + 2, key, value, &cfg.listen),
            .oper => {
                if (opers.items.len == 0) return self.fail(line, col, "internal parser state: no active oper block", .{});
                try self.setOper(line, col + eq + 2, key, value, &opers.items[opers.items.len - 1]);
            },
            .mesh => try self.setMesh(line, col + eq + 2, key, value, &cfg.mesh),
            .limits => try self.setLimits(line, col + eq + 2, key, value, &cfg.limits),
            .media => try self.setMedia(line, col + eq + 2, key, value, &cfg.media),
            .sasl => try self.setSasl(line, col + eq + 2, key, value, &cfg.sasl),
            .cloak => try self.setCloak(line, col + eq + 2, key, value, &cfg.cloak),
            .none => unreachable,
        }
    }

    fn setNode(self: *Parser, line: usize, col: usize, key: []const u8, value: []const u8, node: *Config.Node) !void {
        if (std.mem.eql(u8, key, "id")) node.id = try self.parseIntRange(value, line, col, "node.id", 1, std.math.maxInt(u64)) else if (std.mem.eql(u8, key, "public_key")) {
            replaceOptional(self.allocator, &node.public_key, try self.parseStringValue(value, line, col));
        } else if (std.mem.eql(u8, key, "secret_key")) {
            replaceOptional(self.allocator, &node.secret_key, try self.parseStringValue(value, line, col));
        }
    }

    fn setListen(self: *Parser, line: usize, col: usize, key: []const u8, value: []const u8, listen: *Config.Listen) !void {
        if (std.mem.eql(u8, key, "host")) {
            replaceString(self.allocator, &listen.host, try self.parseStringValue(value, line, col));
        } else if (std.mem.eql(u8, key, "irc")) listen.irc = @intCast(try self.parseIntRange(value, line, col, key, 1, 65535)) else if (std.mem.eql(u8, key, "ws")) listen.ws = @intCast(try self.parseIntRange(value, line, col, key, 0, 65535)) else if (std.mem.eql(u8, key, "webtransport")) listen.webtransport = @intCast(try self.parseIntRange(value, line, col, key, 0, 65535)) else if (std.mem.eql(u8, key, "s2s")) listen.s2s = @intCast(try self.parseIntRange(value, line, col, key, 0, 65535));
    }

    fn setOper(self: *Parser, line: usize, col: usize, key: []const u8, value: []const u8, oper: *Config.Oper) !void {
        if (std.mem.eql(u8, key, "account")) {
            replaceString(self.allocator, &oper.account, try self.parseStringValue(value, line, col));
        } else if (std.mem.eql(u8, key, "class")) {
            replaceString(self.allocator, &oper.class, try self.parseStringValue(value, line, col));
        }
    }

    fn setMesh(self: *Parser, line: usize, col: usize, key: []const u8, value: []const u8, mesh: *Config.Mesh) !void {
        if (std.mem.eql(u8, key, "realm")) {
            replaceString(self.allocator, &mesh.realm, try self.parseStringValue(value, line, col));
        } else if (std.mem.eql(u8, key, "mesh_pass")) {
            replaceOptional(self.allocator, &mesh.mesh_pass, try self.parseStringValue(value, line, col));
        } else if (std.mem.eql(u8, key, "trust_roots")) {
            const roots = try self.parseStringList(value, line, col);
            freeStringList(self.allocator, mesh.trust_roots);
            mesh.trust_roots = roots;
        }
    }

    fn setLimits(self: *Parser, line: usize, col: usize, key: []const u8, value: []const u8, limits: *Config.Limits) !void {
        if (std.mem.eql(u8, key, "backlog")) limits.backlog = @intCast(try self.parseIntRange(value, line, col, key, 1, 32767)) else if (std.mem.eql(u8, key, "max_clients")) limits.max_clients = @intCast(try self.parseIntRange(value, line, col, key, 1, 32767)) else if (std.mem.eql(u8, key, "handshake_timeout")) limits.handshake_timeout_ms = try self.parseDurationMs(value, line, col) else if (std.mem.eql(u8, key, "ping_interval")) limits.ping_interval_ms = try self.parseDurationMs(value, line, col) else if (std.mem.eql(u8, key, "ping_timeout")) limits.ping_timeout_ms = try self.parseDurationMs(value, line, col);
    }

    fn setMedia(self: *Parser, line: usize, col: usize, key: []const u8, value: []const u8, media: *Config.Media) !void {
        if (std.mem.eql(u8, key, "enabled")) media.enabled = try self.parseBool(value, line, col) else if (std.mem.eql(u8, key, "max_upload_bytes")) media.max_upload_bytes = try self.parseIntRange(value, line, col, key, 0, 1024 * 1024 * 1024) else if (std.mem.eql(u8, key, "max_frame_bytes")) media.max_frame_bytes = try self.parseIntRange(value, line, col, key, 0, 16 * 1024 * 1024);
    }

    fn setSasl(self: *Parser, line: usize, col: usize, key: []const u8, value: []const u8, sasl: *Config.Sasl) !void {
        if (std.mem.eql(u8, key, "enabled")) {
            sasl.enabled = try self.parseBool(value, line, col);
        } else if (std.mem.eql(u8, key, "realm")) {
            replaceOptional(self.allocator, &sasl.realm, try self.parseStringValue(value, line, col));
        } else if (std.mem.eql(u8, key, "account_db")) {
            replaceOptional(self.allocator, &sasl.account_db, try self.parseStringValue(value, line, col));
        }
    }

    fn setCloak(self: *Parser, line: usize, col: usize, key: []const u8, value: []const u8, c: *Config.Cloak) !void {
        if (std.mem.eql(u8, key, "secret")) {
            replaceOptional(self.allocator, &c.secret, try self.parseStringValue(value, line, col));
        }
    }

    fn validate(self: *Parser, cfg: *const Config) !void {
        if (cfg.node.id == 0) return self.fail(1, 1, "missing required field [node].id", .{});
        if (cfg.listen.irc == 0) return self.fail(1, 1, "missing required field [listen].irc", .{});
        for (cfg.opers, 0..) |oper, i| {
            if (oper.account.len == 0) return self.fail(1, 1, "missing required field [oper #{d}].account", .{i + 1});
        }
    }

    fn parseStringValue(self: *Parser, text: []const u8, line: usize, col: usize) ![]const u8 {
        if (try self.resolveIndirect(text, line, col)) |owned| return owned;
        if (text.len < 2 or text[0] != '"' or text[text.len - 1] != '"') return self.fail(line, col, "expected quoted string, env:NAME, or @file:path", .{});
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        var i: usize = 1;
        while (i + 1 < text.len) : (i += 1) {
            const ch = text[i];
            if (ch == '\\') {
                i += 1;
                if (i + 1 >= text.len) return self.fail(line, col + i, "expected escape character", .{});
                try out.append(self.allocator, switch (text[i]) {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '"', '\\' => text[i],
                    else => return self.fail(line, col + i, "unknown string escape", .{}),
                });
            } else if (ch == '"') {
                return self.fail(line, col + i, "unexpected quote inside string", .{});
            } else {
                try out.append(self.allocator, ch);
            }
        }
        return out.toOwnedSlice(self.allocator);
    }

    fn parseStringList(self: *Parser, text: []const u8, line: usize, col: usize) ![]const []const u8 {
        if (text.len < 2 or text[0] != '[' or text[text.len - 1] != ']') return self.fail(line, col, "expected list like [\"a\", \"b\"]", .{});
        var out: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (out.items) |item| self.allocator.free(item);
            out.deinit(self.allocator);
        }
        var cursor: usize = 1;
        while (true) {
            cursor = skipWs(text, cursor);
            if (cursor >= text.len - 1) break;
            const start = cursor;
            if (text[cursor] == '"') {
                cursor += 1;
                var escaped = false;
                while (cursor < text.len - 1) : (cursor += 1) {
                    if (escaped) {
                        escaped = false;
                    } else if (text[cursor] == '\\') {
                        escaped = true;
                    } else if (text[cursor] == '"') {
                        cursor += 1;
                        break;
                    }
                }
            } else {
                while (cursor < text.len - 1 and text[cursor] != ',') : (cursor += 1) {}
            }
            const item = std.mem.trim(u8, text[start..cursor], " \t");
            try out.append(self.allocator, try self.parseStringValue(item, line, col + start));
            cursor = skipWs(text, cursor);
            if (cursor < text.len - 1) {
                if (text[cursor] != ',') return self.fail(line, col + cursor, "expected ',' or ']'", .{});
                cursor += 1;
            }
        }
        return out.toOwnedSlice(self.allocator);
    }

    fn parseBool(self: *Parser, text: []const u8, line: usize, col: usize) !bool {
        if (try self.resolveIndirect(text, line, col)) |owned| {
            defer self.allocator.free(owned);
            return self.parseBool(owned, line, col);
        }
        if (std.mem.eql(u8, text, "true")) return true;
        if (std.mem.eql(u8, text, "false")) return false;
        return self.fail(line, col, "expected bool true or false", .{});
    }

    fn parseIntRange(self: *Parser, text: []const u8, line: usize, col: usize, name: []const u8, min: u64, max: u64) !u64 {
        if (try self.resolveIndirect(text, line, col)) |owned| {
            defer self.allocator.free(owned);
            return self.parseIntRange(std.mem.trim(u8, owned, " \t\r\n"), line, col, name, min, max);
        }
        if (text.len == 0 or text[0] == '-') return self.fail(line, col, "expected unsigned integer", .{});
        const value = std.fmt.parseInt(u64, text, 10) catch return self.fail(line, col, "expected unsigned integer", .{});
        if (value < min or value > max) return self.fail(line, col, "{s} must be in range {d}..{d}", .{ name, min, max });
        return value;
    }

    fn parseDurationMs(self: *Parser, text: []const u8, line: usize, col: usize) !u64 {
        if (try self.resolveIndirect(text, line, col)) |owned| {
            defer self.allocator.free(owned);
            return self.parseDurationMs(std.mem.trim(u8, owned, " \t\r\n"), line, col);
        }
        const units = [_]struct { suffix: []const u8, scale: u64 }{
            .{ .suffix = "ms", .scale = 1 },
            .{ .suffix = "s", .scale = 1000 },
            .{ .suffix = "m", .scale = 60_000 },
            .{ .suffix = "h", .scale = 3_600_000 },
        };
        for (units) |unit| {
            if (std.mem.endsWith(u8, text, unit.suffix)) {
                const digits = text[0 .. text.len - unit.suffix.len];
                const n = try self.parseIntRange(digits, line, col, "duration", 1, std.math.maxInt(u64) / unit.scale);
                return n * unit.scale;
            }
        }
        return self.fail(line, col, "expected duration with unit ms, s, m, or h", .{});
    }

    fn resolveIndirect(self: *Parser, text: []const u8, line: usize, col: usize) !?[]const u8 {
        if (std.mem.startsWith(u8, text, "env:")) {
            const name = text["env:".len..];
            if (name.len == 0) return self.fail(line, col, "expected environment variable name", .{});
            const func = self.resolver.env orelse return self.fail(line, col, "env lookup is not configured", .{});
            return try func(self.resolver.ctx, self.allocator, name);
        }
        if (std.mem.startsWith(u8, text, "@file:")) {
            const path = text["@file:".len..];
            if (path.len == 0) return self.fail(line, col, "expected file path", .{});
            const func = self.resolver.file orelse return self.fail(line, col, "file lookup is not configured", .{});
            return try func(self.resolver.ctx, self.allocator, path);
        }
        return null;
    }

    fn fail(self: *Parser, line: usize, col: usize, comptime fmt: []const u8, args: anytype) error{ParseError} {
        self.diagnostic = .{
            .line = line,
            .col = col,
            .message = std.fmt.bufPrint(&self.diag_storage, fmt, args) catch "invalid config",
        };
        return error.ParseError;
    }
};

pub fn parse(allocator: std.mem.Allocator, source: []const u8, resolver: Resolver) !Config {
    var parser = Parser.init(allocator, source, resolver);
    return parser.parse();
}

pub fn render(allocator: std.mem.Allocator, cfg: Config) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.print(allocator, "[node]\nid = {d}\n", .{cfg.node.id});
    if (cfg.node.public_key) |v| try writeKVString(allocator, &out, "public_key", v);
    if (cfg.node.secret_key) |v| try writeKVString(allocator, &out, "secret_key", v);
    try out.print(allocator, "\n[listen]\n", .{});
    try writeKVString(allocator, &out, "host", cfg.listen.host);
    try out.print(allocator, "irc = {d}\nws = {d}\nwebtransport = {d}\ns2s = {d}\n", .{ cfg.listen.irc, cfg.listen.ws, cfg.listen.webtransport, cfg.listen.s2s });
    for (cfg.opers) |oper| {
        try out.print(allocator, "\n[oper ", .{});
        try writeQuoted(allocator, &out, oper.account);
        try out.print(allocator, "]\n", .{});
        if (oper.class.len != 0) try writeKVString(allocator, &out, "class", oper.class);
    }
    try out.print(allocator, "\n[mesh]\n", .{});
    try writeKVString(allocator, &out, "realm", cfg.mesh.realm);
    try out.print(allocator, "trust_roots = [", .{});
    for (cfg.mesh.trust_roots, 0..) |root, i| {
        if (i != 0) try out.print(allocator, ", ", .{});
        try writeQuoted(allocator, &out, root);
    }
    try out.print(allocator, "]\n", .{});
    if (cfg.mesh.mesh_pass) |v| try writeKVString(allocator, &out, "mesh_pass", v);
    try out.print(allocator, "\n[limits]\nbacklog = {d}\nmax_clients = {d}\nhandshake_timeout = {d}ms\n", .{ cfg.limits.backlog, cfg.limits.max_clients, cfg.limits.handshake_timeout_ms });
    try out.print(allocator, "\n[media]\nenabled = {}\nmax_upload_bytes = {d}\nmax_frame_bytes = {d}\n", .{ cfg.media.enabled, cfg.media.max_upload_bytes, cfg.media.max_frame_bytes });
    try out.print(allocator, "\n[sasl]\nenabled = {}\n", .{cfg.sasl.enabled});
    if (cfg.sasl.realm) |v| try writeKVString(allocator, &out, "realm", v);
    return out.toOwnedSlice(allocator);
}

pub fn renderDefaults(allocator: std.mem.Allocator) ![]u8 {
    var cfg = try Config.initDefaults(allocator);
    defer cfg.deinit(allocator);
    cfg.node.id = 1;
    cfg.listen.irc = 6667;
    return render(allocator, cfg);
}

fn writeKVString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), key: []const u8, value: []const u8) !void {
    try out.print(allocator, "{s} = ", .{key});
    try writeQuoted(allocator, out, value);
    try out.append(allocator, '\n');
}

fn writeQuoted(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    try out.append(allocator, '"');
    for (value) |ch| switch (ch) {
        '\n' => try out.appendSlice(allocator, "\\n"),
        '\r' => try out.appendSlice(allocator, "\\r"),
        '\t' => try out.appendSlice(allocator, "\\t"),
        '"', '\\' => {
            try out.append(allocator, '\\');
            try out.append(allocator, ch);
        },
        else => try out.append(allocator, ch),
    };
    try out.append(allocator, '"');
}

fn stripComment(line: []const u8) []const u8 {
    var in_string = false;
    var escaped = false;
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        const ch = line[i];
        if (in_string) {
            if (escaped) escaped = false else if (ch == '\\') escaped = true else if (ch == '"') in_string = false;
        } else if (ch == '"') {
            in_string = true;
        } else if (ch == '#') {
            return line[0..i];
        } else if (ch == '/' and i + 1 < line.len and line[i + 1] == '/') {
            return line[0..i];
        }
    }
    return line;
}

fn skipWs(text: []const u8, start: usize) usize {
    var i = start;
    while (i < text.len and (text[i] == ' ' or text[i] == '\t')) : (i += 1) {}
    return i;
}

fn sectionName(section: Section) []const u8 {
    return switch (section) {
        .none => "",
        .node => "node",
        .listen => "listen",
        .oper => "oper",
        .mesh => "mesh",
        .limits => "limits",
        .media => "media",
        .sasl => "sasl",
        .cloak => "cloak",
    };
}

fn replaceString(allocator: std.mem.Allocator, slot: *[]const u8, owned: []const u8) void {
    allocator.free(slot.*);
    slot.* = owned;
}

fn replaceOptional(allocator: std.mem.Allocator, slot: *?[]const u8, owned: []const u8) void {
    if (slot.*) |old| allocator.free(old);
    slot.* = owned;
}

fn freeStringList(allocator: std.mem.Allocator, values: []const []const u8) void {
    for (values) |value| allocator.free(value);
    allocator.free(values);
}

const sample_config =
    \\# Mizuchi config
    \\[node]
    \\id = 42
    \\public_key = "node-public"
    \\secret_key = @file:/run/mizuchi/node.key
    \\
    \\[listen]
    \\host = "0.0.0.0"
    \\irc = 6667
    \\ws = 8080
    \\webtransport = 4433
    \\s2s = 7000
    \\
    \\[oper "root"]
    \\class = "netadmin"
    \\
    \\[mesh]
    \\realm = "earth"
    \\trust_roots = ["root-a", @file:/run/mizuchi/root-b.pub]
    \\mesh_pass = env:MIZUCHI_MESH_PASS
    \\
    \\[limits]
    \\backlog = 256
    \\max_clients = 2048
    \\handshake_timeout = 45s
    \\
    \\[media]
    \\enabled = true
    \\max_upload_bytes = 33554432
    \\max_frame_bytes = 131072
    \\
    \\[sasl]
    \\enabled = true
    \\realm = "accounts"
;

fn envLookup(_: ?*anyopaque, allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
    if (std.mem.eql(u8, name, "MIZUCHI_OPER_PASS")) return allocator.dupe(u8, "oper-secret");
    if (std.mem.eql(u8, name, "MIZUCHI_MESH_PASS")) return allocator.dupe(u8, "mesh-secret");
    return error.NotFound;
}

fn fileLookup(_: ?*anyopaque, allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    if (std.mem.eql(u8, path, "/run/mizuchi/node.key")) return allocator.dupe(u8, "node-secret");
    if (std.mem.eql(u8, path, "/run/mizuchi/root-b.pub")) return allocator.dupe(u8, "root-b");
    return error.NotFound;
}

test "parse sample config" {
    var parser = Parser.init(std.testing.allocator, sample_config, .{ .env = envLookup, .file = fileLookup });
    var cfg = try parser.parse();
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 42), cfg.node.id);
    try std.testing.expectEqual(@as(u16, 6667), cfg.listen.irc);
    try std.testing.expectEqual(@as(usize, 1), cfg.opers.len);
    try std.testing.expectEqualStrings("root", cfg.opers[0].account);
    try std.testing.expectEqualStrings("netadmin", cfg.opers[0].class);
    try std.testing.expectEqualStrings("root-b", cfg.mesh.trust_roots[1]);
    try std.testing.expectEqual(@as(u64, 45_000), cfg.limits.handshake_timeout_ms);
    try std.testing.expect(cfg.media.enabled);
    try std.testing.expect(cfg.sasl.enabled);
}

test "missing required field reports clear error" {
    var parser = Parser.init(std.testing.allocator,
        \\[node]
        \\id = 7
    , .{});
    try std.testing.expectError(error.ParseError, parser.parse());
    const diag = parser.diagnostic.?;
    try std.testing.expectEqual(@as(usize, 1), diag.line);
    try std.testing.expect(std.mem.indexOf(u8, diag.message, "[listen].irc") != null);
}

test "bad type reports line" {
    var parser = Parser.init(std.testing.allocator,
        \\[node]
        \\id = 9
        \\[listen]
        \\irc = "not-a-port"
    , .{});
    try std.testing.expectError(error.ParseError, parser.parse());
    const diag = parser.diagnostic.?;
    try std.testing.expectEqual(@as(usize, 4), diag.line);
    try std.testing.expect(std.mem.indexOf(u8, diag.message, "unsigned integer") != null);
}

test "env and file indirection resolve through callbacks" {
    var parser = Parser.init(std.testing.allocator, sample_config, .{ .env = envLookup, .file = fileLookup });
    var cfg = try parser.parse();
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("node-secret", cfg.node.secret_key.?);
    try std.testing.expectEqualStrings("mesh-secret", cfg.mesh.mesh_pass.?);
}

test "round trip render parses again" {
    var parser = Parser.init(std.testing.allocator, sample_config, .{ .env = envLookup, .file = fileLookup });
    var cfg = try parser.parse();
    defer cfg.deinit(std.testing.allocator);
    const text = try render(std.testing.allocator, cfg);
    defer std.testing.allocator.free(text);
    var parser2 = Parser.init(std.testing.allocator, text, .{});
    var again = try parser2.parse();
    defer again.deinit(std.testing.allocator);
    try std.testing.expectEqual(cfg.node.id, again.node.id);
    try std.testing.expectEqualStrings(cfg.opers[0].account, again.opers[0].account);
    try std.testing.expectEqualStrings(cfg.mesh.trust_roots[1], again.mesh.trust_roots[1]);
}
