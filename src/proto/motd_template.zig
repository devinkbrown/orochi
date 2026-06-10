//! Personalized MOTD template engine.
//!
//! The MOTD text (configured `[motd] text` or the built-in default) is treated
//! as a template expanded per connection, so a single MOTD greets each client
//! by name, reflects their login/oper state, and shows live network figures.
//!
//! Substitution: `{key}` is replaced from `Vars`; an unknown key is left
//! verbatim. `{{` and `}}` emit literal braces.
//!
//! Conditionals: `{if:COND}...{else}...{/if}` includes one branch based on a
//! per-connection predicate. Supported conditions: `oper`, `account`, `secure`.
//! Conditionals nest and may contain substitutions.
//!
//! Pure `std`; allocation-free (caller supplies the output buffer); natively
//! unit-tested.
const std = @import("std");

/// Per-connection values available to a MOTD template.
pub const Vars = struct {
    nick: []const u8 = "",
    /// Account name, or null when the client is not logged in.
    account: ?[]const u8 = null,
    host: []const u8 = "",
    network: []const u8 = "",
    server: []const u8 = "",
    version: []const u8 = "",
    /// Preformatted local time / date strings (caller-rendered).
    time: []const u8 = "",
    date: []const u8 = "",
    users: u64 = 0,
    opers: u64 = 0,
    channels: u64 = 0,
    is_oper: bool = false,
    /// Whether the client is on a TLS (secure) link.
    secure: bool = false,
    /// Server-local hour [0,23] for the time-of-day `{greeting}`.
    hour: u8 = 12,
    /// Pre-rendered, locale-correct weather line (empty = unavailable).
    weather: []const u8 = "",
    /// Pre-rendered news headline(s) line (empty = unavailable).
    news: []const u8 = "",
};

pub const Error = error{ BufTooSmall, MalformedTemplate };

/// A time-of-day greeting for `hour` (0..23).
pub fn greetingFor(hour: u8) []const u8 {
    return if (hour < 5)
        "Good evening"
    else if (hour < 12)
        "Good morning"
    else if (hour < 18)
        "Good afternoon"
    else
        "Good evening";
}

const Writer = struct {
    buf: []u8,
    len: usize = 0,

    fn write(self: *Writer, bytes: []const u8) Error!void {
        if (self.len + bytes.len > self.buf.len) return error.BufTooSmall;
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn writeU64(self: *Writer, v: u64) Error!void {
        var tmp: [20]u8 = undefined;
        const s = std.fmt.bufPrint(&tmp, "{d}", .{v}) catch return error.BufTooSmall;
        try self.write(s);
    }
};

/// Expand `template` into `out` using `vars`, returning the written slice.
pub fn expand(template: []const u8, vars: Vars, out: []u8) Error![]const u8 {
    var w = Writer{ .buf = out };
    try expandRange(template, vars, &w, 0);
    return w.buf[0..w.len];
}

const max_depth: usize = 16;

fn expandRange(tmpl: []const u8, vars: Vars, w: *Writer, depth: usize) Error!void {
    if (depth > max_depth) return error.MalformedTemplate;
    var i: usize = 0;
    while (i < tmpl.len) {
        const c = tmpl[i];
        if (c == '}' and i + 1 < tmpl.len and tmpl[i + 1] == '}') {
            try w.write("}");
            i += 2;
            continue;
        }
        if (c != '{') {
            try w.write(tmpl[i .. i + 1]);
            i += 1;
            continue;
        }
        // c == '{'
        if (i + 1 < tmpl.len and tmpl[i + 1] == '{') {
            try w.write("{");
            i += 2;
            continue;
        }
        const close = std.mem.indexOfScalarPos(u8, tmpl, i, '}') orelse {
            // No closing brace: emit the rest verbatim.
            try w.write(tmpl[i..]);
            return;
        };
        const tag = tmpl[i + 1 .. close];

        if (std.mem.startsWith(u8, tag, "if:")) {
            const cond = tag["if:".len..];
            const block = try findIfBlock(tmpl, i);
            const taken = if (evalCond(cond, vars)) block.then_text else block.else_text;
            try expandRange(taken, vars, w, depth + 1);
            i = block.after;
            continue;
        }
        if (std.mem.eql(u8, tag, "else") or std.mem.eql(u8, tag, "/if")) {
            // A stray else/endif outside a block: emit verbatim.
            try w.write(tmpl[i .. close + 1]);
            i = close + 1;
            continue;
        }

        // Plain substitution; unknown keys are emitted verbatim.
        if (try substitute(tag, vars, w)) {
            i = close + 1;
        } else {
            try w.write(tmpl[i .. close + 1]);
            i = close + 1;
        }
    }
}

fn evalCond(cond: []const u8, vars: Vars) bool {
    if (std.mem.eql(u8, cond, "oper")) return vars.is_oper;
    if (std.mem.eql(u8, cond, "account")) return vars.account != null;
    if (std.mem.eql(u8, cond, "secure")) return vars.secure;
    if (std.mem.eql(u8, cond, "weather")) return vars.weather.len != 0;
    if (std.mem.eql(u8, cond, "news")) return vars.news.len != 0;
    return false;
}

/// Replace a known `{key}` into `w`; returns false when the key is unknown.
fn substitute(key: []const u8, vars: Vars, w: *Writer) Error!bool {
    if (std.mem.eql(u8, key, "nick")) {
        try w.write(vars.nick);
    } else if (std.mem.eql(u8, key, "account")) {
        try w.write(vars.account orelse "*");
    } else if (std.mem.eql(u8, key, "host")) {
        try w.write(vars.host);
    } else if (std.mem.eql(u8, key, "network")) {
        try w.write(vars.network);
    } else if (std.mem.eql(u8, key, "server")) {
        try w.write(vars.server);
    } else if (std.mem.eql(u8, key, "version")) {
        try w.write(vars.version);
    } else if (std.mem.eql(u8, key, "time")) {
        try w.write(vars.time);
    } else if (std.mem.eql(u8, key, "date")) {
        try w.write(vars.date);
    } else if (std.mem.eql(u8, key, "greeting")) {
        try w.write(greetingFor(vars.hour));
    } else if (std.mem.eql(u8, key, "weather")) {
        try w.write(vars.weather);
    } else if (std.mem.eql(u8, key, "news")) {
        try w.write(vars.news);
    } else if (std.mem.eql(u8, key, "users")) {
        try w.writeU64(vars.users);
    } else if (std.mem.eql(u8, key, "opers")) {
        try w.writeU64(vars.opers);
    } else if (std.mem.eql(u8, key, "channels")) {
        try w.writeU64(vars.channels);
    } else {
        return false;
    }
    return true;
}

const IfBlock = struct {
    /// Template text of the `then` branch (between `{if:...}` and `{else}`/`{/if}`).
    then_text: []const u8,
    /// Template text of the `else` branch (empty when no `{else}`).
    else_text: []const u8,
    /// Index in the source template just past the matching `{/if}`.
    after: usize,
};

/// Locate the branches and end of the `{if:...}` block that starts at `open`
/// (the index of its `{`). Honors nested `{if}`/`{/if}` pairs.
fn findIfBlock(tmpl: []const u8, open: usize) Error!IfBlock {
    const body_start = (std.mem.indexOfScalarPos(u8, tmpl, open, '}') orelse return error.MalformedTemplate) + 1;
    var depth: usize = 1;
    var i: usize = body_start;
    var else_at: ?usize = null; // index of the top-level {else}'s '{'
    while (i < tmpl.len) {
        if (tmpl[i] != '{') {
            i += 1;
            continue;
        }
        if (i + 1 < tmpl.len and tmpl[i + 1] == '{') {
            i += 2;
            continue;
        }
        const close = std.mem.indexOfScalarPos(u8, tmpl, i, '}') orelse return error.MalformedTemplate;
        const tag = tmpl[i + 1 .. close];
        if (std.mem.startsWith(u8, tag, "if:")) {
            depth += 1;
        } else if (std.mem.eql(u8, tag, "/if")) {
            depth -= 1;
            if (depth == 0) {
                const then_end = else_at orelse i;
                const then_text = tmpl[body_start..then_end];
                const else_text = if (else_at) |e|
                    tmpl[(std.mem.indexOfScalarPos(u8, tmpl, e, '}').? + 1)..i]
                else
                    "";
                return .{ .then_text = then_text, .else_text = else_text, .after = close + 1 };
            }
        } else if (std.mem.eql(u8, tag, "else") and depth == 1 and else_at == null) {
            else_at = i;
        }
        i = close + 1;
    }
    return error.MalformedTemplate;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectExpand(template: []const u8, vars: Vars, want: []const u8) !void {
    var buf: [512]u8 = undefined;
    const got = try expand(template, vars, &buf);
    try testing.expectEqualStrings(want, got);
}

test "substitutes known variables" {
    try expectExpand(
        "Hi {nick} on {network} ({users} users)",
        .{ .nick = "alice", .network = "ExampleNet", .users = 42 },
        "Hi alice on ExampleNet (42 users)",
    );
}

test "unknown keys and braces are left verbatim" {
    try expectExpand("a {bogus} b {{lit}} c", .{}, "a {bogus} b {lit} c");
}

test "weather and news substitute, with conditional gating on presence" {
    try expectExpand(
        "{if:account}{account}{else}guest{/if} — {weather}",
        .{ .account = "alice", .weather = "Austin: 72°F, wind 8 mph" },
        "alice — Austin: 72°F, wind 8 mph",
    );
    // Absent weather/news expand to empty.
    try expectExpand("[{weather}][{news}]", .{}, "[][]");
}

test "greeting reflects the hour" {
    try expectExpand("{greeting}", .{ .hour = 9 }, "Good morning");
    try expectExpand("{greeting}", .{ .hour = 14 }, "Good afternoon");
    try expectExpand("{greeting}", .{ .hour = 21 }, "Good evening");
    try expectExpand("{greeting}", .{ .hour = 2 }, "Good evening");
}

test "account substitutes name or * when absent" {
    try expectExpand("acct={account}", .{ .account = "bob" }, "acct=bob");
    try expectExpand("acct={account}", .{ .account = null }, "acct=*");
}

test "if:oper selects branch" {
    try expectExpand("{if:oper}OPER{/if}done", .{ .is_oper = true }, "OPERdone");
    try expectExpand("{if:oper}OPER{/if}done", .{ .is_oper = false }, "done");
}

test "if:account with else" {
    try expectExpand(
        "{if:account}Welcome back, {account}!{else}Please register.{/if}",
        .{ .account = "carol" },
        "Welcome back, carol!",
    );
    try expectExpand(
        "{if:account}Welcome back, {account}!{else}Please register.{/if}",
        .{ .account = null },
        "Please register.",
    );
}

test "nested conditionals expand the right branches" {
    const t = "{if:oper}op{if:secure}+tls{else}+plain{/if}{else}user{/if}";
    try expectExpand(t, .{ .is_oper = true, .secure = true }, "op+tls");
    try expectExpand(t, .{ .is_oper = true, .secure = false }, "op+plain");
    try expectExpand(t, .{ .is_oper = false }, "user");
}

test "reports a too-small output buffer" {
    var tiny: [3]u8 = undefined;
    try testing.expectError(error.BufTooSmall, expand("{nick}", .{ .nick = "longname" }, &tiny));
}

test "malformed (unterminated) if is reported" {
    var buf: [128]u8 = undefined;
    try testing.expectError(error.MalformedTemplate, expand("{if:oper}x", .{}, &buf));
}

test "stray else and endif emit verbatim outside a block" {
    try expectExpand("a {else} b {/if} c", .{}, "a {else} b {/if} c");
}
