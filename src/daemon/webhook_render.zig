// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Discord webhook payload → IRC rendering + hostile-input sanitisation.
//!
//! Pure and allocator-transient: `render` parses an untrusted Discord webhook
//! JSON body into a `webhook.PendingPost` (bot nick + `\n`-joined body lines).
//! Every produced byte is scrubbed of control characters and CR/LF/NUL BEFORE
//! it can reach the wire, and the body is pre-split into separate lines so the
//! reactor can emit one `PRIVMSG` per line — a `\r\n` (or any control byte) in
//! `content`/`username`/an embed can therefore never forge a second wire line
//! or inject an IRC command.
//!
//! The Discord shape handled (all fields optional; a usable post needs `content`
//! OR at least one non-empty embed/component):
//!   { "content", "username", "avatar_url",
//!     "embeds": [ { "title", "description", "url",
//!                   "author": { "name" }, "footer": { "text" },
//!                   "fields": [ { "name", "value" } ] } ],
//!     "components": [ { "type": 1, "components": [
//!                   { "type": 2, "label", "url", "custom_id" },
//!                   { "type": 3, "placeholder",
//!                     "options": [ { "label" } ] } ] } ] }

const std = @import("std");

const webhook = @import("webhook.zig");

/// Max characters emitted per rendered IRC line (keeps `:prefix PRIVMSG #chan
/// :<text>` comfortably under the 512-byte wire limit).
pub const max_line: usize = 400;
/// Max number of lines a single webhook post may expand into.
pub const max_lines: usize = 24;

pub const RenderError = error{ BadJson, EmptyPayload };

/// Parse `body` (untrusted JSON) and fill `post.nick` + `post.body` with the
/// sanitised rendering. `post.channel` is set by the caller from the resolved
/// binding. `fallback_name` supplies the bot nick when the payload omits
/// `username` (typically the binding's configured name).
pub fn render(
    allocator: std.mem.Allocator,
    body: []const u8,
    fallback_name: []const u8,
    post: *webhook.PendingPost,
) RenderError!void {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch
        return error.BadJson;
    defer parsed.deinit();

    if (parsed.value != .object) return error.BadJson;
    const obj = parsed.value.object;

    // --- Bot nick -------------------------------------------------------
    const username = strField(obj, "username") orelse fallback_name;
    var nick_buf: [webhook.max_nick]u8 = undefined;
    const nick = sanitizeNick(username, &nick_buf);
    post.setNick(nick);

    // --- Body lines -----------------------------------------------------
    // Accumulate sanitised lines joined by a single '\n' into the post body.
    var writer = LineWriter{ .buf = &post.body_buf };

    if (strField(obj, "content")) |content| {
        appendMultiline(&writer, content);
    }

    if (obj.get("embeds")) |embeds_val| {
        if (embeds_val == .array) {
            for (embeds_val.array.items) |item| {
                if (item != .object) continue;
                renderEmbed(&writer, item.object);
                if (writer.lines >= max_lines) break;
            }
        }
    }

    if (obj.get("components")) |components_val| {
        renderComponents(&writer, components_val);
    }

    if (writer.lines == 0) return error.EmptyPayload;
    post.body_len = @intCast(writer.len);
}

/// Render one embed object into compact IRC lines: title, description, then
/// `name: value` per field. Empty pieces are skipped.
fn renderEmbed(w: *LineWriter, embed: std.json.ObjectMap) void {
    if (objectField(embed, "author")) |author| {
        if (strField(author, "name")) |name| appendLabelled(w, "by ", name);
    }
    if (strField(embed, "title")) |title| {
        if (strField(embed, "url")) |url|
            appendTitleUrl(w, title, url)
        else
            appendLabelled(w, "* ", title);
    }
    if (strField(embed, "description")) |desc| {
        appendMultiline(w, desc);
    }
    if (embed.get("fields")) |fields_val| {
        if (fields_val == .array) {
            for (fields_val.array.items) |fv| {
                if (fv != .object) continue;
                const name = strField(fv.object, "name") orelse "";
                const value = strField(fv.object, "value") orelse "";
                appendField(w, name, value);
            }
        }
    }
    if (objectField(embed, "footer")) |footer| {
        if (strField(footer, "text")) |text| appendLabelled(w, "-- ", text);
    }
}

/// Split `text` on newlines and append each sanitised, non-empty line.
fn appendMultiline(w: *LineWriter, text: []const u8) void {
    var it = std.mem.splitAny(u8, text, "\r\n");
    while (it.next()) |raw| {
        if (w.lines >= max_lines) return;
        var tmp: [max_line]u8 = undefined;
        const clean = sanitizeLine(raw, &tmp);
        if (clean.len != 0) w.addLine(clean);
    }
}

fn appendLabelled(w: *LineWriter, prefix: []const u8, text: []const u8) void {
    var tmp: [max_line]u8 = undefined;
    const clean = sanitizeLine(text, &tmp);
    if (clean.len != 0) w.addPrefixed(prefix, clean);
}

fn appendTitleUrl(w: *LineWriter, title: []const u8, url: []const u8) void {
    var tbuf: [max_line]u8 = undefined;
    const clean_title = sanitizeLine(title, &tbuf);
    if (clean_title.len == 0) return;
    var ubuf: [max_line]u8 = undefined;
    const clean_url = sanitizeLine(url, &ubuf);
    if (clean_url.len == 0) {
        w.addPrefixed("* ", clean_title);
        return;
    }
    var joined: [max_line]u8 = undefined;
    const line = std.fmt.bufPrint(&joined, "{s} <{s}>", .{ clean_title, clean_url }) catch clean_title;
    w.addPrefixed("* ", line);
}

/// Append a `name: value` field. `value` may itself be multi-line; only the
/// first physical line carries the `name:` label, continuations are indented.
fn appendField(w: *LineWriter, name: []const u8, value: []const u8) void {
    var nbuf: [max_line]u8 = undefined;
    const clean_name = sanitizeLine(name, &nbuf);
    var it = std.mem.splitAny(u8, value, "\r\n");
    var first = true;
    while (it.next()) |raw| {
        if (w.lines >= max_lines) return;
        var vbuf: [max_line]u8 = undefined;
        const clean_val = sanitizeLine(raw, &vbuf);
        if (first) {
            if (clean_name.len == 0 and clean_val.len == 0) continue;
            first = false;
            if (clean_name.len != 0 and clean_val.len != 0) {
                var joined: [max_line]u8 = undefined;
                const n = std.fmt.bufPrint(&joined, "{s}: {s}", .{ clean_name, clean_val }) catch {
                    w.addLine(clean_name);
                    continue;
                };
                w.addLine(n);
            } else if (clean_name.len != 0) {
                w.addPrefixed("", clean_name);
            } else {
                w.addLine(clean_val);
            }
        } else if (clean_val.len != 0) {
            w.addPrefixed("  ", clean_val);
        }
    }
}

fn renderComponents(w: *LineWriter, components_val: std.json.Value) void {
    if (components_val != .array) return;
    for (components_val.array.items) |item| {
        if (w.lines >= max_lines) return;
        if (item != .object) continue;
        renderComponent(w, item.object);
    }
}

fn renderComponent(w: *LineWriter, component: std.json.ObjectMap) void {
    const kind = intField(component, "type") orelse 0;
    switch (kind) {
        1 => {
            const children = component.get("components") orelse return;
            if (children != .array) return;
            for (children.array.items) |child| {
                if (w.lines >= max_lines) return;
                if (child == .object) renderComponent(w, child.object);
            }
        },
        2 => renderButton(w, component),
        3, 5, 6, 7, 8 => renderSelect(w, component),
        else => {},
    }
}

fn renderButton(w: *LineWriter, button: std.json.ObjectMap) void {
    const label = strField(button, "label") orelse strField(button, "custom_id") orelse return;
    var lbuf: [max_line]u8 = undefined;
    const clean_label = sanitizeLine(label, &lbuf);
    if (clean_label.len == 0) return;
    if (strField(button, "url")) |url| {
        var ubuf: [max_line]u8 = undefined;
        const clean_url = sanitizeLine(url, &ubuf);
        var joined: [max_line]u8 = undefined;
        const line = if (clean_url.len == 0)
            clean_label
        else
            std.fmt.bufPrint(&joined, "{s} <{s}>", .{ clean_label, clean_url }) catch clean_label;
        w.addPrefixed("[button] ", line);
    } else {
        w.addPrefixed("[button] ", clean_label);
    }
}

fn renderSelect(w: *LineWriter, select: std.json.ObjectMap) void {
    const label = strField(select, "placeholder") orelse "select";
    var lbuf: [max_line]u8 = undefined;
    const clean_label = sanitizeLine(label, &lbuf);
    if (clean_label.len == 0) return;

    var options_buf: [max_line]u8 = undefined;
    var options_len: usize = 0;
    if (select.get("options")) |options| {
        if (options == .array) {
            for (options.array.items) |opt| {
                if (opt != .object) continue;
                const opt_label = strField(opt.object, "label") orelse continue;
                var obuf: [max_line]u8 = undefined;
                const clean_opt = sanitizeLine(opt_label, &obuf);
                if (clean_opt.len == 0) continue;
                const sep = if (options_len == 0) "" else ", ";
                if (options_len + sep.len + clean_opt.len > options_buf.len) break;
                @memcpy(options_buf[options_len .. options_len + sep.len], sep);
                options_len += sep.len;
                @memcpy(options_buf[options_len .. options_len + clean_opt.len], clean_opt);
                options_len += clean_opt.len;
            }
        }
    }

    var joined: [max_line]u8 = undefined;
    const line = if (options_len == 0)
        clean_label
    else
        std.fmt.bufPrint(&joined, "{s}: {s}", .{ clean_label, options_buf[0..options_len] }) catch clean_label;
    w.addPrefixed("[select] ", line);
}

/// Accumulator that joins lines with a single '\n' into a fixed buffer, capping
/// both the line count and the total byte length.
const LineWriter = struct {
    buf: *[webhook.max_body_render]u8,
    len: usize = 0,
    lines: usize = 0,

    fn addLine(self: *LineWriter, line: []const u8) void {
        self.addPrefixed("", line);
    }

    fn addPrefixed(self: *LineWriter, prefix: []const u8, line: []const u8) void {
        if (self.lines >= max_lines) return;
        const need = (if (self.lines == 0) @as(usize, 0) else 1) + prefix.len + line.len;
        if (self.len + need > self.buf.len) return; // out of inline space: drop
        if (self.lines != 0) {
            self.buf[self.len] = '\n';
            self.len += 1;
        }
        @memcpy(self.buf[self.len .. self.len + prefix.len], prefix);
        self.len += prefix.len;
        @memcpy(self.buf[self.len .. self.len + line.len], line);
        self.len += line.len;
        self.lines += 1;
    }
};

// ---------------------------------------------------------------------------
// Sanitisation
// ---------------------------------------------------------------------------

/// Copy `in` into `out`, dropping every C0 control byte (0x00–0x1F, incl. CR,
/// LF, NUL, TAB) and DEL (0x7F). Printable ASCII and all high (UTF-8 ≥ 0x80)
/// bytes pass through. Trailing spaces are trimmed. The result is capped at
/// `out.len`. Because CR/LF are removed, the returned slice can NEVER split the
/// wire into a second line when placed in a `PRIVMSG` trailing parameter.
pub fn sanitizeLine(in: []const u8, out: []u8) []const u8 {
    var n: usize = 0;
    for (in) |c| {
        if (n >= out.len) break;
        if (c < 0x20 or c == 0x7f) continue; // strip all control bytes
        out[n] = c;
        n += 1;
    }
    // Trim trailing spaces (leading spaces are preserved — harmless as trailing).
    while (n > 0 and out[n - 1] == ' ') n -= 1;
    return out[0..n];
}

/// Derive a valid, wire-safe IRC nick from an arbitrary `username`. Disallowed
/// bytes (space, control, and the prefix/routing metacharacters
/// `!@:.#&+%~,*?` etc.) become '-'; runs of '-' collapse; a leading non-letter
/// is prefixed so the nick never looks like a channel, numeric, or command. The
/// result is guaranteed non-empty (falls back to "webhook"), space/CR/LF-free,
/// and capped to `webhook.max_nick`, so it can be dropped into a message prefix
/// (`:<nick>!…`) without corrupting the wire.
pub fn sanitizeNick(username: []const u8, out: []u8) []const u8 {
    var n: usize = 0;
    var last_dash = false;
    for (username) |c| {
        if (n >= out.len) break;
        if (isNickByte(c)) {
            out[n] = c;
            n += 1;
            last_dash = false;
        } else {
            // Collapse any run of disallowed bytes into a single '-'.
            if (!last_dash and n < out.len) {
                out[n] = '-';
                n += 1;
                last_dash = true;
            }
        }
    }
    // Trim trailing '-'.
    while (n > 0 and out[n - 1] == '-') n -= 1;
    var s = out[0..n];
    // Drop a leading '-' by shifting (rare; keeps the nick well-formed).
    var start: usize = 0;
    while (start < s.len and s[start] == '-') start += 1;
    s = s[start..];
    if (s.len == 0) return "webhook";
    // First char must be a letter or an RFC "special" — never a digit — so the
    // nick can't be mistaken for a numeric or channel. If it is not, fall back.
    if (!isNickFirst(s[0])) return "webhook";
    return s;
}

fn isNickByte(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
        (c >= '0' and c <= '9') or
        c == '[' or c == ']' or c == '\\' or c == '`' or
        c == '_' or c == '^' or c == '{' or c == '}' or c == '|' or c == '-';
}

fn isNickFirst(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
        c == '[' or c == ']' or c == '\\' or c == '`' or
        c == '_' or c == '^' or c == '{' or c == '}' or c == '|';
}

// ---------------------------------------------------------------------------
// std.json helpers
// ---------------------------------------------------------------------------

fn strField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn objectField(obj: std.json.ObjectMap, key: []const u8) ?std.json.ObjectMap {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .object => |o| o,
        else => null,
    };
}

fn intField(obj: std.json.ObjectMap, key: []const u8) ?i64 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .integer => |n| n,
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn renderBody(body: []const u8, post: *webhook.PendingPost) RenderError!void {
    return render(testing.allocator, body, "hook", post);
}

test "render maps content to the body and username to a bot nick" {
    var post: webhook.PendingPost = .{};
    try renderBody("{\"content\":\"hello world\",\"username\":\"CI Bot\"}", &post);
    try testing.expectEqualStrings("hello world", post.body());
    try testing.expectEqualStrings("CI-Bot", post.nick());
}

test "render falls back to the binding name when username is absent" {
    var post: webhook.PendingPost = .{};
    try renderBody("{\"content\":\"hi\"}", &post);
    try testing.expectEqualStrings("hook", post.nick());
}

test "CRLF in content becomes separate lines, never a second wire line" {
    var post: webhook.PendingPost = .{};
    try renderBody("{\"content\":\"line1\\r\\nPRIVMSG #evil :owned\"}", &post);
    // The body holds two '\n'-separated lines; NO raw CR/LF survive.
    try testing.expect(std.mem.indexOfScalar(u8, post.body(), '\r') == null);
    var it = std.mem.splitScalar(u8, post.body(), '\n');
    try testing.expectEqualStrings("line1", it.next().?);
    try testing.expectEqualStrings("PRIVMSG #evil :owned", it.next().?);
    try testing.expect(it.next() == null);
}

test "control characters are stripped from the body" {
    var post: webhook.PendingPost = .{};
    // Embedded NUL, bell, and tab must not appear in the output.
    try renderBody("{\"content\":\"a\\u0000b\\u0007c\\td\"}", &post);
    try testing.expectEqualStrings("abcd", post.body());
}

test "embeds render as compact title/description/field lines" {
    var post: webhook.PendingPost = .{};
    const body =
        "{\"embeds\":[{\"title\":\"Deploy\",\"description\":\"succeeded\"," ++
        "\"fields\":[{\"name\":\"env\",\"value\":\"prod\"},{\"name\":\"rev\",\"value\":\"abc123\"}]}]}";
    try renderBody(body, &post);
    var it = std.mem.splitScalar(u8, post.body(), '\n');
    try testing.expectEqualStrings("* Deploy", it.next().?);
    try testing.expectEqualStrings("succeeded", it.next().?);
    try testing.expectEqualStrings("env: prod", it.next().?);
    try testing.expectEqualStrings("rev: abc123", it.next().?);
}

test "embeds render author title URL and footer metadata" {
    var post: webhook.PendingPost = .{};
    const body =
        "{\"embeds\":[{\"author\":{\"name\":\"GitHub\"}," ++
        "\"title\":\"Build passed\",\"url\":\"https://ci.example/run/1\"," ++
        "\"footer\":{\"text\":\"main abc123\"}}]}";
    try renderBody(body, &post);
    var it = std.mem.splitScalar(u8, post.body(), '\n');
    try testing.expectEqualStrings("by GitHub", it.next().?);
    try testing.expectEqualStrings("* Build passed <https://ci.example/run/1>", it.next().?);
    try testing.expectEqualStrings("-- main abc123", it.next().?);
    try testing.expect(it.next() == null);
}

test "components render button and select fallbacks" {
    var post: webhook.PendingPost = .{};
    const body =
        "{\"content\":\"release gate\"," ++
        "\"components\":[{\"type\":1,\"components\":[" ++
        "{\"type\":2,\"label\":\"Open run\",\"url\":\"https://ci.example/run/2\"}," ++
        "{\"type\":3,\"placeholder\":\"Promote to\",\"options\":[{\"label\":\"staging\"},{\"label\":\"prod\"}]}" ++
        "]}]}";
    try renderBody(body, &post);
    var it = std.mem.splitScalar(u8, post.body(), '\n');
    try testing.expectEqualStrings("release gate", it.next().?);
    try testing.expectEqualStrings("[button] Open run <https://ci.example/run/2>", it.next().?);
    try testing.expectEqualStrings("[select] Promote to: staging, prod", it.next().?);
    try testing.expect(it.next() == null);
}

test "components are sanitized before text fallback rendering" {
    var post: webhook.PendingPost = .{};
    const body =
        "{\"components\":[{\"type\":1,\"components\":[" ++
        "{\"type\":2,\"label\":\"Open\\r\\nPRIVMSG #x :bad\",\"url\":\"https://ok.example\\u0007\"}" ++
        "]}]}";
    try renderBody(body, &post);
    try testing.expectEqualStrings("[button] OpenPRIVMSG #x :bad <https://ok.example>", post.body());
    try testing.expect(std.mem.indexOfScalar(u8, post.body(), '\r') == null);
    try testing.expect(std.mem.indexOfScalar(u8, post.body(), '\n') == null);
}

test "content plus embed both render" {
    var post: webhook.PendingPost = .{};
    try renderBody("{\"content\":\"heads up\",\"embeds\":[{\"title\":\"t\"}]}", &post);
    var it = std.mem.splitScalar(u8, post.body(), '\n');
    try testing.expectEqualStrings("heads up", it.next().?);
    try testing.expectEqualStrings("* t", it.next().?);
}

test "empty payload (no content, no usable embed) is rejected" {
    var post: webhook.PendingPost = .{};
    try testing.expectError(error.EmptyPayload, renderBody("{}", &post));
    try testing.expectError(error.EmptyPayload, renderBody("{\"username\":\"x\"}", &post));
    try testing.expectError(error.EmptyPayload, renderBody("{\"content\":\"\\r\\n  \"}", &post));
}

test "invalid JSON is rejected fail-closed" {
    var post: webhook.PendingPost = .{};
    try testing.expectError(error.BadJson, renderBody("not json", &post));
    try testing.expectError(error.BadJson, renderBody("[1,2,3]", &post)); // not an object
    try testing.expectError(error.BadJson, renderBody("{unterminated", &post));
}

test "sanitizeNick neutralises wire-hostile usernames" {
    var buf: [webhook.max_nick]u8 = undefined;
    // Spaces and metacharacters → '-', collapsed; result is wire-safe.
    try testing.expectEqualStrings("GitHub-Actions", sanitizeNick("GitHub Actions", &buf));
    try testing.expectEqualStrings("evil-root-host", sanitizeNick("evil!root@host", &buf));
    // A CRLF-injection attempt in the username cannot survive.
    const injected = sanitizeNick("a\r\nPRIVMSG", &buf);
    try testing.expect(std.mem.indexOfScalar(u8, injected, '\r') == null);
    try testing.expect(std.mem.indexOfScalar(u8, injected, '\n') == null);
    try testing.expect(std.mem.indexOfScalar(u8, injected, ' ') == null);
    // A username of only metacharacters falls back.
    try testing.expectEqualStrings("webhook", sanitizeNick("###", &buf));
    // A leading-digit nick falls back (never look like a numeric).
    try testing.expectEqualStrings("webhook", sanitizeNick("123", &buf));
}

test "sanitizeLine strips control bytes and trims trailing spaces" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("hello", sanitizeLine("hello   ", &buf));
    try testing.expectEqualStrings("ab", sanitizeLine("a\x01\x1fb", &buf));
    try testing.expectEqualStrings("", sanitizeLine("\r\n\t", &buf));
}

test {
    testing.refAllDecls(@This());
}
