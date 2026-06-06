//! Global operator notice model.
//!
//! A privileged operator may send a single one-shot announcement to a
//! selected audience of *users* (as opposed to the operator-only Event
//! Spine `EVENT BROADCAST`, which targets subscribed opers). This module
//! is a pure, allocation-free core: it parses the command, decides whether
//! a given user belongs to the requested audience, and formats the wire
//! line. Actual delivery — iterating connected clients — is the server's
//! responsibility.
//!
//! Supported command forms (the trailing `:<text>` is the announcement):
//!   * `GLOBAL :<text>`           — everyone (also `GLOBAL * :<text>`)
//!   * `GLOBAL <mask> :<text>`    — users whose `nick!user@host` matches a glob
//!   * `GLOBAL #chan :<text>`     — members of a single channel
//!
//! Audience selection borrows the caller's input slices; no allocation is
//! performed by any function here. Callers own all buffers.

const std = @import("std");

/// Tunable bounds for parsing and formatting. All limits are inclusive
/// byte counts; values larger than the limit are rejected with a typed
/// error rather than silently truncated.
pub const Params = struct {
    /// Maximum length of the announcement text in bytes.
    max_text_bytes: usize = 400,
    /// Maximum length of an audience mask in bytes.
    max_mask_bytes: usize = 256,
    /// Maximum length of a channel name in bytes (including the `#`/`&`).
    max_channel_bytes: usize = 200,
    /// Maximum length of the formatting server name in bytes.
    max_server_name_bytes: usize = 255,
    /// Maximum length of a fully formatted wire line in bytes.
    max_line_bytes: usize = 512,
};

/// Errors produced while parsing a `GLOBAL` command. Allocation errors are
/// not included because nothing here allocates.
pub const ParseError = error{
    /// No announcement text was supplied.
    MissingText,
    /// More tokens than the grammar allows were supplied.
    TooManyParameters,
    /// The audience token was empty or otherwise unusable.
    InvalidAudience,
    /// The announcement text exceeded `Params.max_text_bytes`.
    TextTooLong,
    /// The audience mask exceeded `Params.max_mask_bytes`.
    MaskTooLong,
    /// The channel name exceeded `Params.max_channel_bytes`.
    ChannelTooLong,
};

/// Errors produced while formatting a wire line.
pub const FormatError = error{
    /// The supplied output buffer was too small for the formatted line.
    OutputTooSmall,
    /// The server name was empty.
    InvalidServerName,
    /// The server name exceeded `Params.max_server_name_bytes`.
    ServerNameTooLong,
    /// The announcement text exceeded `Params.max_text_bytes`.
    TextTooLong,
};

/// The set of users an announcement is aimed at. All variants borrow the
/// caller's bytes and never copy.
pub const Audience = union(enum) {
    /// Every connected user.
    all,
    /// Users whose `nick!user@host` matches this case-insensitive glob.
    mask: []const u8,
    /// Members of this single channel (case-insensitive comparison).
    channel: []const u8,
};

/// A parsed `GLOBAL` request: an audience plus the announcement text.
/// Both fields borrow slices owned by the caller's input.
pub const Request = struct {
    audience: Audience,
    text: []const u8,

    /// Parse a `GLOBAL` command using the default `Params`.
    ///
    /// `args` is the post-command token list where the final token is the
    /// announcement text (the IRC trailing parameter). See module docs for
    /// accepted forms.
    pub fn parse(args: []const []const u8) ParseError!Request {
        return parseBounded(.{}, args);
    }

    /// Parse a `GLOBAL` command using explicit `bounds`.
    ///
    /// The last element of `args` is always the announcement text. A zero or
    /// one preceding token selects the audience: absent or bare `*` => all,
    /// a leading `#`/`&` => channel, a token containing `!`, `@`, or `*` =>
    /// mask. Anything else is ambiguous and rejected.
    pub fn parseBounded(comptime bounds: Params, args: []const []const u8) ParseError!Request {
        if (args.len == 0) return error.MissingText;
        if (args.len > 2) return error.TooManyParameters;

        const text = args[args.len - 1];
        if (text.len == 0) return error.MissingText;
        if (text.len > bounds.max_text_bytes) return error.TextTooLong;

        if (args.len == 1) {
            return .{ .audience = .all, .text = text };
        }

        const selector = args[0];
        const audience = try parseSelector(bounds, selector);
        return .{ .audience = audience, .text = text };
    }

    /// Decide whether the user identified by `user_hostmask` (a full
    /// `nick!user@host`) and currently a member of `user_channels` belongs
    /// to this request's audience.
    ///
    /// * `all`     — always true.
    /// * `mask`    — case-insensitive glob match against `user_hostmask`.
    /// * `channel` — case-insensitive membership test against
    ///   `user_channels`.
    pub fn inAudience(
        self: Request,
        user_hostmask: []const u8,
        user_channels: []const []const u8,
    ) bool {
        return switch (self.audience) {
            .all => true,
            .mask => |pattern| globMatchFold(pattern, user_hostmask),
            .channel => |chan| containsFold(user_channels, chan),
        };
    }
};

/// Resolve an audience selector token into an `Audience`.
fn parseSelector(comptime bounds: Params, selector: []const u8) ParseError!Audience {
    if (selector.len == 0) return error.InvalidAudience;

    // A lone `*` means everyone, not a mask.
    if (std.mem.eql(u8, selector, "*")) return .all;

    switch (selector[0]) {
        '#', '&' => {
            if (selector.len > bounds.max_channel_bytes) return error.ChannelTooLong;
            return .{ .channel = selector };
        },
        else => {},
    }

    if (looksLikeMask(selector)) {
        if (selector.len > bounds.max_mask_bytes) return error.MaskTooLong;
        return .{ .mask = selector };
    }

    return error.InvalidAudience;
}

/// A token is treated as a mask when it carries any hostmask punctuation.
fn looksLikeMask(token: []const u8) bool {
    for (token) |byte| {
        switch (byte) {
            '!', '@', '*', '?' => return true,
            else => {},
        }
    }
    return false;
}

/// The prefix prepended to every global-notice payload so users can tell a
/// server-wide announcement apart from an ordinary notice.
pub const global_tag = "[Global] ";

/// Format the wire line for a global notice into `out` using the default
/// `Params`. Returns a slice of `out` ending in CR-LF.
pub fn formatLine(
    out: []u8,
    server_name: []const u8,
    text: []const u8,
) FormatError![]const u8 {
    return formatLineBounded(.{}, out, server_name, text);
}

/// Format the wire line for a global notice into `out` using explicit
/// `bounds`. The produced line has the shape:
///
///   `:<server> NOTICE $* :[Global] <text>\r\n`
///
/// `$*` is the standard target token meaning "all users on the network".
/// Returns a slice of `out`; the caller owns the backing buffer.
pub fn formatLineBounded(
    comptime bounds: Params,
    out: []u8,
    server_name: []const u8,
    text: []const u8,
) FormatError![]const u8 {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > bounds.max_server_name_bytes) return error.ServerNameTooLong;
    if (text.len > bounds.max_text_bytes) return error.TextTooLong;

    var writer = BufferWriter.init(out);
    try writer.appendByte(':');
    try writer.appendBytes(server_name);
    try writer.appendBytes(" NOTICE $* :");
    try writer.appendBytes(global_tag);
    try writer.appendBytes(text);
    try writer.appendBytes("\r\n");
    if (writer.len > bounds.max_line_bytes) return error.OutputTooSmall;
    return writer.slice();
}

/// Case-insensitive membership test: returns true when `needle` equals any
/// element of `haystack` ignoring ASCII case.
fn containsFold(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |item| {
        if (std.ascii.eqlIgnoreCase(item, needle)) return true;
    }
    return false;
}

/// Case-insensitive glob match supporting `*` (any run, including empty) and
/// `?` (exactly one byte). Implemented iteratively with backtracking so it
/// runs without recursion or allocation.
fn globMatchFold(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var star_t: usize = 0;

    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or
            std.ascii.toLower(pattern[p]) == std.ascii.toLower(text[t])))
        {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            star_t = t;
            p += 1;
        } else if (star) |sp| {
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

/// Bounded sink that appends into a caller-owned buffer, refusing to write
/// past the end. Mirrors the writer style used elsewhere in `proto`.
const BufferWriter = struct {
    out: []u8,
    len: usize = 0,

    fn init(out: []u8) BufferWriter {
        return .{ .out = out };
    }

    fn slice(self: *const BufferWriter) []const u8 {
        return self.out[0..self.len];
    }

    fn appendBytes(self: *BufferWriter, bytes: []const u8) FormatError!void {
        if (self.len > self.out.len or bytes.len > self.out.len - self.len) {
            return error.OutputTooSmall;
        }
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *BufferWriter, byte: u8) FormatError!void {
        if (self.len >= self.out.len) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test "parse all form with no selector" {
    // Arrange / Act
    const req = try Request.parse(&.{"hello everyone"});

    // Assert
    try std.testing.expectEqual(Audience.all, std.meta.activeTag(req.audience));
    try std.testing.expectEqualStrings("hello everyone", req.text);
}

test "parse all form with bare star selector" {
    // Arrange / Act
    const req = try Request.parse(&.{ "*", "wide message" });

    // Assert
    try std.testing.expectEqual(Audience.all, std.meta.activeTag(req.audience));
    try std.testing.expectEqualStrings("wide message", req.text);
}

test "parse mask form recognises hostmask punctuation" {
    // Arrange / Act
    const req = try Request.parse(&.{ "*!*@*.example.test", "ops only" });

    // Assert
    try std.testing.expect(req.audience == .mask);
    try std.testing.expectEqualStrings("*!*@*.example.test", req.audience.mask);
    try std.testing.expectEqualStrings("ops only", req.text);
}

test "parse channel form recognises hash and ampersand" {
    // Arrange / Act
    const hash = try Request.parse(&.{ "#staff", "meeting now" });
    const amp = try Request.parse(&.{ "&local", "local notice" });

    // Assert
    try std.testing.expect(hash.audience == .channel);
    try std.testing.expectEqualStrings("#staff", hash.audience.channel);
    try std.testing.expect(amp.audience == .channel);
    try std.testing.expectEqualStrings("&local", amp.audience.channel);
}

test "parse rejects missing and empty text" {
    // Assert
    try std.testing.expectError(error.MissingText, Request.parse(&.{}));
    try std.testing.expectError(error.MissingText, Request.parse(&.{""}));
    try std.testing.expectError(error.MissingText, Request.parse(&.{ "#staff", "" }));
}

test "parse rejects ambiguous bare selector" {
    // A plain word that is neither channel nor mask is ambiguous.
    try std.testing.expectError(error.InvalidAudience, Request.parse(&.{ "nobody", "text" }));
}

test "parse rejects too many parameters" {
    try std.testing.expectError(
        error.TooManyParameters,
        Request.parse(&.{ "#a", "#b", "text" }),
    );
}

test "parse enforces text and mask bounds" {
    // Arrange
    const Tiny = Params{ .max_text_bytes = 4, .max_mask_bytes = 4 };

    // Assert: text too long
    try std.testing.expectError(
        error.TextTooLong,
        Request.parseBounded(Tiny, &.{"toolong"}),
    );
    // Assert: mask too long
    try std.testing.expectError(
        error.MaskTooLong,
        Request.parseBounded(Tiny, &.{ "a@bcdef", "hi" }),
    );
}

test "parse enforces channel bounds" {
    // Arrange
    const Tiny = Params{ .max_channel_bytes = 3 };

    // Assert
    try std.testing.expectError(
        error.ChannelTooLong,
        Request.parseBounded(Tiny, &.{ "#longchan", "hi" }),
    );
}

test "inAudience all matches every user" {
    // Arrange
    const req = Request{ .audience = .all, .text = "x" };

    // Act / Assert
    try std.testing.expect(req.inAudience("nick!user@host", &.{}));
    try std.testing.expect(req.inAudience("", &.{"#anything"}));
}

test "inAudience mask hits and misses" {
    // Arrange
    const req = Request{ .audience = .{ .mask = "*!*@*.example.test" }, .text = "x" };

    // Act / Assert
    try std.testing.expect(req.inAudience("bob!bob@host.example.test", &.{}));
    try std.testing.expect(!req.inAudience("bob!bob@host.other.net", &.{}));
}

test "inAudience mask is case insensitive" {
    // Arrange
    const req = Request{ .audience = .{ .mask = "ALICE!*@*" }, .text = "x" };

    // Act / Assert
    try std.testing.expect(req.inAudience("alice!a@h", &.{}));
}

test "inAudience mask question mark matches one byte" {
    // Arrange
    const req = Request{ .audience = .{ .mask = "a?c!*@*" }, .text = "x" };

    // Act / Assert
    try std.testing.expect(req.inAudience("abc!u@h", &.{}));
    try std.testing.expect(!req.inAudience("ac!u@h", &.{}));
    try std.testing.expect(!req.inAudience("abbc!u@h", &.{}));
}

test "inAudience channel membership hit and miss" {
    // Arrange
    const req = Request{ .audience = .{ .channel = "#Staff" }, .text = "x" };
    const channels = [_][]const u8{ "#general", "#staff" };

    // Act / Assert: case-insensitive hit
    try std.testing.expect(req.inAudience("n!u@h", &channels));
    // Miss when not a member
    try std.testing.expect(!req.inAudience("n!u@h", &.{"#general"}));
    try std.testing.expect(!req.inAudience("n!u@h", &.{}));
}

test "formatLine produces expected wire line" {
    // Arrange
    var out: [128]u8 = undefined;

    // Act
    const line = try formatLine(&out, "irc.example.test", "server going down");

    // Assert
    try std.testing.expectEqualStrings(
        ":irc.example.test NOTICE $* :[Global] server going down\r\n",
        line,
    );
}

test "formatLine rejects empty and oversized server name" {
    // Arrange
    var out: [128]u8 = undefined;
    const Tiny = Params{ .max_server_name_bytes = 3 };

    // Assert
    try std.testing.expectError(error.InvalidServerName, formatLine(&out, "", "hi"));
    try std.testing.expectError(
        error.ServerNameTooLong,
        formatLineBounded(Tiny, &out, "long.name", "hi"),
    );
}

test "formatLine reports output too small" {
    // Arrange: buffer too small to hold the whole line
    var out: [8]u8 = undefined;

    // Assert
    try std.testing.expectError(
        error.OutputTooSmall,
        formatLine(&out, "irc.example.test", "text"),
    );
}

test "formatLine enforces text bound" {
    // Arrange
    var out: [128]u8 = undefined;
    const Tiny = Params{ .max_text_bytes = 2 };

    // Assert
    try std.testing.expectError(
        error.TextTooLong,
        formatLineBounded(Tiny, &out, "irc.example.test", "toolong"),
    );
}

test "glob trailing star matches remainder" {
    // Directly exercise the matcher for edge coverage.
    try std.testing.expect(globMatchFold("abc*", "abcdef"));
    try std.testing.expect(globMatchFold("*", ""));
    try std.testing.expect(globMatchFold("a*c", "ac"));
    try std.testing.expect(!globMatchFold("abc", "abcd"));
}

test "end to end parse then audience then format with no leaks" {
    // Arrange: a channel-targeted announcement.
    const req = try Request.parse(&.{ "#ops", "rolling restart" });
    const member_channels = [_][]const u8{ "#ops", "#general" };
    const outsider_channels = [_][]const u8{"#general"};

    // Act / Assert: audience selection
    try std.testing.expect(req.inAudience("op!o@h", &member_channels));
    try std.testing.expect(!req.inAudience("guest!g@h", &outsider_channels));

    // Act / Assert: wire formatting (caller-owned buffer, no allocation)
    var out: [128]u8 = undefined;
    const line = try formatLine(&out, "mesh.example.test", req.text);
    try std.testing.expectEqualStrings(
        ":mesh.example.test NOTICE $* :[Global] rolling restart\r\n",
        line,
    );
}
