// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! ESMTP submission client protocol state machine (RFC 5321 / 6409).
//!
//! Pure: depends only on `std`. No sockets, clock, RNG, or allocation. The
//! CALLER owns the TCP/TLS socket: it reads bytes, feeds them in via `feed`,
//! and acts on the returned `Action` (write bytes, perform the TLS handshake,
//! finish, or fail). This decoupling makes the conversation unit-testable
//! without a network.
//!
//! Outgoing commands and the DATA payload are built into driver-owned scratch
//! buffers and returned as `.send` slices; those slices are valid only until
//! the next `feed`. Server replies are buffered (multiline `250-...` runs are
//! reassembled) until a complete reply is available, then the state advances.

const std = @import("std");

/// Maximum buffered server reply (one logical reply, all continuation lines).
const reply_buf_len = 2048;
/// Maximum built command line, excluding the DATA payload.
const cmd_buf_len = 1024;
/// Cap on `Config.message`; the DATA scratch holds `len * 2 + 16` for the
/// worst case where every line needs dot-stuffing plus the `\r\n.\r\n` ender.
const max_message_len = 65536;
/// Cap on AUTH user/pass so the base64 AUTH PLAIN line fits `cmd_buf_len`.
const max_auth_field = 255;

/// Submission parameters supplied by the caller; all slices are borrowed.
pub const Config = struct {
    /// Our hostname, sent as the EHLO argument.
    ehlo_domain: []const u8,
    /// Envelope sender as a bare address (no angle brackets).
    mail_from: []const u8,
    /// Recipient as a bare address (no angle brackets).
    rcpt_to: []const u8,
    /// Full RFC 5322 message: headers, blank line, then body. Capped at
    /// `max_message_len` bytes; a larger message makes the driver `.fail`.
    message: []const u8,
    /// AUTH PLAIN user; when both this and `auth_pass` are set, AUTH runs.
    auth_user: ?[]const u8 = null,
    /// AUTH PLAIN password; paired with `auth_user`.
    auth_pass: ?[]const u8 = null,
    /// true: EHLO, STARTTLS, re-EHLO (submission port 587). false: the caller
    /// already established implicit TLS (port 465); STARTTLS is skipped.
    use_starttls: bool = true,
};

/// The next thing the caller must do after a `feed`.
pub const Action = union(enum) {
    /// The buffered reply is incomplete; read more bytes and feed again.
    need_more,
    /// Write these bytes to the socket. Valid only until the next `feed`.
    send: []const u8,
    /// Perform the TLS handshake on the socket now, then call `feed(null)`.
    start_tls,
    /// The message was accepted; the QUIT bytes were already emitted.
    done,
    /// Permanent failure; the slice is a short human-readable reason.
    fail: []const u8,
};

/// Internal protocol phase: which reply the driver is waiting to parse next.
const State = enum {
    greeting,
    ehlo_1,
    starttls,
    ehlo_2,
    auth,
    mail,
    rcpt,
    data,
    eod,
    finished,
    failed,
};

/// Drives one ESMTP submission conversation against caller-owned I/O.
pub const Driver = struct {
    config: Config,
    state: State,
    reply: [reply_buf_len]u8 = undefined,
    reply_len: usize = 0,
    cmd: [cmd_buf_len]u8 = undefined,
    msg: [max_message_len * 2 + 16]u8 = undefined,
    fail_reason: [256]u8 = undefined,

    /// Creates a driver primed to consume the server greeting on the first feed.
    pub fn init(config: Config) Driver {
        return .{ .config = config, .state = .greeting };
    }

    /// Feed freshly read socket bytes, or `null` immediately after completing
    /// the TLS handshake the driver requested via `.start_tls`. The driver
    /// buffers until it holds a COMPLETE SMTP reply (handling multiline
    /// `250-...\r\n250 ...`), then advances the state machine and returns the
    /// next Action. Call once with the initial greeting bytes to begin.
    pub fn feed(self: *Driver, bytes: ?[]const u8) Action {
        if (self.state == .failed) return .{ .fail = "smtp conversation already failed" };
        if (bytes) |chunk| {
            if (chunk.len > self.reply.len - self.reply_len) return self.failWith("server reply too large");
            @memcpy(self.reply[self.reply_len..][0..chunk.len], chunk);
            self.reply_len += chunk.len;
        } else {
            // Resume after the caller-performed TLS handshake.
            return self.command(.ehlo_2, self.buildEhlo());
        }

        const reply = parseReply(self.reply[0..self.reply_len]) orelse {
            if (replyMalformed(self.reply[0..self.reply_len])) return self.failWith("malformed server reply");
            return .need_more;
        };
        self.reply_len = 0;
        return self.advance(reply);
    }

    /// Advance the state machine on a fully-parsed server reply.
    fn advance(self: *Driver, reply: Reply) Action {
        return switch (self.state) {
            .greeting => self.expect(reply, 220, .ehlo_1, self.buildEhlo()),
            .ehlo_1 => self.afterEhlo1(reply),
            .starttls => self.afterStartTls(reply),
            .ehlo_2 => self.afterEhlo2(reply),
            .auth => self.expect(reply, 235, .mail, self.buildMail()),
            .mail => self.expect(reply, 250, .rcpt, self.buildRcpt()),
            .rcpt => self.expect(reply, 250, .data, "DATA\r\n"),
            .data => self.afterData(reply),
            .eod => self.expect(reply, 250, .finished, "QUIT\r\n"),
            // QUIT was sent and the message accepted; any trailing reply (the
            // 221 goodbye, or none) resolves to done.
            .finished => .done,
            .failed => .{ .fail = "unexpected server reply" },
        };
    }

    /// data: a 354 means send the dot-stuffed message; an oversized message
    /// (past `max_message_len`) fails rather than truncating.
    fn afterData(self: *Driver, reply: Reply) Action {
        if (rejected(reply) or reply.code != 354) return self.failReply(reply, "DATA");
        if (self.config.message.len > max_message_len) return self.failWith("message exceeds size cap");
        const payload = dotStuff(self.config.message, &self.msg);
        return self.command(.eod, payload);
    }

    /// starttls: a 220 means the caller must run the TLS handshake next.
    fn afterStartTls(self: *Driver, reply: Reply) Action {
        if (rejected(reply) or reply.code != 220) return self.failReply(reply, "STARTTLS");
        self.state = .ehlo_2;
        return .start_tls;
    }

    /// ehlo_1: a 250 forks to STARTTLS (when configured) or the post-EHLO path.
    fn afterEhlo1(self: *Driver, reply: Reply) Action {
        if (rejected(reply) or reply.code != 250) return self.failReply(reply, "EHLO");
        if (self.config.use_starttls) return self.command(.starttls, "STARTTLS\r\n");
        return self.afterEhloCommon();
    }

    /// ehlo_2: a 250 after STARTTLS proceeds to the post-EHLO path.
    fn afterEhlo2(self: *Driver, reply: Reply) Action {
        if (rejected(reply) or reply.code != 250) return self.failReply(reply, "EHLO");
        return self.afterEhloCommon();
    }

    /// Shared post-EHLO fork: AUTH PLAIN when credentials exist, else MAIL.
    fn afterEhloCommon(self: *Driver) Action {
        if (self.config.auth_user) |user| {
            if (self.config.auth_pass) |pass| {
                const line = self.buildAuth(user, pass) orelse
                    return self.failWith("auth credentials too long");
                return self.command(.auth, line);
            }
        }
        return self.command(.mail, self.buildMail());
    }

    /// Assert `reply.code`, transition to `next`, and emit `send_bytes`.
    fn expect(self: *Driver, reply: Reply, code: u16, next: State, send_bytes: []const u8) Action {
        if (rejected(reply) or reply.code != code) return self.failReply(reply, "step");
        return self.command(next, send_bytes);
    }

    /// Record the next state and return the bytes to write. When `next` is
    /// `.finished` the bytes are the QUIT line: the message is already
    /// accepted, so the following `feed` resolves to `.done`.
    fn command(self: *Driver, next: State, bytes: []const u8) Action {
        self.state = next;
        return .{ .send = bytes };
    }

    fn buildEhlo(self: *Driver) []const u8 {
        return std.fmt.bufPrint(&self.cmd, "EHLO {s}\r\n", .{self.config.ehlo_domain}) catch
            return "EHLO localhost\r\n";
    }

    fn buildMail(self: *Driver) []const u8 {
        return std.fmt.bufPrint(&self.cmd, "MAIL FROM:<{s}>\r\n", .{self.config.mail_from}) catch
            return "MAIL FROM:<>\r\n";
    }

    fn buildRcpt(self: *Driver) []const u8 {
        return std.fmt.bufPrint(&self.cmd, "RCPT TO:<{s}>\r\n", .{self.config.rcpt_to}) catch
            return "RCPT TO:<>\r\n";
    }

    /// Build `AUTH PLAIN <base64(\0user\0pass)>\r\n`; null if it would overflow.
    fn buildAuth(self: *Driver, user: []const u8, pass: []const u8) ?[]const u8 {
        if (user.len > max_auth_field or pass.len > max_auth_field) return null;
        var raw: [1 + max_auth_field + 1 + max_auth_field]u8 = undefined;
        var n: usize = 0;
        raw[n] = 0;
        n += 1;
        @memcpy(raw[n..][0..user.len], user);
        n += user.len;
        raw[n] = 0;
        n += 1;
        @memcpy(raw[n..][0..pass.len], pass);
        n += pass.len;

        const enc = std.base64.standard.Encoder;
        var b64: [std.base64.standard.Encoder.calcSize(raw.len)]u8 = undefined;
        const encoded = enc.encode(&b64, raw[0..n]);
        return std.fmt.bufPrint(&self.cmd, "AUTH PLAIN {s}\r\n", .{encoded}) catch null;
    }

    fn failReply(self: *Driver, reply: Reply, step: []const u8) Action {
        const first = reply.first_line;
        const reason = std.fmt.bufPrint(
            &self.fail_reason,
            "{s} rejected: {s}",
            .{ step, truncate(first, 120) },
        ) catch "smtp step rejected";
        self.state = .failed;
        return .{ .fail = reason };
    }

    fn failWith(self: *Driver, reason: []const u8) Action {
        self.state = .failed;
        return .{ .fail = reason };
    }
};

/// A fully-parsed SMTP reply: the final 3-digit status and its first line text.
const Reply = struct {
    code: u16,
    first_line: []const u8,
};

/// True when the reply is a 4xx or 5xx (transient or permanent failure).
fn rejected(reply: Reply) bool {
    const lead = reply.code / 100;
    return lead == 4 or lead == 5;
}

/// Parse a complete SMTP reply out of `buf`. A reply is one-or-more
/// continuation lines `NNN-text\r\n` followed by a final line `NNN text\r\n`
/// (space after the code). Returns null when no final line is buffered yet.
fn parseReply(buf: []const u8) ?Reply {
    var pos: usize = 0;
    var first_line: ?[]const u8 = null;
    while (indexCrlf(buf, pos)) |line_end| {
        const line = buf[pos..line_end];
        if (line.len < 4) return null;
        if (first_line == null) first_line = line;
        // Final line has a space (not '-') after the 3-digit code.
        if (line[3] == ' ') {
            const code = parseCode(line[0..3]) orelse return null;
            return .{ .code = code, .first_line = first_line.? };
        }
        if (line[3] != '-') return null;
        pos = line_end + 2;
    }
    return null;
}

/// True once a buffered reply is syntactically broken beyond recovery: a
/// terminated line that is too short or has a non-digit status code.
fn replyMalformed(buf: []const u8) bool {
    var pos: usize = 0;
    while (indexCrlf(buf, pos)) |line_end| {
        const line = buf[pos..line_end];
        if (line.len < 4) return true;
        if (line[3] != ' ' and line[3] != '-') return true;
        if (parseCode(line[0..3]) == null) return true;
        if (line[3] == ' ') return false;
        pos = line_end + 2;
    }
    return false;
}

fn parseCode(digits: []const u8) ?u16 {
    var code: u16 = 0;
    for (digits) |ch| {
        if (ch < '0' or ch > '9') return null;
        code = code * 10 + (ch - '0');
    }
    return code;
}

/// Find the next CRLF at or after `start`; returns the index of the '\r'.
fn indexCrlf(buf: []const u8, start: usize) ?usize {
    var i = start;
    while (i + 1 < buf.len) : (i += 1) {
        if (buf[i] == '\r' and buf[i + 1] == '\n') return i;
    }
    return null;
}

/// Dot-stuff `msg` into `out` (RFC 5321 transparency): every line that starts
/// with '.' gets a leading '.' doubled. Appends the `\r\n.\r\n` terminator.
/// `out` must hold at least `msg.len * 2 + 16` bytes.
fn dotStuff(msg: []const u8, out: []u8) []const u8 {
    var w: usize = 0;
    var at_line_start = true;
    for (msg) |ch| {
        if (at_line_start and ch == '.') {
            out[w] = '.';
            w += 1;
        }
        out[w] = ch;
        w += 1;
        at_line_start = ch == '\n';
    }
    const ender = "\r\n.\r\n";
    @memcpy(out[w..][0..ender.len], ender);
    w += ender.len;
    return out[0..w];
}

fn truncate(s: []const u8, max: usize) []const u8 {
    return s[0..@min(s.len, max)];
}

const testing = std.testing;

fn expectSend(action: Action, needle: []const u8) !void {
    try testing.expect(action == .send);
    try testing.expect(std.mem.indexOf(u8, action.send, needle) != null);
}

test "full STARTTLS happy path drives the whole conversation" {
    // Arrange.
    var d = Driver.init(.{
        .ehlo_domain = "mx.example.test",
        .mail_from = "from@example.test",
        .rcpt_to = "to@example.test",
        .message = "Subject: hi\r\n\r\nbody\r\n",
        .auth_user = "alice",
        .auth_pass = "s3cr3t",
    });

    // Act and assert: walk each required reply through to QUIT.
    try expectSend(d.feed("220 greeting\r\n"), "EHLO mx.example.test\r\n");
    try expectSend(d.feed("250-CAP\r\n250 OK\r\n"), "STARTTLS\r\n");
    try testing.expect(d.feed("220 go\r\n") == .start_tls);
    try expectSend(d.feed(null), "EHLO mx.example.test\r\n");

    const auth_action = d.feed("250 ok\r\n");
    try expectSend(auth_action, "AUTH PLAIN ");
    // The base64 payload is \x00alice\x00s3cr3t.
    var raw: [13]u8 = undefined;
    @memcpy(raw[0..1], "\x00");
    @memcpy(raw[1..6], "alice");
    @memcpy(raw[6..7], "\x00");
    @memcpy(raw[7..13], "s3cr3t");
    var b64: [32]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&b64, &raw);
    try expectSend(auth_action, encoded);

    try expectSend(d.feed("235 ok\r\n"), "MAIL FROM:<from@example.test>\r\n");
    try expectSend(d.feed("250 ok\r\n"), "RCPT TO:<to@example.test>\r\n");
    try expectSend(d.feed("250 ok\r\n"), "DATA\r\n");
    try expectSend(d.feed("354 go\r\n"), "\r\n.\r\n");
    const quit = d.feed("250 queued\r\n");
    try expectSend(quit, "QUIT\r\n");
    try testing.expect(d.feed("221 bye\r\n") == .done);
}

test "implicit TLS path skips STARTTLS and AUTH" {
    // Arrange.
    var d = Driver.init(.{
        .ehlo_domain = "mx.example.test",
        .mail_from = "from@example.test",
        .rcpt_to = "to@example.test",
        .message = "Subject: hi\r\n\r\nbody\r\n",
        .use_starttls = false,
    });

    // Act and assert: greeting -> EHLO -> straight to MAIL FROM.
    try expectSend(d.feed("220 greeting\r\n"), "EHLO mx.example.test\r\n");
    try expectSend(d.feed("250 OK\r\n"), "MAIL FROM:<from@example.test>\r\n");
    try expectSend(d.feed("250 ok\r\n"), "RCPT TO:<to@example.test>\r\n");
    try expectSend(d.feed("250 ok\r\n"), "DATA\r\n");
    try expectSend(d.feed("354 go\r\n"), "\r\n.\r\n");
    try expectSend(d.feed("250 queued\r\n"), "QUIT\r\n");
    try testing.expect(d.feed("221 bye\r\n") == .done);
}

test "AUTH PLAIN base64 is the exact encoding of NUL user NUL pass" {
    // Arrange.
    var d = Driver.init(.{
        .ehlo_domain = "h",
        .mail_from = "f@x.test",
        .rcpt_to = "t@x.test",
        .message = "body\r\n",
        .auth_user = "user",
        .auth_pass = "pass",
        .use_starttls = false,
    });

    // Act.
    _ = d.feed("220 hi\r\n");
    const auth = d.feed("250 ok\r\n");

    // Assert: exact line, exact base64.
    try testing.expect(auth == .send);
    try testing.expectEqualStrings("AUTH PLAIN AHVzZXIAcGFzcw==\r\n", auth.send);
}

test "dot-stuffing doubles a leading dot in a body line" {
    // Arrange. Body has a line that begins with '.'.
    var d = Driver.init(.{
        .ehlo_domain = "h",
        .mail_from = "f@x.test",
        .rcpt_to = "t@x.test",
        .message = "Subject: t\r\n\r\n.hidden\r\nplain\r\n",
        .use_starttls = false,
    });

    // Act: walk to the DATA payload.
    _ = d.feed("220 hi\r\n");
    _ = d.feed("250 ok\r\n");
    _ = d.feed("250 ok\r\n");
    _ = d.feed("250 ok\r\n");
    const payload = d.feed("354 go\r\n");

    // Assert: the ".hidden" line is transmitted as "..hidden" and ends in CRLF.CRLF.
    try testing.expect(payload == .send);
    try testing.expect(std.mem.indexOf(u8, payload.send, "\r\n..hidden\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, payload.send, "\r\n.\r\n"));
}

test "auth rejection and rcpt rejection both fail" {
    // Arrange: a 535 at AUTH.
    var auth_d = Driver.init(.{
        .ehlo_domain = "h",
        .mail_from = "f@x.test",
        .rcpt_to = "t@x.test",
        .message = "body\r\n",
        .auth_user = "u",
        .auth_pass = "p",
        .use_starttls = false,
    });
    _ = auth_d.feed("220 hi\r\n");
    _ = auth_d.feed("250 ok\r\n");

    // Act.
    const auth_fail = auth_d.feed("535 5.7.8 auth failed\r\n");

    // Assert.
    try testing.expect(auth_fail == .fail);
    try testing.expect(std.mem.indexOf(u8, auth_fail.fail, "535") != null);

    // Arrange: a 550 at RCPT.
    var rcpt_d = Driver.init(.{
        .ehlo_domain = "h",
        .mail_from = "f@x.test",
        .rcpt_to = "t@x.test",
        .message = "body\r\n",
        .use_starttls = false,
    });
    _ = rcpt_d.feed("220 hi\r\n");
    _ = rcpt_d.feed("250 ok\r\n");
    _ = rcpt_d.feed("250 sender ok\r\n");

    // Act.
    const rcpt_fail = rcpt_d.feed("550 5.1.1 no such user\r\n");

    // Assert.
    try testing.expect(rcpt_fail == .fail);
    try testing.expect(std.mem.indexOf(u8, rcpt_fail.fail, "550") != null);
}

test "partial reply returns need_more then advances when completed" {
    // Arrange.
    var d = Driver.init(.{
        .ehlo_domain = "h",
        .mail_from = "f@x.test",
        .rcpt_to = "t@x.test",
        .message = "body\r\n",
        .use_starttls = false,
    });

    // Act and assert: a continuation-only fragment is incomplete.
    try testing.expect(d.feed("220 hi\r\n") == .send);
    try testing.expect(d.feed("250-foo\r\n") == .need_more);
    // Completing the multiline reply advances to MAIL FROM.
    try expectSend(d.feed("250 bar\r\n"), "MAIL FROM:<f@x.test>\r\n");
}

test "message past the size cap fails instead of truncating" {
    // Arrange: a message one byte over the cap.
    var big_msg: [max_message_len + 1]u8 = undefined;
    @memset(&big_msg, 'a');
    var d = Driver.init(.{
        .ehlo_domain = "h",
        .mail_from = "f@x.test",
        .rcpt_to = "t@x.test",
        .message = &big_msg,
        .use_starttls = false,
    });

    // Act: walk to the DATA prompt.
    _ = d.feed("220 hi\r\n");
    _ = d.feed("250 ok\r\n");
    _ = d.feed("250 ok\r\n");
    _ = d.feed("250 ok\r\n");
    const action = d.feed("354 go\r\n");

    // Assert.
    try testing.expect(action == .fail);
    try testing.expect(std.mem.indexOf(u8, action.fail, "size cap") != null);
}

test "oversized chunk that cannot hold a reply fails cleanly" {
    // Arrange.
    var d = Driver.init(.{
        .ehlo_domain = "h",
        .mail_from = "f@x.test",
        .rcpt_to = "t@x.test",
        .message = "body\r\n",
        .use_starttls = false,
    });

    // Act: feed a fragment with no CRLF larger than the reply buffer.
    var big: [reply_buf_len + 1]u8 = undefined;
    @memset(&big, 'x');
    const action = d.feed(&big);

    // Assert.
    try testing.expect(action == .fail);
}
