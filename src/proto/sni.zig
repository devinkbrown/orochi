//! SNI (Server Name Indication) extraction from a TLS ClientHello.
//!
//! Pure, zero-allocation parser for the RFC 6066 `server_name` extension
//! (extension type 0).  Given the raw bytes of a single TLS record (or the
//! bare handshake message), it walks the wire structure and returns a slice
//! pointing at the `host_name` field — a view into the caller's input, never a
//! copy.  Does NO cryptography and NO I/O: it lets the TLS edge route or filter
//! by advertised host name before any handshake state exists.  Every length is
//! bounds-checked; a malformed/truncated record yields `.malformed` instead of
//! reading past the buffer.  Self-contained: only std is imported.
const std = @import("std");

// Wire constants.
const content_type_handshake: u8 = 22; // TLS record content type
const handshake_type_client_hello: u8 = 1; // Handshake message type
const ext_type_server_name: u16 = 0x0000; // RFC 6066 server_name extension
const name_type_host_name: u8 = 0; // NameType within a ServerNameList entry
const random_len: usize = 32; // fixed ClientHello random length

/// Outcome of an SNI extraction attempt.
pub const Result = union(enum) {
    /// A `host_name` was present; payload is a slice into the input.
    found: []const u8,
    /// Parsed cleanly but no (non-empty) `server_name` extension was present.
    none,
    /// Truncated, not a ClientHello, or an inconsistent length field.
    malformed,
};

// Cursor — a defensive forward reader over the input slice.
const ReadError = error{OutOfBounds};

const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn remaining(self: Cursor) usize {
        return self.buf.len - self.pos;
    }

    fn take(self: *Cursor, n: usize) ReadError![]const u8 {
        if (self.remaining() < n) return error.OutOfBounds;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }

    fn skip(self: *Cursor, n: usize) ReadError!void {
        _ = try self.take(n);
    }

    fn readU8(self: *Cursor) ReadError!u8 {
        return (try self.take(1))[0];
    }

    fn readBe(self: *Cursor, comptime n: usize) ReadError!u32 {
        const s = try self.take(n);
        var v: u32 = 0;
        inline for (0..n) |i| v = (v << 8) | s[i];
        return v;
    }

    fn readU16(self: *Cursor) ReadError!u16 {
        return @intCast(try self.readBe(2));
    }

    fn readU24(self: *Cursor) ReadError!u32 {
        return self.readBe(3);
    }
};

/// Extract the SNI `host_name` from `input`, accepting either a full TLS record
/// or a bare handshake message (auto-detected).  A `.found` slice aliases
/// `input`; no allocation occurs.
pub fn extract(input: []const u8) Result {
    return parse(input) catch return .malformed;
}

/// Optional wrapper: `.found` -> slice; `.none`/`.malformed` -> `null`.
pub fn extractOptional(input: []const u8) ?[]const u8 {
    return switch (extract(input)) {
        .found => |name| name,
        .none, .malformed => null,
    };
}

fn parse(input: []const u8) ReadError!Result {
    if (input.len == 0) return .malformed;
    var cur = Cursor{ .buf = input };
    // Record (content type 22) vs bare handshake (type 1); else reject.
    const handshake_bytes = switch (input[0]) {
        content_type_handshake => try unwrapRecord(&cur),
        handshake_type_client_hello => input,
        else => return .malformed,
    };
    return parseHandshake(handshake_bytes);
}

/// Consume the 5-byte TLS record header and return the record fragment.
fn unwrapRecord(cur: *Cursor) ReadError![]const u8 {
    try cur.skip(3); // content type + legacy_record_version
    return cur.take(try cur.readU16()); // fragment length
}

/// Parse a Handshake message, requiring it to be a ClientHello.
fn parseHandshake(bytes: []const u8) ReadError!Result {
    var cur = Cursor{ .buf = bytes };
    if (try cur.readU8() != handshake_type_client_hello) return .malformed;
    const body = try cur.take(try cur.readU24());
    return parseClientHello(body);
}

/// Walk the ClientHello body to the extensions block, then to the SNI value.
fn parseClientHello(body: []const u8) ReadError!Result {
    var cur = Cursor{ .buf = body };
    try cur.skip(2); // client_version
    try cur.skip(random_len); // random
    try cur.skip(try cur.readU8()); // session_id
    try cur.skip(try cur.readU16()); // cipher_suites
    try cur.skip(try cur.readU8()); // compression_methods
    // Extensions are optional in legacy ClientHellos; absence is a clean "none".
    if (cur.remaining() == 0) return .none;
    return parseExtensions(try cur.take(try cur.readU16()));
}

/// Scan the extension list for `server_name` and parse it if found.
fn parseExtensions(extensions: []const u8) ReadError!Result {
    var cur = Cursor{ .buf = extensions };
    while (cur.remaining() > 0) {
        const ext_type = try cur.readU16();
        const ext_data = try cur.take(try cur.readU16());
        if (ext_type == ext_type_server_name) return parseServerNameList(ext_data);
    }
    return .none;
}

/// Parse a ServerNameList, returning the first `host_name` entry.
fn parseServerNameList(data: []const u8) ReadError!Result {
    var cur = Cursor{ .buf = data };
    // An empty body is the legitimate server-side encoding: no name present.
    if (cur.remaining() == 0) return .none;
    const list = try cur.take(try cur.readU16());
    var entries = Cursor{ .buf = list };
    while (entries.remaining() > 0) {
        const name_type = try entries.readU8();
        const name = try entries.take(try entries.readU16());
        if (name_type == name_type_host_name) {
            return if (name.len == 0) .none else .{ .found = name };
        }
    }
    return .none;
}

// Minimal big-endian byte appender for constructing wire fixtures.
const Builder = struct {
    buf: []u8,
    n: usize = 0,

    fn be(self: *Builder, comptime width: usize, v: u32) void {
        inline for (0..width) |i|
            self.buf[self.n + i] = @intCast((v >> @intCast((width - 1 - i) * 8)) & 0xff);
        self.n += width;
    }
    fn u8v(self: *Builder, v: u8) void {
        self.be(1, v);
    }
    fn u16v(self: *Builder, v: u16) void {
        self.be(2, v);
    }
    fn u24v(self: *Builder, v: u32) void {
        self.be(3, v);
    }
    fn bytes(self: *Builder, s: []const u8) void {
        @memcpy(self.buf[self.n .. self.n + s.len], s);
        self.n += s.len;
    }
    fn out(self: Builder) []const u8 {
        return self.buf[0..self.n];
    }
};

// ClientHello body; `extensions` null omits the field (legacy framing).
fn buildClientHelloBody(buf: []u8, extensions: ?[]const u8) []const u8 {
    var b = Builder{ .buf = buf };
    b.u16v(0x0303); // client_version (TLS 1.2)
    @memset(buf[b.n .. b.n + random_len], 0); // random
    b.n += random_len;
    b.u8v(0); // session_id: empty
    b.u16v(2); // cipher_suites length
    b.u16v(0x1301); // one suite
    b.u8v(1); // compression_methods length
    b.u8v(0); // null compression
    if (extensions) |ext| {
        b.u16v(@intCast(ext.len));
        b.bytes(ext);
    }
    return b.out();
}

// Wrap a ClientHello body in Handshake + TLS record framing.
fn buildRecord(buf: []u8, body: []const u8) []const u8 {
    var b = Builder{ .buf = buf };
    b.u8v(content_type_handshake);
    b.u16v(0x0301); // legacy_record_version
    b.u16v(@intCast(body.len + 4)); // record length (+4 handshake header)
    b.u8v(handshake_type_client_hello);
    b.u24v(@intCast(body.len));
    b.bytes(body);
    return b.out();
}

/// Encode a single `server_name` extension carrying `host`.
fn buildSniExtension(buf: []u8, host: []const u8) []const u8 {
    var b = Builder{ .buf = buf };
    const list_len: u16 = @intCast(1 + 2 + host.len); // type + name_len + host
    b.u16v(ext_type_server_name);
    b.u16v(@intCast(2 + list_len)); // extension_data length
    b.u16v(list_len); // ServerNameList length
    b.u8v(name_type_host_name);
    b.u16v(@intCast(host.len));
    b.bytes(host);
    return b.out();
}

/// Encode a filler (non-SNI) extension of `ext_type` with `payload`.
fn buildGenericExtension(buf: []u8, ext_type: u16, payload: []const u8) []const u8 {
    var b = Builder{ .buf = buf };
    b.u16v(ext_type);
    b.u16v(@intCast(payload.len));
    b.bytes(payload);
    return b.out();
}

// Scratch space large enough for any fixture in the tests below.
const TestArena = struct {
    ext: [512]u8 = undefined,
    body: [768]u8 = undefined,
    rec: [900]u8 = undefined,
};

// Build a full record whose only extension is `server_name(host)`.
fn recordWithSni(arena: *TestArena, host: []const u8) []const u8 {
    const ext = buildSniExtension(&arena.ext, host);
    const body = buildClientHelloBody(&arena.body, ext);
    return buildRecord(&arena.rec, body);
}

test "returns host_name when server_name extension is present" {
    var a = TestArena{};
    const record = recordWithSni(&a, "irc.example.org");
    const result = extract(record);
    try std.testing.expect(result == .found);
    try std.testing.expectEqualStrings("irc.example.org", result.found);
}

test "returned slice aliases the input buffer rather than copying" {
    var a = TestArena{};
    const record = recordWithSni(&a, "host.test");
    const name = extractOptional(record).?;
    const base = @intFromPtr(record.ptr);
    const start = @intFromPtr(name.ptr);
    try std.testing.expect(start >= base);
    try std.testing.expect(start + name.len <= base + record.len);
}

test "returns none when no server_name extension is present" {
    var a = TestArena{};
    const filler = buildGenericExtension(&a.ext, 0x002b, &[_]u8{ 0x03, 0x04, 0x03, 0x03 });
    const body = buildClientHelloBody(&a.body, filler);
    const record = buildRecord(&a.rec, body);
    try std.testing.expect(extract(record) == .none);
    try std.testing.expect(extractOptional(record) == null);
}

test "returns none when the extensions field is entirely absent" {
    var a = TestArena{};
    const body = buildClientHelloBody(&a.body, null);
    const record = buildRecord(&a.rec, body);
    try std.testing.expect(extract(record) == .none);
}

test "finds server_name when it is not the first extension" {
    var pre_buf: [64]u8 = undefined;
    var sni_buf: [128]u8 = undefined;
    var post_buf: [64]u8 = undefined;
    var a = TestArena{};
    const pre1 = buildGenericExtension(&pre_buf, 0x002b, &[_]u8{ 0x03, 0x04 });
    const sni = buildSniExtension(&sni_buf, "late.example.com");
    const post = buildGenericExtension(&post_buf, 0x000a, &[_]u8{ 0x00, 0x02, 0x00, 0x17 });
    var eb = Builder{ .buf = &a.ext };
    eb.bytes(pre1);
    eb.bytes(sni);
    eb.bytes(post);
    const body = buildClientHelloBody(&a.body, eb.out());
    const record = buildRecord(&a.rec, body);
    const result = extract(record);
    try std.testing.expect(result == .found);
    try std.testing.expectEqualStrings("late.example.com", result.found);
}

test "malformed for every truncation length, never panics or reads OOB" {
    var a = TestArena{};
    const record = recordWithSni(&a, "irc.example.org");
    var cut: usize = 1;
    while (cut < record.len) : (cut += 1) {
        const result = extract(record[0..cut]);
        try std.testing.expect(result == .malformed or result == .none);
    }
}

test "malformed when input is not a handshake record" {
    // content type 23 = application_data, not handshake.
    const bogus = [_]u8{ 23, 0x03, 0x03, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x00 };
    try std.testing.expect(extract(&bogus) == .malformed);
}

test "malformed on empty input" {
    try std.testing.expect(extract(&[_]u8{}) == .malformed);
    try std.testing.expect(extractOptional(&[_]u8{}) == null);
}

test "accepts a bare handshake message without record framing" {
    var a = TestArena{};
    const ext = buildSniExtension(&a.ext, "bare.example.net");
    const body = buildClientHelloBody(&a.body, ext);
    var hb = Builder{ .buf = &a.rec };
    hb.u8v(handshake_type_client_hello);
    hb.u24v(@intCast(body.len));
    hb.bytes(body);
    const result = extract(hb.out());
    try std.testing.expect(result == .found);
    try std.testing.expectEqualStrings("bare.example.net", result.found);
}

test "returns none when host_name length is zero" {
    var a = TestArena{};
    const record = recordWithSni(&a, "");
    try std.testing.expect(extract(record) == .none);
}

test "malformed when extension length overruns the buffer" {
    var a = TestArena{};
    const ext = buildSniExtension(&a.ext, "ab");
    // Corrupt the extension_data length to claim 0xFFFF bytes.
    a.ext[2] = 0xff;
    a.ext[3] = 0xff;
    const body = buildClientHelloBody(&a.body, ext);
    const record = buildRecord(&a.rec, body);
    try std.testing.expect(extract(record) == .malformed);
}
