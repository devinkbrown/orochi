//! WASM browser transport shim export surface (#32).
//!
//! Compiled to `wasm32-freestanding` (`zig build wasm`), this exposes the
//! `browser_transport` core to Ocean's in-page client over a single module
//! instance with fixed linear-memory buffers — no allocator crosses the FFI.
//!
//! Inbound flow (server -> browser, over a WebSocket):
//!   1. JS copies received bytes into the buffer at `rx_buf_ptr()` (`rx_buf_cap`).
//!   2. JS calls `rx_push(len)` to hand them to the line framer.
//!   3. JS loops `rx_poll()`; each non-negative return is the byte length of one
//!      complete line, now at `line_ptr()`.
//!   4. JS calls `rx_parse()` to structure that line: it returns the parameter
//!      count (or -1 if malformed) and fills `fields_ptr()` with a flat u16
//!      descriptor of (offset,len) spans into `line_ptr()`:
//!        [tags_off, tags_len, prefix_off, prefix_len, cmd_off, cmd_len,
//!         nparam, p0_off, p0_len, p1_off, p1_len, ...]
//!      A span with len 0 and off 0 means absent (tags/prefix).
//!
//! Tag value codecs (offsets are caller-chosen scratch regions in linear memory):
//!   `escape_tag` / `unescape_tag` convert between raw and IRCv3 wire form,
//!   returning the written length or -1 on overflow/malformed input.
const irc_line = @import("../proto/irc_line.zig");
const bt = @import("browser_transport.zig");

const line_cap: usize = bt.max_line + 2;

var framer: bt.Framer(line_cap) = .{};
/// Inbound staging buffer: JS writes WebSocket bytes here before `rx_push`.
var rx_buf: [32 * 1024]u8 = undefined;
/// The most recently popped line (raw, CR/LF stripped).
var line_buf: [line_cap]u8 = undefined;
var line_len: usize = 0;
/// Flat parse descriptor: 3 fixed spans (tags/prefix/command) + nparam + params.
var fields: [7 + 2 * irc_line.MAXPARA]u16 = undefined;

export fn rx_buf_ptr() [*]u8 {
    return &rx_buf;
}

export fn rx_buf_cap() u32 {
    return rx_buf.len;
}

/// Feed `len` bytes (from the start of `rx_buf`) into the line framer.
export fn rx_push(len: u32) void {
    const n = @min(@as(usize, len), rx_buf.len);
    framer.feed(rx_buf[0..n]);
}

/// Pop the next complete line into `line_buf`; returns its length or -1 if none.
export fn rx_poll() i32 {
    const line = framer.next() orelse return -1;
    @memcpy(line_buf[0..line.len], line);
    line_len = line.len;
    return @intCast(line.len);
}

export fn line_ptr() [*]const u8 {
    return &line_buf;
}

export fn fields_ptr() [*]const u16 {
    return &fields;
}

/// Parse the current `line_buf` into `fields`; returns the parameter count or -1.
export fn rx_parse() i32 {
    const view = bt.parse(line_buf[0..line_len]) orelse return -1;
    const base = @intFromPtr(&line_buf[0]);

    setSpan(0, view.tags_raw, base);
    setSpan(2, view.prefix, base);
    fields[4] = @intCast(@intFromPtr(view.command.ptr) - base);
    fields[5] = @intCast(view.command.len);

    const np = @min(view.param_count, irc_line.MAXPARA);
    fields[6] = @intCast(np);
    var i: usize = 0;
    while (i < np) : (i += 1) {
        const p = view.params[i];
        fields[7 + i * 2] = @intCast(@intFromPtr(p.ptr) - base);
        fields[8 + i * 2] = @intCast(p.len);
    }
    return @intCast(np);
}

fn setSpan(idx: usize, span: ?[]const u8, base: usize) void {
    if (span) |s| {
        fields[idx] = @intCast(@intFromPtr(s.ptr) - base);
        fields[idx + 1] = @intCast(s.len);
    } else {
        fields[idx] = 0;
        fields[idx + 1] = 0;
    }
}

/// Escape a raw tag value (at `ptr[0..len]`) into `out[0..out_cap]`; returns the
/// written length or -1 if it would overflow.
export fn escape_tag(ptr: [*]const u8, len: u32, out: [*]u8, out_cap: u32) i32 {
    const r = bt.escapeTagValue(ptr[0..len], out[0..out_cap]) catch return -1;
    return @intCast(r.len);
}

/// Unescape an IRCv3 tag value into `out[0..out_cap]`; returns length or -1.
export fn unescape_tag(ptr: [*]const u8, len: u32, out: [*]u8, out_cap: u32) i32 {
    const r = bt.unescapeTagValue(ptr[0..len], out[0..out_cap]) catch return -1;
    return @intCast(r.len);
}
