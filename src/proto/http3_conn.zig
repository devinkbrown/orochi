//! HTTP/3 + WebTransport session layer (layer 6) over the QUIC connection
//! driver (`quic_conn.zig`, layer 5).
//!
//! Implements the SERVER side of WebTransport-over-HTTP/3:
//!   * RFC 9114 — HTTP/3: the frame codec (DATA / HEADERS / SETTINGS, plus
//!     tolerate-and-skip for GREASE and unknown frame types) and the
//!     unidirectional stream type prefix (control = 0x00, QPACK encoder/decoder
//!     = 0x02 / 0x03).
//!   * RFC 9220 — WebTransport over HTTP/3: the Extended CONNECT handshake
//!     (`:method = CONNECT`, `:protocol = webtransport`) and the WT bidi/uni
//!     stream type signals (0x41 / 0x54) from `webtransport.zig`.
//!   * RFC 9297 — HTTP Datagrams: WT datagrams carried as QUIC DATAGRAM frames
//!     prefixed with the session's quarter-stream-id.
//!
//! Socketless + layered: this module never touches a socket. It consumes the
//! `Conn` application I/O surface (`openStream` / `openUniStream` /
//! `sendStream` / `readStream` / `streamFinished`, `sendDatagram` /
//! `recvDatagramPayload`) and the lower codecs (`http3_qpack`, `webtransport`).
//! It re-implements neither QUIC streams/datagrams nor QPACK.
//!
//! QPACK simplification (intentional, standard, documented): the server
//! advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` and
//! `SETTINGS_QPACK_BLOCKED_STREAMS = 0`, so no dynamic table is ever used. Every
//! header block is decodable with the static table + literals alone (RFC 9204 —
//! Required Insert Count and Base are always zero). The QPACK encoder/decoder
//! unidirectional streams therefore carry no instructions; we still open the
//! encoder stream (type 0x02, empty) for spec conformance and ignore the peer's.
//!
//! Other documented simplifications:
//!   * One WebTransport session per connection is the common deployment shape; a
//!     second CONNECT is rejected. The session model itself is keyed by CONNECT
//!     stream id, so lifting this to multi-session is a small change.
//!   * No HTTP request routing beyond Extended CONNECT — a plain (non-CONNECT)
//!     request is answered 405 and the stream is finished.
//!   * WebTransport stream flow control is QUIC's; no WT-level capsule-based
//!     flow control beyond session close.
//!
//! All parsing is bounds-checked: a malformed SETTINGS, HEADERS, or stream
//! prefix returns an error and never panics or reads out of bounds.

const std = @import("std");
const Allocator = std.mem.Allocator;

const quic_conn = @import("quic_conn.zig");
const qpack = @import("http3_qpack.zig");
const webtransport = @import("webtransport.zig");

// ===========================================================================
// HTTP/3 constants (RFC 9114, RFC 9220, RFC 9297)
// ===========================================================================

/// HTTP/3 frame types (RFC 9114 §7.2 / §11.2.1). Only the ones we encode or
/// recognise are named; everything else is skipped on the wire.
pub const FrameType = struct {
    pub const data: u64 = 0x00;
    pub const headers: u64 = 0x01;
    pub const cancel_push: u64 = 0x03;
    pub const settings: u64 = 0x04;
    pub const push_promise: u64 = 0x05;
    pub const goaway: u64 = 0x07;
    pub const max_push_id: u64 = 0x0d;
    /// WebTransport bidirectional stream frame type when a session's bidi stream
    /// is signalled inside an HTTP/3 stream (not used on the server accept path,
    /// kept for completeness).
    pub const webtransport_stream: u64 = 0x41;
};

/// Unidirectional stream type prefixes (RFC 9114 §6.2, RFC 9204 §4.2).
pub const UniStreamType = struct {
    pub const control: u64 = 0x00;
    pub const push: u64 = 0x01;
    pub const qpack_encoder: u64 = 0x02;
    pub const qpack_decoder: u64 = 0x03;
    /// WebTransport unidirectional stream (RFC 9220 §4): 0x54 then session id.
    pub const webtransport: u64 = 0x54;
};

/// HTTP/3 SETTINGS identifiers (RFC 9114 §7.2.4.1, RFC 9220 §8.2, RFC 9297 §5).
pub const Setting = struct {
    pub const qpack_max_table_capacity: u64 = 0x01;
    pub const max_field_section_size: u64 = 0x06;
    pub const qpack_blocked_streams: u64 = 0x07;
    /// RFC 9297 — enables HTTP Datagrams (the H3_DATAGRAM setting).
    pub const h3_datagram: u64 = 0x33;
    /// RFC 8441 / RFC 9220 — server allows the Extended CONNECT protocol.
    pub const enable_connect_protocol: u64 = 0x08;
    /// RFC 9220 §8.2 — enables WebTransport over HTTP/3.
    pub const enable_webtransport: u64 = 0x2b603742;
};

pub const Error = error{
    /// A frame, SETTINGS body, or stream prefix could not be parsed within
    /// bounds (truncated, oversized varint, or length running past the buffer).
    Malformed,
    /// The peer's SETTINGS did not advertise the support WebTransport requires.
    WebTransportUnsupported,
    /// A second CONNECT arrived; this layer supports one session per connection.
    SessionAlreadyEstablished,
    /// An Extended CONNECT request was missing or had the wrong pseudo-headers.
    BadConnect,
    /// The underlying QUIC connection is not established / has closed.
    NotReady,
} || Allocator.Error || qpack.DecodeError || qpack.EncodeError || webtransport.FormatError;

// ===========================================================================
// HTTP/3 frame codec (RFC 9114 §7.1) — varint type + varint length + payload
// ===========================================================================

pub const H3Frame = struct {
    frame_type: u64,
    payload: []const u8, // borrows the input
};

/// Decode one HTTP/3 frame from `input`, returning the frame and the number of
/// bytes consumed. Bounds-checked: a truncated header or a length running past
/// the buffer returns `error.Malformed`.
pub fn decodeFrame(input: []const u8) Error!struct { frame: H3Frame, consumed: usize } {
    const t = webtransport.decodeVarint(input) catch return error.Malformed;
    var pos: usize = t.len;
    const l = webtransport.decodeVarint(input[pos..]) catch return error.Malformed;
    pos += l.len;
    const length = std.math.cast(usize, l.value) orelse return error.Malformed;
    if (length > input.len - pos) return error.Malformed;
    const payload = input[pos .. pos + length];
    return .{ .frame = .{ .frame_type = t.value, .payload = payload }, .consumed = pos + length };
}

/// Append an HTTP/3 frame (type varint + length varint + payload) to `out`.
pub fn encodeFrame(allocator: Allocator, out: *std.ArrayList(u8), frame_type: u64, payload: []const u8) Error!void {
    var buf: [8]u8 = undefined;
    try out.appendSlice(allocator, try webtransport.encodeVarint(frame_type, &buf));
    const len_u64 = std.math.cast(u64, payload.len) orelse return error.Malformed;
    try out.appendSlice(allocator, try webtransport.encodeVarint(len_u64, &buf));
    try out.appendSlice(allocator, payload);
}

/// Iterate frames in a buffer, skipping unknown/GREASE frame types. Returns the
/// first frame whose type matches `want`, or null if the buffer is exhausted.
/// `start` is advanced past every frame inspected so the caller can resume.
pub fn findFrame(input: []const u8, start: *usize, want: u64) Error!?H3Frame {
    var pos = start.*;
    while (pos < input.len) {
        const d = try decodeFrame(input[pos..]);
        pos += d.consumed;
        if (d.frame.frame_type == want) {
            start.* = pos;
            return d.frame;
        }
        // Unknown / GREASE / other known-but-uninteresting frames are skipped
        // (RFC 9114 §9 — reserved frame types of the form 0x1f*N+0x21 and any
        // unrecognised type MUST be ignored).
    }
    start.* = pos;
    return null;
}

// ===========================================================================
// SETTINGS codec (RFC 9114 §7.2.4) — sequence of (identifier, value) varints
// ===========================================================================

/// The SETTINGS values we care about, decoded from a peer SETTINGS frame body
/// or used to build our own. Absent settings keep their default (0 / false).
pub const Settings = struct {
    qpack_max_table_capacity: u64 = 0,
    qpack_blocked_streams: u64 = 0,
    max_field_section_size: u64 = 0,
    enable_webtransport: bool = false,
    h3_datagram: bool = false,
    enable_connect_protocol: bool = false,

    /// The server SETTINGS this layer advertises: WebTransport + H3 Datagrams +
    /// Extended CONNECT enabled, and a zero-capacity QPACK dynamic table.
    pub fn serverDefault() Settings {
        return .{
            .qpack_max_table_capacity = 0,
            .qpack_blocked_streams = 0,
            .enable_webtransport = true,
            .h3_datagram = true,
            .enable_connect_protocol = true,
        };
    }

    /// True if the peer advertised everything WebTransport-over-H3 requires:
    /// H3 Datagrams, Extended CONNECT, and WebTransport itself (RFC 9220 §3.1).
    pub fn supportsWebTransport(self: Settings) bool {
        return self.enable_webtransport and self.h3_datagram and self.enable_connect_protocol;
    }
};

/// Encode a SETTINGS frame *body* (the (id,value) pairs only, no frame header).
pub fn encodeSettingsBody(allocator: Allocator, s: Settings) Error![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    var buf: [8]u8 = undefined;

    const Pair = struct { id: u64, value: u64 };
    var pairs: [6]Pair = undefined;
    var n: usize = 0;
    // Always advertise the QPACK zero-capacity settings explicitly so the peer
    // knows the dynamic table is unused.
    pairs[n] = .{ .id = Setting.qpack_max_table_capacity, .value = s.qpack_max_table_capacity };
    n += 1;
    pairs[n] = .{ .id = Setting.qpack_blocked_streams, .value = s.qpack_blocked_streams };
    n += 1;
    if (s.max_field_section_size != 0) {
        pairs[n] = .{ .id = Setting.max_field_section_size, .value = s.max_field_section_size };
        n += 1;
    }
    if (s.enable_connect_protocol) {
        pairs[n] = .{ .id = Setting.enable_connect_protocol, .value = 1 };
        n += 1;
    }
    if (s.h3_datagram) {
        pairs[n] = .{ .id = Setting.h3_datagram, .value = 1 };
        n += 1;
    }
    if (s.enable_webtransport) {
        pairs[n] = .{ .id = Setting.enable_webtransport, .value = 1 };
        n += 1;
    }

    for (pairs[0..n]) |p| {
        try body.appendSlice(allocator, try webtransport.encodeVarint(p.id, &buf));
        try body.appendSlice(allocator, try webtransport.encodeVarint(p.value, &buf));
    }
    return body.toOwnedSlice(allocator);
}

/// Decode a SETTINGS frame body into a `Settings`. Unknown setting identifiers
/// are skipped (RFC 9114 §7.2.4 — an endpoint MUST ignore unknown settings).
/// Bounds-checked: a value varint running past the body is `error.Malformed`.
pub fn decodeSettingsBody(body: []const u8) Error!Settings {
    var s = Settings{};
    var pos: usize = 0;
    while (pos < body.len) {
        const id = webtransport.decodeVarint(body[pos..]) catch return error.Malformed;
        pos += id.len;
        if (pos >= body.len) return error.Malformed; // value missing
        const val = webtransport.decodeVarint(body[pos..]) catch return error.Malformed;
        pos += val.len;
        switch (id.value) {
            Setting.qpack_max_table_capacity => s.qpack_max_table_capacity = val.value,
            Setting.qpack_blocked_streams => s.qpack_blocked_streams = val.value,
            Setting.max_field_section_size => s.max_field_section_size = val.value,
            Setting.enable_connect_protocol => s.enable_connect_protocol = val.value != 0,
            Setting.h3_datagram => s.h3_datagram = val.value != 0,
            Setting.enable_webtransport => s.enable_webtransport = val.value != 0,
            else => {}, // ignore unknown / GREASE settings
        }
    }
    return s;
}

// ===========================================================================
// Extended CONNECT request / response (RFC 9220 §3, RFC 8441)
// ===========================================================================

/// The pseudo-headers of an Extended CONNECT request, borrowing the decoded
/// QPACK strings. A valid WebTransport CONNECT has method=CONNECT,
/// protocol=webtransport, scheme=https, and an :authority + :path.
pub const ConnectRequest = struct {
    method: []const u8 = "",
    protocol: []const u8 = "",
    scheme: []const u8 = "",
    authority: []const u8 = "",
    path: []const u8 = "",

    pub fn isWebTransport(self: ConnectRequest) bool {
        return std.mem.eql(u8, self.method, "CONNECT") and
            std.mem.eql(u8, self.protocol, "webtransport");
    }
};

/// Decode a QPACK header block (the HEADERS frame payload) into a
/// `ConnectRequest`. The returned strings borrow `headers` (owned by caller).
/// Caller frees `headers` with `allocator.free`.
pub fn decodeConnectHeaders(allocator: Allocator, header_block: []const u8) Error!struct {
    request: ConnectRequest,
    headers: []qpack.Header,
} {
    const headers = try qpack.decodeFieldSection(allocator, header_block);
    errdefer allocator.free(headers);
    var req = ConnectRequest{};
    for (headers) |h| {
        if (std.mem.eql(u8, h.name, ":method")) {
            req.method = h.value;
        } else if (std.mem.eql(u8, h.name, ":protocol")) {
            req.protocol = h.value;
        } else if (std.mem.eql(u8, h.name, ":scheme")) {
            req.scheme = h.value;
        } else if (std.mem.eql(u8, h.name, ":authority")) {
            req.authority = h.value;
        } else if (std.mem.eql(u8, h.name, ":path")) {
            req.path = h.value;
        }
    }
    return .{ .request = req, .headers = headers };
}

/// Encode the QPACK header block for an Extended CONNECT request (client side,
/// used by the test helper and by any client embedding). Caller owns the slice.
pub fn encodeConnectHeaders(
    allocator: Allocator,
    authority: []const u8,
    path: []const u8,
) Error![]u8 {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = authority },
        .{ .name = ":path", .value = path },
    };
    return qpack.encodeFieldSection(allocator, &hdrs);
}

/// Encode the QPACK header block for the `:status` response. `ok` selects 200
/// (CONNECT accepted) vs a 4xx rejection. Caller owns the slice.
pub fn encodeStatusHeaders(allocator: Allocator, status: []const u8) Error![]u8 {
    const hdrs = [_]qpack.Header{
        .{ .name = ":status", .value = status },
    };
    return qpack.encodeFieldSection(allocator, &hdrs);
}

// ===========================================================================
// WebTransport session model
// ===========================================================================

pub const SessionId = webtransport.SessionId;

/// A WebTransport stream opened/accepted within a session. `stream_id` is the
/// underlying QUIC stream id; `is_bidirectional` distinguishes WT bidi vs uni.
pub const WtStream = struct {
    stream_id: u64,
    is_bidirectional: bool,
};

/// An established WebTransport session, keyed by the CONNECT (bidi) stream id.
/// Owns copies of the authority/path so they survive past the decoded HEADERS.
pub const Session = struct {
    allocator: Allocator,
    /// The CONNECT stream id == the WebTransport session id (RFC 9220 §4.2).
    session_id: SessionId,
    authority: []u8, // owned
    path: []u8, // owned
    /// WT streams known to this session (opened locally or accepted from peer).
    streams: std.ArrayList(WtStream),
    closed: bool = false,

    fn init(allocator: Allocator, connect_stream_id: u64, authority: []const u8, path: []const u8) Error!Session {
        const sid = SessionId.initClientBidirectional(connect_stream_id) catch return error.Malformed;
        const auth_copy = try allocator.dupe(u8, authority);
        errdefer allocator.free(auth_copy);
        const path_copy = try allocator.dupe(u8, path);
        errdefer allocator.free(path_copy);
        return .{
            .allocator = allocator,
            .session_id = sid,
            .authority = auth_copy,
            .path = path_copy,
            .streams = .empty,
        };
    }

    fn deinit(self: *Session) void {
        self.allocator.free(self.authority);
        self.allocator.free(self.path);
        self.streams.deinit(self.allocator);
        self.* = undefined;
    }

    /// The quarter-stream-id used to prefix this session's datagrams (RFC 9297).
    pub fn quarterStreamId(self: *const Session) u64 {
        return self.session_id.quarterStreamId();
    }
};

// ===========================================================================
// Http3Conn — the server-side driver over a `*quic_conn.Conn`
// ===========================================================================

/// Events surfaced to the caller (the IRC bridge / listener layer).
pub const Event = union(enum) {
    /// A WebTransport session was established. The `Session` is owned by the
    /// `Http3Conn`; the slices borrow it and are valid until the session closes.
    session_established: struct {
        session_id: u64,
        authority: []const u8,
        path: []const u8,
    },
    /// The (single) WebTransport session closed.
    session_closed: struct { session_id: u64 },
    /// A CONNECT request was rejected (e.g. not WebTransport). The stream was
    /// answered with `status` and finished.
    connect_rejected: struct { stream_id: u64, status: []const u8 },
};

/// The server-side HTTP/3 + WebTransport driver. Wraps a `*quic_conn.Conn`
/// (which it does NOT own — the listener owns the QUIC connection). Drives the
/// control stream + SETTINGS, accepts the Extended CONNECT, and models the WT
/// session. Call `service` after feeding the QUIC conn its datagrams.
pub const Http3Conn = struct {
    allocator: Allocator,
    conn: *quic_conn.Conn,
    role: quic_conn.Role,

    /// Local SETTINGS we advertise (server defaults).
    local_settings: Settings,
    /// The control uni-stream id we opened, once opened.
    control_stream_id: ?u64 = null,
    /// True once we have written our SETTINGS frame on the control stream.
    settings_sent: bool = false,
    /// The peer's control stream id, once detected (first uni stream whose type
    /// prefix is 0x00). On the server this is the client's control stream.
    peer_control_stream_id: ?u64 = null,
    /// Peer SETTINGS, once its control stream delivered a SETTINGS frame.
    peer_settings: ?Settings = null,
    /// QPACK encoder uni-stream id (opened empty, zero dynamic table).
    qpack_encoder_stream_id: ?u64 = null,

    /// The established WebTransport session (one per connection), if any.
    session: ?Session = null,

    /// Per-incoming-uni-stream read state: tracks the parsed type prefix so we
    /// can demux control vs qpack vs WT uni streams across multiple reads.
    uni_state: std.AutoHashMapUnmanaged(u64, UniStreamState) = .empty,
    /// Per-incoming-bidi-stream buffered bytes (for assembling the CONNECT
    /// HEADERS frame which may span multiple STREAM frames).
    bidi_buf: std.AutoHashMapUnmanaged(u64, std.ArrayListUnmanaged(u8)) = .empty,
    /// Bidi streams already handled (CONNECT accepted or rejected) so we do not
    /// re-process them.
    bidi_handled: std.AutoHashMapUnmanaged(u64, void) = .empty,

    /// Pending events for the caller to drain via `nextEvent`.
    events: std.ArrayList(Event),

    /// Scratch read buffer for stream reads.
    read_scratch: [4096]u8 = undefined,

    const UniStreamState = struct {
        /// The varint stream-type prefix, once fully read. null until decoded.
        stream_type: ?u64 = null,
        /// For a WT uni stream: the session id that follows the type prefix.
        wt_session_id: ?u64 = null,
        /// Bytes buffered while we accumulate the (possibly fragmented) prefix.
        prefix_buf: std.ArrayListUnmanaged(u8) = .empty,
        /// For the control stream: bytes buffered to assemble the SETTINGS frame.
        body_buf: std.ArrayListUnmanaged(u8) = .empty,
        /// True once we have processed SETTINGS on a control stream.
        settings_done: bool = false,
    };

    pub fn init(allocator: Allocator, conn: *quic_conn.Conn) Http3Conn {
        return .{
            .allocator = allocator,
            .conn = conn,
            .role = conn.role,
            .local_settings = Settings.serverDefault(),
            .events = .empty,
        };
    }

    pub fn deinit(self: *Http3Conn) void {
        if (self.session) |*s| s.deinit();
        {
            var it = self.uni_state.iterator();
            while (it.next()) |e| {
                e.value_ptr.prefix_buf.deinit(self.allocator);
                e.value_ptr.body_buf.deinit(self.allocator);
            }
            self.uni_state.deinit(self.allocator);
        }
        {
            var it = self.bidi_buf.iterator();
            while (it.next()) |e| e.value_ptr.deinit(self.allocator);
            self.bidi_buf.deinit(self.allocator);
        }
        self.bidi_handled.deinit(self.allocator);
        self.events.deinit(self.allocator);
        self.* = undefined;
    }

    // -----------------------------------------------------------------------
    // Public surface
    // -----------------------------------------------------------------------

    pub fn sessionEstablished(self: *const Http3Conn) bool {
        return self.session != null and !self.session.?.closed;
    }

    /// Drain the next pending event, or null. Events borrow this struct's owned
    /// data; consume them before the next `service` call that may close them.
    pub fn nextEvent(self: *Http3Conn) ?Event {
        if (self.events.items.len == 0) return null;
        return self.events.orderedRemove(0);
    }

    /// Drive one service step: once the QUIC connection is established, open the
    /// control stream + QPACK encoder stream and send SETTINGS; then process any
    /// newly-readable peer control / bidi / WT streams and queued WT datagrams.
    ///
    /// The caller invokes this after every `conn.recvDatagram(...)` and before
    /// `conn.sendDatagrams(...)`.
    pub fn service(self: *Http3Conn) Error!void {
        if (!self.conn.isEstablished()) return;

        try self.ensureControlStream();
        try self.serviceUniStreams();
        try self.serviceBidiStreams();
    }

    /// Open the server control + QPACK encoder uni-streams and send our SETTINGS
    /// once the connection is established. Idempotent.
    fn ensureControlStream(self: *Http3Conn) Error!void {
        if (self.settings_sent) return;

        if (self.control_stream_id == null) {
            self.control_stream_id = self.conn.openUniStream() catch return error.NotReady;
        }
        if (self.qpack_encoder_stream_id == null) {
            self.qpack_encoder_stream_id = self.conn.openUniStream() catch return error.NotReady;
        }

        const ctl = self.control_stream_id.?;
        // Control stream type prefix (0x00) followed by a SETTINGS frame.
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.allocator);
        var vbuf: [8]u8 = undefined;
        try out.appendSlice(self.allocator, try webtransport.encodeVarint(UniStreamType.control, &vbuf));

        const settings_body = try encodeSettingsBody(self.allocator, self.local_settings);
        defer self.allocator.free(settings_body);
        try encodeFrame(self.allocator, &out, FrameType.settings, settings_body);
        self.conn.sendStream(ctl, out.items, false) catch return error.NotReady;

        // QPACK encoder stream: just the type prefix (0x02). With a zero-capacity
        // dynamic table it carries no instructions, but RFC 9204 §4.2 expects the
        // stream to exist.
        const enc = self.qpack_encoder_stream_id.?;
        var enc_prefix: [8]u8 = undefined;
        const enc_bytes = try webtransport.encodeVarint(UniStreamType.qpack_encoder, &enc_prefix);
        self.conn.sendStream(enc, enc_bytes, false) catch return error.NotReady;

        self.settings_sent = true;
    }

    // -----------------------------------------------------------------------
    // Incoming unidirectional streams: control / qpack / WebTransport-uni
    // -----------------------------------------------------------------------

    /// Probe the QUIC engine for received unidirectional streams the peer
    /// opened (client uni = 2,6,10,…) and process newly-readable bytes.
    fn serviceUniStreams(self: *Http3Conn) Error!void {
        // The peer (client) opens uni streams at ids 2,6,10,…  We scan a bounded
        // window of candidate ids; a stream only "exists" once the engine has
        // received a STREAM frame for it (getStream != null surfaced via a
        // non-zero read or a recorded final size).
        var ord: u64 = 0;
        const peer_uni_base: u64 = if (self.role == .server) 2 else 3;
        while (ord < max_scanned_streams) : (ord += 1) {
            const sid = peer_uni_base + ord * 4;
            if (!self.streamExists(sid)) continue;
            try self.serviceOneUniStream(sid);
        }
    }

    fn serviceOneUniStream(self: *Http3Conn, sid: u64) Error!void {
        const gop = try self.uni_state.getOrPut(self.allocator, sid);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        const st = gop.value_ptr;

        // Drain all currently-readable bytes into the per-stream prefix/body.
        try self.drainStream(sid, st);

        // Decode the stream-type prefix once enough bytes are present.
        if (st.stream_type == null) {
            const dec = webtransport.decodeVarint(st.prefix_buf.items) catch return; // need more
            st.stream_type = dec.value;
            // Move the post-prefix bytes into body_buf.
            const rest = st.prefix_buf.items[dec.len..];
            try st.body_buf.appendSlice(self.allocator, rest);
            st.prefix_buf.clearRetainingCapacity();
        }

        const stype = st.stream_type orelse return;
        switch (stype) {
            UniStreamType.control => {
                if (self.peer_control_stream_id == null) self.peer_control_stream_id = sid;
                try self.processPeerControl(st);
            },
            UniStreamType.qpack_encoder, UniStreamType.qpack_decoder => {
                // Zero-capacity dynamic table: nothing to process. Drain & drop.
                st.body_buf.clearRetainingCapacity();
            },
            UniStreamType.webtransport => {
                try self.processWtUniStream(sid, st);
            },
            else => {
                // Unknown uni stream type: ignore its bytes (RFC 9114 §6.2 —
                // reserved/unknown stream types are abandoned).
                st.body_buf.clearRetainingCapacity();
            },
        }
    }

    /// Process the peer control stream: decode its SETTINGS frame (the first
    /// frame on the control stream per RFC 9114 §6.2.1) and require WebTransport.
    fn processPeerControl(self: *Http3Conn, st: *UniStreamState) Error!void {
        if (st.settings_done) {
            st.body_buf.clearRetainingCapacity();
            return;
        }
        var pos: usize = 0;
        const frame = (try findFrame(st.body_buf.items, &pos, FrameType.settings)) orelse return;
        const settings = try decodeSettingsBody(frame.payload);
        self.peer_settings = settings;
        if (!settings.supportsWebTransport()) return error.WebTransportUnsupported;
        st.settings_done = true;
        // Keep any trailing bytes after the SETTINGS frame for completeness.
        const remaining = st.body_buf.items[pos..];
        const kept = try self.allocator.dupe(u8, remaining);
        defer self.allocator.free(kept);
        st.body_buf.clearRetainingCapacity();
        try st.body_buf.appendSlice(self.allocator, kept);
    }

    /// Process a WebTransport unidirectional stream: read the session id varint
    /// that follows the 0x54 type prefix, register the WT stream on the session.
    fn processWtUniStream(self: *Http3Conn, sid: u64, st: *UniStreamState) Error!void {
        if (st.wt_session_id == null) {
            const dec = webtransport.decodeVarint(st.body_buf.items) catch return; // need more
            st.wt_session_id = dec.value;
            const rest = st.body_buf.items[dec.len..];
            const kept = try self.allocator.dupe(u8, rest);
            defer self.allocator.free(kept);
            st.body_buf.clearRetainingCapacity();
            try st.body_buf.appendSlice(self.allocator, kept);
            // Register the stream on the matching session.
            if (self.session) |*s| {
                if (s.session_id.stream_id == st.wt_session_id.?) {
                    try s.streams.append(self.allocator, .{ .stream_id = sid, .is_bidirectional = false });
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Incoming bidirectional streams: the Extended CONNECT + WT bidi streams
    // -----------------------------------------------------------------------

    fn serviceBidiStreams(self: *Http3Conn) Error!void {
        // Peer (client) bidi streams are 0,4,8,…
        var ord: u64 = 0;
        const peer_bidi_base: u64 = if (self.role == .server) 0 else 1;
        while (ord < max_scanned_streams) : (ord += 1) {
            const sid = peer_bidi_base + ord * 4;
            if (self.bidi_handled.contains(sid)) continue;
            if (!self.streamExists(sid)) continue;
            try self.serviceOneBidiStream(sid);
        }
    }

    fn serviceOneBidiStream(self: *Http3Conn, sid: u64) Error!void {
        // Once a session exists, a new client bidi stream MAY be a WT bidi stream
        // (it begins with the 0x41 signal + session id). Detect that first.
        if (self.session != null) {
            if (try self.maybeWtBidiStream(sid)) return;
        }

        // Otherwise this is (expected to be) the Extended CONNECT request stream.
        const gop = try self.bidi_buf.getOrPut(self.allocator, sid);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        const buf = gop.value_ptr;

        // Accumulate readable bytes.
        try self.drainStreamInto(sid, buf);

        // Try to decode a HEADERS frame.
        var pos: usize = 0;
        const headers_frame = (try findFrame(buf.items, &pos, FrameType.headers)) orelse return;
        try self.handleConnect(sid, headers_frame.payload);

        // Done with this stream's request buffer.
        _ = self.bidi_handled.put(self.allocator, sid, {}) catch {};
        buf.deinit(self.allocator);
        _ = self.bidi_buf.remove(sid);
    }

    /// If `sid` begins with a WebTransport bidi stream signal (0x41 + session
    /// id), register it on the session and return true. Returns false (and leaves
    /// the stream untouched) if it does not look like a WT bidi stream yet.
    fn maybeWtBidiStream(self: *Http3Conn, sid: u64) Error!bool {
        // Peek a small prefix without consuming, by reading into scratch. The
        // engine's readStream consumes, so we buffer into bidi_buf and re-parse.
        const gop = try self.bidi_buf.getOrPut(self.allocator, sid);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        const buf = gop.value_ptr;
        try self.drainStreamInto(sid, buf);
        if (buf.items.len == 0) return false;

        // The first byte 0x40 0x41 (two-byte varint for 0x41) signals WT bidi.
        const sig = webtransport.decodeVarint(buf.items) catch return false;
        if (sig.value != webtransport.StreamType.webtransport_bidirectional) return false;
        const after_sig = buf.items[sig.len..];
        const sess = webtransport.decodeVarint(after_sig) catch return false;
        // Register the WT bidi stream on the session.
        if (self.session) |*s| {
            if (s.session_id.stream_id == sess.value) {
                try s.streams.append(self.allocator, .{ .stream_id = sid, .is_bidirectional = true });
            }
        }
        // The remaining bytes (after signal+session id) are the WT payload; the
        // caller reads them via readWtStream, which strips the prefix. Mark the
        // stream handled here so we do not re-CONNECT it, but keep the buffer so
        // readWtStream can return the payload.
        _ = self.bidi_handled.put(self.allocator, sid, {}) catch {};
        // Store the payload offset by trimming the consumed prefix from the buf.
        const payload_off = sig.len + sess.len;
        const payload = buf.items[payload_off..];
        const kept = try self.allocator.dupe(u8, payload);
        defer self.allocator.free(kept);
        buf.clearRetainingCapacity();
        try buf.appendSlice(self.allocator, kept);
        return true;
    }

    /// Validate and answer an Extended CONNECT. On success, establish the WT
    /// session and answer `:status=200`; on failure answer a 4xx and finish.
    fn handleConnect(self: *Http3Conn, sid: u64, header_block: []const u8) Error!void {
        const decoded = try decodeConnectHeaders(self.allocator, header_block);
        defer self.allocator.free(decoded.headers);
        const req = decoded.request;

        if (!req.isWebTransport()) {
            // Non-WebTransport / malformed CONNECT — reject without faulting.
            try self.answerStatus(sid, "400");
            try self.events.append(self.allocator, .{ .connect_rejected = .{
                .stream_id = sid,
                .status = "400",
            } });
            return;
        }
        if (self.session != null) {
            try self.answerStatus(sid, "409");
            try self.events.append(self.allocator, .{ .connect_rejected = .{
                .stream_id = sid,
                .status = "409",
            } });
            return;
        }

        // Establish the session keyed by the CONNECT stream id.
        self.session = try Session.init(self.allocator, sid, req.authority, req.path);
        errdefer {
            if (self.session) |*s| s.deinit();
            self.session = null;
        }

        // Answer :status=200 (do NOT fin — the CONNECT stream stays open as the
        // session's control channel, RFC 9220 §4.2).
        try self.answerStatus(sid, "200");

        const s = &self.session.?;
        try self.events.append(self.allocator, .{ .session_established = .{
            .session_id = s.session_id.stream_id,
            .authority = s.authority,
            .path = s.path,
        } });
    }

    /// Write a `:status` HEADERS frame on the CONNECT/request stream. `fin` is
    /// false for a 200 (the stream stays open) and true for a rejection.
    fn answerStatus(self: *Http3Conn, sid: u64, status: []const u8) Error!void {
        const block = try encodeStatusHeaders(self.allocator, status);
        defer self.allocator.free(block);
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.allocator);
        try encodeFrame(self.allocator, &out, FrameType.headers, block);
        const is_reject = !std.mem.eql(u8, status, "200");
        self.conn.sendStream(sid, out.items, is_reject) catch return error.NotReady;
    }

    // -----------------------------------------------------------------------
    // WebTransport stream + datagram I/O (RFC 9220 §4, RFC 9297)
    // -----------------------------------------------------------------------

    /// Open a new WebTransport unidirectional stream for the session. Returns the
    /// underlying QUIC stream id. Writes the 0x54 signal + session id prefix.
    pub fn openWtUniStream(self: *Http3Conn) Error!u64 {
        const s = if (self.session) |*ss| ss else return error.NotReady;
        const sid = self.conn.openUniStream() catch return error.NotReady;
        const prefix = try webtransport.encodeStreamSignal(
            self.allocator,
            webtransport.StreamType.webtransport_unidirectional,
            s.session_id,
        );
        defer self.allocator.free(prefix);
        self.conn.sendStream(sid, prefix, false) catch return error.NotReady;
        try s.streams.append(self.allocator, .{ .stream_id = sid, .is_bidirectional = false });
        return sid;
    }

    /// Open a new WebTransport bidirectional stream for the session. Returns the
    /// underlying QUIC stream id. Writes the 0x41 signal + session id prefix.
    pub fn openWtBidiStream(self: *Http3Conn) Error!u64 {
        const s = if (self.session) |*ss| ss else return error.NotReady;
        const sid = self.conn.openStream() catch return error.NotReady;
        const prefix = try webtransport.encodeStreamSignal(
            self.allocator,
            webtransport.StreamType.webtransport_bidirectional,
            s.session_id,
        );
        defer self.allocator.free(prefix);
        self.conn.sendStream(sid, prefix, false) catch return error.NotReady;
        try s.streams.append(self.allocator, .{ .stream_id = sid, .is_bidirectional = true });
        return sid;
    }

    /// Write application bytes on an already-opened WT stream `sid` (the signal
    /// prefix has already been sent by `openWtUniStream`/`openWtBidiStream`).
    pub fn writeWtStream(self: *Http3Conn, sid: u64, bytes: []const u8, fin: bool) Error!void {
        self.conn.sendStream(sid, bytes, fin) catch return error.NotReady;
    }

    /// Read application bytes from a WT stream `sid` into `dst`. For a WT bidi
    /// stream that arrived from the peer, the leading signal+session prefix was
    /// already stripped into `bidi_buf`; return those buffered bytes first, then
    /// any freshly-readable QUIC bytes. Returns the number of bytes written.
    pub fn readWtStream(self: *Http3Conn, sid: u64, dst: []u8) usize {
        var written: usize = 0;
        // Drain any buffered (already-stripped) prefix payload from a peer WT
        // bidi stream first.
        if (self.bidi_buf.getPtr(sid)) |buf| {
            const n = @min(dst.len, buf.items.len);
            if (n > 0) {
                @memcpy(dst[0..n], buf.items[0..n]);
                // Compact.
                std.mem.copyForwards(u8, buf.items[0 .. buf.items.len - n], buf.items[n..]);
                buf.shrinkRetainingCapacity(buf.items.len - n);
                written += n;
            }
        }
        // For a peer WT uni stream, the body_buf holds post-prefix bytes.
        if (self.uni_state.getPtr(sid)) |st| {
            if (written < dst.len and st.body_buf.items.len > 0) {
                const n = @min(dst.len - written, st.body_buf.items.len);
                @memcpy(dst[written .. written + n], st.body_buf.items[0..n]);
                std.mem.copyForwards(u8, st.body_buf.items[0 .. st.body_buf.items.len - n], st.body_buf.items[n..]);
                st.body_buf.shrinkRetainingCapacity(st.body_buf.items.len - n);
                written += n;
            }
        }
        if (written < dst.len) {
            written += self.conn.readStream(sid, dst[written..]);
        }
        return written;
    }

    /// Send a WebTransport datagram on the session: prefix the payload with the
    /// session's quarter-stream-id and hand it to the QUIC DATAGRAM path.
    pub fn sendWtDatagram(self: *Http3Conn, payload: []const u8) Error!void {
        const s = if (self.session) |*ss| ss else return error.NotReady;
        const framed = try webtransport.encodeSessionDatagram(self.allocator, s.session_id, payload);
        defer self.allocator.free(framed);
        self.conn.sendDatagram(framed) catch return error.NotReady;
    }

    /// Receive the next WebTransport datagram for the session, or null if none.
    /// The returned payload is an owned copy (free via the allocator). Datagrams
    /// whose quarter-stream-id does not match the session are dropped.
    pub fn recvWtDatagram(self: *Http3Conn) Error!?[]u8 {
        const s = if (self.session) |*ss| ss else return null;
        while (self.conn.recvDatagramPayload()) |raw| {
            defer self.allocator.free(raw);
            const decoded = webtransport.decodeSessionDatagram(raw) catch continue;
            if (decoded.session_id.stream_id != s.session_id.stream_id) continue;
            return try self.allocator.dupe(u8, decoded.payload);
        }
        return null;
    }

    /// Close the WebTransport session: emit a session_closed event and mark it.
    pub fn closeSession(self: *Http3Conn) Error!void {
        if (self.session) |*s| {
            if (!s.closed) {
                s.closed = true;
                try self.events.append(self.allocator, .{ .session_closed = .{
                    .session_id = s.session_id.stream_id,
                } });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Whether the QUIC engine has any received state for `sid` (a STREAM frame
    /// arrived). Used to decide which candidate stream ids to service.
    fn streamExists(self: *Http3Conn, sid: u64) bool {
        return self.conn.engine.getStream(sid) != null;
    }

    /// Drain all currently-readable bytes from QUIC stream `sid` into the
    /// per-uni-stream prefix/body buffers (prefix while the type is unknown,
    /// body afterwards).
    fn drainStream(self: *Http3Conn, sid: u64, st: *UniStreamState) Error!void {
        while (true) {
            const n = self.conn.readStream(sid, &self.read_scratch);
            if (n == 0) break;
            if (st.stream_type == null) {
                try st.prefix_buf.appendSlice(self.allocator, self.read_scratch[0..n]);
            } else {
                try st.body_buf.appendSlice(self.allocator, self.read_scratch[0..n]);
            }
        }
    }

    /// Drain all currently-readable bytes from QUIC stream `sid` into `buf`.
    fn drainStreamInto(self: *Http3Conn, sid: u64, buf: *std.ArrayListUnmanaged(u8)) Error!void {
        while (true) {
            const n = self.conn.readStream(sid, &self.read_scratch);
            if (n == 0) break;
            try buf.appendSlice(self.allocator, self.read_scratch[0..n]);
        }
    }
};

/// How many candidate stream ids per (initiator, directionality) class to scan
/// when probing the QUIC engine for newly-received streams. Bounded so a peer
/// cannot make us scan unboundedly; the control + qpack + a handful of WT
/// streams fit comfortably.
const max_scanned_streams: u64 = 64;

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;
const Ed25519 = std.crypto.sign.Ed25519;
const x509_selfsign = @import("x509_selfsign.zig");
const quic_transport_params = @import("quic_transport_params.zig");

// ---- pure codec tests (no QUIC) -------------------------------------------

test "h3 frame codec round-trips DATA/HEADERS/SETTINGS" {
    const alloc = testing.allocator;
    inline for (.{ FrameType.data, FrameType.headers, FrameType.settings }) |ft| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(alloc);
        const payload = "hello frame payload";
        try encodeFrame(alloc, &out, ft, payload);
        const d = try decodeFrame(out.items);
        try testing.expectEqual(@as(u64, ft), d.frame.frame_type);
        try testing.expectEqualStrings(payload, d.frame.payload);
        try testing.expectEqual(out.items.len, d.consumed);
    }
}

test "h3 frame codec skips unknown / GREASE frame types" {
    const alloc = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);
    // An unknown (GREASE) frame type 0x21, then a SETTINGS frame.
    try encodeFrame(alloc, &out, 0x21, "greasy");
    try encodeFrame(alloc, &out, 0x1f * 7 + 0x21, "more grease");
    try encodeFrame(alloc, &out, FrameType.settings, "SETTINGS-BODY");

    var pos: usize = 0;
    const found = (try findFrame(out.items, &pos, FrameType.settings)).?;
    try testing.expectEqual(@as(u64, FrameType.settings), found.frame_type);
    try testing.expectEqualStrings("SETTINGS-BODY", found.payload);
}

test "h3 frame codec rejects a length running past the buffer" {
    // type=0x04 (settings), length=0x10 (16) but only 2 payload bytes present.
    const bad = [_]u8{ 0x04, 0x10, 0xaa, 0xbb };
    try testing.expectError(error.Malformed, decodeFrame(&bad));
}

test "settings round-trip includes WT / datagram / connect-protocol settings" {
    const alloc = testing.allocator;
    const s = Settings.serverDefault();
    const body = try encodeSettingsBody(alloc, s);
    defer alloc.free(body);

    const decoded = try decodeSettingsBody(body);
    try testing.expect(decoded.enable_webtransport);
    try testing.expect(decoded.h3_datagram);
    try testing.expect(decoded.enable_connect_protocol);
    try testing.expectEqual(@as(u64, 0), decoded.qpack_max_table_capacity);
    try testing.expectEqual(@as(u64, 0), decoded.qpack_blocked_streams);
    try testing.expect(decoded.supportsWebTransport());
}

test "settings decode ignores unknown settings and reports missing WT support" {
    const alloc = testing.allocator;
    // Only QPACK settings — no WebTransport / datagram / connect-protocol.
    const s = Settings{};
    const body = try encodeSettingsBody(alloc, s);
    defer alloc.free(body);
    const decoded = try decodeSettingsBody(body);
    try testing.expect(!decoded.supportsWebTransport());

    // A SETTINGS body with an unknown identifier is tolerated.
    var custom: std.ArrayList(u8) = .empty;
    defer custom.deinit(alloc);
    var vbuf: [8]u8 = undefined;
    try custom.appendSlice(alloc, try webtransport.encodeVarint(0xdead, &vbuf)); // unknown id
    try custom.appendSlice(alloc, try webtransport.encodeVarint(0x1234, &vbuf)); // value
    try custom.appendSlice(alloc, try webtransport.encodeVarint(Setting.enable_webtransport, &vbuf));
    try custom.appendSlice(alloc, try webtransport.encodeVarint(1, &vbuf));
    const d2 = try decodeSettingsBody(custom.items);
    try testing.expect(d2.enable_webtransport);
}

test "settings decode rejects a truncated value varint" {
    // id present (0x06), but the value varint declares 2 bytes and only 1 is
    // present.
    const bad = [_]u8{ 0x06, 0x40 };
    try testing.expectError(error.Malformed, decodeSettingsBody(&bad));
}

test "qpack: decodes CONNECT pseudo-headers from the static table + literals" {
    const alloc = testing.allocator;
    const block = try encodeConnectHeaders(alloc, "irc.example", "/wt");
    defer alloc.free(block);

    const decoded = try decodeConnectHeaders(alloc, block);
    defer alloc.free(decoded.headers);
    const req = decoded.request;
    try testing.expectEqualStrings("CONNECT", req.method);
    try testing.expectEqualStrings("webtransport", req.protocol);
    try testing.expectEqualStrings("https", req.scheme);
    try testing.expectEqualStrings("irc.example", req.authority);
    try testing.expectEqualStrings("/wt", req.path);
    try testing.expect(req.isWebTransport());
}

test "qpack: encodes :status=200 decodable with the static table" {
    const alloc = testing.allocator;
    const block = try encodeStatusHeaders(alloc, "200");
    defer alloc.free(block);
    const headers = try qpack.decodeFieldSection(alloc, block);
    defer alloc.free(headers);
    try testing.expectEqual(@as(usize, 1), headers.len);
    try testing.expectEqualStrings(":status", headers[0].name);
    try testing.expectEqualStrings("200", headers[0].value);
}

test "connect request without :protocol=webtransport is not WebTransport" {
    const alloc = testing.allocator;
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "irc.example" },
        // no :protocol
    };
    const block = try qpack.encodeFieldSection(alloc, &hdrs);
    defer alloc.free(block);
    const decoded = try decodeConnectHeaders(alloc, block);
    defer alloc.free(decoded.headers);
    try testing.expect(!decoded.request.isWebTransport());
}

// ---- loopback establish-session + WT datagram/stream tests ----------------

const test_client_cid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
const test_server_cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
const test_initial_dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
const test_alpn = [_][]const u8{"h3"};

fn mintCert(out: *[1024]u8, kp: Ed25519.KeyPair) ![]const u8 {
    return x509_selfsign.buildSelfSigned(out, .{
        .common_name = "wt.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x51, 0x99 },
        .key_pair = kp,
        .dns_names = &.{"wt.test"},
        .is_ca = true,
    });
}

const server_params: quic_transport_params.TransportParameters = .{
    .initial_source_connection_id = &test_server_cid,
    .max_idle_timeout = 30_000,
    .initial_max_data = 1 << 20,
    .initial_max_stream_data_bidi_local = 256 * 1024,
    .initial_max_stream_data_bidi_remote = 256 * 1024,
    .initial_max_streams_bidi = 100,
};
const client_params: quic_transport_params.TransportParameters = .{
    .initial_source_connection_id = &test_client_cid,
    .initial_max_data = 1 << 20,
    .initial_max_stream_data_bidi_local = 256 * 1024,
    .initial_max_stream_data_bidi_remote = 256 * 1024,
    .initial_max_streams_bidi = 100,
};

const WtLoopback = struct {
    kp: Ed25519.KeyPair,
    cert_buf: [1024]u8,
    cert: []const u8,
    cert_chain: [1][]const u8,
    server: quic_conn.Conn,
    client: quic_conn.Conn,

    fn init(alloc: Allocator) !*WtLoopback {
        const lb = try alloc.create(WtLoopback);
        errdefer alloc.destroy(lb);
        lb.kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x37} ** Ed25519.KeyPair.seed_length);
        lb.cert = try mintCert(&lb.cert_buf, lb.kp);
        lb.cert_chain = .{lb.cert};

        lb.server = try quic_conn.Conn.initServer(alloc, .{
            .cert_chain = &lb.cert_chain,
            .signing_key = .{ .ed25519 = lb.kp },
            .alpn_protocols = &test_alpn,
            .transport_params = server_params,
            .local_cid = &test_server_cid,
            .x25519_seed = [_]u8{0x21} ** 32,
            .server_random = [_]u8{0x55} ** 32,
        });
        errdefer lb.server.deinit();
        lb.client = try quic_conn.Conn.initClient(alloc, .{
            .alpn_protocols = &test_alpn,
            .transport_params = client_params,
            .local_cid = &test_client_cid,
            .initial_dcid = &test_initial_dcid,
            .x25519_seed = [_]u8{0x42} ** 32,
            .client_random = [_]u8{0x11} ** 32,
        });
        return lb;
    }

    fn deinit(self: *WtLoopback, alloc: Allocator) void {
        self.server.deinit();
        self.client.deinit();
        alloc.destroy(self);
    }
};

fn pump(alloc: Allocator, from: *quic_conn.Conn, to: *quic_conn.Conn) !void {
    var out: std.ArrayList(quic_conn.OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try from.sendDatagrams(&out);
    for (out.items) |d| try to.recvDatagram(d.bytes);
}

fn driveHandshake(alloc: Allocator, lb: *WtLoopback) !void {
    var rounds: usize = 0;
    while (rounds < 12) : (rounds += 1) {
        try pump(alloc, &lb.client, &lb.server);
        try pump(alloc, &lb.server, &lb.client);
        if (lb.client.isEstablished() and lb.server.isEstablished()) return;
    }
    return error.HandshakeDidNotComplete;
}

/// A minimal WebTransport *client* helper for the loopback test: it sends the
/// control stream + SETTINGS and the Extended CONNECT, then exchanges WT
/// streams/datagrams. It reuses the same codecs as the server.
const WtClient = struct {
    alloc: Allocator,
    conn: *quic_conn.Conn,
    control_stream: ?u64 = null,
    connect_stream: ?u64 = null,
    session_id: ?SessionId = null,
    status_ok: bool = false,
    connect_buf: std.ArrayListUnmanaged(u8) = .empty,

    fn deinit(self: *WtClient) void {
        self.connect_buf.deinit(self.alloc);
    }

    fn sendControlAndConnect(self: *WtClient, authority: []const u8, path: []const u8) !void {
        // Control stream + SETTINGS.
        const ctl = try self.conn.openUniStream();
        self.control_stream = ctl;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.alloc);
        var vbuf: [8]u8 = undefined;
        try out.appendSlice(self.alloc, try webtransport.encodeVarint(UniStreamType.control, &vbuf));
        const body = try encodeSettingsBody(self.alloc, Settings.serverDefault());
        defer self.alloc.free(body);
        try encodeFrame(self.alloc, &out, FrameType.settings, body);
        try self.conn.sendStream(ctl, out.items, false);

        // Extended CONNECT on a fresh bidi stream.
        const cs = try self.conn.openStream();
        self.connect_stream = cs;
        self.session_id = try SessionId.initClientBidirectional(cs);
        const block = try encodeConnectHeaders(self.alloc, authority, path);
        defer self.alloc.free(block);
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(self.alloc);
        try encodeFrame(self.alloc, &req, FrameType.headers, block);
        try self.conn.sendStream(cs, req.items, false);
    }

    /// Read the CONNECT response on the connect stream; set status_ok on 200.
    fn pollConnectResponse(self: *WtClient) !void {
        const cs = self.connect_stream orelse return;
        var scratch: [2048]u8 = undefined;
        while (true) {
            const n = self.conn.readStream(cs, &scratch);
            if (n == 0) break;
            try self.connect_buf.appendSlice(self.alloc, scratch[0..n]);
        }
        var pos: usize = 0;
        const frame = (try findFrame(self.connect_buf.items, &pos, FrameType.headers)) orelse return;
        const headers = try qpack.decodeFieldSection(self.alloc, frame.payload);
        defer self.alloc.free(headers);
        for (headers) |h| {
            if (std.mem.eql(u8, h.name, ":status") and std.mem.eql(u8, h.value, "200")) {
                self.status_ok = true;
            }
        }
    }

    fn sendWtDatagram(self: *WtClient, payload: []const u8) !void {
        const sid = self.session_id.?;
        const framed = try webtransport.encodeSessionDatagram(self.alloc, sid, payload);
        defer self.alloc.free(framed);
        try self.conn.sendDatagram(framed);
    }

    fn recvWtDatagram(self: *WtClient) !?[]u8 {
        const sid = self.session_id.?;
        while (self.conn.recvDatagramPayload()) |raw| {
            defer self.alloc.free(raw);
            const decoded = webtransport.decodeSessionDatagram(raw) catch continue;
            if (decoded.session_id.stream_id != sid.stream_id) continue;
            return try self.alloc.dupe(u8, decoded.payload);
        }
        return null;
    }

    /// Open a WT uni stream and write `payload` after the signal prefix.
    fn openWtUniAndWrite(self: *WtClient, payload: []const u8) !u64 {
        const sid = try self.conn.openUniStream();
        const prefix = try webtransport.encodeStreamSignal(
            self.alloc,
            webtransport.StreamType.webtransport_unidirectional,
            self.session_id.?,
        );
        defer self.alloc.free(prefix);
        try self.conn.sendStream(sid, prefix, false);
        try self.conn.sendStream(sid, payload, false);
        return sid;
    }
};

fn pumpBoth(alloc: Allocator, lb: *WtLoopback) !void {
    try pump(alloc, &lb.client, &lb.server);
    try pump(alloc, &lb.server, &lb.client);
}

test "wt loopback establishes a WebTransport session over Extended CONNECT" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var server_h3 = Http3Conn.init(alloc, &lb.server);
    defer server_h3.deinit();
    var client = WtClient{ .alloc = alloc, .conn = &lb.client };
    defer client.deinit();

    // Server opens its control stream + SETTINGS.
    try server_h3.service();
    // Client sends control + SETTINGS + Extended CONNECT.
    try client.sendControlAndConnect("irc.example", "/wt");

    // Drive a few round trips: client→server delivers CONNECT, server replies.
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        try pumpBoth(alloc, lb);
        try server_h3.service();
        try client.pollConnectResponse();
        if (server_h3.sessionEstablished() and client.status_ok) break;
    }

    try testing.expect(server_h3.sessionEstablished());
    try testing.expect(client.status_ok);

    // The session surfaces authority/path.
    var saw_event = false;
    while (server_h3.nextEvent()) |ev| {
        switch (ev) {
            .session_established => |se| {
                try testing.expectEqualStrings("irc.example", se.authority);
                try testing.expectEqualStrings("/wt", se.path);
                saw_event = true;
            },
            else => {},
        }
    }
    try testing.expect(saw_event);
    // The session id is the CONNECT stream id (the client's first bidi stream).
    try testing.expectEqual(client.connect_stream.?, server_h3.session.?.session_id.stream_id);
}

test "wt loopback exchanges a datagram byte-exact in both directions" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var server_h3 = Http3Conn.init(alloc, &lb.server);
    defer server_h3.deinit();
    var client = WtClient{ .alloc = alloc, .conn = &lb.client };
    defer client.deinit();

    try server_h3.service();
    try client.sendControlAndConnect("irc.example", "/wt");
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        try pumpBoth(alloc, lb);
        try server_h3.service();
        try client.pollConnectResponse();
        if (server_h3.sessionEstablished() and client.status_ok) break;
    }
    try testing.expect(server_h3.sessionEstablished());
    while (server_h3.nextEvent()) |_| {}

    // client → server datagram.
    try client.sendWtDatagram("voice-frame-c2s");
    try pump(alloc, &lb.client, &lb.server);
    const got_s = (try server_h3.recvWtDatagram()).?;
    defer alloc.free(got_s);
    try testing.expectEqualStrings("voice-frame-c2s", got_s);

    // server → client datagram.
    try server_h3.sendWtDatagram("voice-frame-s2c");
    try pump(alloc, &lb.server, &lb.client);
    const got_c = (try client.recvWtDatagram()).?;
    defer alloc.free(got_c);
    try testing.expectEqualStrings("voice-frame-s2c", got_c);
}

test "wt loopback exchanges a unidirectional stream byte-exact (client → server)" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var server_h3 = Http3Conn.init(alloc, &lb.server);
    defer server_h3.deinit();
    var client = WtClient{ .alloc = alloc, .conn = &lb.client };
    defer client.deinit();

    try server_h3.service();
    try client.sendControlAndConnect("irc.example", "/wt");
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        try pumpBoth(alloc, lb);
        try server_h3.service();
        try client.pollConnectResponse();
        if (server_h3.sessionEstablished() and client.status_ok) break;
    }
    try testing.expect(server_h3.sessionEstablished());
    while (server_h3.nextEvent()) |_| {}

    // Client opens a WT uni stream and writes a payload after the signal prefix.
    const wt_msg = "WEBTRANSPORT-UNI-STREAM-PAYLOAD :: byte exact";
    const wsid = try client.openWtUniAndWrite(wt_msg);
    try pump(alloc, &lb.client, &lb.server);
    try server_h3.service();

    // The server registered the WT uni stream on the session.
    var found = false;
    var stream_id: u64 = 0;
    for (server_h3.session.?.streams.items) |s| {
        if (!s.is_bidirectional and s.stream_id == wsid) {
            found = true;
            stream_id = s.stream_id;
        }
    }
    try testing.expect(found);

    // Read the payload (prefix already stripped by the service step).
    var rbuf: [256]u8 = undefined;
    var total: usize = 0;
    var tries: usize = 0;
    while (tries < 4 and total < wt_msg.len) : (tries += 1) {
        try server_h3.service();
        total += server_h3.readWtStream(stream_id, rbuf[total..]);
    }
    try testing.expectEqualSlices(u8, wt_msg, rbuf[0..total]);
}

test "wt loopback exchanges a bidirectional stream byte-exact (client → server)" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var server_h3 = Http3Conn.init(alloc, &lb.server);
    defer server_h3.deinit();
    var client = WtClient{ .alloc = alloc, .conn = &lb.client };
    defer client.deinit();

    try server_h3.service();
    try client.sendControlAndConnect("irc.example", "/wt");
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        try pumpBoth(alloc, lb);
        try server_h3.service();
        try client.pollConnectResponse();
        if (server_h3.sessionEstablished() and client.status_ok) break;
    }
    try testing.expect(server_h3.sessionEstablished());
    while (server_h3.nextEvent()) |_| {}

    // Client opens a WT bidi stream: signal 0x41 + session id, then payload.
    const bsid = try lb.client.openStream();
    const prefix = try webtransport.encodeStreamSignal(
        alloc,
        webtransport.StreamType.webtransport_bidirectional,
        client.session_id.?,
    );
    defer alloc.free(prefix);
    try lb.client.sendStream(bsid, prefix, false);
    const bmsg = "WT-BIDI :: hello over a bidirectional WebTransport stream";
    try lb.client.sendStream(bsid, bmsg, false);

    var rbuf: [256]u8 = undefined;
    var total: usize = 0;
    var tries: usize = 0;
    while (tries < 6 and total < bmsg.len) : (tries += 1) {
        try pump(alloc, &lb.client, &lb.server);
        try server_h3.service();
        total += server_h3.readWtStream(bsid, rbuf[total..]);
    }
    try testing.expectEqualSlices(u8, bmsg, rbuf[0..total]);

    // The WT bidi stream is registered on the session.
    var found = false;
    for (server_h3.session.?.streams.items) |s| {
        if (s.is_bidirectional and s.stream_id == bsid) found = true;
    }
    try testing.expect(found);
}

test "wt loopback rejects a CONNECT without :protocol=webtransport" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var server_h3 = Http3Conn.init(alloc, &lb.server);
    defer server_h3.deinit();
    try server_h3.service();

    // Client control stream + SETTINGS.
    const ctl = try lb.client.openUniStream();
    {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(alloc);
        var vbuf: [8]u8 = undefined;
        try out.appendSlice(alloc, try webtransport.encodeVarint(UniStreamType.control, &vbuf));
        const body = try encodeSettingsBody(alloc, Settings.serverDefault());
        defer alloc.free(body);
        try encodeFrame(alloc, &out, FrameType.settings, body);
        try lb.client.sendStream(ctl, out.items, false);
    }

    // A plain CONNECT (no :protocol) on a bidi stream.
    const cs = try lb.client.openStream();
    {
        const hdrs = [_]qpack.Header{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "irc.example" },
        };
        const block = try qpack.encodeFieldSection(alloc, &hdrs);
        defer alloc.free(block);
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(alloc);
        try encodeFrame(alloc, &req, FrameType.headers, block);
        try lb.client.sendStream(cs, req.items, false);
    }

    var round: usize = 0;
    var rejected = false;
    while (round < 8) : (round += 1) {
        try pumpBoth(alloc, lb);
        try server_h3.service();
        while (server_h3.nextEvent()) |ev| {
            switch (ev) {
                .connect_rejected => |cr| {
                    try testing.expectEqualStrings("400", cr.status);
                    rejected = true;
                },
                else => {},
            }
        }
        if (rejected) break;
    }
    try testing.expect(rejected);
    // No session was established.
    try testing.expect(!server_h3.sessionEstablished());
}

test "wt malformed HEADERS block on the CONNECT stream errors without panicking" {
    const alloc = testing.allocator;
    // A HEADERS frame whose QPACK body is a bare dynamic-table reference (0x80),
    // which the static-only decoder rejects. Drive it through decodeConnectHeaders.
    const bad_block = [_]u8{ 0x00, 0x00, 0x80 }; // RIC=0, Base=0, indexed dynamic
    try testing.expectError(error.InvalidRepresentation, decodeConnectHeaders(alloc, &bad_block));
}
