//! mizuchi-proto — IRC/IRCv3/IRCX/LADON/VEIL schemas, the comptime codec
//! generator (Codec Loom) and the canonical wire format (CoilPack).
//! Skeleton; see planning/04.

pub const irc_line = @import("irc_line.zig");
pub const coilpack = @import("coilpack.zig");
pub const numeric = @import("numeric.zig");
pub const cap = @import("cap.zig");
pub const frame = @import("frame.zig");
pub const veil = @import("veil.zig");
pub const sasl = @import("sasl.zig");

/// Native server-to-server mesh protocol (replaces TS6 entirely).
pub const s2s_protocol = "LADON";

/// Transport security wrapper for post-auth mesh frames.
pub const transport_security = "VEIL";

test {
    _ = irc_line;
    _ = coilpack;
    _ = numeric;
    _ = cap;
    _ = frame;
    _ = veil;
    _ = sasl;
}
