//! mizuchi-proto — IRC/IRCv3/IRCX/LADON/VEIL schemas, the comptime codec
//! generator (Codec Loom) and the canonical wire format (CoilPack).
//! Skeleton; see planning/04.

/// Native server-to-server mesh protocol (replaces TS6 entirely).
pub const s2s_protocol = "LADON";

/// Transport security wrapper for post-auth mesh frames.
pub const transport_security = "VEIL";
