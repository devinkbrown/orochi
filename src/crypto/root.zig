//! mizuchi-crypto — primitives, TLS 1.3-only, VEIL v2 (PQ-hybrid), and the
//! Secret(T) constant-time discipline. Skeleton; see planning/02.
pub const secret = @import("secret.zig");

pub const Secret = secret.Secret;
