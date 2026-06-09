//! Canonical protocol inventory — the single source of truth for the static
//! RPL_ISUPPORT (005) tokens, the network name, and the channel-mode token the
//! server advertises.
//!
//! This module is pure data, std-only, and sits in the low protocol layer so it
//! can be imported by BOTH the registration path (`daemon/dispatch.zig`, which
//! emits 005) and the daemon module registry without forming an import cycle.
//! Previously these tokens were hardcoded inline in `dispatch.zig`; centralizing
//! them here means every advertiser shares one definition and a drift test can
//! pin the registry's declared inventory to this list.

const std = @import("std");

/// Network name advertised in ISUPPORT `NETWORK=` and elsewhere.
pub const network_name = "Mizuchi";

/// Channel-mode advertisement token (`CHANMODES=<A>,<B>,<C>,<D>`).
pub const chanmodes_token = "CHANMODES=beIZ,k,lfj,imnstCTNMSg";

/// The static RPL_ISUPPORT (005) tokens, in advertisement order. Dynamic
/// per-connection tokens (if any are added later) are appended by the emitter.
pub const isupport_tokens = [_][]const u8{
    "NETWORK=" ++ network_name,
    "CHANTYPES=#&",
    "NICKLEN=64",
    "CASEMAPPING=ascii",
    "PREFIX=(Qqov)!.@+",
    chanmodes_token,
    "STATUSMSG=!.@+",
    "BOT=B",
    "EXTBAN=$,acgmrz",
    "WHOX",
    "UTF8ONLY",
};

test "isupport tokens are well-formed key[=value] pairs" {
    for (isupport_tokens) |token| {
        try std.testing.expect(token.len > 0);
        // The key part (before any '=') must be non-empty and uppercase-ish.
        const eq = std.mem.indexOfScalar(u8, token, '=');
        const key = if (eq) |i| token[0..i] else token;
        try std.testing.expect(key.len > 0);
        for (key) |c| try std.testing.expect(c != ' ');
    }
}

test "chanmodes token has the four comma-separated classes" {
    const value = chanmodes_token["CHANMODES=".len..];
    var commas: usize = 0;
    for (value) |c| {
        if (c == ',') commas += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), commas);
}
