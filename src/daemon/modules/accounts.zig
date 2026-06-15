//! accounts module — account/services command family (register, identify,
//! channel registration, ghost, multi-session). Thin thunks over existing
//! LinuxServer handlers. See 17-module-system.md.
const registry = @import("../registry.zig");
const Core = @import("../module_core.zig").Core;
const I = registry.CommandInvocation;
const accounts_feature = "accounts";

fn register(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleRegister(x.conn, x.parsed);
}
fn verify(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleVerify(x.conn, x.parsed);
}
fn identify(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleIdentify(x.conn, x.parsed);
}
fn logout(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleLogout(x.id, x.conn);
}
fn drop(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleDrop(x.conn, x.parsed);
}
fn accountInfo(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAccountInfo(x.conn, x.parsed);
}
fn account(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAccountAdmin(x.conn, x.parsed);
}
fn saslInfo(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSaslInfo(x.conn);
}
fn accountSet(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAccountSet(x.conn, x.parsed);
}
fn ghost(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleGhost(x.conn, x.parsed);
}
fn channel(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleChannel(x.conn, x.parsed);
}
fn session(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSession(x.id, x.conn, x.parsed);
}
fn sessionToken(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSessionToken(x.conn);
}
fn certAdd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleCertAdd(x.conn);
}
fn certList(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleCertList(x.conn);
}
fn certDel(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleCertDel(x.conn, x.parsed);
}

pub const REGISTER_spec = registry.CommandSpec{ .name = "REGISTER", .feature = accounts_feature, .handler = register };
pub const VERIFY_spec = registry.CommandSpec{ .name = "VERIFY", .feature = accounts_feature, .handler = verify };
pub const IDENTIFY_spec = registry.CommandSpec{ .name = "IDENTIFY", .feature = accounts_feature, .handler = identify };
pub const LOGOUT_spec = registry.CommandSpec{ .name = "LOGOUT", .feature = accounts_feature, .handler = logout };
pub const DROP_spec = registry.CommandSpec{ .name = "DROP", .feature = accounts_feature, .handler = drop };
pub const ACCOUNTINFO_spec = registry.CommandSpec{ .name = "ACCOUNTINFO", .feature = accounts_feature, .handler = accountInfo };
pub const ACCOUNT_spec = registry.CommandSpec{ .name = "ACCOUNT", .access = .oper, .feature = accounts_feature, .handler = account, .summary = "administer account lifecycle flags" };
pub const SASLINFO_spec = registry.CommandSpec{ .name = "SASLINFO", .handler = saslInfo };
pub const ACCOUNTSET_spec = registry.CommandSpec{ .name = "ACCOUNTSET", .feature = accounts_feature, .handler = accountSet };
pub const GHOST_spec = registry.CommandSpec{ .name = "GHOST", .feature = accounts_feature, .handler = ghost };
pub const CHANNEL_spec = registry.CommandSpec{ .name = "CHANNEL", .feature = accounts_feature, .handler = channel };
pub const CS_spec = registry.CommandSpec{ .name = "CS", .feature = accounts_feature, .handler = channel };
pub const SESSION_spec = registry.CommandSpec{ .name = "SESSION", .feature = accounts_feature, .handler = session };
pub const SESSIONTOKEN_spec = registry.CommandSpec{ .name = "SESSIONTOKEN", .feature = accounts_feature, .handler = sessionToken };
pub const CERTADD_spec = registry.CommandSpec{ .name = "CERTADD", .feature = accounts_feature, .handler = certAdd };
pub const CERTLIST_spec = registry.CommandSpec{ .name = "CERTLIST", .feature = accounts_feature, .handler = certList };
pub const CERTDEL_spec = registry.CommandSpec{ .name = "CERTDEL", .feature = accounts_feature, .handler = certDel };

pub const module = registry.Module{
    .id = "accounts",
    .commands = &.{
        REGISTER_spec,
        VERIFY_spec,
        IDENTIFY_spec,
        LOGOUT_spec,
        DROP_spec,
        ACCOUNTINFO_spec,
        ACCOUNT_spec,
        SASLINFO_spec,
        ACCOUNTSET_spec,
        GHOST_spec,
        CHANNEL_spec,
        CS_spec,
        SESSION_spec,
        SESSIONTOKEN_spec,
        CERTADD_spec,
        CERTLIST_spec,
        CERTDEL_spec,
    },
};

test "accounts commands are feature gated except SASLINFO" {
    const caps = registry.DispatchCaps{ .registered = true, .oper = true, .disabled_features = &.{"accounts"} };

    try @import("std").testing.expect(!registry.commandAvailable(REGISTER_spec, caps));
    try @import("std").testing.expect(!registry.commandAvailable(CHANNEL_spec, caps));
    try @import("std").testing.expect(!registry.commandAvailable(SESSIONTOKEN_spec, caps));
    try @import("std").testing.expect(registry.commandAvailable(SASLINFO_spec, caps));
}
