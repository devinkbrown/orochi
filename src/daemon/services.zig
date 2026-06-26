// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-process IRC services over OroStore with typed results and no IRC I/O.
const std = @import("std");

const store_mod = @import("store.zig");
const toml = @import("../proto/toml.zig");
const scram_store_mod = @import("scram_store.zig");
const sasl = @import("../proto/sasl.zig");
const certfp_bind_mod = @import("certfp_bind.zig");
const rwlock = @import("../substrate/rwlock.zig");
const svc_enforce = @import("svc_enforce.zig");
const svc_acclist = @import("svc_acclist.zig");
const svc_chanbadwords = @import("svc_chanbadwords.zig");

pub const OroStore = store_mod.OroStore;
pub const ScramStore = scram_store_mod.ScramStore;

const account_max = 32;
const channel_max = 64;
const nick_max = 64;
const email_max = 96;
const mlock_max = 128;
const mask_max = 160;
const reason_max = 128;
const key_max = 256;
const record_max = 768;
const salt_len = 16;
const hash_len = 32;
const salt_hex_len = salt_len * 2;
const hash_hex_len = hash_len * 2;
const generation_len = 16;
const generation_hex_len = generation_len * 2;
const default_pbkdf2_rounds: u32 = 100_000;

/// Runtime-tunable account/credential policy. Defaults preserve the historical
/// hardcoded behaviour; the orchestrator overlays the `[accounts]` TOML section
/// via `Config.applyToml` before constructing `Services`.
pub const Config = struct {
    /// PBKDF2-HMAC-SHA256 iteration count for account password hashing.
    pbkdf2_rounds: u32 = default_pbkdf2_rounds,

    /// Overlay `[accounts]` keys from a parsed TOML document onto `cfg`. Missing
    /// keys leave the current value untouched. Pure: no I/O, never fails.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("accounts.pbkdf2_rounds")) |v| {
            if (v >= 1 and v <= std.math.maxInt(u32)) cfg.pbkdf2_rounds = @intCast(v);
        }
    }
};

const account_version = "A1";
const account_version_v2 = "A2";
const channel_version = "C1";
const channel_version_v2 = "C2";
const access_version = "X1";
const akick_version = "K1";
const verify_version = "V1";
const ward_version = "W1";
const saccess_version = "S1";
const access_prefix = "chanaccess:";
const akick_prefix = "chanakick:";
const verify_prefix = "acctverify:";
const ward_prefix = "ward:";
const saccess_prefix = "saccess:";
const missing_account_salt: [salt_len]u8 = .{
    0x6d, 0x69, 0x7a, 0x75, 0x63, 0x68, 0x69, 0x2d,
    0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
};
pub const session_token_prefix = "sst_";
pub const session_token_random_len: usize = 16;
pub const session_token_len: usize = session_token_prefix.len + session_token_random_len * 2;
pub const default_session_token_ttl_seconds: i64 = 30 * 24 * 60 * 60;

pub const channel_access_family = store_mod.Family.props;

const StorePutError = @typeInfo(@typeInfo(@TypeOf(OroStore.put)).@"fn".return_type.?).error_union.error_set;
const StoreDeleteError = @typeInfo(@typeInfo(@TypeOf(OroStore.delete)).@"fn".return_type.?).error_union.error_set;
const Pbkdf2Error = @typeInfo(@typeInfo(@TypeOf(std.crypto.pwhash.pbkdf2)).@"fn".return_type.?).error_union.error_set;

pub const ServiceError = StorePutError || StoreDeleteError || Pbkdf2Error || error{
    NotFound,
    AuthFailed,
    Forbidden,
    AlreadyExists,
    InvalidName,
    InvalidChannel,
    InvalidRecord,
    InvalidPassword,
    InvalidValue,
    RandomUnavailable,
    BufferTooSmall,
};

comptime {
    if (@typeInfo(ServiceError).error_set == null) @compileError("ServiceError must remain concrete");
}

/// Optional integration hook for the daemon's SUIMYAKU state.
pub const StateHook = struct {
    ptr: *anyopaque,
    create_channel: *const fn (ctx: *anyopaque, channel: []const u8) ServiceError!void,
    /// Optional: invoked when a channel registration is dropped, so the live
    /// world can clear the +r REGISTERED flag and let the channel become
    /// ephemeral again. Null hooks simply skip this notification.
    drop_channel: ?*const fn (ctx: *anyopaque, channel: []const u8) ServiceError!void = null,

    pub fn createChannel(self: StateHook, channel: []const u8) ServiceError!void {
        try self.create_channel(self.ptr, channel);
    }

    pub fn dropChannel(self: StateHook, channel: []const u8) ServiceError!void {
        if (self.drop_channel) |cb| try cb(self.ptr, channel);
    }
};

pub fn InlineText(comptime max_len: usize) type {
    return struct {
        bytes: [max_len]u8 = [_]u8{0} ** max_len,
        len: u16 = 0,

        pub fn init(input: []const u8) error{StringTooLong}!@This() {
            if (input.len > max_len) return error.StringTooLong;
            var out = @This(){};
            if (input.len != 0) @memcpy(out.bytes[0..input.len], input);
            out.len = @intCast(input.len);
            return out;
        }

        pub fn empty() @This() {
            return .{};
        }

        pub fn asSlice(self: *const @This()) []const u8 {
            return self.bytes[0..self.len];
        }
    };
}

pub const AccountName = InlineText(account_max);
pub const ChannelName = InlineText(channel_max);
pub const NickName = InlineText(nick_max);
pub const Email = InlineText(email_max);
pub const Mlock = InlineText(mlock_max);
pub const Mask = InlineText(mask_max);
pub const Reason = InlineText(reason_max);

pub const AccessLevel = enum(u8) {
    voice = 10,
    op = 25,
    admin = 50,
    founder = 100,

    pub fn allows(self: AccessLevel, needed: AccessLevel) bool {
        return @intFromEnum(self) >= @intFromEnum(needed);
    }
};

pub const AccountSetField = union(enum) { email: []const u8, flags: u32, secure: bool, enforce: bool };
pub const ChannelSetField = union(enum) { flags: u32, mlock: []const u8 };
pub const AccessAction = enum { query, grant, revoke };
pub const AkickAction = enum { add, remove, query };
pub const AccountRef = struct { name: AccountName };
pub const ChannelRef = struct { name: ChannelName };

// ── Registered-channel boolean settings (CHANNEL SET) ───────────────────────
// Stored in the channel record's `flags` so they survive recreation. A fresh
// record has flags 0 (all off), which preserves the prior "unset" behavior.
/// TOPICLOCK: only channel ops / those with channel ACCESS may change the topic
/// (a registration-backed +t that holds even after the channel empties).
pub const channel_flag_topiclock: u32 = 1 << 0;
/// GUARD: keep the registered channel "open" — services hold it so its modes and
/// topic persist while empty (surfaced to the daemon to recreate/secure it).
pub const channel_flag_guard: u32 = 1 << 1;
/// PRIVATE: hide the channel from public listings (LIST / NAMES enumeration).
pub const channel_flag_private: u32 = 1 << 2;

pub const account_flag_suspended: u32 = 1 << 0;
pub const account_flag_forbidden: u32 = 1 << 1;
pub const account_flag_noexpire: u32 = 1 << 2;
/// Owner-settable nick-protection flags (NOT privileged). Stored so the bit
/// layout stays backward-compatible: a fresh/old account record has these 0,
/// which means "ENFORCE on, SECURE off" — exactly today's always-on behavior.
/// `enforce_off` is inverted (set = the owner opted OUT of auto-enforcement on
/// their registered nick) so default protection is preserved without a DB
/// format change. `secure` = recognize the account only via identify.
pub const account_flag_enforce_off: u32 = 1 << 3;
pub const account_flag_secure: u32 = 1 << 4;
pub const account_flags_privileged: u32 = account_flag_suspended | account_flag_forbidden | account_flag_noexpire;

pub const AccountInfo = struct {
    name: AccountName,
    email: Email = Email.empty(),
    email_verified: bool = false,
    flags: u32 = 0,
};

pub const AccountAdminInfo = struct {
    name: AccountName,
    email: Email = Email.empty(),
    email_verified: bool = false,
    flags: u32 = 0,
    registered: bool = false,

    pub fn suspended(self: AccountAdminInfo) bool {
        return (self.flags & account_flag_suspended) != 0;
    }

    pub fn forbidden(self: AccountAdminInfo) bool {
        return (self.flags & account_flag_forbidden) != 0;
    }

    pub fn noexpire(self: AccountAdminInfo) bool {
        return (self.flags & account_flag_noexpire) != 0;
    }
};

pub const ChannelInfo = struct {
    name: ChannelName,
    founder: AccountName,
    flags: u32 = 0,
    mlock: Mlock = Mlock.empty(),
};

pub const GhostInfo = struct {
    account: AccountName,
    nick: NickName,
};

pub const SessionTokenIssue = struct {
    account: AccountName,
    token: [session_token_len]u8,
    expires_unix: i64,

    pub fn tokenSlice(self: *const SessionTokenIssue) []const u8 {
        return self.token[0..];
    }
};

pub const AccessInfo = struct {
    channel: ChannelName,
    account: AccountName,
    level: AccessLevel,
};

pub const AkickInfo = struct {
    channel: ChannelName,
    mask: Mask,
    setter: AccountName,
    reason: Reason = Reason.empty(),
};

pub const EmailVerifyResult = enum {
    verified,
    expired,
    no_pending,
    bad_token,
};

pub const ReplayWard = struct {
    match: []const u8,
    pattern: []const u8,
    scope: []const u8,
    action: []const u8,
    reason: []const u8,
    setter: []const u8,
    created_ms: i64,
    expires_ms: i64,
};

/// Server-level IRCX ACCESS (SACCESS) entry as carried across the persistence
/// boundary. Fields borrow from caller-owned buffers / decoded WAL values.
pub const ReplaySaccess = struct {
    /// Entry-type token: DENY / GAG / GRANT / NOCHANNEL / NONICK.
    entry_type: []const u8,
    mask: []const u8,
    duration: u64 = 0,
    reason: []const u8 = "",
};

pub const LiveReplaySummary = struct {
    channels: usize = 0,
    mlocks: usize = 0,
    akicks: usize = 0,
    wards: usize = 0,
    saccesses: usize = 0,
};

pub const LiveReplaySink = struct {
    ptr: *anyopaque,
    channel: *const fn (ctx: *anyopaque, channel: []const u8, mlock: []const u8) ServiceError!void,
    akick: ?*const fn (ctx: *anyopaque, channel: []const u8, mask: []const u8, reason: []const u8, setter: []const u8) ServiceError!void = null,
    ward: ?*const fn (ctx: *anyopaque, ward: ReplayWard) ServiceError!void = null,
    saccess: ?*const fn (ctx: *anyopaque, entry: ReplaySaccess) ServiceError!void = null,
};

pub const CommandResult = union(enum) {
    registered_account: AccountRef,
    identified: AccountRef,
    dropped_account: AccountRef,
    ghosted: GhostInfo,
    set_account: AccountInfo,
    account_info: AccountInfo,
    registered_channel: ChannelInfo,
    dropped_channel: ChannelRef,
    channel_info: ChannelInfo,
    access: AccessInfo,
    access_revoked: AccessInfo,
    akick: AkickInfo,
    akick_removed: AkickInfo,
    set_channel: ChannelInfo,
};

const AccountRecord = struct {
    name: AccountName,
    salt: [salt_len]u8,
    hash: [hash_len]u8,
    email: Email = Email.empty(),
    email_verified: bool = false,
    flags: u32 = 0,

    fn info(self: AccountRecord) AccountInfo {
        return .{ .name = self.name, .email = self.email, .email_verified = self.email_verified, .flags = self.flags };
    }

    fn adminInfo(self: AccountRecord) AccountAdminInfo {
        return .{ .name = self.name, .email = self.email, .email_verified = self.email_verified, .flags = self.flags, .registered = true };
    }
};

const ChannelRecord = struct {
    name: ChannelName,
    founder: AccountName,
    generation: [generation_len]u8,
    flags: u32 = 0,
    mlock: Mlock = Mlock.empty(),

    fn info(self: ChannelRecord) ChannelInfo {
        return .{ .name = self.name, .founder = self.founder, .flags = self.flags, .mlock = self.mlock };
    }
};

const AccessRecord = struct {
    channel: ChannelName,
    account: AccountName,
    generation: [generation_len]u8,
    level: AccessLevel,

    fn info(self: AccessRecord) AccessInfo {
        return .{ .channel = self.channel, .account = self.account, .level = self.level };
    }
};

const AkickRecord = struct {
    channel: ChannelName,
    mask: Mask,
    generation: [generation_len]u8,
    setter: AccountName,
    reason: Reason = Reason.empty(),

    fn info(self: AkickRecord) AkickInfo {
        return .{ .channel = self.channel, .mask = self.mask, .setter = self.setter, .reason = self.reason };
    }
};

pub const Services = struct {
    store: *OroStore,
    state: ?StateHook = null,
    cfg: Config = .{},
    /// Optional SCRAM-SHA-256 credential mirror. When set, account registration
    /// additionally derives and stores `{salt, iters, StoredKey, ServerKey}` so
    /// the daemon can advertise and complete SCRAM-SHA-256. PLAIN remains the
    /// source of truth in the persistent account record; this is an in-memory
    /// companion (see scram_store.zig). Null leaves SCRAM unprovisioned, exactly
    /// matching the historical PLAIN-only behaviour.
    scram: ?*ScramStore = null,
    /// Optional account ⇄ TLS certfp bindings, backing SASL EXTERNAL (CERTADD).
    /// In-memory companion (see certfp_bind.zig); null = EXTERNAL has nothing to
    /// match and fails closed.
    certfp_binds: ?*certfp_bind_mod.CertfpBindStore = null,
    lock: rwlock.RwLock = .{},

    pub fn init(store: *OroStore, state: ?StateHook) Services {
        return .{ .store = store, .state = state };
    }

    pub fn initWithConfig(store: *OroStore, state: ?StateHook, cfg: Config) Services {
        return .{ .store = store, .state = state, .cfg = cfg };
    }

    /// Attach a SCRAM credential mirror. Accounts registered after this call
    /// gain SCRAM-SHA-256 material; the store must outlive `self`.
    pub fn attachScramStore(self: *Services, scram: *ScramStore) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        self.scram = scram;
    }

    /// Attach the account ⇄ certfp binding store (for SASL EXTERNAL / CERTADD).
    /// The store must outlive `self`.
    pub fn attachCertfpBinds(self: *Services, binds: *certfp_bind_mod.CertfpBindStore) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        self.certfp_binds = binds;
    }

    /// Bind a TLS certfp to an account (the CERTADD command). Caller has verified
    /// the account is the caller's own logged-in account.
    pub fn bindCertfp(self: *Services, account: []const u8, fingerprint: []const u8) certfp_bind_mod.CertfpBindError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const binds = self.certfp_binds orelse return error.InvalidFingerprint;
        try binds.bind(account, fingerprint);
        // Mirror the binding into the durable store, keyed by fingerprint, so it
        // survives a restart. In-memory is authoritative for this session; the
        // store is a best-effort durable mirror (a WAL hiccup must not fail the
        // already-applied in-memory bind).
        var kb: [certfp_key_max]u8 = undefined;
        if (certfpKey(&kb, fingerprint)) |k| {
            self.store.family(.props).put(k, account) catch {};
        }
        self.addCertfpListEntry(account, fingerprint) catch {};
    }

    /// List certfps bound to `account` by CERTADD. Output slices borrow durable
    /// store memory and remain valid until the next mutation.
    pub fn listCertfps(self: *Services, account: []const u8, out: [][]const u8) ServiceError![]const []const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const key = try accountKey(account);
        var kb: [certfp_account_key_max]u8 = undefined;
        const list_key = certfpAccountKey(&kb, key.asSlice()) orelse return error.BufferTooSmall;
        const value = self.store.family(.props).get(list_key) orelse return out[0..0];
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, value, '\n');
        while (it.next()) |fp| {
            if (fp.len == 0) continue;
            if (count >= out.len) return error.BufferTooSmall;
            out[count] = fp;
            count += 1;
        }
        return out[0..count];
    }

    /// Remove a certfp from `account`. Returns NotFound when the fingerprint is
    /// unbound, and Forbidden when another account owns it.
    pub fn deleteCertfp(self: *Services, account: []const u8, fingerprint: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try accountKey(account);
        const owner = try self.certfpOwnerUnlocked(fingerprint);
        if (!std.ascii.eqlIgnoreCase(owner, key.asSlice())) return error.Forbidden;

        if (self.certfp_binds) |binds| _ = binds.unbind(fingerprint);
        var fp_key_buf: [certfp_key_max]u8 = undefined;
        if (certfpKey(&fp_key_buf, fingerprint)) |fp_key| self.store.family(.props).delete(fp_key) catch {};
        try self.removeCertfpListEntry(key.asSlice(), fingerprint);
    }

    /// Mirror an account's derived SCRAM tuple into the durable store, keyed by
    /// account. Serializes BOTH the SHA-256 and (when provisioned) SHA-512
    /// material in a single backward-compatible record so a SCRAM-SHA-256 OR
    /// SCRAM-SHA-512 login resolves after a restart. Best-effort; the in-memory
    /// SCRAM store is authoritative live.
    fn persistScram(self: *Services, scram: *ScramStore, account: []const u8) void {
        const rec256 = scram.lookup(account) orelse return;
        var full = ScramStore.FullRecord{
            .salt = rec256.salt,
            .iterations = rec256.iterations,
            .stored_key = rec256.stored_key,
            .server_key = rec256.server_key,
        };
        if (scram.lookup512(account)) |rec512| {
            full.has_512 = true;
            full.stored_key_512 = rec512.stored_key;
            full.server_key_512 = rec512.server_key;
        }
        var vbuf: [ScramStore.serialized_max]u8 = undefined;
        const value = ScramStore.serializeFullRecord(full, &vbuf) orelse return;
        var kb: [scram_key_max]u8 = undefined;
        const key = scramKey(&kb, account) orelse return;
        self.store.family(.props).put(key, value) catch {};
    }

    /// A backfill loader for the SCRAM store that reads this services' durable
    /// mirror, so a SCRAM login resolves after a restart. The returned record's
    /// salt borrows store memory and is copied by the SCRAM store before caching.
    /// Carries SHA-512 material when the durable record includes it.
    pub fn scramLoader(self: *Services) ScramStore.Loader {
        return .{ .ptr = self, .loadFn = scramLoadThunk };
    }

    fn scramLoadThunk(ptr: *anyopaque, account: []const u8) ?ScramStore.FullRecord {
        const self: *Services = @ptrCast(@alignCast(ptr));
        var kb: [scram_key_max]u8 = undefined;
        const key = scramKey(&kb, account) orelse return null;
        const bytes = self.store.family(.props).get(key) orelse return null;
        return ScramStore.deserializeFullRecord(bytes);
    }

    /// The account a certfp is bound to, if any (SASL EXTERNAL verification).
    /// Falls back to the durable store when the in-memory cache is cold (e.g.
    /// immediately after a restart, before any CERTADD has repopulated it).
    pub fn accountForCertfp(self: *const Services, fingerprint: []const u8) ?[]const u8 {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        return @constCast(self).accountForCertfpUnlocked(fingerprint) catch null;
    }

    /// Issue a durable SASL SESSION-TOKEN for an already-authenticated services
    /// account. The raw token is returned once to the caller; only SHA-256(token)
    /// and expiry metadata are stored.
    pub fn issueSessionToken(self: *Services, account: []const u8, now_unix: i64) ServiceError!SessionTokenIssue {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try accountKey(account);
        const value = self.store.family(.accounts).get(key.asSlice()) orelse return error.NotFound;
        const record = try decodeAccount(value);
        if ((record.flags & account_flag_suspended) != 0 or (record.flags & account_flag_forbidden) != 0) return error.AuthFailed;

        var token: [session_token_len]u8 = undefined;
        @memcpy(token[0..session_token_prefix.len], session_token_prefix);
        var random: [session_token_random_len]u8 = undefined;
        self.store.io.randomSecure(&random) catch return error.RandomUnavailable;
        var random_hex = std.fmt.bytesToHex(random, .lower);
        @memcpy(token[session_token_prefix.len..], &random_hex);
        secureZero(random[0..]);
        secureZero(random_hex[0..]);

        var digest: [hash_len]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&token, &digest, .{});
        defer secureZero(digest[0..]);
        var hash_hex = std.fmt.bytesToHex(digest, .lower);
        defer secureZero(hash_hex[0..]);

        var acct_key_buf: [session_token_account_key_max]u8 = undefined;
        const acct_key = sessionTokenAccountKey(&acct_key_buf, key.asSlice()) orelse return error.BufferTooSmall;
        if (self.store.family(.props).get(acct_key)) |old_hash| {
            var old_token_key_buf: [session_token_key_max]u8 = undefined;
            if (old_hash.len == hash_hex_len) {
                if (sessionTokenKey(&old_token_key_buf, old_hash)) |old_token_key| {
                    self.store.family(.props).delete(old_token_key) catch {};
                }
            }
        }

        const expires_unix = now_unix + default_session_token_ttl_seconds;
        var value_buf: [session_token_value_max]u8 = undefined;
        const encoded = try encodeSessionTokenRecord(record.name.asSlice(), expires_unix, hash_hex[0..], &value_buf);
        var token_key_buf: [session_token_key_max]u8 = undefined;
        const token_key = sessionTokenKey(&token_key_buf, hash_hex[0..]) orelse return error.BufferTooSmall;
        try self.store.family(.props).put(token_key, encoded);
        try self.store.family(.props).put(acct_key, hash_hex[0..]);

        return .{
            .account = record.name,
            .token = token,
            .expires_unix = expires_unix,
        };
    }

    /// Validate SASL SESSION-TOKEN credentials. `authcid` must be the account
    /// name bound to the token, and `account_out` receives the canonical account
    /// on success. Returns null for malformed, expired, missing, suspended, or
    /// mismatched tokens.
    pub fn validateSessionToken(
        self: *Services,
        authcid: []const u8,
        token: []const u8,
        now_unix: i64,
        account_out: []u8,
    ) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const key = accountKey(authcid) catch return null;
        if (!validSessionTokenText(token)) return null;

        var digest: [hash_len]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});
        defer secureZero(digest[0..]);
        var hash_hex = std.fmt.bytesToHex(digest, .lower);
        defer secureZero(hash_hex[0..]);

        var token_key_buf: [session_token_key_max]u8 = undefined;
        const token_key = sessionTokenKey(&token_key_buf, hash_hex[0..]) orelse return null;
        const encoded = self.store.family(.props).get(token_key) orelse return null;
        const record = decodeSessionTokenRecord(encoded) catch return null;
        if (record.expires_unix <= now_unix) return null;
        if (!std.mem.eql(u8, record.account.asSlice(), key.asSlice())) return null;

        var stored_hash: [hash_hex_len]u8 = undefined;
        if (record.hash.len != stored_hash.len) return null;
        @memcpy(&stored_hash, record.hash);
        defer secureZero(stored_hash[0..]);
        const hash_ok = std.crypto.timing_safe.eql([hash_hex_len]u8, stored_hash, hash_hex);
        if (!hash_ok) return null;

        const acct_value = self.store.family(.accounts).get(key.asSlice()) orelse return null;
        const acct_record = decodeAccount(acct_value) catch return null;
        if ((acct_record.flags & account_flag_suspended) != 0 or (acct_record.flags & account_flag_forbidden) != 0) return null;
        if (acct_record.name.asSlice().len > account_out.len) return null;
        @memcpy(account_out[0..acct_record.name.asSlice().len], acct_record.name.asSlice());
        return account_out[0..acct_record.name.asSlice().len];
    }

    fn accountForCertfpUnlocked(self: *Services, fingerprint: []const u8) ServiceError![]const u8 {
        const acct = try self.certfpOwnerUnlocked(fingerprint);
        if (try self.accountSuspendedUnlocked(acct)) return error.AuthFailed;
        return acct;
    }

    fn certfpOwnerUnlocked(self: *Services, fingerprint: []const u8) ServiceError![]const u8 {
        if (self.certfp_binds) |binds| {
            if (binds.accountForFingerprint(fingerprint)) |acct| return acct;
        }
        var kb: [certfp_key_max]u8 = undefined;
        const k = certfpKey(&kb, fingerprint) orelse return error.NotFound;
        return self.store.family(.props).get(k) orelse error.NotFound;
    }

    pub fn registerAccount(self: *Services, name: []const u8, password: []const u8, scratch: []u8) ServiceError!CommandResult {
        return self.registerAccountWithEmail(name, password, null, false, scratch);
    }

    pub fn registerAccountWithEmail(
        self: *Services,
        name: []const u8,
        password: []const u8,
        email: ?[]const u8,
        email_verified: bool,
        scratch: []u8,
    ) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try accountKey(name);
        if (self.accountForbiddenUnlocked(key.asSlice())) return error.Forbidden;
        if (self.store.family(.accounts).get(key.asSlice()) != null) return error.AlreadyExists;
        try validatePassword(password);

        var salt: [salt_len]u8 = undefined;
        self.store.io.randomSecure(&salt) catch self.store.io.random(&salt);

        var hash: [hash_len]u8 = undefined;
        try hashPassword(&hash, password, &salt, self.cfg.pbkdf2_rounds);

        const record = AccountRecord{
            .name = AccountName.init(key.asSlice()) catch return error.InvalidName,
            .salt = salt,
            .hash = hash,
            .email = if (email) |value| try validateEmail(value) else Email.empty(),
            .email_verified = email_verified and email != null,
        };
        const encoded = try encodeAccount(record, scratch);
        try self.store.family(.accounts).put(key.asSlice(), encoded);

        // Mirror the credential into the SCRAM store, if attached, so a
        // SCRAM-SHA-256 exchange can later verify this account. The canonical
        // (lowercased) name is used so SCRAM lookups match the account key. The
        // PLAIN record above is already persisted and authoritative; a SCRAM
        // mirror failure must not roll that back, so failures map to
        // error.InvalidRecord rather than leaving a half-registered account.
        if (self.scram) |scram| {
            scram.deriveAndStore(record.name.asSlice(), password) catch return error.InvalidRecord;
            // Persist the derived SCRAM tuple so a SCRAM-SHA-256 login still works
            // after a restart (the in-memory store is otherwise re-seeded only on
            // a fresh register/identify). Best-effort: a mirror failure must not
            // roll back the already-persisted PLAIN account record.
            self.persistScram(scram, record.name.asSlice());
        }
        return .{ .registered_account = .{ .name = record.name } };
    }

    pub fn setAccountEmailPending(
        self: *Services,
        name: []const u8,
        email: []const u8,
        token: []const u8,
        issued_ms: u64,
        scratch: []u8,
    ) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadAccount(name);
        record.email = try validateEmail(email);
        record.email_verified = false;
        try self.saveAccount(record, scratch);

        var key_buf: [verify_key_max]u8 = undefined;
        const key = verifyKey(&key_buf, record.name.asSlice()) orelse return error.BufferTooSmall;
        var value_buf: [verify_value_max]u8 = undefined;
        const value = try encodeVerify(record.name.asSlice(), record.email.asSlice(), token, issued_ms, &value_buf);
        try self.store.family(.props).put(key, value);
    }

    pub fn confirmAccountEmail(
        self: *Services,
        name: []const u8,
        token: []const u8,
        now_ms: u64,
        scratch: []u8,
    ) ServiceError!EmailVerifyResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try accountKey(name);
        var verify_key_buf: [verify_key_max]u8 = undefined;
        const verify_key_text = verifyKey(&verify_key_buf, key.asSlice()) orelse return error.BufferTooSmall;
        const encoded = self.store.family(.props).get(verify_key_text) orelse return .no_pending;
        const pending = try decodeVerify(encoded);
        if (!std.ascii.eqlIgnoreCase(pending.account, key.asSlice())) return .no_pending;
        if (now_ms >= pending.issued_ms and now_ms - pending.issued_ms >= default_verify_ttl_ms) {
            try self.store.family(.props).delete(verify_key_text);
            return .expired;
        }
        if (!tokenMatches(pending.token, token)) return .bad_token;

        var record = try self.loadAccount(key.asSlice());
        record.email = try validateEmail(pending.email);
        record.email_verified = true;
        try self.saveAccount(record, scratch);
        try self.store.family(.props).delete(verify_key_text);
        return .verified;
    }

    pub fn identifyAccount(self: *Services, name: []const u8, password: []const u8) ServiceError!CommandResult {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const key = try accountKey(name);
        const value = self.store.family(.accounts).get(key.asSlice()) orelse {
            try rejectMissingAccount(password, self.cfg.pbkdf2_rounds);
            return error.AuthFailed;
        };
        const record = try decodeAccount(value);
        try verifyPassword(record, password, self.cfg.pbkdf2_rounds);
        if ((record.flags & account_flag_suspended) != 0) return error.AuthFailed;
        return .{ .identified = .{ .name = record.name } };
    }

    pub fn dropAccount(self: *Services, name: []const u8, password: []const u8) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const record = try self.loadAccount(name);
        try verifyPassword(record, password, self.cfg.pbkdf2_rounds);
        try self.store.family(.accounts).delete(record.name.asSlice());
        return .{ .dropped_account = .{ .name = record.name } };
    }

    /// Change an account's password after verifying the presented current one.
    /// Errors: AuthFailed (wrong current password), InvalidPassword (new fails the
    /// length policy or equals the current one). On success the new salt/hash are
    /// persisted and the SCRAM mirror (if any) is re-derived so SCRAM logins track
    /// the new password. All other account fields are preserved.
    pub fn changeAccountPassword(
        self: *Services,
        name: []const u8,
        old_password: []const u8,
        new_password: []const u8,
        scratch: []u8,
    ) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadAccount(name);
        try verifyPassword(record, old_password, self.cfg.pbkdf2_rounds);
        try validatePassword(new_password);
        // A change must actually change the password.
        if (std.mem.eql(u8, old_password, new_password)) return error.InvalidPassword;

        var salt: [salt_len]u8 = undefined;
        self.store.io.randomSecure(&salt) catch self.store.io.random(&salt);
        var hash: [hash_len]u8 = undefined;
        try hashPassword(&hash, new_password, &salt, self.cfg.pbkdf2_rounds);
        record.salt = salt;
        record.hash = hash;

        const encoded = try encodeAccount(record, scratch);
        try self.store.family(.accounts).put(record.name.asSlice(), encoded);

        // Re-derive the SCRAM credential so a SCRAM-SHA-256 login uses the new
        // password; a mirror failure must not roll back the persisted change.
        if (self.scram) |scram| {
            scram.deriveAndStore(record.name.asSlice(), new_password) catch return error.InvalidRecord;
            self.persistScram(scram, record.name.asSlice());
        }
    }

    pub fn ghostAccount(self: *Services, name: []const u8, password: []const u8, nick: []const u8) ServiceError!CommandResult {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadAccount(name);
        try verifyPassword(record, password, self.cfg.pbkdf2_rounds);
        const clean_nick = try validateNick(nick);
        return .{ .ghosted = .{ .account = record.name, .nick = clean_nick } };
    }

    pub fn setAccount(
        self: *Services,
        name: []const u8,
        password: []const u8,
        field: AccountSetField,
        scratch: []u8,
    ) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadAccount(name);
        try verifyPassword(record, password, self.cfg.pbkdf2_rounds);
        switch (field) {
            .email => |email| {
                record.email = try validateEmail(email);
                record.email_verified = false;
            },
            .flags => |flags| {
                const preserved = record.flags & account_flags_privileged;
                if ((flags & account_flags_privileged) != preserved) return error.Forbidden;
                record.flags = preserved | (flags & ~account_flags_privileged);
            },
            // SECURE on/off. ENFORCE on/off is stored inverted (`enforce_off`) so
            // the default-0 record keeps today's always-on enforcement.
            .secure => |on| setFlag(&record.flags, account_flag_secure, on),
            .enforce => |on| setFlag(&record.flags, account_flag_enforce_off, !on),
        }
        const encoded = try encodeAccount(record, scratch);
        try self.store.family(.accounts).put(record.name.asSlice(), encoded);
        return .{ .set_account = record.info() };
    }

    pub fn accountInfo(self: *Services, name: []const u8) ServiceError!CommandResult {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadAccount(name);
        return .{ .account_info = record.info() };
    }

    /// Server-side (no password) read of an account's nick-protection settings,
    /// for the registration sweep. An unknown account yields the protective
    /// default (ENFORCE on, SECURE off). ENFORCETIME is the configured grace,
    /// supplied by the caller as `enforce_seconds` since it is not per-account.
    pub fn accountSecurity(self: *Services, name: []const u8, enforce_seconds: u32) svc_enforce.AccountSecurity {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const key = accountKey(name) catch return .{ .enforce = true, .enforce_seconds = enforce_seconds };
        const value = self.store.family(.accounts).get(key.asSlice()) orelse
            return .{ .enforce = true, .enforce_seconds = enforce_seconds };
        const record = decodeAccount(value) catch
            return .{ .enforce = true, .enforce_seconds = enforce_seconds };
        return .{
            .secure = (record.flags & account_flag_secure) != 0,
            .enforce = (record.flags & account_flag_enforce_off) == 0,
            .enforce_seconds = enforce_seconds,
        };
    }

    pub fn setAccountSuspended(self: *Services, name: []const u8, suspended: bool, scratch: []u8) ServiceError!AccountAdminInfo {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadAccount(name);
        setFlag(&record.flags, account_flag_suspended, suspended);
        try self.saveAccount(record, scratch);
        return record.adminInfo();
    }

    pub fn setAccountNoExpire(self: *Services, name: []const u8, noexpire: bool, scratch: []u8) ServiceError!AccountAdminInfo {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadAccount(name);
        setFlag(&record.flags, account_flag_noexpire, noexpire);
        try self.saveAccount(record, scratch);
        return record.adminInfo();
    }

    /// Reserve or unreserve an account name. Registered accounts record the
    /// forbidden bit in their account record; unregistered names use a durable
    /// props-family reservation so REGISTER can reject the name later.
    pub fn setAccountForbidden(self: *Services, name: []const u8, forbidden: bool, scratch: []u8) ServiceError!AccountAdminInfo {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try accountKey(name);
        var kb: [forbidden_account_key_max]u8 = undefined;
        const reservation_key = forbiddenAccountKey(&kb, key.asSlice()) orelse return error.BufferTooSmall;

        if (self.store.family(.accounts).get(key.asSlice())) |value| {
            var record = try decodeAccount(value);
            setFlag(&record.flags, account_flag_forbidden, forbidden);
            try self.saveAccount(record, scratch);
            if (forbidden) {
                try self.store.family(.props).put(reservation_key, "1");
            } else {
                try self.store.family(.props).delete(reservation_key);
            }
            return record.adminInfo();
        }

        if (forbidden) {
            try self.store.family(.props).put(reservation_key, "1");
            return .{ .name = key, .flags = account_flag_forbidden, .registered = false };
        }
        if (self.store.family(.props).get(reservation_key) == null) return error.NotFound;
        try self.store.family(.props).delete(reservation_key);
        return .{ .name = key, .registered = false };
    }

    pub fn adminAccountInfo(self: *Services, name: []const u8) ServiceError!AccountAdminInfo {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const key = try accountKey(name);
        if (self.store.family(.accounts).get(key.asSlice())) |value| {
            return (try decodeAccount(value)).adminInfo();
        }
        if (self.accountForbiddenUnlocked(key.asSlice())) {
            return .{ .name = key, .flags = account_flag_forbidden, .registered = false };
        }
        return error.NotFound;
    }

    pub fn registerChannel(self: *Services, channel: []const u8, founder: []const u8, scratch: []u8) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const channel_key = try channelKey(channel);
        if (self.store.family(.chanregs).get(channel_key.asSlice()) != null) return error.AlreadyExists;
        const founder_key = try accountKey(founder);
        if (self.store.family(.accounts).get(founder_key.asSlice()) == null) return error.NotFound;

        var generation: [generation_len]u8 = undefined;
        self.store.io.randomSecure(&generation) catch self.store.io.random(&generation);

        const record = ChannelRecord{
            .name = ChannelName.init(channel_key.asSlice()) catch return error.InvalidChannel,
            .founder = AccountName.init(founder_key.asSlice()) catch return error.InvalidName,
            .generation = generation,
        };
        const encoded = try encodeChannel(record, scratch);
        try self.store.family(.chanregs).put(record.name.asSlice(), encoded);
        _ = try self.putAccess(record, record.founder, .founder, scratch);

        if (self.state) |hook| try hook.createChannel(record.name.asSlice());

        return .{ .registered_channel = record.info() };
    }

    pub fn dropChannel(self: *Services, channel: []const u8, actor: []const u8) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .founder);
        try self.store.family(.chanregs).delete(record.name.asSlice());
        if (self.state) |hook| try hook.dropChannel(record.name.asSlice());
        return .{ .dropped_channel = .{ .name = record.name } };
    }

    /// Transfer founder ownership of a registered channel. Only the CURRENT founder
    /// may transfer; the new founder must be a registered account. The new founder
    /// also receives an explicit FOUNDER access grant.
    pub fn transferChannel(self: *Services, channel: []const u8, actor: []const u8, new_founder: []const u8, scratch: []u8) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadChannel(channel);
        const actor_key = try accountKey(actor);
        if (!std.ascii.eqlIgnoreCase(record.founder.asSlice(), actor_key.asSlice())) return error.Forbidden;
        const nf_key = try accountKey(new_founder);
        if (self.store.family(.accounts).get(nf_key.asSlice()) == null) return error.NotFound;

        record.founder = nf_key;
        const encoded = try encodeChannel(record, scratch);
        try self.store.family(.chanregs).put(record.name.asSlice(), encoded);
        _ = try self.putAccess(record, record.founder, .founder, scratch);
        return .{ .registered_channel = record.info() };
    }

    pub fn channelAccess(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        target: []const u8,
        action: AccessAction,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!CommandResult {
        switch (action) {
            .query => {
                self.lock.lockShared();
                defer self.lock.unlockShared();
                return self.channelAccessUnlocked(channel, actor, target, action, level, scratch);
            },
            .grant, .revoke => {
                self.lock.lockExclusive();
                defer self.lock.unlockExclusive();
                return self.channelAccessUnlocked(channel, actor, target, action, level, scratch);
            },
        }
    }

    pub fn channelAccessList(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        out: []AccessInfo,
    ) ServiceError![]AccessInfo {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .admin);
        var prefix_buf: [key_max]u8 = undefined;
        const prefix = try prefixedKey(access_prefix, record.name.asSlice(), "", &prefix_buf);
        var count: usize = 0;
        var it = self.store.maps[@intFromEnum(channel_access_family)].map.iterator();
        while (it.next()) |entry| {
            if (!std.mem.startsWith(u8, entry.key_ptr.*, prefix)) continue;
            const access = try decodeAccess(entry.value_ptr.*);
            if (!sameBytes(generation_len, &access.generation, &record.generation)) continue;
            if (count >= out.len) return error.BufferTooSmall;
            out[count] = access.info();
            count += 1;
        }
        return out[0..count];
    }

    fn channelAccessUnlocked(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        target: []const u8,
        action: AccessAction,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!CommandResult {
        const record = try self.loadChannel(channel);
        const target_key = try accountKey(target);
        if (self.store.family(.accounts).get(target_key.asSlice()) == null) return error.NotFound;

        switch (action) {
            .query => {
                const access = try self.loadAccess(record, target_key.asSlice());
                return .{ .access = access.info() };
            },
            .grant => {
                try self.requireAccess(record, actor, .admin);
                if (level == .founder) try self.requireAccess(record, actor, .founder);
                const access = try self.putAccess(record, AccountName.init(target_key.asSlice()) catch return error.InvalidName, level, scratch);
                return .{ .access = access.info() };
            },
            .revoke => {
                try self.requireAccess(record, actor, .admin);
                if (std.mem.eql(u8, target_key.asSlice(), record.founder.asSlice())) return error.Forbidden;
                const existing = try self.loadAccess(record, target_key.asSlice());
                var key_buf: [key_max]u8 = undefined;
                const key = try accessKey(record.name.asSlice(), target_key.asSlice(), &key_buf);
                try self.store.delete(channel_access_family, key);
                return .{ .access_revoked = existing.info() };
            },
        }
    }

    pub fn channelAkick(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        mask: []const u8,
        action: AkickAction,
        reason: []const u8,
        scratch: []u8,
    ) ServiceError!CommandResult {
        switch (action) {
            .query => {
                self.lock.lockShared();
                defer self.lock.unlockShared();
                return self.channelAkickUnlocked(channel, actor, mask, action, reason, scratch);
            },
            .add, .remove => {
                self.lock.lockExclusive();
                defer self.lock.unlockExclusive();
                return self.channelAkickUnlocked(channel, actor, mask, action, reason, scratch);
            },
        }
    }

    pub fn channelAkickList(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        out: []AkickInfo,
    ) ServiceError![]AkickInfo {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .admin);
        var prefix_buf: [key_max]u8 = undefined;
        const prefix = try prefixedKey(akick_prefix, record.name.asSlice(), "", &prefix_buf);
        var count: usize = 0;
        var it = self.store.maps[@intFromEnum(channel_access_family)].map.iterator();
        while (it.next()) |entry| {
            if (!std.mem.startsWith(u8, entry.key_ptr.*, prefix)) continue;
            const akick = try decodeAkick(entry.value_ptr.*);
            if (!sameBytes(generation_len, &akick.generation, &record.generation)) continue;
            if (count >= out.len) return error.BufferTooSmall;
            out[count] = akick.info();
            count += 1;
        }
        return out[0..count];
    }

    fn channelAkickUnlocked(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        mask: []const u8,
        action: AkickAction,
        reason: []const u8,
        scratch: []u8,
    ) ServiceError!CommandResult {
        const record = try self.loadChannel(channel);
        const clean_mask = try validateMask(mask);
        switch (action) {
            .query => {
                const akick = try self.loadAkick(record, clean_mask.asSlice());
                return .{ .akick = akick.info() };
            },
            .add => {
                try self.requireAccess(record, actor, .admin);
                const actor_key = try accountKey(actor);
                const akick = AkickRecord{
                    .channel = record.name,
                    .mask = clean_mask,
                    .generation = record.generation,
                    .setter = AccountName.init(actor_key.asSlice()) catch return error.InvalidName,
                    .reason = try validateReason(reason),
                };
                const encoded = try encodeAkick(akick, scratch);
                var key_buf: [key_max]u8 = undefined;
                const key = try akickKey(record.name.asSlice(), clean_mask.asSlice(), &key_buf);
                try self.store.put(channel_access_family, key, encoded);
                return .{ .akick = akick.info() };
            },
            .remove => {
                try self.requireAccess(record, actor, .admin);
                const existing = try self.loadAkick(record, clean_mask.asSlice());
                var key_buf: [key_max]u8 = undefined;
                const key = try akickKey(record.name.asSlice(), clean_mask.asSlice(), &key_buf);
                try self.store.delete(channel_access_family, key);
                return .{ .akick_removed = existing.info() };
            },
        }
    }

    pub fn setChannel(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        field: ChannelSetField,
        scratch: []u8,
    ) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .admin);
        switch (field) {
            .flags => |flags| record.flags = flags,
            .mlock => |spec| record.mlock = try validateMlock(spec),
        }
        const encoded = try encodeChannel(record, scratch);
        try self.store.family(.chanregs).put(record.name.asSlice(), encoded);
        return .{ .set_channel = record.info() };
    }

    /// Set or clear a single registered-channel boolean flag bit (TOPICLOCK /
    /// GUARD / PRIVATE) while preserving the others. Requires founder-or-admin
    /// ACCESS on the channel. Persists the record so the flag survives recreation.
    pub fn setChannelFlag(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        flag: u32,
        on: bool,
        scratch: []u8,
    ) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .admin);
        if (on) {
            record.flags |= flag;
        } else {
            record.flags &= ~flag;
        }
        const encoded = try encodeChannel(record, scratch);
        try self.store.family(.chanregs).put(record.name.asSlice(), encoded);
    }

    /// True when `flag` is set on `channel`'s registration record. False for an
    /// unregistered channel (read-only, no lock contention on the live path).
    pub fn channelFlagSet(self: *Services, channel: []const u8, flag: u32) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const record = self.loadChannel(channel) catch return false;
        return (record.flags & flag) != 0;
    }

    pub fn channelInfo(self: *Services, channel: []const u8) ServiceError!CommandResult {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadChannel(channel);
        return .{ .channel_info = record.info() };
    }

    pub fn channelAccessLevelFor(self: *Services, channel: []const u8, account: []const u8) ServiceError!?AccessLevel {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadChannel(channel);
        const key = try accountKey(account);
        if (std.mem.eql(u8, key.asSlice(), record.founder.asSlice())) return .founder;
        const access = self.loadAccess(record, key.asSlice()) catch |err| switch (err) {
            error.NotFound => return null,
            else => return err,
        };
        return access.level;
    }

    pub fn persistWard(self: *Services, ward: ReplayWard, scratch: []u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try wardKey(ward.match, ward.pattern, scratch);
        var value_buf: [ward_value_max]u8 = undefined;
        const value = try encodeWard(ward, &value_buf);
        try self.store.family(.bans).put(key, value);
    }

    pub fn deleteWard(self: *Services, match: []const u8, pattern: []const u8, scratch: []u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try wardKey(match, pattern, scratch);
        try self.store.family(.bans).delete(key);
    }

    /// Persist (add or replace) one server-level IRCX ACCESS / SACCESS entry so
    /// it survives restart and hot-rebuild. Mirrors `persistWard`: keyed by
    /// `saccess:<type>:<mask>` in the durable `bans` family. Idempotent — a
    /// re-add of the same type+mask overwrites the prior value.
    pub fn persistSaccess(self: *Services, entry: ReplaySaccess, scratch: []u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try saccessKey(entry.entry_type, entry.mask, scratch);
        var value_buf: [saccess_value_max]u8 = undefined;
        const value = try encodeSaccess(entry, &value_buf);
        try self.store.family(.bans).put(key, value);
    }

    /// Remove one persisted SACCESS entry by type+mask. Restart-safe: a delete
    /// that mutated the live store is durably reflected.
    pub fn deleteSaccess(self: *Services, entry_type: []const u8, mask: []const u8, scratch: []u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try saccessKey(entry_type, mask, scratch);
        try self.store.family(.bans).delete(key);
    }

    /// Remove all persisted SACCESS entries (optionally one type). Mirrors the
    /// live `ServerAccessStore.clear` so a CLEAR is durable across restart.
    ///
    /// Keys are snapshotted into a caller-owned buffer BEFORE any delete: the
    /// store frees the map-owned key on delete, so deleting straight from a
    /// borrowed iterator key would be a use-after-free (the WAL/changefeed
    /// re-reads the key after the map entry is freed).
    pub fn clearSaccess(self: *Services, entry_type: ?[]const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var key_store: [256][saccess_key_max]u8 = undefined;
        var key_lens: [256]usize = undefined;
        var keys_len: usize = 0;
        {
            var it = self.store.maps[@intFromEnum(store_mod.Family.bans)].map.iterator();
            while (it.next()) |entry| {
                const key = entry.key_ptr.*;
                if (!std.mem.startsWith(u8, key, saccess_prefix)) continue;
                if (entry_type) |want| {
                    const decoded = decodeSaccess(entry.value_ptr.*) catch continue;
                    if (!std.ascii.eqlIgnoreCase(decoded.entry_type, want)) continue;
                }
                if (keys_len >= key_store.len or key.len > saccess_key_max) continue;
                @memcpy(key_store[keys_len][0..key.len], key);
                key_lens[keys_len] = key.len;
                keys_len += 1;
            }
        }
        for (0..keys_len) |idx| {
            self.store.family(.bans).delete(key_store[idx][0..key_lens[idx]]) catch {};
        }
    }

    // ── Account recognition masks (svc_acclist feature; RECOGNIZE command) ───────
    // Per-account hostmask list. Stored as ONE newline-joined value in the `.props`
    // family — durable, restart-safe, and isolated from account/channel records
    // (so it can never corrupt them). Matching uses `svc_acclist.globMatch`.
    const recognize_prefix = "rcg\x00";
    const recognize_max_masks: usize = svc_acclist.default_max_masks;
    const recognize_mask_max: usize = 128;
    const recognize_key_max: usize = recognize_prefix.len + account_max;
    const recognize_value_max: usize = recognize_max_masks * (recognize_mask_max + 1);

    pub const RecognizeAdd = enum { added, already_present, list_full, invalid_mask };

    fn recognizeKey(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < recognize_prefix.len + account.len) return null;
        @memcpy(buf[0..recognize_prefix.len], recognize_prefix);
        for (account, 0..) |c, i| buf[recognize_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. recognize_prefix.len + account.len];
    }

    fn validRecognizeMask(mask: []const u8) bool {
        if (mask.len == 0 or mask.len > recognize_mask_max) return false;
        for (mask) |c| {
            if (c < 0x20 or c == '\n' or c == 0) return false;
        }
        return true;
    }

    /// True if `hostmask` (nick!user@host) matches any recognition mask owned by
    /// `account`. Reads the durable mirror, so it is correct immediately after a
    /// restart with no in-memory warm-up.
    pub fn recognizeMatches(self: *Services, account: []const u8, hostmask: []const u8) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [recognize_key_max]u8 = undefined;
        const key = recognizeKey(&kb, account) orelse return false;
        const blob = self.store.family(.props).get(key) orelse return false;
        var it = std.mem.splitScalar(u8, blob, '\n');
        while (it.next()) |mask| {
            if (mask.len != 0 and svc_acclist.globMatch(mask, hostmask)) return true;
        }
        return false;
    }

    /// Copy the newline-joined recognition mask blob for `account` into `out`,
    /// returning the populated slice ("" when none). Used by RECOGNIZE LIST.
    pub fn recognizeBlob(self: *Services, account: []const u8, out: []u8) []const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [recognize_key_max]u8 = undefined;
        const key = recognizeKey(&kb, account) orelse return out[0..0];
        const blob = self.store.family(.props).get(key) orelse return out[0..0];
        const n = @min(blob.len, out.len);
        @memcpy(out[0..n], blob[0..n]);
        return out[0..n];
    }

    /// Add `mask` to `account`'s recognition list (durable). Idempotent; bounded
    /// by `recognize_max_masks`.
    pub fn recognizeAdd(self: *Services, account: []const u8, mask: []const u8) ServiceError!RecognizeAdd {
        if (!validRecognizeMask(mask)) return .invalid_mask;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [recognize_key_max]u8 = undefined;
        const key = recognizeKey(&kb, account) orelse return .invalid_mask;
        const existing = self.store.family(.props).get(key) orelse "";
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |m| {
            if (m.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(m, mask)) return .already_present;
            count += 1;
        }
        if (count >= recognize_max_masks) return .list_full;
        var vbuf: [recognize_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vbuf);
        if (existing.len != 0) {
            w.writeAll(existing) catch return .list_full;
            w.writeAll("\n") catch return .list_full;
        }
        w.writeAll(mask) catch return .list_full;
        try self.store.family(.props).put(key, w.buffered());
        return .added;
    }

    /// Remove `mask` from `account`'s recognition list (durable). Returns whether
    /// a mask was actually removed.
    pub fn recognizeDel(self: *Services, account: []const u8, mask: []const u8) ServiceError!bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [recognize_key_max]u8 = undefined;
        const key = recognizeKey(&kb, account) orelse return false;
        const existing = self.store.family(.props).get(key) orelse return false;
        var vbuf: [recognize_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vbuf);
        var found = false;
        var remaining: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |m| {
            if (m.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(m, mask)) {
                found = true;
                continue;
            }
            if (remaining != 0) w.writeAll("\n") catch return found;
            w.writeAll(m) catch return found;
            remaining += 1;
        }
        if (!found) return false;
        if (remaining == 0) {
            try self.store.family(.props).delete(key);
        } else {
            try self.store.family(.props).put(key, w.buffered());
        }
        return true;
    }

    // ── Durable account-scoped IRCv3 METADATA (web-client profiles) ─────────────
    // The live metadata store (server.metadata) is in-memory; these helpers mirror
    // a logged-in user's OWN metadata into the durable `.props` family keyed by
    // ACCOUNT, so a profile (avatar/display-name/…) survives a cold restart and is
    // restored into the live store on next login. Value = "<vis-token>\x00<value>".
    // Isolated key namespace ("mda\x00…") — never touches account/channel records.
    const metadata_prefix = "mda\x00";
    const metadata_key_max = 64;
    const metadata_value_max = 512;
    const metadata_full_key_max = metadata_prefix.len + account_max + 1 + metadata_key_max;

    fn metadataAccountPrefix(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < metadata_prefix.len + account.len + 1) return null;
        @memcpy(buf[0..metadata_prefix.len], metadata_prefix);
        for (account, 0..) |c, i| buf[metadata_prefix.len + i] = std.ascii.toLower(c);
        buf[metadata_prefix.len + account.len] = 0;
        return buf[0 .. metadata_prefix.len + account.len + 1];
    }

    fn metadataKey(buf: []u8, account: []const u8, key: []const u8) ?[]const u8 {
        if (key.len == 0 or key.len > metadata_key_max) return null;
        var pb: [metadata_full_key_max]u8 = undefined;
        const prefix = metadataAccountPrefix(&pb, account) orelse return null;
        if (buf.len < prefix.len + key.len) return null;
        @memcpy(buf[0..prefix.len], prefix);
        @memcpy(buf[prefix.len .. prefix.len + key.len], key);
        return buf[0 .. prefix.len + key.len];
    }

    pub fn metadataPut(self: *Services, account: []const u8, key: []const u8, value: []const u8, vis_token: []const u8) ServiceError!void {
        if (value.len > metadata_value_max or vis_token.len == 0 or vis_token.len > 16) return;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [metadata_full_key_max]u8 = undefined;
        const k = metadataKey(&kb, account, key) orelse return;
        var vb: [metadata_value_max + 24]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        w.writeAll(vis_token) catch return;
        w.writeAll("\x00") catch return;
        w.writeAll(value) catch return;
        try self.store.family(.props).put(k, w.buffered());
    }

    pub fn metadataDelete(self: *Services, account: []const u8, key: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [metadata_full_key_max]u8 = undefined;
        const k = metadataKey(&kb, account, key) orelse return;
        try self.store.family(.props).delete(k);
    }

    /// Invoke `cb(ctx, key, value, vis_token)` for every durable metadata entry
    /// owned by `account`. Used to restore a user's profile metadata at login.
    pub fn metadataForEach(self: *Services, account: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8, []const u8, []const u8) void) void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var pb: [metadata_full_key_max]u8 = undefined;
        const prefix = metadataAccountPrefix(&pb, account) orelse return;
        var it = self.store.maps[@intFromEnum(store_mod.Family.props)].map.iterator();
        while (it.next()) |entry| {
            const k = entry.key_ptr.*;
            if (!std.mem.startsWith(u8, k, prefix)) continue;
            const blob = entry.value_ptr.*;
            const sep = std.mem.indexOfScalar(u8, blob, 0) orelse continue;
            cb(ctx, k[prefix.len..], blob[sep + 1 ..], blob[0..sep]);
        }
    }

    // ── Durable account-scoped SILENCE (ignore list survives reconnect/restart) ──
    // One newline-joined blob per account in `.props` ("sil\x00<account>"). The live
    // per-nick `server.silence` store is restored from this at login.
    const silence_prefix = "sil\x00";
    const silence_max_masks: usize = 64;
    const silence_mask_max: usize = 128;
    const silence_key_max: usize = silence_prefix.len + account_max;
    const silence_value_max: usize = silence_max_masks * (silence_mask_max + 1);

    fn silenceKey(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < silence_prefix.len + account.len) return null;
        @memcpy(buf[0..silence_prefix.len], silence_prefix);
        for (account, 0..) |c, i| buf[silence_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. silence_prefix.len + account.len];
    }

    pub fn silencePersistAdd(self: *Services, account: []const u8, mask: []const u8) ServiceError!void {
        if (mask.len == 0 or mask.len > silence_mask_max) return;
        for (mask) |c| if (c < 0x20 or c == '\n' or c == 0) return;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [silence_key_max]u8 = undefined;
        const k = silenceKey(&kb, account) orelse return;
        const existing = self.store.family(.props).get(k) orelse "";
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |m| {
            if (m.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(m, mask)) return;
            count += 1;
        }
        if (count >= silence_max_masks) return;
        var vb: [silence_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        if (existing.len != 0) {
            w.writeAll(existing) catch return;
            w.writeAll("\n") catch return;
        }
        w.writeAll(mask) catch return;
        try self.store.family(.props).put(k, w.buffered());
    }

    pub fn silencePersistDel(self: *Services, account: []const u8, mask: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [silence_key_max]u8 = undefined;
        const k = silenceKey(&kb, account) orelse return;
        const existing = self.store.family(.props).get(k) orelse return;
        var vb: [silence_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        var remaining: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |m| {
            if (m.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(m, mask)) continue;
            if (remaining != 0) w.writeAll("\n") catch return;
            w.writeAll(m) catch return;
            remaining += 1;
        }
        if (remaining == 0) {
            try self.store.family(.props).delete(k);
        } else {
            try self.store.family(.props).put(k, w.buffered());
        }
    }

    /// Invoke `cb(ctx, mask)` for each persisted SILENCE mask owned by `account`.
    pub fn silenceForEach(self: *Services, account: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8) void) void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [silence_key_max]u8 = undefined;
        const k = silenceKey(&kb, account) orelse return;
        const blob = self.store.family(.props).get(k) orelse return;
        var it = std.mem.splitScalar(u8, blob, '\n');
        while (it.next()) |m| {
            if (m.len != 0) cb(ctx, m);
        }
    }

    /// Invoke `cb(ctx, channel, level)` for every channel where `account` holds a
    /// live access grant — the durable reverse of `channelAccessList`, backing
    /// LISTCHANS. Stale grants (channel dropped, or dropped+re-registered) are
    /// skipped by re-checking the channel's current generation.
    pub fn channelsForAccount(self: *Services, account: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8, AccessLevel) void) void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var it = self.store.maps[@intFromEnum(channel_access_family)].map.iterator();
        while (it.next()) |entry| {
            if (!std.mem.startsWith(u8, entry.key_ptr.*, access_prefix)) continue;
            const access = decodeAccess(entry.value_ptr.*) catch continue;
            if (!std.ascii.eqlIgnoreCase(access.account.asSlice(), account)) continue;
            const record = self.loadChannel(access.channel.asSlice()) catch continue;
            if (!sameBytes(generation_len, &access.generation, &record.generation)) continue;
            cb(ctx, access.channel.asSlice(), access.level);
        }
    }

    // ── Durable per-channel bad-word filter (svc_chanbadwords; CHANBADWORDS) ─────
    // One newline-joined pattern blob per channel in `.props` ("cbw\x00<channel>"),
    // channel-op managed. A non-op/non-oper channel message containing any pattern
    // (case-insensitive substring, via svc_chanbadwords.containsIgnoreCase) is
    // blocked. Read straight from the store, so it is correct across restarts.
    const chanbadword_prefix = "cbw\x00";
    const chanbadword_max: usize = 64;
    const chanbadword_pattern_max: usize = 128;
    const chanbadword_key_max: usize = chanbadword_prefix.len + channel_max;
    const chanbadword_value_max: usize = chanbadword_max * (chanbadword_pattern_max + 1);

    fn chanBadwordKey(buf: []u8, channel: []const u8) ?[]const u8 {
        if (channel.len == 0 or channel.len > channel_max) return null;
        if (buf.len < chanbadword_prefix.len + channel.len) return null;
        @memcpy(buf[0..chanbadword_prefix.len], chanbadword_prefix);
        for (channel, 0..) |c, i| buf[chanbadword_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. chanbadword_prefix.len + channel.len];
    }

    pub fn chanBadwordAdd(self: *Services, channel: []const u8, pattern: []const u8) ServiceError!bool {
        if (pattern.len == 0 or pattern.len > chanbadword_pattern_max) return false;
        for (pattern) |c| if (c < 0x20 or c == '\n' or c == 0) return false;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [chanbadword_key_max]u8 = undefined;
        const k = chanBadwordKey(&kb, channel) orelse return false;
        const existing = self.store.family(.props).get(k) orelse "";
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |p| {
            if (p.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(p, pattern)) return false;
            count += 1;
        }
        if (count >= chanbadword_max) return false;
        var vb: [chanbadword_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        if (existing.len != 0) {
            w.writeAll(existing) catch return false;
            w.writeAll("\n") catch return false;
        }
        w.writeAll(pattern) catch return false;
        try self.store.family(.props).put(k, w.buffered());
        return true;
    }

    pub fn chanBadwordDel(self: *Services, channel: []const u8, pattern: []const u8) ServiceError!bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [chanbadword_key_max]u8 = undefined;
        const k = chanBadwordKey(&kb, channel) orelse return false;
        const existing = self.store.family(.props).get(k) orelse return false;
        var vb: [chanbadword_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        var found = false;
        var remaining: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |p| {
            if (p.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(p, pattern)) {
                found = true;
                continue;
            }
            if (remaining != 0) w.writeAll("\n") catch return found;
            w.writeAll(p) catch return found;
            remaining += 1;
        }
        if (!found) return false;
        if (remaining == 0) {
            try self.store.family(.props).delete(k);
        } else {
            try self.store.family(.props).put(k, w.buffered());
        }
        return true;
    }

    pub fn chanBadwordForEach(self: *Services, channel: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8) void) void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [chanbadword_key_max]u8 = undefined;
        const k = chanBadwordKey(&kb, channel) orelse return;
        const blob = self.store.family(.props).get(k) orelse return;
        var it = std.mem.splitScalar(u8, blob, '\n');
        while (it.next()) |p| if (p.len != 0) cb(ctx, p);
    }

    /// True if `text` contains any of `channel`'s bad-word patterns. Read directly
    /// from the durable store (correct across restarts, no warm-up).
    pub fn chanBadwordMatches(self: *Services, channel: []const u8, text: []const u8) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [chanbadword_key_max]u8 = undefined;
        const k = chanBadwordKey(&kb, channel) orelse return false;
        const blob = self.store.family(.props).get(k) orelse return false;
        var it = std.mem.splitScalar(u8, blob, '\n');
        while (it.next()) |p| {
            if (p.len != 0 and svc_chanbadwords.containsIgnoreCase(text, p)) return true;
        }
        return false;
    }

    // ── Durable KEEPTOPIC (registered-channel topic survives recreation) ────────
    // "ktp\x00<channel>" in `.props`: presence = enabled; value = the saved topic
    // (empty when enabled but nothing saved yet). Restored on channel recreation.
    const keeptopic_prefix = "ktp\x00";
    const keeptopic_key_max: usize = keeptopic_prefix.len + channel_max;
    const keeptopic_value_max: usize = 512;

    fn keepTopicKey(buf: []u8, channel: []const u8) ?[]const u8 {
        if (channel.len == 0 or channel.len > channel_max) return null;
        if (buf.len < keeptopic_prefix.len + channel.len) return null;
        @memcpy(buf[0..keeptopic_prefix.len], keeptopic_prefix);
        for (channel, 0..) |c, i| buf[keeptopic_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. keeptopic_prefix.len + channel.len];
    }

    pub fn chanKeepTopicEnable(self: *Services, channel: []const u8, on: bool) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [keeptopic_key_max]u8 = undefined;
        const k = keepTopicKey(&kb, channel) orelse return;
        if (on) {
            if (self.store.family(.props).get(k) == null) try self.store.family(.props).put(k, "");
        } else {
            try self.store.family(.props).delete(k);
        }
    }

    /// Persist `topic` for `channel` — only when KEEPTOPIC is enabled (key present).
    pub fn chanKeepTopicSave(self: *Services, channel: []const u8, topic: []const u8) ServiceError!void {
        if (topic.len > keeptopic_value_max) return;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [keeptopic_key_max]u8 = undefined;
        const k = keepTopicKey(&kb, channel) orelse return;
        if (self.store.family(.props).get(k) == null) return; // not enabled
        try self.store.family(.props).put(k, topic);
    }

    /// Copy the saved topic for `channel` into `out` when KEEPTOPIC is enabled and a
    /// non-empty topic is stored; else null. Returns a slice into `out`.
    pub fn chanKeepTopicGet(self: *Services, channel: []const u8, out: []u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [keeptopic_key_max]u8 = undefined;
        const k = keepTopicKey(&kb, channel) orelse return null;
        const blob = self.store.family(.props).get(k) orelse return null;
        if (blob.len == 0) return null;
        const n = @min(blob.len, out.len);
        @memcpy(out[0..n], blob[0..n]);
        return out[0..n];
    }

    // ── Durable registered-channel founder successor (svc_successor; SUCCESSOR) ──
    // One successor account per channel in `.props` ("suc\x00<channel>"). When the
    // founder's account is dropped, the channel is handed to its successor.
    const successor_prefix = "suc\x00";
    const successor_key_max: usize = successor_prefix.len + channel_max;

    fn successorKey(buf: []u8, channel: []const u8) ?[]const u8 {
        if (channel.len == 0 or channel.len > channel_max) return null;
        if (buf.len < successor_prefix.len + channel.len) return null;
        @memcpy(buf[0..successor_prefix.len], successor_prefix);
        for (channel, 0..) |c, i| buf[successor_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. successor_prefix.len + channel.len];
    }

    /// Set `account` (normalized) as `channel`'s configured successor.
    pub fn channelSuccessorSet(self: *Services, channel: []const u8, account: []const u8) ServiceError!void {
        const acc = try accountKey(account);
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [successor_key_max]u8 = undefined;
        const k = successorKey(&kb, channel) orelse return error.InvalidChannel;
        try self.store.family(.props).put(k, acc.asSlice());
    }

    /// Remove `channel`'s configured successor. No-op when unset.
    pub fn channelSuccessorClear(self: *Services, channel: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [successor_key_max]u8 = undefined;
        const k = successorKey(&kb, channel) orelse return;
        try self.store.family(.props).delete(k);
    }

    /// Copy `channel`'s configured successor account into `out`, or null if unset.
    pub fn channelSuccessorGet(self: *Services, channel: []const u8, out: []u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [successor_key_max]u8 = undefined;
        const k = successorKey(&kb, channel) orelse return null;
        const blob = self.store.family(.props).get(k) orelse return null;
        if (blob.len == 0) return null;
        const n = @min(blob.len, out.len);
        @memcpy(out[0..n], blob[0..n]);
        return out[0..n];
    }

    // ── Durable registered-channel metadata (CHANNEL SET DESC / URL) ────────────
    // Free-text channel metadata in `.props` keyed by "<tag>\x00<channel>". DESC
    // is a human description; URL is a homepage link. Empty value clears the key.
    const meta_value_max: usize = 400;

    fn metaKey(buf: []u8, tag: []const u8, channel: []const u8) ?[]const u8 {
        if (channel.len == 0 or channel.len > channel_max) return null;
        if (buf.len < tag.len + channel.len) return null;
        @memcpy(buf[0..tag.len], tag);
        for (channel, 0..) |c, i| buf[tag.len + i] = std.ascii.toLower(c);
        return buf[0 .. tag.len + channel.len];
    }

    fn chanMetaSet(self: *Services, tag: []const u8, channel: []const u8, value: []const u8) ServiceError!void {
        if (value.len > meta_value_max) return error.InvalidChannel;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [16 + channel_max]u8 = undefined;
        const k = metaKey(&kb, tag, channel) orelse return error.InvalidChannel;
        if (value.len == 0) {
            try self.store.family(.props).delete(k);
        } else {
            try self.store.family(.props).put(k, value);
        }
    }

    fn chanMetaGet(self: *Services, tag: []const u8, channel: []const u8, out: []u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [16 + channel_max]u8 = undefined;
        const k = metaKey(&kb, tag, channel) orelse return null;
        const blob = self.store.family(.props).get(k) orelse return null;
        if (blob.len == 0) return null;
        const n = @min(blob.len, out.len);
        @memcpy(out[0..n], blob[0..n]);
        return out[0..n];
    }

    /// Set (or clear, when empty) `channel`'s human description (CHANNEL SET DESC).
    pub fn chanDescSet(self: *Services, channel: []const u8, value: []const u8) ServiceError!void {
        return self.chanMetaSet("desc\x00", channel, value);
    }

    /// Copy `channel`'s description into `out`, or null if unset.
    pub fn chanDescGet(self: *Services, channel: []const u8, out: []u8) ?[]const u8 {
        return self.chanMetaGet("desc\x00", channel, out);
    }

    /// Set (or clear, when empty) `channel`'s homepage URL (CHANNEL SET URL).
    pub fn chanUrlSet(self: *Services, channel: []const u8, value: []const u8) ServiceError!void {
        return self.chanMetaSet("url\x00", channel, value);
    }

    /// Copy `channel`'s URL into `out`, or null if unset.
    pub fn chanUrlGet(self: *Services, channel: []const u8, out: []u8) ?[]const u8 {
        return self.chanMetaGet("url\x00", channel, out);
    }

    pub fn replayLiveState(self: *Services, sink: LiveReplaySink) ServiceError!LiveReplaySummary {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var summary = LiveReplaySummary{};
        {
            var it = self.store.maps[@intFromEnum(store_mod.Family.chanregs)].map.iterator();
            while (it.next()) |entry| {
                const record = decodeChannel(entry.value_ptr.*) catch continue;
                try sink.channel(sink.ptr, record.name.asSlice(), record.mlock.asSlice());
                summary.channels += 1;
                if (record.mlock.asSlice().len != 0) summary.mlocks += 1;
            }
        }
        if (sink.akick) |on_akick| {
            var it = self.store.maps[@intFromEnum(channel_access_family)].map.iterator();
            while (it.next()) |entry| {
                if (!std.mem.startsWith(u8, entry.key_ptr.*, akick_prefix)) continue;
                const akick = decodeAkick(entry.value_ptr.*) catch continue;
                const channel = self.loadChannel(akick.channel.asSlice()) catch continue;
                if (!sameBytes(generation_len, &akick.generation, &channel.generation)) continue;
                try on_akick(sink.ptr, akick.channel.asSlice(), akick.mask.asSlice(), akick.reason.asSlice(), akick.setter.asSlice());
                summary.akicks += 1;
            }
        }
        if (sink.ward) |on_ward| {
            var it = self.store.maps[@intFromEnum(store_mod.Family.bans)].map.iterator();
            while (it.next()) |entry| {
                if (!std.mem.startsWith(u8, entry.key_ptr.*, ward_prefix)) continue;
                const ward = decodeWard(entry.value_ptr.*) catch continue;
                try on_ward(sink.ptr, ward);
                summary.wards += 1;
            }
        }
        if (sink.saccess) |on_saccess| {
            var it = self.store.maps[@intFromEnum(store_mod.Family.bans)].map.iterator();
            while (it.next()) |entry| {
                if (!std.mem.startsWith(u8, entry.key_ptr.*, saccess_prefix)) continue;
                const sa = decodeSaccess(entry.value_ptr.*) catch continue;
                try on_saccess(sink.ptr, sa);
                summary.saccesses += 1;
            }
        }
        return summary;
    }

    fn addCertfpListEntry(self: *Services, account: []const u8, fingerprint: []const u8) ServiceError!void {
        const key = try accountKey(account);
        var kb: [certfp_account_key_max]u8 = undefined;
        const list_key = certfpAccountKey(&kb, key.asSlice()) orelse return error.BufferTooSmall;
        const existing = self.store.family(.props).get(list_key) orelse "";

        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |fp| {
            if (std.ascii.eqlIgnoreCase(fp, fingerprint)) return;
        }

        var out: [certfp_list_value_max]u8 = undefined;
        if (existing.len == 0) {
            const value = std.fmt.bufPrint(&out, "{s}", .{fingerprint}) catch return error.BufferTooSmall;
            try self.store.family(.props).put(list_key, value);
            return;
        }
        const value = std.fmt.bufPrint(&out, "{s}\n{s}", .{ existing, fingerprint }) catch return error.BufferTooSmall;
        try self.store.family(.props).put(list_key, value);
    }

    fn removeCertfpListEntry(self: *Services, account: []const u8, fingerprint: []const u8) ServiceError!void {
        var kb: [certfp_account_key_max]u8 = undefined;
        const list_key = certfpAccountKey(&kb, account) orelse return error.BufferTooSmall;
        const existing = self.store.family(.props).get(list_key) orelse return error.NotFound;

        var out: [certfp_list_value_max]u8 = undefined;
        var len: usize = 0;
        var removed = false;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |fp| {
            if (fp.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(fp, fingerprint)) {
                removed = true;
                continue;
            }
            if (len != 0) {
                if (len >= out.len) return error.BufferTooSmall;
                out[len] = '\n';
                len += 1;
            }
            if (len + fp.len > out.len) return error.BufferTooSmall;
            @memcpy(out[len..][0..fp.len], fp);
            len += fp.len;
        }
        if (!removed) return error.NotFound;
        if (len == 0) {
            try self.store.family(.props).delete(list_key);
        } else {
            try self.store.family(.props).put(list_key, out[0..len]);
        }
    }

    fn accountSuspendedUnlocked(self: *Services, account: []const u8) ServiceError!bool {
        const key = try accountKey(account);
        const value = self.store.family(.accounts).get(key.asSlice()) orelse return false;
        const record = try decodeAccount(value);
        return (record.flags & account_flag_suspended) != 0;
    }

    fn accountForbiddenUnlocked(self: *Services, account: []const u8) bool {
        const key = accountKey(account) catch return false;
        if (self.store.family(.accounts).get(key.asSlice())) |value| {
            const record = decodeAccount(value) catch return false;
            if ((record.flags & account_flag_forbidden) != 0) return true;
        }
        var kb: [forbidden_account_key_max]u8 = undefined;
        const reservation_key = forbiddenAccountKey(&kb, key.asSlice()) orelse return false;
        return self.store.family(.props).get(reservation_key) != null;
    }

    fn loadAccount(self: *Services, name: []const u8) ServiceError!AccountRecord {
        const key = try accountKey(name);
        const value = self.store.family(.accounts).get(key.asSlice()) orelse return error.NotFound;
        return decodeAccount(value);
    }

    fn saveAccount(self: *Services, record: AccountRecord, scratch: []u8) ServiceError!void {
        const encoded = try encodeAccount(record, scratch);
        try self.store.family(.accounts).put(record.name.asSlice(), encoded);
    }

    fn loadChannel(self: *Services, channel: []const u8) ServiceError!ChannelRecord {
        const key = try channelKey(channel);
        const value = self.store.family(.chanregs).get(key.asSlice()) orelse return error.NotFound;
        return decodeChannel(value);
    }

    fn putAccess(
        self: *Services,
        channel: ChannelRecord,
        account: AccountName,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!AccessRecord {
        const record = AccessRecord{
            .channel = channel.name,
            .account = account,
            .generation = channel.generation,
            .level = level,
        };
        const encoded = try encodeAccess(record, scratch);
        var key_buf: [key_max]u8 = undefined;
        const key = try accessKey(channel.name.asSlice(), account.asSlice(), &key_buf);
        try self.store.put(channel_access_family, key, encoded);
        return record;
    }

    fn loadAccess(self: *Services, channel: ChannelRecord, account: []const u8) ServiceError!AccessRecord {
        var key_buf: [key_max]u8 = undefined;
        const key = try accessKey(channel.name.asSlice(), account, &key_buf);
        const value = self.store.get(channel_access_family, key) orelse return error.NotFound;
        const record = try decodeAccess(value);
        if (!sameBytes(generation_len, &record.generation, &channel.generation)) return error.NotFound;
        return record;
    }

    fn loadAkick(self: *Services, channel: ChannelRecord, mask: []const u8) ServiceError!AkickRecord {
        var key_buf: [key_max]u8 = undefined;
        const key = try akickKey(channel.name.asSlice(), mask, &key_buf);
        const value = self.store.get(channel_access_family, key) orelse return error.NotFound;
        const record = try decodeAkick(value);
        if (!sameBytes(generation_len, &record.generation, &channel.generation)) return error.NotFound;
        return record;
    }

    fn requireAccess(self: *Services, channel: ChannelRecord, actor: []const u8, needed: AccessLevel) ServiceError!void {
        const actor_key = try accountKey(actor);
        if (std.mem.eql(u8, actor_key.asSlice(), channel.founder.asSlice())) return;
        const access = self.loadAccess(channel, actor_key.asSlice()) catch |err| switch (err) {
            error.NotFound => return error.Forbidden,
            else => return err,
        };
        if (!access.level.allows(needed)) return error.Forbidden;
    }
};

fn validatePassword(password: []const u8) ServiceError!void {
    if (password.len < 8 or password.len > 512) return error.InvalidPassword;
    for (password) |byte| if (byte == 0 or byte == '\n' or byte == '\r') return error.InvalidPassword;
}

fn validateEmail(input: []const u8) ServiceError!Email {
    if (input.len == 0) return Email.empty();
    if (input.len > email_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Email.init(input) catch error.InvalidValue;
}

fn validateMlock(input: []const u8) ServiceError!Mlock {
    if (input.len == 0) return Mlock.empty();
    if (input.len > mlock_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Mlock.init(input) catch error.InvalidValue;
}

fn validateReason(input: []const u8) ServiceError!Reason {
    if (input.len > reason_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Reason.init(input) catch error.InvalidValue;
}

fn validateNick(input: []const u8) ServiceError!NickName {
    if (input.len == 0 or input.len > nick_max or hasCtlOrSep(input)) return error.InvalidName;
    for (input) |byte| if (byte == ' ' or byte == ',') return error.InvalidName;
    return NickName.init(input) catch error.InvalidName;
}

fn validateMask(input: []const u8) ServiceError!Mask {
    if (input.len == 0 or input.len > mask_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Mask.init(input) catch error.InvalidValue;
}

/// Durable-store key prefix for certfp→account bindings (props family). The
/// prefix keeps these out of the channel-access keyspace that shares `.props`.
const certfp_key_prefix = "certfp:";
const certfp_key_max = certfp_key_prefix.len + 128;
const certfp_account_key_prefix = "certfps:";
const certfp_account_key_max = certfp_account_key_prefix.len + account_max;
const certfp_list_value_max = 16 * 64 + 15;
const forbidden_account_key_prefix = "acctforbid:";
const forbidden_account_key_max = forbidden_account_key_prefix.len + account_max;
const verify_key_max = verify_prefix.len + account_max;
const verify_value_max = verify_version.len + 1 + account_max + 1 + email_max + 1 + 128 + 1 + 20;
const default_verify_ttl_ms: u64 = 15 * 60 * 1000;
const ward_key_max = ward_prefix.len + 16 + 1 + 256;
const ward_value_max = ward_version.len + 1 + 16 + 1 + 256 + 1 + 16 + 1 + 16 + 1 + 20 + 1 + 20 + 1 + 64 + 1 + 512;

// SACCESS persistence sizing. Entry-type token <= 9 ("NOCHANNEL"); mask is the
// IRCX access mask (DEFAULT_MAX_MASK_BYTES = 128); reason <= 256; duration is a
// u64 (<= 20 digits). Generous bounds keep this restart-safe under any config.
const saccess_type_max = 16;
const saccess_mask_max = 256;
const saccess_reason_max = 512;
const saccess_key_max = saccess_prefix.len + saccess_type_max + 1 + saccess_mask_max;
const saccess_value_max = saccess_version.len + 1 + saccess_type_max + 1 + saccess_mask_max + 1 + 20 + 1 + saccess_reason_max;
const session_token_version = "T1";
const session_token_key_prefix = "sessiontok:";
const session_token_account_key_prefix = "sessiontokacct:";
const session_token_key_max = session_token_key_prefix.len + hash_hex_len;
const session_token_account_key_max = session_token_account_key_prefix.len + account_max;
const session_token_value_max = session_token_version.len + 1 + account_max + 1 + 20 + 1 + hash_hex_len;

const SessionTokenRecord = struct {
    account: AccountName,
    expires_unix: i64,
    hash: []const u8,
};

fn secureZero(buf: []u8) void {
    for (buf) |*byte| {
        const vp: *volatile u8 = @ptrCast(byte);
        vp.* = 0;
    }
}

/// Build the props-family key for a certfp binding, or null if it would not fit.
fn certfpKey(buf: []u8, fingerprint: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, certfp_key_prefix ++ "{s}", .{fingerprint}) catch null;
}

fn certfpAccountKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, certfp_account_key_prefix ++ "{s}", .{account}) catch null;
}

fn forbiddenAccountKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, forbidden_account_key_prefix ++ "{s}", .{account}) catch null;
}

fn verifyKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, verify_prefix ++ "{s}", .{account}) catch null;
}

/// Durable-store key prefix for persisted SCRAM credential tuples (props family).
const scram_key_prefix = "scram:";
const scram_key_max = scram_key_prefix.len + account_max;

/// Build the props-family key for an account's SCRAM tuple, or null if too long.
fn scramKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, scram_key_prefix ++ "{s}", .{account}) catch null;
}

fn sessionTokenKey(buf: []u8, hash_hex: []const u8) ?[]const u8 {
    if (hash_hex.len != hash_hex_len) return null;
    return std.fmt.bufPrint(buf, session_token_key_prefix ++ "{s}", .{hash_hex}) catch null;
}

fn sessionTokenAccountKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, session_token_account_key_prefix ++ "{s}", .{account}) catch null;
}

fn encodeSessionTokenRecord(account: []const u8, expires_unix: i64, hash_hex: []const u8, scratch: []u8) ServiceError![]const u8 {
    if (hash_hex.len != hash_hex_len) return error.InvalidRecord;
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{d}|{s}",
        .{ session_token_version, account, expires_unix, hash_hex },
    ) catch error.BufferTooSmall;
}

fn decodeSessionTokenRecord(value: []const u8) ServiceError!SessionTokenRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    const version = it.next() orelse return error.InvalidRecord;
    if (!std.mem.eql(u8, version, session_token_version)) return error.InvalidRecord;
    const account = try accountKey(it.next() orelse return error.InvalidRecord);
    const expires_unix = std.fmt.parseInt(i64, it.next() orelse return error.InvalidRecord, 10) catch return error.InvalidRecord;
    const hash_hex = it.next() orelse return error.InvalidRecord;
    if (it.next() != null) return error.InvalidRecord;
    if (hash_hex.len != hash_hex_len) return error.InvalidRecord;
    for (hash_hex) |ch| if (!std.ascii.isHex(ch)) return error.InvalidRecord;
    return .{ .account = account, .expires_unix = expires_unix, .hash = hash_hex };
}

fn validSessionTokenText(token: []const u8) bool {
    if (token.len != session_token_len) return false;
    if (!std.mem.eql(u8, token[0..session_token_prefix.len], session_token_prefix)) return false;
    for (token[session_token_prefix.len..]) |ch| {
        if (!std.ascii.isHex(ch)) return false;
    }
    return true;
}

fn accountKey(input: []const u8) ServiceError!AccountName {
    if (input.len == 0 or input.len > account_max) return error.InvalidName;
    var out = AccountName{};
    for (input, 0..) |byte, idx| {
        if (!isAccountChar(byte)) return error.InvalidName;
        out.bytes[idx] = asciiLower(byte);
    }
    out.len = @intCast(input.len);
    return out;
}

fn channelKey(input: []const u8) ServiceError!ChannelName {
    if (input.len < 2 or input.len > channel_max or input[0] != '#') return error.InvalidChannel;
    var out = ChannelName{};
    for (input, 0..) |byte, idx| {
        if (byte <= 0x20 or byte == 0x7f or byte == '|' or byte == ',' or byte == ':') return error.InvalidChannel;
        out.bytes[idx] = asciiLower(byte);
    }
    out.len = @intCast(input.len);
    return out;
}

fn isAccountChar(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or
        (byte >= 'A' and byte <= 'Z') or
        (byte >= '0' and byte <= '9') or
        byte == '_' or byte == '-' or byte == '.';
}

fn asciiLower(byte: u8) u8 {
    if (byte >= 'A' and byte <= 'Z') return byte + ('a' - 'A');
    return byte;
}

fn setFlag(flags: *u32, bit: u32, enabled: bool) void {
    if (enabled) {
        flags.* |= bit;
    } else {
        flags.* &= ~bit;
    }
}

fn hasCtlOrSep(input: []const u8) bool {
    for (input) |byte| if (byte < 0x20 or byte == 0x7f or byte == '|') return true;
    return false;
}

fn hashPassword(out: *[hash_len]u8, password: []const u8, salt: *const [salt_len]u8, rounds: u32) ServiceError!void {
    try std.crypto.pwhash.pbkdf2(out, password, salt, rounds, std.crypto.auth.hmac.sha2.HmacSha256);
}

fn verifyPassword(record: AccountRecord, password: []const u8, rounds: u32) ServiceError!void {
    try validatePassword(password);
    var candidate: [hash_len]u8 = undefined;
    try hashPassword(&candidate, password, &record.salt, rounds);
    if (!std.crypto.timing_safe.eql([hash_len]u8, candidate, record.hash)) return error.AuthFailed;
}

fn rejectMissingAccount(password: []const u8, rounds: u32) ServiceError!void {
    try validatePassword(password);
    var candidate: [hash_len]u8 = undefined;
    try hashPassword(&candidate, password, &missing_account_salt, rounds);
}

fn encodeAccount(record: AccountRecord, scratch: []u8) ServiceError![]const u8 {
    var salt_hex = std.fmt.bytesToHex(record.salt, .lower);
    var hash_hex = std.fmt.bytesToHex(record.hash, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{}|{s}|{}",
        .{ account_version_v2, record.name.asSlice(), &salt_hex, &hash_hex, record.flags, record.email.asSlice(), record.email_verified },
    ) catch error.BufferTooSmall;
}

fn decodeAccount(value: []const u8) ServiceError!AccountRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    const version = it.next() orelse return error.InvalidRecord;
    const is_v1 = std.mem.eql(u8, version, account_version);
    const is_v2 = std.mem.eql(u8, version, account_version_v2);
    if (!is_v1 and !is_v2) return error.InvalidRecord;
    const name = try accountKey(it.next() orelse return error.InvalidRecord);
    const salt_hex = it.next() orelse return error.InvalidRecord;
    const hash_hex = it.next() orelse return error.InvalidRecord;
    const flags_text = it.next() orelse return error.InvalidRecord;
    const email_text = it.next() orelse "";
    const verified_text = if (is_v2) it.next() orelse return error.InvalidRecord else "false";
    if (it.next() != null) return error.InvalidRecord;
    if (salt_hex.len != salt_hex_len or hash_hex.len != hash_hex_len) return error.InvalidRecord;

    var record = AccountRecord{
        .name = name,
        .salt = undefined,
        .hash = undefined,
        .flags = std.fmt.parseInt(u32, flags_text, 10) catch return error.InvalidRecord,
        .email = try validateEmail(email_text),
        .email_verified = std.mem.eql(u8, verified_text, "true"),
    };
    _ = std.fmt.hexToBytes(&record.salt, salt_hex) catch return error.InvalidRecord;
    _ = std.fmt.hexToBytes(&record.hash, hash_hex) catch return error.InvalidRecord;
    return record;
}

fn encodeChannel(record: ChannelRecord, scratch: []u8) ServiceError![]const u8 {
    var gen_hex = std.fmt.bytesToHex(record.generation, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{}|{s}",
        .{ channel_version_v2, record.name.asSlice(), record.founder.asSlice(), &gen_hex, record.flags, record.mlock.asSlice() },
    ) catch error.BufferTooSmall;
}

fn decodeChannel(value: []const u8) ServiceError!ChannelRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    const version = it.next() orelse return error.InvalidRecord;
    const is_v1 = std.mem.eql(u8, version, channel_version);
    const is_v2 = std.mem.eql(u8, version, channel_version_v2);
    if (!is_v1 and !is_v2) return error.InvalidRecord;
    const name = try channelKey(it.next() orelse return error.InvalidRecord);
    const founder = try accountKey(it.next() orelse return error.InvalidRecord);
    const gen_hex = it.next() orelse return error.InvalidRecord;
    const flags_text = it.next() orelse return error.InvalidRecord;
    const mlock_text = if (is_v2) it.next() orelse return error.InvalidRecord else "";
    if (it.next() != null or gen_hex.len != generation_hex_len) return error.InvalidRecord;
    var record = ChannelRecord{
        .name = name,
        .founder = founder,
        .generation = undefined,
        .flags = std.fmt.parseInt(u32, flags_text, 10) catch return error.InvalidRecord,
        .mlock = try validateMlock(mlock_text),
    };
    _ = std.fmt.hexToBytes(&record.generation, gen_hex) catch return error.InvalidRecord;
    return record;
}

fn encodeAccess(record: AccessRecord, scratch: []u8) ServiceError![]const u8 {
    var gen_hex = std.fmt.bytesToHex(record.generation, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{}",
        .{ access_version, record.channel.asSlice(), record.account.asSlice(), &gen_hex, @intFromEnum(record.level) },
    ) catch error.BufferTooSmall;
}

fn decodeAccess(value: []const u8) ServiceError!AccessRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, access_version)) return error.InvalidRecord;
    const channel = try channelKey(it.next() orelse return error.InvalidRecord);
    const account = try accountKey(it.next() orelse return error.InvalidRecord);
    const gen_hex = it.next() orelse return error.InvalidRecord;
    const level_text = it.next() orelse return error.InvalidRecord;
    if (it.next() != null or gen_hex.len != generation_hex_len) return error.InvalidRecord;
    var record = AccessRecord{
        .channel = channel,
        .account = account,
        .generation = undefined,
        .level = levelFromInt(std.fmt.parseInt(u8, level_text, 10) catch return error.InvalidRecord) orelse return error.InvalidRecord,
    };
    _ = std.fmt.hexToBytes(&record.generation, gen_hex) catch return error.InvalidRecord;
    return record;
}

fn encodeAkick(record: AkickRecord, scratch: []u8) ServiceError![]const u8 {
    var gen_hex = std.fmt.bytesToHex(record.generation, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{s}|{s}",
        .{ akick_version, record.channel.asSlice(), record.mask.asSlice(), &gen_hex, record.setter.asSlice(), record.reason.asSlice() },
    ) catch error.BufferTooSmall;
}

fn decodeAkick(value: []const u8) ServiceError!AkickRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, akick_version)) return error.InvalidRecord;
    const channel = try channelKey(it.next() orelse return error.InvalidRecord);
    const mask = try validateMask(it.next() orelse return error.InvalidRecord);
    const gen_hex = it.next() orelse return error.InvalidRecord;
    const setter = try accountKey(it.next() orelse return error.InvalidRecord);
    const reason = try validateReason(it.next() orelse "");
    if (it.next() != null or gen_hex.len != generation_hex_len) return error.InvalidRecord;
    var record = AkickRecord{
        .channel = channel,
        .mask = mask,
        .generation = undefined,
        .setter = setter,
        .reason = reason,
    };
    _ = std.fmt.hexToBytes(&record.generation, gen_hex) catch return error.InvalidRecord;
    return record;
}

const PendingVerify = struct {
    account: []const u8,
    email: []const u8,
    token: []const u8,
    issued_ms: u64,
};

fn encodeVerify(account: []const u8, email: []const u8, token: []const u8, issued_ms: u64, out: []u8) ServiceError![]const u8 {
    if (hasCtlOrSep(token) or token.len == 0 or token.len > 128) return error.InvalidValue;
    return std.fmt.bufPrint(out, "{s}|{s}|{s}|{s}|{d}", .{ verify_version, account, email, token, issued_ms }) catch error.BufferTooSmall;
}

fn decodeVerify(value: []const u8) ServiceError!PendingVerify {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, verify_version)) return error.InvalidRecord;
    const account = it.next() orelse return error.InvalidRecord;
    const email = it.next() orelse return error.InvalidRecord;
    const token = it.next() orelse return error.InvalidRecord;
    const issued_text = it.next() orelse return error.InvalidRecord;
    if (it.next() != null) return error.InvalidRecord;
    _ = try accountKey(account);
    _ = try validateEmail(email);
    if (hasCtlOrSep(token) or token.len == 0 or token.len > 128) return error.InvalidRecord;
    return .{
        .account = account,
        .email = email,
        .token = token,
        .issued_ms = std.fmt.parseInt(u64, issued_text, 10) catch return error.InvalidRecord,
    };
}

fn tokenMatches(expected: []const u8, actual: []const u8) bool {
    if (expected.len != actual.len) return false;
    return std.crypto.timing_safe.compare(u8, expected, actual, .big) == .eq;
}

fn validateWardField(value: []const u8, max_len: usize) ServiceError!void {
    if (value.len == 0 or value.len > max_len) return error.InvalidValue;
    if (hasCtlOrSep(value)) return error.InvalidValue;
}

fn validateWardOptionalField(value: []const u8, max_len: usize) ServiceError!void {
    if (value.len > max_len) return error.InvalidValue;
    if (hasCtlOrSep(value)) return error.InvalidValue;
}

fn wardKey(match: []const u8, pattern: []const u8, out: []u8) ServiceError![]const u8 {
    try validateWardField(match, 16);
    try validateWardField(pattern, 256);
    if (ward_prefix.len + match.len + 1 + pattern.len > @min(out.len, ward_key_max)) return error.BufferTooSmall;
    return std.fmt.bufPrint(out, ward_prefix ++ "{s}:{s}", .{ match, pattern }) catch error.BufferTooSmall;
}

fn encodeWard(ward: ReplayWard, out: []u8) ServiceError![]const u8 {
    try validateWardField(ward.match, 16);
    try validateWardField(ward.pattern, 256);
    try validateWardField(ward.scope, 16);
    try validateWardField(ward.action, 16);
    try validateWardOptionalField(ward.setter, 64);
    try validateWardOptionalField(ward.reason, 512);
    return std.fmt.bufPrint(
        out,
        "{s}|{s}|{s}|{s}|{s}|{d}|{d}|{s}|{s}",
        .{
            ward_version,
            ward.match,
            ward.pattern,
            ward.scope,
            ward.action,
            ward.created_ms,
            ward.expires_ms,
            ward.setter,
            ward.reason,
        },
    ) catch error.BufferTooSmall;
}

fn decodeWard(value: []const u8) ServiceError!ReplayWard {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, ward_version)) return error.InvalidRecord;
    const match = it.next() orelse return error.InvalidRecord;
    const pattern = it.next() orelse return error.InvalidRecord;
    const scope = it.next() orelse return error.InvalidRecord;
    const action = it.next() orelse return error.InvalidRecord;
    const created = it.next() orelse return error.InvalidRecord;
    const expires = it.next() orelse return error.InvalidRecord;
    const setter = it.next() orelse "";
    const reason = it.next() orelse "";
    if (it.next() != null) return error.InvalidRecord;
    try validateWardField(match, 16);
    try validateWardField(pattern, 256);
    try validateWardField(scope, 16);
    try validateWardField(action, 16);
    try validateWardOptionalField(setter, 64);
    try validateWardOptionalField(reason, 512);
    return .{
        .match = match,
        .pattern = pattern,
        .scope = scope,
        .action = action,
        .created_ms = std.fmt.parseInt(i64, created, 10) catch return error.InvalidRecord,
        .expires_ms = std.fmt.parseInt(i64, expires, 10) catch return error.InvalidRecord,
        .setter = setter,
        .reason = reason,
    };
}

fn saccessKey(entry_type: []const u8, mask: []const u8, out: []u8) ServiceError![]const u8 {
    try validateWardField(entry_type, saccess_type_max);
    try validateWardField(mask, saccess_mask_max);
    if (saccess_prefix.len + entry_type.len + 1 + mask.len > @min(out.len, saccess_key_max)) return error.BufferTooSmall;
    return std.fmt.bufPrint(out, saccess_prefix ++ "{s}:{s}", .{ entry_type, mask }) catch error.BufferTooSmall;
}

fn encodeSaccess(entry: ReplaySaccess, out: []u8) ServiceError![]const u8 {
    try validateWardField(entry.entry_type, saccess_type_max);
    try validateWardField(entry.mask, saccess_mask_max);
    try validateWardOptionalField(entry.reason, saccess_reason_max);
    return std.fmt.bufPrint(
        out,
        "{s}|{s}|{s}|{d}|{s}",
        .{ saccess_version, entry.entry_type, entry.mask, entry.duration, entry.reason },
    ) catch error.BufferTooSmall;
}

fn decodeSaccess(value: []const u8) ServiceError!ReplaySaccess {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, saccess_version)) return error.InvalidRecord;
    const entry_type = it.next() orelse return error.InvalidRecord;
    const mask = it.next() orelse return error.InvalidRecord;
    const duration = it.next() orelse return error.InvalidRecord;
    const reason = it.next() orelse "";
    if (it.next() != null) return error.InvalidRecord;
    try validateWardField(entry_type, saccess_type_max);
    try validateWardField(mask, saccess_mask_max);
    try validateWardOptionalField(reason, saccess_reason_max);
    return .{
        .entry_type = entry_type,
        .mask = mask,
        .duration = std.fmt.parseInt(u64, duration, 10) catch return error.InvalidRecord,
        .reason = reason,
    };
}

fn levelFromInt(value: u8) ?AccessLevel {
    return switch (value) {
        @intFromEnum(AccessLevel.voice) => .voice,
        @intFromEnum(AccessLevel.op) => .op,
        @intFromEnum(AccessLevel.admin) => .admin,
        @intFromEnum(AccessLevel.founder) => .founder,
        else => null,
    };
}

fn accessKey(channel: []const u8, account: []const u8, out: []u8) ServiceError![]const u8 {
    return prefixedKey(access_prefix, channel, account, out);
}

fn akickKey(channel: []const u8, mask: []const u8, out: []u8) ServiceError![]const u8 {
    return prefixedKey(akick_prefix, channel, mask, out);
}

fn prefixedKey(prefix: []const u8, channel: []const u8, tail: []const u8, out: []u8) ServiceError![]const u8 {
    if (prefix.len + channel.len + 1 + tail.len > out.len) return error.BufferTooSmall;
    var len: usize = 0;
    @memcpy(out[len..][0..prefix.len], prefix);
    len += prefix.len;
    @memcpy(out[len..][0..channel.len], channel);
    len += channel.len;
    out[len] = ':';
    len += 1;
    @memcpy(out[len..][0..tail.len], tail);
    len += tail.len;
    return out[0..len];
}

fn sameBytes(comptime len: usize, a: *const [len]u8, b: *const [len]u8) bool {
    return std.crypto.timing_safe.eql([len]u8, a.*, b.*);
}

fn openTestStore(tmp: std.testing.TmpDir, name: []const u8) !OroStore {
    return OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, name);
}

test "register and identify account" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-account.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    const registered = try services.registerAccount("Alice", "correct horse battery staple", &scratch);
    try std.testing.expectEqualStrings("alice", registered.registered_account.name.asSlice());

    const identified = try services.identifyAccount("ALICE", "correct horse battery staple");
    try std.testing.expectEqualStrings("alice", identified.identified.name.asSlice());
}

test "channel SET flags and DESC/URL persist and round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-channel-set.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("admin", "correct horse battery staple", &scratch);
    _ = try services.registerChannel("#room", "admin", &scratch);

    // Flags start clear, set independently, and persist without clobbering siblings.
    try std.testing.expect(!services.channelFlagSet("#room", channel_flag_topiclock));
    try services.setChannelFlag("#room", "admin", channel_flag_topiclock, true, &scratch);
    try services.setChannelFlag("#room", "admin", channel_flag_private, true, &scratch);
    try std.testing.expect(services.channelFlagSet("#room", channel_flag_topiclock));
    try std.testing.expect(services.channelFlagSet("#room", channel_flag_private));
    try std.testing.expect(!services.channelFlagSet("#room", channel_flag_guard));

    // Clearing one leaves the other intact.
    try services.setChannelFlag("#room", "admin", channel_flag_topiclock, false, &scratch);
    try std.testing.expect(!services.channelFlagSet("#room", channel_flag_topiclock));
    try std.testing.expect(services.channelFlagSet("#room", channel_flag_private));

    // DESC / URL round-trip and clear on empty.
    var out: [512]u8 = undefined;
    try std.testing.expect(services.chanDescGet("#room", &out) == null);
    try services.chanDescSet("#room", "Our room");
    try std.testing.expectEqualStrings("Our room", services.chanDescGet("#room", &out).?);
    try services.chanUrlSet("#room", "https://example.test");
    try std.testing.expectEqualStrings("https://example.test", services.chanUrlGet("#room", &out).?);
    try services.chanDescSet("#room", "");
    try std.testing.expect(services.chanDescGet("#room", &out) == null);

    // A non-founder/non-admin actor cannot set flags.
    _ = try services.registerAccount("mallory", "another correct horse battery", &scratch);
    try std.testing.expectError(error.Forbidden, services.setChannelFlag("#room", "mallory", channel_flag_guard, true, &scratch));
}

test "wrong password is rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-wrong-pass.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", "wrong horse battery staple"));
}

test "missing identify collapses to auth failed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-missing-identify.wal");
    defer store.deinit();
    var services = Services.init(&store, null);

    try std.testing.expectError(error.AuthFailed, services.identifyAccount("missing", "correct horse battery staple"));
}

test "session tokens issue, validate by hash, and expire" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-session-token.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("Alice", "correct horse battery staple", &scratch);
    const issued = try services.issueSessionToken("alice", 1000);
    try std.testing.expectEqualStrings("alice", issued.account.asSlice());
    try std.testing.expect(std.mem.startsWith(u8, issued.tokenSlice(), session_token_prefix));

    var account_out: [account_max]u8 = undefined;
    const account = services.validateSessionToken("ALICE", issued.tokenSlice(), 1001, &account_out) orelse return error.ExpectedValidToken;
    try std.testing.expectEqualStrings("alice", account);
    try std.testing.expect(services.validateSessionToken("bob", issued.tokenSlice(), 1001, &account_out) == null);
    try std.testing.expect(services.validateSessionToken("alice", "sst_ffffffffffffffffffffffffffffffff", 1001, &account_out) == null);
    try std.testing.expect(services.validateSessionToken("alice", issued.tokenSlice(), issued.expires_unix, &account_out) == null);
}

test "corrupt account record is rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-corrupt-account.wal");
    defer store.deinit();
    var services = Services.init(&store, null);

    try store.family(.accounts).put("alice", "A1|alice|not-a-salt|not-a-hash|0|");
    try std.testing.expectError(error.InvalidRecord, services.identifyAccount("alice", "correct horse battery staple"));
}

test "account persists across store reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-persist.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;
        _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
        _ = try services.setAccount("alice", "correct horse battery staple", .{ .email = "alice@example.test" }, &scratch);
    }
    {
        var store = try openTestStore(tmp, "services-persist.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        const result = try services.accountInfo("ALICE");
        try std.testing.expectEqualStrings("alice@example.test", result.account_info.email.asSlice());
        _ = try services.identifyAccount("alice", "correct horse battery staple");
    }
}

test "recognize masks: add/match/list/delete and persist across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-recognize.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        try std.testing.expectEqual(Services.RecognizeAdd.added, try services.recognizeAdd("kain", "*!*@*.example.net"));
        try std.testing.expectEqual(Services.RecognizeAdd.added, try services.recognizeAdd("kain", "kain!*@host"));
        // case-insensitive account + mask dedupe
        try std.testing.expectEqual(Services.RecognizeAdd.already_present, try services.recognizeAdd("KAIN", "*!*@*.EXAMPLE.net"));
        try std.testing.expectEqual(Services.RecognizeAdd.invalid_mask, try services.recognizeAdd("kain", ""));

        try std.testing.expect(services.recognizeMatches("kain", "kain!user@gw.example.net"));
        try std.testing.expect(!services.recognizeMatches("kain", "kain!user@other.org"));
        try std.testing.expect(!services.recognizeMatches("nobody", "kain!user@gw.example.net"));

        try std.testing.expect(try services.recognizeDel("kain", "kain!*@host"));
        try std.testing.expect(!try services.recognizeDel("kain", "kain!*@host"));
    }
    {
        // reopen: the remaining mask survived durably; the deleted one did not.
        var store = try openTestStore(tmp, "services-recognize.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try std.testing.expect(services.recognizeMatches("kain", "anyone!x@host.example.net"));
        var lb: [512]u8 = undefined;
        const blob = services.recognizeBlob("kain", &lb);
        try std.testing.expect(std.mem.indexOf(u8, blob, "*!*@*.example.net") != null);
        try std.testing.expect(std.mem.indexOf(u8, blob, "kain!*@host") == null);
    }
}

test "account metadata: put/delete persist; restore via forEach across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-acctmeta.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try services.metadataPut("kain", "avatar", "https://x/a.png", "*");
        try services.metadataPut("kain", "display-name", "Kain", "*");
        try services.metadataDelete("kain", "avatar"); // remove one
    }
    {
        var store = try openTestStore(tmp, "services-acctmeta.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        var count: usize = 0;
        var ok_display = false;
        const Ctx = struct { count: *usize, ok: *bool };
        services.metadataForEach("KAIN", Ctx{ .count = &count, .ok = &ok_display }, struct {
            fn cb(c: Ctx, key: []const u8, value: []const u8, vis: []const u8) void {
                c.count.* += 1;
                if (std.mem.eql(u8, key, "display-name") and std.mem.eql(u8, value, "Kain") and std.mem.eql(u8, vis, "*")) c.ok.* = true;
            }
        }.cb);
        // avatar was deleted; only display-name survives, with value + visibility intact.
        try std.testing.expectEqual(@as(usize, 1), count);
        try std.testing.expect(ok_display);
    }
}

test "account silence: add/remove persist; restore via forEach across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-acctsilence.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try services.silencePersistAdd("kain", "*!*@spam.example");
        try services.silencePersistAdd("kain", "troll!*@*");
        try services.silencePersistAdd("KAIN", "*!*@SPAM.example"); // case-insensitive dup: no-op
        try services.silencePersistDel("kain", "troll!*@*");
    }
    {
        var store = try openTestStore(tmp, "services-acctsilence.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var count: usize = 0;
        var ok = false;
        const Ctx = struct { count: *usize, ok: *bool };
        services.silenceForEach("kain", Ctx{ .count = &count, .ok = &ok }, struct {
            fn cb(c: Ctx, mask: []const u8) void {
                c.count.* += 1;
                if (std.mem.eql(u8, mask, "*!*@spam.example")) c.ok.* = true;
            }
        }.cb);
        try std.testing.expectEqual(@as(usize, 1), count); // troll removed; one survives
        try std.testing.expect(ok);
    }
}

test "channelsForAccount: durable reverse access lookup (LISTCHANS)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-listchans.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another good passphrase here", &scratch);
    _ = try services.registerChannel("#orochi", "alice", &scratch);
    _ = try services.channelAccess("#orochi", "alice", "bob", .grant, .op, &scratch);

    var count: usize = 0;
    var found_op = false;
    const Ctx = struct { count: *usize, found: *bool };
    services.channelsForAccount("BOB", Ctx{ .count = &count, .found = &found_op }, struct {
        fn cb(c: Ctx, channel: []const u8, level: AccessLevel) void {
            c.count.* += 1;
            if (std.ascii.eqlIgnoreCase(channel, "#orochi") and level == .op) c.found.* = true;
        }
    }.cb);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expect(found_op);
}

test "channel bad-words: add/match/remove persist across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "services-chanbadwords.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try std.testing.expect(try services.chanBadwordAdd("#chan", "spam"));
        try std.testing.expect(try services.chanBadwordAdd("#chan", "scam"));
        try std.testing.expect(!try services.chanBadwordAdd("#CHAN", "SPAM")); // case-insensitive dup
        try std.testing.expect(services.chanBadwordMatches("#chan", "buy this SpAm now"));
        try std.testing.expect(!services.chanBadwordMatches("#chan", "a clean message"));
        try std.testing.expect(try services.chanBadwordDel("#chan", "spam"));
    }
    {
        var store = try openTestStore(tmp, "services-chanbadwords.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try std.testing.expect(!services.chanBadwordMatches("#chan", "buy this spam now")); // removed
        try std.testing.expect(services.chanBadwordMatches("#chan", "a scam here")); // survived
    }
}

test "keeptopic: enable/save/get persist across reopen; save is a no-op when off" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "services-keeptopic.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var buf: [128]u8 = undefined;
        // off by default; save does nothing while off
        try std.testing.expect(services.chanKeepTopicGet("#chan", &buf) == null);
        try services.chanKeepTopicSave("#chan", "ignored");
        try std.testing.expect(services.chanKeepTopicGet("#chan", &buf) == null);
        // enable then save
        try services.chanKeepTopicEnable("#chan", true);
        try services.chanKeepTopicSave("#chan", "the topic");
        const got = services.chanKeepTopicGet("#CHAN", &buf) orelse return error.TestUnexpectedResult; // case-insensitive
        try std.testing.expectEqualStrings("the topic", got);
    }
    {
        var store = try openTestStore(tmp, "services-keeptopic.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var buf: [128]u8 = undefined;
        const got = services.chanKeepTopicGet("#chan", &buf) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("the topic", got); // survived reopen
        try services.chanKeepTopicEnable("#chan", false);
        try std.testing.expect(services.chanKeepTopicGet("#chan", &buf) == null); // disabled -> gone
    }
}

test "channel transfer: only the founder may hand ownership to a registered account" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-chantransfer.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another good passphrase here", &scratch);
    _ = try services.registerChannel("#orochi", "alice", &scratch);

    try std.testing.expectError(error.Forbidden, services.transferChannel("#orochi", "bob", "bob", &scratch)); // not founder
    try std.testing.expectError(error.NotFound, services.transferChannel("#orochi", "alice", "carol", &scratch)); // unknown target
    const res = try services.transferChannel("#orochi", "alice", "bob", &scratch);
    try std.testing.expectEqualStrings("bob", res.registered_channel.founder.asSlice());
    // ownership moved: alice can no longer transfer
    try std.testing.expectError(error.Forbidden, services.transferChannel("#orochi", "alice", "alice", &scratch));
}

test "account email verification persists across store reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-email-verify.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;

        _ = try services.registerAccountWithEmail("Alice", "correct horse battery staple", "alice@example.test", false, &scratch);
        var info = try services.accountInfo("alice");
        try std.testing.expectEqualStrings("alice@example.test", info.account_info.email.asSlice());
        try std.testing.expect(!info.account_info.email_verified);

        try services.setAccountEmailPending("alice", "alice@example.test", "abc123", 10, &scratch);
    }
    {
        var store = try openTestStore(tmp, "services-email-verify.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;

        try std.testing.expectEqual(EmailVerifyResult.bad_token, try services.confirmAccountEmail("ALICE", "wrong", 11, &scratch));
        var info = try services.accountInfo("alice");
        try std.testing.expect(!info.account_info.email_verified);

        try std.testing.expectEqual(EmailVerifyResult.verified, try services.confirmAccountEmail("ALICE", "abc123", 12, &scratch));
        info = try services.accountInfo("alice");
        try std.testing.expectEqualStrings("alice@example.test", info.account_info.email.asSlice());
        try std.testing.expect(info.account_info.email_verified);
        try std.testing.expectEqual(EmailVerifyResult.no_pending, try services.confirmAccountEmail("ALICE", "abc123", 13, &scratch));
    }
}

test "certfp binding persists across store reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const fp = "a" ** 64; // 64-hex placeholder fingerprint

    {
        var store = try openTestStore(tmp, "services-certfp.wal");
        defer store.deinit();
        var binds = certfp_bind_mod.CertfpBindStore.init(std.testing.allocator);
        defer binds.deinit();
        var services = Services.init(&store, null);
        services.attachCertfpBinds(&binds);
        try services.bindCertfp("alice", fp);
        try std.testing.expectEqualStrings("alice", services.accountForCertfp(fp).?);
    }
    {
        // Reopen with a COLD in-memory cache: the binding must come from the
        // durable store via the lazy fallback.
        var store = try openTestStore(tmp, "services-certfp.wal");
        defer store.deinit();
        var binds = certfp_bind_mod.CertfpBindStore.init(std.testing.allocator);
        defer binds.deinit();
        var services = Services.init(&store, null);
        services.attachCertfpBinds(&binds);
        try std.testing.expectEqualStrings("alice", services.accountForCertfp(fp).?);
        // An unknown fingerprint still returns null.
        try std.testing.expect(services.accountForCertfp("b" ** 64) == null);
    }
}

test "certfp list and delete enforce account ownership" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const fp_alice = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const fp_bob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    var store = try openTestStore(tmp, "services-certfp-list.wal");
    defer store.deinit();
    var binds = certfp_bind_mod.CertfpBindStore.init(std.testing.allocator);
    defer binds.deinit();
    var services = Services.init(&store, null);
    services.attachCertfpBinds(&binds);

    try services.bindCertfp("alice", fp_alice);
    try services.bindCertfp("bob", fp_bob);

    var listed_buf: [4][]const u8 = undefined;
    var listed = try services.listCertfps("alice", listed_buf[0..]);
    try std.testing.expectEqual(@as(usize, 1), listed.len);
    try std.testing.expectEqualStrings(fp_alice, listed[0]);

    try std.testing.expectError(error.Forbidden, services.deleteCertfp("alice", fp_bob));
    try services.deleteCertfp("alice", fp_alice);
    listed = try services.listCertfps("alice", listed_buf[0..]);
    try std.testing.expectEqual(@as(usize, 0), listed.len);
    try std.testing.expect(services.accountForCertfp(fp_alice) == null);
}

test "account lifecycle flags round-trip and persist" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-account-lifecycle.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;

        _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
        var info = try services.setAccountSuspended("alice", true, &scratch);
        try std.testing.expect(info.suspended());
        try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", "correct horse battery staple"));

        info = try services.setAccountSuspended("alice", false, &scratch);
        try std.testing.expect(!info.suspended());
        _ = try services.identifyAccount("alice", "correct horse battery staple");

        info = try services.setAccountForbidden("alice", true, &scratch);
        try std.testing.expect(info.forbidden());
        info = try services.setAccountNoExpire("alice", true, &scratch);
        try std.testing.expect(info.noexpire());

        const reserved = try services.setAccountForbidden("Reserved", true, &scratch);
        try std.testing.expect(!reserved.registered);
        try std.testing.expect(reserved.forbidden());
        try std.testing.expectError(error.Forbidden, services.registerAccount("reserved", "correct horse battery staple", &scratch));
    }
    {
        var store = try openTestStore(tmp, "services-account-lifecycle.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        const info = try services.adminAccountInfo("ALICE");
        try std.testing.expect(info.registered);
        try std.testing.expect(info.forbidden());
        try std.testing.expect(info.noexpire());
        try std.testing.expect(!info.suspended());

        const reserved = try services.adminAccountInfo("reserved");
        try std.testing.expect(!reserved.registered);
        try std.testing.expect(reserved.forbidden());
    }
}

test "setAccount refuses password-holder lifecycle flag changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-accountset-lifecycle-denied.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    try std.testing.expectError(error.Forbidden, services.setAccount("alice", "correct horse battery staple", .{ .flags = account_flag_suspended }, &scratch));
    try std.testing.expectError(error.Forbidden, services.setAccount("alice", "correct horse battery staple", .{ .flags = account_flag_noexpire }, &scratch));

    const display_pref: u32 = 1 << 8;
    const changed = try services.setAccount("alice", "correct horse battery staple", .{ .flags = display_pref }, &scratch);
    try std.testing.expectEqual(display_pref, changed.set_account.flags);

    var admin = try services.setAccountNoExpire("alice", true, &scratch);
    try std.testing.expect(admin.noexpire());
    try std.testing.expectError(error.Forbidden, services.setAccount("alice", "correct horse battery staple", .{ .flags = display_pref }, &scratch));

    const with_pref = try services.setAccount("alice", "correct horse battery staple", .{ .flags = display_pref | account_flag_noexpire }, &scratch);
    try std.testing.expectEqual(display_pref | account_flag_noexpire, with_pref.set_account.flags);
    admin = try services.adminAccountInfo("alice");
    try std.testing.expect(admin.noexpire());
}

test "ghostAccount authenticates account separately from target nick" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-ghost-nick.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    const ghosted = try services.ghostAccount("alice", "correct horse battery staple", "AwayNick");
    try std.testing.expectEqualStrings("alice", ghosted.ghosted.account.asSlice());
    try std.testing.expectEqualStrings("AwayNick", ghosted.ghosted.nick.asSlice());
    try std.testing.expectError(error.NotFound, services.ghostAccount("AwayNick", "correct horse battery staple", "AwayNick"));
}

test "scram credentials persist across store reopen via loader" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-scram.wal");
        defer store.deinit();
        var scram = ScramStore.init(std.testing.allocator);
        defer scram.deinit();
        var services = Services.init(&store, null);
        services.attachScramStore(&scram);
        var scratch: [record_max]u8 = undefined;
        _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
        try std.testing.expect(scram.lookup("alice") != null);
    }
    {
        // Reopen with a COLD in-memory SCRAM store + the durable loader.
        var store = try openTestStore(tmp, "services-scram.wal");
        defer store.deinit();
        var scram = ScramStore.init(std.testing.allocator);
        defer scram.deinit();
        var services = Services.init(&store, null);
        services.attachScramStore(&scram);
        scram.setLoader(services.scramLoader());
        try std.testing.expect(scram.lookup("alice") == null); // cold cache
        try std.testing.expect(scram.resolve("alice") != null); // backfilled from disk
        try std.testing.expect(scram.resolve("nobody") == null);
    }
}

test "channel register and access grant" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-channel.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
    const registered = try services.registerChannel("#Orochi", "alice", &scratch);
    try std.testing.expectEqualStrings("#orochi", registered.registered_channel.name.asSlice());
    try std.testing.expectEqualStrings("alice", registered.registered_channel.founder.asSlice());

    const granted = try services.channelAccess("#orochi", "alice", "bob", .grant, .op, &scratch);
    try std.testing.expectEqual(AccessLevel.op, granted.access.level);

    const queried = try services.channelAccess("#orochi", "bob", "bob", .query, .voice, &scratch);
    try std.testing.expectEqual(AccessLevel.op, queried.access.level);
}

test "channel mlock access akick and ward replay from durable services" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-live-replay.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;

        _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
        _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
        _ = try services.registerChannel("#Orochi", "alice", &scratch);
        _ = try services.setChannel("#orochi", "alice", .{ .mlock = "+nt-k" }, &scratch);
        _ = try services.channelAccess("#orochi", "alice", "bob", .grant, .op, &scratch);
        _ = try services.channelAkick("#orochi", "alice", "Bad!*@*", .add, "go away", &scratch);
        try services.persistWard(.{
            .match = "mask",
            .pattern = "Bad!*@*",
            .scope = "node",
            .action = "expel",
            .reason = "spam",
            .setter = "alice",
            .created_ms = 111,
            .expires_ms = 222,
        }, &scratch);
    }

    {
        var store = try openTestStore(tmp, "services-live-replay.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        const info = try services.channelInfo("#orochi");
        try std.testing.expectEqualStrings("+nt-k", info.channel_info.mlock.asSlice());
        try std.testing.expectEqual(AccessLevel.op, (try services.channelAccessLevelFor("#orochi", "bob")).?);

        const ReplayRecorder = struct {
            channel: [channel_max]u8 = [_]u8{0} ** channel_max,
            channel_len: usize = 0,
            mlock: [mlock_max]u8 = [_]u8{0} ** mlock_max,
            mlock_len: usize = 0,
            akick_channel: [channel_max]u8 = [_]u8{0} ** channel_max,
            akick_channel_len: usize = 0,
            akick_mask: [mask_max]u8 = [_]u8{0} ** mask_max,
            akick_mask_len: usize = 0,
            akick_reason: [reason_max]u8 = [_]u8{0} ** reason_max,
            akick_reason_len: usize = 0,
            ward_match: [16]u8 = [_]u8{0} ** 16,
            ward_match_len: usize = 0,
            ward_pattern: [mask_max]u8 = [_]u8{0} ** mask_max,
            ward_pattern_len: usize = 0,
            ward_reason: [reason_max]u8 = [_]u8{0} ** reason_max,
            ward_reason_len: usize = 0,

            fn copyInto(dst: []u8, len: *usize, value: []const u8) ServiceError!void {
                if (value.len > dst.len) return error.BufferTooSmall;
                @memcpy(dst[0..value.len], value);
                len.* = value.len;
            }

            fn onChannel(ctx: *anyopaque, channel: []const u8, mlock: []const u8) ServiceError!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                try copyInto(&self.channel, &self.channel_len, channel);
                try copyInto(&self.mlock, &self.mlock_len, mlock);
            }

            fn onAkick(ctx: *anyopaque, channel: []const u8, mask: []const u8, reason: []const u8, _: []const u8) ServiceError!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                try copyInto(&self.akick_channel, &self.akick_channel_len, channel);
                try copyInto(&self.akick_mask, &self.akick_mask_len, mask);
                try copyInto(&self.akick_reason, &self.akick_reason_len, reason);
            }

            fn onWard(ctx: *anyopaque, ward: ReplayWard) ServiceError!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                try copyInto(&self.ward_match, &self.ward_match_len, ward.match);
                try copyInto(&self.ward_pattern, &self.ward_pattern_len, ward.pattern);
                try copyInto(&self.ward_reason, &self.ward_reason_len, ward.reason);
            }
        };
        var recorder = ReplayRecorder{};
        const summary = try services.replayLiveState(.{
            .ptr = &recorder,
            .channel = ReplayRecorder.onChannel,
            .akick = ReplayRecorder.onAkick,
            .ward = ReplayRecorder.onWard,
        });
        try std.testing.expectEqual(@as(usize, 1), summary.channels);
        try std.testing.expectEqual(@as(usize, 1), summary.mlocks);
        try std.testing.expectEqual(@as(usize, 1), summary.akicks);
        try std.testing.expectEqual(@as(usize, 1), summary.wards);
        try std.testing.expectEqualStrings("#orochi", recorder.channel[0..recorder.channel_len]);
        try std.testing.expectEqualStrings("+nt-k", recorder.mlock[0..recorder.mlock_len]);
        try std.testing.expectEqualStrings("#orochi", recorder.akick_channel[0..recorder.akick_channel_len]);
        try std.testing.expectEqualStrings("Bad!*@*", recorder.akick_mask[0..recorder.akick_mask_len]);
        try std.testing.expectEqualStrings("go away", recorder.akick_reason[0..recorder.akick_reason_len]);
        try std.testing.expectEqualStrings("mask", recorder.ward_match[0..recorder.ward_match_len]);
        try std.testing.expectEqualStrings("Bad!*@*", recorder.ward_pattern[0..recorder.ward_pattern_len]);
        try std.testing.expectEqualStrings("spam", recorder.ward_reason[0..recorder.ward_reason_len]);
    }
}

test "SACCESS entries persist across a WAL reopen and replay" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-saccess-replay.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;

        try services.persistSaccess(.{ .entry_type = "DENY", .mask = "bad!*@*", .duration = 60, .reason = "abuse" }, &scratch);
        try services.persistSaccess(.{ .entry_type = "GRANT", .mask = "trusted!*@*" }, &scratch);
        try services.persistSaccess(.{ .entry_type = "GAG", .mask = "noisy!*@*" }, &scratch);
        // A deleted entry must not survive the reopen.
        try services.persistSaccess(.{ .entry_type = "DENY", .mask = "temp!*@*" }, &scratch);
        try services.deleteSaccess("DENY", "temp!*@*", &scratch);
        // A re-add of the same type+mask is idempotent (overwrite, not duplicate).
        try services.persistSaccess(.{ .entry_type = "GAG", .mask = "noisy!*@*", .reason = "updated" }, &scratch);
    }

    {
        // Reopen the WAL — this is the actual "restart": state comes only from disk.
        var store = try openTestStore(tmp, "services-saccess-replay.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        const Recorder = struct {
            count: usize = 0,
            deny_mask: [256]u8 = [_]u8{0} ** 256,
            deny_mask_len: usize = 0,
            deny_duration: u64 = 0,
            deny_reason: [512]u8 = [_]u8{0} ** 512,
            deny_reason_len: usize = 0,
            saw_grant: bool = false,
            saw_gag: bool = false,
            gag_reason: [512]u8 = [_]u8{0} ** 512,
            gag_reason_len: usize = 0,
            saw_temp: bool = false,

            fn onChannel(_: *anyopaque, _: []const u8, _: []const u8) ServiceError!void {}

            fn onSaccess(ctx: *anyopaque, entry: ReplaySaccess) ServiceError!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                self.count += 1;
                if (std.mem.eql(u8, entry.entry_type, "DENY") and std.mem.eql(u8, entry.mask, "bad!*@*")) {
                    @memcpy(self.deny_mask[0..entry.mask.len], entry.mask);
                    self.deny_mask_len = entry.mask.len;
                    self.deny_duration = entry.duration;
                    @memcpy(self.deny_reason[0..entry.reason.len], entry.reason);
                    self.deny_reason_len = entry.reason.len;
                }
                if (std.mem.eql(u8, entry.entry_type, "DENY") and std.mem.eql(u8, entry.mask, "temp!*@*")) self.saw_temp = true;
                if (std.mem.eql(u8, entry.entry_type, "GRANT")) self.saw_grant = true;
                if (std.mem.eql(u8, entry.entry_type, "GAG")) {
                    self.saw_gag = true;
                    @memcpy(self.gag_reason[0..entry.reason.len], entry.reason);
                    self.gag_reason_len = entry.reason.len;
                }
            }
        };
        var recorder = Recorder{};
        const summary = try services.replayLiveState(.{
            .ptr = &recorder,
            .channel = Recorder.onChannel,
            .saccess = Recorder.onSaccess,
        });

        // 3 survivors: DENY bad, GRANT trusted, GAG noisy (temp DENY was deleted,
        // and the duplicate GAG add overwrote rather than added).
        try std.testing.expectEqual(@as(usize, 3), summary.saccesses);
        try std.testing.expectEqual(@as(usize, 3), recorder.count);
        try std.testing.expectEqualStrings("bad!*@*", recorder.deny_mask[0..recorder.deny_mask_len]);
        try std.testing.expectEqual(@as(u64, 60), recorder.deny_duration);
        try std.testing.expectEqualStrings("abuse", recorder.deny_reason[0..recorder.deny_reason_len]);
        try std.testing.expect(recorder.saw_grant);
        try std.testing.expect(recorder.saw_gag);
        try std.testing.expectEqualStrings("updated", recorder.gag_reason[0..recorder.gag_reason_len]);
        try std.testing.expect(!recorder.saw_temp);
    }
}

test "SACCESS codec round-trips and rejects malformed records" {
    var key_buf: [saccess_key_max]u8 = undefined;
    const key = try saccessKey("DENY", "bad!*@*", &key_buf);
    try std.testing.expectEqualStrings("saccess:DENY:bad!*@*", key);

    var val_buf: [saccess_value_max]u8 = undefined;
    const encoded = try encodeSaccess(.{ .entry_type = "GAG", .mask = "x!*@*", .duration = 7, .reason = "hush" }, &val_buf);
    const decoded = try decodeSaccess(encoded);
    try std.testing.expectEqualStrings("GAG", decoded.entry_type);
    try std.testing.expectEqualStrings("x!*@*", decoded.mask);
    try std.testing.expectEqual(@as(u64, 7), decoded.duration);
    try std.testing.expectEqualStrings("hush", decoded.reason);

    // A pipe in a field would corrupt the delimiter; encode rejects it.
    try std.testing.expectError(error.InvalidValue, encodeSaccess(.{ .entry_type = "DENY", .mask = "a|b", .duration = 0, .reason = "" }, &val_buf));
    // Wrong version / truncated record is rejected on decode.
    try std.testing.expectError(error.InvalidRecord, decodeSaccess("S9|DENY|m|0|"));
    try std.testing.expectError(error.InvalidRecord, decodeSaccess("S1|DENY"));
}

test "non-admin channel mutations are forbidden" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-channel-forbidden.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
    _ = try services.registerAccount("carol", "carol correct battery staple", &scratch);
    _ = try services.registerChannel("#orochi", "alice", &scratch);

    try std.testing.expectError(error.Forbidden, services.channelAccess("#orochi", "bob", "carol", .grant, .op, &scratch));
    try std.testing.expectError(error.Forbidden, services.channelAccess("#orochi", "bob", "carol", .revoke, .op, &scratch));
    try std.testing.expectError(error.Forbidden, services.channelAkick("#orochi", "bob", "*!*@bad.test", .add, "bad", &scratch));
    try std.testing.expectError(error.Forbidden, services.channelAkick("#orochi", "bob", "*!*@bad.test", .remove, "", &scratch));
}

test "missing access and akick removals return not found" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-channel-missing-remove.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
    _ = try services.registerChannel("#orochi", "alice", &scratch);

    try std.testing.expectError(error.NotFound, services.channelAccess("#orochi", "alice", "bob", .revoke, .op, &scratch));
    try std.testing.expectError(error.NotFound, services.channelAkick("#orochi", "alice", "*!*@missing.test", .remove, "", &scratch));
}

test "drop account and channel" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-drop.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerChannel("#orochi", "alice", &scratch);
    _ = try services.dropChannel("#orochi", "alice");
    try std.testing.expectError(error.NotFound, services.channelInfo("#orochi"));

    _ = try services.dropAccount("alice", "correct horse battery staple");
    try std.testing.expectError(error.NotFound, services.accountInfo("alice"));
}

test "state hook fires on channel register and drop" {
    const Recorder = struct {
        created: [64]u8 = undefined,
        created_len: usize = 0,
        dropped: [64]u8 = undefined,
        dropped_len: usize = 0,

        fn onCreate(ctx: *anyopaque, channel: []const u8) ServiceError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            @memcpy(self.created[0..channel.len], channel);
            self.created_len = channel.len;
        }
        fn onDrop(ctx: *anyopaque, channel: []const u8) ServiceError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            @memcpy(self.dropped[0..channel.len], channel);
            self.dropped_len = channel.len;
        }
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-hook.wal");
    defer store.deinit();

    var rec = Recorder{};
    var services = Services.init(&store, .{
        .ptr = &rec,
        .create_channel = Recorder.onCreate,
        .drop_channel = Recorder.onDrop,
    });
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerChannel("#Orochi", "alice", &scratch);
    // The canonical (lowercased) channel name is bridged to the live world.
    try std.testing.expectEqualStrings("#orochi", rec.created[0..rec.created_len]);
    try std.testing.expectEqual(@as(usize, 0), rec.dropped_len);

    _ = try services.dropChannel("#orochi", "alice");
    try std.testing.expectEqualStrings("#orochi", rec.dropped[0..rec.dropped_len]);
}

test "Config default preserves historical pbkdf2 rounds" {
    const cfg = Config{};
    try std.testing.expectEqual(default_pbkdf2_rounds, cfg.pbkdf2_rounds);
    try std.testing.expectEqual(@as(u32, 100_000), cfg.pbkdf2_rounds);
}

test "Config.applyToml overlays accounts.pbkdf2_rounds" {
    var doc = try toml.parse(std.testing.allocator, "[accounts]\npbkdf2_rounds = 250000\n");
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(u32, 250_000), cfg.pbkdf2_rounds);
}

test "Config.applyToml leaves defaults when keys absent" {
    var doc = try toml.parse(std.testing.allocator, "[server]\nname = \"x\"\n");
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(default_pbkdf2_rounds, cfg.pbkdf2_rounds);
}

test "Config.applyToml ignores out-of-range rounds" {
    var doc = try toml.parse(std.testing.allocator, "[accounts]\npbkdf2_rounds = 0\n");
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(default_pbkdf2_rounds, cfg.pbkdf2_rounds);
}

test "registerAccount mirrors SCRAM credentials when a store is attached" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-scram-mirror.wal");
    defer store.deinit();

    var scram = ScramStore.init(std.testing.allocator);
    defer scram.deinit();

    var services = Services.init(&store, null);
    services.attachScramStore(&scram);
    var scratch: [record_max]u8 = undefined;

    // Registration provisions both the PLAIN record and the SCRAM mirror.
    _ = try services.registerAccount("Alice", "correct horse battery staple", &scratch);
    const record = scram.lookup("alice");
    try std.testing.expect(record != null);
    try std.testing.expect(record.?.salt.len != 0);
    // The PLAIN path still verifies against the persistent account record.
    _ = try services.identifyAccount("alice", "correct horse battery staple");
}

test "registerAccount without a SCRAM store leaves SCRAM unprovisioned" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-scram-absent.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    // No store attached: registration succeeds with historical behaviour intact.
    const registered = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    try std.testing.expectEqualStrings("alice", registered.registered_account.name.asSlice());
    try std.testing.expect(services.scram == null);
}

test "initWithConfig threads custom rounds into hashing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-cfg-rounds.wal");
    defer store.deinit();
    var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 4096 });
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("Bob", "correct horse battery staple", &scratch);
    const identified = try services.identifyAccount("bob", "correct horse battery staple");
    try std.testing.expectEqualStrings("bob", identified.identified.name.asSlice());
}

const ServicesMtCtx = struct {
    services: *Services,
    writer_id: usize,
    iters: usize,
    failures: *std.atomic.Value(u32),

    fn accountName(out: *[account_max]u8, writer_id: usize, i: usize) []const u8 {
        return std.fmt.bufPrint(out, "svc{d}_{d}", .{ writer_id, i }) catch unreachable;
    }

    fn writer(ctx: *ServicesMtCtx) void {
        var scratch: [record_max]u8 = undefined;
        var name_buf: [account_max]u8 = undefined;
        var i: usize = 0;
        while (i < ctx.iters) : (i += 1) {
            const name = accountName(&name_buf, ctx.writer_id, i);
            _ = ctx.services.registerAccount(name, "correct horse battery staple", &scratch) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            _ = ctx.services.setAccount(name, "correct horse battery staple", .{ .email = "thread@example.test" }, &scratch) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
        }
    }

    fn reader(ctx: *ServicesMtCtx) void {
        var i: usize = 0;
        while (i < ctx.iters * 4) : (i += 1) {
            _ = ctx.services.identifyAccount("seed", "correct horse battery staple") catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            const info = ctx.services.accountInfo("seed") catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            if (!std.mem.eql(u8, info.account_info.name.asSlice(), "seed")) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
            _ = ctx.services.ghostAccount("seed", "correct horse battery staple", "SeedNick") catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
        }
    }
};

test "Services concurrent account writers and readers preserve account records" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-concurrent.wal");
    defer store.deinit();
    var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 16 });
    var scratch: [record_max]u8 = undefined;
    _ = try services.registerAccount("seed", "correct horse battery staple", &scratch);

    const writers = 4;
    const readers = 4;
    const iters = 16;
    var failures = std.atomic.Value(u32).init(0);
    var ctxs: [writers]ServicesMtCtx = undefined;
    for (0..writers) |i| {
        ctxs[i] = .{ .services = &services, .writer_id = i, .iters = iters, .failures = &failures };
    }

    var threads: [writers + readers]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();
    for (0..writers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, ServicesMtCtx.writer, .{&ctxs[i]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (0..readers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, ServicesMtCtx.reader, .{&ctxs[i % writers]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();

    try std.testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    var name_buf: [account_max]u8 = undefined;
    for (0..writers) |w| {
        for (0..iters) |i| {
            const name = ServicesMtCtx.accountName(&name_buf, w, i);
            const info = try services.accountInfo(name);
            try std.testing.expectEqualStrings("thread@example.test", info.account_info.email.asSlice());
        }
    }
}
