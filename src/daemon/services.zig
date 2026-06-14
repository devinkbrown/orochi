//! In-process IRC services over OroStore with typed results and no IRC I/O.
const std = @import("std");

const store_mod = @import("store.zig");
const toml = @import("../proto/toml.zig");
const scram_store_mod = @import("scram_store.zig");
const sasl = @import("../proto/sasl.zig");
const certfp_bind_mod = @import("certfp_bind.zig");
const rwlock = @import("../substrate/rwlock.zig");

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
const access_prefix = "chanaccess:";
const akick_prefix = "chanakick:";
const verify_prefix = "acctverify:";
const ward_prefix = "ward:";
const missing_account_salt: [salt_len]u8 = .{
    0x6d, 0x69, 0x7a, 0x75, 0x63, 0x68, 0x69, 0x2d,
    0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
};

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

pub const AccountSetField = union(enum) { email: []const u8, flags: u32 };
pub const ChannelSetField = union(enum) { flags: u32, mlock: []const u8 };
pub const AccessAction = enum { query, grant, revoke };
pub const AkickAction = enum { add, remove, query };
pub const AccountRef = struct { name: AccountName };
pub const ChannelRef = struct { name: ChannelName };

pub const account_flag_suspended: u32 = 1 << 0;
pub const account_flag_forbidden: u32 = 1 << 1;
pub const account_flag_noexpire: u32 = 1 << 2;
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

pub const LiveReplaySummary = struct {
    channels: usize = 0,
    mlocks: usize = 0,
    akicks: usize = 0,
    wards: usize = 0,
};

pub const LiveReplaySink = struct {
    ptr: *anyopaque,
    channel: *const fn (ctx: *anyopaque, channel: []const u8, mlock: []const u8) ServiceError!void,
    akick: ?*const fn (ctx: *anyopaque, channel: []const u8, mask: []const u8, reason: []const u8, setter: []const u8) ServiceError!void = null,
    ward: ?*const fn (ctx: *anyopaque, ward: ReplayWard) ServiceError!void = null,
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
    /// account. Best-effort; the in-memory SCRAM store is authoritative live.
    fn persistScram(self: *Services, scram: *ScramStore, account: []const u8) void {
        const rec = scram.lookup(account) orelse return;
        var vbuf: [ScramStore.serialized_max]u8 = undefined;
        const value = ScramStore.serializeRecord(rec, &vbuf) orelse return;
        var kb: [scram_key_max]u8 = undefined;
        const key = scramKey(&kb, account) orelse return;
        self.store.family(.props).put(key, value) catch {};
    }

    /// A backfill loader for the SCRAM store that reads this services' durable
    /// mirror, so a SCRAM login resolves after a restart. The returned record's
    /// salt borrows store memory and is copied by the SCRAM store before caching.
    pub fn scramLoader(self: *Services) ScramStore.Loader {
        return .{ .ptr = self, .loadFn = scramLoadThunk };
    }

    fn scramLoadThunk(ptr: *anyopaque, account: []const u8) ?sasl.ScramRecord {
        const self: *Services = @ptrCast(@alignCast(ptr));
        var kb: [scram_key_max]u8 = undefined;
        const key = scramKey(&kb, account) orelse return null;
        const bytes = self.store.family(.props).get(key) orelse return null;
        return ScramStore.deserializeRecord(bytes);
    }

    /// The account a certfp is bound to, if any (SASL EXTERNAL verification).
    /// Falls back to the durable store when the in-memory cache is cold (e.g.
    /// immediately after a restart, before any CERTADD has repopulated it).
    pub fn accountForCertfp(self: *const Services, fingerprint: []const u8) ?[]const u8 {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        return @constCast(self).accountForCertfpUnlocked(fingerprint) catch null;
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
