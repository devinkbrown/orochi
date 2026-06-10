//! Central, config-driven IRC protocol policy limits.
//!
//! This module is the SINGLE authoritative source for the IRC protocol layer's
//! tunable policy values: ISUPPORT-advertised caps, IRCv3 feature sizing,
//! chathistory/read-marker sizing, resolver tuning, and nick-reservation /
//! list-sizing limits.
//!
//! Design contract:
//!   - Every field defaults to the historical hardcoded value, so a `Limits`
//!     value left untouched reproduces the previous behaviour exactly.
//!   - `applyToml` overlays values found under the `[limits]`, `[ircv3]`,
//!     `[history]`, `[dns]`, `[flood]`, and `[server]` tables of a parsed TOML
//!     document. Missing keys are left at their default; out-of-range or
//!     wrong-typed keys are ignored (the previous value is kept).
//!   - The module is PURE: it performs no I/O. The orchestrator parses the
//!     document and calls `applyToml`, then derives per-module `Params` and the
//!     ISUPPORT token surface from the resulting struct.
//!
//! This module performs no allocation and reads the system clock never.

const std = @import("std");
const toml = @import("toml.zig");

/// Inclusive `[min, max]` clamp helper used by `applyToml`.
fn clampU(value: u64, lo: u64, hi: u64) u64 {
    return @min(@max(value, lo), hi);
}

/// Bounded string buffer for string-valued policy tokens whose content may be
/// overridden from config (CHANTYPES, NETWORK, CASEMAPPING, ...). Fixed
/// capacity keeps `Limits` allocation-free and trivially copyable.
pub fn BoundedString(comptime cap: usize) type {
    return struct {
        const Self = @This();
        buf: [cap]u8 = undefined,
        len: usize = 0,

        pub fn fromLiteral(comptime literal: []const u8) Self {
            comptime std.debug.assert(literal.len <= cap);
            var self = Self{};
            @memcpy(self.buf[0..literal.len], literal);
            self.len = literal.len;
            return self;
        }

        pub fn set(self: *Self, bytes: []const u8) void {
            if (bytes.len > cap) return; // ignore over-long override; keep prior
            @memcpy(self.buf[0..bytes.len], bytes);
            self.len = bytes.len;
        }

        pub fn slice(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }
    };
}

const Str = BoundedString(96);

/// Central policy-limit configuration. All numeric fields are `u32` (well below
/// any 64-bit concern) except where a wider/narrower width is required by the
/// consuming API; consumers `@intCast`/widen as needed.
pub const Limits = struct {
    // ---- [limits] : ISUPPORT-advertised identifier/length caps -------------
    nick_len: u32 = 64,
    channel_len: u32 = 64,
    topic_len: u32 = 512,
    away_len: u32 = 390,
    user_len: u32 = 64,
    host_len: u32 = 255,
    server_name_len: u32 = 255,
    realname_len: u32 = 512,
    reason_len: u32 = 512,
    message_len: u32 = 512,
    source_len: u32 = 512,

    monitor_targets: u32 = 512,
    chan_limit: u32 = 100,
    max_ban_list: u32 = 100,
    max_except_list: u32 = 100,
    max_invex_list: u32 = 100,
    modes_per_line: u32 = 4,

    // String-valued ISUPPORT policy tokens.
    chantypes: Str = Str.fromLiteral("#&"),
    prefix: Str = Str.fromLiteral("(qaohv)~&@%+"),
    chanmodes: Str = Str.fromLiteral("b,k,l,imnpst"),
    casemapping: Str = Str.fromLiteral("ascii"),
    network: Str = Str.fromLiteral("Orochi"),
    elist: Str = Str.fromLiteral("CMNTU"),
    statusmsg: Str = Str.fromLiteral("~&@%+"),
    targmax: Str = Str.fromLiteral("JOIN:,WHOIS:1,PRIVMSG:,NOTICE:,MONITOR:"),
    excepts_mode: Str = Str.fromLiteral("e"),
    invex_mode: Str = Str.fromLiteral("I"),
    extban: Str = Str.fromLiteral("$,acgmrz"),
    account_extban: Str = Str.fromLiteral("a"),
    isupport_trailing: Str = Str.fromLiteral("are supported by this server"),
    channel_prefixes: Str = Str.fromLiteral("#+&!"),

    // ---- [limits] : per-feature sizing ------------------------------------
    away_max_clients: u32 = 4096,
    target_len_128: u32 = 128,
    whisper_recipients: u32 = 16,
    account_len: u32 = 32,
    account_email_len: u32 = 96,
    password_min: u32 = 8,
    password_max: u32 = 512,
    account_code_len: u32 = 128,
    email_local_len: u32 = 64,
    email_domain_len: u32 = 255,
    email_total_len: u32 = 254,
    service_nick_len: u32 = 32,
    service_target_nick_len: u32 = 32,
    list_max_filters: u32 = 16,
    list_mask_len: u32 = 128,
    whowas_max_entries: u32 = 20,
    who_selector_fields: u32 = 16,
    whox_token_len: u32 = 32,

    // ---- [ircv3] : IRCX advertised caps -----------------------------------
    ircx_max_prop: u32 = 512,
    ircx_max_access: u32 = 128,
    ircx_max_codepage: u32 = 0,
    ircx_max_language: u32 = 0,

    // ---- [ircv3] : caps / multiline / monitor / metadata ------------------
    cap_reply_body: u32 = 500,
    multiline_max_bytes: u32 = 40_000,
    multiline_max_lines: u32 = 64,
    multiline_ref_len: u32 = 64,
    multiline_target_len: u32 = 128,
    label_len: u32 = 64,
    label_batch_ref_len: u32 = 64,
    monitor_reply_target_bytes: u32 = 400,
    ext_monitor_verb_len: u32 = 32,
    ext_monitor_param_len: u32 = 512,
    ext_monitor_account_len: u32 = 64,
    ext_monitor_meta_key_len: u32 = 64,
    ext_monitor_meta_value_len: u32 = 512,
    metadata_entity_len: u32 = 128,
    metadata_key_len: u32 = 64,
    metadata_value_len: u32 = 512,
    metadata_max_keys: u32 = 64,
    metadata_max_subscriptions: u32 = 64,
    metadata_max_targets: u32 = 1024,

    // ---- [ircv3] : SASL ---------------------------------------------------
    sasl_authenticate_payload: u32 = 512,
    sasl_scram_message: u32 = 512,
    sasl_scram_username: u32 = 128,
    sasl_scram_nonce: u32 = 128,
    sasl_scram_salt: u32 = 128,
    sasl_authenticate_chunk: u32 = 400,
    sasl_external_payload: u32 = 400,
    sasl_anonymous_trace_len: u32 = 255,
    sasl_scram_iterations: u32 = 4096,

    // ---- [ircv3] : STS / cloak / IRCX detail ------------------------------
    sts_value_len: u32 = 96,
    sts_preload_host_len: u32 = 255,
    sts_preload_max_entries: u32 = 4096,
    sts_preload_min_duration: u32 = 1,
    sts_max_age_secs: u32 = 2_592_000,
    cloak_hostname_len: u32 = 253,

    ircx_prop_name_len: u32 = 64,
    ircx_prop_value_len: u32 = 512,
    ircx_entity_id_len: u32 = 128,
    ircx_access_mask_len: u32 = 128,
    ircx_max_entities: u32 = 1024,
    ircx_props_per_entity: u32 = 64,
    ircx_prop_owner_len: u32 = 128,
    ircx_prop_request_keys: u32 = 16,
    ircx_access_max_entries: u32 = 256,
    ircx_access_reason_len: u32 = 256,
    ircx_duration_digits: u32 = 20,
    ircx_modex_max_changes: u32 = 16,
    ircx_modex_name_len: u32 = 64,
    ircx_modex_target_len: u32 = 160,
    ircx_saccess_reason_len: u32 = 256,

    // ---- [history] : chathistory / read-marker / msgedit ------------------
    history_max_messages_advertised: u32 = 1000,
    history_page_max: u32 = 50,
    history_target_len: u32 = 128,
    history_msgid_len: u32 = 128,
    history_batch_ref_len: u32 = 64,
    history_sender_len: u32 = 256,
    read_marker_max_entries: u32 = 1024,
    read_marker_owner_len: u32 = 128,
    read_marker_target_len: u32 = 128,
    msgedit_msgid_len: u32 = 255,
    reaction_len: u32 = 128,
    msgedit_text_len: u32 = 1024,
    activity_reaction_len: u32 = 64,

    // ---- [dns] : resolver tuning ------------------------------------------
    dns_ndots: u32 = 1,
    dns_timeout_secs: u32 = 5,
    dns_attempts: u32 = 2,
    dns_max_nameservers: u32 = 4,
    dns_max_search: u32 = 6,
    dns_max_domain_len: u32 = 253,
    dns_max_cache_addrs: u32 = 8,
    dns_max_answers: u32 = 8,

    // ---- [flood] : nick reservation / accept / silence sizing -------------
    nick_quit_delay_secs: u32 = 60,
    nick_change_delay_secs: u32 = 30,
    nick_max_holds: u32 = 4096,
    nick_note_len: u32 = 256,
    accept_max_owners: u32 = 1024,
    accept_entries_per_owner: u32 = 64,
    silence_masks_per_owner: u32 = 32,
    silence_ops_per_command: u32 = 32,

    // ---- [server] : clock skew --------------------------------------------
    time_skew_alarm_ms: u32 = 120_000,
};

/// One `[section].key` -> field mapping with an inclusive clamp range.
const UKey = struct {
    path: []const u8,
    field: []const u8,
    lo: u64,
    hi: u64,
};

/// One `[section].key` -> string field mapping.
const SKey = struct {
    path: []const u8,
    field: []const u8,
};

const uint_keys = [_]UKey{
    // [limits]
    .{ .path = "limits.nick_len", .field = "nick_len", .lo = 9, .hi = 255 },
    .{ .path = "limits.channel_len", .field = "channel_len", .lo = 8, .hi = 255 },
    .{ .path = "limits.topic_len", .field = "topic_len", .lo = 80, .hi = 1024 },
    .{ .path = "limits.away_len", .field = "away_len", .lo = 100, .hi = 512 },
    .{ .path = "limits.user_len", .field = "user_len", .lo = 1, .hi = 64 },
    .{ .path = "limits.host_len", .field = "host_len", .lo = 63, .hi = 255 },
    .{ .path = "limits.server_name_len", .field = "server_name_len", .lo = 1, .hi = 255 },
    .{ .path = "limits.realname_len", .field = "realname_len", .lo = 50, .hi = 512 },
    .{ .path = "limits.reason_len", .field = "reason_len", .lo = 50, .hi = 512 },
    .{ .path = "limits.message_len", .field = "message_len", .lo = 100, .hi = 1024 },
    .{ .path = "limits.source_len", .field = "source_len", .lo = 64, .hi = 512 },
    .{ .path = "limits.monitor_targets", .field = "monitor_targets", .lo = 0, .hi = 4096 },
    .{ .path = "limits.chan_limit", .field = "chan_limit", .lo = 1, .hi = 1000 },
    .{ .path = "limits.max_ban_list", .field = "max_ban_list", .lo = 1, .hi = 1000 },
    .{ .path = "limits.max_except_list", .field = "max_except_list", .lo = 1, .hi = 1000 },
    .{ .path = "limits.max_invex_list", .field = "max_invex_list", .lo = 1, .hi = 1000 },
    .{ .path = "limits.modes_per_line", .field = "modes_per_line", .lo = 1, .hi = 20 },
    .{ .path = "limits.away_max_clients", .field = "away_max_clients", .lo = 64, .hi = 65536 },
    .{ .path = "limits.target_len_128", .field = "target_len_128", .lo = 8, .hi = 255 },
    .{ .path = "limits.whisper_recipients", .field = "whisper_recipients", .lo = 1, .hi = 64 },
    .{ .path = "limits.account_len", .field = "account_len", .lo = 1, .hi = 64 },
    .{ .path = "limits.account_email_len", .field = "account_email_len", .lo = 5, .hi = 254 },
    .{ .path = "limits.password_min", .field = "password_min", .lo = 1, .hi = 64 },
    .{ .path = "limits.password_max", .field = "password_max", .lo = 8, .hi = 1024 },
    .{ .path = "limits.account_code_len", .field = "account_code_len", .lo = 4, .hi = 256 },
    .{ .path = "limits.email_local_len", .field = "email_local_len", .lo = 1, .hi = 64 },
    .{ .path = "limits.email_domain_len", .field = "email_domain_len", .lo = 1, .hi = 255 },
    .{ .path = "limits.email_total_len", .field = "email_total_len", .lo = 5, .hi = 254 },
    .{ .path = "limits.service_nick_len", .field = "service_nick_len", .lo = 1, .hi = 64 },
    .{ .path = "limits.service_target_nick_len", .field = "service_target_nick_len", .lo = 1, .hi = 64 },
    .{ .path = "limits.list_max_filters", .field = "list_max_filters", .lo = 1, .hi = 64 },
    .{ .path = "limits.list_mask_len", .field = "list_mask_len", .lo = 1, .hi = 255 },
    .{ .path = "limits.whowas_max_entries", .field = "whowas_max_entries", .lo = 1, .hi = 100 },
    .{ .path = "limits.who_selector_fields", .field = "who_selector_fields", .lo = 1, .hi = 32 },
    .{ .path = "limits.whox_token_len", .field = "whox_token_len", .lo = 1, .hi = 64 },

    // [ircv3] IRCX advertised
    .{ .path = "ircv3.ircx_max_prop", .field = "ircx_max_prop", .lo = 0, .hi = 4096 },
    .{ .path = "ircv3.ircx_max_access", .field = "ircx_max_access", .lo = 0, .hi = 1024 },
    .{ .path = "ircv3.ircx_max_codepage", .field = "ircx_max_codepage", .lo = 0, .hi = 255 },
    .{ .path = "ircv3.ircx_max_language", .field = "ircx_max_language", .lo = 0, .hi = 255 },

    // [ircv3] caps / multiline / monitor / metadata
    .{ .path = "ircv3.cap_reply_body", .field = "cap_reply_body", .lo = 100, .hi = 510 },
    .{ .path = "ircv3.multiline_max_bytes", .field = "multiline_max_bytes", .lo = 4096, .hi = 262144 },
    .{ .path = "ircv3.multiline_max_lines", .field = "multiline_max_lines", .lo = 2, .hi = 1024 },
    .{ .path = "ircv3.multiline_ref_len", .field = "multiline_ref_len", .lo = 1, .hi = 128 },
    .{ .path = "ircv3.multiline_target_len", .field = "multiline_target_len", .lo = 8, .hi = 255 },
    .{ .path = "ircv3.label_len", .field = "label_len", .lo = 1, .hi = 128 },
    .{ .path = "ircv3.label_batch_ref_len", .field = "label_batch_ref_len", .lo = 1, .hi = 128 },
    .{ .path = "ircv3.monitor_reply_target_bytes", .field = "monitor_reply_target_bytes", .lo = 100, .hi = 510 },
    .{ .path = "ircv3.ext_monitor_verb_len", .field = "ext_monitor_verb_len", .lo = 1, .hi = 64 },
    .{ .path = "ircv3.ext_monitor_param_len", .field = "ext_monitor_param_len", .lo = 1, .hi = 1024 },
    .{ .path = "ircv3.ext_monitor_account_len", .field = "ext_monitor_account_len", .lo = 1, .hi = 128 },
    .{ .path = "ircv3.ext_monitor_meta_key_len", .field = "ext_monitor_meta_key_len", .lo = 1, .hi = 128 },
    .{ .path = "ircv3.ext_monitor_meta_value_len", .field = "ext_monitor_meta_value_len", .lo = 1, .hi = 1024 },
    .{ .path = "ircv3.metadata_entity_len", .field = "metadata_entity_len", .lo = 1, .hi = 255 },
    .{ .path = "ircv3.metadata_key_len", .field = "metadata_key_len", .lo = 1, .hi = 128 },
    .{ .path = "ircv3.metadata_value_len", .field = "metadata_value_len", .lo = 1, .hi = 4096 },
    .{ .path = "ircv3.metadata_max_keys", .field = "metadata_max_keys", .lo = 1, .hi = 512 },
    .{ .path = "ircv3.metadata_max_subscriptions", .field = "metadata_max_subscriptions", .lo = 1, .hi = 512 },
    .{ .path = "ircv3.metadata_max_targets", .field = "metadata_max_targets", .lo = 16, .hi = 65536 },

    // [ircv3] SASL
    .{ .path = "ircv3.sasl_authenticate_payload", .field = "sasl_authenticate_payload", .lo = 256, .hi = 1024 },
    .{ .path = "ircv3.sasl_scram_message", .field = "sasl_scram_message", .lo = 256, .hi = 2048 },
    .{ .path = "ircv3.sasl_scram_username", .field = "sasl_scram_username", .lo = 1, .hi = 255 },
    .{ .path = "ircv3.sasl_scram_nonce", .field = "sasl_scram_nonce", .lo = 16, .hi = 256 },
    .{ .path = "ircv3.sasl_scram_salt", .field = "sasl_scram_salt", .lo = 8, .hi = 256 },
    .{ .path = "ircv3.sasl_authenticate_chunk", .field = "sasl_authenticate_chunk", .lo = 100, .hi = 400 },
    .{ .path = "ircv3.sasl_external_payload", .field = "sasl_external_payload", .lo = 1, .hi = 512 },
    .{ .path = "ircv3.sasl_anonymous_trace_len", .field = "sasl_anonymous_trace_len", .lo = 1, .hi = 512 },
    .{ .path = "ircv3.sasl_scram_iterations", .field = "sasl_scram_iterations", .lo = 4096, .hi = 1_000_000 },

    // [ircv3] STS / cloak / IRCX detail
    .{ .path = "ircv3.sts_value_len", .field = "sts_value_len", .lo = 16, .hi = 255 },
    .{ .path = "ircv3.sts_preload_host_len", .field = "sts_preload_host_len", .lo = 1, .hi = 255 },
    .{ .path = "ircv3.sts_preload_max_entries", .field = "sts_preload_max_entries", .lo = 16, .hi = 65536 },
    .{ .path = "ircv3.sts_preload_min_duration", .field = "sts_preload_min_duration", .lo = 1, .hi = 31536000 },
    .{ .path = "ircv3.sts_max_age_secs", .field = "sts_max_age_secs", .lo = 0, .hi = 31536000 },
    .{ .path = "ircv3.cloak_hostname_len", .field = "cloak_hostname_len", .lo = 1, .hi = 253 },
    .{ .path = "ircv3.ircx_prop_name_len", .field = "ircx_prop_name_len", .lo = 1, .hi = 128 },
    .{ .path = "ircv3.ircx_prop_value_len", .field = "ircx_prop_value_len", .lo = 1, .hi = 4096 },
    .{ .path = "ircv3.ircx_entity_id_len", .field = "ircx_entity_id_len", .lo = 1, .hi = 255 },
    .{ .path = "ircv3.ircx_access_mask_len", .field = "ircx_access_mask_len", .lo = 1, .hi = 255 },
    .{ .path = "ircv3.ircx_max_entities", .field = "ircx_max_entities", .lo = 16, .hi = 65536 },
    .{ .path = "ircv3.ircx_props_per_entity", .field = "ircx_props_per_entity", .lo = 1, .hi = 512 },
    .{ .path = "ircv3.ircx_prop_owner_len", .field = "ircx_prop_owner_len", .lo = 1, .hi = 255 },
    .{ .path = "ircv3.ircx_prop_request_keys", .field = "ircx_prop_request_keys", .lo = 1, .hi = 64 },
    .{ .path = "ircv3.ircx_access_max_entries", .field = "ircx_access_max_entries", .lo = 1, .hi = 4096 },
    .{ .path = "ircv3.ircx_access_reason_len", .field = "ircx_access_reason_len", .lo = 1, .hi = 512 },
    .{ .path = "ircv3.ircx_duration_digits", .field = "ircx_duration_digits", .lo = 1, .hi = 20 },
    .{ .path = "ircv3.ircx_modex_max_changes", .field = "ircx_modex_max_changes", .lo = 1, .hi = 64 },
    .{ .path = "ircv3.ircx_modex_name_len", .field = "ircx_modex_name_len", .lo = 1, .hi = 128 },
    .{ .path = "ircv3.ircx_modex_target_len", .field = "ircx_modex_target_len", .lo = 8, .hi = 255 },
    .{ .path = "ircv3.ircx_saccess_reason_len", .field = "ircx_saccess_reason_len", .lo = 1, .hi = 512 },

    // [history]
    .{ .path = "history.max_messages_advertised", .field = "history_max_messages_advertised", .lo = 1, .hi = 10000 },
    .{ .path = "history.page_max", .field = "history_page_max", .lo = 1, .hi = 1000 },
    .{ .path = "history.target_len", .field = "history_target_len", .lo = 8, .hi = 255 },
    .{ .path = "history.msgid_len", .field = "history_msgid_len", .lo = 1, .hi = 255 },
    .{ .path = "history.batch_ref_len", .field = "history_batch_ref_len", .lo = 1, .hi = 128 },
    .{ .path = "history.sender_len", .field = "history_sender_len", .lo = 1, .hi = 512 },
    .{ .path = "history.read_marker_max_entries", .field = "read_marker_max_entries", .lo = 16, .hi = 65536 },
    .{ .path = "history.read_marker_owner_len", .field = "read_marker_owner_len", .lo = 1, .hi = 255 },
    .{ .path = "history.read_marker_target_len", .field = "read_marker_target_len", .lo = 8, .hi = 255 },
    .{ .path = "history.msgedit_msgid_len", .field = "msgedit_msgid_len", .lo = 1, .hi = 255 },
    .{ .path = "history.reaction_len", .field = "reaction_len", .lo = 1, .hi = 256 },
    .{ .path = "history.msgedit_text_len", .field = "msgedit_text_len", .lo = 100, .hi = 8191 },
    .{ .path = "history.activity_reaction_len", .field = "activity_reaction_len", .lo = 1, .hi = 256 },

    // [dns]
    .{ .path = "dns.ndots", .field = "dns_ndots", .lo = 0, .hi = 15 },
    .{ .path = "dns.timeout_secs", .field = "dns_timeout_secs", .lo = 1, .hi = 30 },
    .{ .path = "dns.attempts", .field = "dns_attempts", .lo = 1, .hi = 10 },
    .{ .path = "dns.max_nameservers", .field = "dns_max_nameservers", .lo = 1, .hi = 16 },
    .{ .path = "dns.max_search", .field = "dns_max_search", .lo = 1, .hi = 16 },
    .{ .path = "dns.max_domain_len", .field = "dns_max_domain_len", .lo = 1, .hi = 253 },
    .{ .path = "dns.max_cache_addrs", .field = "dns_max_cache_addrs", .lo = 1, .hi = 64 },
    .{ .path = "dns.max_answers", .field = "dns_max_answers", .lo = 1, .hi = 64 },

    // [flood]
    .{ .path = "flood.nick_quit_delay_secs", .field = "nick_quit_delay_secs", .lo = 0, .hi = 3600 },
    .{ .path = "flood.nick_change_delay_secs", .field = "nick_change_delay_secs", .lo = 0, .hi = 3600 },
    .{ .path = "flood.nick_max_holds", .field = "nick_max_holds", .lo = 16, .hi = 65536 },
    .{ .path = "flood.nick_note_len", .field = "nick_note_len", .lo = 1, .hi = 512 },
    .{ .path = "flood.accept_max_owners", .field = "accept_max_owners", .lo = 16, .hi = 65536 },
    .{ .path = "flood.accept_entries_per_owner", .field = "accept_entries_per_owner", .lo = 1, .hi = 512 },
    .{ .path = "flood.silence_masks_per_owner", .field = "silence_masks_per_owner", .lo = 1, .hi = 256 },
    .{ .path = "flood.silence_ops_per_command", .field = "silence_ops_per_command", .lo = 1, .hi = 128 },

    // [server]
    .{ .path = "server.time_skew_alarm_ms", .field = "time_skew_alarm_ms", .lo = 0, .hi = 600000 },
};

const string_keys = [_]SKey{
    .{ .path = "limits.chantypes", .field = "chantypes" },
    .{ .path = "limits.prefix", .field = "prefix" },
    .{ .path = "limits.chanmodes", .field = "chanmodes" },
    .{ .path = "limits.casemapping", .field = "casemapping" },
    .{ .path = "limits.network", .field = "network" },
    .{ .path = "limits.elist", .field = "elist" },
    .{ .path = "limits.statusmsg", .field = "statusmsg" },
    .{ .path = "limits.targmax", .field = "targmax" },
    .{ .path = "limits.excepts_mode", .field = "excepts_mode" },
    .{ .path = "limits.invex_mode", .field = "invex_mode" },
    .{ .path = "limits.extban", .field = "extban" },
    .{ .path = "limits.account_extban", .field = "account_extban" },
    .{ .path = "limits.isupport_trailing", .field = "isupport_trailing" },
    .{ .path = "limits.channel_prefixes", .field = "channel_prefixes" },
};

/// Overlay any recognised `[limits]`/`[ircv3]`/`[history]`/`[dns]`/`[flood]`/
/// `[server]` keys from `doc` onto `self`. Unknown, mistyped, or out-of-range
/// keys are ignored, leaving the prior (default) value intact.
pub fn applyToml(self: *Limits, doc: *const toml.Document) void {
    inline for (uint_keys) |k| {
        if (doc.getUint(k.path)) |raw| {
            const clamped = clampU(raw, k.lo, k.hi);
            @field(self, k.field) = @intCast(clamped);
        }
    }
    inline for (string_keys) |k| {
        if (doc.getString(k.path)) |bytes| {
            @field(self, k.field).set(bytes);
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

test "defaults reproduce historical values" {
    const l = Limits{};
    try std.testing.expectEqual(@as(u32, 64), l.nick_len);
    try std.testing.expectEqual(@as(u32, 512), l.topic_len);
    try std.testing.expectEqual(@as(u32, 390), l.away_len);
    try std.testing.expectEqual(@as(u32, 100), l.chan_limit);
    try std.testing.expectEqual(@as(u32, 1000), l.history_max_messages_advertised);
    try std.testing.expectEqual(@as(u32, 5), l.dns_timeout_secs);
    try std.testing.expectEqual(@as(u32, 60), l.nick_quit_delay_secs);
    try std.testing.expectEqualStrings("Orochi", l.network.slice());
    try std.testing.expectEqualStrings("#&", l.chantypes.slice());
}

test "applyToml overlays known keys and clamps out of range" {
    const text =
        \\[limits]
        \\nick_len = 32
        \\network = "TestNet"
        \\chan_limit = 999999
        \\[history]
        \\max_messages_advertised = 500
        \\[dns]
        \\timeout_secs = 7
        \\[flood]
        \\nick_quit_delay_secs = 120
        \\[ircv3]
        \\multiline_max_lines = 256
        \\
    ;
    var doc = try toml.parse(std.testing.allocator, text);
    defer doc.deinit(std.testing.allocator);

    var l = Limits{};
    applyToml(&l, &doc);

    try std.testing.expectEqual(@as(u32, 32), l.nick_len);
    try std.testing.expectEqualStrings("TestNet", l.network.slice());
    try std.testing.expectEqual(@as(u32, 1000), l.chan_limit); // clamped to max
    try std.testing.expectEqual(@as(u32, 500), l.history_max_messages_advertised);
    try std.testing.expectEqual(@as(u32, 7), l.dns_timeout_secs);
    try std.testing.expectEqual(@as(u32, 120), l.nick_quit_delay_secs);
    try std.testing.expectEqual(@as(u32, 256), l.multiline_max_lines);
}

test "fromLimits with default Limits reproduces module Params defaults" {
    const l = Limits{};

    // Reply-builder identity caps must round-trip to the historical defaults so
    // that an unconfigured server behaves exactly as before.
    {
        const invite = @import("invite.zig");
        const got = invite.Params.fromLimits(&l);
        try std.testing.expectEqual((invite.Params{}).max_nick_bytes, got.max_nick_bytes);
        try std.testing.expectEqual((invite.Params{}).max_host_bytes, got.max_host_bytes);
        try std.testing.expectEqual((invite.Params{}).max_description_bytes, got.max_description_bytes);
    }
    {
        const nickdelay = @import("nickdelay.zig");
        const got = nickdelay.Params.fromLimits(&l);
        try std.testing.expectEqual((nickdelay.Params{}).quit_delay_secs, got.quit_delay_secs);
        try std.testing.expectEqual((nickdelay.Params{}).max_holds, got.max_holds);
    }
    {
        const metadata_store = @import("metadata_store.zig");
        const got = metadata_store.Params.fromLimits(&l);
        try std.testing.expectEqual((metadata_store.Params{}).max_targets, got.max_targets);
        try std.testing.expectEqual((metadata_store.Params{}).max_value, got.max_value);
    }
    {
        const ircx_prop_store = @import("ircx_prop_store.zig");
        const got = ircx_prop_store.Params.fromLimits(&l);
        try std.testing.expectEqual((ircx_prop_store.Params{}).max_entities, got.max_entities);
        try std.testing.expectEqual((ircx_prop_store.Params{}).max_value, got.max_value);
    }
}

test "applyToml leaves untouched fields at default and ignores unknown" {
    const text =
        \\[limits]
        \\unknown_key = 5
        \\
    ;
    var doc = try toml.parse(std.testing.allocator, text);
    defer doc.deinit(std.testing.allocator);

    var l = Limits{};
    applyToml(&l, &doc);
    try std.testing.expectEqual(@as(u32, 64), l.nick_len);
}
