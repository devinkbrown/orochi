# Orochi IRC protocol-layer hardcoded constant sweep (`src/proto/*.zig`)

READ-ONLY survey. Scope: IRC protocol layer only. Excludes `tls_*`, `tls12_*`, `dtls_*`, `acme_*`, `toml.zig` (owned by other agents) and the non-IRC crypto/codec/transport modules (asn1/der/pem/pkcs8/csr/ocsp/x509/ed25519/cbor/merkle/gcounter/orset/quorum/skiplist/reservoir/rendezvous/snowflake/uuid/varint/punycode/idna/base32/base64url/percent/mime/levenshtein/semver/glob/hostmask/wildcard/word_wrap/utf8_width/numeric_range/humanize/color_strip/casemap/quic/http*/stun/ice/sdp/rtp/opus/vp8/webtransport/socks5/proxy_protocol/happy_eyeballs/secure_fns/meshpass/cidr_match etc.).
Excludes IRC numerics, RFC wire constants, enum discriminants, type widths, fuzz/test iteration counts.

Note: most `MAX_*_BYTES` for nick/user/host/server/channel in per-feature reply builders are *defaults* of comptime `Params` structs and repeat the same policy values across many files (NICKLEN=64, hostlen=255, etc.). Where a value is purely a wire-framing buffer (e.g. `MAX_IRC_LINE_BYTES=512`, `MAX_WIRE_LINE`) it is marked borderline. The canonical policy source for ISUPPORT-advertised limits is `isupport.zig:default_tokens` — those should be the single source of truth, with per-module `Params` derived from config.

---

## [limits] — ISUPPORT-advertised policy (canonical source: isupport.zig default_tokens)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| isupport.zig:256 | default_tokens NICKLEN | 64 | Max nickname length (ISUPPORT NICKLEN) | limits.nick_len | uint | 64 | 9..255 |
| isupport.zig:257 | default_tokens CHANNELLEN | 64 | Max channel name length (CHANNELLEN) | limits.channel_len | uint | 64 | 8..255 |
| isupport.zig:258 | default_tokens TOPICLEN | 512 | Max topic length (TOPICLEN) | limits.topic_len | uint | 512 | 80..1024 |
| isupport.zig:259 | default_tokens AWAYLEN | 390 | Max AWAY message length (AWAYLEN) | limits.away_len | uint | 390 | 100..512 |
| isupport.zig:263 | default_tokens MONITOR | 512 | Max MONITOR targets per client (ISUPPORT) | limits.monitor_targets | uint | 512 | 0..4096 |
| isupport.zig:264 | default_tokens CHATHISTORY | 1000 | Max messages returnable per CHATHISTORY req | history.max_messages_advertised | uint | 1000 | 1..10000 |
| isupport.zig:270 | default_tokens CHANLIMIT `#:100` | 100 | Max channels a user may join (`#`) | limits.chan_limit | uint | 100 | 1..1000 |
| isupport.zig:271 | default_tokens MAXLIST `b:100,e:100,I:100` | 100 / 100 / 100 | Max ban / except / invex entries per channel | limits.max_ban_list / max_except_list / max_invex_list | uint | 100 | 1..1000 |
| isupport.zig:272 | default_tokens MODES | 4 | Max mode params per MODE command | limits.modes_per_line | uint | 4 | 1..20 |
| isupport.zig:281 | default_tokens MAXPROP | 512 | Max IRCX properties per entity (advertised) | ircv3.ircx_max_prop | uint | 512 | 0..4096 |
| isupport.zig:282 | default_tokens MAXACCESS | 128 | Max IRCX access entries (advertised) | ircv3.ircx_max_access | uint | 128 | 0..1024 |
| isupport.zig:279 | default_tokens MAXCODEPAGE | 0 | Advertised codepage cap (0=unset) | ircv3.ircx_max_codepage | uint | 0 | 0..255 |
| isupport.zig:280 | default_tokens MAXLANGUAGE | 0 | Advertised language cap (0=unset) | ircv3.ircx_max_language | uint | 0 | 0..255 |
| isupport.zig:253 | default_tokens CHANTYPES | `#` | Allowed channel prefix types | limits.chantypes | string | `#` | – |
| isupport.zig:254 | default_tokens PREFIX | `(qaohv)~&@%+` | Channel membership prefixes/modes (policy) | limits.prefix | string | `(qaohv)~&@%+` | – |
| isupport.zig:255 | default_tokens CHANMODES | `b,k,l,imnpst` | Channel mode classes A,B,C,D (policy) | limits.chanmodes | string | `b,k,l,imnpst` | – |
| isupport.zig:260 | default_tokens CASEMAPPING | `ascii` | Casemapping policy | limits.casemapping | string | `ascii` | – |
| isupport.zig:261 | default_tokens NETWORK | `Orochi` | Advertised network name | limits.network | string | `Orochi` | – |
| isupport.zig:262 | default_tokens ELIST | `CMNTU` | Supported LIST filter flags | limits.elist | string | `CMNTU` | – |
| isupport.zig:268 | default_tokens STATUSMSG | `~&@%+` | Prefixes usable for STATUSMSG targets | limits.statusmsg | string | `~&@%+` | – |
| isupport.zig:269 | default_tokens TARGMAX | `JOIN:,WHOIS:1,PRIVMSG:,NOTICE:,MONITOR:` | Per-command target maxima | limits.targmax | string | (as shown) | – |
| isupport.zig:273 | default_tokens EXCEPTS | `e` | Ban-exception mode letter | limits.excepts_mode | string | `e` | – |
| isupport.zig:274 | default_tokens INVEX | `I` | Invite-exception mode letter | limits.invex_mode | string | `I` | – |
| isupport.zig:275 | default_tokens EXTBAN | `$,acgr` | Extban prefix + supported types | limits.extban | string | `$,acgr` | – |
| isupport.zig:276 | default_tokens ACCOUNTEXTBAN | `a` | Account extban letter | limits.account_extban | string | `a` | – |
| isupport.zig:12 | DEFAULT_TRAILING | "are supported by this server" | ISUPPORT 005 trailing text | limits.isupport_trailing | string | (as shown) | – |
| isupport.zig:10 / irc_isupport.zig:7 | MAX_TOKENS_PER_LINE | 13 | ISUPPORT tokens per 005 line | borderline limits.isupport_tokens_per_line | uint | 13 | 1..20 |
| isupport.zig:11 | MAX_IRC_LINE_BYTES | 512 | IRC line octet budget incl CRLF | borderline (RFC wire) | uint | 512 | – |

## [limits] — per-feature identifier/length caps (policy, repeated across modules)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| away.zig:11 | DEFAULT_MAX_CLIENTS | 4096 | Max tracked away clients | limits.away_max_clients | uint | 4096 | 64..65536 |
| away.zig:12 | DEFAULT_MAX_AWAY_MESSAGE_BYTES | 512 | Stored away message cap | limits.away_len (dup of AWAYLEN; align) | uint | 512 | 100..512 |
| away.zig:13 / monitor.zig:9 / extended_monitor.zig:11 / invite.zig:11 / knock.zig:13 / whisper.zig:13 / channel_rename.zig:10 / whowas_reply.zig:12 / ison_userhost.zig:12 / names_reply.zig:12 / silence.zig (owner) | MAX_NICK_BYTES / DEFAULT_MAX_NICK_BYTES | 64 | Nick byte cap in reply builders | limits.nick_len (single source) | uint | 64 | 9..255 |
| invite.zig:13 / knock.zig:15 / whisper.zig:15 / extended_monitor.zig:13 / channel_rename.zig:12 / whowas_reply.zig:14 / ison_userhost.zig:14 / names_reply.zig:14 | DEFAULT_MAX_HOST_BYTES | 255 | Host byte cap in reply builders | limits.host_len | uint | 255 | 63..255 |
| invite.zig:12 / knock.zig:14 / whisper.zig:14 / extended_monitor.zig:12 / channel_rename.zig:11 / whowas_reply.zig:13 / ison_userhost.zig:13 | DEFAULT_MAX_USER_BYTES | 64 | Ident/user byte cap | limits.user_len | uint | 64 | 1..64 |
| invite.zig:15 / knock.zig:17 / whisper.zig:17 / channel_rename.zig:14 | DEFAULT_MAX_CHANNEL_BYTES | 200 | Channel byte cap in some builders | limits.channel_len (align; differs from 64/128) | uint | 200 | 8..255 |
| listx.zig:21 / chathistory_cmd.zig:7 / extended_monitor_store(line) / names_reply.zig:15 / list.zig:10 / elist.zig:9 / silence.zig:13 | *MAX*CHANNEL/MASK/TARGET_BYTES | 128 | Channel/mask/target byte cap (128 variant) | limits.target_len_128 | uint | 128 | 8..255 |
| invite.zig:14 / knock.zig:16 / whisper.zig:16 / invite SERVER_NAME / whowas_reply.zig:11 / ison_userhost.zig:11 / names_reply.zig:11 / silence.zig:17 / listx.zig:19 / channel_rename.zig:13 (HOST/SOURCE) | DEFAULT_MAX_SERVER(_NAME)_BYTES | 255 | Server-name byte cap | limits.server_name_len | uint | 255 | 1..255 |
| invite.zig:16 / knock.zig:19 / whisper.zig:19 / channel_rename.zig:16 / whowas_reply.zig:15 | DEFAULT_MAX_DESCRIPTION/REALNAME_BYTES | 512 | Realname/description byte cap | limits.realname_len | uint | 512 | 50..512 |
| knock.zig:18 / channel_rename.zig:15 | DEFAULT_MAX_REASON_BYTES | 512 | KNOCK/RENAME reason byte cap | limits.reason_len | uint | 512 | 50..512 |
| whisper.zig:18 | DEFAULT_MAX_TEXT_BYTES | 512 | WHISPER message byte cap | limits.message_len | uint | 512 | 100..1024 |
| whisper.zig:20 | DEFAULT_MAX_RECIPIENTS | 16 | Max WHISPER recipients | limits.whisper_recipients | uint | 16 | 1..64 |
| invite.zig:17 / knock.zig:20 / whisper.zig:21 | DEFAULT_CHANNEL_PREFIXES | `#+&!` | Accepted channel prefixes (these builders) | limits.channel_prefixes (reconcile w/ CHANTYPES=`#`) | string | `#+&!` | – |
| channel_rename.zig:13 (SOURCE) | DEFAULT_MAX_SOURCE_BYTES | 512 | nick!user@host source cap | limits.source_len | uint | 512 | 64..512 |
| account_register.zig:7 | MAX_ACCOUNT_BYTES | 32 | Max account name length (REGISTER) | limits.account_len | uint | 32 | 1..64 |
| account_register.zig:8 | MAX_EMAIL_BYTES | 96 | Max email length (REGISTER) | limits.account_email_len | uint | 96 | 5..254 |
| account_register.zig:9 | MIN_PASSWORD_BYTES | 8 | Min password length (REGISTER) | limits.password_min | uint | 8 | 1..64 |
| account_register.zig:10 | MAX_PASSWORD_BYTES | 512 | Max password length (REGISTER) | limits.password_max | uint | 512 | 8..1024 |
| account_register.zig:11 | MAX_CODE_BYTES | 128 | Max verification-code length | limits.account_code_len | uint | 128 | 4..256 |
| email_validate.zig:27 | MAX_LOCAL_LEN | 64 | Email local-part cap | limits.email_local_len | uint | 64 | 1..64 |
| email_validate.zig:30 | MAX_DOMAIN_LEN | 255 | Email domain cap | limits.email_domain_len | uint | 255 | 1..255 |
| email_validate.zig:33 | MAX_LABEL_LEN | 63 | Email DNS label cap | borderline (DNS spec) | uint | 63 | – |
| email_validate.zig:37 | MAX_TOTAL_LEN | 254 | Email total length cap | limits.email_total_len | uint | 254 | 5..254 |
| services_alias.zig:9 | DEFAULT_MAX_SERVICE_NICK_BYTES | 32 | Service-alias target nick cap | limits.service_nick_len | uint | 32 | 1..64 |
| services_alias.zig:10 | DEFAULT_MAX_TARGET_NICK_BYTES | 32 | Alias target nick cap | limits.service_target_nick_len | uint | 32 | 1..64 |
| services_alias.zig:11 | DEFAULT_MAX_TEXT_BYTES | 8191 | Alias relayed text cap | borderline (multiline wire) | uint | 8191 | – |
| nickdelay.zig:242 | maxNickBufLen | 64 | NickDelay nick buffer cap | limits.nick_len (reuse) | uint | 64 | 9..255 |

## [history] — chathistory / read-marker / msgedit sizing

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| chathistory_query.zig:443 | max_limit | 50 | Max messages per CHATHISTORY page (parse cap) | history.page_max | uint | 50 | 1..1000 |
| chathistory_cmd.zig:7 | max_target_len | 128 | CHATHISTORY target byte cap | history.target_len | uint | 128 | 8..255 |
| chathistory_cmd.zig:8 | max_msgid_len | 128 | msgid byte cap in CHATHISTORY | history.msgid_len | uint | 128 | 1..255 |
| chathistory_cmd.zig:9 | max_batch_ref_len | 64 | batch-ref byte cap | history.batch_ref_len | uint | 64 | 1..128 |
| chathistory_cmd.zig:10 | max_sender_len | 256 | sender byte cap | history.sender_len | uint | 256 | 1..512 |
| chathistory_cmd.zig:11 | max_line_body | 8191 | CHATHISTORY output line body cap | borderline (wire) | uint | 8191 | – |
| read_marker_store.zig:8 | default_max_entries | 1024 | Max read-marker targets stored | history.read_marker_max_entries | uint | 1024 | 16..65536 |
| read_marker_store.zig:9 | default_max_owner_bytes | 128 | Read-marker owner-id cap | history.read_marker_owner_len | uint | 128 | 1..255 |
| read_marker.zig:11 | default_max_target_bytes | 128 | Read-marker target byte cap | history.read_marker_target_len | uint | 128 | 8..255 |
| msgedit.zig:10 | MAX_MSGID_LEN | 255 | Edited-message msgid cap | history.msgedit_msgid_len | uint | 255 | 1..255 |
| msgedit.zig:14 | MAX_REACTION_LEN | 128 | Reaction string cap | history.reaction_len | uint | 128 | 1..256 |
| msgedit.zig:17 | MAX_TEXT_VALUE_LEN | 1024 | Edit/reason text cap | history.msgedit_text_len | uint | 1024 | 100..8191 |
| msgedit_store.zig:11 | MAX_NOTIFICATION_LEN | 8191 | Msg-edit notification line cap | borderline (wire) | uint | 8191 | – |
| activity.zig:26 | max_reaction_len | 64 | TAGMSG reaction cap | history.activity_reaction_len | uint | 64 | 1..256 |
| msgtags.zig:10 | MSGID_LEN | 22 | Generated msgid length | borderline ircv3.msgid_len | uint | 22 | 16..64 |
| msgtags.zig:11 / server_time_skew.zig:34 | SERVER_TIME_LEN | 24 | server-time tag length | borderline (fixed format) | uint | 24 | – |

## [ircv3] — caps, multiline, monitor, metadata, labeled-response, SASL

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| cap.zig:8 | MAX_CAP_REPLY_BODY | 500 | CAP LS/LIST reply body byte budget | ircv3.cap_reply_body | uint | 500 | 100..510 |
| cap_registry.zig:3 | default_line_limit | 510 | CAP line octet limit | borderline ircv3.cap_line_limit | uint | 510 | 256..512 |
| multiline.zig:14 | default_max_bytes | 40000 | Max total bytes per multiline batch | ircv3.multiline_max_bytes | uint | 40000 | 4096..262144 |
| multiline.zig:15 | default_max_lines | 64 | Max lines per multiline batch | ircv3.multiline_max_lines | uint | 64 | 2..1024 |
| multiline.zig:16 | default_max_ref_len | 64 | multiline batch-ref cap | ircv3.multiline_ref_len | uint | 64 | 1..128 |
| multiline.zig:17 | default_max_target_len | 128 | multiline target cap | ircv3.multiline_target_len | uint | 128 | 8..255 |
| labeled_response.zig:8 | MAX_LABEL_LEN | 64 | labeled-response label cap | ircv3.label_len | uint | 64 | 1..128 |
| labeled_response.zig:9 | MAX_BATCH_REF_LEN | 64 | labeled batch-ref cap | ircv3.label_batch_ref_len | uint | 64 | 1..128 |
| labeled_response.zig:10 | MAX_LINE_BODY | 8191 | labeled line body cap | borderline (wire) | uint | 8191 | – |
| monitor.zig:9 | MAX_NICK_BYTES | 64 | MONITOR nick cap | limits.nick_len (reuse) | uint | 64 | 9..255 |
| monitor.zig:10 | MAX_REPLY_TARGET_BYTES | 400 | MONITOR reply target list cap | ircv3.monitor_reply_target_bytes | uint | 400 | 100..510 |
| extended_monitor.zig:14 | DEFAULT_MAX_VERB_BYTES | 32 | ext-monitor verb cap | ircv3.ext_monitor_verb_len | uint | 32 | 1..64 |
| extended_monitor.zig:15 | DEFAULT_MAX_PARAM_BYTES | 512 | ext-monitor param cap | ircv3.ext_monitor_param_len | uint | 512 | 1..1024 |
| extended_monitor_store.zig:15 | DEFAULT_MAX_ACCOUNT_BYTES | 64 | ext-monitor account cap | ircv3.ext_monitor_account_len | uint | 64 | 1..128 |
| extended_monitor_store.zig:16 | DEFAULT_MAX_METADATA_KEY_BYTES | 64 | ext-monitor metadata key cap | ircv3.ext_monitor_meta_key_len | uint | 64 | 1..128 |
| extended_monitor_store.zig:17 | DEFAULT_MAX_METADATA_VALUE_BYTES | 512 | ext-monitor metadata value cap | ircv3.ext_monitor_meta_value_len | uint | 512 | 1..1024 |
| metadata.zig:8 | default_max_entity_bytes | 128 | Metadata entity-id cap | ircv3.metadata_entity_len | uint | 128 | 1..255 |
| metadata.zig:9 / metadata_store.zig:10 | default_max_key(_bytes) | 64 | Metadata key cap | ircv3.metadata_key_len | uint | 64 | 1..128 |
| metadata.zig:10 / metadata_store.zig:11 | default_max_value(_bytes) | 512 | Metadata value cap | ircv3.metadata_value_len | uint | 512 | 1..4096 |
| metadata.zig:11 / metadata_store.zig:9 | default_max_keys_per_entity/target | 64 | Max metadata keys per target | ircv3.metadata_max_keys | uint | 64 | 1..512 |
| metadata.zig:12 | default_max_subscriptions | 64 | Max metadata subscriptions per client | ircv3.metadata_max_subscriptions | uint | 64 | 1..512 |
| metadata_store.zig:8 | default_max_targets | 1024 | Max distinct metadata targets stored | ircv3.metadata_max_targets | uint | 1024 | 16..65536 |
| sasl.zig:28 | MAX_AUTHENTICATE_PAYLOAD | 512 | Max AUTHENTICATE payload bytes | ircv3.sasl_authenticate_payload | uint | 512 | 256..1024 |
| sasl.zig:29 / sasl_scram.zig:29 | MAX_SCRAM_MESSAGE | 512 | Max SCRAM message bytes | ircv3.sasl_scram_message | uint | 512 | 256..2048 |
| sasl.zig:30 / sasl_scram.zig:30 | MAX_SCRAM_USERNAME | 128 | Max SCRAM username bytes | ircv3.sasl_scram_username | uint | 128 | 1..255 |
| sasl.zig:31 / sasl_scram.zig:31 | MAX_SCRAM_NONCE | 128 | Max SCRAM nonce bytes | ircv3.sasl_scram_nonce | uint | 128 | 16..256 |
| sasl.zig:32 / sasl_scram.zig:32 | MAX_SCRAM_SALT | 128 | Max SCRAM salt bytes | ircv3.sasl_scram_salt | uint | 128 | 8..256 |
| sasl_mechrouter.zig:12 | MAX_AUTHENTICATE_CHUNK | 400 | AUTHENTICATE chunking size | ircv3.sasl_authenticate_chunk | uint | 400 | 100..400 |
| sasl_external.zig:10 | max_authenticate_payload | 400 | EXTERNAL payload cap | ircv3.sasl_external_payload | uint | 400 | 1..512 |
| sasl_anonymous.zig:12 | default_max_trace_bytes | 255 | ANONYMOUS trace string cap | ircv3.sasl_anonymous_trace_len | uint | 255 | 1..512 |

## [ircv3] — STS / SNI / cloak / chghost

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| sts.zig:9 | MAX_VALUE_LEN | 96 | STS cap value byte cap | ircv3.sts_value_len | uint | 96 | 16..255 |
| cap_sts_preload.zig:8 | MAX_HOST_LEN | 255 | STS preload hostname cap | ircv3.sts_preload_host_len | uint | 255 | 1..255 |
| cap_sts_preload.zig:11 | DEFAULT_MAX_ENTRIES | 4096 | Max STS preload hostnames | ircv3.sts_preload_max_entries | uint | 4096 | 16..65536 |
| cap_sts_preload.zig:14 | MIN_DURATION_SECONDS | 1 | Min accepted STS preload duration | ircv3.sts_preload_min_duration | duration(s) | 1 | 1..31536000 |
| cloak.zig:12 | key_len | 32 | Cloak HMAC secret-key length | ircv3.cloak_key_len | uint | 32 | borderline (crypto) |
| cloak.zig:14 | max_hostname_len | 253 | Cloak input hostname cap | ircv3.cloak_hostname_len | uint | 253 | 1..253 |

## [ircv3] — IRCX (PROP / ACCESS / MODEX / SACCESS)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| ircx.zig:9 | MAX_PROP_NAME | 64 | IRCX property name cap | ircv3.ircx_prop_name_len | uint | 64 | 1..128 |
| ircx.zig:10 | MAX_PROP_VALUE | 512 | IRCX property value cap | ircv3.ircx_prop_value_len | uint | 512 | 1..4096 |
| ircx.zig:11 | MAX_ENTITY_ID | 128 | IRCX entity-id cap | ircv3.ircx_entity_id_len | uint | 128 | 1..255 |
| ircx.zig:12 | MAX_ACCESS_MASK | 128 | IRCX access mask cap | ircv3.ircx_access_mask_len | uint | 128 | 1..255 |
| ircx_prop_store.zig:6 | default_max_entities | 1024 | Max IRCX prop-holding entities | ircv3.ircx_max_entities | uint | 1024 | 16..65536 |
| ircx_prop_store.zig:7 | default_max_props_per_entity | 64 | Max props per entity | ircv3.ircx_props_per_entity | uint | 64 | 1..512 |
| ircx_prop_store.zig:11 | default_max_owner_bytes | 128 | Prop owner-id cap | ircv3.ircx_prop_owner_len | uint | 128 | 1..255 |
| ircx_prop_store.zig:12 | default_max_request_keys | 16 | Max keys per PROP request | ircv3.ircx_prop_request_keys | uint | 16 | 1..64 |
| ircx_access_store.zig:14 | DEFAULT_MAX_ENTRIES | 256 | Max IRCX access entries | ircv3.ircx_access_max_entries | uint | 256 | 1..4096 |
| ircx_access_store.zig:18 | DEFAULT_MAX_REASON_BYTES | 256 | Access reason cap | ircv3.ircx_access_reason_len | uint | 256 | 1..512 |
| ircx_access_store.zig:22 / ircx_saccess.zig:20 | DEFAULT_MAX_DURATION_DIGITS | 20 | Access duration digit cap | ircv3.ircx_duration_digits | uint | 20 | 1..20 |
| ircx_modex.zig:16 | DEFAULT_MAX_CHANGES | 16 | Max MODEX changes per command | ircv3.ircx_modex_max_changes | uint | 16 | 1..64 |
| ircx_modex.zig:18 | DEFAULT_MAX_NAME_BYTES | 64 | MODEX mode-name cap | ircv3.ircx_modex_name_len | uint | 64 | 1..128 |
| ircx_modex.zig:22 | DEFAULT_MAX_TARGET_BYTES | 160 | MODEX target cap | ircv3.ircx_modex_target_len | uint | 160 | 8..255 |
| ircx_saccess.zig:16 | DEFAULT_MAX_REASON_BYTES | 256 | SACCESS reason cap | ircv3.ircx_saccess_reason_len | uint | 256 | 1..512 |

## [dns] — resolver tuning (resolv_conf defaults + dns sizing)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| resolv_conf.zig:22 | default_ndots | 1 | ndots before treating name as absolute | dns.ndots | uint | 1 | 0..15 |
| resolv_conf.zig:23 | default_timeout | 5 | Per-query timeout (seconds) | dns.timeout_secs | duration(s) | 5 | 1..30 |
| resolv_conf.zig:24 | default_attempts | 2 | Query retry attempts | dns.attempts | uint | 2 | 1..10 |
| resolv_conf.zig:15 | max_nameservers | 4 | Max nameservers honoured | dns.max_nameservers | uint | 4 | 1..16 |
| resolv_conf.zig:17 | max_search | 6 | Max search-domain entries | dns.max_search | uint | 6 | 1..16 |
| resolv_conf.zig:19 | max_domain_len | 253 | Max stored search-domain length | dns.max_domain_len | uint | 253 | 1..253 |
| dns.zig:8 | max_message_len | 512 | DNS UDP message buffer cap | borderline dns.udp_message_len | uint | 512 | 512..4096 |
| dns.zig:9 | max_domain_text_len | 253 | Max domain text length | borderline (DNS spec) | uint | 253 | – |
| dns.zig:10 | max_cache_addrs | 8 | Max cached A/AAAA addresses | dns.max_cache_addrs | uint | 8 | 1..64 |
| dns_resolver.zig:108 | max_answers | 8 | Max answers parsed per response | dns.max_answers | uint | 8 | 1..64 |

## [server] — clock skew / motd / lists

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| server_time_skew.zig:54 | Config.max_skew_ms | 120000 (2*60*1000) | server-time drift alarm threshold | server.time_skew_alarm_ms | duration(ms) | 120000 | 0..600000 |
| motd.zig:9 | DEFAULT_MAX_LINE_BYTES | 510 | MOTD line octet cap | borderline server.motd_line_bytes | uint | 510 | 256..512 |
| list.zig:9 / listx.zig:15 / elist.zig (16) | MAX_FILTERS / DEFAULT_MAX_FILTERS | 16 | Max LIST filter clauses | limits.list_max_filters | uint | 16 | 1..64 |
| list.zig:10 / listx.zig:17 / elist.zig:9 | MAX_MASK_BYTES | 128 | LIST mask byte cap | limits.list_mask_len | uint | 128 | 1..255 |
| listx.zig:22 | DEFAULT_MAX_TOPIC_BYTES | 512 | LISTX topic byte cap | limits.topic_len (reuse) | uint | 512 | 80..1024 |
| whowas_reply.zig:16 | DEFAULT_MAX_ENTRIES | 20 | Max WHOWAS history entries returned | limits.whowas_max_entries | uint | 20 | 1..100 |
| who.zig:10 / who_props (16) | MAX_SELECTOR_FIELDS | 16 | Max WHO selector fields | limits.who_selector_fields | uint | 16 | 1..32 |
| whox.zig:8 | MAX_TOKEN_BYTES | 32 | WHOX field-token cap | limits.whox_token_len | uint | 32 | 1..64 |

## [flood] — nick reservation / accept lists (no message-rate flood throttles found in proto layer)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| nickdelay.zig:57 | Params.quit_delay_secs | 60 | Nick reservation after QUIT | flood.nick_quit_delay_secs | duration(s) | 60 | 0..3600 |
| nickdelay.zig:59 | Params.change_delay_secs | 30 | Nick reservation after NICK change | flood.nick_change_delay_secs | duration(s) | 30 | 0..3600 |
| nickdelay.zig:61 | Params.max_holds | 4096 | Max simultaneous nick holds | flood.nick_max_holds | uint | 4096 | 16..65536 |
| nickdelay.zig:65 | Params.max_note_bytes | 256 | Nick-hold note cap | flood.nick_note_len | uint | 256 | 1..512 |
| accept_list.zig:23 | Params.max_owners | 1024 | Max ACCEPT-list owners | flood.accept_max_owners | uint | 1024 | 16..65536 |
| accept_list.zig:24 | Params.max_entries_per_owner | 64 | Max ACCEPT entries per user | flood.accept_entries_per_owner | uint | 64 | 1..512 |
| silence.zig:12 | DEFAULT_MAX_MASKS_PER_OWNER | 32 | Max SILENCE masks per user | flood.silence_masks_per_owner | uint | 32 | 1..256 |
| silence.zig:15 | DEFAULT_MAX_OPERATIONS | 32 | Max SILENCE ops per command | flood.silence_ops_per_command | uint | 32 | 1..128 |

---

## Notes / gaps
- **No message-rate flood/throttle windows** (sendq/recvq, per-command rate, penalty timers) exist in the proto layer — those live elsewhere (likely the core/net layer, out of this scope). `[flood]` here is reservation/list sizing only.
- **SCRAM iteration count** is *not* hardcoded in proto: `recordFromPassword`/`deriveScramKeys` take `iterations: u32` from the caller (sasl.zig:302, :288). The default belongs in whatever credential-creation/config layer calls it — flag for the config author as `ircv3.sasl_scram_iterations` (e.g. 4096+).
- **STS max-age/duration** is caller-supplied (`sts_policy.zig` ServerConfig.duration_seconds is `?u64`, no hardcoded default). Doc comment shows `2592000` (30d) as example only. Add `ircv3.sts_max_age_secs` default in config.
- Many `MAX_*_BYTES` (nick/user/host/server/channel) repeat the same policy values across ~12 reply-builder modules. Strongly recommend a single `[limits]` block feeding all module `Params` rather than per-module keys.
- `default_tokens` in `isupport.zig` is the authoritative ISUPPORT policy table and should drive the config, not the scattered per-module defaults.
