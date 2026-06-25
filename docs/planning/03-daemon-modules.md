# Daemon core, comptime modules, and feature parity
*Design note from the planning phase — records design intent; shipped behavior is documented under docs/guide/ and docs/reference/.*

This document defines the planning-phase daemon architecture, comptime module model, persistence approach, and Ophion feature-parity assignments.

Note: `ophion/modules/extensions/` is absent in this checkout, so the inventory below covers `modules/` plus `python_modules/`.

## Design position

Orochi should not port Ophion’s module system. Ophion’s MAPI v4 centers on runtime `_mheader` discovery through `dlopen`/`dlsym`, then late command/hook/cap registration (`modules.c`, `modules.h`). That made sense for C, but it is the wrong substrate for a Zig-native daemon with no C interop.

Orochi’s core should be a statically linked, compile-time assembled daemon. Modules are Zig packages selected by build profile. The compiler validates the graph, emits command tables, hook dispatchers, capability bitsets, ISUPPORT rows, mode tables, config schemas, and numeric metadata. Runtime `/REHASH` changes config and policy, not the code graph. Runtime feature-set changes happen through graceful drain into a newly built binary.

This matches the Orochi brief: clean-slate Zig-native, Ophion/libop/opssl as reference only, full feature surface, and LADON+VEIL replacing TS6 ([BRIEF.md](orochi/docs/BRIEF.md), [BRIEF.md](orochi/docs/BRIEF.md), [BRIEF.md](orochi/docs/BRIEF.md)).

## Daemon lifecycle

Use TOML externally, but not Ophion’s legacy callback bridge. Ophion currently parses `ircd.toml` through a TOML bridge and special-cases `[modules]` and `modblacklist` (`toml_conf.c`, `toml_conf.c`, `toml_conf.c`). Orochi should keep TOML because operators know it, but generate a typed config parser from module schemas at comptime. ZON is better for Zig developers, not IRC operators.

Lifecycle steps:

1. `BootEarly`: initialize allocator, monotonic clock, structured logger, crash ring, signal FD.
2. `ParseConfig`: parse TOML into generated `ConfigDraft`; validate cross-module constraints.
3. `InitRegistry`: registry is already compile-time generated; runtime only binds config to modules.
4. `InitStores`: open `OroStore`, load accounts, channels, bans, history, memos, vhosts.
5. `InitNetwork`: start transport backends, TLS, WebSocket, LADON mesh, resolver, GeoIP reader.
6. `InitServices`: build account/channel/memo/vhost service indexes.
7. `InitModules`: call typed `init` hooks in dependency order.
8. `Accepting`: open listeners and enter structured reactor.

Signals should be event-loop inputs, not async mutation. Ophion sets global flags like `dorehash`, `do_shutdown`, `do_upgrade_drain` from signal handlers (`ircd.c`, `ircd_signal.c`). Orochi should use Linux `signalfd` where available and a self-pipe fallback elsewhere.

`/REHASH` should parse config off-reactor, validate, publish a new immutable config generation, then call typed hooks: `RehashPrepare`, `RehashCommit`, `RehashAbort`. Ophion already moved toward async rehash and worker quiescence (`s_conf.c`, `s_conf.c`). Orochi should make this a first-class state machine.

Graceful drain should preserve Ophion’s operational goal but replace the shim protocol with a typed supervisor. Ophion closes listeners, drains or migrates clients, fires upgrade hooks, and forces exit on timeout (`restart.c`, `restart.c`, `restart.c`). Orochi states: `Running`, `Rehashing`, `Draining`, `Migrating`, `Stopping`. A successor binary receives typed session capsules: socket FD, TLS transcript state if resumable, client ID, caps, registration state, flood counters, SASL state, batches, and outbound queue watermark.

## Comptime module registry

Ophion has rich MAPI metadata: dependencies, conflicts, caps, commands, hooks, config blocks, save/restore state, flags like `NETWORK_WIDE`, `NO_UNLOAD`, `STATEFUL`, `NO_RELOAD`, `REQUIRES_OPER`, `TRUSTED` (`modules.h`, `modules.h`, `modules.h`). Orochi keeps the information, not the ABI.

Static comptime wins because:

- No C interop, no `dlopen`, no ABI drift.
- Command collisions and missing dependencies become compile errors.
- Hook payload types are checked by Zig.
- Capability bit positions and ISUPPORT output are generated once.
- `/REHASH` remains fast and safe because code does not unload under active users.

Build and runtime controls:

| Surface | Control |
|---|---|
| Build profile | `build.zig`: `-Dprofile=minimal|ircd|ircx|media|services|full` |
| Build toggles | `-Denable-wasm=true`, `-Denable-geoip=true`, `-Denable-media=true` |
| Runtime config | Can disable commands, caps, listeners, services, or oper privileges |
| Runtime boundary | Cannot load missing code. Changing the module set means building a new binary and using graceful drain. |

Registry sketch:

```zig
pub const Module = struct {
    id: ModuleId,
    category: Category,
    requires: []const ModuleId = &.{},
    conflicts: []const ModuleId = &.{},
    features: []const Feature = &.{},

    commands: []const CommandSpec = &.{},
    hooks: []const HookBinding = &.{},
    caps: []const CapSpec = &.{},
    chanmodes: []const ChanModeSpec = &.{},
    usermodes: []const UserModeSpec = &.{},
    numerics: []const NumericSpec = &.{},
    isupport: []const ISupportSpec = &.{},

    Config: type = void,
    init: ?fn (*Core) anyerror!void = null,
    deinit: ?fn (*Core) void = null,
};

pub fn Registry(comptime mods: []const Module) type {
    comptime {
        validateDependencies(mods);
        validateConflicts(mods);
        validateUniqueCommands(mods);
        validateUniqueCaps(mods);
        validateModeLetters(mods);
        validateNumerics(mods);
    }

    const command_table = comptime buildCommandTable(mods);
    const hook_table = comptime buildHookTable(mods);
    const cap_table = comptime buildCapTable(mods);
    const config_schema = comptime buildConfigSchema(mods);

    return struct {
        pub const commands = command_table;
        pub const hooks = hook_table;
        pub const caps = cap_table;
        pub const Config = config_schema;

        pub fn dispatch(core: *Core, client: ClientId, line: ParsedLine) !void {
            const spec = commands.lookup(line.command) orelse
                return core.reply.errUnknownCommand(client, line.command);
            return spec.invoke(core, client, line);
        }

        pub fn callHook(
            comptime hook: HookId,
            core: *Core,
            payload: *HookPayload(hook),
        ) !HookResult {
            var result: HookResult = .continue_;
            inline for (hooks[@intFromEnum(hook)]) |binding| {
                result = try binding.call(core, payload);
                if (result == .stop) break;
            }
            return result;
        }
    };
}

pub const cap_server_time = Module{
    .id = .cap_server_time,
    .category = .capability,
    .caps = &.{ .{ .name = "server-time", .kind = .client } },
    .hooks = &.{
        hook(.outbound_msg, .normal, addServerTime),
    },
};

fn addServerTime(core: *Core, msg: *OutboundMsg) !HookResult {
    msg.addTag(.server_time, "time", try core.clock.ircv3Time());
    return .continue_;
}
```

## Typed hooks

Ophion’s hook API is `typedef void (*hookfn)(void *data)` (`hook.h`), with global integer hook IDs and many ad hoc payload structs (`hook.h`, `hook.h`). Dispatch is runtime linked-list iteration over `void *` (`hook.c`, `hook.c`). Orochi replaces that with typed event specs:

```zig
pub const HookId = enum {
    client_pre_register,
    client_registered,
    before_privmsg_channel,
    before_privmsg_user,
    outbound_msg,
    channel_join,
    channel_lowerts,
    account_login,
    rehash_prepare,
    rehash_commit,
    upgrade_drain,
};

pub fn HookPayload(comptime hook: HookId) type {
    return switch (hook) {
        .outbound_msg => OutboundMsg,
        .before_privmsg_channel => PrivmsgChannelEvent,
        .account_login => AccountLoginEvent,
        .rehash_commit => RehashCommitEvent,
        else => EmptyHook,
    };
}
```

Dispatch ordering is `.first`, `.early`, `.normal`, `.late`, `.last`, matching the spirit of Ophion’s priority constants (`hook.h`). Ties are stable by module order.

Cap-gated emission becomes a type-level property. Ophion stores message tags with `capmask` and linebuf caches by capability mask (`msgbuf.h`, `msgbuf.h`, `msgbuf.h`). Orochi should model this explicitly:

```zig
pub const WireTag = struct {
    key: []const u8,
    value: ?[]const u8,
    gate: CapExpr,
};

pub fn addTag(
    msg: *OutboundMsg,
    comptime cap: CapId,
    comptime key: []const u8,
    value: []const u8,
) void {
    msg.tags.appendAssumeCapacity(.{
        .key = key,
        .value = value,
        .gate = CapExpr.one(cap),
    });
}
```

A handler cannot accidentally emit `time` to non-`server-time` clients because the tag constructor requires a capability gate.

## Data model and parse pipeline

Use opaque generational IDs instead of raw pointers:

```zig
pub const ClientId = packed struct { shard: u12, slot: u20, gen: u32 };
pub const ChannelId = packed struct { shard: u12, slot: u20, gen: u32 };
pub const MembershipId = packed struct { shard: u12, slot: u20, gen: u32 };
```

`Client` is split into components:

| Component | Contents |
|---|---|
| `Identity` | nick, uid, account, realname, visible host, cloaked host |
| `Connection` | transport, local address, TLS/WebSocket state, send queue |
| `Registration` | prereg state, CAP state, SASL state |
| `Permissions` | oper class, services access, IRCX flags |
| `Rate` | flood, spam, command buckets |
| `Protocol` | negotiated caps, labeled-response, batches, multiline |

Ophion’s current `Client`/`LocalUser` packs identity, transport, caps, WebSocket, SASL, queues, S2S/LADON, and auth state together (`client.h`, `client.h`). Orochi should keep the data, but split ownership.

`Channel` stores name, topic, modes, member map, hot local-recipient arrays, bans/except/invex/quiet, props, access entries, history cursor, and LADON CRDT metadata. Ophion already maintains member buckets, ban lists, prop/access pointers, mode logs, caches, and locks (`channel.h`). Orochi should make those structures explicit and testable.

Command dispatch:

1. Transport yields bytes.
2. Zero-copy IRC line parser builds `ParsedLine`.
3. Message-tags parser validates client-only tags.
4. CAP, batch, labeled-response, multiline, and registration middleware run.
5. Registry dispatches by interned command.
6. Typed handler writes through `ReplyCtx`.

Ophion’s parser resolves prefixes, looks up `struct Message`, intercepts batch handlers, enforces min params, then calls handler slots (`parse.c`, `parse.c`, `parse.c`, `parse.c`). Orochi keeps the pipeline, but handlers are generated function pointers with typed contexts, not mutable dictionaries guarded by runtime locks.

## Full feature inventory

| Feature group | Ophion evidence | Orochi assignment | Effort | Rationale |
|---|---|---:|---:|---|
| Dynamic MAPI v4, module flags, deps, priorities | MAPI header and flags in `modules.h`, `modules.h`; runtime scanning in `modules.c` | DROP-AND-REPLACE | L | Replace with `SerpentRegistry` comptime graph and generated tables. |
| Core command registry | Handler slots in `msg.h`; runtime `mod_add_cmd` in `parse.c` | COMPTIME-GENERATE | M | Generate command table and registration gates. |
| Core user/channel commands: PASS, NICK, USER, CAP, AUTHENTICATE, PING/PONG, QUIT, JOIN/SJOIN, PART, KICK, PRIVMSG, NOTICE, TAGMSG, MODE/TMODE/MLOCK/BMASK, TOPIC, INVITE, NAMES/NAMESX, WHO/WHOX, WHOIS/WHOWAS, LIST/LISTX, LUSERS, MOTD, VERSION, TIME, ADMIN, INFO, STATS, LINKS, MAP, TRACE, ETRACE, CHANTRACE, MASKTRACE, USERHOST, ISON, AWAY, ACCOUNT, MONITOR, ACCEPT, KNOCK, CHGHOST, REALHOST, SETNAME, STARTTLS, WEBIRC | Core module table in `modules.c`; representative message handler in `m_message.c` | NATIVE-ZIG | L | Native handlers with generated dispatch metadata. |
| Oper/server/security commands: OPER, PRIVS, WALLOPS, OPERWALL, SNOTE, REHASH, ACMERELOAD, RESTART, DIE, UPGRADE, CONNECT, SQUIT, SERVER, SID, SVSSID, ENCAP, KILL, CLOSE, TESTLINE, TESTMASK, TESTGECOS, SCAN, JUPE, HASHCHECK, RESYNC, REBURST, MSEQ, MSYNC, MRESYNC, STARTMSGPACK | Oper/server modules in `modules/`; server parse and dispatch in `parse.c` | NATIVE-ZIG | L | Keep behavior, remove legacy TS6-only code paths where LADON replaces them. |
| IRCv3 CAP framework and `cap-notify` | CAP LS/REQ/ACK/END in `m_cap.c`; cap-notify emission in `modules.c` | COMPTIME-GENERATE | M | Cap table generated from modules; runtime negotiation only toggles bits. |
| IRCv3 caps: `batch`, `draft/netsplit`, `draft/netjoin`, `message-tags`, `echo-message`, `server-time`, `account-tag`, `account-notify`, `account-extban`, `away-notify`, `draft/pre-away`, `bot`, `cap-notify`, `chghost`, `setname`, `tls`, `sts`, `utf8-only`, `no-implicit-names`, `extended-monitor`, `draft/chathistory`, `draft/event-playback`, `msgid`, `draft/multiline`, `draft/read-marker`, `draft/channel-rename`, `draft/file-upload`, `draft/search`, `draft/reply`, `draft/react`, `draft/message-editing`, `draft/message-redaction`, `draft/typing`, `ophion/prop-notify`, `ophion/session-sync`, `ophion/ladon-media` | Examples: `cap_batch.c`, `cap_message_tags.c`, `cap_server_time.c`, `m_chathistory.c`, `m_sasl_core.c` | COMPTIME-GENERATE | L | Cap declarations generate negotiation, tag gates, ISUPPORT, and tests. |
| Message tags, replies, reactions, edits, redactions, typing | TAGMSG and tag relay in `cap_message_tags.c`; server-time tag hook in `cap_server_time.c` | NATIVE-ZIG | M | Typed outbound envelope with gated tags. |
| Batch, netsplit/netjoin, multiline | Batch interception in `parse.c`; multiline cap module exists in `modules/m_multiline.c` | NATIVE-ZIG | M | Middleware layer before command dispatch. |
| Chathistory, msgid, event playback, read-marker, search | History ring and caps in `m_chathistory.c`; msgid state in `m_chathistory.c` | NATIVE-ZIG | L | Back by `OroStore` history column family. |
| SASL core and numerics 900/903/904/905/906/907/908 | SASL core in `m_sasl_core.c` | COMPTIME-GENERATE | M | Mechanism registry generated; session runtime native. |
| SASL PLAIN, SCRAM-SHA-256, SCRAM-SHA-256-PLUS, SCRAM-SHA-512, EXTERNAL, ACCOUNT | PLAIN in `sasl_plain.c`; SCRAM in `sasl_scram.c` | NATIVE-ZIG | L | Implement crypto in Zig; expose typed mechanism interface. |
| IRCX base, opt-in, `IRCX`, `ISIRCX`, `%#`, MAXCODEPAGE/MAXLANGUAGE | `m_ircx_base.c`, `m_ircx_base.c` | NATIVE-ZIG | M | Keep legacy surface as native compatibility layer. |
| IRCX PROP, TPROP, BTPROP, entity/account/channel/user/member/onjoin/onpart/opkey/ownerkey/profile props | PROP system in `m_ircx_prop.c`; hookable synthetic props in `m_ircx_prop.c` | COMPTIME-GENERATE | L | Generate property schemas and propagation codecs. |
| IRCX ACCESS, SACCESS, channel/server access, DENY/GRANT/QUIET/HOST/OP/OWNER/VOICE | `m_ircx_access.c`, `m_ircx_access.c` | NATIVE-ZIG | L | Merge with typed permission lattice. |
| IRCX WHISPER, CREATE, LISTX, REQUEST/REPLY, AUTH, EVENT, DATA/comic | Comic support in `m_ircx_comic.c`; event masks in `m_ircx_event.c` | NATIVE-ZIG | L | Preserve protocol behavior, modernize internals. |
| IRCX modes: MODEX names, +u +h +a +d +E +f +z +r, auditorium +x, nowhisper +w, comic +Y | MODEX names in `m_ircx_modex.c`; comic +Y in `m_ircx_comic.c` | COMPTIME-GENERATE | M | Mode letters and privilege ranks generated with collision checks. |
| Services: NickServ/account REGISTER, DROP, IDENTIFY, GHOST, RECOVER, GROUP, INFO, SET, SENDPASS, ACCESS, CERT, SUSPEND | `svc_account.c`, login side effects in `svc_account.c` | NATIVE-ZIG | L | First-class services, no pseudo-client dependency. |
| Services: ChanServ REGISTER, DROP, INFO, SET, ACCESS, AKICK, TOPIC, INVITE, UNBAN, KICK, REWIND | `svc_channel.c` | NATIVE-ZIG | L | Store-backed channel registry and rewind. |
| Services: MemoServ, VHost/HostServ, service sync, account-notify/FNC | Service DB scope in `services_db.c`; service module caps in `m_services.c` | NATIVE-ZIG | L | Model as service domains over `OroStore`. |
| WebSocket and WEBIRC | In-process WS in `wsproc.c`; listener flow in `listener.c`; WEBIRC in `m_webirc.c` | NATIVE-ZIG | M | Pure Zig HTTP upgrade/framing and trusted gateway policy. |
| GeoIP | MaxMind integration in `geoip.c`; S2S GEOIP in `m_geoip.c` | DROP-AND-REPLACE | M | Implement Zig MMDB reader or generated prefix DB; no C library. |
| Cloaking/host identity | `mangledhost` in `client.h`; config `cloaking_style` in `s_conf.h` | DROP-AND-REPLACE | M | Replace ad hoc host mangling with typed identity policy. |
| Spamfilter | Scoring/actions in `m_spamfilter.c`; hooks in `m_spamfilter.c` | DROP-AND-REPLACE | L | Compile filters to Zig-native DFA/glob/regex programs at rehash. |
| Bans: KLINE, DLINE, XLINE, RESV, GAG, NOCHANNEL, NONICK, GRANT | Unified ban module in `m_banlist.c`; DB tables in `bans_db.c` | NATIVE-ZIG | M | Store-backed ban graph with generated oper commands. |
| LADON/VEIL/media: LADON, MEDIA, MEDIAFRAME, MEDIASTATUS, VOICELIST, BWREPORT, DATASTAT, WHITEBOARD, STREAM/POLL/RAID, ABR, simulcast, mixer, CRDT, transcript, datachannel, E2E | Brief mandates LADON+VEIL replacing TS6 ([BRIEF.md](orochi/docs/BRIEF.md)); modules exist under `modules/m_ladon_*` | NATIVE-ZIG | XL | Native network substrate, not an IRC module bolted on. |
| Python modules: API, bot, bridge/relay, webadmin, OAuth, push, RSS, search, URL preview, Twitch, Matrix, moderation, games, notes, polls, paste, Prometheus, etc. | CPython embedding in `pymod.c`; API capsules in `pymod_api.c`; Python module set in `python_modules/` | DROP-AND-REPLACE | XL | Replace CPython with sandboxed WASM plugins. |

## Scripting and extensibility

Ophion embeds a single CPython interpreter, imports `.py` modules, exposes `_ophion_ircd`, and bridges commands/hooks/timers through C trampolines (`pymod.c`, `pymod.c`). The API exposes raw client/channel handles and pointer registries (`pymod_api.c`, `ophion_pyapi.h`).

Orochi should drop embedded CPython.

Recommendation: `OroWasm`.

| Area | Plan |
|---|---|
| Core modules | Static Zig comptime modules only |
| Third-party extensions | Hot-reloadable WASM components |
| Host API | Generated from a WIT-like Zig schema |
| Safety | Fuel limits, memory limits, no raw pointers, no blocking syscalls |
| Determinism | Timers and randomness flow through hostcalls |
| Permissions | Plugin manifest declares command, hook, store, network, and oper scopes |

Cost is high, but it is the only option that gives hot reload, sandboxing, multi-language support, and no C ABI dependency. If a pure Zig WASM runtime is not mature enough, Orochi should build a minimal MVP runtime for command/hook plugins before supporting broad WASI.

## Persistence

Ophion uses SQLite for services and can use SQLite/LMDB for bans (`services_db.c`, `bans_db.c`). Orochi’s “no C interop” constraint rules out normal SQLite.

Recommendation: build `OroStore`, a Zig-native embedded store:

- Append-only WAL with checksummed records.
- Periodic snapshots.
- Typed column families: `accounts`, `nicks`, `certfps`, `account_access`, `chanregs`, `chanaccess`, `memos`, `vhosts`, `props`, `bans`, `history`, `read_markers`.
- Generated migrations from Zig schemas.
- Changefeed for service sync and LADON anti-entropy.
- Export/import tools for JSON and SQL text.

This is more work than SQLite, but it makes services, history, bans, and replay testing native to the daemon rather than dependent on an external C database.

## Novel technologies

| Technology | Planning role |
|---|---|
| `SerpentRegistry` | Comptime module graph that emits command dispatch, hook callsites, cap bitsets, ISUPPORT, numerics, mode tables, config schema, and inventory docs. It fails the build on dependency, conflict, command, cap, mode, or numeric collision. |
| `Aqualine` | Schema-generated wire codecs for IRC, IRCv3 tags, LADON, VEIL, numerics, and server capsules. Each command/numeric has a typed encoder and parser plus generated golden tests. |
| `CapProof` | Typed capability and permission lattice. IRCv3 caps, IRCX privileges, services access flags, oper privileges, and channel membership ranks are typed evidence values. Emitting a tag, running an oper command, or mutating access requires the correct evidence. |
| `KawaReplay` | Deterministic replay harness. Records input frames, config generation, timers, random seeds, store mutations, and LADON events. Replays crashes and protocol bugs exactly under `zig test`. |
| `FlowForge` | Structured concurrency for daemon work. Per-client serial command execution, cancellable channel transactions, bounded background tasks, and deadline propagation from command handlers to store/network operations. |
| `OroStore` | Typed store with snapshots, WAL, schema migrations, and CRDT-aware changefeed. It is persistence and replication substrate, not just a database wrapper. |

## Risks and open questions

- The feature surface is enormous. Full parity needs generated conformance tests from Ophion behavior before implementation starts.
- Static modules reduce operator flexibility. The mitigation is explicit build profiles plus graceful drain into a new binary.
- WASM is the right scripting target, but a pure Zig runtime may become its own large project. Define a narrow MVP: commands, timers, outbound replies, read-only client/channel lookup, limited store namespace.
- Pure Zig crypto/TLS, store, WebSocket, GeoIP, and regex engines are major risk areas. They need isolated milestones and fuzzing.
- IRCX compatibility has legacy ambiguity. Orochi should preserve wire behavior, but model it as a compatibility domain, not as a design center.
- LADON+VEIL replacing TS6 raises migration questions. Per the brief, TS6 should not be in core. If legacy bridging is needed, build a separate gateway, not a daemon mode.
- Spamfilter needs a Zig-native regex/glob engine. Start with glob plus compiled literal/substring/DFA rules, then add richer regex if needed.
- GeoIP needs a no-C answer: either a Zig MMDB reader or a generated prefix database.
- The old Python feature set is broad. WASM host APIs should be versioned and permissioned from day one, or plugin compatibility will recreate the old C API problem in a new form.
