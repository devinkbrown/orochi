# 17 — SerpentRegistry Module System + Helix Upgrade (clean-room design)

Status: **design + active build**. This is the consolidated synthesis of six deep-research
reports (Zig-native module idioms, IRCd module-system mistakes, in-process upgrades,
cross-language plugin systems, upgrade engineering, WASM verdict) reconciled with the
vocabulary already laid down in `05-innovation.md` (SerpentRegistry, Helix Upgrade, Event
Spine, CoilPack, OroWasm, Codec Loom) and the code that already exists
(`src/daemon/registry.zig`).

The thesis, in one line: **the core is compiled in (comptime registry, zero ABI boundary,
typed hooks, compile-time graph validation); only untrusted third-party extensions get a
sandbox (WASM); state moves between binary versions through typed, versioned capsules, not
`void*` blobs.** Every decision below is justified against a concrete mistake the C lineage
(ophion / Solanum / UnrealIRCd / InspIRCd) actually made.

---

## 0. What already exists (do not re-invent)

- `src/daemon/registry.zig` — **SerpentRegistry**: a working comptime registry. `Module`
  struct literal carries `id/requires/conflicts/commands/hooks/caps/chanmodes/usermodes/
  numerics/isupport`; `Registry(mods)` validates at comptime (duplicate id/command/cap/mode/
  numeric, missing dep, conflict) and generates immutable command/hook/cap/mode/numeric/
  isupport tables + `dispatch()` + priority-ordered `callHook()`. 4 tests pass. **It is not
  yet wired into the live server.**
- `src/daemon/server.zig` (9.6k lines) — `dispatchRegistered()` is a ~190-line
  `eqlIgnoreCase` if-chain over ~90 commands, each an `LinuxServer` method
  (`handleJoin`, `handleWhois`, …). This is the spine to modularize.
- `src/daemon/event_spine.zig` — typed event bus (Event Spine, already live).
- `src/proto/coilpack*.zig` — canonical signature-stable wire format (capsule substrate).
- `build.zig` builds OPVOX/OPVIS to **freestanding wasm32** already; the team owns the
  `wasm32-freestanding` toolchain. The daemon does **not** yet host/execute WASM.

The module system is therefore ~60% latent: the registry exists, the seam to the live
dispatch does not. This doc specifies the seam, the typed capability/hook layer, the
lifecycle, Helix Upgrade, and the WASM boundary.

---

## 1. Anti-pattern catalog → countermeasures (the design contract)

From `ircd-mistakes-and-wasm.md`. Every line is a hard rule for this design.

| # | Anti-pattern (seen in C lineage) | Orochi countermeasure |
|---|---|---|
| AP-1 | Cross-binary struct/vtable ABI as the load contract | **No ABI boundary for core** — modules are comptime-composed into one binary. Cross-version state uses a typed wire schema (CoilPack), never a memory layout. |
| AP-2 | Coarse global version integer → fleet recompile | No global ABI integer. Cross-version negotiation is **per-capsule schema id + min/max**, and (for WASM) per-host-function. |
| AP-3 | `RTLD_GLOBAL` symbol pollution, double-dlopen, DEEPBIND maze | No dynamic linker. Modules reference each other through the **typed registry + Services handle**, never global symbols. |
| AP-4 | `void*` hook payloads, integer/alphabetized hook IDs | **Typed `HookId` enum + comptime `HookPayload(id) → type`**. Compiler rejects a handler that reads the wrong payload; adding a hook can't renumber anything. |
| AP-5 | Manual N-registry register/unregister, leak-prone | Comptime registration: there is nothing to unwind at runtime. (WASM plugins: host owns all registrations keyed by plugin handle; teardown = drop the store.) |
| AP-6 | Crash-on-unload / use-after-unmap | Core code is never unmapped at runtime. Version changes go through **Helix Upgrade** (drain to a new process). WASM "unload" = drop an isolated store, no unmap race. |
| AP-7 | Load-order/dep/conflict/cascade resolver bugs | The dependency/conflict graph is resolved **at compile time**; a cycle or collision fails the *build*, never the running server. |
| AP-8 | No fault isolation; raw pointers handed to plugins (CPython) | Core is type-safe comptime Zig. Untrusted extensions run in a **WASM sandbox** (linear memory, fuel/epoch limits, no raw host pointers). |
| AP-9 | `void*` state blobs across reload | All cross-reload / cross-upgrade state is **typed + versioned** (CoilPack capsules with schema id, semantic validator, min/max). |
| AP-10 | `.so`-per-command boilerplate sprawl | A module is a **typed registry value** (`Module{ .commands = …, .hooks = … }`); tables are generated, glue is deleted. |

8 modern principles we adopt (from `zig-native.md`): embedded-interface +
`@fieldParentPtr` for any runtime-heterogeneous interface; comptime manifest registry with
DCE of disabled modules; capability injection via one typed `Services` struct (no globals);
per-module comptime descriptor; `fn(comptime Deps) type` for sized subsystems; **unmanaged**
std containers (allocator supplied at call site); build-every-feature-combo in CI; prefer a
small fixed-set tagged union only for the always-on protocol core.

---

## 2. Module model

A module is a comptime `registry.Module` value (already defined). We extend it minimally:

```zig
pub const Module = struct {
    id: []const u8,
    version: Version = .{ .major = 0, .minor = 0, .patch = 0 }, // NEW: per-module, not global
    category: Category = .feature,                              // NEW: core | protocol | service | security | feature | media | diagnostic
    requires: []const []const u8 = &.{},
    optional_requires: []const []const u8 = &.{},              // NEW: soft dep (one field, not two — fixes ophion's accreted alias)
    conflicts: []const []const u8 = &.{},
    priority: Priority = .normal,                               // NEW: init/activate ordering within a category

    commands: []const CommandSpec = &.{},
    hooks:    []const HookBinding = &.{},
    caps:     []const CapSpec = &.{},
    chanmodes:[]const ChanModeSpec = &.{},
    usermodes:[]const UserModeSpec = &.{},
    numerics: []const NumericSpec = &.{},
    isupport: []const ISupportSpec = &.{},
    config_blocks: []const []const u8 = &.{},                   // NEW: TOML sections this module owns (e.g. "media", "filter")

    // Lifecycle hooks (all optional). Signatures take the typed *Core (§4).
    on_register:  ?*const fn (*Core) anyerror!void = null,
    on_init:      ?*const fn (*Core) anyerror!void = null,
    on_ready:     ?*const fn (*Core) anyerror!void = null,
    on_reload:    ?*const fn (*Core) anyerror!void = null,
    on_deinit:    ?*const fn (*Core) void = null,
};
```

**Command handler signature is unified** to `*const fn (*Core) anyerror!void` (the registry's
existing `*anyopaque` handler stays the erased ABI; `*Core` is what we pass as `ctx`). One
signature replaces the ~90 heterogeneous `handleXxx(self, id, conn, parsed, line)` methods —
all of that context now lives on `Core` (§4).

The manifest is one tuple in `src/daemon/modules/manifest.zig`:

```zig
pub const enabled = [_]registry.Module{
    core_protocol.module,     // NICK/USER/PING/QUIT/PRIVMSG/NOTICE — always on
    channel_ops.module,       // JOIN/PART/MODE/KICK/TOPIC/INVITE/NAMES/KNOCK
    query_info.module,        // VERSION/TIME/ADMIN/INFO/MOTD/LUSERS/USERS/MAP/LINKS/STATS
    accounts.module,          // REGISTER/VERIFY/IDENTIFY/LOGOUT/DROP/ACCOUNTINFO/ACCOUNTSET
    ircx.module,              // IRCX/CREATE/PROP/ACCESS/EVENT/DATA/WHISPER/MODEX/LISTX
    services_chan.module,     // CHANNEL/CS/GHOST/SESSION
    security.module,          // WARD/SHUN/KILL/CLOSE/DRAIN/UNREJECT/TESTLINE/TESTMASK
    operator.module,          // OPER/REHASH/DIE/RESTART/CONNECT/SQUIT/TRACE/ETRACE/STATS
    media.module,             // MEDIA + breakout/spatial/captions/reactions
    messaging_v3.module,      // TAGMSG/CHATHISTORY/MARKREAD/REDACT/METADATA/MONITOR/SILENCE
    // … one line per module; disabled = deleted line = dead-code-eliminated
};
pub const Live = registry.Registry(&enabled); // comptime-validated; build fails on collision
```

Adding a module = one line. A disabled module is fully DCE'd. A duplicate command across two
modules is a **compile error**, not a runtime surprise (AP-7/AP-10 dissolved).

---

## 3. Typed hooks (AP-4 killer)

Replace the stringly-typed `hook: []const u8` with a typed enum + a comptime payload map.
This is the single most important upgrade to `registry.zig`.

```zig
pub const HookId = enum {
    client_pre_register, client_registered, client_quit,
    channel_pre_join, channel_joined, channel_part,
    message_pre_deliver,           // veto-capable
    nick_pre_change, nick_changed,
    oper_elevated,
    config_reloaded,
    upgrade_capsule_export, upgrade_capsule_import,
    // …
};

pub fn HookPayload(comptime id: HookId) type = switch (id) {
    .client_registered   => *ClientRegistered,
    .channel_pre_join    => *ChannelPreJoin,    // has `approved: bool` for veto
    .message_pre_deliver => *MessagePreDeliver, // has `approved: bool` + mutable tags
    // …
};
```

A `HookBinding` becomes `{ id: HookId, priority, handler: *const fn(*Core, HookPayload(id)) anyerror!HookResult }`,
enforced by a small comptime wrapper so the handler's payload type is checked at the binding
site. `callHook(comptime id, core, payload)` keeps the priority-ordered, stop-on-veto
semantics already in `registry.zig`. **Veto** = a `*X` payload carrying `approved: bool` that
an early hook can flip; the dispatcher honors it. This is how anti-spam/join-gates/policy
hooks say "no" without owning core state.

Dispatch is **phase-based**: the generated hook table is grouped by `HookId` at comptime, so
firing `channel_pre_join` only walks bindings for that id (no scan of unrelated hooks — fixes
the per-call cost worry).

---

## 4. Capability injection — the `Core` / `Services` handle (AP-3/AP-8 killer)

No module ever reaches for a global. Everything it may touch arrives through one typed
handle. We split per-invocation context (`Core`) from long-lived capabilities (`Services`):

```zig
pub const Services = struct {              // long-lived, host-owned, survives upgrades
    allocator: std.mem.Allocator,          // HOST-owned (the §3c hot-reload allocator bug)
    io: std.Io,                            // 0.16 IO interface, injected not global
    clock: Clock,
    config: *const server.Config,
    events: *event_spine.Bus,              // publish/subscribe (WALLOPS/snomask/audit/IRCX EVENT)
    log: Logger,
    world: *World,                         // converged mesh → IRC surface (read mostly)
    rng: Csprng,
};

pub const Core = struct {                  // per-command-invocation context
    services: *Services,
    server: *LinuxServer,                  // escape hatch during migration; narrowed over time
    id: client_model.ClientId,
    conn: *ConnState,
    parsed: *const irc_line.LineView,
    line: []const u8,

    // narrow typed helpers a module is allowed to use:
    pub fn reply(self: *Core, code: Numeric, params: []const []const u8, trailing: []const u8) !void {…}
    pub fn nowMs(self: *Core) i64 {…}
    pub fn account(self: *Core) ?[]const u8 {…}
    pub fn isOper(self: *Core) bool {…}
    pub fn emit(self: *Core, comptime id: HookId, payload: HookPayload(id)) !HookResult {…}
    pub fn publish(self: *Core, ev: anytype) void { self.services.events.publish(ev); }
};
```

Migration reality: `Core.server` is the escape hatch so a module handler can call the
existing `LinuxServer.handleXxx` body verbatim on day one. As each family is extracted, its
logic moves behind narrow `Core` helpers and the raw `server` reach-through shrinks. The
end-state goal is that feature/service/security modules touch only `Services` + narrow `Core`
helpers, never `*LinuxServer` directly. (Always-on protocol core keeps direct access — it
*is* the core.)

Containers in module state are **unmanaged** (`ArrayListUnmanaged`, `AutoHashMapUnmanaged`),
allocator supplied from `services.allocator` at the call site.

---

## 5. Lifecycle

Multi-phase, ordered by `(category, priority, manifest order)`, resolved at comptime:

```
register → init → ready → activate ──(running)── on_reload* → deactivate → drain → deinit
```

- **register**: declare-only (already implicit in the manifest); no side effects.
- **init**: allocate module state from `services.allocator`, open stores. Deps guaranteed
  inited first (comptime topo-sort).
- **ready**: cross-module wiring is safe (all peers inited).
- **activate**: begin accepting traffic / arm timers.
- **on_reload**: REHASH re-runs config; module re-reads its `config_blocks`. Pure;
  no teardown.
- **drain**: Helix Upgrade quiesce — finish in-flight, refuse new, flush WAL. An atomic
  in-flight counter gates the handoff (two-version coexistence window).
- **deinit**: free state. (Never an `.so` unmap — AP-6.)

The strangler-fig wiring keeps the legacy path alive throughout: the registry is consulted
first; unmigrated commands fall through to the existing if-chain. The daemon is shippable at
every step.

---

## 6. Live dispatch seam (the wiring)

`dispatchRegistered` becomes:

```zig
fn dispatchRegistered(self, id, conn, parsed, line) !void {
    var core = Core{ .services = &self.services, .server = self, .id = id,
                     .conn = conn, .parsed = parsed, .line = line };
    switch (try Live.dispatch(&core, parsed.command, parsed.params())) {
        .handled => return,
        .too_few_params => |min| return core.reply(.ERR_NEEDMOREPARAMS, …),
        .not_found => {},   // fall through to legacy chain (shrinks each wave)
    }
    // … existing if-chain, minus every command already migrated …
}
```

`Registry.dispatch` already does case-insensitive lookup + min-param check + `*anyopaque`
handler call; passing `&core` as ctx is the whole integration. Module handlers
`@ptrCast(@alignCast(ctx))` back to `*Core`.

---

## 7. Helix Upgrade (in-process upgrade) — `orochi --supervisor`

The clean-room replacement for ophion's externalized shim. Same binary, `--supervisor` mode.

**Topology.** The supervisor process owns the listening sockets and a sealed `memfd` handoff
arena, and speaks to the worker over an `AF_UNIX` `SOCK_SEQPACKET` control socket. On
`/UPGRADE`:

1. Worker **freezes accept**, drains module in-flight counters, flushes WAL.
2. Worker serializes schema-versioned **CoilPack capsules** (clients, channels, sessions,
   TLS/kTLS session state, VEIL ratchets, mesh CRDT Merkle checkpoints, raw send queues)
   into the **sealed memfd** (seals prevent post-handoff mutation).
3. Client/peer **fds are dup'd to the new worker via `SCM_RIGHTS`** over the SEQPACKET socket
   (respect the 253-fd/`sendmsg` batch limit — chunk it). kTLS sockets keep kernel crypto
   continuity across exec; non-kTLS TLS rides session capsules; io_uring registered files do
   **not** survive exec, so the new worker re-`REGISTER_FILES` into a fresh ring.
4. New worker reconstructs state from capsules, validates each (schema id + semantic
   validator + min/max), and sends a **health attestation** before the old worker exits.
5. **Auto-rollback**: the supervisor still holds the listeners; if the new worker fails
   attestation or times out, the old worker is told to un-freeze and resume — zero dropped
   clients. The new worker is reaped.

**Versioning (AP-2/AP-9).** Every capsule has `{schema_id, version, min_supported,
max_supported}`. The simulator (`Deterministic Ocean`) runs mixed-version upgrade campaigns
across the last N schemas. No global ABI integer anywhere — compatibility is per-capsule.

State-migration contracts use Cap'n-Proto-style **ordinal evolution** (add fields with new
ordinals, never reorder) and expand-contract for CRDT shapes. This is the same typed-capsule
discipline as `12-world-projection.md` / CoilPack, reused — not a second mechanism.

Files (new, no `server.zig` contention): `src/daemon/helix/supervisor.zig`,
`helix/handoff.zig` (memfd + SCM_RIGHTS), `helix/capsule.zig` (schema registry over
CoilPack), `helix/attest.zig`.

---

## 8. OroWasm — sandboxed third-party control-plane plugins (optional layer)

**Verdict (from `ircd-mistakes-and-wasm.md`): worth it, but narrowly.** WASM is the right
answer for *untrusted third-party extensions* and the wrong answer for *core*. It replaces
ophion's embedded-CPython bridge and is a clear upgrade: fault isolation (AP-8), no raw host
pointers, atomic teardown (AP-6: drop the store), fuel/memory limits, determinism for replay.

Hard boundaries:

- **Allowed (control plane only):** command handlers, hook/event reactions, timers, outbound
  replies, read-only client/channel lookup, a namespaced store slice, services/moderation
  logic.
- **Forbidden:** per-frame media (OPVOX/OPVIS stay native), the io_uring completion path,
  per-byte parsing. The copy-in/out + per-call tax is negligible on the control plane and
  unacceptable on the hot path.
- **No C interop** (project hard rule) ⇒ the runtime is a **pure-Zig wasm32 interpreter**
  (interpreter speed is fine for control-plane call rates), not Wasmtime/Extism (those are
  Rust reachable only over a C ABI — which would re-introduce AP-1).
- **Design the host API first.** The host↔plugin contract is a **typed, versioned,
  permissioned wire schema** (WIT-like, expressed in CoilPack), per-host-function
  capabilities — *not* a struct layout, *not* a global integer. This is the part that must be
  right from day one or it recreates the C API problem (AP-1/AP-2/AP-9 reborn).
- Time + randomness flow through hostcalls ⇒ plugins are replayable under the deterministic
  simulator (an advantage no native `.so` model can offer).

OroWasm is **phase-last** and opt-in. The comptime registry ships and proves itself first;
WASM plugs into the *same* `Module`/`HookId`/`Services` contract as a sandboxed producer of
registry entries owned by the host handle.

Files (new): `src/wasm/host/interp.zig` (interpreter), `wasm/host/abi.zig` (versioned host
API schema), `wasm/host/plugin.zig` (store lifecycle + per-handle registration ownership).

---

## 9. Build plan (waves)

The seam is the only serial, collision-prone step; everything after fans out.

| Wave | Scope | Parallelizable? | Owner |
|---|---|---|---|
| **W0** | This design doc | — | done |
| **W1** | Typed `HookId`+payload map + lifecycle fields in `registry.zig`; `module_core.zig` (`Core`/`Services`); wire `Live.dispatch` into `dispatchRegistered` (strangler-fig); migrate first batch (query/info: VERSION/TIME/ADMIN/INFO/MOTD/LUSERS/USERS/MAP/LINKS). Build green. | **No — serial (me)** | main |
| **W2a** | Helix Upgrade supervisor skeleton (new files) | Yes — disjoint | agent/codex worktree |
| **W2b** | OroWasm host API schema + interpreter MVP (new files) | Yes — disjoint | agent/codex worktree |
| **W2c** | Migrate channel-ops family into `modules/channel_ops.zig` | Yes — disjoint manifest section | agent/codex worktree |
| **W2d** | Migrate accounts/services family into `modules/accounts.zig` | Yes — disjoint | agent/codex worktree |
| **W2e** | Migrate IRCX family into `modules/ircx.zig` | Yes — disjoint | agent/codex worktree |
| **W2f** | Migrate security/operator family into `modules/security.zig` + `operator.zig` | Yes — disjoint | agent/codex worktree |
| **W3** | Integrate all worktrees, delete migrated if-chain arms, `zig build test` + `-Dtarget=x86_64-windows` green, live smoke | Serial (me) | main |

Parallel-safety rule (per `workflow_claude_codex_parallel`): every parallel worker runs in
its **own git worktree**; never `git add -A`; I integrate and resolve. Each migration worker
owns a **disjoint** set of commands and writes a **separate** module file + a clearly-marked
manifest stanza, so the only integration conflict is the one-line manifest insert, which I
fold in by hand.

## 10. Test strategy

- Comptime: the registry already fails the build on duplicate command/cap/mode/numeric,
  missing dep, conflict, and (new) dependency cycle. Add a cycle test.
- Unit: each module file ships `std.testing` tests for its handlers against a fake `Core`.
- Golden: existing IRC/IRCv3/IRCX goldens must stay green through every wave (behavior is
  preserved — handlers are *moved*, not rewritten).
- Upgrade: Deterministic Ocean mixed-version capsule campaigns for Helix.
- WASM: replay determinism + fuel/memory-limit enforcement tests for OroWasm.
- CI: build every feature-combo manifest (Ghostty's lesson — unreferenced comptime branches
  rot silently).
