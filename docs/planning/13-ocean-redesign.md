# 13 — Ocean redesign and Orochi caps

*Design note from the planning phase — records design intent; shipped behavior is documented under docs/guide/ and docs/reference/.*

Connects Ocean redesign tasks #16 / #17 to Orochi capability work from a read-only investigation of onyx and orochi.

## Ocean today (facts)

Condensed from a read-only investigation of onyx (Ocean, PROPRIETARY —
never push) and orochi.

| Area | Fact |
|---|---|
| Stack | Next.js 16 (React 19, App Router), TS5, Tailwind 4, Zustand 5, Vitest+Playwright, static export to `out/`. **pnpm only.** |
| Transport | WebSocket IRCv3 (`lib/irc/client.ts`) — SASL (SCRAM-SHA-512/256, SESSION-TOKEN, PLAIN), full CAP negotiation incl. `draft/chathistory,reply,react,typing,message-editing,message-redaction,multiline,read-marker`, plus `ophion/ladon-media`, `ophion/prop-notify`, `ophion/session-sync`. |
| Media | LADON over IRC (`MEDIAFRAME`/`MCHUNK`) + VEIL (P-256 ECDH + AES-256-GCM), Opcodec WASM (`lib/ladon-media/`). |
| Interface inventory | 138 components; ocean-depth theme (3 palettes); 40+ modals (modal fatigue). |

## #16 direction: mesh-native collaboration interface

Emphasize open IRCv3 + E2EE LADON + IRCX role/permission model instead of a
Discord-clone 3-column + modal cabinet. Use sans+mono pairing,
bioluminescent activity accents, and HLC-aware adaptive dark.

| Surface | Direction |
|---|---|
| Dynamic layout | Collapse serverbar <3 servers; place **presence ribbon** top; place **thread sidebar** right, replacing ThreadPanel modal. |
| Message views | Threaded message tree. |
| Reactions | Reactions with reactor avatar stacks. |
| Command access | Global `/` Spotlight command palette. |
| Forum route | Dedicated `/forum` route (tag browse + trending). |
| Permissions | Role badges = live permission indicators. |
| Voice | Draggable voice PIP. |
| Properties | Inline property/topic edit. |

## #17 new server caps mapped to Orochi subsystems

| Cap | Wire | Subsystem |
|---|---|---|
| ophion/presence-sync | MONITOR + activity in tags (status/channel/typing/speaking) | Event Spine + Store |
| ophion/activity-stream | `ACTIVITY SUBSCRIBE #ch` → server pushes voice/typing/edit/react events | Event Spine subscription |
| ophion/thread-sync | CHATHISTORY returns `@thread_parent_id`; `THREAD #ch <id> [GET\|SET CLOSED]` | Lotus history + Goryu CRDT |
| ophion/reaction-persist | `REACTIONS.<msgid>` PROP family / TAGMSG `+draft/react`; convergent | Goryu CRDT + Event Spine |
| ophion/role-matrix | `ROLEMX #ch` → RPL_ROLEDEF per role (perm bitmask) | IRCX Access + PROP |
| ophion/media-policy-query | `PROP #ch LADON.MEDIA.VOICE` GET → policy matrix | IRCX PROP |
| (future) spatial voice | MEDIAFRAME position vector → Web Audio panning | LADON + kagura_frame |

## Integration contract phases

| Phase | Scope |
|---|---|
| 1 | Presence & activity (MONITOR + ACTIVITY events). |
| 2 | Reaction persistence (Goryu CRDT keyed by msgid+emoji; CHATHISTORY carries them). |
| 3 | Threading (`thread_parent_id` in msg schema; Lotus index by (channel,parent); THREAD cmd). |
| 4 | Role matrix (PROP `ROLES.*` families + ROLEMX). |
| 5 | Activity stream subscription. |
| 6 | (future) spatial voice. |

## Implementation targets

| Area | Targets |
|---|---|
| Orochi | `store.zig` (UserActivity, MessageReaction, ThreadMetadata), `event_spine.zig` (ActivityChanged/ReactionAdded/ThreadStateChanged), `dispatch.zig` (ROLEMX, THREAD, PROP families), Goryu CRDT (reactions/thread state convergence), Lotus (thread index). |
| Ocean | PresenceRibbon, ThreadSidebar, SpotlightSearch, ForumBrowser, RoleMatrixEditor, voice PIP. |

This is planning only. Ocean lives in onyx (proprietary; never GitHub).
