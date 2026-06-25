# 07 — Ophion parity: the 100-item campaign

*Design note from the planning phase — records design intent; shipped behavior is documented under docs/guide/ and docs/reference/.*

This document records the parity backlog for the live single-node daemon, grounded in a full survey of `ophion` (ircd/core + modules/).

Items are ordered roughly by value and dependency. State-bearing items are grouped so a session can land a whole world-model change at once. Each item is a discrete, testable unit.

| Status | Meaning |
| --- | --- |
| `[x]` | done & e2e-tested |
| `[~]` | builder exists, not wired |
| `[ ]` | not started |

Keep the run-verified cadence: wire → threaded loopback test → fmt → native test → cross-compile exe → commit.

## A. Core user commands (live dispatch)

1. [x] AWAY (305/306, RPL_AWAY 301 on PRIVMSG, away in WHOIS)
2. [x] SETNAME (IRCv3, echo + setname-cap fan-out)
3. [x] OPER (381 / 464, +o reflection)
4. [x] WALLOPS (oper-gated 481, oper fan-out)
5. [x] REHASH (oper 382)
6. [x] INFO (371/373/374)
7. [x] USERS (392/393/394/395)
8. [x] LINKS (364/365, single-node)
9. [x] MAP (015/017, single-node)
10. [x] PONG (accepted)
11. [x] KILL (oper 481, graceful close-on-drain)
12. [x] WHOWAS (needs history store; daemon/whowas.zig exists) `[~]`
13. [x] USERIP (oper; needs per-conn IP)
14. [x] SUMMON (446 disabled stub)
15. [x] TAGMSG (IRCv3 message-tags; needs tag relay)
16. [x] NAMESX / UHNAMES (cap-driven NAMES formatting) `[x]` live via names_reply.zig (multi-prefix + userhost-in-names)

## B. Channel mode enforcement (world-model state wave)

> Land as one wave: add owned key (heap, not self-slice — channels live in a
> rehashing HashMap), limit (u32), invite list, ban/except/invex lists.

17. [x] MODE +k <key> set/unset (owned storage)
18. [x] MODE +l <limit> set/unset
19. [x] MODE +i toggle (already a flag) + invite-list recording via INVITE
20. [x] MODE +b <mask> add/remove (ban list storage)
21. [x] MODE +e <mask> ban-exception list
22. [x] MODE +I <mask> invite-exception list
23. [x] RPL_BANLIST 367 / RPL_ENDOFBANLIST 368
24. [x] RPL_EXCEPTLIST 348 / 349, RPL_INVITELIST 346 / 347
25. [x] JOIN enforce +k → ERR_BADCHANNELKEY 475
26. [x] JOIN enforce +l → ERR_CHANNELISFULL 471
27. [x] JOIN enforce +i → ERR_INVITEONLYCHAN 473 (respect invite list)
28. [x] JOIN enforce +b → ERR_BANNEDFROMCHAN 474 (respect +e)
29. [x] JOIN with key param: `JOIN #c key`
30. [x] +n no-external-messages enforcement on PRIVMSG/NOTICE
31. [x] +t topic-ops echoed in RPL_CHANNELMODEIS (324) — verified by e2e test
32. [x] MODE query shows key/limit params to members only
33. [x] KNOCK (713/711/ERR_CHANOPEN; needs +i) `[~]` proto/knock.zig
34. [x] Channel +p private (distinct from +s secret) in LIST/WHOIS

## C. Membership status and multi-target

35. [x] MODE multi-target/multi-flag batching (`+ov nick1 nick2`)
36. [x] JOIN comma-list of channels (`JOIN #a,#b key1,key2`)
37. [x] PART comma-list of channels
38. [x] PRIVMSG/NOTICE comma-list of targets
39. [x] Status-prefix targets (`PRIVMSG @#chan`, `+#chan`)
40. [x] NICK change while registered (broadcast to common channels)
41. [~] Collision handling on NICK change (rename-to-UID, per memory)

## D. IRCX surface (draft-pfenning-04)

42. [x] CREATE `[~]` proto/ircx_create.zig — opt-in IRCX channel state
43. [x] MODEX (extended channel modes) `[x]` live — world now stores IRCX ext flags (chanmode_ext.ExtChannelFlags); MODE accepts the extended letters (a/x/w/u/f/d/E/r/z/Y, oper-gated for E/r/z); MODEX is a named-mode front-end delegating to MODE + a 806/807 query. +w NOWHISPER enforced in WHISPER (923)
44. [x] ACCESS list (GRANT/DENY/OWNER/HOST/VOICE) `[x]` live (801-805, channel-op gated, ircx_access_store)
45. [x] PROP get/set on channel/user/member entities `[x]` live (818/819, channel-op/self gated, ircx_prop_store)
46. [x] EVENT subscribe/unsubscribe (Event Spine wiring) `[x]` live (oper-gated ADD/DEL/LIST over event_spine CategoryMask, daemon-native parse)
47. [x] LISTX extended LIST `[~]` proto/listx.zig
48. [x] WHISPER channel-scoped private msg `[x]` live (sender+recipient must be on channel; 401/442)
49. [x] +h HIDDEN channel mode (IRCX, NOT halfop)
50. [~] AUTH (IRCX auth package negotiation)
51. [ ] IRCX command gating behind `CREATE`/ISIRCX state
52. [x] AUDITORIUM (+x) member-visibility semantics `[x]` live — NAMES hides regular members from each other (ops/voiced + self visible) via auditorium.zig predicates + the +x ext flag

## E. IRCv3 capabilities

53. [x] server-time tag on all relayed messages (have realtimeMillis)
54. [~] message-tags relay (client tags passthrough)
55. [x] account-tag on messages
56. [~] account-notify on login/logout `[~]` proto/account_notify.zig
57. [x] extended-join (account+realname in JOIN) `[~]` proto/extended_join.zig
58. [~] chghost `[~]` proto/chghost.zig
59. [x] invite-notify `[~]` proto/invite_notify.zig
60. [x] echo-message already; verify for NOTICE + TAGMSG
61. [ ] batch (netjoin/netsplit/chathistory) `[~]` proto/batch.zig
62. [~] labeled-response (label → echo correlation)
63. [~] CAP NEW / CAP DEL dynamic advertisement
64. [~] STS policy advertisement `[~]` proto/sts.zig
65. [x] bot-mode (+B umode, WHOIS 335) `[~]` proto/bot_mode.zig
66. [~] multiline `[~]` proto/multiline.zig
67. [x] message-redaction / message-edit `[~]` proto/msgedit.zig
68. [x] read-marker `[~]` proto/read_marker.zig
69. [x] metadata `[~]` proto/metadata.zig
70. [x] monitor (MONITOR +/-/C/L/S; 730/731/732/733/734) `[~]` proto/monitor.zig
71. [~] extended-monitor `[~]` proto/extended_monitor.zig
72. [x] utf8-only (UTF8ONLY ISUPPORT + FAIL INVALID_UTF8 on PRIVMSG/TAGMSG) `[x]` live
73. [~] standard-replies (FAIL/WARN/NOTE) used on new error paths
74. [x] chathistory (needs msgstore) `[~]` proto/chathistory.zig

## F. SASL and accounts

75. [~] SASL EXTERNAL (cert-based) — sasl.Dispatcher consolidation
76. [x] SASL SCRAM-SHA-256 `[~]` proto/sasl.zig
77. [x] SASL SCRAM-SHA-512 `[~]`
78. [~] Advertise EXTERNAL/SCRAM once wired
79. [~] ACCOUNT registration/identify path (services bridge)
80. [~] CERTFP (m_certfp / m_certadd)
81. [x] WHOIS RPL_WHOISLOGGEDIN 330 / certfp 276

## G. Oper and server management

82. [x] STATS (l/o/u/c/i/k subset) — multiple RPL_STATS*
83. [~] CONNECT / SQUIT (S2S) — CONNECT [x] live (oper, io_uring connect op → outbound S2sLink handshake); live S2S listener [x] (inbound accept → S2sLink); SQUIT + already-linked guard + oper-visible CONNECT broadcast remain
84. [x] DIE (oper shutdown)
85. [x] RESTART (oper)
86. [x] KLINE / DLINE / GLINE + UNKLINE (ban storage)
87. [x] TESTLINE / TESTMASK `[x]` live — oper tools: TESTLINE reports matching K/D-line (725/726), TESTMASK counts connected clients matching a mask (727)
88. [x] TRACE / ETRACE (200-262 family)
89. [~] SNOMASK / server notices (+s umode)
90. [x] OPER MODE +o user-umode reflection + RPL_UMODEIS `[x]` live — umodeString emits +o when is_oper; RPL_UMODEIS (221) shows it
91. [x] WHOIS RPL_WHOISOPERATOR 313 (add `is_oper` to WhoisSubject)
92. [x] WALLOPS via Event Spine announce/BROADCAST (oper-visible event, not +w umode)
93. [~] GRANT / privilege sets (oper.zig Privilege wiring)

## H. Mesh and S2S (Suimyaku — later milestones)

94. [x] LINKS/MAP reflect real mesh peers `[x]` live — LINKS (364) lists each established S2S peer by remoteName as a 1-hop neighbour; MAP (015) shows them as child nodes. (Multi-hop topology arrives with route-table propagation.)
95. [~] Server burst / state sync (Suimyaku CRDT)
96. [~] Cross-node PRIVMSG routing
97. [~] Cross-node channel membership convergence
98. [~] Netsplit/netjoin batches
99. [~] /UPGRADE live migration (session_migrate analog)
100. [~] VEIL security layer handshake on peer links

---

## Notes for the next session

- `[~]` items already have a pure, unit-tested builder under `src/proto/` —
  wiring is mostly: parse params → call world/builder → deliver. Cheapest wins.
- The Section B world-model wave is the single highest-value block: it makes
  channels actually enforce their modes. Do key-ownership carefully — channel
  values live in a rehashing `AutoHashMap`, so a `key: ?[]const u8` must point
  at heap (allocator-owned, freed on change/destroy), never into the struct.
- Live `Numeric` enum in `server.zig` is a deliberate subset; add codes there
  as you wire each command (the full table is `src/proto/numeric.zig`).
- Test-only loopback helpers (`connectLoopback`) are Linux-native; tests run on
  Linux only. The cross-platform gate is `zig build -Dtarget=...` (the exe),
  not `zig test --test-no-exec` of the test blocks.
