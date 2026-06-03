# 07 — Ophion Parity: the 100-item campaign

> Grounded in a full survey of `/home/kain/ophion` (ircd/core + modules/). This
> is the parity backlog for the live single-node daemon, ordered roughly by
> value and by dependency (state-bearing items grouped so a session can land a
> whole world-model change at once). Each item is a discrete, testable unit.
>
> Status legend: `[x]` done & e2e-tested · `[~]` builder exists, not wired ·
> `[ ]` not started. Keep the run-verified cadence: wire → threaded loopback
> test → fmt → native test → cross-compile exe → commit.

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
12. [ ] WHOWAS (needs history store; daemon/whowas.zig exists) `[~]`
13. [ ] USERIP (oper; needs per-conn IP)
14. [ ] SUMMON (446 disabled stub)
15. [ ] TAGMSG (IRCv3 message-tags; needs tag relay)
16. [ ] NAMESX / UHNAMES (cap-driven NAMES formatting)

## B. Channel mode enforcement (world-model state wave)

> Land as one wave: add owned key (heap, not self-slice — channels live in a
> rehashing HashMap), limit (u32), invite list, ban/except/invex lists.

17. [x] MODE +k <key> set/unset (owned storage)
18. [x] MODE +l <limit> set/unset
19. [x] MODE +i toggle (already a flag) + invite-list recording via INVITE
20. [x] MODE +b <mask> add/remove (ban list storage)
21. [ ] MODE +e <mask> ban-exception list
22. [ ] MODE +I <mask> invite-exception list
23. [x] RPL_BANLIST 367 / RPL_ENDOFBANLIST 368
24. [ ] RPL_EXCEPTLIST 348 / 349, RPL_INVITELIST 346 / 347
25. [x] JOIN enforce +k → ERR_BADCHANNELKEY 475
26. [x] JOIN enforce +l → ERR_CHANNELISFULL 471
27. [x] JOIN enforce +i → ERR_INVITEONLYCHAN 473 (respect invite list)
28. [x] JOIN enforce +b → ERR_BANNEDFROMCHAN 474 (respect +e)
29. [x] JOIN with key param: `JOIN #c key`
30. [ ] +n no-external-messages enforcement on PRIVMSG/NOTICE
31. [ ] +t already; verify +t list-mode echo in RPL_CHANNELMODEIS with params
32. [ ] MODE query shows key/limit params to members only
33. [ ] KNOCK (713/711/ERR_CHANOPEN; needs +i) `[~]` proto/knock.zig
34. [ ] Channel +p private (distinct from +s secret) in LIST/WHOIS

## C. Membership status & multi-target

35. [ ] MODE multi-target/multi-flag batching (`+ov nick1 nick2`)
36. [ ] JOIN comma-list of channels (`JOIN #a,#b key1,key2`)
37. [ ] PART comma-list of channels
38. [ ] PRIVMSG/NOTICE comma-list of targets
39. [ ] Status-prefix targets (`PRIVMSG @#chan`, `+#chan`)
40. [ ] NICK change while registered (broadcast to common channels)
41. [ ] Collision handling on NICK change (rename-to-UID, per memory)

## D. IRCX surface (draft-pfenning-04)

42. [ ] CREATE `[~]` proto/ircx_create.zig — opt-in IRCX channel state
43. [ ] MODEX (extended channel modes) `[~]` proto/ircx_modex.zig
44. [ ] ACCESS list (GRANT/DENY/OWNER/HOST/VOICE) `[~]` proto/ircx_saccess.zig
45. [ ] PROP get/set on channel/user/member entities
46. [ ] EVENT subscribe/unsubscribe (Event Spine wiring)
47. [ ] LISTX extended LIST `[~]` proto/listx.zig
48. [ ] WHISPER channel-scoped private msg `[~]` proto/whisper.zig
49. [ ] +h HIDDEN channel mode (IRCX, NOT halfop)
50. [ ] AUTH (IRCX auth package negotiation)
51. [ ] IRCX command gating behind `CREATE`/ISIRCX state
52. [ ] AUDITORIUM (+x) member-visibility semantics

## E. IRCv3 capabilities

53. [ ] server-time tag on all relayed messages (have realtimeMillis)
54. [ ] message-tags relay (client tags passthrough)
55. [ ] account-tag on messages
56. [ ] account-notify on login/logout `[~]` proto/account_notify.zig
57. [ ] extended-join (account+realname in JOIN) `[~]` proto/extended_join.zig
58. [ ] chghost `[~]` proto/chghost.zig
59. [ ] invite-notify `[~]` proto/invite_notify.zig
60. [ ] echo-message already; verify for NOTICE + TAGMSG
61. [ ] batch (netjoin/netsplit/chathistory) `[~]` proto/batch.zig
62. [ ] labeled-response (label → echo correlation)
63. [ ] CAP NEW / CAP DEL dynamic advertisement
64. [ ] STS policy advertisement `[~]` proto/sts.zig
65. [ ] bot-mode (+B umode, WHOIS 335) `[~]` proto/bot_mode.zig
66. [ ] multiline `[~]` proto/multiline.zig
67. [ ] message-redaction / message-edit `[~]` proto/msgedit.zig
68. [ ] read-marker `[~]` proto/read_marker.zig
69. [ ] metadata `[~]` proto/metadata.zig
70. [ ] monitor (MONITOR +/-/C/L/S; 730/731/732/733/734) `[~]` proto/monitor.zig
71. [ ] extended-monitor `[~]` proto/extended_monitor.zig
72. [ ] utf8-only `[~]` proto/utf8_only.zig
73. [ ] standard-replies (FAIL/WARN/NOTE) used on new error paths
74. [ ] chathistory (needs msgstore) `[~]` proto/chathistory.zig

## F. SASL & accounts

75. [ ] SASL EXTERNAL (cert-based) — sasl.Dispatcher consolidation
76. [ ] SASL SCRAM-SHA-256 `[~]` proto/sasl.zig
77. [ ] SASL SCRAM-SHA-512 `[~]`
78. [ ] Advertise EXTERNAL/SCRAM once wired
79. [ ] ACCOUNT registration/identify path (services bridge)
80. [ ] CERTFP (m_certfp / m_certadd)
81. [ ] WHOIS RPL_WHOISLOGGEDIN 330 / certfp 276

## G. Oper & server management

82. [ ] STATS (l/o/u/c/i/k subset) — multiple RPL_STATS*
83. [ ] CONNECT / SQUIT (S2S; deferred to mesh)
84. [ ] DIE (oper shutdown)
85. [ ] RESTART (oper)
86. [ ] KLINE / DLINE / GLINE + UNKLINE (ban storage)
87. [ ] TESTLINE / TESTMASK
88. [ ] TRACE / ETRACE (200-262 family)
89. [ ] SNOMASK / server notices (+s umode)
90. [ ] OPER MODE +o user-umode reflection + RPL_UMODEIS
91. [ ] WHOIS RPL_WHOISOPERATOR 313 (add `is_oper` to WhoisSubject)
92. [ ] WALLOPS gated to +w umode recipients (not all opers)
93. [ ] GRANT / privilege sets (oper.zig Privilege wiring)

## H. Mesh / S2S (Suimyaku — later milestones)

94. [ ] LINKS/MAP reflect real mesh peers (Sazanami membership)
95. [ ] Server burst / state sync (Suimyaku CRDT)
96. [ ] Cross-node PRIVMSG routing
97. [ ] Cross-node channel membership convergence
98. [ ] Netsplit/netjoin batches
99. [ ] /UPGRADE live migration (session_migrate analog)
100. [ ] VEIL security layer handshake on peer links

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
