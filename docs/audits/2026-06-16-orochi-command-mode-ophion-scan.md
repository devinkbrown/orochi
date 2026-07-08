# Orochi command and mode scan against Ophion - 2026-06-16
*Historical research note: records a source-only command, mode, and hierarchy scan against the local Ophion checkout.*

This command-focused companion to `docs/audits/2026-06-15-orochi-vs-ophion-gap-audit.md` compares Orochi's live surface against the local Ophion checkout.

## Scope and method

- Orochi source: `orochi`.
- Ophion reference: `ophion`.
- Orochi accepted commands were taken from the enabled SerpentRegistry modules
  in `src/daemon/modules/manifest.zig` plus the lower registration dispatcher
  in `src/daemon/dispatch.zig`.
- Ophion accepted commands were taken mechanically from `struct Message`
  registrations in `ophion/modules` and
  `ophion/extensions`.
- Mode behavior was checked from Orochi's live `MODE` handlers and mode
  catalogs, then compared with Ophion's C mode registration tables.

Mechanical counts from this scan:

| Metric | Count |
| --- | ---: |
| Orochi registered/lower-dispatch command names | 137 |
| Ophion `struct Message` command names | 273 |
| Ophion command names not accepted by Orochi under the same name | 154 |

## Main findings

Orochi is not a command-compatible clone of Ophion. Many Ophion-only commands
are intentionally outside Orochi's product target: TS/server-burst verbs, C
module management, CPython/MAPI tooling, STARTTLS/WEBIRC, DCC/filehost, and the
LADON module command vocabulary.

The real compatibility gaps, if an Ophion client or oper workflow must run
unchanged, are mostly aliases and wire vocabulary:

- `OPER` is accepted by Orochi but intentionally nonfunctional. It always
  replies that password `OPER` is disabled and that operator status comes from
  SASL account bindings.
- `SUMMON` is accepted and functional: Orochi repurposes the obsolete
  host-paging command as an **operator force-join** — `SUMMON <nick> <channel>`
  forces the target into the channel (oper-gated, same path as `FORCEJOIN`) and
  replies `RPL_SUMMONING` (342) to the requester (`src/daemon/server.zig`
  `handleSummon`).
- `BATCH` is not a normal registry command. Orochi emits IRCv3 `BATCH` and
  accepts inbound `BATCH` only for `draft/multiline` when the client negotiated
  that cap.
- Orochi accepts top-level `WHOX` as an alias for the existing WHOX selector path
  (`WHOX <target> %<fields>[,token]` and `WHO <target> %<fields>[,token]`).
- Ophion accepts `CHGHOST` / `REALHOST` as commands. Orochi emits IRCv3
  `CHGHOST` notifications and has `VHOST`, but no command aliases named
  `CHGHOST` or `REALHOST`.
- Ophion's legacy broadcast commands `WALLOPS`, `OPERWALL`, `LOCOPS`, and
  `SNOTE` are not accepted. Orochi routes that class of behavior through
  `GLOBAL` and IRCX/Event-Spine `EVENT BROADCAST`.
- Ophion IRCX aliases `TACCESS`, `BTACCESS`, `TPROP`, `BTPROP`, and
  `CHARENME` are not accepted. Orochi accepts `ACCESS`, `SACCESS`, `PROP`, and
  `RENAME`.
- Ophion IRCX oper commands `GAG`, `GAG_*`, `OPFORCE`, and `SVSJOIN` are not
  accepted. Orochi has `MODE <nick> +z` GAG, `SHUN`/`UNSHUN`, and `FORCE*`
  commands instead.
- Orochi has native `MEDIA`, but it does not implement Ophion's LADON command
  names (`MEDIAFRAME`, `LADON*`, `VOICELIST`, `MEDIASTATUS`, `BWREPORT`, etc.).
- Several account/service operations exist under Orochi-native commands, but
  not under Ophion names such as `ACCOUNTOPER`, `ACREATE`, `SETACCOUNT`,
  `SUSPEND`, `UNSUSPEND`, `FORBID`, `UNFORBID`, `NOEXPIRE`, `CHANNOEXPIRE`,
  `LOGIN`, `SU`, `RSFNC`, `NICKDELAY`, `SETPASS`, `SETEMAIL`, or `SET`.

## Orochi live command evidence

The enabled module list is the source of truth for post-registration commands:
`query_info`, `channel_ops`, `messaging`, `accounts`, `ircx`,
`oper_security`, `user_query`, `feature_misc`, `introspect`, `upgrade`, and
`services_ext` are assembled into `module_manifest.Live`
(`src/daemon/modules/manifest.zig:22`).

Notable live registry rows:

- IRCX commands are `IRCX`, `ISIRCX`, `DATA`, `REQUEST`, `REPLY`, `WHISPER`,
  `PROP`, `ACCESS`, `SACCESS`, `AUTH`, `EVENT`, `MODEX`, and `LISTX`
  (`src/daemon/modules/ircx.zig:53`).
- Oper/security commands include `OPER`, `REHASH`, `GRANT`, `REVOKE`,
  `GRANTS`, `KILL`, `CLOSE`, `DRAIN`, `UNREJECT`, `WARD`, `KLINE`, `DLINE`,
  `XLINE`, `SHUN`, `UNSHUN`, `GLOBAL`, `OPERMOTD`, `DIE`, `RESTART`,
  `CONNECT`, `SQUIT`, `TRACE`, `ETRACE`, `STATS`, `TESTLINE`, `TESTMASK`,
  `USERIP`, `DEBUG`, `MESH`, `NETSTAT`, `ROUTE`, and `NETHEALTH`
  (`src/daemon/modules/oper_security.zig:128`).
- `MEDIA` is feature-gated by `media`; `SUMMON` is an oper force-join;
  `PONG` is a no-reply heartbeat (`src/daemon/modules/feature_misc.zig:46`).

Orochi accepted command names from this scan:

`ACCEPT ACCESS ACCOUNT ACCOUNTINFO ACCOUNTSET ACTIVITY ADMIN AUTH AUTHENTICATE AUTOJOIN AWAY CAP CERTADD CERTDEL CERTLIST CHANNEL CHATHISTORY CLEAR CLONES CLOSE COMMANDS CONNECT CREATE CS DATA DEBUG DIE DLINE DRAIN DROP EDIT ETRACE EVENT FILTER FORCEDEOP FORCEJOIN FORCEOP FORCEPART FORCETOPIC GEOIP GHOST GLOBAL GRANT GRANTS GROUP HELP HELPOP IDENTIFY INFO INVITE IRCX ISIRCX ISON JOIN KICK KILL KLINE KNOCK LINKS LIST LISTX LOGOUT LUSERS MAP MARKREAD MEDIA MESH METADATA MODE MODEX MODLIST MODULES MONITOR MOTD NAMES NETHEALTH NETSTAT NICK NOTICE OPER OPERMOTD PART PASS PING PONG PRIVMSG PRIVS PROP QUIT REDACT REGISTER REHASH RENAME REPLY REQUEST RESTART RESV REVOKE ROUTE SACCESS SASLINFO SEARCH SEEN SESSION SESSIONTOKEN SETNAME SHUN SILENCE SQUIT STATS SUMMON TAGMSG TEGAMI TEMPMODE TESTLINE TESTMASK TIME TOPIC TRACE UNREJECT UNRESV UNSHUN UPGRADE USER USERHOST USERIP USERS VERIFY VERSION VHOST WARD WELCOME WHISPER WHO WHOIS WHOWAS XLINE`

## Command gaps by category

### Accepted but intentionally limited in Orochi

| Command | Status | Evidence |
| --- | --- | --- |
| `OPER` | Accepted, always rejects. Orochi is SASL-account-oper only; no password `OPER`. | `src/daemon/modules/oper_security.zig:134`, `src/daemon/server.zig:15491` (reject at `:15496`) |
| `SUMMON` | Accepted and functional — repurposed as an oper force-join (`SUMMON <nick> <channel>`, replies `RPL_SUMMONING` 342), not the obsolete host-paging form. | `src/daemon/modules/feature_misc.zig:36`, `src/daemon/server.zig` `handleSummon` |
| `BATCH` | Emitted for IRCv3 flows and consumed only for inbound `draft/multiline`; not a general registry command. | `src/daemon/server.zig:19566` |
| `MEDIA` | Native Orochi media control exists, but LADON command compatibility does not. | `src/daemon/server.zig:17233` |
| `MODLIST` / `MODULES` | Lists Orochi's compile-time SerpentRegistry modules, not Ophion's load/unload module control surface. | `src/daemon/modules/introspect.zig:1` |

### Ophion user/client commands missing by name

These are client-visible or common-oper names accepted by Ophion but not by
Orochi under the same command name:

`BAN BATCH BOUNCER CERTFP CHALLENGE CHANSET CHGHOST FILEHOST GET LOGIN MEDIAFRAME MEMO MLOCK NAMESX OPERWALL POST PROTOCTL PUT REALHOST REGAIN REWIND SET SETEMAIL SETPASS STARTMSGPACK STARTTLS SU TB UHELP UNGROUP VHOFFER VHOFFERLIST WALLOPS WEBIRC`

Notes:

- `CHGHOST` behavior is notification-side and VHOST-side only; the command name
  is absent.
- `MLOCK` behavior exists through channel services state, but the raw Ophion
  command name is absent.
- `BATCH` is partial as described above.
- `STARTTLS`, `WEBIRC`, `FILEHOST`, and DCC/filehost-style transfer are not
  Orochi targets in the current audit baseline.

### Ophion oper/admin/diagnostics missing by name

`ACMERELOAD ADMINWALL CHANTRACE DEBUGCORR DEBUGINFO DEBUGLEVEL DEBUGLOG DEBUGROTATE DEBUGSTATS DEBUGSUBSYS DEBUGWATCH DEHELPER EXTENDCHANS FINDFORWARDS GOPER HEAL HURT JUPE JUPELIST LINKSTATS LOCOPS MASKTRACE MKPASSWD MODINFO MODSTATS OPERSPY REBURST RESYNC SCAN SENDBANS SENDPASS SERVSET SNOTE SOPER SPAMFILTER TESTGECOS TGINFO UNJUPE`

Orochi has partial native equivalents for some of this class:

- `DEBUG` exists, but not the full Ophion `DEBUG*` family.
- `MESH`, `NETSTAT`, `ROUTE`, `NETHEALTH`, `TRACE`, `ETRACE`, `STATS`,
  `TESTLINE`, and `TESTMASK` cover some diagnostics.
- `GLOBAL` / `EVENT BROADCAST` cover the intent of some oper broadcasts.
- `WARD`, `KLINE`, `DLINE`, `XLINE`, `RESV`, and `UNRESV` cover some network
  policy operations, but not every Ophion alias.

### Ophion account/services commands missing by name

`ACCOUNTOPER ACREATE CHANNOEXPIRE FORBID NICKDELAY NOEXPIRE RSFNC SETACCOUNT SUSPEND SVCPAUSE SVCRESUME SVCRESYNC SVCSPAUSE UNFORBID UNSUSPEND`

Orochi has native account/service surfaces instead:

- `REGISTER`, `VERIFY`, `IDENTIFY`, `LOGOUT`, `DROP`, `ACCOUNTINFO`,
  `ACCOUNT`, `ACCOUNTSET`, `CHANNEL`, `CS`, `SESSION`, `SESSIONTOKEN`,
  `CERTADD`, `CERTLIST`, and `CERTDEL`.
- `ACCOUNT` handles account lifecycle flags under a different command shape.
- `CHANNEL` handles registration, access, AKICK, settings, and transfer under a
  different command shape.

If Ophion oper scripts must be reused unchanged, this is an alias-compatibility
gap even where the underlying operation exists natively.

### Ophion IRCX commands missing by name

`BTACCESS BTPROP CHARENME GAG GAG_ADD GAG_CLEAR GAG_DEL GRANT_ADD GRANT_CLR GRANT_DEL NOCHAN_ADD NOCHAN_CLR NOCHAN_DEL NONICK_ADD NONICK_CLR NONICK_DEL OPFORCE SVSJOIN TACCESS TPROP`

Orochi's current IRCX surface is live but narrower by name:

- It accepts `IRCX`, `ISIRCX`, `DATA`, `REQUEST`, `REPLY`, `WHISPER`, `PROP`,
  `ACCESS`, `SACCESS`, `AUTH`, `EVENT`, `MODEX`, and `LISTX`.
- `TACCESS`/`BTACCESS` and `TPROP`/`BTPROP` transaction/batch aliases are not
  accepted.
- `OPFORCE` maps conceptually to Orochi `FORCEOP`, `FORCEDEOP`, `FORCEJOIN`,
  `FORCEPART`, and `FORCETOPIC`.
- Ophion `GAG` maps conceptually to Orochi `MODE <nick> +z`,
  `SHUN`/`UNSHUN`, and service access entries, but not by command name.
- Ophion `EVENT` numeric families are not wire-compatible; Orochi uses its
  Event Spine and `NOTE EVENT` style delivery.

### Ophion LADON/media commands missing by name

`ANNOTATE BREAKOUT BWREPORT DATASTAT LADON LADONADMIN LADONKEY LADONLIST LADONMIXER LADONPOLL LADONVIDEO LADONVOICE MEDIASTATUS VOICELIST WHITEBOARD`

Orochi has native media features behind `MEDIA` and the native/WebTransport
media plane, but it is not a LADON module port. This is a compatibility gap for
clients expecting Ophion command names, LADON CAP values, or LADON media mode
vocabulary.

### Ophion module-system commands missing by name

`MODBLACKLIST MODCHECK MODCONFIG MODDEPS MODGRAPH MODGROUP MODLOAD MODPIN MODRELOAD MODRESET MODRESTART MODUNLOAD MODUNPIN`

Orochi intentionally does not implement Ophion's runtime C module loader or
CPython/MAPI module ecosystem. It has compile-time SerpentRegistry modules and a
WASM plugin control plane, so these names are not equivalent.

### Ophion server/TS/burst commands missing by name

`BMASK ENCAP ERROR ETB EUID HASHCHECK MRESYNC MSEQ MSYNC SAVE SERVER SID SIGNON SJOIN SVCSACCESS SVCSBURST SVCSCDROP SVCSCERT SVCSCHAN SVCSDROP SVCSID SVCSMODE SVCSNICK SVCSOPER SVCSPWD SVCSREG SVSLOGIN SVSSID TMODE UID`

These are mostly server-to-server, TS, services-sync, or burst verbs. Orochi's
mesh/S2S path uses native signed state frames and mesh events, so accepting
these raw Ophion commands would be a deliberate compatibility layer, not a
missing handler in the current architecture.

### Ophion ban/reservation aliases missing by name

`UNDLINE UNKLINE UNXLINE`

Orochi accepts `DLINE`, `KLINE`, `XLINE`, `WARD`, `RESV`, and `UNRESV`, but does
not accept every Ophion un* alias. This is an oper-script compatibility gap if
old scripts are expected to work unchanged.

## Raw Ophion-only command diff

This is the full mechanical list of Ophion `struct Message` command names that
were not found in Orochi's live command registry/lower dispatch:

`ACCOUNTOPER ACMERELOAD ACREATE ADMINWALL ANNOTATE BAN BATCH BMASK BOUNCER BREAKOUT BTACCESS BTPROP BWREPORT CERTFP CHALLENGE CHANNOEXPIRE CHANSET CHANTRACE CHARENME CHGHOST DATASTAT DEBUGCORR DEBUGINFO DEBUGLEVEL DEBUGLOG DEBUGROTATE DEBUGSTATS DEBUGSUBSYS DEBUGWATCH DEHELPER ENCAP ERROR ETB EUID EXTENDCHANS FILEHOST FINDFORWARDS FORBID GAG GAG_ADD GAG_CLEAR GAG_DEL GET GOPER GRANT_ADD GRANT_CLR GRANT_DEL HASHCHECK HEAL HURT INVITED JUPE JUPELIST LADON LADONADMIN LADONKEY LADONLIST LADONMIXER LADONPOLL LADONVIDEO LADONVOICE LINKSTATS LOCOPS LOGIN MASKTRACE MEDIAFRAME MEDIASTATUS MEMO MKPASSWD MLOCK MODBLACKLIST MODCHECK MODCONFIG MODDEPS MODGRAPH MODGROUP MODINFO MODLOAD MODPIN MODRELOAD MODRESET MODRESTART MODSTATS MODUNLOAD MODUNPIN MRESYNC MSEQ MSYNC NAMESX NICKDELAY NOCHAN_ADD NOCHAN_CLR NOCHAN_DEL NOEXPIRE NONICK_ADD NONICK_CLR NONICK_DEL OPERSPY OPERWALL OPFORCE POLL POST PROTOCTL PUT RAID REALHOST REBURST REGAIN RESYNC REWIND RSFNC SASLTHROTTLE SAVE SCAN SENDBANS SENDPASS SERVER SERVSET SET SETACCOUNT SETEMAIL SETFILTER SETPASS SID SIGNON SJOIN SNOTE SOPER SPAMFILTER STARTMSGPACK STARTTLS STREAM SU SUSPEND SVCPAUSE SVCRESUME SVCRESYNC SVCSACCESS SVCSBURST SVCSCDROP SVCSCERT SVCSCHAN SVCSDROP SVCSID SVCSMODE SVCSNICK SVCSOPER SVCSPAUSE SVCSPWD SVCSREG SVSJOIN SVSLOGIN SVSSID TACCESS TB TESTGECOS TGINFO TMODE TPROP UHELP UID UNDLINE UNFORBID UNGROUP UNJUPE UNKLINE UNSUSPEND UNXLINE VHOFFER VHOFFERLIST VOICELIST WALLOPS WEBIRC WHITEBOARD`

## Mode behavior

### Orochi channel modes

Orochi advertises:

- `CHANMODES=beIZ,k,lfj,imnstCTNMSgWOAVUFD`
  (`src/proto/protocol_inventory.zig:56`).
- `PREFIX=(YQqov)*!.@+`, derived from the member hierarchy in
  `src/daemon/chanmode.zig` (`src/daemon/chanmode.zig:396`).

Orochi's compact channel-mode catalog includes:

- List modes: `b` ban, `e` exempt, `I` invite-exception.
- Param modes: `k` key, `l` limit.
- Flags: `i`, `m`, `n`, `t`, `s`, `C`, `T`, `N`, `g`, `S`, `M`, `W`, `O`, `A`.

The live `MODE` handler also implements `Z` quiet/mute list, `j` join throttle,
`f` forward, `p` private, `h` hidden, and IRCX extended flags from
`chanmode_ext`: `u`, `a`, `d`, `E`, `r`, `z`, `x`, `w`, `V`, `U`, `F`, `D`
(`src/daemon/server.zig:8488`, `src/daemon/server.zig:8521`,
`src/daemon/server.zig:8622`, `src/daemon/server.zig:8643`,
`src/daemon/server.zig:8663`, `src/daemon/server.zig:8697`,
`src/proto/chanmode_ext.zig:48`).

### Ophion channel modes and letter mismatches

Ophion's core channel table registers `b`, `e`, `I`, `Z`, `o`, `q`, `v`, `k`,
`l`, `j`, `y`, `L`, `F`, `M`, `Q`, `g`, `i`, `m`, `n`, `p`, `s`, and `t`
(`ophion/ircd/chmode.c:1724`). Built-ins add `c`, `C`, `O`, `A`,
and `S` (`ophion/ircd/chm_builtin.c:149`). IRCX adds `u`, `h`, `a`,
`d`, `E`, `f`, `z`, and `r`
(`ophion/modules/m_ircx_modes.c:300`). LADON adds `B`, `G`, `R`,
`V`, and `W` (`ophion/modules/m_ladon_modes.c:40`).

Important letter differences:

| Ophion letter or set | Orochi behavior |
| --- | --- |
| `M` | Ophion `M` is op-moderation. Orochi `M` is moderate-unregistered; Orochi op-moderation is `U`. |
| `Q` | Ophion `Q` is disforward. Orochi `Q` is a founder member status mode; Orochi disforward is `D`. |
| `y` | Ophion `y` is channel forward. Orochi forward is `f`. |
| `L` | Ophion `L` is staff/exlimit-style behavior. Orochi does not implement that exact letter. |
| `c` | Ophion `c` is no-color. Orochi uses IRCX `NOFORMAT` as `f`. |
| `B`, `G`, `R`, `V`, `W` | Ophion/LADON `B`, `G`, `R`, `V`, and `W` are not LADON-compatible in Orochi. Orochi uses `W` for news-wire and `V` for NOCOMICDATA. |
| `Y` | Ophion IRCX comic `Y` is not Orochi's NOCOMICDATA letter. Orochi moved NOCOMICDATA to `V` because `Y` is the derived network-operator prefix mode. |

### Member hierarchy

Orochi's member status order is:

`network oper * (derived, mode Y)` > `founder ! (+Q)` > `owner . (+q)` >
`op @ (+o)` > `voice + (+v)`.

The derived `*` is not a grantable channel mode; it renders for operators with
the `oper_override` privilege. The founder tier is also special: it is created
at channel creation and cannot be granted with ordinary `MODE +Q`:
`handleMode` rejects adding founder through the mode path
(`src/daemon/server.zig:8432`; the `Q/q/o/v` status case begins at
`src/daemon/server.zig:8418`).

Mode changes are processed per letter inside one `MODE` line. `handleMode`
walks the mode string, flips the active sign on `+` or `-`, and consumes one
target argument for each status letter (`src/daemon/server.zig:8414`,
`src/daemon/server.zig:8419`). A channel creator starts with founder only, not
implicit owner/op bits — each member occupies a single chain level
(`src/daemon/world.zig:612`).

The four tiers form a **cumulative authority chain** modelled on Ophion's
`chm_owner`/`chm_op` (`ophion/ircd/chmode.c:1136-1384`): founder
carries owner-and-op authority, owner carries op authority, and a member holds
exactly one chain tier (voice is independent). Each named status change is
expanded into the concrete tier ops it implies by
`chanmode.cascadeStatusOps` (`src/daemon/chanmode.zig`) and applied in
`handleMode` (`src/daemon/server.zig:8438-8500`):

- Removing a lower tier strips the higher tier it carries: `-o` on a founder
  echoes `-Q` (full strip-down); `-o` on an owner echoes `-q`.
- Removing a higher tier demotes exactly one rank: `-Q` on a founder echoes
  `-Q+q` (→ owner); `-q` on an owner echoes `-q+o` (→ op).
- Adding a chain tier moves the member to exactly that level: `+o` on an owner
  echoes `-q+o` (demote → op); `+q` on an op echoes `+q-o` (promote → owner).
- `+Q` is still rejected (founder is creation-only); voice (`+v`/`-v`) toggles
  independently and stacks with any chain tier (e.g. NAMES `!+nick`).

The wire echo names the tier actually changed, so a `-o` that strips a founder
is reported as `-Q`. The manual paired forms (`-Q+q`, `-q+o`) are no longer
required — the daemon now performs the demotion cascade itself.

Rank rules are stricter than classic op-only models:

- Authority is checked against the **highest tier the cascade touches**, not the
  letter typed: a `-o` that strips a founder requires founder-level authority
  (`src/daemon/server.zig:8438`-`:8500`).
- A member cannot change another member ranked above them.
- A server operator with active override can bypass channel authority and is
  audited.

This means an Ophion client expecting only `q/o/v` hierarchy will see one extra
grantable tier (`Q/!`) and one derived display tier (`Y/*`).

### Orochi user modes

Orochi's user-mode catalog is:

`i` invisible, `B` bot, `r` registered, `z` secure TLS, `D` deaf, `g`
callerid, `C` no-CTCP, `x` cloaked, `R` regonly PM, `p` hide channel list,
`Q` no-forward, `H` hide-oper, `M` media transmit deny, `P` media presence
private, `a` admin, `j` operator override, plus derived `o` operator
(`src/proto/usermode.zig:143`).

The user `MODE` path applies only client-writable modes. Server-managed and
unknown letters are ignored on the client path; `+j` requires `oper_override`
(`src/daemon/server.zig:8744`).

### Ophion user mode differences

Ophion has core user modes such as `B`, `D`, `H`, `Q`, `S`, `Z`, `a`, `i`,
`l`, and `o` in `s_user.c`, and dynamic built-ins `f`, `J`, `R`, `r`, `C`,
`M`, and `P` in `um_builtin.c` (`ophion/ircd/um_builtin.c:317`).
Extensions/modules add more, such as `K` for anonkill, `g` for IRCX oper gag,
`G` for godmode, `u` for filter, `p` for override, and `x` for IP cloaking.

Compatibility-impacting differences:

| Ophion mode | Orochi behavior |
| --- | --- |
| `+f`/`+J` | Ophion `+f`/`+J` callerid maps to Orochi `+g`. |
| `+Z` | Ophion uppercase `+Z` TLS maps to Orochi lowercase server-managed `+z`. |
| `+l` / `+S` | Ophion `+l` locops and `+S` service do not have the same user-settable Orochi equivalents. |
| `+g` | Ophion `+g` IRCX oper gag is not Orochi `+g`; Orochi `+g` is callerid. |
| `+G` / `+K` | Ophion `+G` godmode and `+K` anonkill have no Orochi equivalent. |
| `+p` | Ophion `+p` override does not match Orochi `+p`; Orochi `+p` hides channel lists in WHOIS. Orochi override is `+j`. |
| `+M` / `+P` | Orochi `+M` and `+P` are media-related, but they are not a LADON command compatibility layer. |

## Implementation priority if Ophion wire compatibility is desired

1. Add harmless aliases for already-native behavior: `CHARENME`, `TACCESS`,
   `BTACCESS`, `TPROP`, `BTPROP`, selected account aliases, and selected VHOST
   aliases.
2. Decide whether `OPER` should remain intentionally rejected or gain a
   compatibility shim that instructs users to SASL without looking broken to
   older clients.
3. Decide whether `WALLOPS` / `OPERWALL` / `LOCOPS` / `SNOTE` should become
   aliases to `EVENT BROADCAST` / `GLOBAL`.
4. Decide whether mode-letter compatibility matters. The highest-risk
   conflicts are `M`, `Q`, `Y`, `V`, `W`, `g`, `p`, `z`, and `Z`.
5. Treat LADON as a separate compatibility project. Orochi's native media
   command is not a drop-in replacement for Ophion LADON command names or modes.
6. Keep TS/server-burst commands out unless Orochi explicitly needs an Ophion
   server-protocol compatibility bridge.
