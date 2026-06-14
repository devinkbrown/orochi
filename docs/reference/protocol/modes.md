# Orochi Modes

This page documents current source only. The advertised channel-mode token is `CHANMODES=beIZ,k,lfj,imnstCTNMSgWOA` from `src/proto/protocol_inventory.zig:36`; the advertised status-prefix token is `PREFIX=(Qqov)!.@+` from `src/proto/protocol_inventory.zig:56` and `src/daemon/chanmode.zig:310`.

## User Modes

`MODE <nick> [modes]` only allows a client to view or change its own modes; cross-user changes return `ERR_USERSDONTMATCH` except operator `+z` GAG handling (`src/daemon/server.zig:4151`, `src/daemon/server.zig:4531`). The live handler only applies catalog entries whose policy is `client_writable`; server-managed and unknown letters are ignored by the client path (`src/daemon/server.zig:4557`).

| Letter | Name | Policy | Who Sets It | Meaning / Current Behavior | Evidence |
| --- | --- | --- | --- | --- | --- |
| `i` | invisible | client-writable | User via `MODE <ownnick> +/-i`. | Stored and serialized as a normal user mode. | `src/proto/usermode.zig:140`, `src/daemon/server.zig:4560` |
| `B` | bot | client-writable | User via `MODE <ownnick> +/-B`. | IRCv3 bot mode; advertised through ISUPPORT `BOT=B`. | `src/proto/usermode.zig:141`, `src/proto/protocol_inventory.zig:59` |
| `r` | registered | server-managed | Server/account services. | Read-only to clients; marks registered identity. | `src/proto/usermode.zig:142`, `src/proto/usermode.zig:185` |
| `z` | secure-tls | server-managed; special IRCX GAG letter in oper cross-user path. | Server for TLS state; opers may use user-target MODE `+z` as GAG on another user. | TLS/security state in catalog; server `applyGag` silently drops gagged user's messages. | `src/proto/usermode.zig:143`, `src/daemon/server.zig:4151`, `src/daemon/server.zig:4111` |
| `D` | deaf | client-writable | User. | Stored user flag. | `src/proto/usermode.zig:144`, `src/daemon/server.zig:4557` |
| `g` | callerid | client-writable | User. | Stored user flag. | `src/proto/usermode.zig:145`, `src/daemon/server.zig:4557` |
| `C` | no-ctcp | client-writable | User. | Stored user flag. Channel `+C` separately blocks channel CTCP from non-ops. | `src/proto/usermode.zig:146`, `src/daemon/server.zig:11021` |
| `x` | cloaked | server-managed | Server/services. | Read-only to clients. | `src/proto/usermode.zig:147`, `src/proto/usermode.zig:190` |
| `R` | regonly-pm | client-writable | User. | Rejects direct PRIVMSG/NOTICE from unauthenticated non-oper senders. | `src/proto/usermode.zig:148`, `src/daemon/server.zig:11135` |
| `p` | hide-chans | client-writable | User. | Suppresses own channel list in WHOIS for non-opers. | `src/proto/usermode.zig:149` |
| `Q` | no-forward | client-writable | User. | User opt-out of channel forward behavior. | `src/proto/usermode.zig:150` |
| `H` | hide-oper | client-writable | User. | Hides operator status from WHOIS/WHO for non-opers. | `src/proto/usermode.zig:151` |

Orochi divergence: legacy wallops/snomask do not use user `+w`. Operator notifications ride the Event Spine as `NOTE EVENT ...`; the comment explicitly says this replaces legacy snote/wallops broadcast channels (`src/daemon/server.zig:10009`).

## Member Status Modes and Prefixes

The member-prefix rank order is founder `+Q` (`!`) > owner `+q` (`.`) > op `+o` (`@`) > voice `+v` (`+`) (`src/daemon/chanmode.zig:244`). The first member to join a newly-created channel receives founder (`src/daemon/world.zig:477`). Founder is creation-only and cannot be handed out through ordinary MODE (`src/daemon/server.zig:4275`).

| Mode | Prefix | Rank | Param | Who Sets It | Notes | Evidence |
| --- | --- | ---: | --- | --- | --- | --- |
| `Q` | `!` | 4 | target nick | First joiner at channel creation; founder may remove/alter via rank-gated operations. | Cannot be added by MODE; highest rank. | `src/daemon/chanmode.zig:250`, `src/daemon/chanmode.zig:293`, `src/daemon/world.zig:480`, `src/daemon/server.zig:4264` |
| `q` | `.` | 3 | target nick | Founder/owner-level actor with sufficient rank. | IRCX owner tier; admin aliases owner, not a separate wire mode. | `src/daemon/chanmode.zig:244`, `src/daemon/server.zig:4268`, `src/daemon/server.zig:4282` |
| `o` | `@` | 2 | target nick | Op or higher. | Grants channel operator authority. | `src/daemon/chanmode.zig:295`, `src/daemon/chanmode.zig:314`, `src/daemon/server.zig:4264` |
| `v` | `+` | 1 | target nick | Op or higher. | May speak in `+m` moderated channels. | `src/daemon/chanmode.zig:297`, `src/daemon/chanmode.zig:319`, `src/daemon/server.zig:4264` |

Rank gating: a member may only set/clear a tier whose rank is less than or equal to their own highest rank, and may not change modes of a higher-ranked member unless they are a server oper (`src/daemon/server.zig:4282`, `src/daemon/server.zig:4294`).

## Advertised Channel Mode Classes

| Class | Advertised Letters | Param Rules | Source |
| --- | --- | --- | --- |
| A list modes | `b`, `e`, `I`, `Z` | Always take a mask parameter for add/remove; no parameter queries the list. | `src/proto/protocol_inventory.zig:36`, `src/daemon/server.zig:4378`, `src/daemon/server.zig:4432` |
| B parameter modes | `k` | Always has a parameter in the generic catalog; live server uses a key on set and emits `*` on unset echo. | `src/proto/protocol_inventory.zig:36`, `src/daemon/chanmode.zig:96`, `src/daemon/server.zig:4353` |
| C parameter-on-set modes | `l`, `f`, `j` | `+l` takes numeric limit; `+f` takes forward channel; `+j` takes `joins:seconds`; unset is bare. | `src/proto/protocol_inventory.zig:36`, `src/daemon/server.zig:4365`, `src/daemon/server.zig:4450`, `src/daemon/server.zig:4468` |
| D flags | `i`, `m`, `n`, `s`, `t`, `C`, `T`, `N`, `M`, `S`, `g`, `W`, `O`, `A` | No parameter. | `src/proto/protocol_inventory.zig:36`, `src/daemon/chanmode.zig:98`, `src/daemon/server.zig:4320` |

## Channel List Modes

| Letter | Name | Param | Who Sets It | Meaning | Evidence |
| --- | --- | --- | --- | --- | --- |
| `b` | ban | mask | Channel op or higher. | Blocks matching JOIN unless exempted by `+e`; supports extended-ban context in world checks. | `src/daemon/chanmode.zig:93`, `src/daemon/world.zig:732`, `src/daemon/world.zig:924`, `src/daemon/server.zig:4378` |
| `e` | exempt | mask | Channel op or higher. | Ban/quiet exception list; overrides `+b` and `+Z`. | `src/daemon/chanmode.zig:94`, `src/daemon/world.zig:807`, `src/daemon/world.zig:919`, `src/daemon/server.zig:4398` |
| `I` | invite-exception | mask | Channel op or higher. | Lets matching users bypass `+i`. | `src/daemon/chanmode.zig:95`, `src/daemon/world.zig:825`, `src/daemon/server.zig:4415` |
| `Z` | quiet / mute | mask | Channel op or higher. | Suppresses speech for matching masks without blocking JOIN; `+e` exempts. | `src/daemon/world.zig:132`, `src/daemon/world.zig:843`, `src/daemon/server.zig:4432`, `src/daemon/server.zig:11002` |

List modes are capped by `World.max_list_entries`; exceeding the cap returns `ERR_BANLISTFULL` (`src/daemon/world.zig:195`, `src/daemon/world.zig:761`, `src/daemon/server.zig:4130`).

## Channel Parameter Modes

| Letter | Name | Param | Who Sets It | Meaning | Evidence |
| --- | --- | --- | --- | --- | --- |
| `k` | key | key on set; unset echo uses `*` | Channel op or higher. | Requires matching JOIN key. | `src/daemon/chanmode.zig:96`, `src/daemon/world.zig:595`, `src/daemon/server.zig:4353`, `src/daemon/server.zig:3817` |
| `l` | limit | integer on set; no param on unset | Channel op or higher. | Maximum member count; blocks JOIN with `ERR_CHANNELISFULL`. | `src/daemon/chanmode.zig:97`, `src/daemon/world.zig:608`, `src/daemon/server.zig:4365`, `src/daemon/server.zig:3942` |
| `j` | join throttle | `joins:seconds` on set; no param on unset | Channel op or higher. | At most N joins per window; blocked JOIN returns `ERR_THROTTLE`. | `src/daemon/world.zig:135`, `src/daemon/world.zig:875`, `src/daemon/server.zig:4450`, `src/daemon/server.zig:3934` |
| `f` | forward | target channel on set; no param on unset | Channel op or higher, with target-side permission unless oper. | Redirects refused JOINs to another channel; target must be valid and, unless `+F`, controlled by setter. | `src/daemon/world.zig:143`, `src/daemon/world.zig:863`, `src/daemon/server.zig:4468`, `src/daemon/server.zig:4475` |

## Channel Flag Modes

| Letter | Name | Param | Who Sets It | Meaning | Evidence |
| --- | --- | --- | --- | --- | --- |
| `i` | invite-only | none | Channel op or higher. | JOIN requires invite or `+I` exception. | `src/daemon/chanmode.zig:98`, `src/daemon/world.zig:579`, `src/daemon/server.zig:3811` |
| `m` | moderated | none | Channel op or higher. | Only voiced or operator-tier members may speak. | `src/daemon/chanmode.zig:99`, `src/daemon/chanmode.zig:319`, `src/daemon/server.zig:10977` |
| `n` | no-external | none | Channel op or higher. | Non-members cannot message the channel. | `src/daemon/chanmode.zig:100`, `src/daemon/server.zig:10964` |
| `t` | topic-ops | none | Channel op or higher. | Only channel operators may change topic. | `src/daemon/chanmode.zig:101`, `src/daemon/server.zig:11189` |
| `s` | secret | none | Channel op or higher. | Secret channel flag, hidden from listing behavior. | `src/daemon/chanmode.zig:102`, `src/daemon/world.zig:1065` |
| `C` | no-ctcp | none | Channel op or higher. | Blocks channel CTCP except ACTION from non-ops. | `src/daemon/chanmode.zig:103`, `src/daemon/server.zig:11021` |
| `T` | no-notice | none | Channel op or higher. | Drops channel NOTICE from non-ops. | `src/daemon/chanmode.zig:104`, `src/daemon/server.zig:11028` |
| `N` | no-nick | none | Channel op or higher. | Blocks nick changes by non-ops while joined. | `src/daemon/chanmode.zig:105`, `src/daemon/chanmode.zig:27` |
| `g` | free-invite | none | Channel op or higher. | Any member may INVITE while `+i`. | `src/daemon/chanmode.zig:106`, `src/daemon/chanmode.zig:28` |
| `S` | tls-only | none | Channel op or higher. | JOIN only over TLS; non-TLS gets `ERR_SECUREONLYCHAN`. | `src/daemon/chanmode.zig:107`, `src/daemon/server.zig:3770` |
| `M` | moderate-unregistered | none | Channel op or higher. | Unauthenticated members need voice/operator tier to speak. | `src/daemon/chanmode.zig:108`, `src/daemon/server.zig:10989` |
| `W` | news-wire | none | Channel op or higher. | Enables the in-channel `!news`/`!localnews` bot in this channel; silent without it. | `src/daemon/chanmode.zig:109`, `src/daemon/server.zig:11155` |
| `O` | oper-only | none | Channel op or higher. | JOIN requires IRC operator status. | `src/daemon/chanmode.zig:110`, `src/daemon/server.zig:5718` |
| `A` | admin-only | none | Channel op or higher. | JOIN requires server administrator privileges. | `src/daemon/chanmode.zig:111`, `src/daemon/server.zig:5722` |

The generic `chanmode.zig` catalog includes `b e I k l i m n t s C T N g S M W O A` (`src/daemon/chanmode.zig:92`). The live server also implements `Z`, `j`, `f`, `p`, `h`, and IRCX extended flags in `server.zig` / `world.zig`.

## IRCX Extended Channel Flags

The live MODE handler recognizes extended channel flags through `chanmode_ext.letterToFlag`; oper-only flags require server operator status (`src/daemon/server.zig:4500`, `src/proto/chanmode_ext.zig:234`, `src/proto/chanmode_ext.zig:252`).

| Letter | IRCX Name | Oper Only | Meaning / Current Storage | Evidence |
| --- | --- | --- | --- | --- |
| `p` | PRIVATE | No | Private channel flag stored separately in `World.Channel`. | `src/proto/chanmode_ext.zig:49`, `src/daemon/world.zig:703`, `src/daemon/server.zig:4345` |
| `h` | HIDDEN | No | Omit from LIST. | `src/proto/chanmode_ext.zig:50`, `src/daemon/world.zig:715`, `src/daemon/server.zig:4345` |
| `u` | KNOCK | No | Enables KNOCK behavior. | `src/proto/chanmode_ext.zig:56`, `src/daemon/server.zig:5149` |
| `a` | AUTHONLY | No | Requires authenticated user to JOIN. | `src/proto/chanmode_ext.zig:57`, `src/daemon/server.zig:3777` |
| `f` | NOFORMAT | No | Strips mIRC color/formatting before channel delivery. | `src/proto/chanmode_ext.zig:58`, `src/daemon/server.zig:11042` |
| `d` | CLONEABLE | No | Channel clone/template flag. | `src/proto/chanmode_ext.zig:59`, `src/daemon/world.zig:633` |
| `E` | CLONE | Yes | Marks cloned channel. | `src/proto/chanmode_ext.zig:60`, `src/daemon/world.zig:654` |
| `r` | REGISTERED | Yes | Persistent registered channel flag. | `src/proto/chanmode_ext.zig:61`, `src/daemon/world.zig:554` |
| `z` | SERVICE | Yes | Service channel flag. | `src/proto/chanmode_ext.zig:62` |
| `x` | AUDITORIUM | No | IRCX auditorium flag. | `src/proto/chanmode_ext.zig:63` |
| `w` | NOWHISPER | No | Blocks channel WHISPER with `ERR_NOWHISPER`. | `src/proto/chanmode_ext.zig:64`, `src/daemon/server.zig:7790` |
| `V` | NOCOMICDATA | No | IRCX flag: disables comic-chat `DATA` to the channel. Non-op members are refused with `ERR_NOCOMICDATA` (531); channel ops/founder and network opers bypass. (Letter was `Y`, reassigned to `V` because `Y` is the network-operator PREFIX status letter.) | `src/proto/chanmode_ext.zig:65`, `src/daemon/server.zig` (handleData) |
| `U` | OPMODERATE | No | Routes messages blocked by moderation gates (`+m`/`+M`/`+Z`) to ops instead of rejecting them. (Letter was `O`, reassigned to `U` per `mode_rearchitecture.md` — `O` is the enum oper-only channel mode above; opmoderate was previously unreachable because the enum `+O` shadowed it.) | `src/proto/chanmode_ext.zig:66`, `src/daemon/server.zig` (channelSpeechGate / opmod_route) |
| `F` | FREETARGET | No | Allows channels to be forward targets without target-side op check. | `src/proto/chanmode_ext.zig:67`, `src/daemon/server.zig:4484` |
| `D` | DISFORWARD | No | Refuses use as a forward target. | `src/proto/chanmode_ext.zig:68`, `src/daemon/server.zig:3880` |

Some IRCX names duplicate base flags (`PRIVATE`, `HIDDEN`, `SECRET`, `MODERATED`, `TOPICOP`, `INVITEONLY`, `NOEXTERN`). The live handler special-cases `p` and `h`, handles base letters through the base channel-mode path, and sends remaining recognized letters through `chanmode_ext` (`src/daemon/server.zig:4320`, `src/daemon/server.zig:4345`, `src/daemon/server.zig:4500`).
