# Orochi numeric replies

*The numeric reply codes Orochi emits, where each originates, and the message text clients receive.*

This reference documents current source only. Orochi is a pure-Zig 0.17-dev clean-room IRC daemon and a bespoke successor to C ophion, not a clone. Numeric values are drawn from the daemon-local enum in `src/daemon/server.zig:701` and the shared protocol enum in `src/proto/numeric.zig:9`; pre-registration numerics are also emitted by `src/daemon/dispatch.zig:141`.

## Source inventories

| Source | Scope | Evidence |
| --- | --- | --- |
| `src/daemon/server.zig` | Live daemon command handlers and daemon-local extension numerics. | `Numeric` enum at `src/daemon/server.zig:701`; formatter at `src/daemon/server.zig:816`; live 005 emitter at `src/daemon/server.zig:8105`. |
| `src/daemon/dispatch.zig` | Pre-registration command dispatch, welcome burst, CAP/SASL registration numerics. | `Numeric` enum at `src/daemon/dispatch.zig:141`; welcome burst at `src/daemon/dispatch.zig:1493`. |
| `src/proto/numeric.zig` | Shared protocol numeric catalog and compile-time duplicate guard. | `Numeric` enum at `src/proto/numeric.zig:9`; derived table at `src/proto/numeric.zig:235`; duplicate check at `src/proto/numeric.zig:238`. |

Current enum sizes are 113 daemon-local live handler codes, 15 pre-registration dispatch codes, and 215 shared protocol catalog codes. The shared catalog is intentionally broader than the set currently emitted by handlers.

## Connection registration

| Value | Name | When Emitted | Message Text | Evidence |
| ---: | --- | --- | --- | --- |
| 001 | `RPL_WELCOME` | Registration completes in the pre-registration dispatcher. | `Welcome to the Orochi IRC Network` | `src/daemon/dispatch.zig:142`, `src/daemon/dispatch.zig:1493`, `src/proto/numeric.zig:10` |
| 002 | `RPL_YOURHOST` | Registration welcome burst. | `Your host is orochi.local, running Orochi` | `src/daemon/dispatch.zig:143`, `src/daemon/dispatch.zig:1494`, `src/proto/numeric.zig:11` |
| 003 | `RPL_CREATED` | Registration welcome burst. | `This server was created for deterministic tests` | `src/daemon/dispatch.zig:144`, `src/daemon/dispatch.zig:1495`, `src/proto/numeric.zig:12` |
| 004 | `RPL_MYINFO` | Registration welcome burst. | `are supported by this server` with server/version/user/channel mode params. | `src/daemon/dispatch.zig:145`, `src/daemon/dispatch.zig:1496`, `src/proto/numeric.zig:13` |
| 005 | `RPL_ISUPPORT` | Registration burst and live support query path. | `are supported by this server` | `src/daemon/dispatch.zig:146`, `src/daemon/dispatch.zig:1497`, `src/daemon/server.zig:702`, `src/daemon/server.zig:8105`, `src/proto/numeric.zig:14` |
| 410 | `ERR_INVALIDCAPCMD` | Invalid CAP subcommand before registration. | `Invalid CAP command` | `src/daemon/dispatch.zig:147`, `src/daemon/dispatch.zig:1312`, `src/proto/numeric.zig:156` |
| 421 | `ERR_UNKNOWNCOMMAND` | Disabled command in server dispatcher or unknown pre-registration command. | `Command disabled by configuration` / `Unknown command` | `src/daemon/server.zig:785`, `src/daemon/server.zig:3464`, `src/daemon/dispatch.zig:148`, `src/daemon/dispatch.zig:1506`, `src/proto/numeric.zig:163` |
| 432 | `ERR_ERRONEUSNICKNAME` | NICK contains control bytes or exceeds runtime `NICKLEN`. | `Erroneous nickname`; `Erroneous nickname (too long)` | `src/daemon/dispatch.zig:149`, `src/daemon/dispatch.zig:1266`, `src/daemon/dispatch.zig:1272`, `src/proto/numeric.zig:168` |
| 451 | `ERR_NOTREGISTERED` | Command requires completed registration. | `You have not registered` | `src/daemon/server.zig:784`, `src/daemon/server.zig:3459`, `src/daemon/dispatch.zig:150`, `src/daemon/dispatch.zig:1152`, `src/proto/numeric.zig:181` |
| 461 | `ERR_NEEDMOREPARAMS` | Generic arity/usage failure across handlers. | Usually `Not enough parameters`; handlers also emit command-specific usage strings. | `src/daemon/server.zig:792`, `src/daemon/server.zig:3453`, `src/daemon/dispatch.zig:151`, `src/daemon/dispatch.zig:1514`, `src/proto/numeric.zig:185` |
| 462 | `ERR_ALREADYREGISTRED` | USER/AUTHENTICATE after registration or duplicate registration attempt. | `You may not reregister` | `src/daemon/dispatch.zig:152`, `src/daemon/dispatch.zig:1285`, `src/daemon/dispatch.zig:1327`, `src/proto/numeric.zig:186` |

## SASL and account registration

| Value | Name | When Emitted | Message Text | Evidence |
| ---: | --- | --- | --- | --- |
| 900 | `RPL_LOGGEDIN` | SASL exchange succeeds. | `You are now logged in` | `src/daemon/dispatch.zig:153`, `src/daemon/dispatch.zig:1430`, `src/proto/numeric.zig:224` |
| 903 | `RPL_SASLSUCCESS` | SASL exchange succeeds after `RPL_LOGGEDIN`. | `SASL authentication successful` | `src/daemon/dispatch.zig:154`, `src/daemon/dispatch.zig:1431`, `src/proto/numeric.zig:227` |
| 904 | `ERR_SASLFAIL` | SASL not negotiated, unsupported mechanism, verifier failure, or router failure. | `SASL authentication failed`; `Unsupported SASL mechanism` | `src/daemon/dispatch.zig:155`, `src/daemon/dispatch.zig:1332`, `src/daemon/dispatch.zig:1460`, `src/proto/numeric.zig:228` |
| 906 | `ERR_SASLABORTED` | Client sends `AUTHENTICATE *` or router reports abort. | `SASL authentication aborted` | `src/daemon/dispatch.zig:156`, `src/daemon/dispatch.zig:1346`, `src/daemon/dispatch.zig:1469`, `src/proto/numeric.zig:230` |

Note: the daemon-local IRCX enum also names 900 as `ERR_BADCOMMAND` and 903 as `ERR_BADLEVEL` (`src/daemon/server.zig:801`, `src/daemon/server.zig:802`). The registration code currently emitted uses the SASL meanings above.

## Operator, server, and mesh

| Value | Name | When Emitted | Message Text | Evidence |
| ---: | --- | --- | --- | --- |
| 015 | `RPL_MAP` | `/MAP` renders local node and peer topology. | Dynamic map detail. | `src/daemon/server.zig:703`, `src/daemon/server.zig:10170`, `src/daemon/server.zig:10177`, `src/proto/numeric.zig:18` |
| 017 | `RPL_MAPEND` | Terminates `/MAP`. | `End of /MAP` | `src/daemon/server.zig:704`, `src/daemon/server.zig:10185`, `src/proto/numeric.zig:20` |
| 211 | `RPL_STATSLLINE` | `/STATS l` established S2S peer links. | Dynamic peer-link detail: `sendq_cap`, queued bytes, and uptime seconds. | `src/daemon/server.zig:980`, `src/daemon/server.zig:10360`, `src/daemon/server.zig:10377`, `src/daemon/server.zig:10378` |
| 218 | `RPL_STATSYLINE` | `/STATS Y` connection-class rows. | Dynamic class policy, match summary, and live member count. | `src/daemon/server.zig:979`, `src/daemon/server.zig:10337`, `src/daemon/server.zig:10343`, `src/daemon/server.zig:10356`, `src/proto/numeric.zig:39` |
| 219 | `RPL_ENDOFSTATS` | Terminates `/STATS`. | `End of /STATS report` | `src/daemon/server.zig:981`, `src/daemon/server.zig:10397`, `src/proto/numeric.zig:40` |
| 242 | `RPL_STATSUPTIME` | `/STATS u`. | Dynamic uptime text. | `src/daemon/server.zig:975`, `src/daemon/server.zig:10317`, `src/daemon/server.zig:10325`, `src/proto/numeric.zig:48` |
| 243 | `RPL_STATSOLINE` | `/STATS o` configured oper bindings. | Empty trailing text; params carry binding. | `src/daemon/server.zig:976`, `src/daemon/server.zig:10327`, `src/daemon/server.zig:10331`, `src/proto/numeric.zig:49` |
| 249 | `RPL_STATSDEBUG` | Oper-only `/STATS z` runtime counters. | Dynamic counter line. | `src/daemon/server.zig:974`, `src/daemon/server.zig:10382`, `src/daemon/server.zig:10390`, `src/proto/numeric.zig:54` |
| 270 | `RPL_PRIVS` | Oper privilege/class query. | Dynamic privilege list. | `src/daemon/server.zig:705`, `src/daemon/server.zig:9695`, `src/daemon/server.zig:9731`, `src/proto/numeric.zig:70` |
| 364 | `RPL_LINKS` | `/LINKS` lists local server and one-hop mesh neighbours. | Dynamic link detail. | `src/daemon/server.zig:708`, `src/daemon/server.zig:10141`, `src/daemon/server.zig:10146`, `src/proto/numeric.zig:123` |
| 365 | `RPL_ENDOFLINKS` | Terminates `/LINKS`. | `End of /LINKS list` | `src/daemon/server.zig:709`, `src/daemon/server.zig:10154`, `src/proto/numeric.zig:124` |
| 381 | `RPL_YOUREOPER` | Oper status granted through operator auth/binding. | `You are now an IRC operator` | `src/daemon/server.zig:710`, `src/daemon/server.zig:8299`, `src/daemon/server.zig:8438`, `src/proto/numeric.zig:136` |
| 382 | `RPL_REHASHING` | `/REHASH` status and reload outcome. | `No config file; nothing to reload`; `No I/O available; cannot reload`; dynamic reload note. | `src/daemon/server.zig:711`, `src/daemon/server.zig:10035`, `src/daemon/server.zig:10085`, `src/proto/numeric.zig:137` |
| 481 | `ERR_NOPRIVILEGES` | Operator-only command or plugin capability failure. | `Permission Denied- You're not an IRC operator`; other handler-specific privilege text. | `src/daemon/server.zig:796`, `src/daemon/server.zig:3458`, `src/daemon/server.zig:9652`, `src/proto/numeric.zig:204` |
| 491 | `ERR_NOOPERHOST` | Legacy `OPER` command is disabled. | `OPER is disabled; authenticate via SASL (operator status is granted on login)` | `src/daemon/server.zig:798`, `src/daemon/server.zig:8305`, `src/proto/numeric.zig:211` |

## Channel membership, MODE, and messaging

| Value | Name | When Emitted | Message Text | Evidence |
| ---: | --- | --- | --- | --- |
| 221 | `RPL_UMODEIS` | `MODE <own-nick>` query. | Current user mode string. | `src/daemon/server.zig:725`, `src/daemon/server.zig:4531`, `src/daemon/server.zig:4543`, `src/proto/numeric.zig:42` |
| 301 | `RPL_AWAY` | PRIVMSG to an away user. | Target away message. | `src/daemon/server.zig:719`, `src/daemon/server.zig:11157`, `src/daemon/server.zig:11162`, `src/proto/numeric.zig:76` |
| 305 | `RPL_UNAWAY` | Bare AWAY clears away state. | `You are no longer marked as being away` | `src/daemon/server.zig:720`, `src/daemon/server.zig:8246`, `src/daemon/server.zig:8262`, `src/proto/numeric.zig:80` |
| 306 | `RPL_NOWAWAY` | AWAY with message sets away state. | `You have been marked as being away` | `src/daemon/server.zig:721`, `src/daemon/server.zig:8246`, `src/daemon/server.zig:8259`, `src/proto/numeric.zig:81` |
| 324 | `RPL_CHANNELMODEIS` | `MODE #channel` query. | Empty trailing; params contain active modes and visible params. | `src/daemon/server.zig:724`, `src/daemon/server.zig:4172`, `src/daemon/server.zig:4210`, `src/proto/numeric.zig:96` |
| 331 | `RPL_NOTOPIC` | `TOPIC #channel` when no topic exists. | `No topic is set` | `src/daemon/server.zig:722`, `src/daemon/server.zig:11231`, `src/daemon/server.zig:11236`, `src/proto/numeric.zig:101` |
| 332 | `RPL_TOPIC` | `TOPIC #channel` query when a topic exists. | Current topic text. | `src/daemon/server.zig:723`, `src/daemon/server.zig:11231`, `src/daemon/server.zig:11234`, `src/proto/numeric.zig:102` |
| 346 | `RPL_INVITELIST` | `MODE #channel I` list query. | Invite-exception mask row. | `src/daemon/server.zig:735`, `src/daemon/server.zig:4416`, `src/proto/numeric.zig:109` |
| 347 | `RPL_ENDOFINVITELIST` | Terminates `+I` list. | `End of channel invite exception list` | `src/daemon/server.zig:736`, `src/daemon/server.zig:4418`, `src/proto/numeric.zig:110` |
| 348 | `RPL_EXCEPTLIST` | `MODE #channel e` list query. | Ban-exception mask row. | `src/daemon/server.zig:737`, `src/daemon/server.zig:4399`, `src/proto/numeric.zig:111` |
| 349 | `RPL_ENDOFEXCEPTLIST` | Terminates `+e` list. | `End of channel exception list` | `src/daemon/server.zig:738`, `src/daemon/server.zig:4401`, `src/proto/numeric.zig:112` |
| 353 | `RPL_NAMREPLY` | NAMES/JOIN names burst. | Channel member list. | `src/daemon/server.zig:726`, `src/daemon/server.zig:11336`, `src/proto/numeric.zig:115` |
| 366 | `RPL_ENDOFNAMES` | Terminates NAMES/JOIN names burst. | `End of /NAMES list` | `src/daemon/server.zig:727`, `src/daemon/server.zig:11336`, `src/proto/numeric.zig:125` |
| 367 | `RPL_BANLIST` | `MODE #channel b` list query. | Ban mask row. | `src/daemon/server.zig:728`, `src/daemon/server.zig:4379`, `src/daemon/server.zig:11241`, `src/proto/numeric.zig:126` |
| 368 | `RPL_ENDOFBANLIST` | Terminates `+b` list. | `End of channel ban list` | `src/daemon/server.zig:732`, `src/daemon/server.zig:11241`, `src/proto/numeric.zig:127` |
| 401 | `ERR_NOSUCHNICK` | Missing nick target across NAMES/WHOIS/INVITE/KILL/WHISPER/message paths. | `No such nick` | `src/daemon/server.zig:773`, `src/daemon/server.zig:4082`, `src/daemon/server.zig:11132`, `src/proto/numeric.zig:148` |
| 403 | `ERR_NOSUCHCHANNEL` | Missing channel target across JOIN/PART/MODE/TOPIC/etc. | `No such channel` | `src/daemon/server.zig:775`, `src/daemon/server.zig:3896`, `src/daemon/server.zig:4168`, `src/proto/numeric.zig:150` |
| 404 | `ERR_CANNOTSENDTOCHAN` | Message blocked by `+n`, `+m`, `+M`, `+Z`, or `+C`. | Handler-specific `Cannot send to channel (...)` text. | `src/daemon/server.zig:776`, `src/daemon/server.zig:10969`, `src/daemon/server.zig:11025`, `src/proto/numeric.zig:151` |
| 405 | `ERR_TOOMANYCHANNELS` | JOIN would exceed configured channel limit. | `You have joined too many channels` | `src/daemon/server.zig:730`, `src/daemon/server.zig:3908`, `src/proto/numeric.zig:152` |
| 407 | `ERR_TOOMANYTARGETS` | PRIVMSG/NOTICE exceeds `MAXTARGETS`. | `Too many recipients` | `src/daemon/server.zig:731`, `src/daemon/server.zig:10769`, `src/proto/numeric.zig:154` |
| 431 | `ERR_NONICKNAMEGIVEN` | NICK command without nickname. | `No nickname given` | `src/daemon/server.zig:786`, `src/daemon/server.zig:8159`, `src/proto/numeric.zig:167` |
| 433 | `ERR_NICKNAMEINUSE` | NICK collision. | `Nickname is already in use` | `src/daemon/server.zig:788`, `src/daemon/server.zig:3563`, `src/daemon/server.zig:8197`, `src/proto/numeric.zig:169` |
| 437 | `ERR_UNAVAILRESOURCE` | Reserved channel/nick resource blocks JOIN or a requested nick is held by nick delay. | Dynamic reservation reason, or `Nick is held (nick delay); try again shortly`. | `src/daemon/server.zig:1007`, `src/daemon/server.zig:5884`, `src/daemon/server.zig:5885`, `src/daemon/server.zig:15958`, `src/daemon/server.zig:15959`, `src/proto/numeric.zig:172` |
| 441 | `ERR_USERNOTINCHANNEL` | Target user is not on channel for MODE/KICK/WHISPER/etc. | `They aren't on that channel` | `src/daemon/server.zig:789`, `src/daemon/server.zig:4306`, `src/proto/numeric.zig:175` |
| 442 | `ERR_NOTONCHANNEL` | Acting client is not on the channel. | `You're not on that channel` | `src/daemon/server.zig:791`, `src/daemon/server.zig:4215`, `src/proto/numeric.zig:176` |
| 443 | `ERR_USERONCHANNEL` | INVITE target already joined. | `is already on channel` | `src/daemon/server.zig:790`, `src/daemon/server.zig:4980`, `src/proto/numeric.zig:177` |
| 471 | `ERR_CHANNELISFULL` | JOIN blocked by `+l`. | `Cannot join channel (+l)` | `src/daemon/server.zig:777`, `src/daemon/server.zig:3942`, `src/proto/numeric.zig:194` |
| 473 | `ERR_INVITEONLYCHAN` | JOIN blocked by `+i`. | `Cannot join channel (+i)` | `src/daemon/server.zig:778`, `src/daemon/server.zig:3811`, `src/proto/numeric.zig:196` |
| 474 | `ERR_BANNEDFROMCHAN` | JOIN blocked by quarantine, AKICK, or `+b`. | `Cannot join channel (+b)` or dynamic reason. | `src/daemon/server.zig:779`, `src/daemon/server.zig:3763`, `src/daemon/server.zig:3806`, `src/proto/numeric.zig:197` |
| 475 | `ERR_BADCHANNELKEY` | JOIN blocked by `+k`. | `Cannot join channel (+k)` | `src/daemon/server.zig:780`, `src/daemon/server.zig:3817`, `src/proto/numeric.zig:198` |
| 477 | `ERR_NEEDREGGEDNICK` | JOIN blocked by `+a`, or PM blocked by user `+R`. | `Cannot join channel (+a) - you must be authenticated`; `Cannot message this user (+R: identify to a registered account)` | `src/daemon/server.zig:781`, `src/daemon/server.zig:3777`, `src/daemon/server.zig:11140`, `src/proto/numeric.zig:200` |
| 478 | `ERR_BANLISTFULL` | Adding `+b`, `+e`, `+I`, or `+Z` exceeds `max_list_entries`. | `Channel list is full` | `src/daemon/server.zig:729`, `src/daemon/server.zig:4130`, `src/daemon/server.zig:4135`, `src/proto/numeric.zig:201` |
| 480 | `ERR_THROTTLE` | JOIN blocked by `+j` join throttle. | `Cannot join channel (+j) - join rate exceeded, try again shortly` | `src/daemon/server.zig:707`, `src/daemon/server.zig:3934`, `src/proto/numeric.zig:203` |
| 482 | `ERR_CHANOPRIVSNEEDED` | Operator-tier channel privilege required. | `You're not channel operator` plus handler-specific privilege text. | `src/daemon/server.zig:797`, `src/daemon/server.zig:4219`, `src/daemon/server.zig:4287`, `src/proto/numeric.zig:205` |
| 489 | `ERR_SECUREONLYCHAN` | JOIN blocked by channel `+S` over non-TLS session. | `Cannot join channel (+S) - TLS required` | `src/daemon/server.zig:706`, `src/daemon/server.zig:3770`, `src/proto/numeric.zig:210` |
| 502 | `ERR_USERSDONTMATCH` | User MODE target is not the caller. | `Cannot change mode for other users` | `src/daemon/server.zig:795`, `src/daemon/server.zig:4537`, `src/proto/numeric.zig:215` |

## Lists, monitor, silence, knock, metadata, IRCX

| Value | Name | When Emitted | Message Text | Evidence |
| ---: | --- | --- | --- | --- |
| 271 | `RPL_SILELIST` | `SILENCE` query row. | Mask row. | `src/daemon/server.zig:739`, `src/daemon/server.zig:5382`, `src/daemon/server.zig:5389` |
| 272 | `RPL_ENDOFSILELIST` | Terminates `SILENCE` query. | `End of SILENCE list` | `src/daemon/server.zig:740`, `src/daemon/server.zig:5390` |
| 281 | `RPL_ACCEPTLIST` | `ACCEPT` query row. | Mask row. | `src/daemon/server.zig:756`, `src/daemon/server.zig:6027`, `src/proto/numeric.zig:73` |
| 282 | `RPL_ENDOFACCEPT` | Terminates `ACCEPT` query. | `End of /ACCEPT list` | `src/daemon/server.zig:757`, `src/daemon/server.zig:6028`, `src/proto/numeric.zig:74` |
| 710 | `RPL_KNOCK` | Delivered to channel operators when a KNOCK arrives. | Knock reason. | `src/daemon/server.zig:758`, `src/daemon/server.zig:5149`, `src/daemon/server.zig:5185` |
| 711 | `RPL_KNOCKDLVR` | Sent to the knocker after delivery. | `Your KNOCK has been delivered` | `src/daemon/server.zig:759`, `src/daemon/server.zig:5187` |
| 713 | `ERR_CHANOPEN` | KNOCK refused because channel is open. | `Channel is open` | `src/daemon/server.zig:760`, `src/daemon/server.zig:5173` |
| 714 | `ERR_KNOCKONCHAN` | KNOCK refused because caller is already joined. | `You are already on that channel` | `src/daemon/server.zig:761`, `src/daemon/server.zig:5164` |
| 725 | `RPL_TESTLINE` | `TESTLINE` matches a Warden ban/ward. | Dynamic ward result. | `src/daemon/server.zig:753`, `src/daemon/server.zig:6429`, `src/daemon/server.zig:6441` |
| 726 | `RPL_NOTESTLINE` | `TESTLINE` finds no matching ban. | `No matching ban found` | `src/daemon/server.zig:754`, `src/daemon/server.zig:6444` |
| 727 | `RPL_TESTMASK` | `TESTMASK` reports matching clients. | `clients match` | `src/daemon/server.zig:755`, `src/daemon/server.zig:6467` |
| 728 | `RPL_QUIETLIST` | `MODE #channel Z` quiet-list query row. | Quiet mask row. | `src/daemon/server.zig:733`, `src/daemon/server.zig:4434`, `src/daemon/server.zig:4436` |
| 729 | `RPL_ENDOFQUIETLIST` | Terminates quiet-list query. | `End of channel quiet list` | `src/daemon/server.zig:734`, `src/daemon/server.zig:4436` |
| 730 | `RPL_MONONLINE` | MONITOR online notification. | Monitor target list. | `src/daemon/server.zig:762`, `src/daemon/server.zig:5280` |
| 731 | `RPL_MONOFFLINE` | MONITOR offline notification. | Monitor target list. | `src/daemon/server.zig:763`, `src/daemon/server.zig:5280` |
| 732 | `RPL_MONLIST` | MONITOR list query. | Monitor target list. | `src/daemon/server.zig:764`, `src/daemon/server.zig:5280` |
| 733 | `RPL_ENDOFMONLIST` | Terminates MONITOR list query. | End marker. | `src/daemon/server.zig:765`, `src/daemon/server.zig:5280` |
| 734 | `ERR_MONLISTFULL` | MONITOR add exceeds limit. | Monitor limit failure. | `src/daemon/server.zig:766`, `src/daemon/server.zig:5280` |
| 761 | `RPL_KEYVALUE` | METADATA GET/LIST/SET/CLEAR value rows. | Metadata value or empty string. | `src/daemon/server.zig:741`, `src/daemon/server.zig:7874`, `src/daemon/server.zig:7892` |
| 762 | `RPL_METADATAEND` | Terminates METADATA command. | `end of metadata` | `src/daemon/server.zig:742`, `src/daemon/server.zig:7910`, `src/daemon/server.zig:7926` |
| 766 | `ERR_KEYNOTSET` | METADATA GET for absent key. | `key not set` | `src/daemon/server.zig:743`, `src/daemon/server.zig:7894` |
| 767 | `ERR_KEYINVALID` | METADATA key validation failure. | `invalid key` | `src/daemon/server.zig:744`, `src/daemon/server.zig:7917` |
| 769 | `ERR_KEYNOPERMISSION` | METADATA SET/CLEAR without permission. | `permission denied` | `src/daemon/server.zig:745`, `src/daemon/server.zig:7909` |
| 800 | `RPL_IRCX` | `MODE ISIRCX` / IRCX discovery. | Trailing `*`; params include state, version, package list, and max message size. | `src/daemon/server.zig:752`, `src/daemon/server.zig:4145`, `src/daemon/server.zig:7696`, `src/daemon/server.zig:7703` |
| 904 | `ERR_BADTAG` | IRCX DATA invalid tag. | `Invalid DATA tag` | `src/daemon/server.zig:751`, `src/daemon/server.zig:7731` |
| 906 | `ERR_BADVALUE` | IRCX PROP invalid property value. | `Invalid property value` | `src/daemon/server.zig:750`, `src/daemon/server.zig:7670` |
| 913 | `ERR_NOACCESS` | IRCX PROP/DATA access denied. | `Insufficient access to set property`; `Cannot set that property`; DATA reserved-tag denials. | `src/daemon/server.zig:746`, `src/daemon/server.zig:7656`, `src/daemon/server.zig:7740` |
| 923 | `ERR_NOWHISPER` | WHISPER blocked by IRCX NOWHISPER (`+w`). | `Channel does not allow whispers (+w)` | `src/daemon/server.zig:749`, `src/daemon/server.zig:7790`, `src/daemon/server.zig:7792` |

## Standard replies: FAIL, WARN, NOTE

Standard replies are not numeric replies. They are line types carrying a severity token, a command token, a reply-code token, optional context params, and a trailing description.

| Token | Builder / Emitter | Shape | Current Uses | Evidence |
| --- | --- | --- | --- | --- |
| `FAIL` | `standard_replies.fail`, `standard_replies_emit.fail`, and `LinuxServer.failReply`. | `FAIL <command> <code> [context...] :<description>` | CHATHISTORY parse failures, invalid UTF-8, Koshi content filter, multiline failures, media/service failures. | `src/proto/standard_replies.zig:15`, `src/proto/standard_replies.zig:200`, `src/proto/standard_replies_emit.zig:121`, `src/daemon/server.zig:10001`, `src/daemon/server.zig:5491`, `src/daemon/server.zig:10803` |
| `WARN` | `standard_replies.warn` / `standard_replies_emit.warn`. | `WARN <command> <code> [context...] :<description>` | Cataloged builder support; no live `server.zig` emission found in current source. | `src/proto/standard_replies.zig:205`, `src/proto/standard_replies_emit.zig:131` |
| `NOTE` | `standard_replies.note` / `standard_replies_emit.note`. | `NOTE <command> <code> [context...] :<description>` | Cataloged standard-reply builder support; Event Spine operator traffic uses raw `EVENT` lines. | `src/proto/standard_replies.zig:210`, `src/proto/standard_replies_emit.zig:136`, `src/daemon/event_spine.zig:292` |

The shared standard-replies catalog currently contains these code tokens: `ACCOUNT_ALREADY_EXISTS`, `ACCOUNT_REQUIRED`, `ALREADY_AUTHENTICATED`, `ALREADY_REGISTERED`, `AUTHENTICATION_FAILED`, `BAD_ACCOUNT_NAME`, `BAD_CHANNEL_NAME`, `BAD_PASSWORD`, `BAD_TARGET`, `BANNED_FROM_CHANNEL`, `CANNOT_SEND_TO_CHANNEL`, `CHANNEL_DISABLED`, `CHANNEL_DOES_NOT_EXIST`, `CHANNEL_FULL`, `CHANNEL_RENAMED`, `CHANNEL_REQUIRED`, `COMMAND_DISABLED`, `COMMAND_RATE_LIMITED`, `EXPIRED_TOKEN`, `HOST_REQUIRED`, `INVALID_ACCOUNT_NAME`, `INVALID_CREDENTIALS`, `INVALID_KEY`, `INVALID_MODE`, `INVALID_PARAMS`, `INVALID_PROPERTY`, `INVALID_TARGET`, `INVALID_TOKEN`, `LIST_EMPTY`, `MESSAGE_RATE_LIMITED`, `MESSAGE_TOO_LONG`, `METADATA_LIMIT_REACHED`, `MONITOR_LIMIT_REACHED`, `NEED_MORE_PARAMS`, `NETWORK_ERROR`, `NICK_LOCKED`, `NO_MATCHING_KEY`, `NOT_AUTHENTICATED`, `NOT_CHANNEL_OPERATOR`, `NOT_ON_CHANNEL`, `NOT_REGISTERED`, `PERMISSION_DENIED`, `PRIVILEGES_REQUIRED`, `PROPERTY_REQUIRED`, `REGISTRATION_IS_DISABLED`, `SILENTLY_DROPPED`, `TARGET_REQUIRED`, `TOKEN_REQUIRED`, `TOO_MANY_CHANNELS`, `TOO_MANY_MATCHES`, `TOO_MANY_MONITOR_TARGETS`, `UNKNOWN_COMMAND`, `UNKNOWN_ERROR`, `UNKNOWN_PROPERTY`, and `UNSUPPORTED_MEDIA_TYPE` (`src/proto/standard_replies.zig:33`).

## Cataloged but not currently emitted by `server.zig`

The daemon-local enum includes residual IRCX 9xx numerics that stay inert until a handler emits them: `ERR_BADCOMMAND` 900, `ERR_BADLEVEL` 903, `ERR_BADPROPERTY` 905, `ERR_RESOURCE` 907, `ERR_SECURITY` 908, `ERR_UNKNOWNPACKAGE` 912, `ERR_DUPACCESS` 914, `ERR_MISACCESS` 915, `ERR_TOOMANYACCESSES` 916, `ERR_NOSUCHOBJECT` 924, `ERR_NOTSUPPORTED` 925, `ERR_CHANNELEXIST` 926, and `ERR_ALREADYONCHANNEL` 927 (`src/daemon/server.zig:799`).

The shared protocol enum is broader than the live daemon emission set. It catalogs additional 0xx, 2xx, 3xx, 4xx, 5xx, 6xx, and SASL/account numerics including `RPL_SAVENICK`, TRACE/STATS variants, WHOIS/WHOWAS variants, LIST/MOTD/ADMIN/TIME/USERS variants, `ERR_UNKNOWNMODE`, `ERR_UMODEUNKNOWNFLAG`, `ERR_DISABLED`, `ERR_INVALIDKEY`, `RPL_WHOISSECURE`, and `RPL_SASLMECHS` (`src/proto/numeric.zig:21`, `src/proto/numeric.zig:23`, `src/proto/numeric.zig:72`, `src/proto/numeric.zig:148`, `src/proto/numeric.zig:224`). Correct shared-catalog names for the historically conflicting 4xx slots are `ERR_NEEDREGGEDNICK` 477, `ERR_ISCHANSERVICE` 484, and `ERR_BANNEDNICK` 485 (`src/proto/numeric.zig:200`, `src/proto/numeric.zig:207`, `src/proto/numeric.zig:208`). Do not treat a catalog entry as live behavior unless a handler citation above or a future handler emission exists.
