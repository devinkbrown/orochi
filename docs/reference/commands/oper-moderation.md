# Operator and moderation commands

*Operator authority, network bans, force actions, and server-to-server link control.*

The operator/security module registers the oper and moderation commands (`src/daemon/modules/oper_security.zig:104`). Most are registry-gated with `.access = .oper`; `OPER`, `STATS`, and `USERIP` are exceptions in the command table (`src/daemon/modules/oper_security.zig:107`). Handlers check fine-grained operator privileges with `requirePriv` (`src/daemon/server.zig:9700`).

## OPER

- Syntax: `OPER <ignored...>`
- Description: Password `OPER` is disabled. Orochi grants operator status only from authenticated accounts with configured oper bindings via `elevateOperFromAccount`.
- Privileges: Registered client; never grants by command password.
- Parameters: Ignored by handler.
- Replies: None on success because the command always fails.
- Errors: `ERR_NOOPERHOST 491`.
- Example: `OPER name password`
- Sources: `src/daemon/modules/oper_security.zig:110`, `src/daemon/server.zig:8300`, `src/daemon/server.zig:8308`

## REHASH

- Syntax: `REHASH`
- Description: Reloads configuration/state through the server rehash handler.
- Privileges: Oper.
- Parameters: None.
- Replies: `RPL_REHASHING 382` and/or server notices from handler.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `REHASH`
- Sources: `src/daemon/modules/oper_security.zig:111`, `src/daemon/server.zig:10031`

## GRANT

- Syntax: `GRANT <account> <class> [priv,priv,...]`
- Description: Gives a registered account operator authority network-wide. Mints a
  signed grant recorded locally, propagated to secured S2S peers, and honored on
  the account's next SASL login; already-connected sessions are elevated
  immediately. Privileges come from the class preset (`admin`/`netadmin`/`sa` →
  full, incl. `oper_grant`; any other class → a standard operator set) or an
  explicit comma-separated privilege-name list. Persisted across restart when
  `[oper] grants_path` is set.
- Privileges: Oper holding the `oper_grant` privilege.
- Parameters: Target account; class label; optional privilege list.
- Replies: Server notice confirming the grant.
- Errors: `ERR_NOPRIVILEGES 481`, `ERR_NEEDMOREPARAMS 461`; notice on unknown account/privilege.
- Example: `GRANT alice netadmin`
- Sources: `src/daemon/modules/oper_security.zig:115`, `src/daemon/server.zig:handleGrant`

## REVOKE

- Syntax: `REVOKE <account>`
- Description: Removes a runtime operator grant network-wide. A zero-privilege
  tombstone supersedes the grant (propagated to peers, honored on next login) and
  connected sessions are de-elevated immediately (`MODE -o` + notice). Configured
  `[[opers]]` accounts are not revocable this way (edit config + `REHASH`).
- Privileges: Oper holding the `oper_grant` privilege.
- Parameters: Target account.
- Replies: Server notice confirming the revocation.
- Errors: `ERR_NOPRIVILEGES 481`, `ERR_NEEDMOREPARAMS 461`.
- Example: `REVOKE alice`
- Sources: `src/daemon/modules/oper_security.zig:116`, `src/daemon/server.zig:handleRevoke`

## GRANTS

- Syntax: `GRANTS`
- Description: Lists the live runtime operator grants (account, class, issuer node). Tombstoned (revoked) accounts are omitted.
- Privileges: Oper.
- Parameters: None.
- Replies: Server notices, one per active grant, then an end marker.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `GRANTS`
- Sources: `src/daemon/modules/oper_security.zig:117`, `src/daemon/server.zig:handleGrants`

## AUDIT

- Syntax: `AUDIT [JSON] [oper] [count] | AUDIT PROOF [JSON] <proof-id>`
- Description: Lists recent privileged actions from the bounded oper audit ring. Signed records and signed Event Spine moderation notices include `proof=<id>` for covered actions including `KILL`, `JUPE`, native `WARD ADD`/`WARD DEL`, `SHUN`, `UNSHUN`, `CONNECT`, `SQUIT`, `REDACT`, IRCX `ACCESS` add/delete/clear mutations, and FORCE* channel actions. `AUDIT JSON` streams stable audit objects, and `AUDIT PROOF JSON <proof-id>` returns the stored ProofMark policy fields, reason hash, public key, detached signature, and a `valid=true|false` verification result.
- Privileges: Oper holding the `audit_read` privilege.
- Parameters: Optional oper filter and count for record listing; ProofMark id for proof inspection.
- Replies: Event Spine lines: `:<server> EVENT <oper> AUDIT ...`.
- Errors: `ERR_NOPRIVILEGES 481`; usage or missing proof reports are server notices.
- Example: `AUDIT PROOF JSON 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`
- Sources: `src/daemon/modules/oper_security.zig:178`, `src/daemon/server.zig:handleAudit`

## KILL

- Syntax: `KILL <nick> [:reason]`
- Description: Disconnects a local target nick and publishes the operator action.
- Privileges: Oper.
- Parameters: Target nick; optional reason.
- Replies: Target receives close/error path; oper action is published.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHNICK 401`, `ERR_NOPRIVILEGES 481`.
- Example: `KILL badnick :abuse`
- Sources: `src/daemon/modules/oper_security.zig:112`, `src/daemon/server.zig:5080`

## CLOSE

- Syntax: `CLOSE`
- Description: Closes unregistered/unknown clients and reports counts.
- Privileges: Oper.
- Parameters: None.
- Replies: `RPL_CLOSING 362`, `RPL_CLOSEEND 363` or notices from handler.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `CLOSE`
- Sources: `src/daemon/modules/oper_security.zig:113`, `src/daemon/server.zig:5060`

## DRAIN

- Syntax: `DRAIN <ON|OFF|STATUS>`
- Description: Toggles listener drain state so new client accepts are refused while existing links stay up.
- Privileges: Oper.
- Parameters: Drain subcommand parsed by handler.
- Replies: Server `NOTICE` status.
- Errors: `ERR_NOPRIVILEGES 481`; handler notices for invalid syntax.
- Example: `DRAIN ON`
- Sources: `src/daemon/modules/oper_security.zig:114`, `src/daemon/server.zig:5050`

## UNREJECT

- Syntax: `UNREJECT <ip>`
- Description: Clears an IP from the connection reject/throttle table.
- Privileges: Oper.
- Parameters: IP string.
- Replies: Server notice.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`.
- Example: `UNREJECT 203.0.113.10`
- Sources: `src/daemon/modules/oper_security.zig:115`, `src/daemon/server.zig:5029`

## WARD

- Syntax: `WARD ADD <match> <pattern> [scope] [action] [secs] [:reason] | WARD DEL <match> <pattern> | WARD LIST [match] | WARD TEST <match> <value>`
- Description: Unified Warden network-ban registry. A Ward is `Match x Scope x Action`: match facets are `address`, `host`, `mask`, `account`, `realname`, `certfp`, `country`, and `asn`; scopes are `node` or `mesh`; actions are `refuse`, `expel`, `quarantine`, or `require_auth`. The registered surface has no K/D/G/Z-line commands.
- Privileges: Oper plus `client_moderate` privilege.
- Parameters: Subcommand-specific Warden axes and optional duration/reason.
- Replies: Server notices and oper events. `WARD ADD` and `WARD DEL` oper events include `proof=<id>` when the node has a signing identity. `WARD TEST` reports match/no-match by notice.
- Errors: `ERR_NOPRIVILEGES 481`; usage and validation failures are server notices.
- Example: `WARD ADD address 203.0.113.0/24 mesh refuse 3600 :abuse`
- Sources: `src/daemon/modules/oper_security.zig:116`, `src/daemon/server.zig:5892`, `src/daemon/warden.zig:21`

## SPAMTRAP

- Syntax: `SPAMTRAP ADD <NICK|CHAN> <target> | SPAMTRAP DEL <NICK|CHAN> <target> | SPAMTRAP LIST`
- Description: Operator-designated spam-trap (honeypot) registry. A trap nick or channel is one a legitimate user has no reason to contact. A non-operator that PRIVMSGs a trap nick or JOINs a trap channel trips the trap, which raises a one-shot `FLOOD` Event Spine alert and flags the offender for follow-up (for example, with `WARD`). The hot path is lock-free when no traps are configured. `LIST` reports trap and offender counts.
- Privileges: Oper plus `client_moderate` privilege.
- Parameters: Subcommand, target kind (`NICK`/`CHAN`), and target.
- Replies: Server notice + oper event; offenders are flagged in the registry.
- Errors: `ERR_NOPRIVILEGES 481`; usage and add/remove failures are server notices.
- Example: `SPAMTRAP ADD CHAN #freenudes`
- Sources: `src/daemon/modules/oper_security.zig`, `src/daemon/server.zig` `handleSpamtrap`, `src/daemon/spamtrap.zig`

## SHUN

- Syntax: `SHUN <nick|ip|mask> [:reason]`
- Description: Adds a gag/shun restriction through the `handleShun` path.
- Privileges: Oper.
- Parameters: Target and optional reason.
- Replies: Server notice/oper event with `proof=<id>` when the node has a signing identity.
- Errors: `ERR_NOPRIVILEGES 481`; handler validation notices.
- Example: `SHUN badnick :flood`
- Sources: `src/daemon/modules/oper_security.zig:117`, `src/daemon/server.zig:5799`

## UNSHUN

- Syntax: `UNSHUN <nick|ip|mask>`
- Description: Clears a gag/shun restriction through the same handler with `adding = false`.
- Privileges: Oper.
- Parameters: Target.
- Replies: Server notice/oper event with `proof=<id>` when the node has a signing identity.
- Errors: `ERR_NOPRIVILEGES 481`; handler validation notices.
- Example: `UNSHUN badnick`
- Sources: `src/daemon/modules/oper_security.zig:118`, `src/daemon/server.zig:5799`

## GLOBAL

- Syntax: `GLOBAL :<message>`
- Description: Sends a server global notice to connected users.
- Privileges: Oper.
- Parameters: Message text.
- Replies: Broadcast notice.
- Errors: `ERR_NOPRIVILEGES 481`, `ERR_NEEDMOREPARAMS 461`.
- Example: `GLOBAL :maintenance soon`
- Sources: `src/daemon/modules/oper_security.zig:119`, `src/daemon/server.zig:5853`

## OPERMOTD

- Syntax: `OPERMOTD [SET :text]`
- Description: Shows the operator MOTD, or replaces it when `SET` is used.
- Privileges: Oper.
- Parameters: Optional `SET` and text.
- Replies: Operator MOTD numerics or server notices.
- Errors: `ERR_NOPRIVILEGES 481`; no-oper-MOTD numeric/notice if unset.
- Example: `OPERMOTD`
- Sources: `src/daemon/modules/oper_security.zig:120`, `src/daemon/server.zig:5598`

## DIE

- Syntax: `DIE`
- Description: Publishes a critical oper action and clears the reactor run flag. Requires shutdown privilege.
- Privileges: Oper plus `server_shutdown` privilege.
- Parameters: None.
- Replies: Oper event; no numeric success reply.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `DIE`
- Sources: `src/daemon/modules/oper_security.zig:121`, `src/daemon/server.zig:6060`

## RESTART

- Syntax: `RESTART`
- Description: Same handler as `DIE`, but checks `server_restart` privilege and labels the action as `RESTART`.
- Privileges: Oper plus `server_restart` privilege.
- Parameters: None.
- Replies: Oper event; no numeric success reply.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `RESTART`
- Sources: `src/daemon/modules/oper_security.zig:122`, `src/daemon/server.zig:6060`

## CONNECT

- Syntax: `CONNECT <host> <port>`
- Description: Opens an outbound server-to-server link, creating either a secured S2S initiator or plaintext S2S link and submitting an async connect.
- Privileges: Oper plus `mesh_admin` privilege.
- Parameters: Host and TCP port.
- Replies: Oper event with `proof=<id>` when the node has a signing identity, plus server notice such as `CONNECT initiated` or `CONNECT initiated (secured)`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`, notices for illegal port, invalid host, full table, or socket failure.
- Example: `CONNECT 203.0.113.20 6667`
- Sources: `src/daemon/modules/oper_security.zig:123`, `src/daemon/server.zig:6307`

## SQUIT

- Syntax: `SQUIT <server> [:reason]`
- Description: Finds an established S2S peer by remote server name and closes it.
- Privileges: Oper plus `mesh_admin` privilege.
- Parameters: Server name; reason is currently not used by the handler.
- Replies: Oper event with `proof=<id>` when the node has a signing identity, plus `SQUIT complete` notice.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHSERVER 402`, `ERR_NOPRIVILEGES 481`.
- Example: `SQUIT peer.example :maintenance`
- Sources: `src/daemon/modules/oper_security.zig:124`, `src/daemon/server.zig:6373`

## TESTLINE

- Syntax: `TESTLINE <mask>`
- Description: Probes the target against Warden address, mask, and host facets. This is a Warden probe, not a legacy K/D-line command.
- Privileges: Oper.
- Parameters: Mask/IP/host token.
- Replies: `RPL_TESTLINE 725` or `RPL_NOTESTLINE 726`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`.
- Example: `TESTLINE 203.0.113.10`
- Sources: `src/daemon/modules/oper_security.zig:128`, `src/daemon/server.zig:6430`

## TESTMASK

- Syntax: `TESTMASK <mask>`
- Description: Counts registered clients whose `nick!user@host` matches a glob.
- Privileges: Oper.
- Parameters: Hostmask glob.
- Replies: `RPL_TESTMASK 727`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`.
- Example: `TESTMASK *!*@*.example`
- Sources: `src/daemon/modules/oper_security.zig:129`, `src/daemon/server.zig:6449`

## USERIP

- Syntax: `USERIP <nick>...`
- Description: Returns up to five nick entries with oper/away flags and IP-style host data. It is not registry oper-gated.
- Privileges: Registered client.
- Parameters: Nick list.
- Replies: Numeric `340` line from `userip.writeUseripReply`.
- Errors: `ERR_NEEDMOREPARAMS 461`.
- Example: `USERIP alice bob`
- Sources: `src/daemon/modules/oper_security.zig:130`, `src/daemon/server.zig:6032`

## DEBUG

- Syntax: `DEBUG`
- Description: Dumps the flight recorder as server notices.
- Privileges: Oper.
- Parameters: None.
- Replies: Server notices and final `End of DEBUG flight recorder`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `DEBUG`
- Sources: `src/daemon/modules/oper_security.zig:131`, `src/daemon/server.zig:6416`

## GEOIP

- Syntax: `GEOIP <ip>`
- Description: Looks up an IP in the configured MaxMind database and reports country, location, ASN/network, and proxy/hosting flags when present.
- Privileges: Oper plus `oper_spy` privilege.
- Parameters: IPv4 or IPv6 literal.
- Replies: Server notices.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`; notices for invalid IP, missing database, read error, or no data.
- Example: `GEOIP 8.8.8.8`
- Sources: `src/daemon/modules/feature_misc.zig:55`, `src/daemon/server.zig:7264`

## CLONES

- Syntax: `CLONES`
- Description: Reports connection clusters sharing an exact IP or /24-/64-style network prefix, annotated with GeoIP tags when available.
- Privileges: Oper.
- Parameters: None.
- Replies: Server notices.
- Errors: `ERR_NOPRIVILEGES 481`; `CLONES: scan failed` notice on scan failure.
- Example: `CLONES`
- Sources: `src/daemon/modules/services_ext.zig:57`, `src/daemon/server.zig:7360`

## RESV

- Syntax: `RESV <#pattern> <duration-ms> :reason | RESV DEL <#pattern> | RESV LIST`
- Description: Adds, removes, lists, or sweeps channel-name reservations. Reserved names are refused at `JOIN` for non-opers.
- Privileges: Oper.
- Parameters: Parsed by `svc_resv.parseServerCommand`.
- Replies: Server notices.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`.
- Example: `RESV #help* 3600000 :reserved`
- Sources: `src/daemon/modules/services_ext.zig:48`, `src/daemon/server.zig:6859`

## UNRESV

- Syntax: `UNRESV <#pattern>`
- Description: Alias command path into the same reservation parser, removing a reservation.
- Privileges: Oper.
- Parameters: Channel glob pattern.
- Replies: Server notice.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`.
- Example: `UNRESV #help*`
- Sources: `src/daemon/modules/services_ext.zig:49`, `src/daemon/server.zig:6859`

## FORCEOP

- Syntax: `FORCEOP <#channel> <nick>`
- Description: Forces channel operator mode on a target nick. Successful actions publish an oper Event Spine notice with `proof=<id>` when the node has a signing identity.
- Privileges: Oper.
- Parameters: Channel and nick.
- Replies: `MODE` broadcast or server notice for no-op.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOSUCHNICK 401`, `ERR_USERNOTINCHANNEL 441`, `ERR_NOPRIVILEGES 481`.
- Example: `FORCEOP #zig alice`
- Sources: `src/daemon/modules/services_ext.zig:50`, `src/daemon/server.zig:6923`

## FORCEDEOP

- Syntax: `FORCEDEOP <#channel> <nick>`
- Description: Forces removal of channel operator mode from a target nick. Successful actions publish an oper Event Spine notice with `proof=<id>` when the node has a signing identity.
- Privileges: Oper.
- Parameters: Channel and nick.
- Replies: `MODE` broadcast or server notice for no-op.
- Errors: Same as `FORCEOP`.
- Example: `FORCEDEOP #zig alice`
- Sources: `src/daemon/modules/services_ext.zig:51`, `src/daemon/server.zig:6923`

## FORCEJOIN

- Syntax: `FORCEJOIN <#channel> <nick>`
- Description: Applies `JOIN` to the target user's live connection. Successful actions publish an oper Event Spine notice with `proof=<id>` when the node has a signing identity.
- Privileges: Oper.
- Parameters: Channel and nick.
- Replies: Normal join replies to target; `Force action applied` notice to oper.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHNICK 401`, join errors, `ERR_NOPRIVILEGES 481`.
- Example: `FORCEJOIN #zig alice`
- Sources: `src/daemon/modules/services_ext.zig:52`, `src/daemon/server.zig:6923`, `src/daemon/server.zig:6973`

## FORCEPART

- Syntax: `FORCEPART <#channel> <nick> [:reason]`
- Description: Parts a target user from a channel with an optional reason. Successful actions publish an oper Event Spine notice with `proof=<id>` when the node has a signing identity.
- Privileges: Oper.
- Parameters: Channel, nick, optional reason.
- Replies: `PART` broadcast; `Force action applied` notice.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOSUCHNICK 401`, `ERR_NOPRIVILEGES 481`.
- Example: `FORCEPART #zig alice :cleanup`
- Sources: `src/daemon/modules/services_ext.zig:53`, `src/daemon/server.zig:6923`, `src/daemon/server.zig:6979`

## FORCETOPIC

- Syntax: `FORCETOPIC <#channel> :<topic>`
- Description: Sets a channel topic as the server and broadcasts it. Successful actions publish an oper Event Spine notice with `proof=<id>` when the node has a signing identity.
- Privileges: Oper.
- Parameters: Channel and topic.
- Replies: `TOPIC` broadcast.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOPRIVILEGES 481`.
- Example: `FORCETOPIC #zig :new topic`
- Sources: `src/daemon/modules/services_ext.zig:54`, `src/daemon/server.zig:6923`, `src/daemon/server.zig:7012`
