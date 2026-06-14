# Accounts And Services Commands

Account and service commands are registered by the `accounts` module (`src/daemon/modules/accounts.zig:59`) and feature/service modules. Orochi services are real server commands and server notices; there are no pseudo-clients in these handlers (`src/daemon/server.zig:8698`, `src/daemon/server.zig:8709`).

## REGISTER

- Syntax: `REGISTER <account> <email|*> <password>`
- Description: Registers an account immediately, logs the session in, optionally issues an email verification token, applies SASL-account oper elevation if configured, tracks the session, delivers tegami, applies autojoin, and emits welcome/client-registration side effects.
- Privileges: Registered client.
- Parameters: Account, email or `*`, password.
- Replies: Raw `REGISTER SUCCESS <account> :Account registered`, optional `VERIFY <token>` notice, welcome/account side effects.
- Errors: IRCv3 `FAIL REGISTER` with `TEMPORARILY_UNAVAILABLE`, `NEED_MORE_PARAMS`, `ACCOUNT_EXISTS`, `BAD_ACCOUNT_NAME`, `INVALID_PASSWORD`.
- Example: `REGISTER alice alice@example.net correct-horse`
- Sources: `src/daemon/modules/accounts.zig:60`, `src/daemon/server.zig:8475`

## VERIFY

- Syntax: `VERIFY <token>`
- Description: Confirms a pending account email verification token.
- Privileges: Registered client.
- Parameters: Verification token.
- Replies: Server notice/failure from handler.
- Errors: Handler-specific failure replies for missing or invalid token.
- Example: `VERIFY abcdef012345`
- Sources: `src/daemon/modules/accounts.zig:61`, `src/daemon/server.zig:5717`

## IDENTIFY

- Syntax: `IDENTIFY <account> <password>`
- Description: Authenticates to an existing account, logs the session in, performs derived oper elevation, tracks the session, delivers tegami, autojoins, and emits login side effects.
- Privileges: Registered client.
- Parameters: Account and password.
- Replies: Server `NOTICE` confirming login plus account-notify/welcome side effects.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_PASSWDMISMATCH 464`, IRCv3 `FAIL IDENTIFY TEMPORARILY_UNAVAILABLE`.
- Example: `IDENTIFY alice correct-horse`
- Sources: `src/daemon/modules/accounts.zig:62`, `src/daemon/server.zig:8519`

## LOGOUT

- Syntax: `LOGOUT`
- Description: Removes the account login, removes the live session from the session registry, sends account-notify, and revokes `+o` when oper status came from the account.
- Privileges: Registered client.
- Parameters: None.
- Replies: Optional `MODE <nick> :-o`, then server `NOTICE` confirming logout.
- Errors: None specific.
- Example: `LOGOUT`
- Sources: `src/daemon/modules/accounts.zig:63`, `src/daemon/server.zig:8545`

## DROP

- Syntax: `DROP <account> <password>`
- Description: Deletes an account after password verification.
- Privileges: Registered client.
- Parameters: Account and password.
- Replies: Server `NOTICE` confirming drop.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_PASSWDMISMATCH 464`, IRCv3 `FAIL DROP TEMPORARILY_UNAVAILABLE`.
- Example: `DROP alice correct-horse`
- Sources: `src/daemon/modules/accounts.zig:64`, `src/daemon/server.zig:8568`

## ACCOUNTINFO

- Syntax: `ACCOUNTINFO [account]`
- Description: Reports account name and flags. Without an argument, uses the caller's logged-in account.
- Privileges: Registered client.
- Parameters: Optional account.
- Replies: Server `NOTICE` `account=<name> flags=<n>`.
- Errors: `ERR_NEEDMOREPARAMS 461` when neither argument nor login exists; `FAIL ACCOUNTINFO ACCOUNT_UNKNOWN`; `FAIL ACCOUNTINFO TEMPORARILY_UNAVAILABLE`.
- Example: `ACCOUNTINFO alice`
- Sources: `src/daemon/modules/accounts.zig:65`, `src/daemon/server.zig:8585`

## SASLINFO

- Syntax: `SASLINFO`
- Description: Shows configured SASL mechanisms and whether the caller is currently logged in.
- Privileges: Registered client.
- Parameters: None.
- Replies: Server notices.
- Errors: None specific.
- Example: `SASLINFO`
- Sources: `src/daemon/modules/accounts.zig:66`, `src/daemon/server.zig:8605`

## ACCOUNTSET

- Syntax: `ACCOUNTSET <account> <password> <email|flags> <value>`
- Description: Updates account email or numeric flags after password verification.
- Privileges: Registered client.
- Parameters: Account, password, field, value.
- Replies: Server `NOTICE` confirming update.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_PASSWDMISMATCH 464`, `FAIL ACCOUNTSET INVALID_VALUE`, `FAIL ACCOUNTSET INVALID_FIELD`, `FAIL ACCOUNTSET TEMPORARILY_UNAVAILABLE`.
- Example: `ACCOUNTSET alice correct-horse email alice@example.net`
- Sources: `src/daemon/modules/accounts.zig:67`, `src/daemon/server.zig:8636`

## GHOST

- Syntax: `GHOST <nick> <password>`
- Description: Password-verifies the account associated with the target nick and disconnects the stale live session if present.
- Privileges: Registered client.
- Parameters: Target nick and password.
- Replies: Victim receives `ERROR :Ghosted by <nick>`; caller receives server `NOTICE`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_PASSWDMISMATCH 464`, `FAIL GHOST TEMPORARILY_UNAVAILABLE`.
- Example: `GHOST alice_ correct-horse`
- Sources: `src/daemon/modules/accounts.zig:68`, `src/daemon/server.zig:8668`

## CHANNEL

- Syntax: `CHANNEL <REGISTER|DROP|INFO|ACCESS|AKICK|SET|TRANSFER> <#channel> ...`
- Description: Real server command for channel services. Current implemented switch handles `REGISTER`, `DROP`, `INFO`, `ACCESS`, `AKICK`, and `SET MLOCK`; `TRANSFER` and non-MLOCK `SET` fields are parsed surfaces that still reply as unavailable.
- Privileges: Registered client logged in to an account.
- Parameters: Subcommand and channel-specific arguments.
- Replies: Server notices; `REGISTER`/`DROP` also reflect live registered-channel state.
- Errors: IRCv3 `FAIL CHANNEL` codes including `TEMPORARILY_UNAVAILABLE`, `NEED_MORE_PARAMS`, `ACCOUNT_REQUIRED`, `INVALID_PARAMS`, `CHANNEL_EXISTS`, `CHANNEL_UNKNOWN`, `ACCESS_DENIED`, `BAD_CHANNEL_NAME`.
- Example: `CHANNEL REGISTER #zig`
- Sources: `src/daemon/modules/accounts.zig:69`, `src/daemon/server.zig:8709`

## CS

- Syntax: `CS <subcommand> <#channel> ...`
- Description: Alias of `CHANNEL`, dispatched to the same handler.
- Privileges: Same as `CHANNEL`.
- Parameters: Same as `CHANNEL`.
- Replies: Same as `CHANNEL`.
- Errors: Same as `CHANNEL`.
- Example: `CS INFO #zig`
- Sources: `src/daemon/modules/accounts.zig:70`, `src/daemon/server.zig:8714`

## SESSION

- Syntax: `SESSION [LIST|TOKEN|RESUME <token>]`
- Description: Lists live sessions for the caller's account, reveals this session's local and optional mesh reclaim tokens, or resumes a detached session.
- Privileges: Registered client logged in to an account.
- Parameters: Optional subcommand; `LIST` is default.
- Replies: `NOTE SESSION LIST`, `NOTE SESSION TOKEN`, optional `NOTE SESSION MTOKEN`, or end notices.
- Errors: `FAIL SESSION INVALID_TOKEN`, `FAIL SESSION NO_SESSION`; account-required notice.
- Example: `SESSION TOKEN`
- Sources: `src/daemon/modules/accounts.zig:71`, `src/daemon/server.zig:8880`, `src/daemon/server.zig:8930`

## CERTADD

- Syntax: `CERTADD`
- Description: Binds the TLS client-certificate fingerprint presented on this connection to the logged-in account for future SASL EXTERNAL use.
- Privileges: Registered client logged in to an account with client certificate.
- Parameters: None.
- Replies: Server notice confirming fingerprint binding.
- Errors: `FAIL CERTADD TEMPORARILY_UNAVAILABLE`, `NOT_LOGGED_IN`, `NO_CLIENT_CERT`, `CERT_ADD_FAILED`.
- Example: `CERTADD`
- Sources: `src/daemon/modules/accounts.zig:85`, `src/daemon/server.zig:12157`

## CERTLIST

- Syntax: `CERTLIST`
- Description: Lists TLS client-certificate fingerprints bound to the logged-in account for SASL EXTERNAL.
- Privileges: Registered client logged in to an account.
- Parameters: None.
- Replies: Server notices, one `CERTLIST <fingerprint>` per bound fingerprint, or a no-fingerprints notice.
- Errors: `FAIL CERTLIST TEMPORARILY_UNAVAILABLE`, `NOT_LOGGED_IN`, `CERT_LIST_FAILED`.
- Example: `CERTLIST`
- Sources: `src/daemon/modules/accounts.zig:86`, `src/daemon/server.zig:12167`

## CERTDEL

- Syntax: `CERTDEL <fingerprint>`
- Description: Removes a TLS client-certificate fingerprint binding from the logged-in account.
- Privileges: Registered client logged in to an account.
- Parameters: Certificate fingerprint.
- Replies: Server notice confirming removal.
- Errors: `FAIL CERTDEL TEMPORARILY_UNAVAILABLE`, `NOT_LOGGED_IN`, `NEED_MORE_PARAMS`, `CERT_NOT_OWNED`, `CERT_NOT_FOUND`, `CERT_DEL_FAILED`.
- Example: `CERTDEL SHA256:...`
- Sources: `src/daemon/modules/accounts.zig:87`, `src/daemon/server.zig:12183`

## TEGAMI

- Syntax: `TEGAMI [LIST|CLEAR|SEND <account> :message]`
- Description: Offline account messages. `LIST` is default and does not clear; login delivery clears pending messages.
- Privileges: Registered client; account login required for list/clear/send.
- Parameters: Optional subcommand; `SEND` target account and message.
- Replies: `NOTE TEGAMI` lines, clear count, or delivery notice.
- Errors: `ERR_NEEDMOREPARAMS 461`, `FAIL TEGAMI ACCOUNT_REQUIRED`, `ACCOUNT_UNKNOWN`, `MAILBOX_FULL`, `INVALID_MESSAGE`, `TEMPORARILY_UNAVAILABLE`, `INVALID_SUBCOMMAND`.
- Example: `TEGAMI SEND alice :ping me later`
- Sources: `src/daemon/modules/feature_misc.zig:53`, `src/daemon/server.zig:9030`

## VHOST

- Syntax: `VHOST [LIST|USE <name>|OFF|CLAIM <host>|REQUEST <host>|OFFERLIST|APPROVE <account>|DENY <account> [:reason]|OFFER <template> [:label]|SET <account> <host> [name]|<host>]`
- Description: Manages visible host personas. Bare `VHOST` lists the wardrobe and offers. Users can request, claim, use, or turn off personas. Opers can approve/deny requests, publish offers, set account personas, or set their own host with bare `VHOST <host>`. Applying a vhost broadcasts native `CHGHOST` to capable common-channel peers; `CHGHOST` itself is not a registered command.
- Privileges: Registered client for list/use/off/claim/request/offerlist; account login required for persona actions; oper required for approve/deny/offer/set/bare host set.
- Parameters: Subcommand-specific.
- Replies: Server notices; native `CHGHOST` lines to capable clients when a host changes.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`, `FAIL VHOST ACCOUNT_REQUIRED`, `INVALID_HOST`, `TEMPORARILY_UNAVAILABLE`; other validation failures as notices.
- Example: `VHOST REQUEST staff.example`
- Sources: `src/daemon/modules/feature_misc.zig:49`, `src/daemon/server.zig:9734`, `src/daemon/server.zig:9982`

## PRIVS

- Syntax: `PRIVS`
- Description: Reports the caller's live operator class and privilege set.
- Privileges: Oper.
- Parameters: None.
- Replies: `RPL_PRIVS 270`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `PRIVS`
- Sources: `src/daemon/modules/feature_misc.zig:50`, `src/daemon/server.zig:9709`

## FILTER

- Syntax: `FILTER <ADD|DEL|LIST> [pattern]`
- Description: Oper-only content filter control. Patterns are case-insensitive substring blocks applied to non-oper messages.
- Privileges: Oper.
- Parameters: `LIST`, or `ADD`/`DEL` plus pattern.
- Replies: `NOTE FILTER` list/end notices or server notices.
- Errors: `ERR_NOPRIVILEGES 481`, `ERR_NEEDMOREPARAMS 461`, `FAIL FILTER TEMPORARILY_UNAVAILABLE`, `INVALID_PATTERN`, `NO_SUCH_PATTERN`, `INVALID_SUBCOMMAND`.
- Example: `FILTER ADD badword`
- Sources: `src/daemon/modules/feature_misc.zig:51`, `src/daemon/server.zig:9647`

## SEEN

- Syntax: `SEEN <account>`
- Description: Reports an account's last seen and last login timestamps plus recent login/logout history recorded by account login/logout hooks.
- Privileges: Registered client (`services.ext` sets `.access = .registered`).
- Parameters: Account name.
- Replies: Server notices with summary and recent records, or `SEEN <account>: no record`.
- Errors: `ERR_NEEDMOREPARAMS 461`.
- Example: `SEEN alice`
- Sources: `src/daemon/modules/services_ext.zig:58`, `src/daemon/server.zig:7185`
