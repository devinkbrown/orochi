# Accounts and services commands

*Account, service, and persona commands exposed as real server commands — Orochi has no pseudo-clients.*

The `accounts` module registers the account and service commands (`src/daemon/modules/accounts.zig:59`), with additional commands from feature and service modules. Orochi services are real server commands that reply through server notices; no pseudo-clients exist in these handlers (`src/daemon/server.zig:8698`, `src/daemon/server.zig:8709`).

## REGISTER

- Syntax: `REGISTER <account> <email|*> <password>`
- Description: Registers an account immediately and logs the session in. Optionally issues an email verification token, applies SASL-account oper elevation when configured, tracks the session, delivers tegami, applies autojoin, and emits welcome and client-registration side effects.
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

- Syntax: `IDENTIFY <account> <password> [<2fa-code>]`
- Description: Authenticates to an existing account and logs the session in. Performs derived oper elevation, tracks the session, delivers tegami, applies autojoin, and emits login side effects. When the account has TOTP two-factor auth active (see `TOTP`), a valid 6-digit code is required as the third parameter; a correct password with a missing or wrong code is a failed login (and counts against the brute-force throttle).
- Privileges: Registered client.
- Parameters: Account, password, and — for 2FA accounts — the current TOTP code.
- Replies: Server `NOTICE` confirming login plus account-notify/welcome side effects.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_PASSWDMISMATCH 464`, IRCv3 `FAIL IDENTIFY TEMPORARILY_UNAVAILABLE`, `FAIL IDENTIFY TOTP_REQUIRED` (2FA code missing/incorrect).
- Example: `IDENTIFY alice correct-horse 492817`
- Sources: `src/daemon/modules/accounts.zig:62`, `src/daemon/server.zig:8519`

## TOTP

- Syntax: `TOTP <ENROLL | CONFIRM <code> | DISABLE | STATUS>`
- Description: Manages the logged-in account's TOTP (RFC 6238) two-factor authentication. `ENROLL` mints a 160-bit shared secret and returns it plus an `otpauth://` URI for an authenticator app (requires a TLS link — the secret must not cross plaintext). `CONFIRM <code>` activates the enrollment after verifying a code and durably saves the secret. `DISABLE` removes it. `STATUS` reports active/pending/disabled. Enabling or disabling 2FA revokes any existing SASL session token. Once active, every login path enforces the second factor: `IDENTIFY` requires the code; knowledge-factor SASL (PLAIN/SCRAM, over both IRCv3 `AUTHENTICATE` and IRCX `AUTH`) is refused with a pointer to use `IDENTIFY`. EXTERNAL (client cert) and OAUTHBEARER are not gated.
- Privileges: Registered client logged in to an account.
- Parameters: A subcommand; `CONFIRM` additionally takes the current 6-digit code.
- Replies: Server `NOTICE` lines (secret + otpauth URI on `ENROLL`; status/confirmation otherwise).
- Errors: IRCv3 `FAIL TOTP` with `ACCOUNT_REQUIRED`, `TEMPORARILY_UNAVAILABLE`, `INSECURE_TRANSPORT` (ENROLL off TLS), `ALREADY_ENROLLED`, `NEED_MORE_PARAMS`, `INVALID_CODE`, `NO_PENDING`, `INVALID_SUBCOMMAND`.
- Example: `TOTP ENROLL` then `TOTP CONFIRM 492817`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` (`handleTotp`), `src/daemon/totp_auth.zig`

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

## RESETPASS

- Syntax: `RESETPASS <account>` (request) or `RESETPASS <account> <code> <new-password>` (set).
- Description: Reset a forgotten password by proving ownership of the account's verified email — the "other method" companion to the cert-verified one-argument `SETPASS`. The request form emails a one-time code (32 hex chars, 15-minute TTL) to the account's verified address; the set form consumes the code, sets the new password, and revokes existing session tokens. Usable while logged out.
- Privileges: Any registered connection (no login required).
- Requirements: A configured mail transport (`[mail]`); the account must have a **verified** email. Without `[mail]`, the request form replies `FAIL RESETPASS UNAVAILABLE`.
- Anti-abuse: The request form replies identically whether or not the account exists or has a verified email (no account enumeration), and will not re-send while a code issued within the last 60s is still pending.
- Replies: Request → `NOTICE` "if that account has a verified email, a reset code has been sent."; set → raw `RESETPASS SUCCESS <account> :Password reset; log in with your new password`.
- Errors: `ERR_NEEDMOREPARAMS 461`; IRCv3 `FAIL RESETPASS` with `TEMPORARILY_UNAVAILABLE`, `UNAVAILABLE`, `NO_REQUEST`, `EXPIRED`, `BAD_CODE`, `TOO_MANY_ATTEMPTS`, `INVALID_PASSWORD`.
- Example: `RESETPASS alice` then `RESETPASS alice 0123456789abcdef0123456789abcdef new-correct-horse`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` `handleResetpass`, `src/daemon/password_reset.zig`

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
- Description: Shows configured SASL mechanisms and whether the caller is currently logged in. Live mechanism listings are limited to wired mechanisms: `PLAIN`, `SCRAM-SHA-256`, and `EXTERNAL` when their backends are configured.
- Privileges: Registered client.
- Parameters: None.
- Replies: Server notices.
- Errors: None specific.
- Example: `SASLINFO`
- Sources: `src/daemon/modules/accounts.zig:66`, `src/daemon/server.zig:8605`

## ACCOUNTSET

- Syntax: `ACCOUNTSET <account> <password> <email|flags|secure|enforce> <value>`
- Description: Updates account settings after password verification. `email` sets the address; `flags` sets the non-privileged numeric flag bits; `secure on|off` recognizes the account only via identify, never an access-list match alone; `enforce on|off` controls nick protection on the account's registered nick (on by default — `off` opts the account out of the automatic force-rename sweep).
- Privileges: Registered client (the account owner).
- Parameters: Account, password, field, value.
- Replies: Server `NOTICE` confirming update.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_PASSWDMISMATCH 464`, `FAIL ACCOUNTSET INVALID_VALUE`, `FAIL ACCOUNTSET INVALID_FIELD`, `FAIL ACCOUNTSET TEMPORARILY_UNAVAILABLE`.
- Example: `ACCOUNTSET alice correct-horse secure on`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` `handleAccountSet`, `src/daemon/svc_enforce.zig`

## RECOVER

- Syntax: `RECOVER <nick>`
- Description: Forces an unauthenticated holder off the account owner's registered nick immediately, rather than waiting out the protection grace, then briefly holds the nick (nick-delay) so the owner can reclaim it. The requester must be identified to the account that owns the nick. A holder that is the owner's own authenticated session is never ejected. The pure `svc_recover` module owns the decision logic.
- Privileges: Registered client identified to the owning account.
- Parameters: Target nick.
- Replies: Server `NOTICE`; the holder is force-renamed to a `Guest…` nick.
- Errors: `ERR_NEEDMOREPARAMS 461`, `FAIL RECOVER NICK_NOT_REGISTERED`, `FAIL RECOVER ACCESS_DENIED`, `FAIL RECOVER TEMPORARILY_UNAVAILABLE`.
- Example: `RECOVER alice`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` `handleRecover`, `src/daemon/svc_recover.zig`

## RELEASE

- Syntax: `RELEASE <nick>`
- Description: Drops a server-held nick reservation (nick-delay) on the account owner's registered nick ahead of its window, making the nick available again. Requires identification to the account.
- Privileges: Registered client identified to the owning account.
- Parameters: Target nick.
- Replies: Server `NOTICE`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `FAIL RELEASE NICK_NOT_REGISTERED`, `FAIL RELEASE ACCESS_DENIED`, `FAIL RELEASE TEMPORARILY_UNAVAILABLE`.
- Example: `RELEASE alice`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` `handleRelease`, `src/daemon/svc_recover.zig`

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
- Description: Real server command for channel services. The implemented switch handles `REGISTER`, `DROP`, `INFO`, `ACCESS`, `AKICK`, and `SET MLOCK`; `TRANSFER` and non-MLOCK `SET` fields are parsed but still reply as unavailable.
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
- Replies: Server notices for `SESSION LIST`, `SESSION TOKEN`, optional `SESSION MTOKEN`, resume, redirect, and list end. Reclaim and migration state changes are also published on the Event Spine service plane.
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

## KEYTRANS

- Syntax: `KEYTRANS [STATUS|ROOT|PROOF <position>]`
- Description: Inspects the account credential transparency log. `STATUS` (default) reports whether the log is enabled plus the current append count and Merkle Mountain Range root. `ROOT` is an alias for status. `PROOF <position>` streams an inclusion-proof snapshot for a leaf index as `KEYTRANS PROOF`, `KEYTRANS PATH`, `KEYTRANS PEAK`, and `KEYTRANS PROOF-END` server notices.
- Privileges: Registered client.
- Parameters: Optional subcommand; `PROOF` additionally takes a decimal leaf index.
- Replies: Server notices: `KEYTRANS STATUS disabled`, `KEYTRANS STATUS enabled entries=<n> root=<hex>`, or proof lines with root/path/peak hashes.
- Errors: `FAIL KEYTRANS TEMPORARILY_UNAVAILABLE`, `NEED_MORE_PARAMS`, `BAD_POSITION`, `DISABLED`, `NO_SUCH_LEAF`, `INTERNAL_ERROR`, `INVALID_SUBCOMMAND`.
- Example: `KEYTRANS PROOF 42`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` `handleKeyTrans`, `src/daemon/services.zig` `keyTransparencyProof`

## E2EEKEY

- Syntax: `E2EEKEY [STATUS|LIST [account]|ADD <device-id> <algorithm> <public-key>|DEL <device-id>]`
- Description: Manages public E2EE device-key advertisements for the caller's logged-in account. Device records are stored as account-scoped user PROP metadata under `e2ee.device.<device-id>` with value `<algorithm>:<public-key>`, so they replicate over the signed `ENTITY_PROP` path. `LIST [account]` reads public device keys for the caller or a named account; `ADD` and `DEL` require login to the owning account.
- Privileges: Registered client; account login required for `STATUS`, `ADD`, `DEL`, and caller-default `LIST`.
- Parameters: Optional subcommand; `ADD` takes a bounded device id, algorithm token, and public key token.
- Replies: Server notices: `E2EEKEY STATUS account=<account> devices=<n>`, `E2EEKEY DEVICE account=<account> id=<device> alg=<algorithm> key=<public-key>`, `E2EEKEY END account=<account> devices=<n>`, `E2EEKEY ADDED ...`, or `E2EEKEY DELETED ...`.
- Errors: `FAIL E2EEKEY NOT_LOGGED_IN`, `NEED_MORE_PARAMS`, `BAD_DEVICE`, `BAD_KEY`, `STORE_FAILED`, `INVALID_SUBCOMMAND`.
- Example: `E2EEKEY ADD phone mls-x25519 abcd+/=`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` `handleE2eeKey`, `src/proto/e2ee_policy.zig`

## TEGAMI

- Syntax: `TEGAMI [LIST|CLEAR|SEND <account> :message]` (alias: `MEMO`)
- Description: Offline account messages (手紙 — "letter"); `MEMO` is an alias for the same command. `LIST` is the default and does not clear; login delivery clears pending messages.
- Privileges: Registered client; account login required for list/clear/send.
- Parameters: Optional subcommand; `SEND` target account and message.
- Replies: Server notices for message lists, clear count, forwarding, ignore lists, and delivery. Clear/forward mutations are also published on the Event Spine service plane.
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
- Replies: Server notices for list/end output and mutation confirmations.
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
