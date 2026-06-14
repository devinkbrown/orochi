# Orochi ISUPPORT (005)

`src/proto/protocol_inventory.zig` is the source of truth for static `RPL_ISUPPORT` tokens (`src/proto/protocol_inventory.zig:1`, `src/proto/protocol_inventory.zig:40`). At boot, `main.zig` installs the configured network name, builds config-driven ISUPPORT tokens, and stores runtime limits before serving clients (`src/main.zig:129`, `src/main.zig:134`, `src/main.zig:139`).

The live server emits `RPL_ISUPPORT` with `protocol_inventory.currentIsupport()` and trailing text `are supported by this server` (`src/daemon/server.zig:8105`). The pre-registration welcome burst also emits the same current token list (`src/daemon/dispatch.zig:1497`).

## Token Table

| Token | Default Value | Meaning | Config / Runtime Notes | Evidence |
| --- | --- | --- | --- | --- |
| `NETWORK` | `Orochi` | Advertised network name. | Default is `network_name`; operators can override via `[network] name`, installed by `setNetworkName` and rewritten by `buildIsupportTokens`. | `src/proto/protocol_inventory.zig:14`, `src/proto/protocol_inventory.zig:40`, `src/daemon/server.zig:860`, `src/main.zig:129` |
| `CHANTYPES` | `#&` | Channel name prefixes accepted/advertised. | Static token. | `src/proto/protocol_inventory.zig:42` |
| `NICKLEN` | `64` | Maximum nick length in bytes. | Config-overridable via `[limits]`; pre-registration NICK enforcement reads `currentLimits().nicklen`. | `src/proto/protocol_inventory.zig:43`, `src/proto/protocol_inventory.zig:82`, `src/daemon/server.zig:868`, `src/daemon/dispatch.zig:1269` |
| `TOPICLEN` | `390` | Maximum topic bytes. | Config-overridable via `[limits]`; TOPIC truncates to configured `topiclen` on UTF-8 boundary. | `src/proto/protocol_inventory.zig:46`, `src/daemon/server.zig:862`, `src/daemon/server.zig:11195` |
| `AWAYLEN` | `256` | Maximum AWAY message bytes. | Config-overridable via `[limits]` in `buildIsupportTokens`. | `src/proto/protocol_inventory.zig:47`, `src/daemon/server.zig:864` |
| `KICKLEN` | `307` | Maximum KICK comment bytes. | Config-overridable via `[limits]`; KICK truncation is documented in handler comments. | `src/proto/protocol_inventory.zig:48`, `src/daemon/server.zig:866`, `src/daemon/server.zig:4612` |
| `CHANNELLEN` | `64` | Maximum channel name length. | Config-overridable via `[limits]` in `buildIsupportTokens`. | `src/proto/protocol_inventory.zig:49`, `src/daemon/server.zig:870` |
| `MAXLIST` | `beIZ:100` | Per-channel cap on list modes `+b`, `+e`, `+I`, `+Z`. | Config-overridable via `[limits]`; `World.max_list_entries` enforces the cap. | `src/proto/protocol_inventory.zig:50`, `src/daemon/server.zig:872`, `src/daemon/world.zig:195`, `src/daemon/world.zig:761` |
| `CHANLIMIT` | `#&:50` | Maximum joined channels by prefix class. | Config-overridable via `[limits]`; JOIN emits `ERR_TOOMANYCHANNELS` when exceeded. | `src/proto/protocol_inventory.zig:51`, `src/daemon/server.zig:874`, `src/daemon/server.zig:3908` |
| `MAXTARGETS` | `4` | Maximum message targets per PRIVMSG/NOTICE command. | Config-overridable via `[limits]`; excess emits `ERR_TOOMANYTARGETS`. | `src/proto/protocol_inventory.zig:52`, `src/daemon/server.zig:876`, `src/daemon/server.zig:10769` |
| `MONITOR` | `128` | Maximum MONITOR targets. | Config-overridable via `[limits]`; MONITOR handler maps list-full to `ERR_MONLISTFULL`. | `src/proto/protocol_inventory.zig:53`, `src/daemon/server.zig:878`, `src/daemon/server.zig:5267`, `src/daemon/server.zig:5280` |
| `SILENCE` | `32` | Maximum SILENCE masks. | Config-overridable via `[limits]`; SILENCE query emits 271/272. | `src/proto/protocol_inventory.zig:54`, `src/daemon/server.zig:880`, `src/daemon/server.zig:5382` |
| `CASEMAPPING` | `ascii` | Case-folding policy for identifiers. | World maps use ASCII case-insensitive contexts for nicks/channels. | `src/proto/protocol_inventory.zig:55`, `src/daemon/world.zig:75` |
| `PREFIX` | `(Qqov)!.@+` | Member status modes and their prefix characters. | Founder `Q`/`!` is Orochi-native and ranks above owner. | `src/proto/protocol_inventory.zig:56`, `src/daemon/chanmode.zig:244`, `src/daemon/chanmode.zig:310` |
| `CHANMODES` | `beIZ,k,lfj,imnstCTNMSgWOAVUFD` | Four channel-mode classes: list, param-always, param-on-set, flag. | Static token from `chanmodes_token`. `W` (NOWHISPER), `O` (oper-only), `A` (admin-only), `V` (NOCOMICDATA), `U` (OPMODERATE), `F` (FREETARGET), and `D` (DISFORWARD) are live flag modes; see `modes.md`. | `src/proto/protocol_inventory.zig` (`chanmodes_token`) |
| `STATUSMSG` | `!.@+` | Allowed status-target prefixes for channel messages. | Server maps `!`, `.`, `@`, `+` to minimum delivery ranks. | `src/proto/protocol_inventory.zig:58`, `src/daemon/server.zig:10946`, `src/daemon/server.zig:11031` |
| `BOT` | `B` | Bot user mode letter. | Mirrors user mode `+B` and IRCv3 bot support. | `src/proto/protocol_inventory.zig:59`, `src/proto/usermode.zig:141` |
| `EXTBAN` | `$,acgmrz` | Extended-ban namespace and supported extban types. | World list matching parses `$` entries for account/realname/country/channel/negation contexts. | `src/proto/protocol_inventory.zig:60`, `src/daemon/world.zig:787`, `src/daemon/world.zig:791` |
| `WHOX` | present | WHOX extended WHO replies are supported. | WHOX uses `RPL_WHOSPCRPL` 354 and `RPL_ENDOFWHO` 315. | `src/proto/protocol_inventory.zig:61`, `src/daemon/server.zig:4660`, `src/daemon/server.zig:4750` |
| `UTF8ONLY` | present | Clients must send UTF-8 message bodies. | Invalid PRIVMSG body gets `FAIL <command> INVALID_UTF8`; NOTICE stays silent. | `src/proto/protocol_inventory.zig:62`, `src/daemon/server.zig:10803` |

## Override Path

`buildIsupportTokens` copies the static token list and rewrites `NETWORK`, `TOPICLEN`, `AWAYLEN`, `KICKLEN`, `NICKLEN`, `CHANNELLEN`, `MAXLIST`, `CHANLIMIT`, `MAXTARGETS`, `MONITOR`, and `SILENCE` from `Config` (`src/daemon/server.zig:851`, `src/daemon/server.zig:859`). Tokens not matched by those prefixes are borrowed directly from the static inventory (`src/daemon/server.zig:882`).

`protocol_inventory.currentIsupport()` returns the config-built override when installed, otherwise the static array (`src/proto/protocol_inventory.zig:65`, `src/proto/protocol_inventory.zig:73`).
