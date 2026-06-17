# Quickstart

Orochi is a pure-Zig 0.16 clean-room IRC daemon. The build package declares Zig `0.16.0` as the minimum supported compiler (`build.zig.zon:28`), and the daemon build rejects 32-bit targets (`build.zig:20`, `build.zig:24`).

## Build

From the repository root:

```sh
zig build
```

The default build installs the `orochi` executable under `zig-out/bin` (`build.zig:87`, `build.zig:119`).

For a fast semantic check:

```sh
zig build check
```

The `check` step analyzes `src/main.zig` without emitting a daemon binary (`build.zig:213`, `build.zig:227`).

## Minimal Config

The parser requires only `[node].id` and `[listen].irc` (`src/daemon/config_format.zig:478`):

```toml
[node]
id = 1

[listen]
host = "127.0.0.1"
irc = 6680
```

Save that as a local TOML file, or start from the runnable reference at `etc/orochi.reference.toml`. Current source still requires `[listen].irc` even for TLS-first deployments.

## First Run

Run with an explicit config path:

```sh
zig build run -- etc/orochi.reference.toml
```

`src/main.zig` treats the first non-command argument as the config file path, reads up to 1 MiB, parses it, maps it onto `server.Config`, and stores the path for live `REHASH` (`src/main.zig:99`, `src/main.zig:104`, `src/main.zig:106`, `src/main.zig:112`). If the file is missing or invalid, current boot logs the error and keeps defaults instead of aborting (`src/main.zig:116`, `src/main.zig:119`).

The normal listener default is port `6680` before config overlay (`src/main.zig:40`). The boot sequence then installs the configured network name, ISUPPORT limits, mesh identity, SASL account store, cloaking key, TLS listener, and optional STS policy before starting the server loop (`src/main.zig:129`, `src/main.zig:141`, `src/main.zig:160`, `src/main.zig:200`, `src/main.zig:216`, `src/main.zig:242`, `src/main.zig:266`).

## Config Indirection

The parser supports `env:NAME` and `@file:path` string indirection (`src/daemon/config_format.zig:486`). The current CLI boot resolver wires `env:` only (`src/main.zig:100`), so `@file:` currently requires a boot path that provides a file resolver.

## Connection Classes

After the basic setup, consider defining connection classes under `[class.<name>]` to control per-client resource limits, flood policies, and admission rules by IP/TLS/account/oper status. See [operators.md](operators.md) for detailed coverage. Every custom class inherits sensible fallbacks via the built-in `user` and `server` classes.
