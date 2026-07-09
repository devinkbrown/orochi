# Orochi runbook

*Build, stage, validate, deploy, monitor, hot-upgrade, and roll back an Orochi node.*

This runbook describes the shipped tree. For full configuration details, use
[reference/config.md](reference/config.md) and `etc/orochi.reference.toml`.

## Operator Model

Orochi runs as a long-lived network daemon with:

- a config file passed as `argv[1]`;
- a systemd unit in `etc/systemd/orochi.service`;
- state under `/var/lib/orochi` in the packaged unit;
- ReleaseFast production binaries from `zig build release` or `zig build package`;
- session-preserving reload via SIGUSR2/Helix, exposed as `systemctl reload orochi`.

Cold restart is the fallback path and drops sessions. Reload is the normal upgrade path.

## Build And Stage

```sh
zig build check
zig build test-smoke --summary all
zig build test-roadmap --summary all
zig build test-smoke -Doptimize=ReleaseSafe --summary all
zig build package --prefix /tmp/orochi-stage
```

The package step stages:

| Path | Contents |
|---|---|
| `/tmp/orochi-stage/bin/orochi` | ReleaseFast stripped daemon |
| `/tmp/orochi-stage/etc/orochi/orochi.reference.toml` | Annotated reference config |
| `/tmp/orochi-stage/lib/systemd/system/orochi.service` | systemd service unit |

For local smoke tests against the debug binary:

```sh
zig build
python3 tools/runtime_smoke.py zig-out/bin/orochi
python3 tools/upgrade_smoke.py zig-out/bin/orochi
```

## Pre-Deploy Config Validation

Validate the exact config before staging a reload:

```sh
zig build run -- --check-config /etc/orochi/orochi.toml
```

`--check-config` reads and parses the file, resolves configured `env:` and `@file:`
string indirection through the CLI resolver, reports `config OK`, and exits without
binding listeners or dialing mesh peers.

## First Install

The packaged systemd unit documents the required host setup:

```sh
useradd --system --home-dir /var/lib/orochi --shell /usr/sbin/nologin orochi
install -d -o orochi -g orochi /var/lib/orochi /etc/orochi
install -m 0640 -o orochi -g orochi etc/orochi.reference.toml /etc/orochi/orochi.toml
install -m 0755 zig-out/bin/orochi /usr/local/bin/orochi
install -m 0644 etc/systemd/orochi.service /etc/systemd/system/orochi.service
systemctl daemon-reload
systemctl enable --now orochi
```

If all listeners use high ports, remove `AmbientCapabilities=CAP_NET_BIND_SERVICE` and
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE` from the unit.

## Hot Upgrade

Use Helix reload for normal production upgrades:

```sh
zig build package --prefix /tmp/orochi-stage
zig build run -- --check-config /etc/orochi/orochi.toml
install -m 0755 /tmp/orochi-stage/bin/orochi /usr/local/bin/orochi
systemctl reload orochi
```

`ExecReload=/bin/kill -USR2 $MAINPID` asks the live daemon to re-exec in place. The
successor inherits the listener and attempts to reattach live sessions from the sealed
Helix arena. The process PID remains under systemd control; systemd does not see a
normal restart.

Verify after reload:

```sh
systemctl status orochi --no-pager
journalctl -u orochi -n 100 --no-pager
```

Then connect an IRC client or run an out-of-band probe against the configured listener.

## Cold Restart

Use cold restart only when changing host-level unit constraints, recovering from a bad
state, or accepting session loss:

```sh
systemctl restart orochi
systemctl status orochi --no-pager
```

Cold restart drops live client sessions and mesh links. Mesh peers should redial through
the configured `[mesh].connect` and listener paths.

## Rollback

Keep the previous known-good binary before replacing `/usr/local/bin/orochi`:

```sh
install -m 0755 /usr/local/bin/orochi /usr/local/bin/orochi.prev
install -m 0755 /tmp/orochi-stage/bin/orochi /usr/local/bin/orochi
systemctl reload orochi
```

If the new image fails after reload:

```sh
install -m 0755 /usr/local/bin/orochi.prev /usr/local/bin/orochi
systemctl reload orochi || systemctl restart orochi
```

Prefer a second reload for rollback. Use restart only if the process is already failed
or the reload path itself is broken.

## Health Checks

| Check | Command / Surface | Expected |
|---|---|---|
| systemd state | `systemctl status orochi --no-pager` | active running |
| recent logs | `journalctl -u orochi -n 100 --no-pager` | no repeated panic/restart loop |
| config parse | `orochi --check-config /etc/orochi/orochi.toml` | `config OK` |
| IRC registration | connect to listener, send `NICK`/`USER` | `001` welcome |
| PING/PONG | send `PING :token` | `PONG` with token |
| INFO | `/INFO` | runtime limits, class count, mesh peer count |
| STATS Y | `/STATS Y` as oper | connection-class policy visible |
| STATS l | `/STATS l` as oper | established S2S sendq state |
| status feed | configured `chanstats_dir/status.json` | current node and peer health |
| Prometheus | configured `[metrics].port` `/metrics` | Prometheus text body |

`status.json` and channel stats are file outputs, not daemon-owned HTTP routes. Serve
the configured stats directory with nginx or another static file server if needed.

## Common Incidents

| Symptom | Likely Cause | Action |
|---|---|---|
| `--check-config` fails | Bad TOML, missing `[node].id`, missing `[listen].irc`, invalid range, missing `@file:` target | Fix config and rerun `--check-config`; do not reload until clean. |
| systemd starts then loops | Binary crash or invalid runtime dependency | Check `journalctl -u orochi`; restore previous binary and restart/reload. |
| Privileged port bind fails | Unit lacks `CAP_NET_BIND_SERVICE` or port already bound | Add capability lines from unit or move listeners to high ports; inspect `ss -ltnup`. |
| Reload drops sessions | Helix fallback or adoption failure | Check logs for `SIGUSR2 UPGRADE failed` or adoption errors; run `tools/upgrade_smoke.py` locally. |
| Mesh peer absent after reload | Peer link not reattached or redial still pending | Inspect `/INFO`, `/STATS l`, status feed, and `[mesh].connect`; verify peer listener reachability. |
| Metrics unavailable | `[metrics].port = 0`, bind failure, or loopback-only bind | Check config and startup logs; default bind is loopback unless widened deliberately. |
| WebSocket/WebTransport disabled | TLS cert/key material missing or listener disabled | Check `[tls]`, `[listen].ws`, `[listen].webtransport`, and boot logs. |

## CI And Release Expectations

Before merging a release-bearing change:

```sh
zig build all-checks --summary all
zig build release -Dtarget=x86_64-linux-musl
zig build package --summary all
git diff --check
```

For long tmux or CI diagnosis, use verbose lanes:

```sh
zig build test-roadmap-verbose --summary all
zig build all-checks-verbose --summary all
```

Verbose lanes print every test name, duration, final counts, and the slowest tests.
