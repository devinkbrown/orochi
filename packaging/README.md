# Orochi — self-host quickstart & reproducible releases

Orochi is a single, static, **zero-external-dependency** binary. There is no
database server to run, no OpenSSL to patch, no runtime to install — it ships
its own TLS 1.3 stack, its own mesh, and its own services. This directory holds
everything to run it and to prove the binary you run is the one from source.

## 60-second quickstart (native)

```sh
# 1. Get the binary (build it — see "Reproducible releases" — or download a release).
# 2. Run a single self-hosted node with the zero-config quickstart:
./orochi packaging/orochi.quickstart.toml
```

That boots a working node:

- **`ws://localhost:8080`** — the browser WebSocket endpoint for the Onyx web client.
- **`irc://localhost:6667`** — plaintext IRC for any IRC client.

The node's **sovereign identity key** (`orochi-node.key`) and the account store
(`accounts.db`) are generated in the working directory on first run — nothing to
configure. For production, replace the quickstart config with a TLS config (real
certs or the built-in ACME client) and set `ws_plain = false`.

## 60-second quickstart (Docker)

```sh
packaging/release.sh                                   # build the verified static binary → dist/
docker build -f packaging/Dockerfile -t orochi:latest .
docker run -p 6667:6667 -p 8080:8080 -v orochi:/data orochi:latest
```

`/data` holds the node key + account store — the named volume persists them.

## Connecting the web client

Onyx (the first-party client) picks its server at build time via `VITE_IRC_WS`:

```sh
cd /path/to/onyx
VITE_IRC_WS=ws://localhost:8080 pnpm build   # dist/ now points at your node
# serve dist/ with any static file server (or a hosted Onyx build)
```

Any standard IRC client works too — point it at `localhost:6667`.

## Reproducible releases (trust, not faith)

Because the build is hermetic (pure Zig, no C interop) and static
(`x86_64-linux-musl`), a `ReleaseFast` build **at a fixed commit is bit-for-bit
reproducible**. You never have to trust the release machine.

```sh
packaging/release.sh          # → dist/orochi-<ver>-x86_64-linux-musl, SHA256SUMS, orochi.cdx.json
packaging/verify-release.sh   # rebuild from source with a clean cache; must match SHA256SUMS
```

`verify-release.sh` exits non-zero if the rebuild is not byte-identical — so a
tampered or differently-sourced binary is caught mechanically. Both scripts
refuse to run on a dirty tree (which would embed a non-reproducible `-dirty`
version).

### Signing

`release.sh` cosign-signs `SHA256SUMS` when a signer is configured
(`COSIGN_KEY=...` or keyless `COSIGN_EXPERIMENTAL=1` in CI OIDC), producing
`SHA256SUMS.sig`. `verify-release.sh` checks it when `COSIGN_PUBKEY` is set.

### SBOM

`orochi.cdx.json` is a CycloneDX SBOM — and it fits on one screen, because the
component graph is a single binary with **zero external dependencies**. That is
the whole security pitch: the software bill of materials is one line.
