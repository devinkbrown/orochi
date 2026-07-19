# TLS/SSL Library Research: OpenSSL vs BoringSSL vs LibreSSL vs mbedTLS vs wolfSSL

**Generated:** 2026-07-18, via the `deep-research` workflow (107 sub-agents: scope → 6 parallel
search angles → 24 sources fetched → 100 claims extracted → 25 adversarially 3-vote-verified →
19 confirmed / 6 refuted / 0 left unverified).

**Master copy:** `/home/kain/research/TLS_SSL_LIBRARY_RESEARCH.md` (cross-project reference; this
is a synced copy for discoverability alongside orochi's own TLS research).

**Relevance to orochi:** this was commissioned for the xchat2 client's `xchat2-security` agent
(which wraps OpenSSL directly), not for Armor — orochi's from-scratch, no-C-interop TLS stack is a
different animal entirely and this research does not evaluate it or suggest replacing it. It's
included here because the licensing/governance/CVE findings on OpenSSL, BoringSSL, LibreSSL,
mbedTLS, and wolfSSL are useful background when this repo's own research
([tls-feature-gaps.md](tls-feature-gaps.md), [tls13-feature-audit.md](tls13-feature-audit.md),
[pq-kem-compliance.md](pq-kem-compliance.md)) benchmarks Armor against BoringSSL/wolfSSL feature
parity, and when reasoning about what those upstream projects' *external* TLS libraries actually
guarantee vs. what Armor implements natively.

> **How to use this file:** treat the "Confirmed findings" table as load-bearing (each claim
> survived a 3-independent-reviewer refutation vote). Treat "Refuted claims" as things that
> *sounded* plausible but did NOT survive verification — don't re-assert them elsewhere. Treat
> "Known gaps" as honest holes, not settled negatives. This is a point-in-time snapshot (2026-07)
> of a fast-moving space (wolfSSL relicensed and took 3 CVEs in the ~12 months before this was
> written) — re-verify anything load-bearing before citing it as current fact a year from now.

---

## BLUF / Executive Summary

**For a GPLv2 desktop client linking exactly one TLS library for outbound connections (the
originating xchat2 case), verified evidence does not support moving off OpenSSL:**

- **wolfSSL is disqualified on licensing**, not just preference: it relicensed its GPL tier from
  GPLv2 to **GPLv3-only** in v5.8.2 (~Sept 2025). A strict GPLv2 project (no "or later" clause —
  check your own `COPYING` file) cannot link it without a commercial license or a named slot in
  wolfSSL's FLOSS exception list, which does not include arbitrary third-party projects.
- **wolfSSL's OpenSSL-compat layer is a documented partial subset**, not a parity guarantee — code
  written against real OpenSSL (`SSL_CTX`/`SSL`/`BIO`) is not assumed to compile unchanged. That
  same compat layer carried a **critical 2026 X.509 trust-chain-bypass CVE**
  (CVE-2026-11310) — the exact surface a migrating project would land on.
- **mbedTLS is licensing-clean** (Apache-2.0, vendor-neutral Trusted Firmware governance) but uses
  its own native API (PSA Crypto), not an OpenSSL shim — adopting it means a **rewrite**, not a
  drop-in swap, for a desktop (non-embedded) target where mbedTLS's footprint advantage doesn't
  matter.
- **OpenSSL itself is Apache-2.0 since 3.0** (Sept 2021) — already GPL-compatible, matching the
  linking-exception assumption most older GPL projects were written around. It has mature TLS 1.3
  and shipped native PQC (ML-KEM/ML-DSA/SLH-DSA, default hybrid X25519MLKEM768) in 3.5 (April
  2025). Its well-documented 3.x locking-performance regression is a high-concurrency **server**
  problem, largely irrelevant to a client holding a handful of connections.
- **BoringSSL and LibreSSL remain largely unverified in this pass** — see Known Gaps. Don't infer
  drop-in compatibility for either; a specific claim to that effect ("curl's configure script
  detects them the same way as OpenSSL, so they're near drop-in") was explicitly **refuted** by
  adversarial review.

---

## Per-library snapshot

### OpenSSL
- **License:** Apache-2.0 since 3.0.0 (Sept 2021) — was the old dual OpenSSL/SSLeay license before
  that. GPL-compatible.
- **Protocol/PQC:** no official NIST PQC through 3.4 (2024); native ML-KEM/ML-DSA/SLH-DSA landed in
  **3.5 (April 2025)**, with hybrid X25519MLKEM768 on by default. Mature TLS 1.3.
- **Performance:** OpenSSL 3.0+ has a well-documented multi-threaded locking regression vs 1.1.1
  (10–99% throughput loss depending on scenario), root-caused by excessive internal locking and
  only partially mitigated by 3.5 LTS. This matters for high-connection-count **servers**; largely
  irrelevant to a client holding one or a few TLS connections.
- **API:** the reference SSL_CTX/SSL/BIO model everything else is compared against.

### wolfSSL
- **License:** dual **GPLv3-or-commercial** as of v5.8.2 (~Sept 2025) — changed from GPLv2. A
  strict GPLv2-only project (no "or later") cannot link it without a commercial license or a named
  slot in wolfSSL's FLOSS exception list (verified narrower than a blanket "combine with any FOSS
  license" allowance — see Refuted claims).
- **API compat:** ships a real OpenSSL-compatibility layer (`OPENSSL_EXTRA`,
  `wolfssl/openssl/*.h` mirroring `SSL_CTX`/`SSL`/`BIO`, ~500+ mirrored functions per vendor docs)
  — but vendor documentation itself frames it as a **partial, growing subset**, not a parity
  guarantee.
- **Security:** three 2026 CVEs directly in cert/signature verification: **CVE-2026-5194**
  (FIPS 186-4 signature-check bypass, fixed 5.9.1), **CVE-2026-11310** (X.509 trust-chain bypass
  scoped specifically to the `OPENSSL_EXTRA` verify-cert compat path, fixed 5.9.2), and
  **CVE-2026-6679** (DTLS 1.3 pre-auth heap overflow, fixed 5.9.1). Separately, the Trail of
  Bits/LORIA-INRIA `tlspuffin` fuzzer found four CVEs in 2022 (NULL-deref DoS, MitM client crash,
  TLS 1.3 resumption stack overflow, record-header heap over-read) — a track record of
  protocol-logic bugs, not just memory-safety issues.
- **Performance/footprint:** genuinely strong on embedded targets — vendor benchmarks (methodology
  disclosed, but vendor-run) show large wins over mbedTLS on ARM Cortex-A/M and RISC-V, and heap
  use for a TLS connection reported at ~38 KB vs OpenSSL 3.0's 800+ KB.
- **PQC:** fully supports ML-KEM/ML-DSA in TLS 1.3 as of 2025, markets CNSA 2.0 compliance —
  relevant background when reading [pq-kem-compliance.md](pq-kem-compliance.md)'s comparison
  points.

### mbedTLS
- **Governance:** vendor-neutral **Trusted Firmware Foundation** since March 2020. Crypto
  primitives now live in a sibling project, **TF-PSA-Crypto**, implementing the PSA Crypto API,
  which Mbed TLS consumes.
- **License:** Apache-2.0 — no licensing friction with any GPL variant.
- **API:** its own native API (PSA Crypto / mbedtls_*), **not** an OpenSSL shim as far as this
  research confirmed — see Known Gaps, this is an open question, not a settled negative.
- **Target profile:** embedded/constrained-environment focus (small footprint).

### BoringSSL
- Google-internal-first, explicitly **no API/ABI stability promise** for external consumers
  (well-known industry reputation, not independently re-verified as a *new* claim in this pass).
- PQC: BoringSSL/Chrome shipped standardized ML-KEM in **Sept 2024**, fully replacing the earlier
  draft-Kyber codepoint by Chrome 131 — a confirmed, cited finding, and useful context for
  [tls13-feature-audit.md](tls13-feature-audit.md)'s BoringSSL comparison points.
- Everything else (governance detail, CVE history, audit history, API migration friction) is a
  **gap** in this research pass — see Known Gaps.

### LibreSSL
- OpenBSD-driven; ISC/OpenBSD-style licensing (background knowledge, not freshly verified here).
- **PQC status is explicitly unresolved**: a claim that LibreSSL "has not implemented any NIST PQC
  algorithms as of 2025" was gathered but **refuted** on adversarial review (0-3 vote) — meaning
  the refutation process found the blanket claim unsupportable, not that the opposite is true.
- Audit history, API migration friction, and CVE history are **gaps** — see Known Gaps.

---

## Confirmed findings (survived 3-vote adversarial verification)

| Claim | Confidence | Key sources |
|---|---|---|
| mbedTLS is governed by the vendor-neutral Trusted Firmware Foundation; crypto primitives split into the sibling TF-PSA-Crypto project (PSA Crypto API) | high | trustedfirmware.org |
| wolfSSL's OpenSSL compat layer (`OPENSSL_EXTRA`, `wolfssl/openssl/*.h`) is real but an explicitly-documented partial subset, not guaranteed parity | high | wolfssl.com manual ch.13, wolfssl.com/docs/wolfssl-openssl |
| wolfSSL relicensed GPLv2→GPLv3-or-commercial in v5.8.2 (~Sept 2025); its FLOSS exception is a narrow named list that does not cover arbitrary GPLv2 projects | high | wolfssl.com/license, wolfssl.com/docs/floss-exception, wolfSSL COPYING/LICENSING, GH issue wolfSSL/wolfssl#9177 |
| OpenSSL's license changed from the old OpenSSL/SSLeay dual license to Apache-2.0 starting at 3.0.0 (Sept 2021) | high | openssl.org/source/license.html |
| PQC timeline: OpenSSL 3.5 (Apr 2025) shipped native ML-KEM/ML-DSA/SLH-DSA with default hybrid X25519MLKEM768; wolfSSL fully supports ML-KEM/ML-DSA in TLS 1.3 as of 2025; BoringSSL/Chrome shipped standardized ML-KEM Sept 2024 | high | openssl-library.org 3.5 release post, security.googleblog.com, arxiv.org/pdf/2508.16078 |
| wolfSSL 2026 CVEs: CVE-2026-5194 (FIPS 186-4 sig-check bypass, fixed 5.9.1), CVE-2026-11310 (X.509 trust-chain bypass in the `OPENSSL_EXTRA` verify-cert path, fixed 5.9.2), CVE-2026-6679 (DTLS 1.3 pre-auth heap overflow, fixed 5.9.1) | high | wolfssl.com/docs/security-vulnerabilities |
| `tlspuffin` (Trail of Bits/LORIA-INRIA, Dolev-Yao-model-guided fuzzer) found 4 wolfSSL CVEs in 2022 (CVE-2022-38152/-38153/-39173/-42905) | high | blog.trailofbits.com/2023/01/12 |
| OpenSSL 3.0+ has a severe multi-threaded locking-performance regression vs 1.1.1 (10–99% loss depending on scenario), partially mitigated in 3.5 LTS | high | haproxy.com/blog/state-of-ssl-stacks |
| curl's pluggable-TLS-backend architecture (OpenSSL/BoringSSL/GnuTLS/wolfSSL/LibreSSL/quictls/AWS-LC/Schannel) is a proven real-world pattern, but curl's own docs group the OpenSSL-family forks under one tracking column rather than vetting them independently — a stronger "near drop-in" claim was refuted | medium | everything.curl.dev/internals/backends.html, curl.se/libcurl/c/tls-options.html |

## Refuted claims (do NOT re-assert these)

These sounded plausible enough to extract but did **not** survive the 3-independent-reviewer
refutation vote — listed so nobody re-introduces them as fact later:

1. ~~"wolfSSL is distributed under GPLv2 as its base license."~~ — **false as of Sept 2025**; it's GPLv3-or-commercial now (vote 1-2).
2. ~~"wolfSSL's FLOSS exception permits combining GPLv2 wolfSSL code with any other approved open-source license without the combined work needing to be GPL."~~ — refuted (vote 0-3); the exception is a narrow named list.
3. ~~"BoringSSL and LibreSSL are positioned by curl as OpenSSL-API-compatible variants... rather than fundamentally different APIs."~~ — refuted (vote 1-2).
4. ~~"BoringSSL/LibreSSL are close enough to OpenSSL's build/API surface that curl's configure script detects them the same way, supporting near-drop-in status."~~ — refuted (vote 0-3). **Do not assume drop-in compatibility for either.**
5. ~~"As of 2025, LibreSSL has implemented no NIST PQC algorithms, with no roadmap."~~ — refuted (vote 0-3). Status is genuinely unresolved, not confirmed-absent.
6. ~~"Without an explicit GPL linking exception, a GPLv2 program cannot lawfully link a non-GPL-compatible TLS library."~~ — refuted as a blanket legal-mechanics claim (vote 0-3); the actual legal analysis needs to rest on each library's specific license text, not general principle.

## Known gaps (honest holes, not settled negatives)

- **mbedTLS**: does it offer *any* OpenSSL-compatibility shim, or is adoption a full rewrite
  against its native PSA/mbedtls API? Not confirmed either way.
- **BoringSSL**: no confirmed data in this pass on its actual API/ABI stability posture for
  non-Google downstream consumers, its CVE history, or its audit history.
- **LibreSSL**: no confirmed data on PQC/hybrid-KEM roadmap or formal audit history.
- **wolfSSL compile-compatibility**: whether OpenSSL-shaped client code would actually compile
  unmodified against wolfSSL's `OPENSSL_EXTRA` layer was never confirmed — moot given the
  licensing disqualification for strict-GPLv2 projects.
- This research is a **single pass over 24 sources**, not exhaustive — treat as a strong starting
  point, not the final word, especially on anything time-sensitive.

---

## Licensing quick-reference (for any GPL C/C++ project)

| Library | License | GPLv2-only compatible? |
|---|---|---|
| OpenSSL (≥3.0) | Apache-2.0 | Yes |
| OpenSSL (<3.0, old) | OpenSSL/SSLeay dual license | Historically needed an explicit linking exception |
| BoringSSL | Mixed (OpenSSL-derived + Google additions) | Not independently re-verified this pass — check current LICENSE file |
| LibreSSL | ISC/OpenBSD-style | Generally yes, not independently re-verified this pass |
| mbedTLS | Apache-2.0 | Yes |
| wolfSSL | **GPLv3-or-commercial** (changed from GPLv2 in v5.8.2, ~Sept 2025) | **No**, unless you hold a commercial license or a named FLOSS-exception slot |

---

## Full source list (24 fetched)

| URL | Quality | Angle |
|---|---|---|
| haproxy.com/blog/state-of-ssl-stacks | blog | Governance/roadmap |
| safeguard.sh/resources/blog/openssl-vs-libressl-vs-boringssl-2026 | blog | Governance/roadmap |
| trustedfirmware.org/projects/mbed-tls | primary | Governance/roadmap |
| wolfssl.com/documentation/manuals/wolfssl/chapter13.html | primary | API compat |
| wolfssl.com/migrating-openssl-wolfssl | blog | API compat |
| forums.mbed.com/t/guide-to-porting-from-openssl-to-mbedtls/15004 | forum | API compat |
| arxiv.org/pdf/2508.16078 | secondary | Protocol/CVE history |
| wolfssl.com/docs/security-vulnerabilities | primary | Protocol/CVE history |
| blog.trailofbits.com/2023/01/12/wolfssl-vulnerabilities-tlspuffin-fuzzing-ssh | primary | Protocol/CVE history |
| wolfssl.com/wolfssl-vs-mbedtls-an-apples-to-apples-benchmark... | blog | Performance/footprint |
| wolfssl.com/comparing-wolfssl-vs-openssl | blog | Performance/footprint |
| en.wikipedia.org/wiki/Comparison_of_TLS_implementations | secondary | Performance/footprint |
| medium.com/@thealonemusk/the-2mb-vs-20mb-showdown-mbedtls-and-openssl-face-off | blog | Performance/footprint |
| grokipedia.com/page/Comparison_of_TLS_implementations | unreliable (0 claims used) | Performance/footprint |
| en.wikipedia.org/wiki/GPL_linking_exception | secondary | Licensing |
| github.com/RetroShare/RetroShare/issues/1807 | forum | Licensing |
| wolfssl.com/docs/floss-exception | primary | Licensing |
| github.com/wolfssl/wolfssl/issues/9177 | forum | Licensing |
| curl.se/docs/ssl-compared.html | primary | Desktop-client precedent |
| everything.curl.dev/internals/backends.html | primary | Desktop-client precedent |
| everything.curl.dev/build/tls.html | primary | Desktop-client precedent |
| daniel.haxx.se/blog/2021/04/23/please-select-your-tls | blog | Desktop-client precedent |
| curl.se/libcurl/c/tls-options.html | primary | Desktop-client precedent |
| github.com/alexcrichton/curl-rust/issues/536 | forum | Desktop-client precedent |
