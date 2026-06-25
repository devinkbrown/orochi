# Transport stack assembly (task #22)
*Design note from the planning phase — records design intent; shipped behavior is documented under docs/guide/ and docs/reference/.*

This document composes the parallel-authored substrate modules into a congestion-controlled, paced, loss-recovering datagram transport behind the ryusen `Transport` vtable.

## Congestion-control interface

The stack unifies l4s and bbr behind one vtable:

```zig
CongestionControl.VTable {
  on_ack(ptr, now_us, acked_bytes, total_acked, rtt_us, ce_marked, app_limited),
  on_loss(ptr, now_us),
  cwnd(ptr) u64,
  pacing_rate(ptr, rtt_us) u64,
}
```

Adapters drop the arguments each CC ignores.

| Controller path | Mismatch | Adapter behavior |
|---|---|---|
| `l4s.onAck(bytes_acked, ce_marked, total_acked, rtt_us)` | no `now_us`/`app_limited` | Drop `now_us` and `app_limited`. |
| `bbr.onAck(now_us, delivered_bytes, rtt_us, app_limited)` | no CE/total | Drop CE and total. |
| **bbr has NO onLoss** | no loss callback | Use a model no-op; the stack treats `bbr.cwnd()` as authoritative (recovery via retransmit+pacing, not multiplicative cut). l4s does a real multiplicative backoff. Convergence assertions branch per controller. |
| `l4s.pacingRate(rtt_us)` vs `bbr.pacingRate()` | vtable passes rtt | bbr ignores rtt. |

## TransportStack

Create `src/substrate/transport_stack.zig` with these fields:

| Field | Role |
|---|---|
| `transport` | `ryusen.Transport`, borrowed |
| `cc` | `CongestionControl`, borrowed |
| `pacer` | `pacing.Pacer` |
| `cwnd_window` | `flow.CreditWindow == cwnd-in-flight gate` |
| `rate_cap` | `?flow.TokenBucket` |
| `loss` | `loss_recovery.LossRecovery` |
| `qlog` | `*Recorder` |

Time uses µs everywhere except `sim_net` (`i64 ms` → multiply by 1000 at the boundary; keep latencies whole ms for exact deterministic RTT).

| Operation | Behavior |
|---|---|
| `send(payload)` | Gate by `cwnd_window.available()` → `rate_cap.take()` → `pacer.canSend()` and return `blocked_cwnd` / `blocked_rate` / `paced{nextSendTime}`; assign `pn`; call `startSend` and drain `pollSendCompletions` for accepted bytes (`ryusen` may partial-accept); call `loss.onSent`, `pacer.onSent`, and `cwnd_window.consume`; emit qlog `"packet_sent"`. |
| `recv(buf)` | Call `supplyReceiveBuffer` and `pollReceiveCompletions`. |
| `onAck(acked_pns, sacks, ack_delay, ce)` | Call `loss.onAck` (updates SRTT/min_rtt, clears in-flight) → compute `acked_bytes` from inflight delta → call `cc.onAck` → call `cwnd_window.replenish` and set `cwnd_window.max = cc.cwnd()` (clamp credit; `CreditWindow.max` is a public field, the one place we touch a field not a method) → set `pacer.pacing_rate = cc.pacingRate(rtt)`. |
| `tick(now)` | Call `loss.detectLost` → on loss, call `cc.onLoss`, resize `cwnd_window`, and return lost pns for retransmit; run RTO + TLP checks. |

## Build order

0. Land l4s, bbr, pacing into `src/substrate/` + genroots (l4s NOT in tree yet; the `l4s` grep hits in `proto/ctcp*` are unrelated). `zig build test`.
1. CC vtable + l4s/bbr cc() adapters (+ adapter unit tests).
2. TransportStack init/deinit/send/recv/onAck/tick.
3. E2E test (inline, repo convention): `LoopbackTransport` data plane + `sim_net` timeline; assert recovery (lossy → payload arrives in order, `inFlightBytes()==0`), cwnd convergence (l4s: grow then steady-band; bbr: phase progression + cwnd≈BDP), determinism (double-run + qlog NDJSON byte-compare), pacing spread (can't send whole cwnd at t0).

Already in tree: ryusen, flow, loss_recovery, qlog, sim_net.
