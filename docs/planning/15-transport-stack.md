# Transport stack assembly (task #22)

Compose the parallel-authored substrate modules into a congestion-controlled,
paced, loss-recovering datagram transport behind the ryusen Transport vtable.

## CC interface (unify l4s + bbr behind one vtable)
```
CongestionControl.VTable {
  on_ack(ptr, now_us, acked_bytes, total_acked, rtt_us, ce_marked, app_limited),
  on_loss(ptr, now_us),
  cwnd(ptr) u64,
  pacing_rate(ptr, rtt_us) u64,
}
```
Adapters drop the args each CC ignores. **Mismatches to adapt:**
- l4s.onAck(bytes_acked, ce_marked, total_acked, rtt_us) — no now_us/app_limited.
- bbr.onAck(now_us, delivered_bytes, rtt_us, app_limited) — no CE/total.
- **bbr has NO onLoss** → adapter is a model no-op; stack treats `bbr.cwnd()` as
  authoritative (recovery via retransmit+pacing, not multiplicative cut). l4s does
  a real multiplicative backoff. Convergence assertions branch per controller.
- l4s.pacingRate(rtt_us) vs bbr.pacingRate() — vtable passes rtt; bbr ignores.

## TransportStack (new src/substrate/transport_stack.zig)
Fields: transport (ryusen.Transport, borrowed), cc (CongestionControl, borrowed),
pacer (pacing.Pacer), cwnd_window (flow.CreditWindow == cwnd-in-flight gate),
rate_cap (?flow.TokenBucket), loss (loss_recovery.LossRecovery), qlog (*Recorder).
Time in µs everywhere except sim_net (i64 ms → multiply by 1000 at boundary; keep
latencies whole ms for exact deterministic RTT).

- send(payload): gate by cwnd_window.available() → rate_cap.take() → pacer.canSend()
  (return blocked_cwnd / blocked_rate / paced{nextSendTime}); assign pn; startSend +
  drain pollSendCompletions for accepted bytes (ryusen may partial-accept); loss.onSent,
  pacer.onSent, cwnd_window.consume; qlog "packet_sent".
- recv(buf): supplyReceiveBuffer + pollReceiveCompletions.
- onAck(acked_pns, sacks, ack_delay, ce): loss.onAck (updates SRTT/min_rtt, clears
  in-flight) → acked_bytes from inflight delta → cc.onAck → cwnd_window.replenish +
  set cwnd_window.max = cc.cwnd() (clamp credit; CreditWindow.max is a public field —
  the one place we touch a field not a method) → pacer.pacing_rate = cc.pacingRate(rtt).
- tick(now): loss.detectLost → on loss cc.onLoss + resize cwnd_window + return lost
  pns for retransmit; RTO + TLP checks.

## Build order
0. Land l4s, bbr, pacing into src/substrate/ + genroots (l4s NOT in tree yet; the
   `l4s` grep hits in proto/ctcp* are unrelated). `zig build test`.
1. CC vtable + l4s/bbr cc() adapters (+ adapter unit tests).
2. TransportStack init/deinit/send/recv/onAck/tick.
3. E2E test (inline, repo convention): LoopbackTransport data plane +
   sim_net timeline; assert recovery (lossy → payload arrives in order,
   inFlightBytes()==0), cwnd convergence (l4s: grow then steady-band; bbr: phase
   progression + cwnd≈BDP), determinism (double-run + qlog NDJSON byte-compare),
   pacing spread (can't send whole cwnd at t0).

Already in tree: ryusen, flow, loss_recovery, qlog, sim_net.
