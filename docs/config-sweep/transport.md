# Orochi Transport Subsystem — Hardcoded Config Sweep

READ-ONLY survey of `/home/kain/orochi/src/substrate/` transport files. Lists operationally/performance-meaningful hardcoded literals to be lifted into a TOML config. Excludes wire-format/spec constants, crypto, enum discriminants, type widths, and pure test values.

Files surveyed: ryusen.zig, bbr.zig, l4s.zig, twcc.zig, transport_stack.zig, sim_net.zig, pacing.zig, pmtud.zig, cc_cubic.zig, loss_recovery.zig, backoff.zig, multipath.zig, flow.zig, gcra.zig.

Note: flow.zig, gcra.zig are generic limiter primitives — all parameters are caller-supplied with no embedded operational defaults, so nothing to lift. backoff.zig Policy has only structural defaults (factor=2). multipath.zig Scheduler has no numeric tuning defaults.

---

## [transport]  (stack-level / general)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| transport_stack.zig:114 | `Config.mss` | 1460 | Max segment size used to size pacer burst (`2*mss`) | transport.mss_bytes | uint | 1460 | 1200..9000 |
| transport_stack.zig:115-116 | `Config.rate_cap_bps` | 0 (disabled) | Optional admission rate ceiling (bytes/s); 0 disables | transport.rate_cap_bps | uint | 0 | 0..– |
| transport_stack.zig:117 | `Config.rate_cap_burst` | 0 | Token-bucket burst for the rate cap | transport.rate_cap_burst_bytes | uint | 0 | 0..– |
| transport_stack.zig:150 | `init` seed pacing rate probe `cc.pacingRate(10_000)` | 10_000 us | RTT assumed when seeding initial pacer rate before first ACK | transport.seed_rtt_us | duration(us) | 10000 | 1000..1000000 |
| transport_stack.zig:155 | pacer `burst_budget` = `@max(2*mss,1)` | 2 (×mss) | Pacer burst budget as multiple of MSS | transport.pacer_burst_mss_multiple | uint | 2 | 1..16 |
| transport_stack.zig:227 | `onAck` RTT fallback `self.loss.smoothedRtt() orelse 10_000` | 10_000 us | RTT used for cc/pacing when no SRTT yet | transport.fallback_rtt_us | duration(us) | 10000 | 1000..1000000 |
| transport_stack.zig:129 | `Recorder = qlog.Recorder(1024)` | 1024 | qlog ring-buffer event capacity | transport.qlog_capacity | uint | 1024 | 64..65536 |

## [transport.pmtud]  (path MTU discovery, RFC 8899)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| pmtud.zig:25 | `Config.base_mtu` | 1200 | Conservative MTU floor (borderline: 1200 is the QUIC min, but exposed as tunable) | transport.pmtud.base_mtu | uint | 1200 | 1200..1500 |
| pmtud.zig:27 | `Config.max_mtu` | 1500 | Upper bound the caller probes toward | transport.pmtud.max_mtu | uint | 1500 | 1280..9216 |
| pmtud.zig:29 | `Config.min_probe_delta` | 1 | Smallest useful MTU increase per probe | transport.pmtud.min_probe_delta | uint | 1 | 1..256 |
| pmtud.zig:32 | `Config.blackhole_loss_threshold` | 3 | Consecutive losses at current MTU before blackhole fallback | transport.pmtud.blackhole_loss_threshold | uint | 3 | 1..16 |

## [transport.congestion]  (cross-CC / generic)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|

## [transport.congestion.l4s]  (DCTCP / TCP-Prague-lite, l4s.zig)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| l4s.zig:15 | `Config.initial_cwnd` | 12_000 | Initial congestion window (bytes) | transport.congestion.l4s.initial_cwnd_bytes | uint | 12000 | 2400..16777216 |
| l4s.zig:17 | `Config.min_cwnd` | 2_400 | Lower cwnd clamp (bytes) | transport.congestion.l4s.min_cwnd_bytes | uint | 2400 | 1200..– |
| l4s.zig:19 | `Config.max_cwnd` | 16*1024*1024 (16 MiB) | Upper cwnd clamp (bytes) | transport.congestion.l4s.max_cwnd_bytes | uint | 16777216 | 65536..– |
| l4s.zig:21 | `Config.additive_increase_bytes` | 1_200 | Byte quantum per additive increase (≈1 MSS) | transport.congestion.l4s.additive_increase_bytes | uint | 1200 | 1..9000 |
| l4s.zig:23 | `Config.alpha_gain_num` | 1 | DCTCP alpha EWMA gain numerator (gain=1/16) | transport.congestion.l4s.alpha_gain_num | uint | 1 | 1..– |
| l4s.zig:25 | `Config.alpha_gain_den` | 16 | DCTCP alpha EWMA gain denominator | transport.congestion.l4s.alpha_gain_den | uint | 16 | 1..1024 |
| l4s.zig:27 | `Config.marking_reduction_num` | 1 | CE-mark backoff numerator (cwnd*alpha/2) | transport.congestion.l4s.marking_reduction_num | uint | 1 | 1..– |
| l4s.zig:29 | `Config.marking_reduction_den` | 2 | CE-mark backoff denominator | transport.congestion.l4s.marking_reduction_den | uint | 2 | 1..1024 |
| l4s.zig:31 | `Config.loss_backoff_num` | 1 | Classic loss multiplicative-decrease numerator (halving) | transport.congestion.l4s.loss_backoff_num | uint | 1 | 1..– |
| l4s.zig:33 | `Config.loss_backoff_den` | 2 | Classic loss multiplicative-decrease denominator | transport.congestion.l4s.loss_backoff_den | uint | 2 | 1..1024 |

## [transport.congestion.bbr]  (bandwidth+RTT model, bbr.zig)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| bbr.zig:117 | `Config.mss` | 1460 | Initial max segment size (bytes) | transport.congestion.bbr.mss_bytes | uint | 1460 | 1200..9000 |
| bbr.zig:119 | `Config.min_rtt_window_us` | 10_000_000 (10 s) | Min-RTT filter window; drives ProbeRTT cadence | transport.congestion.bbr.min_rtt_window_us | duration(us) | 10000000 | 1000000..60000000 |
| bbr.zig:121 | `Config.initial_cwnd_bytes` | 10*1460 (14600) | Initial cwnd seed before first ACK | transport.congestion.bbr.initial_cwnd_bytes | uint | 14600 | 4380..– |
| bbr.zig:34-36 | `PACING_GAIN_CYCLE` | {1.25,0.75,1,1,1,1,1,1} | ProbeBW 8-slot pacing-gain cycle | transport.congestion.bbr.pacing_gain_cycle | list[float] | [1.25,0.75,1,1,1,1,1,1] | – |
| bbr.zig:39 | `STARTUP_PACING_GAIN` | 2.885 | Startup pacing gain (2/ln2) | transport.congestion.bbr.startup_pacing_gain | float | 2.885 | 1.0..4.0 |
| bbr.zig:40 | `STARTUP_CWND_GAIN` | 2.0 | Startup cwnd gain (also Drain cwnd gain) | transport.congestion.bbr.startup_cwnd_gain | float | 2.0 | 1.0..4.0 |
| bbr.zig:43 | `PROBE_BW_CWND_GAIN` | 2.0 | ProbeBW cwnd gain | transport.congestion.bbr.probe_bw_cwnd_gain | float | 2.0 | 1.0..4.0 |
| bbr.zig:44 | `PROBE_RTT_CWND_FRACTION` | 0.75 | cwnd fraction held during ProbeRTT | transport.congestion.bbr.probe_rtt_cwnd_fraction | float | 0.75 | 0.25..1.0 |
| bbr.zig:47 | `BW_WINDOW_LEN` | 10 | Max-bandwidth filter window (RTT rounds) | transport.congestion.bbr.bw_window_rounds | uint | 10 | 2..64 |
| bbr.zig:51 | `PROBE_RTT_DURATION_US` | 200_000 (200 ms) | How long ProbeRTT holds reduced cwnd | transport.congestion.bbr.probe_rtt_duration_us | duration(us) | 200000 | 50000..1000000 |
| bbr.zig:53 | `MIN_CWND_BYTES` | 4*1500 (6000) | Floor cwnd to avoid degenerate windows | transport.congestion.bbr.min_cwnd_bytes | uint | 6000 | 2400..– |
| bbr.zig:325,434 | round/cycle duration fallback `100_000` | 100_000 (100 ms) | Round/cycle duration before first RTT sample | transport.congestion.bbr.pre_rtt_round_us | duration(us) | 100000 | 10000..1000000 |
| bbr.zig:381 | Startup gain threshold `*125/100` | 1.25 (25%) | Min bw growth/round to stay in Startup | transport.congestion.bbr.startup_growth_threshold | float | 1.25 | 1.05..2.0 |
| bbr.zig:389 | Startup exit `rounds_without_gain >= 3` | 3 | Consecutive flat rounds before exiting Startup | transport.congestion.bbr.startup_full_bw_rounds | uint | 3 | 1..8 |
| bbr.zig:412 | Drain exit `drain_rounds >= 1` | 1 | Rounds spent in Drain before ProbeBW | transport.congestion.bbr.drain_rounds | uint | 1 | 1..4 |

## [transport.congestion.cubic]  (CUBIC, cc_cubic.zig)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| cc_cubic.zig:3 | `DEFAULT_C` | 0.4 | CUBIC scaling constant C (aggressiveness) | transport.congestion.cubic.c | float | 0.4 | 0.1..1.0 |
| cc_cubic.zig:4 | `DEFAULT_BETA` | 0.7 | CUBIC multiplicative-decrease beta | transport.congestion.cubic.beta | float | 0.7 | 0.5..0.9 |
| cc_cubic.zig:11 | `Config.initial_cwnd` | 10 (packets) | Initial cwnd in packets | transport.congestion.cubic.initial_cwnd_packets | uint | 10 | 2..100 |
| cc_cubic.zig:12 | `Config.min_cwnd` | 2 (packets) | Min cwnd in packets | transport.congestion.cubic.min_cwnd_packets | uint | 2 | 1..– |
| cc_cubic.zig:13 | `Config.max_cwnd` | maxInt(u64) | Max cwnd in packets (effectively unbounded) | transport.congestion.cubic.max_cwnd_packets | uint | 0 (=unbounded) | 0..– |
| cc_cubic.zig:14 | `Config.initial_ssthresh` | maxInt(u64) | Initial slow-start threshold (packets) | transport.congestion.cubic.initial_ssthresh_packets | uint | 0 (=unbounded) | 0..– |

## [transport.recovery]  (loss detection / RTO / RACK / TLP, loss_recovery.zig)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| loss_recovery.zig:25 | `initial_rto_us` | 1_000_000 (1 s) | RTO used before any SRTT sample | transport.recovery.initial_rto_us | duration(us) | 1000000 | 200000..6000000 |
| loss_recovery.zig:26 | `min_rto_us` | 1_000_000 (1 s) | Lower clamp on computed RTO | transport.recovery.min_rto_us | duration(us) | 1000000 | 100000..6000000 |
| loss_recovery.zig:27 | `clock_granularity_us` | 1_000 (1 ms) | Granularity floor added to RTT variation | transport.recovery.clock_granularity_us | duration(us) | 1000 | 100..10000 |
| loss_recovery.zig:28 | `rack_min_reorder_window_us` | 1_000 (1 ms) | Floor of RACK reorder window (else min_rtt/4) | transport.recovery.rack_min_reorder_window_us | duration(us) | 1000 | 100..50000 |
| loss_recovery.zig:29 | `initial_tlp_delay_us` | 200_000 (200 ms) | TLP probe delay before SRTT exists | transport.recovery.initial_tlp_delay_us | duration(us) | 200000 | 10000..1000000 |
| loss_recovery.zig:30 | `min_tlp_delay_us` | 10_000 (10 ms) | Lower clamp on TLP delay (else 2*srtt) | transport.recovery.min_tlp_delay_us | duration(us) | 10000 | 1000..200000 |
| loss_recovery.zig:31 | `default_packet_threshold` | 3 | RACK/packet-threshold reorder gap before declaring loss | transport.recovery.packet_threshold | uint | 3 | 1..16 |
| loss_recovery.zig:206 | rackReorderWindow `min_rtt / 4` | 4 (divisor) | Fraction of min-RTT used as RACK reorder window | transport.recovery.rack_reorder_rtt_fraction_div | uint | 4 | 1..16 |
| loss_recovery.zig:186-187 | SRTT/RTTVAR EWMA `7/8` & `3/4` | 1/8, 1/4 (gains) | RFC6298 SRTT/RTTVAR smoothing weights (borderline: spec-derived but tunable) | transport.recovery.srtt_alpha_shift / rttvar_beta_shift | uint | 3 / 2 | 1..6 |
| loss_recovery.zig:144 | tlpTimeout `srtt * 2` | 2 | TLP delay multiplier on SRTT | transport.recovery.tlp_srtt_multiplier | uint | 2 | 1..4 |
| loss_recovery.zig:127 | rto `rttvar * 4` | 4 | RTTVAR multiplier in RTO formula (RFC6298 K; borderline) | transport.recovery.rto_rttvar_multiplier | uint | 4 | 1..8 |

## [transport.twcc]  (transport-wide congestion control feedback, twcc.zig)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| _(none — all literals are draft-holmer wire-format/spec constants: delta_unit_us=250, reference_time_unit_us=64000, payload types, chunk formats. Feedback cadence is driven by caller, not a hardcoded interval here.)_ |||||||

---

## Summary

**Total liftable constants: 49**

Per-section counts:
- `[transport]` (stack-level): 7
- `[transport.pmtud]`: 4
- `[transport.congestion.l4s]`: 10
- `[transport.congestion.bbr]`: 16
- `[transport.congestion.cubic]`: 6
- `[transport.recovery]`: 12
- `[transport.twcc]`: 0 (all spec/wire constants)

**Excluded (no operational literals to lift):** twcc.zig (all wire-format), flow.zig, gcra.zig, multipath.zig, sim_net.zig NetworkModel (test-harness, all 0/false), ryusen.zig (loopback sim only — SimulationConfig is a DST test fixture, not production tuning), pacing.zig Pacer/GsoLimits (no embedded defaults; values are caller/stack-supplied).

**Top 10 highest-value lifts:**
1. `transport.congestion.l4s.initial_cwnd_bytes` (12000) — primary CC ramp behavior, l4s.zig:15
2. `transport.congestion.l4s.max_cwnd_bytes` (16 MiB) — caps throughput ceiling, l4s.zig:19
3. `transport.recovery.initial_rto_us` (1 s) — dominates startup/handshake retransmit latency, loss_recovery.zig:25
4. `transport.recovery.min_rto_us` (1 s) — hard floor on all RTO; very impactful on recovery responsiveness, loss_recovery.zig:26
5. `transport.congestion.bbr.min_rtt_window_us` (10 s) — governs ProbeRTT cadence and fairness, bbr.zig:119
6. `transport.fallback_rtt_us` / `transport.seed_rtt_us` (10 ms) — RTT assumed before first sample; biases initial pacing for every flow, transport_stack.zig:150,227
7. `transport.recovery.packet_threshold` (3) — directly controls loss-detection sensitivity/spurious retransmits, loss_recovery.zig:31
8. `transport.pmtud.max_mtu` (1500) — upper bound on path MTU probing; gates large-datagram throughput, pmtud.zig:27
9. `transport.congestion.bbr.startup_pacing_gain` (2.885) — Startup aggressiveness, bbr.zig:39
10. `transport.congestion.cubic.beta` (0.7) — CUBIC backoff depth; throughput-vs-fairness knob, cc_cubic.zig:4
