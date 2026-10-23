# MK1Ai physical throughput benchmark plan

## Status

**Not executed.** The present Codespaces environment has no qualified physical
high-speed NIC, generator/receiver system, or multi-rack fabric. Its localhost
component probes and repeatability trials are not substitutes. The detailed
current evidence and design background are in
[`THROUGHPUT_DESIGN.md`](./THROUGHPUT_DESIGN.md).

## Definition and acceptance boundary

The system target is 5,000 Tbps of **one-way authenticated application payload
goodput**. Measure each direction separately; do not add transmit and receive
counts for the target. A byte counts only once at the independent receiver after
authentication, AES-256-GCM verification/decryption, required DPI/packet
inspection and AI policy decision, and sequence/hash validation. Record offered
L1 load, L2/L3/L4 receive rates, retransmission, duplicate, and drop counters
separately from goodput.

For the candidate data path, cryptographic verification/decryption occurs before
inspection, AI policy and forwarding acceptance. This is a test boundary to be
confirmed against an implemented deployment. ML-KEM-768 session establishment
and connection churn are measured separately from steady-state packet rate.
Never disable required encryption, authentication, inspection, logging or
isolation to meet a throughput target.

## Environment manifest (required before a run)

Record actual values; do not fill unknowns with assumed equipment:

* SUT CPU, sockets/NUMA, memory model/capacity/bandwidth, GPU/accelerator,
  BIOS, OS/kernel, CPU governor, driver and firmware versions.
* NIC make/model, ports, negotiated rate, PCIe width/generation, RSS/queue
  settings, offloads, MTU, FEC, optics/cable part numbers and link counters.
* ToR/spine models and firmware, port map, link rates, oversubscription,
  bisection capacity, ECMP/hash policy, routing and queue configuration.
* Measured payload-to-wire efficiency by packet profile and directional
  fabric-cut capacity. Do not substitute the illustrative
  `fabric_link_sensitivity` values in
  [`performance-capacity.json`](./performance-capacity.json) for measured
  values or a port map.
* Traffic generator and receiver hardware/software/license, port calibration,
  timestamp resolution, offered-load capability, and independent counter source.
* MK1Ai immutable build/config/model/checkpoint hashes, dependency locks,
  cipher/mode, key rotation, peer authentication, DPI rules, AI enabled/model/
  batch/device, logging level, fsync/retention, and isolation profile.
* UTC synchronization source and measured offset; ambient/inlet temperature,
  power-meter model/calibration, host thermal/frequency state and external load.

Save manifests, sanitized commands/configuration, generator and receiver raw
counters, switch/NIC counters, run IDs and hashes. Do not include secrets or
packet payloads containing personal/sensitive information.

## Metrics and analysis

* One-way verified payload goodput per node and aggregate, in bps and Tbps.
  Report Tx/Rx separately; preserve direction and measurement point.
* Packet rate/pps by Ethernet frame length; state whether reported length is
  wire/L1, L2, or application payload.
* Mean, p95, p99 and max latency, sample count and timestamp error; RTT and
  one-way latency are separate.
* Loss, duplication, reordering, retransmission, authentication/decryption
  failure, corruption, NIC/PCIe queue drop, switch-buffer drop and CRC/FEC.
* CPU overall/per-core/softirq, GPU/accelerator, memory utilization and
  bandwidth, NUMA access, queue depth/occupancy, interrupts, PCIe utilization.
* Power and temperature at SUT and fabric boundaries; disclose facility PUE
  separately and never infer it from rack IT power.
* New connections/s and ML-KEM handshake latency separately from established
  flow throughput. Capture security event/log counts and durable-write behavior.

The receiver's unique validated sequence/payload-byte counter is the goodput
numerator. The denominator is the stable measurement interval, excluding agreed
warm-up and shutdown time. Correlate sender, receiver and fabric counters to
detect generator saturation, missing packets and double counting.

For every relevant fabric cut, calculate effective payload capacity from
measured line-rate capacity and the measured payload-to-wire efficiency for the
same packet/security profile. Preserve directional values. Separately model
the loss of a link, ToR and spine using the actual topology; a one-link N+1
count cannot establish switch- or path-failure tolerance.

For a node-level link failure, test the configured port set with one link
removed and verify the surviving links still meet both the payload target and
the pre-agreed utilization ceiling. A raw post-failure wire-equivalent budget
above target but with utilization exceeding the ceiling is not an 80%-headroom
pass.

For a system-level combined-failure case, remove one node and one link in
separate failure domains, then recompute the bottleneck as the minimum of
measured surviving node goodput and measured directional fabric-cut goodput.
Only execute combined fault injection after each individual failure test has
passed and recovery is verified.

## Staged test sequence

All runs use an approved isolated lab, safe synthetic traffic, and maintained
network isolation. Apply normal security policy; never expose a test generator
or fault-injection setup to production networks.

1. Validate generator/receiver capacity, calibration, synchronization and
   independent counters below target load.
2. Single-node unencrypted diagnostic baseline; retain only as a comparison,
   never as an acceptance result.
3. Single-node authenticated AES-256-GCM, DPI, required logs and isolation;
   separately record ML-KEM setup and established-connection load.
4. Repeat with required AI detection enabled using the reviewed model. AI-off
   is an explicitly labeled diagnostic comparison.
5. Sweep frame sizes 64, 128, 256, 512, 1024, 1518 bytes and approved jumbo
   sizes; flow counts 1, 1k, 10k, 100k+, plus measured connection churn.
6. Test one rack and then multiple racks/spines; balanced, incast/hotspot,
   asymmetric, mixed-size, inter-node, and simultaneous directional profiles.
7. Sustained load for at least 30 minutes per acceptance scenario, five or more
   independent runs after warm-up; report median, range and raw observations.
   For the 5 Pbps objective, increase real node/fabric/generator capacity in
   stages and measure at the receiving application; do not multiply a single
   node result to claim cluster performance.
8. In an isolated approval-controlled window, fail one node, one uplink, one
   ToR, one spine, power feed and cooling domain separately. Measure degraded
   goodput, 80% utilization condition, loss burst, convergence/recovery and
   post-recovery stability.
9. Repeat with operational security settings, logs/retention and key lifecycle
   applied. Archive failed and incomplete trials as evidence, too.

## Acceptance gate

Before testing, owners must set exact packet mix/direction, target semantics,
maximum latency percentiles, permitted loss/reordering, authentication failure
limits, logging durability, 30-minute duration, repetitions, failure scenarios,
and whether the target must persist during each failure. These SLO values are
currently **undefined** and must not be invented by the benchmark operator.

Report 1.6 Tbps/node only when each required protected node profile sustains at
least that much verified one-way payload goodput under its agreed SLO. Report
5 Pbps only when independent receiver counters prove at least 5,000 Tbps of
simultaneous unique end-to-end one-way goodput across the actual multi-node
fabric under the agreed security profile and duration. For N+1 acceptance,
repeat the entire target test after each defined single failure. Port sums,
offered load, arithmetic extrapolation and localhost results do not pass.

Required evidence: environment manifests, topology, exact commands, config and
build/model hashes, raw counter snapshots, receiver validation, time sync,
run logs, plots plus plot source, resource/power traces, all failure records,
and a repeatable calculation of the reported result.
