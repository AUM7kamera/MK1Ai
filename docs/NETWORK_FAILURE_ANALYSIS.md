# MK1Ai aggregate-fabric failure analysis

## Status and model

No production fabric topology, rack layout, link rate, oversubscription ratio,
ECMP policy, or switch model is present in the repository. This is a **qualitative
failure model plus explicitly conditional node arithmetic**, not a simulation or
physical test. Do not infer fabric capacity from the node-count table.

For node goodput `g`, `N` healthy nodes, and independently measured usable
fabric capacity `F` in the same one-way verified-payload unit, a first-order
capacity bound is:

`C_before = min(N * g, F_before)`

After a failure remove all affected node capacity and use the measured
post-convergence fabric capacity:

`C_after = min((N - affected_nodes) * g, F_after)`

For the conditional 80%-headroom calculation, apply the utilization factor
once to each post-failure nameplate:

`C_after_80 = min(0.8 * (N - 1) * g, 0.8 * (L - 1) * r * eta)`

Here `L` is the installed number of equivalent links on one directional cut,
`r` is nominal line rate in Tbps, and `eta` is the assumed payload efficiency.
Subtract exactly one failed node and one failed link-equivalent before applying
80%; do not subtract the failed link again from an already post-failure count.
The code's generic evaluator also checks arbitrary installed counts, so it can
report node-only insufficiency, fabric-only insufficiency, both insufficient,
both sufficient, and a tied bottleneck. The generated planning cases use
headroom-plus-N+1 counts; insufficient cases are unit-test inputs, not claimed
physical configurations.

Only if `C_after >= 5,000 Tbps` and all latency/loss/security SLOs hold can the
target be said to persist. `F_before` and `F_after` are **undefined** until the
physical fabric is specified and tested.

For the standard arithmetic scenario (`g=1.6 Tbps`, Mode A 80%+N+1,
`N=3,908`), node-only nameplate capacity is 6,252.8 Tbps before a node fault
and 6,251.2 Tbps after one node fault. At 5,000 Tbps target this is at most
80% utilization after that fault. Applying the 80% planning ceiling gives
5,000.96 Tbps usable capacity after the fault; target utilization is
approximately 79.9846%. Mode B comparison uses 3,751 nodes; after one node fault
its remaining node nameplate capacity is exactly 6,000 Tbps, implying
83.333…% target utilization. These figures exclude the fabric and are not
measured performance. Exact per-rate values are in
[`performance-capacity.json`](./performance-capacity.json).

To expose fabric scale sensitivity without inventing a topology, the same JSON
also includes conditional one-way link-equivalent counts for 400/800 Gbps links
and assumed payload efficiencies of 70/90/100%. The formula maintains an 80%
utilization ceiling after losing one equivalent link. For example, the assumed
70%-efficient 800 Gbps case yields 11,162 installed link equivalents; after one
link loss, 11,161 links provide 6,250.16 Tbps nameplate payload-equivalent
capacity and 5,000.128 Tbps at the 80% ceiling. This is exact arithmetic over
assumptions, not a switch design or fabric measurement. It excludes topology,
ToR/spine port constraints, ECMP imbalance, common-cause link failures and
forwarding pps limits.

The generated JSON also enumerates paired system-scale node/fabric arithmetic.
At 1.6 Tbps/node with the assumed 70%-efficient 800 Gbps link equivalent,
Mode A requires 3,908 nodes and the system fabric sensitivity requires 11,162
link equivalents. After one node and one link are lost, the 80%-limited node
capacity is 5,000.96 Tbps, the fabric capacity is 5,000.128 Tbps, and the
modeled end-to-end bound is their minimum: 5,000.128 Tbps. These are conditional
assumptions, not an actual cluster result. The per-node link-equivalent table
is separate; its 5 links describe only the hypothetical connection capacity
for one node and must not be mistaken for system fabric links. The paired model
only illustrates the `min(node, fabric)` bottleneck calculation and is not a
simulation.

## Failure cases

| Failure | Capacity before/after | 5 Pbps / 80% status | Likely bottleneck | Required response / additional inputs | Residual risk |
| --- | --- | --- | --- | --- | --- |
| One node | Mode A node-only: 6,252.8 / 6,251.2 Tbps at 1.6 Tbps/node. Actual is `min(node, F)`. | Node arithmetic meets target and <=80% post-fault; fabric/SLO unverified. | Surviving nodes, local links, hot queues. | Validate exact N+1 placement, live node goodput, rebalancing and receiver counters. | One node in a shared ToR may also remove a network path. |
| One rack | `min(Ng,F)` to `min((N-n_r)g,F_after)`; `n_r` nodes/rack undefined. | Unknown; node-level N+1 is insufficient. | Rack power, ToR pair, aggregation uplinks. | Define rack population, dual-homing, independent power/cooling, spare rack capacity; test whole-rack removal. | Correlated node, ToR, cable and power loss. |
| One ToR | Fabric capacity depends on remaining paths; ToR capacities/topology undefined. | Unknown. | ToR ports, dual-homed access, surviving uplink capacity. | Specify ToR redundancy, MLAG/EVPN or routing design as actually selected, convergence and loop/isolation policy; test a ToR failure. | Redundant ToRs can share software/configuration faults. |
| One spine | `F_after` unknown; cannot infer from count of spines alone. | Unknown. | Remaining spine ports and bisection bandwidth. | Document spine count, port map, link speeds, oversubscription and ECMP behavior; remove one spine at full offered load. | ECMP rehash may create transient hotspots/loss. |
| Uplink cut | Capacity is bounded by surviving cut bandwidth and endpoint capacity. | Unknown. | Aggregation cut, LAG member, optical route. | Measure each cut set and alternate path; test single physical and logical links independently. | Shared conduit/optics can defeat path diversity. |
| ECMP/path imbalance | `F_after` depends on per-path load, not aggregate port sum. | Unknown. | A single overloaded hash bucket/link or elephant flow. | Record flow count/distribution and per-link queues; test skewed flow sizes and hash collisions. | Flow hashing may not react quickly to changing demand. |
| One-way link congestion/asymmetry | Forward and reverse `F` differ; only each direction's validated goodput counts. | Unknown independently in each direction. | Congested direction, ACK/control reverse path, asymmetric route. | Report directional goodput and queue/drop/RTT data; exercise asymmetric traffic and path. | Summing Tx+Rx could mask a failing direction. |
| Power feed / PSU domain | `F_after` and online nodes depend on PSU topology and transfer capacity. | Unknown. | Shared PDU, UPS, busway or power conversion capacity. | Specify A/B feed loading at peak and PSU failure mode; test approved isolated failover. | Both feeds may share upstream switchgear. |
| Cooling domain | Thermal throttling can reduce `g`; duration-dependent capacity unknown. | Unknown. | Rack inlet temperature, facility cooling loop, thermal throttling. | Measure inlet/outlet, frequency and sustained goodput; define failure envelope and safe abort. | Facility cooling failures may span multiple racks. |
| Control plane | Data-plane path survival/convergence behavior is implementation-specific. | Unknown. | Routing controller, route reflector, orchestration, state synchronization. | Document controller HA and stale-state behavior; isolate controller failure and restore. | Split-brain, stale ACLs or loss of secure policy distribution. |
| Common firmware/config/software | Common-mode impact could affect every node or switch. | Unknown; arithmetic redundancy offers no protection. | Shared release, key/policy/config push, firmware defect. | Staged rollout, signed artifacts, canary/rollback, config validation and blast-radius limits. | A valid but defective common update can defeat all redundant instances. |

## Required topology inputs before a quantitative fault simulation

* Nodes/rack, rack count, node links/node, and each node's measured directional
  goodput under the secure profile.
* ToR/spine counts, port maps/rates, redundant paths, oversubscription at every
  layer, bisection bandwidth, buffer limits and fabric telemetry access.
* ECMP/hash algorithm, flowlet/teardown behavior, routing convergence, link and
  switch failure detection timers, packet reordering tolerance.
* Independent A/B power paths and cooling domains; PSU, UPS and generator
  capacity/failure behavior.
* Control-plane components, software/firmware versions, configuration
  distribution and rollback boundaries.
* SLO for target during failure: whether 5 Pbps and <=80% utilization must both
  persist, plus allowed loss burst, latency and recovery time.

Run faults only on an approved isolated test fabric. Preserve security isolation,
authentication, encryption, inspection, logging and authorization. Fault-test
the smallest failure domain first, then compound tests only after individual
recovery has been validated.
