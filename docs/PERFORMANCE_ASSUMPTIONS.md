# MK1Ai throughput capacity assumptions

## Status and measurement boundary

All values here are design assumptions or exact arithmetic scenarios, not measured
MK1Ai performance, a vendor quote, or a facility design. The governing evidence
and calculation output are [`THROUGHPUT_DESIGN.md`](./THROUGHPUT_DESIGN.md) and
[`performance-capacity.json`](./performance-capacity.json). Rebuild the JSON with:

```sh
python3 scripts/performance_capacity.py --output docs/performance-capacity.json
```

The 5 Pbps system objective is interpreted as **5,000 Tbps in one direction**.
Report transmit offered load, receive wire rate, verified application goodput,
and reverse-direction goodput separately. Do not add Tx and Rx values to claim
the one-direction objective.

Goodput is unique application payload bytes accepted by the receiving application
after required authentication, AES-GCM tag verification/decryption, inspection,
AI policy decision, and sequence/hash validation, divided by elapsed measurement
time. Headers, encryption overhead, retransmissions, duplicates, dropped data,
and unauthenticated payload do not count. This is a future acceptance boundary;
the current repository does not contain a verified high-speed path implementing
that whole sequence.

For the candidate design, encryption/authentication precedes packet acceptance;
inspection and required AI policy run on authenticated plaintext/metadata before
forwarding or acceptance. AI-disabled runs are diagnostic comparisons only, not
a security-equivalent acceptance profile. The actual placement must be fixed and
reviewed against the deployed trust boundary before hardware testing.

## Capacity and redundancy definitions

Let `T = 5,000 Tbps` and measured per-node one-way goodput be `g Tbps/node`.
All ratios are calculated from decimal strings as exact rational numbers; ceiling
is integer arithmetic. The current evaluated rates are 0.4, 0.8, 1.2, and
1.6 Tbps/node.

In the generated JSON, counts are JSON integers, state flags are booleans, and
exact rates/capacities/percentages are strings so decimal inputs are not rounded
through binary floating point. Non-terminating exact rational percentages use
`numerator/denominator` strings. The explicitly estimated facility-power
scenario remains a rounded numeric range and is labeled as an assumption.

| Scenario | Formula | Meaning |
| --- | --- | --- |
| Theoretical minimum | `ceil(T/g)` | No reserve and no failure allowance. |
| Bare N+1 | `ceil(T/g)+1` | One node fails; remaining theoretical capacity still reaches T. |
| Headroom A | `ceil(T/(0.8*g))` | Normal target uses at most 80% of installed capacity. |
| Headroom A + N+1 | `ceil(T/(0.8*g))+1` | Adopted design: after one node loss, target remains at or below 80% of remaining installed capacity. |
| Headroom B + N+1 | `ceil((1.2*T)/g)+1` | Comparison only: after one node loss, nameplate capacity is at least 120% of T; target utilization may reach 83.333%. |

Mode A requires at least `1/0.8 = 1.25*T` remaining capacity after the node
failure: at least 25% excess relative to target, with 20% of that installed
capacity unused. Mode B adds capacity equal to 20% of target, which is not 20%
unused installed capacity. Mode A is adopted; Mode B is not.

The generated `fabric_link_sensitivity` JSON is a separate conditional
lower-bound model. It varies assumed payload-to-wire efficiency (70%, 90%,
100%) and nominal 400/800 Gbps links, then calculates a one-link-spare cut
capacity with at most 80% utilization after that link fault. These efficiency
values are illustrative only; they are neither measured nor a chosen hardware
profile. The link-equivalent counts do not specify switch port counts or
oversubscription and cannot establish end-to-end capacity.

The same model includes a 1.6 Tbps/node scenario. Under the illustrative 70%
efficiency and 800 Gbps link assumptions, four links leave 1.68 Tbps
payload-equivalent nameplate after one link loss, but only 1.344 Tbps at the
80% utilization ceiling. Five installed links are needed in this simplified
case to leave 1.792 Tbps of 80%-limited capacity. This demonstrates why
surviving nominal line capacity is not itself proof that the headroom target is
met; it is not a recommendation or measured hardware configuration.

A separate paired scenario applies `min(remaining node capacity, remaining
fabric-cut capacity)` after one node and one fabric-link-equivalent failure.
For the 5,000 Tbps target, 1.6 Tbps/node, 70%-efficient 800 Gbps links, the
conditional model gives 5,000.96 Tbps node capacity and 5,000.128 Tbps fabric
capacity at the 80% ceiling, so the modeled bottleneck is the fabric. The
system-scale link count is 11,162; it is distinct from the 5 link-equivalents
in the single-node sensitivity example. Neither is a topology recommendation
or a measured result.

The generated JSON records node-nameplate capacity before and after one node
failure, Mode A's usable 80%-limited capacity after failure, and target
utilization after failure for each mode. At 1.6 Tbps/node this is 6,252.8 Tbps
Mode A nameplate before failure, 6,251.2 Tbps after failure, 5,000.96 Tbps
usable at the 80% ceiling, and 79.9846% target utilization. Mode B has 6,000
Tbps remaining nameplate capacity and 83.333…% target utilization. The
headroom values describe node arithmetic only; fabric capacity remains a
separate `min(node capacity, measured fabric capacity)` constraint.

The prior design draft's 3,907-node reserve calculation at 1.6 Tbps/node used
`ceil(5000 / (0.8 * 1.6))`, so it already represented Mode A. This update keeps
that existing interpretation and adds Mode B as a separately labeled
comparison; it does not replace Mode A with a different reserve policy.

## Cost and energy assumptions

No source quote or power measurement exists for the chosen node or fabric. These
are transparent placeholders only:

| Input | Assumed range | Basis |
| --- | ---: | --- |
| Per-node purchase price | USD 100,000–500,000 | Planning placeholder, compute node only. |
| Per-node IT power | 1–3 kW | Planning placeholder, no SKU or measured load. |
| Network/optical equipment power multiplier | 1.1–1.3 x node IT load | Coarse aggregate placeholder; not a switch/NIC inventory. |
| Facility PUE | 1.2–1.5 | Scenario range only; no facility source or measurement. |

For the adopted `g = 1.6 Tbps/node`, Mode A + N+1 is 3,908 nodes:

* Node purchase estimate: `3,908 * USD 100k–500k` = **USD 390.8M–1.954B**.
  This is not total system procurement cost.
* Node IT load: `3,908 * 1–3 kW` = **3.908–11.724 MW**.
* Coarse network/optical IT allowance implied by the multiplier:
  `node IT load * (factor - 1)` = **0.391–3.517 MW**.
* Facility input scenario:
  `node_count * node_kW * equipment_factor * PUE / 1000` =
  **5.159–22.862 MW**. It is not a cooling-system design or measured peak.

Mode B + N+1 uses 3,751 nodes at 1.6 Tbps/node, for estimated node-only
purchase of USD 375.1M–1.8755B and node IT load of 3.751–11.253 MW. It does not
inherit Mode A's 80% utilization guarantee.

ToR, spine, NIC, transceiver, cable, rack, PDU/UPS, cooling plant, redundancy
equipment, maintenance, spares, software licenses, facility construction,
staffing, and test generators are excluded because there is no bill of
materials or quote. Idle/peak power, PSU losses, failure/maintenance power,
cooling load, and facility-specific PUE are not separately measured. Treat the
JSON's facility number as a sensitivity range, not a procurement or capacity
commitment.

## Fabric assumptions not yet defined

No physical topology has been selected. Node-per-rack, ToR and spine port counts,
port rate, oversubscription, bisection bandwidth, ECMP/hash behavior, buffering,
optical path diversity, failure domains, and converged throughput are unset.
Therefore node arithmetic is not an end-to-end aggregate-capacity prediction.
See [`NETWORK_FAILURE_ANALYSIS.md`](./NETWORK_FAILURE_ANALYSIS.md) for required
failure-model inputs and consequences.
