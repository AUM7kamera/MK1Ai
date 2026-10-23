#!/usr/bin/env python3
"""Generate exact capacity arithmetic for the MK1Ai throughput design."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from fractions import Fraction
from pathlib import Path
from typing import Any


DEFAULT_TARGET_TBPS = "5000"
DEFAULT_PER_NODE_TARGET_TBPS = "1.6"
DEFAULT_GOODPUT_TBPS = ("0.4", "0.8", "1.2", "1.6")
NODE_PRICE_USD = (100_000, 500_000)
NODE_POWER_KW = ("1", "3")
NETWORK_EQUIPMENT_IT_POWER_FACTOR = ("1.1", "1.3")
FACILITY_PUE = ("1.2", "1.5")
FABRIC_PAYLOAD_EFFICIENCIES = ("0.7", "0.9", "1.0")
FABRIC_PORT_RATES_TBPS = ("0.4", "0.8")
HEADROOM = Fraction(4, 5)
TARGET_PLUS_20_PERCENT = Fraction(6, 5)


def positive_fraction(value: object, name: str) -> Fraction:
    if value is None or isinstance(value, bool):
        raise ValueError(f"{name} must be a positive finite number")
    try:
        result = value if isinstance(value, Fraction) else Fraction(str(value))
    except (ValueError, ZeroDivisionError, TypeError) as exc:
        raise ValueError(f"{name} must be a positive finite number") from exc
    if result <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return result


def ceil_fraction(value: Fraction) -> int:
    if value <= 0:
        raise ValueError("cannot ceil a non-positive capacity ratio")
    return (value.numerator + value.denominator - 1) // value.denominator


def decimal_text(value: Fraction) -> str:
    denominator = value.denominator
    twos = 0
    fives = 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1:
        return f"{value.numerator}/{value.denominator}"
    places = max(twos, fives)
    scaled = value.numerator * (10**places) // value.denominator
    sign = "-" if scaled < 0 else ""
    digits = str(abs(scaled)).rjust(places + 1, "0")
    if places == 0:
        return sign + digits
    whole, fractional = digits[:-places], digits[-places:]
    fractional = fractional.rstrip("0")
    return sign + whole + (f".{fractional}" if fractional else "")


def estimate_for_nodes(node_count: int) -> dict[str, Any]:
    node_it_power_kw = [
        node_count * int(Fraction(power))
        for power in NODE_POWER_KW
    ]
    facility_power_mw = [
        Fraction(node_count)
        * Fraction(NODE_POWER_KW[0])
        * Fraction(NETWORK_EQUIPMENT_IT_POWER_FACTOR[0])
        * Fraction(FACILITY_PUE[0])
        / 1000,
        Fraction(node_count)
        * Fraction(NODE_POWER_KW[1])
        * Fraction(NETWORK_EQUIPMENT_IT_POWER_FACTOR[1])
        * Fraction(FACILITY_PUE[1])
        / 1000,
    ]
    return {
        "node_count": node_count,
        "node_purchase_cost_usd": [
            node_count * NODE_PRICE_USD[0],
            node_count * NODE_PRICE_USD[1],
        ],
        "node_it_power_kw": node_it_power_kw,
        "estimated_facility_input_power_mw": [
            round(float(value), 6) for value in facility_power_mw
        ],
        "scope": "node purchase and modeled electrical load only; not a system quote or measurement",
    }


def fabric_link_scenario(
    target_tbps: object,
    port_rate_tbps: object,
    payload_efficiency: object,
) -> dict[str, Any]:
    target = positive_fraction(target_tbps, "target_tbps")
    port_rate = positive_fraction(port_rate_tbps, "port_rate_tbps")
    efficiency = positive_fraction(payload_efficiency, "payload_efficiency")
    if efficiency > 1:
        raise ValueError("payload_efficiency must not exceed 1")
    payload_capacity_per_link = port_rate * efficiency
    theoretical_minimum_links = ceil_fraction(target / payload_capacity_per_link)
    active_links_after_one_link_failure = ceil_fraction(
        target / (payload_capacity_per_link * HEADROOM),
    )
    installed_links = active_links_after_one_link_failure + 1
    capacity_before_failure = installed_links * payload_capacity_per_link
    capacity_after_failure = (
        installed_links - 1
    ) * payload_capacity_per_link
    return {
        "port_rate_tbps": decimal_text(port_rate),
        "assumed_payload_efficiency": decimal_text(efficiency),
        "effective_payload_tbps_per_link": decimal_text(payload_capacity_per_link),
        "theoretical_minimum_links_no_reserve": theoretical_minimum_links,
        "active_links_required_after_one_link_failure_at_80_percent": (
            active_links_after_one_link_failure
        ),
        "installed_links_with_one_link_spare": installed_links,
        "payload_capacity_before_one_link_failure_tbps": decimal_text(
            capacity_before_failure,
        ),
        "payload_capacity_after_one_link_failure_tbps": decimal_text(
            capacity_after_failure,
        ),
        "payload_capacity_after_failure_at_80_percent_tbps": decimal_text(
            capacity_after_failure * HEADROOM,
        ),
        "target_utilization_after_one_link_failure_percent": decimal_text(
            target / capacity_after_failure * 100,
        ),
    }


def positive_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def evaluate_joint_failure_capacity(
    target_tbps: object,
    node_goodput_tbps: object,
    installed_node_count: object,
    port_rate_tbps: object,
    payload_efficiency: object,
    installed_fabric_link_count: object,
) -> dict[str, Any]:
    target = positive_fraction(target_tbps, "target_tbps")
    node_goodput = positive_fraction(node_goodput_tbps, "node_goodput_tbps")
    port_rate = positive_fraction(port_rate_tbps, "port_rate_tbps")
    efficiency = positive_fraction(payload_efficiency, "payload_efficiency")
    if efficiency > 1:
        raise ValueError("payload_efficiency must not exceed 1")
    node_count = positive_integer(installed_node_count, "installed_node_count")
    link_count = positive_integer(
        installed_fabric_link_count,
        "installed_fabric_link_count",
    )
    surviving_nodes = max(node_count - 1, 0)
    surviving_links = max(link_count - 1, 0)
    node_capacity = surviving_nodes * node_goodput
    fabric_capacity = surviving_links * port_rate * efficiency
    node_usable_capacity = node_capacity * HEADROOM
    fabric_usable_capacity = fabric_capacity * HEADROOM
    joint_capacity = min(node_usable_capacity, fabric_usable_capacity)
    if node_usable_capacity == fabric_usable_capacity:
        limiting_layer = "both"
    elif node_usable_capacity < fabric_usable_capacity:
        limiting_layer = "node"
    else:
        limiting_layer = "fabric"
    return {
        "target_tbps": decimal_text(target),
        "installed_node_count": node_count,
        "surviving_node_count_after_one_failure": surviving_nodes,
        "node_goodput_tbps_per_node": decimal_text(node_goodput),
        "node_capacity_after_one_node_failure_tbps": decimal_text(node_capacity),
        "node_capacity_after_failure_at_80_percent_tbps": decimal_text(
            node_usable_capacity,
        ),
        "port_rate_tbps": decimal_text(port_rate),
        "assumed_payload_efficiency": decimal_text(efficiency),
        "installed_fabric_link_count": link_count,
        "surviving_fabric_link_count_after_one_failure": surviving_links,
        "fabric_capacity_after_one_link_failure_tbps": decimal_text(fabric_capacity),
        "fabric_capacity_after_failure_at_80_percent_tbps": decimal_text(
            fabric_usable_capacity,
        ),
        "joint_capacity_after_one_node_and_one_link_failure_at_80_percent_tbps": (
            decimal_text(joint_capacity)
        ),
        "node_meets_target_after_failure": node_usable_capacity >= target,
        "fabric_meets_target_after_failure": fabric_usable_capacity >= target,
        "limiting_layer": limiting_layer,
        "meets_target_after_both_failures": joint_capacity >= target,
    }


def joint_node_fabric_scenario(
    target_tbps: object,
    node_goodput_tbps: object,
    port_rate_tbps: object,
    payload_efficiency: object,
) -> dict[str, Any]:
    target = positive_fraction(target_tbps, "target_tbps")
    node_goodput = positive_fraction(node_goodput_tbps, "node_goodput_tbps")
    node_count = ceil_fraction(target / (node_goodput * HEADROOM)) + 1
    link_scenario = fabric_link_scenario(
        target,
        port_rate_tbps,
        payload_efficiency,
    )
    result = evaluate_joint_failure_capacity(
        target,
        node_goodput,
        node_count,
        port_rate_tbps,
        payload_efficiency,
        link_scenario["installed_links_with_one_link_spare"],
    )
    return {
        "node_count_with_80_percent_and_n_plus_1": node_count,
        "fabric_links_with_80_percent_and_n_plus_1": (
            link_scenario["installed_links_with_one_link_spare"]
        ),
        **result,
    }


def capacity_row(target_tbps: object, goodput_tbps: object) -> dict[str, Any]:
    target = positive_fraction(target_tbps, "target_tbps")
    goodput = positive_fraction(goodput_tbps, "goodput_tbps")
    minimum = ceil_fraction(target / goodput)
    utilization_80 = ceil_fraction(target / (HEADROOM * goodput))
    target_plus_20_percent = ceil_fraction(
        TARGET_PLUS_20_PERCENT * target / goodput,
    )
    mode_a_n1 = utilization_80 + 1
    mode_b_n1 = target_plus_20_percent + 1
    mode_a_capacity_before_failure = goodput * mode_a_n1
    mode_a_capacity_after_failure = goodput * (mode_a_n1 - 1)
    mode_b_capacity_before_failure = goodput * mode_b_n1
    mode_b_capacity_after_failure = goodput * (mode_b_n1 - 1)
    return {
        "goodput_tbps_per_node": decimal_text(goodput),
        "theoretical_minimum_nodes": minimum,
        "n_plus_1_nodes": minimum + 1,
        "mode_a_80_percent_utilization_nodes": utilization_80,
        "mode_a_80_percent_utilization_plus_n1_nodes": mode_a_n1,
        "mode_b_120_percent_target_capacity_nodes": target_plus_20_percent,
        "mode_b_120_percent_target_capacity_plus_n1_nodes": mode_b_n1,
        "mode_a_capacity_before_one_node_failure_tbps": decimal_text(
            mode_a_capacity_before_failure,
        ),
        "mode_a_capacity_after_one_node_failure_tbps": decimal_text(
            mode_a_capacity_after_failure,
        ),
        "mode_a_usable_capacity_after_failure_at_80_percent_tbps": decimal_text(
            mode_a_capacity_after_failure * HEADROOM,
        ),
        "mode_a_target_utilization_after_failure_percent": decimal_text(
            target / mode_a_capacity_after_failure * 100,
        ),
        "mode_b_capacity_before_one_node_failure_tbps": decimal_text(
            mode_b_capacity_before_failure,
        ),
        "mode_b_capacity_after_one_node_failure_tbps": decimal_text(
            mode_b_capacity_after_failure,
        ),
        "mode_b_target_utilization_after_failure_percent": decimal_text(
            target / mode_b_capacity_after_failure * 100,
        ),
        "mode_a_estimates": estimate_for_nodes(mode_a_n1),
        "mode_b_estimates": estimate_for_nodes(mode_b_n1),
    }


def build_report(
    target_tbps: object = DEFAULT_TARGET_TBPS,
    goodput_rates_tbps: tuple[object, ...] = DEFAULT_GOODPUT_TBPS,
) -> dict[str, Any]:
    target = positive_fraction(target_tbps, "target_tbps")
    if not goodput_rates_tbps:
        raise ValueError("at least one goodput rate is required")
    rows = [capacity_row(target, rate) for rate in goodput_rates_tbps]
    fabric_scenarios = [
        {
            "target_tbps": decimal_text(target),
            **fabric_link_scenario(target, port_rate, efficiency),
        }
        for efficiency in FABRIC_PAYLOAD_EFFICIENCIES
        for port_rate in FABRIC_PORT_RATES_TBPS
    ]
    per_node_fabric_scenarios = [
        {
            "target_tbps": DEFAULT_PER_NODE_TARGET_TBPS,
            **fabric_link_scenario(
                DEFAULT_PER_NODE_TARGET_TBPS,
                port_rate,
                efficiency,
            ),
        }
        for efficiency in FABRIC_PAYLOAD_EFFICIENCIES
        for port_rate in FABRIC_PORT_RATES_TBPS
    ]
    joint_failure_scenarios = [
        joint_node_fabric_scenario(
            target,
            node_goodput,
            port_rate,
            efficiency,
        )
        for node_goodput in goodput_rates_tbps
        for efficiency in FABRIC_PAYLOAD_EFFICIENCIES
        for port_rate in FABRIC_PORT_RATES_TBPS
    ]
    return {
        "schema_version": 1,
        "classification": "exact arithmetic scenarios; not measured performance",
        "evidence_provenance": {
            "generator": "scripts/performance_capacity.py",
            "source_sha256": hashlib.sha256(
                Path(__file__).read_bytes(),
            ).hexdigest(),
        },
        "units": {
            "system_target": "Tbps, one direction",
            "per_node_goodput": "Tbps, authenticated application payload in one direction",
            "conversion": "1 Pbps = 1000 Tbps",
            "conversion_tbps_to_gbps": "1 Tbps = 1000 Gbps",
            "conversion_tbps_to_bps": "1 Tbps = 1000000000000 bps",
            "exact_value_representation": (
                "Counts are JSON integers and flags are JSON booleans; exact "
                "rates, capacities and percentages are decimal strings, with "
                "non-terminating rational values encoded as numerator/denominator."
            ),
        },
        "target": {
            "value_tbps": decimal_text(target),
            "equivalent_pbps": decimal_text(target / 1000),
            "scope": "one-way end-to-end authenticated application payload; do not add Tx and Rx",
        },
        "fabric_link_sensitivity": {
            "classification": (
                "conditional arithmetic only; link rates and payload efficiencies "
                "are illustrative inputs, not selected hardware or measurements"
            ),
            "units": {
                "port_rate": "Tbps per one-way link, nominal line rate",
                "payload_efficiency": "dimensionless fraction from 0 to 1",
                "payload_capacity": "Tbps of one-way payload-equivalent capacity",
                "installed_link_count": "integer equivalent links across one directional cut",
            },
            "formula": (
                "installed_links = ceil(T / (payload_efficiency * port_rate * 0.8)) + 1"
            ),
            "scope": (
                "one-way fabric-cut link equivalents; one spare link after a single "
                "link failure; excludes switch ports, topology, node NICs, and common-mode failures"
            ),
            "not_a_topology_design": True,
            "per_node_target_tbps": DEFAULT_PER_NODE_TARGET_TBPS,
            "per_node_scenarios": per_node_fabric_scenarios,
            "scenarios": fabric_scenarios,
            "joint_node_fabric_after_failure": {
                "classification": (
                    "conditional min(node capacity, fabric capacity) arithmetic; "
                    "assumes one node and one equivalent link fail simultaneously"
                ),
                "formula": (
                    "node_usable=0.8*max(installed_nodes-1,0)*g; "
                    "fabric_usable=0.8*max(installed_links-1,0)*port_rate*efficiency; "
                    "joint=min(node_usable,fabric_usable)"
                ),
                "headroom_application": (
                    "Apply 80% separately to each layer's nameplate capacity after "
                    "subtracting exactly one failed node or link-equivalent."
                ),
                "failure_scope": (
                    "One node plus one fabric-cut equivalent link fail at the same time; "
                    "the model does not assert independent physical failure domains."
                ),
                "scenarios": joint_failure_scenarios,
            },
        },
        "goodput_definition": (
            "Unique application payload bytes accepted at the receiving application after "
            "required authentication, AEAD verification/decryption, inspection and policy "
            "decision, divided by measurement interval. Excludes headers, retransmissions, "
            "duplicates, dropped or unauthenticated bytes."
        ),
        "headroom_modes": {
            "mode_a": {
                "name": "installed capacity utilization at most 80 percent",
                "normal_nodes": "ceil(T / (0.8 * g))",
                "n_plus_1_nodes": "ceil(T / (0.8 * g)) + 1",
                "failure_state": "after one node loss, distribute target across remaining capacity at no more than 80 percent utilization",
                "capacity_relation": "remaining installed capacity is at least 1.25 * T; 20 percent of installed capacity is unused (at least 25 percent excess relative to T)",
                "adopted": True,
            },
            "mode_b": {
                "name": "target capacity plus 20 percent, then one spare node",
                "n_plus_1_nodes": "ceil((1.2 * T) / g) + 1",
                "failure_state": "after one node loss, remaining nameplate capacity is at least 1.2 * T; target utilization can be as high as 83.333 percent",
                "capacity_relation": "20 percent additional capacity relative to target is not the same as 20 percent unused installed capacity",
                "adopted": False,
            },
        },
        "cost_and_power_assumptions": {
            "status": "assumptions only; no vendor quote or facility measurement",
            "node_unit_price_usd": list(NODE_PRICE_USD),
            "node_power_kw": [int(Fraction(value)) for value in NODE_POWER_KW],
            "network_equipment_it_power_factor": [
                float(Fraction(value))
                for value in NETWORK_EQUIPMENT_IT_POWER_FACTOR
            ],
            "facility_pue": [float(Fraction(value)) for value in FACILITY_PUE],
            "facility_power_formula": (
                "node_count * node_kW * network_equipment_factor * PUE / 1000 = MW"
            ),
            "network_equipment_factor_note": (
                "coarse 1.1-1.3 multiplier covering unspecified network/optical IT load; "
                "not a separate equipment inventory or quote"
            ),
            "included_cost": "compute nodes only",
            "excluded_costs": [
                "ToR switches",
                "spine switches",
                "NICs",
                "optical transceivers and cables",
                "racks and power distribution",
                "cooling plant",
                "redundant power systems",
                "maintenance and spare parts",
                "licenses, facilities, staffing, and test equipment",
            ],
            "power_conditions_not_separately_modeled": [
                "idle and peak workload",
                "redundant PSU conversion losses",
                "failure and maintenance states",
                "cooling load beyond the assumed PUE",
            ],
        },
        "scenarios": rows,
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target-tbps",
        default=DEFAULT_TARGET_TBPS,
        help="positive system target in one-way Tbps (default: 5000)",
    )
    parser.add_argument(
        "--goodput-tbps",
        nargs="+",
        default=list(DEFAULT_GOODPUT_TBPS),
        help="positive per-node authenticated payload goodput rates in Tbps",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/performance-capacity.json"),
        help="output JSON path",
    )
    args = parser.parse_args()
    try:
        report = build_report(args.target_tbps, tuple(args.goodput_tbps))
    except ValueError as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rendered = render_json(report)
    args.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
