from __future__ import annotations

import hashlib
import json
import unittest
from fractions import Fraction
from pathlib import Path

from scripts.performance_capacity import (
    DEFAULT_GOODPUT_TBPS,
    build_report,
    capacity_row,
    evaluate_joint_failure_capacity,
    fabric_link_scenario,
    joint_node_fabric_scenario,
    render_json,
)


ROOT = Path(__file__).resolve().parents[1]
CAPACITY_JSON = ROOT / "docs" / "performance-capacity.json"
DESIGN_DOC = ROOT / "docs" / "THROUGHPUT_DESIGN.md"
BASELINE_JSON = ROOT / "docs" / "throughput-component-baseline.json"
AI_COMPARISON_JSON = ROOT / "docs" / "throughput-component-ai-comparison.json"


class PerformanceCapacityTests(unittest.TestCase):
    def test_all_rates_match_exact_expected_counts_and_ceiling_invariants(self):
        expected = {
            "0.4": (12500, 12501, 15625, 15626, 15001),
            "0.8": (6250, 6251, 7813, 7814, 7501),
            "1.2": (4167, 4168, 5209, 5210, 5001),
            "1.6": (3125, 3126, 3907, 3908, 3751),
        }
        target = 5000
        for goodput, counts in expected.items():
            with self.subTest(goodput=goodput):
                row = capacity_row(target, goodput)
                actual = (
                    row["theoretical_minimum_nodes"],
                    row["n_plus_1_nodes"],
                    row["mode_a_80_percent_utilization_nodes"],
                    row["mode_a_80_percent_utilization_plus_n1_nodes"],
                    row["mode_b_120_percent_target_capacity_plus_n1_nodes"],
                )
                self.assertEqual(actual, counts)
                self.assertTrue(all(type(count) is int for count in actual))

                minimum = counts[0]
                rate = Fraction(goodput)
                self.assertLess((minimum - 1) * rate, target)
                self.assertGreaterEqual((counts[1] - 1) * rate, target)
                mode_a_without_n1 = counts[2] - 1
                self.assertLess(mode_a_without_n1 * rate * Fraction(4, 5), target)
                mode_a_after_failure = counts[3] - 1
                self.assertGreaterEqual(
                    mode_a_after_failure * rate * Fraction(4, 5),
                    target,
                )
                mode_b_after_failure = counts[4] - 1
                self.assertGreaterEqual(
                    mode_b_after_failure * rate,
                    Fraction(6, 5) * target,
                )

    def test_mode_a_and_mode_b_are_distinct_and_mode_a_is_adopted(self):
        report = build_report()
        self.assertTrue(report["headroom_modes"]["mode_a"]["adopted"])
        self.assertFalse(report["headroom_modes"]["mode_b"]["adopted"])
        for row in report["scenarios"]:
            self.assertGreaterEqual(
                row["mode_a_80_percent_utilization_plus_n1_nodes"],
                row["mode_b_120_percent_target_capacity_plus_n1_nodes"],
            )
        standard = next(
            row for row in report["scenarios"]
            if row["goodput_tbps_per_node"] == "1.6"
        )
        mode_b_capacity = Fraction(
            standard["mode_b_capacity_after_one_node_failure_tbps"],
        )
        mode_b_utilization = Fraction(report["target"]["value_tbps"]) / mode_b_capacity
        self.assertEqual(mode_b_utilization, Fraction(5, 6))
        self.assertGreater(mode_b_utilization, Fraction(4, 5))
        self.assertEqual(
            Fraction(standard["mode_b_target_utilization_after_failure_percent"]),
            Fraction(250, 3),
        )
        self.assertEqual(
            Fraction(standard["mode_a_usable_capacity_after_failure_at_80_percent_tbps"]),
            Fraction(500096, 100),
        )
        self.assertLessEqual(
            Fraction(standard["mode_a_target_utilization_after_failure_percent"]),
            80,
        )
        self.assertEqual(report["target"]["value_tbps"], "5000")
        self.assertEqual(report["target"]["equivalent_pbps"], "5")
        self.assertEqual(report["units"]["conversion"], "1 Pbps = 1000 Tbps")
        self.assertEqual(report["units"]["conversion_tbps_to_gbps"], "1 Tbps = 1000 Gbps")
        self.assertEqual(report["units"]["conversion_tbps_to_bps"], "1 Tbps = 1000000000000 bps")
        self.assertIn(
            "JSON integers",
            report["units"]["exact_value_representation"],
        )
        self.assertIn("do not add Tx and Rx", report["target"]["scope"])

    def test_required_node_counts_do_not_increase_with_higher_goodput(self):
        rows = [capacity_row(5000, rate) for rate in DEFAULT_GOODPUT_TBPS]
        count_fields = (
            "theoretical_minimum_nodes",
            "n_plus_1_nodes",
            "mode_a_80_percent_utilization_nodes",
            "mode_a_80_percent_utilization_plus_n1_nodes",
            "mode_b_120_percent_target_capacity_plus_n1_nodes",
        )
        for field in count_fields:
            counts = [row[field] for row in rows]
            self.assertEqual(counts, sorted(counts, reverse=True), field)

    def test_invalid_target_and_goodput_are_rejected(self):
        for value in (None, 0, -1, "", "nan", "inf", True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    capacity_row(value, "1.6")
                with self.assertRaises(ValueError):
                    capacity_row("5000", value)

    def test_fabric_link_sensitivity_is_exact_and_preserves_80_percent_after_failure(self):
        expected = {
            ("0.7", "0.4"): (17858, 22322, 22323),
            ("0.7", "0.8"): (8929, 11161, 11162),
            ("0.9", "0.4"): (13889, 17362, 17363),
            ("0.9", "0.8"): (6945, 8681, 8682),
            ("1.0", "0.4"): (12500, 15625, 15626),
            ("1.0", "0.8"): (6250, 7813, 7814),
        }
        for (efficiency, port_rate), counts in expected.items():
            with self.subTest(efficiency=efficiency, port_rate=port_rate):
                row = fabric_link_scenario("5000", port_rate, efficiency)
                actual = (
                    row["theoretical_minimum_links_no_reserve"],
                    row["active_links_required_after_one_link_failure_at_80_percent"],
                    row["installed_links_with_one_link_spare"],
                )
                self.assertEqual(actual, counts)
                effective_rate = Fraction(port_rate) * Fraction(efficiency)
                remaining = (counts[2] - 1) * effective_rate
                self.assertGreaterEqual(remaining * Fraction(4, 5), 5000)
                self.assertLessEqual(
                    Fraction(row["target_utilization_after_one_link_failure_percent"]),
                    80,
                )

    def test_fabric_sensitivity_rejects_efficiency_above_one(self):
        for efficiency in (0, -1, "1.01", None, True):
            with self.subTest(efficiency=efficiency):
                with self.assertRaises(ValueError):
                    fabric_link_scenario("5000", "0.8", efficiency)

    def test_per_node_fabric_sensitivity_preserves_target_after_link_failure(self):
        report = build_report()
        scenarios = report["fabric_link_sensitivity"]["per_node_scenarios"]
        four_800g = next(
            row for row in scenarios
            if row["port_rate_tbps"] == "0.8"
            and row["assumed_payload_efficiency"] == "0.7"
        )
        self.assertEqual(four_800g["installed_links_with_one_link_spare"], 5)
        self.assertEqual(
            four_800g["payload_capacity_after_one_link_failure_tbps"],
            "2.24",
        )
        self.assertEqual(
            four_800g["payload_capacity_after_failure_at_80_percent_tbps"],
            "1.792",
        )
        for row in scenarios:
            with self.subTest(
                port_rate=row["port_rate_tbps"],
                efficiency=row["assumed_payload_efficiency"],
            ):
                self.assertGreaterEqual(
                    Fraction(
                        row["payload_capacity_after_failure_at_80_percent_tbps"],
                    ),
                    Fraction("1.6"),
                )

    def test_joint_node_and_fabric_failure_capacity_is_the_minimum_layer(self):
        row = joint_node_fabric_scenario("5000", "1.6", "0.8", "0.7")
        self.assertEqual(row["node_count_with_80_percent_and_n_plus_1"], 3908)
        self.assertEqual(
            row["node_capacity_after_failure_at_80_percent_tbps"],
            "5000.96",
        )
        self.assertEqual(row["fabric_links_with_80_percent_and_n_plus_1"], 11162)
        self.assertEqual(row["installed_fabric_link_count"], 11162)
        self.assertEqual(row["surviving_fabric_link_count_after_one_failure"], 11161)
        self.assertEqual(
            row["fabric_capacity_after_one_link_failure_tbps"],
            "6250.16",
        )
        self.assertEqual(
            row["fabric_capacity_after_failure_at_80_percent_tbps"],
            "5000.128",
        )
        self.assertEqual(
            row["joint_capacity_after_one_node_and_one_link_failure_at_80_percent_tbps"],
            "5000.128",
        )
        self.assertEqual(row["limiting_layer"], "fabric")
        self.assertTrue(row["meets_target_after_both_failures"])
        for scenario in build_report()["fabric_link_sensitivity"][
            "joint_node_fabric_after_failure"
        ]["scenarios"]:
            with self.subTest(
                node_rate=scenario["node_goodput_tbps_per_node"],
                port_rate=scenario["port_rate_tbps"],
                efficiency=scenario["assumed_payload_efficiency"],
            ):
                self.assertEqual(
                    Fraction(
                        scenario[
                            "joint_capacity_after_one_node_and_one_link_failure_at_80_percent_tbps"
                        ],
                    ),
                    min(
                        Fraction(
                            scenario["node_capacity_after_failure_at_80_percent_tbps"],
                        ),
                        Fraction(
                            scenario["fabric_capacity_after_failure_at_80_percent_tbps"],
                        ),
                    ),
                )

    def test_joint_failure_evaluator_reports_each_capacity_outcome(self):
        cases = (
            {
                "name": "fabric_only_insufficient",
                "args": ("1.6", "1.6", 3, "0.8", "0.7", 2),
                "node_ok": True,
                "fabric_ok": False,
                "limit": "fabric",
                "meets": False,
            },
            {
                "name": "node_only_insufficient",
                "args": ("1.6", "1.6", 2, "0.8", "0.7", 5),
                "node_ok": False,
                "fabric_ok": True,
                "limit": "node",
                "meets": False,
            },
            {
                "name": "both_insufficient",
                "args": ("1.6", "1.6", 2, "0.4", "0.7", 2),
                "node_ok": False,
                "fabric_ok": False,
                "limit": "fabric",
                "meets": False,
            },
            {
                "name": "both_sufficient",
                "args": ("1.6", "1.6", 3, "1.6", "0.7", 5),
                "node_ok": True,
                "fabric_ok": True,
                "limit": "node",
                "meets": True,
            },
        )
        for case in cases:
            with self.subTest(case=case["name"]):
                result = evaluate_joint_failure_capacity(*case["args"])
                self.assertEqual(
                    result["node_meets_target_after_failure"],
                    case["node_ok"],
                )
                self.assertEqual(
                    result["fabric_meets_target_after_failure"],
                    case["fabric_ok"],
                )
                self.assertEqual(result["limiting_layer"], case["limit"])
                self.assertEqual(
                    result["meets_target_after_both_failures"],
                    case["meets"],
                )
                self.assertEqual(
                    Fraction(
                        result[
                            "joint_capacity_after_one_node_and_one_link_failure_at_80_percent_tbps"
                        ],
                    ),
                    min(
                        Fraction(
                            result["node_capacity_after_failure_at_80_percent_tbps"],
                        ),
                        Fraction(
                            result["fabric_capacity_after_failure_at_80_percent_tbps"],
                        ),
                    ),
                )

    def test_joint_failure_evaluator_rejects_invalid_counts(self):
        for node_count, link_count in ((0, 2), (-1, 2), (1.5, 2), (True, 2), (2, 0)):
            with self.subTest(node_count=node_count, link_count=link_count):
                with self.assertRaises(ValueError):
                    evaluate_joint_failure_capacity(
                        "1.6",
                        "1.6",
                        node_count,
                        "0.8",
                        "0.7",
                        link_count,
                    )

    def test_joint_failure_evaluator_reports_a_tied_bottleneck(self):
        result = evaluate_joint_failure_capacity(
            "1.2",
            "1.6",
            2,
            "1.6",
            "1",
            2,
        )
        self.assertEqual(
            result["node_capacity_after_failure_at_80_percent_tbps"],
            "1.28",
        )
        self.assertEqual(
            result["fabric_capacity_after_failure_at_80_percent_tbps"],
            "1.28",
        )
        self.assertEqual(result["limiting_layer"], "both")
        self.assertTrue(result["meets_target_after_both_failures"])

    def test_changed_target_updates_counts_cost_and_power(self):
        standard_report = build_report("5000")
        increased_report = build_report("6000")
        standard = next(
            row for row in standard_report["scenarios"]
            if row["goodput_tbps_per_node"] == "1.6"
        )
        increased = next(
            row for row in increased_report["scenarios"]
            if row["goodput_tbps_per_node"] == "1.6"
        )
        self.assertGreater(
            increased["mode_a_80_percent_utilization_plus_n1_nodes"],
            standard["mode_a_80_percent_utilization_plus_n1_nodes"],
        )
        self.assertGreater(
            increased["mode_a_estimates"]["node_purchase_cost_usd"][0],
            standard["mode_a_estimates"]["node_purchase_cost_usd"][0],
        )
        self.assertGreater(
            increased["mode_a_estimates"]["node_it_power_kw"][0],
            standard["mode_a_estimates"]["node_it_power_kw"][0],
        )
        standard_fabric = standard_report["fabric_link_sensitivity"]["scenarios"][0]
        increased_fabric = increased_report["fabric_link_sensitivity"]["scenarios"][0]
        self.assertGreater(
            increased_fabric["installed_links_with_one_link_spare"],
            standard_fabric["installed_links_with_one_link_spare"],
        )

    def test_generated_json_is_deterministic_and_matches_markdown_table(self):
        generated = build_report()
        actual = json.loads(CAPACITY_JSON.read_text(encoding="utf-8"))
        self.assertEqual(actual, generated)
        self.assertEqual(render_json(generated), render_json(build_report()))
        self.assertEqual(
            actual["evidence_provenance"]["source_sha256"],
            hashlib.sha256(
                (ROOT / "scripts" / "performance_capacity.py").read_bytes(),
            ).hexdigest(),
        )

        lines = DESIGN_DOC.read_text(encoding="utf-8").splitlines()
        for row in actual["scenarios"]:
            expected_line = (
                f"| {row['goodput_tbps_per_node']} Tbps/node "
                f"| {row['theoretical_minimum_nodes']:,} "
                f"| {row['n_plus_1_nodes']:,} "
                f"| {row['mode_a_80_percent_utilization_nodes']:,} "
                f"| {row['mode_a_80_percent_utilization_plus_n1_nodes']:,} "
                f"| {row['mode_b_120_percent_target_capacity_plus_n1_nodes']:,} |"
            )
            self.assertIn(expected_line, lines)
        for row in actual["fabric_link_sensitivity"]["scenarios"]:
            capacity = row["payload_capacity_after_failure_at_80_percent_tbps"]
            whole, separator, fractional = capacity.partition(".")
            capacity_display = f"{int(whole):,}"
            if separator:
                capacity_display += f".{fractional}"
            expected_line = (
                f"| {int(Fraction(row['assumed_payload_efficiency']) * 100)}% "
                f"| {int(Fraction(row['port_rate_tbps']) * 1000)} Gbps "
                f"| {row['effective_payload_tbps_per_link']} Tbps "
                f"| {row['theoretical_minimum_links_no_reserve']:,} "
                f"| {row['installed_links_with_one_link_spare']:,} "
                f"| {capacity_display} Tbps |"
            )
            self.assertIn(expected_line, lines)
        per_node_header = next(
            index for index, line in enumerate(lines)
            if "1.6 Tbps/node" in line and "効率" in line
        )
        per_node_lines = lines[per_node_header + 2:]
        for row in actual["fabric_link_sensitivity"]["per_node_scenarios"]:
            capacity = row["payload_capacity_after_failure_at_80_percent_tbps"]
            whole, separator, fractional = capacity.partition(".")
            capacity_display = f"{int(whole):,}"
            if separator:
                capacity_display += f".{fractional}"
            expected_line = (
                f"| {int(Fraction(row['assumed_payload_efficiency']) * 100)}% "
                f"| {int(Fraction(row['port_rate_tbps']) * 1000)} Gbps "
                f"| {row['effective_payload_tbps_per_link']} Tbps "
                f"| {row['theoretical_minimum_links_no_reserve']:,} "
                f"| {row['installed_links_with_one_link_spare']:,} "
                f"| {capacity_display} Tbps |"
            )
            self.assertIn(expected_line, per_node_lines)
        joint_header = next(
            index for index, line in enumerate(lines)
            if "両故障後のmin容量" in line
        )
        joint_lines = lines[joint_header + 2:]
        for row in actual["fabric_link_sensitivity"][
            "joint_node_fabric_after_failure"
        ]["scenarios"]:
            if row["node_goodput_tbps_per_node"] != "1.6":
                continue
            node_capacity = row["node_capacity_after_failure_at_80_percent_tbps"]
            node_whole, node_separator, node_fractional = node_capacity.partition(".")
            node_capacity_display = f"{int(node_whole):,}"
            if node_separator:
                node_capacity_display += f".{node_fractional}"
            fabric_capacity = row[
                "fabric_capacity_after_failure_at_80_percent_tbps"
            ]
            fabric_whole, fabric_separator, fabric_fractional = fabric_capacity.partition(".")
            fabric_capacity_display = f"{int(fabric_whole):,}"
            if fabric_separator:
                fabric_capacity_display += f".{fabric_fractional}"
            joint_capacity = row[
                "joint_capacity_after_one_node_and_one_link_failure_at_80_percent_tbps"
            ]
            joint_whole, joint_separator, joint_fractional = joint_capacity.partition(".")
            joint_capacity_display = f"{int(joint_whole):,}"
            if joint_separator:
                joint_capacity_display += f".{joint_fractional}"
            expected_line = (
                f"| {int(Fraction(row['assumed_payload_efficiency']) * 100)}% "
                f"| {int(Fraction(row['port_rate_tbps']) * 1000)} Gbps "
                f"| {row['node_count_with_80_percent_and_n_plus_1']:,} "
                f"| {node_capacity_display} Tbps "
                f"| {row['fabric_links_with_80_percent_and_n_plus_1']:,} "
                f"| {fabric_capacity_display} Tbps "
                "| "
                f"{joint_capacity_display} Tbps "
                f"| {row['limiting_layer']} |"
            )
            self.assertIn(expected_line, joint_lines)

    def test_component_report_values_match_design_markdown(self):
        document = DESIGN_DOC.read_text(encoding="utf-8")
        lines = document.splitlines()
        markdown_rows = {}
        for line in lines:
            if line.startswith("| ") and line.count("|") == 5:
                columns = [column.strip() for column in line.strip("|").split("|")]
                if columns[0].isdigit() and columns[1].isdigit():
                    markdown_rows[(int(columns[0]), int(columns[1]))] = columns

        def table_rows(header_fragment: str) -> dict[int, list[str]]:
            header_index = next(
                index
                for index, line in enumerate(lines)
                if header_fragment in line
            )
            rows: dict[int, list[str]] = {}
            for line in lines[header_index + 2:]:
                if not line.startswith("|"):
                    break
                columns = [column.strip() for column in line.strip("|").split("|")]
                if columns and columns[0].isdigit():
                    rows[int(columns[0])] = columns
            return rows

        baseline = json.loads(BASELINE_JSON.read_text(encoding="utf-8"))
        reports = (
            ("AI無効", BASELINE_JSON),
            ("AI診断", AI_COMPARISON_JSON),
        )
        for label, path in reports:
            report = json.loads(path.read_text(encoding="utf-8"))
            for scenario in report["results"]["localhost_tcp_secure_pipeline"]:
                frame_bytes = scenario["frame_bytes"]
                for connection in scenario["connections"]:
                    count = connection["connection_count"]
                    with self.subTest(report=label, frame=frame_bytes, count=count):
                        columns = markdown_rows[(frame_bytes, count)]
                        latency = connection["request_response_rtt"]
                        expected = (
                            f"{connection['request_packets_per_second']:,.0f}; "
                            f"{connection['request_goodput_bps'] / 1_000_000:.3f}; "
                            f"{latency['p95_us'] / 1000:.3f} / "
                            f"{latency['p99_us'] / 1000:.3f}"
                        )
                        self.assertEqual(columns[2 if label == "AI無効" else 3], expected)

        aes_rows = table_rows("AES-GCM encrypt (Gbps / ops/s)")
        for scenario in baseline["results"]["aes_256_gcm"]:
            payload = scenario["payload_bytes"]
            enc = scenario["encrypt"]
            dec = scenario["decrypt_with_tag_verification"]
            expected = [
                str(payload),
                f"{enc['input_gbps']:.3f} / {enc['operations_per_second']:,.0f}",
                f"{enc['latency']['p95_us']:.2f} / {enc['latency']['p99_us']:.2f}",
                f"{dec['input_gbps']:.3f} / {dec['operations_per_second']:,.0f}",
                f"{dec['latency']['p95_us']:.2f} / {dec['latency']['p99_us']:.2f}",
            ]
            self.assertEqual(aes_rows[payload], expected)

        baseline_pipeline_rows = table_rows(
            "Synthetic frame (byte) | Operations/s",
        )
        for scenario in baseline["results"]["synthetic_packet_pipeline_ai_disabled"]:
            frame = scenario["frame_bytes"]
            result = scenario["processing"]
            expected = [
                str(frame),
                f"{result['operations_per_second']:,.0f}",
                f"{result['input_gbps'] * 1000:.2f}",
                f"{result['latency']['p95_us']:.2f} / "
                f"{result['latency']['p99_us']:.2f}",
                f"{result['cpu_percent_of_one_core']:.1f}",
            ]
            self.assertEqual(baseline_pipeline_rows[frame], expected)

        ai_pipeline_rows = table_rows(
            "Synthetic frame (byte) | AI off packet/s",
        )
        comparison = json.loads(AI_COMPARISON_JSON.read_text(encoding="utf-8"))
        for scenario in comparison["results"]["synthetic_packet_pipeline_ai_disabled"]:
            frame = scenario["frame_bytes"]
            off = scenario["processing"]
            on = next(
                entry["processing"]
                for entry in comparison["results"]["synthetic_packet_pipeline_ai_diagnostic"]
                if entry["frame_bytes"] == frame
            )
            expected = [
                str(frame),
                f"{off['operations_per_second']:,.0f}; "
                f"{off['latency']['p95_us']:.2f} / "
                f"{off['latency']['p99_us']:.2f}",
                f"{on['operations_per_second']:,.0f}; "
                f"{on['latency']['p95_us']:.2f} / "
                f"{on['latency']['p99_us']:.2f}",
                f"{off['cpu_percent_of_one_core']:.1f} / "
                f"{on['cpu_percent_of_one_core']:.1f}",
            ]
            self.assertEqual(ai_pipeline_rows[frame], expected)

        log_rows = table_rows("forced inspection log (record/s)")
        for scenario in baseline["results"]["synthetic_forced_full_inspection_log"]:
            frame = scenario["frame_bytes"]
            result = scenario["logging"]
            expected = [
                str(frame),
                f"{result['operations_per_second']:,.0f}",
                f"{result['timed_log_bytes_per_second'] / 2**20:.2f}",
                f"{result['latency']['p95_us']:.2f} / "
                f"{result['latency']['p99_us']:.2f}",
            ]
            self.assertEqual(log_rows[frame], expected)

        kem = baseline["results"]["ml_kem_768_sequential_session_establishment"]
        self.assertIn(
            f"**{kem['operations_per_second']:,.0f}操作/s**",
            document,
        )
        self.assertIn(
            f"**{kem['latency']['p95_us']:.2f}/"
            f"{kem['latency']['p99_us']:.2f} µs**",
            document,
        )

    def test_standard_scenario_estimate_ranges_are_explicit(self):
        row = next(
            row for row in build_report()["scenarios"]
            if row["goodput_tbps_per_node"] == "1.6"
        )
        estimates = row["mode_a_estimates"]
        self.assertEqual(estimates["node_count"], 3908)
        self.assertEqual(
            estimates["node_purchase_cost_usd"],
            [390_800_000, 1_954_000_000],
        )
        self.assertEqual(estimates["node_it_power_kw"], [3908, 11724])
        self.assertEqual(
            estimates["estimated_facility_input_power_mw"],
            [5.15856, 22.8618],
        )
        assumptions = (ROOT / "docs" / "PERFORMANCE_ASSUMPTIONS.md").read_text(
            encoding="utf-8",
        )
        design = DESIGN_DOC.read_text(encoding="utf-8")
        for value in (
            "USD 390.8M–1.954B",
            "3.908–11.724 MW",
            "5.159–22.862 MW",
            "3,751 nodes",
        ):
            self.assertIn(value, assumptions + design)


if __name__ == "__main__":
    unittest.main()
