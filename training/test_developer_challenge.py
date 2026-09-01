from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from training import developer_challenge as challenge
from training import internal_holdout as shared


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "experiments/client-detector-developer-challenge-v1/protocol.json"
BANK = ROOT / "experiments/client-detector-developer-challenge-v1/scenario-bank.json"


class DeveloperChallengeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = shared.load_json(PROTOCOL)
        self.bank = shared.load_json(BANK)
        challenge.validate_inputs(self.protocol, self.bank)

    def test_matrix_has_240_complete_counterfactual_pairs(self) -> None:
        cases, gold = challenge.build_rows(self.protocol, self.bank)
        self.assertEqual(len(cases), 480)
        self.assertEqual(len(gold), 480)
        pairs = {}
        for case in cases:
            pairs.setdefault(case["pair_id"], {})[case["target_polarity"]] = case
        self.assertEqual(len(pairs), 240)
        self.assertTrue(all(set(members) == {"risky", "safe"} for members in pairs.values()))
        for members in pairs.values():
            target = members["risky"]["messages"][1]["text"]
            self.assertIn(target, members["safe"]["messages"][1]["text"])

    def test_build_freezes_inputs_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "challenge"
            self.assertEqual(
                challenge.cmd_build(
                    SimpleNamespace(protocol=PROTOCOL, scenario_bank=BANK, output_dir=output)
                ),
                0,
            )
            manifest = shared.load_json(output / "manifest.json")
            self.assertEqual(manifest["status"], "frozen_before_first_run")
            self.assertFalse(manifest["release_eligible"])
            self.assertEqual(manifest["counts"]["pairs"], 240)
            self.assertEqual(manifest["counts"]["cases"], 480)

    def test_always_safe_probe_is_a_diagnostic_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "challenge"
            challenge.cmd_build(
                SimpleNamespace(protocol=PROTOCOL, scenario_bank=BANK, output_dir=output)
            )
            fake_probe = root / "always-safe-probe"
            fake_probe.write_text(
                """#!/usr/bin/env python3
import json
import sys
families = ("bullying", "grooming", "explicit", "threat", "self_harm", "spam", "scam", "phishing", "manipulation", "nsfw", "hate_speech", "doxxing", "pii_leakage", "propaganda", "opsec_violation", "psyops", "military_social_eng", "coordinate_leak")
for line in sys.stdin:
    case = json.loads(line)
    turn = {"backend": "rules_context", "primary": "none", "primary_score": 0.0, "action": "allow", "scores": {family: 0.0 for family in families}, "reason_codes": [], "analysis_time_us": 1}
    print(json.dumps({"id": case["id"], "turns": [dict(turn, turn_index=index) for index, _ in enumerate(case["messages"])]}))
""",
                encoding="utf-8",
            )
            fake_probe.chmod(0o700)
            result = root / "result.json"
            self.assertEqual(
                challenge.cmd_evaluate(
                    SimpleNamespace(
                        manifest=output / "manifest.json",
                        protocol=PROTOCOL,
                        scenario_bank=BANK,
                        cases=output / "cases.jsonl",
                        gold=output / "gold.jsonl",
                        probe=fake_probe,
                        output=result,
                    )
                ),
                1,
            )
            report = shared.load_json(result)
            self.assertEqual(report["status"], "diagnostic_fail")
            self.assertFalse(report["release_eligible"])
            self.assertEqual(report["overall"]["expected_family_recall"]["numerator"], 0)
            self.assertEqual(report["overall"]["safe_specificity"]["numerator"], 240)
            self.assertEqual(
                report["timing"]["detector_reported_turn_latency_us"]["count"], 960
            )

    def test_probe_timing_is_aggregated_without_case_content(self) -> None:
        outputs = {
            "case-a": {
                "analyzer_init_us": 100,
                "runtime_reset_us": 3,
                "probe_wall_us": 120,
                "turns": [{"analysis_time_us": 7}, {"analysis_time_us": 11}],
            },
            "case-b": {
                "analyzer_init_us": None,
                "runtime_reset_us": 5,
                "probe_wall_us": 23,
                "turns": [{"analysis_time_us": 13}],
            },
        }
        self.assertEqual(
            challenge.aggregate_probe_timing(outputs, 211),
            {
                "analyzer_init_us": {
                    "count": 1,
                    "total": 100,
                    "median": 100,
                    "p95": 100,
                    "maximum": 100,
                },
                "runtime_reset_us": {
                    "count": 2,
                    "total": 8,
                    "median": 5,
                    "p95": 5,
                    "maximum": 5,
                },
                "probe_wall_us": 211,
                "probe_reported_conversation_wall_us": {
                    "count": 2,
                    "total": 143,
                    "median": 120,
                    "p95": 120,
                    "maximum": 120,
                },
                "detector_reported_turn_latency_us": {
                    "count": 3,
                    "total": 31,
                    "median": 11,
                    "p95": 13,
                    "maximum": 13,
                },
            },
        )

    def test_legacy_probe_output_keeps_timing_addition_backward_compatible(self) -> None:
        outputs = {"legacy": {"turns": [{"analysis_time_us": 17}]}}
        self.assertEqual(
            challenge.aggregate_probe_timing(outputs, 29),
            {
                "analyzer_init_us": {
                    "count": 0,
                    "total": 0,
                    "median": 0,
                    "p95": 0,
                    "maximum": 0,
                },
                "runtime_reset_us": {
                    "count": 0,
                    "total": 0,
                    "median": 0,
                    "p95": 0,
                    "maximum": 0,
                },
                "probe_wall_us": 29,
                "probe_reported_conversation_wall_us": {
                    "count": 0,
                    "total": 0,
                    "median": 0,
                    "p95": 0,
                    "maximum": 0,
                },
                "detector_reported_turn_latency_us": {
                    "count": 1,
                    "total": 17,
                    "median": 17,
                    "p95": 17,
                    "maximum": 17,
                },
            },
        )


if __name__ == "__main__":
    unittest.main()
