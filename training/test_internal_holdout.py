from __future__ import annotations

import copy
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

from training import internal_holdout as holdout


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = (
    ROOT / "experiments/client-detector-internal-holdout-v1/protocol.json"
)


class InternalHoldoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = holdout.load_json(PROTOCOL_PATH)
        holdout.validate_protocol(self.protocol)
        self.assignments = holdout.assignment_rows(self.protocol)

    def case_for(self, assignment: dict) -> dict:
        return {
            "case_id": assignment["case_id"],
            "assignment_id": assignment["assignment_id"],
            "language": assignment["language"],
            "account_type": assignment["account_type"],
            "account_holder_age": assignment["account_holder_age"],
            "conversation_type": assignment["conversation_type"],
            "sender_relationship": assignment["sender_relationship"],
            "relationship_trust_source": assignment["relationship_trust_source"],
            "messages": [
                {"speaker": "protected", "text": "Synthetic opening message."},
                {"speaker": "other", "text": "Synthetic response for review."},
            ],
            "author_certification": {
                "original_synthetic_text": True,
                "no_real_child_data": True,
                "no_direct_identifiers": True,
                "no_detector_access": True,
            },
        }

    def test_assignment_matrix_has_ten_pairs_per_language_family(self) -> None:
        self.assertEqual(len(self.assignments), 480)
        support = Counter(
            (row["language"], row["target_family"], row["target_polarity"])
            for row in self.assignments
        )
        self.assertEqual(set(support.values()), {10})
        self.assertEqual(len({row["pair_id"] for row in self.assignments}), 240)
        self.assertEqual(len({row["case_id"] for row in self.assignments}), 480)

    def test_case_validator_rejects_direct_identifier(self) -> None:
        assignment = self.assignments[0]
        case = self.case_for(assignment)
        case["messages"][0]["text"] = "Write to child@example.com now."
        errors = holdout.validate_case(case, assignment, self.protocol)
        self.assertTrue(any("possible email" in error for error in errors))

    def test_case_validator_accepts_placeholders(self) -> None:
        assignment = self.assignments[0]
        case = self.case_for(assignment)
        case["messages"][0]["text"] = "Use [LINK] and call [PHONE]."
        self.assertEqual(
            holdout.validate_case(case, assignment, self.protocol), []
        )

    def test_case_validator_rejects_false_certification(self) -> None:
        assignment = self.assignments[0]
        case = self.case_for(assignment)
        case["author_certification"]["no_detector_access"] = False
        errors = holdout.validate_case(case, assignment, self.protocol)
        self.assertIn("all author certifications must be true", errors)

    def test_adjudication_agreement_is_exact_on_release_fields(self) -> None:
        annotation = {
            "included": True,
            "primary_threat": "grooming",
            "onset_turn": 1,
            "minimum_action": "warn",
        }
        self.assertTrue(holdout.annotations_agree(annotation, copy.deepcopy(annotation)))
        changed = copy.deepcopy(annotation)
        changed["onset_turn"] = 0
        self.assertFalse(holdout.annotations_agree(annotation, changed))

    def test_case_result_ignores_pre_onset_allow_for_risky_case(self) -> None:
        output = {
            "turns": [
                {
                    "action": "allow",
                    "scores": {family: 0.0 for family in holdout.ALL_PROBE_FAMILIES},
                },
                {
                    "action": "warn",
                    "scores": {
                        **{family: 0.0 for family in holdout.ALL_PROBE_FAMILIES},
                        "grooming": 0.9,
                    },
                },
            ]
        }
        result = holdout.case_result(
            self.protocol,
            {"target_polarity": "risky"},
            {"primary_threat": "grooming", "onset_turn": 1},
            output,
        )
        self.assertTrue(result["correct"])
        self.assertFalse(result["action_error"])

    def test_manifest_identity_detects_changed_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text(json.dumps({"value": 1}), encoding="utf-8")
            identity = holdout.file_identity(path)
            manifest = {"inputs": {"protocol": identity}}
            holdout.verify_manifest_input(manifest, "protocol", path)
            path.write_text(json.dumps({"value": 2}), encoding="utf-8")
            with self.assertRaises(ValueError):
                holdout.verify_manifest_input(manifest, "protocol", path)

    def test_full_synthetic_workflow_freezes_before_expected_failed_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assignments_path = root / "assignments.jsonl"
            cases_path = root / "cases.jsonl"
            holdout.write_jsonl(assignments_path, self.assignments)
            cases = []
            annotations_a = []
            annotations_b = []
            for assignment in self.assignments:
                case = self.case_for(assignment)
                marker = assignment["assignment_id"]
                case["messages"] = [
                    {"speaker": "protected", "text": f"Synthetic opening {marker}."},
                    {"speaker": "other", "text": f"Synthetic response {marker}."},
                ]
                cases.append(case)
                threat = (
                    assignment["target_family"]
                    if assignment["target_polarity"] == "risky"
                    else "none"
                )
                annotation = {
                    "case_id": case["case_id"],
                    "reviewer_id": "reviewer_a",
                    "included": True,
                    "primary_threat": threat,
                    "onset_turn": 1 if threat != "none" else None,
                    "minimum_action": "warn" if threat != "none" else "allow",
                    "naturalness": 5,
                    "confidence": 5,
                    "contains_pii": False,
                    "exclusion_reason": None,
                    "notes": None,
                }
                annotations_a.append(annotation)
                annotations_b.append({**annotation, "reviewer_id": "reviewer_b"})
            holdout.write_jsonl(cases_path, cases)
            packet_dir = root / "packets"
            self.assertEqual(
                holdout.cmd_packets(
                    SimpleNamespace(
                        protocol=PROTOCOL_PATH,
                        assignments=assignments_path,
                        cases=cases_path,
                        output_dir=packet_dir,
                        reference_json=[],
                        allow_partial=False,
                    )
                ),
                0,
            )
            self.assertEqual(len(list(packet_dir.glob("annotation-*.jsonl"))), 6)

            review_a_path = root / "review-a.jsonl"
            review_b_path = root / "review-b.jsonl"
            gold_path = root / "gold.jsonl"
            adjudication_path = root / "adjudication.json"
            holdout.write_jsonl(review_a_path, annotations_a)
            holdout.write_jsonl(review_b_path, annotations_b)
            self.assertEqual(
                holdout.cmd_adjudicate(
                    SimpleNamespace(
                        cases=cases_path,
                        review_a=[review_a_path],
                        review_b=[review_b_path],
                        review_c=[],
                        gold_output=gold_path,
                        report_output=adjudication_path,
                    )
                ),
                0,
            )

            manifest_path = root / "manifest.json"
            self.assertEqual(
                holdout.cmd_freeze(
                    SimpleNamespace(
                        protocol=PROTOCOL_PATH,
                        assignments=assignments_path,
                        cases=cases_path,
                        gold=gold_path,
                        adjudication_report=adjudication_path,
                        output=manifest_path,
                    )
                ),
                0,
            )
            self.assertEqual(holdout.load_json(manifest_path)["status"], "frozen")

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
            result_path = root / "result.json"
            self.assertEqual(
                holdout.cmd_evaluate(
                    SimpleNamespace(
                        manifest=manifest_path,
                        protocol=PROTOCOL_PATH,
                        assignments=assignments_path,
                        cases=cases_path,
                        gold=gold_path,
                        probe=fake_probe,
                        output=result_path,
                    )
                ),
                1,
            )
            result = holdout.load_json(result_path)
            self.assertEqual(result["status"], "fail")
            self.assertEqual(
                result["overall"]["expected_family_recall"]["numerator"], 0
            )
            self.assertEqual(result["overall"]["safe_specificity"]["numerator"], 240)


if __name__ == "__main__":
    unittest.main()
