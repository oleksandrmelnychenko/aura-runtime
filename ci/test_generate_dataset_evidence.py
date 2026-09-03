import copy
import json
import tempfile
import unittest
from pathlib import Path

from ci import generate_dataset_evidence


def valid_dataset() -> dict:
    return {
        "schema_version": 1,
        "dataset_id": "aura_code_switch_context_boundaries",
        "dataset_label": "Code-switch boundaries",
        "maintainer": "aura_core_team",
        "created_at_ms": 100,
        "updated_at_ms": 200,
        "provenance": "repository_owned_synthetic_seed",
        "review_status": "developer_reviewed_not_independent_gold",
        "pairs": [
            {
                "case_id": "en_uk_threat",
                "languages": ["en", "uk"],
                "context_role": "quote_report",
                "detector_origin": "lexical",
                "threat_type": "threat",
                "event_kind": "physical_threat",
                "safe_text": "He wrote the quoted threat. I am reporting it.",
                "risky_text": "He wrote the quoted threat. I will hurt you.",
            }
        ],
    }


def matching_changelog() -> list[dict]:
    return [
        {
            "change_id": "test-change",
            "changed_at_ms": 200,
            "author": "aura_core_team",
            "change_kind": "coverage_expansion",
            "summary": "Test fixture.",
            "affected_slices": ["code_switch:en-uk"],
            "support_impact": "increase",
            "review_ticket": "test",
        }
    ]


class CodeSwitchDatasetEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "code-switch.json"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def validate(self, dataset: dict) -> dict:
        self.path.write_text(json.dumps(dataset), encoding="utf-8")
        return generate_dataset_evidence.validate_code_switch_dataset(
            dataset, matching_changelog(), self.path
        )

    def test_valid_counterfactual_pair_passes(self) -> None:
        report = self.validate(valid_dataset())

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["coverage"]["pair_count"], 1)
        self.assertEqual(report["coverage"]["language_pair"], {"en-uk": 1})
        self.assertFalse(report["privacy"]["contains_direct_identifiers"])

    def test_incompatible_threat_event_route_fails_closed(self) -> None:
        dataset = valid_dataset()
        dataset["pairs"][0]["event_kind"] = "sexual_content"

        report = self.validate(dataset)

        self.assertEqual(report["status"], "fail")
        self.assertTrue(
            any("incompatible threat_type/event_kind" in error for error in report["errors"])
        )

    def test_equal_counterfactuals_and_direct_identifiers_fail(self) -> None:
        dataset = copy.deepcopy(valid_dataset())
        dataset["pairs"][0]["safe_text"] = "contact child@example.com"
        dataset["pairs"][0]["risky_text"] = "contact child@example.com"

        report = self.validate(dataset)

        self.assertEqual(report["status"], "fail")
        self.assertTrue(report["privacy"]["contains_direct_identifiers"])
        self.assertTrue(
            any("distinct safe/risky counterfactuals" in error for error in report["errors"])
        )


if __name__ == "__main__":
    unittest.main()
