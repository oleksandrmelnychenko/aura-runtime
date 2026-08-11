import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ci import generate_evidence_manifest


def world_lifecycle_payload(**overrides):
    payload = {
        "schema_version": "world_suite.v1",
        "total_worlds": 2,
        "total_events": 20,
        "threat_events": 4,
        "total_findings": 0,
        "reports": [
            {"label": "clean_negative", "findings": []},
            {"label": "grooming_positive", "findings": []},
        ],
    }
    payload.update(overrides)
    return payload


def temporal_shadow_payload(**overrides):
    payload = {
        "schema_version": "aura.military.temporal_shadow_report.v1",
        "overall_status": "pass",
        "runtime_policy_enabled": False,
        "privacy": {
            "raw_text_present": False,
            "stable_actor_identifiers_present": False,
            "content_hashes_reported": False,
        },
        "metrics": {
            "total_cases": 37,
            "total_events": 100,
            "adversarial_variants": 259,
            "adversarial_mismatch_variants": 0,
            "shadow_action_cases": 0,
        },
    }
    payload.update(overrides)
    return payload


def temporal_telemetry_validation_payload(**overrides):
    def deployment(name):
        return {
            "schema_version": "aura.military.temporal_shadow_telemetry.v1",
            "overall_status": "pass",
            "deployment": name,
            "runtime_policy_enabled": False,
            "action_execution_enabled": False,
            "privacy": {
                "raw_text_collected": False,
                "actor_identifiers_collected": False,
                "content_hashes_collected": False,
                "event_timestamps_exported": False,
                "per_conversation_records_exported": False,
                "minimum_aggregation_inputs": 20,
            },
            "metrics": {"evaluated_inputs": 37, "suppressed_actions": 0},
        }

    payload = {
        "schema_version": "aura.military.temporal_shadow_telemetry_validation.v1",
        "overall_status": "pass",
        "on_prem": deployment("on_prem"),
        "adk": deployment("adk"),
    }
    payload.update(overrides)
    return payload


def temporal_review_payload(**overrides):
    payload = {
        "schema_version": "aura.military.temporal_review_report.v2",
        "overall_status": "pass",
        "blinding_assurance": "packet_bound",
        "blind_packet_id": "blind_round_alpha",
        "blind_packet_canonical_sha256": "a" * 64,
        "privacy": {
            "raw_text_present": False,
            "reviewer_tokens_exported": False,
            "affiliation_tokens_exported": False,
            "stable_actor_identifiers_present": False,
            "internal_case_ids_exported": False,
        },
        "metrics": {
            "corpus_cases": 37,
            "cases_with_two_independent_reviews": 37,
        },
    }
    payload.update(overrides)
    return payload


class WorldLifecycleStatusTests(unittest.TestCase):
    def test_passes_clean_suite(self):
        self.assertEqual(
            generate_evidence_manifest.world_lifecycle_status(world_lifecycle_payload()),
            "pass",
        )

    def test_rejects_wrong_schema(self):
        self.assertEqual(
            generate_evidence_manifest.world_lifecycle_status(
                world_lifecycle_payload(schema_version="world_suite.v0")
            ),
            "invalid_schema",
        )

    def test_rejects_summary_count_mismatch(self):
        self.assertEqual(
            generate_evidence_manifest.world_lifecycle_status(
                world_lifecycle_payload(total_worlds=3)
            ),
            "invalid_summary",
        )

    def test_rejects_top_level_findings(self):
        self.assertEqual(
            generate_evidence_manifest.world_lifecycle_status(
                world_lifecycle_payload(total_findings=1)
            ),
            "findings_present",
        )

    def test_rejects_nested_findings(self):
        payload = world_lifecycle_payload(total_findings=0)
        payload["reports"][1]["findings"] = [{"message": "missed expected threat"}]
        self.assertEqual(
            generate_evidence_manifest.world_lifecycle_status(payload),
            "findings_present",
        )


class RefactorEvidenceStatusTests(unittest.TestCase):
    def test_world_performance_accepts_clean_tier(self):
        payload = {
            "schema_version": "aura_world_performance_gate.v1",
            "status": "pass",
            "failures": [],
            "tiers": [{"tier": "10k", "status": "pass"}],
        }

        self.assertEqual(
            generate_evidence_manifest.world_performance_status(payload),
            "pass",
        )

    def test_world_performance_rejects_empty_tiers(self):
        payload = {
            "schema_version": "aura_world_performance_gate.v1",
            "status": "pass",
            "failures": [],
            "tiers": [],
        }

        self.assertEqual(
            generate_evidence_manifest.world_performance_status(payload),
            "invalid_summary",
        )

    def test_refactor_diff_rejects_regression(self):
        payload = {
            "schema_version": "aura.refactor_diff.v1",
            "status": "fail",
            "summary": {
                "regression": 1,
                "invalid_approval_count": 0,
            },
        }

        self.assertEqual(
            generate_evidence_manifest.refactor_diff_status(payload),
            "regression",
        )

    def test_refactor_diff_accepts_approved_changes(self):
        payload = {
            "schema_version": "aura.refactor_diff.v1",
            "status": "pass",
            "summary": {
                "regression": 0,
                "invalid_approval_count": 0,
                "structural_only": 2,
                "approved_safety_improvement": 1,
            },
        }

        self.assertEqual(
            generate_evidence_manifest.refactor_diff_status(payload),
            "pass",
        )

    def test_apple_artifact_accepts_clean_verified_slices(self):
        payload = {
            "schema_version": "aura.apple_artifact_verification.v1",
            "status": "pass",
            "shippable": True,
            "source_tree_dirty": False,
            "slices": [{}, {}, {}],
        }

        self.assertEqual(
            generate_evidence_manifest.apple_artifact_status(payload),
            "pass",
        )

    def test_apple_artifact_rejects_dirty_local_build(self):
        payload = {
            "schema_version": "aura.apple_artifact_verification.v1",
            "status": "pass",
            "shippable": False,
            "source_tree_dirty": True,
            "slices": [{}, {}, {}],
        }

        self.assertEqual(
            generate_evidence_manifest.apple_artifact_status(payload),
            "non_shippable",
        )


class TemporalEvidenceStatusTests(unittest.TestCase):
    def test_temporal_shadow_accepts_adversarially_clean_report(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_shadow_status(
                temporal_shadow_payload()
            ),
            "pass",
        )

    def test_temporal_shadow_rejects_adversarial_mismatch(self):
        payload = temporal_shadow_payload()
        payload["metrics"]["adversarial_mismatch_variants"] = 1

        self.assertEqual(
            generate_evidence_manifest.temporal_shadow_status(payload),
            "adversarial_mismatch",
        )

    def test_temporal_shadow_rejects_enabled_runtime_policy(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_shadow_status(
                temporal_shadow_payload(runtime_policy_enabled=True)
            ),
            "runtime_policy_enabled",
        )

    def test_temporal_telemetry_accepts_private_on_prem_and_adk_aggregates(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_shadow_telemetry_validation_status(
                temporal_telemetry_validation_payload()
            ),
            "pass",
        )

    def test_temporal_telemetry_rejects_actor_identifiers(self):
        payload = temporal_telemetry_validation_payload()
        payload["adk"]["privacy"]["actor_identifiers_collected"] = True

        self.assertEqual(
            generate_evidence_manifest.temporal_shadow_telemetry_validation_status(
                payload
            ),
            "privacy_fail",
        )

    def test_temporal_review_accepts_complete_private_report(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_independent_review_status(
                temporal_review_payload()
            ),
            "pass",
        )

    def test_temporal_review_preserves_pending_status(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_independent_review_status(
                temporal_review_payload(overall_status="pending")
            ),
            "pending",
        )

    def test_temporal_review_rejects_declared_only_blinding(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_independent_review_status(
                temporal_review_payload(blinding_assurance="declared_only")
            ),
            "insufficient_blinding",
        )

    def test_temporal_review_rejects_noncanonical_packet_digest(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_independent_review_status(
                temporal_review_payload(
                    blind_packet_canonical_sha256=("a" * 62) + "  "
                )
            ),
            "invalid_blind_packet_identity",
        )

    def test_temporal_activation_stays_pending_without_independent_review(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_policy_activation_readiness(
                temporal_shadow_payload(),
                None,
                temporal_telemetry_validation_payload(),
            ),
            "pending",
        )

    def test_temporal_activation_passes_only_with_independent_review(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_policy_activation_readiness(
                temporal_shadow_payload(),
                temporal_review_payload(),
                temporal_telemetry_validation_payload(),
            ),
            "pass",
        )


class EvidenceManifestWorldLifecycleTests(unittest.TestCase):
    def test_manifest_records_world_lifecycle_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = {
                "release": root / "release.json",
                "contract": root / "contract.json",
                "soak": root / "soak.json",
                "dataset": root / "dataset.json",
                "audit": root / "audit.json",
                "world_lifecycle": root / "world-lifecycle.json",
                "world_performance": root / "world-performance.json",
                "refactor_diff": root / "refactor-diff.json",
                "temporal_shadow": root / "temporal-shadow.json",
                "temporal_telemetry": root / "temporal-telemetry.json",
                "manifest": root / "manifest.json",
            }
            write_json(
                paths["release"],
                {
                    "overall_status": "pass",
                    "schema_version": "aura.release_report.v1",
                    "operator_summary": [],
                },
            )
            write_json(
                paths["contract"],
                {
                    "runtime_release_version": "test",
                    "wire": {"proto_package": "aura.test", "wire_major_version": 1},
                    "persisted_state": {"schema_version": 1},
                    "abi": {"request_limits_bytes": [], "exported_functions": []},
                },
            )
            write_json(paths["soak"], {"status": "pass", "iterations": 1, "attempts_run": 1})
            write_json(paths["dataset"], {"status": "pass", "datasets": []})
            write_json(
                paths["audit"],
                {
                    "status": "pass",
                    "audit_schema_version": "aura.audit.v1",
                    "forbidden_fields_absent": True,
                },
            )
            write_json(paths["world_lifecycle"], world_lifecycle_payload())
            write_json(
                paths["world_performance"],
                {
                    "schema_version": "aura_world_performance_gate.v1",
                    "status": "pass",
                    "failures": [],
                    "tiers": [
                        {
                            "tier": "10k",
                            "status": "pass",
                            "total_events": 12000,
                            "timing": {
                                "elapsed_seconds": 10.0,
                                "max_rss_mb": 100.0,
                            },
                        }
                    ],
                },
            )
            write_json(
                paths["refactor_diff"],
                {
                    "schema_version": "aura.refactor_diff.v1",
                    "status": "pass",
                    "summary": {
                        "change_count": 0,
                        "regression": 0,
                        "invalid_approval_count": 0,
                        "structural_only": 0,
                        "approved_safety_improvement": 0,
                    },
                },
            )
            write_json(paths["temporal_shadow"], temporal_shadow_payload())
            write_json(
                paths["temporal_telemetry"],
                temporal_telemetry_validation_payload(),
            )

            argv = [
                "generate_evidence_manifest.py",
                "--output",
                paths["manifest"].as_posix(),
                "--label",
                "unit-test",
                "--release-report",
                paths["release"].as_posix(),
                "--contract-evidence",
                paths["contract"].as_posix(),
                "--ffi-soak",
                paths["soak"].as_posix(),
                "--dataset-evidence",
                paths["dataset"].as_posix(),
                "--audit-evidence",
                paths["audit"].as_posix(),
                "--world-lifecycle-report",
                paths["world_lifecycle"].as_posix(),
                "--world-performance-report",
                paths["world_performance"].as_posix(),
                "--refactor-diff-report",
                paths["refactor_diff"].as_posix(),
                "--temporal-shadow-report",
                paths["temporal_shadow"].as_posix(),
                "--temporal-shadow-telemetry-validation",
                paths["temporal_telemetry"].as_posix(),
            ]
            with patch.object(sys, "argv", argv):
                self.assertEqual(generate_evidence_manifest.main(), 0)

            manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
            self.assertEqual(manifest["evidence_status"], "pass")
            self.assertEqual(manifest["summary"]["world_lifecycle_status"], "pass")
            self.assertEqual(manifest["summary"]["world_lifecycle_total_worlds"], 2)
            self.assertEqual(manifest["summary"]["world_lifecycle_finding_count"], 0)
            self.assertEqual(manifest["summary"]["world_performance_status"], "pass")
            self.assertEqual(manifest["summary"]["refactor_diff_status"], "pass")
            self.assertEqual(manifest["summary"]["temporal_shadow_status"], "pass")
            self.assertEqual(
                manifest["summary"]["temporal_shadow_adversarial_variant_count"],
                259,
            )
            self.assertEqual(
                manifest["summary"]["temporal_shadow_telemetry_validation_status"],
                "pass",
            )
            self.assertEqual(
                manifest["summary"]["temporal_policy_activation_readiness"],
                "pending",
            )
            self.assertEqual(
                manifest["artifacts"]["world_lifecycle_report"]["observed_status"],
                "pass",
            )


def write_json(path: Path, payload: dict):
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
