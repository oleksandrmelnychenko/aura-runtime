#!/usr/bin/env python3

import argparse
import json
import math
import os
import sys
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path


SCHEMA_VERSION = "aura.evidence_manifest.v1"
PILOT_SHADOW_SCHEMA_VERSION = "aura.shadow_mode_bundle.v1"
TEMPORAL_SHADOW_SCHEMA_VERSION = "aura.military.temporal_shadow_report.v1"
TEMPORAL_REVIEW_SCHEMA_VERSION = "aura.military.temporal_review_report.v3"
TEMPORAL_STUDY_ATTESTATION_VERIFICATION_SCHEMA_VERSION = (
    "aura.military.temporal_study_attestation_verification.v1"
)
TEMPORAL_TELEMETRY_VALIDATION_SCHEMA_VERSION = (
    "aura.military.temporal_shadow_telemetry_validation.v1"
)
TEMPORAL_TELEMETRY_SCHEMA_VERSION = "aura.military.temporal_shadow_telemetry.v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a unified machine-readable manifest for AURA release evidence."
    )
    parser.add_argument("--output", required=True, help="Path to manifest JSON output.")
    parser.add_argument("--label", required=True, help="Short label for this evidence bundle.")
    parser.add_argument("--release-report", required=True, help="Path to release report JSON.")
    parser.add_argument(
        "--contract-evidence", required=True, help="Path to contract evidence JSON."
    )
    parser.add_argument("--ffi-soak", required=True, help="Path to FFI soak JSON evidence.")
    parser.add_argument(
        "--ffi-smoke",
        default=None,
        help="Optional path to FFI header smoke JSON evidence.",
    )
    parser.add_argument(
        "--dataset-evidence", required=True, help="Path to dataset evidence JSON."
    )
    parser.add_argument(
        "--audit-evidence", required=True, help="Path to audit evidence JSON."
    )
    parser.add_argument(
        "--pilot-shadow-bundle",
        default=None,
        help="Optional path to pilot/shadow replay bundle JSON.",
    )
    parser.add_argument(
        "--pilot-regression-report",
        default=None,
        help="Optional path to pilot simulation regression report JSON.",
    )
    parser.add_argument(
        "--temporal-shadow-report",
        default=None,
        help="Optional path to military temporal Shadow evaluation JSON.",
    )
    parser.add_argument(
        "--temporal-independent-review-report",
        default=None,
        help="Optional path to independent temporal review readiness JSON.",
    )
    parser.add_argument(
        "--temporal-study-attestation-verification",
        default=None,
        help="Optional path to trusted-key verification of the temporal study commitment.",
    )
    parser.add_argument(
        "--temporal-shadow-telemetry-validation",
        default=None,
        help="Optional path to on-prem/ADK temporal Shadow telemetry validation JSON.",
    )
    parser.add_argument(
        "--pilot-gate-report",
        default=None,
        help="Optional path to pilot gate report JSON.",
    )
    parser.add_argument(
        "--kids-preprod-dry-run-report",
        default=None,
        help="Optional path to KIDS pre-prod dry-run matrix report JSON.",
    )
    parser.add_argument(
        "--community-surface-report",
        default=None,
        help="Optional path to community surface simulation gate JSON.",
    )
    parser.add_argument(
        "--world-lifecycle-report",
        default=None,
        help="Optional path to world lifecycle simulation suite JSON.",
    )
    parser.add_argument(
        "--world-performance-report",
        default=None,
        help="Optional path to world performance gate JSON.",
    )
    parser.add_argument(
        "--refactor-diff-report",
        default=None,
        help="Optional path to AURA Core refactor differential report JSON.",
    )
    parser.add_argument(
        "--apple-artifact-verification",
        default=None,
        help="Optional path to Apple XCFramework verification JSON.",
    )
    return parser.parse_args()


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_digest(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "path": path.as_posix(),
        "bytes": len(data),
        "sha256": sha256(data).hexdigest(),
    }


def load_json_artifact(path_str: str, required: bool) -> tuple[dict | None, dict]:
    path = Path(path_str)
    artifact = {
        "required": required,
        "exists": path.exists(),
        "path": path.as_posix(),
    }
    if not path.exists():
        artifact["status"] = "missing"
        return None, artifact

    artifact.update(file_digest(path))
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        artifact["status"] = "invalid_json"
        artifact["error"] = str(error)
        return None, artifact

    artifact["status"] = "loaded"
    return payload, artifact


def release_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return payload.get("overall_status")


def release_operator_summary(payload: dict | None) -> list[str]:
    if payload is None:
        return []
    summary = payload.get("operator_summary", [])
    return summary if isinstance(summary, list) else []


def social_context_inference_snapshot(payload: dict | None) -> dict | None:
    if payload is None:
        return None
    suites = payload.get("suites", [])
    if not isinstance(suites, list):
        return None
    for suite in suites:
        if not isinstance(suite, dict):
            continue
        if suite.get("suite_id") != "social_context":
            continue
        inference = suite.get("social_context_inference")
        return inference if isinstance(inference, dict) else None
    return None


def soak_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return payload.get("status")


def smoke_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return payload.get("status")


def dataset_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return payload.get("status")


def audit_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return payload.get("status")


def pilot_shadow_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    privacy = payload.get("privacy", {})
    summary = payload.get("summary", {})
    if payload.get("schema_version") != PILOT_SHADOW_SCHEMA_VERSION:
        return "invalid_schema"
    if privacy.get("raw_text_present") is not False:
        return "privacy_fail"
    if privacy.get("raw_identifier_fields_present") is not False:
        return "privacy_fail"
    if summary.get("finding_count") not in (0, None):
        return "findings_present"
    return "pass"


def pilot_regression_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return payload.get("overall_status")


def temporal_shadow_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    if payload.get("schema_version") != TEMPORAL_SHADOW_SCHEMA_VERSION:
        return "invalid_schema"
    privacy = payload.get("privacy")
    metrics = payload.get("metrics")
    if not isinstance(privacy, dict) or not isinstance(metrics, dict):
        return "invalid_summary"
    if payload.get("overall_status") != "pass":
        return "fail"
    if payload.get("runtime_policy_enabled") is not False:
        return "runtime_policy_enabled"
    if any(
        privacy.get(field) is not False
        for field in (
            "raw_text_present",
            "stable_actor_identifiers_present",
            "content_hashes_reported",
        )
    ):
        return "privacy_fail"
    if metrics.get("adversarial_variants", 0) < 200:
        return "insufficient_adversarial_coverage"
    if metrics.get("adversarial_mismatch_variants") != 0:
        return "adversarial_mismatch"
    if metrics.get("shadow_action_cases") != 0:
        return "shadow_actions_present"
    return "pass"


def temporal_independent_review_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    if payload.get("schema_version") != TEMPORAL_REVIEW_SCHEMA_VERSION:
        return "invalid_schema"
    privacy = payload.get("privacy")
    if not isinstance(privacy, dict):
        return "invalid_summary"
    if any(
        privacy.get(field) is not False
        for field in (
            "raw_text_present",
            "reviewer_tokens_exported",
            "affiliation_tokens_exported",
            "stable_actor_identifiers_present",
            "internal_case_ids_exported",
        )
    ):
        return "privacy_fail"
    status = payload.get("overall_status")
    if status == "pass":
        if payload.get("blinding_assurance") != "packet_bound":
            return "insufficient_blinding"
        packet_id = payload.get("blind_packet_id")
        packet_digest = payload.get("blind_packet_canonical_sha256")
        if (
            not isinstance(packet_id, str)
            or not 8 <= len(packet_id) <= 64
            or not all(
                char.isascii() and (char.isalnum() or char in "_-.")
                for char in packet_id
            )
        ):
            return "invalid_blind_packet_identity"
        if (
            not isinstance(packet_digest, str)
            or len(packet_digest) != 64
            or any(char not in "0123456789abcdef" for char in packet_digest)
        ):
            return "invalid_blind_packet_identity"
        if payload.get("preregistration_assurance") != "packet_bound":
            return "insufficient_preregistration"
        study_id = payload.get("study_id")
        preregistration_digest = payload.get("preregistration_canonical_sha256")
        study_commitment_digest = payload.get(
            "study_commitment_canonical_sha256"
        )
        if (
            not isinstance(study_id, str)
            or not 8 <= len(study_id) <= 64
            or not all(
                char.isascii() and (char.isalnum() or char in "_-.")
                for char in study_id
            )
            or not isinstance(preregistration_digest, str)
            or len(preregistration_digest) != 64
            or any(char not in "0123456789abcdef" for char in preregistration_digest)
        ):
            return "invalid_preregistration_identity"
        if (
            not isinstance(study_commitment_digest, str)
            or len(study_commitment_digest) != 64
            or any(char not in "0123456789abcdef" for char in study_commitment_digest)
        ):
            return "invalid_study_commitment"
        if payload.get("study_corpus_class") != "embargoed_external":
            return "insufficient_external_validity"
        metrics = payload.get("metrics")
        if not isinstance(metrics, dict) or metrics.get("reviewer_pair_comparisons", 0) <= 0:
            return "invalid_agreement_summary"
        for field in (
            "exact_set_pair_agreement_rate",
            "krippendorff_alpha_nominal",
        ):
            value = metrics.get(field)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value > 1.0
                or (field == "exact_set_pair_agreement_rate" and value < 0.0)
            ):
                return "invalid_agreement_summary"
        if (
            metrics["exact_set_pair_agreement_rate"] < 0.8
            or metrics["krippendorff_alpha_nominal"] < 0.8
        ):
            return "insufficient_interreviewer_agreement"
    return status


def temporal_study_attestation_verification_status(
    payload: dict | None,
    temporal_independent_review_payload: dict | None,
) -> str | None:
    if payload is None:
        return None
    if (
        payload.get("schema_version")
        != TEMPORAL_STUDY_ATTESTATION_VERIFICATION_SCHEMA_VERSION
    ):
        return "invalid_schema"
    if payload.get("status") != "pass":
        return "fail"
    if payload.get("signature_algorithm") != "Ed25519":
        return "invalid_signature_algorithm"
    key_id = payload.get("key_id")
    if (
        not isinstance(key_id, str)
        or not key_id.isascii()
        or not 1 <= len(key_id) <= 64
        or not all(character.isalnum() or character in "_.-" for character in key_id)
    ):
        return "invalid_key_identity"
    for field in (
        "commitment_file_sha256",
        "commitment_canonical_sha256",
        "preregistration_canonical_sha256",
        "corpus_sha256",
        "packet_canonical_sha256",
        "public_key_spki_sha256",
    ):
        digest = payload.get(field)
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            return "invalid_attestation_identity"
    registered_at_ms = payload.get("registered_at_ms")
    if (
        isinstance(registered_at_ms, bool)
        or not isinstance(registered_at_ms, int)
        or registered_at_ms <= 0
    ):
        return "invalid_attestation_identity"
    if payload.get("trusted_timestamp_assurance") != "absent":
        return "unsupported_timestamp_claim"
    if temporal_independent_review_payload is None:
        return "missing_review_binding"
    bindings = (
        ("study_id", "study_id"),
        ("corpus_class", "study_corpus_class"),
        ("commitment_canonical_sha256", "study_commitment_canonical_sha256"),
        ("preregistration_canonical_sha256", "preregistration_canonical_sha256"),
        ("corpus_sha256", "corpus_sha256"),
        ("packet_canonical_sha256", "blind_packet_canonical_sha256"),
    )
    if any(
        payload.get(attestation_field) != temporal_independent_review_payload.get(review_field)
        for attestation_field, review_field in bindings
    ):
        return "review_binding_mismatch"
    return "pass"


def temporal_shadow_telemetry_validation_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    if payload.get("schema_version") != TEMPORAL_TELEMETRY_VALIDATION_SCHEMA_VERSION:
        return "invalid_schema"
    if payload.get("overall_status") != "pass":
        return "fail"
    for deployment_name in ("on_prem", "adk"):
        report = payload.get(deployment_name)
        if not isinstance(report, dict):
            return "invalid_summary"
        if report.get("schema_version") != TEMPORAL_TELEMETRY_SCHEMA_VERSION:
            return "invalid_schema"
        if report.get("overall_status") != "pass":
            return "fail"
        if report.get("deployment") != deployment_name:
            return "deployment_mismatch"
        if report.get("runtime_policy_enabled") is not False:
            return "runtime_policy_enabled"
        if report.get("action_execution_enabled") is not False:
            return "action_execution_enabled"
        privacy = report.get("privacy")
        metrics = report.get("metrics")
        if not isinstance(privacy, dict) or not isinstance(metrics, dict):
            return "invalid_summary"
        if any(
            privacy.get(field) is not False
            for field in (
                "raw_text_collected",
                "actor_identifiers_collected",
                "content_hashes_collected",
                "event_timestamps_exported",
                "per_conversation_records_exported",
            )
        ):
            return "privacy_fail"
        if privacy.get("minimum_aggregation_inputs", 0) < 20:
            return "insufficient_privacy_threshold"
        if metrics.get("evaluated_inputs", 0) < 20:
            return "insufficient_aggregation"
        if metrics.get("suppressed_actions") != 0:
            return "shadow_actions_present"
    return "pass"


def temporal_policy_activation_readiness(
    temporal_shadow_payload: dict | None,
    temporal_independent_review_payload: dict | None,
    temporal_shadow_telemetry_validation_payload: dict | None,
    temporal_study_attestation_verification_payload: dict | None,
) -> str | None:
    shadow_status = temporal_shadow_status(temporal_shadow_payload)
    review_status = temporal_independent_review_status(
        temporal_independent_review_payload
    )
    telemetry_status = temporal_shadow_telemetry_validation_status(
        temporal_shadow_telemetry_validation_payload
    )
    attestation_status = temporal_study_attestation_verification_status(
        temporal_study_attestation_verification_payload,
        temporal_independent_review_payload,
    )
    if (
        shadow_status is None
        and review_status is None
        and telemetry_status is None
        and attestation_status is None
    ):
        return None
    if shadow_status != "pass" or telemetry_status != "pass":
        return "fail"
    if attestation_status not in (None, "pass"):
        return "fail"
    if review_status == "pass":
        if attestation_status == "pass":
            return "pass"
        if attestation_status is None:
            return "pending"
        return "fail"
    if review_status in (None, "pending"):
        return "pending"
    return "fail"


def pilot_gate_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return payload.get("overall_status")


def kids_preprod_dry_run_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return payload.get("overall_status")


def community_surface_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    gates = payload.get("gates", {})
    findings = payload.get("findings", [])
    if gates.get("passed") is not True:
        return "fail"
    if isinstance(findings, list) and findings:
        return "findings_present"
    return "pass"


def world_lifecycle_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    if payload.get("schema_version") != "world_suite.v1":
        return "invalid_schema"
    reports = payload.get("reports")
    if not isinstance(reports, list):
        return "invalid_schema"
    if payload.get("total_worlds") != len(reports):
        return "invalid_summary"
    if payload.get("total_findings") != 0:
        return "findings_present"
    for report in reports:
        if not isinstance(report, dict):
            return "invalid_schema"
        findings = report.get("findings", [])
        if not isinstance(findings, list):
            return "invalid_schema"
        if findings:
            return "findings_present"
    return "pass"


def world_performance_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    if payload.get("schema_version") != "aura_world_performance_gate.v1":
        return "invalid_schema"
    tiers = payload.get("tiers")
    if not isinstance(tiers, list) or not tiers:
        return "invalid_summary"
    if payload.get("status") != "pass":
        return "fail"
    if payload.get("failures"):
        return "fail"
    if any(
        not isinstance(tier, dict) or tier.get("status") != "pass"
        for tier in tiers
    ):
        return "fail"
    return "pass"


def refactor_diff_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    if payload.get("schema_version") != "aura.refactor_diff.v1":
        return "invalid_schema"
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        return "invalid_summary"
    if summary.get("regression") != 0:
        return "regression"
    if summary.get("invalid_approval_count") != 0:
        return "invalid_approval"
    return "pass" if payload.get("status") == "pass" else "fail"


def apple_artifact_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    if payload.get("schema_version") != "aura.apple_artifact_verification.v1":
        return "invalid_schema"
    if payload.get("status") != "pass":
        return "fail"
    if payload.get("shippable") is not True:
        return "non_shippable"
    if payload.get("source_tree_dirty") is not False:
        return "non_shippable"
    slices = payload.get("slices")
    if not isinstance(slices, list) or len(slices) != 3:
        return "invalid_summary"
    return "pass"


def evidence_status(artifacts: dict, summary: dict) -> str:
    if any(meta["required"] and not meta["exists"] for meta in artifacts.values()):
        return "blocked"
    if any(meta["status"] == "invalid_json" for meta in artifacts.values()):
        return "blocked"
    if summary["release_report_status"] != "pass":
        return "fail"
    if summary["ffi_soak_status"] != "pass":
        return "fail"
    if (
        summary["ffi_smoke_status"] == "blocked"
        and summary.get("ffi_smoke_mode") == "local_stub_no_compiler"
    ):
        return "blocked"
    if summary["ffi_smoke_status"] not in (None, "pass"):
        return "fail"
    if summary["dataset_evidence_status"] != "pass":
        return "fail"
    if summary["audit_evidence_status"] != "pass":
        return "fail"
    if summary["audit_forbidden_fields_absent"] is not True:
        return "fail"
    if summary["pilot_shadow_status"] not in (None, "pass"):
        return "fail"
    if summary["pilot_regression_status"] not in (None, "pass"):
        return "fail"
    if summary["temporal_shadow_status"] not in (None, "pass"):
        return "fail"
    if summary["temporal_independent_review_status"] not in (None, "pass"):
        return "fail"
    if summary["temporal_study_attestation_verification_status"] not in (
        None,
        "pass",
    ):
        return "fail"
    if summary["temporal_shadow_telemetry_validation_status"] not in (None, "pass"):
        return "fail"
    if summary["pilot_gate_status"] not in (None, "pass"):
        return "fail"
    if summary["kids_preprod_dry_run_status"] not in (None, "pass"):
        return "fail"
    if summary["community_surface_status"] not in (None, "pass"):
        return "fail"
    if summary["world_lifecycle_status"] not in (None, "pass"):
        return "fail"
    if summary["world_performance_status"] not in (None, "pass"):
        return "fail"
    if summary["refactor_diff_status"] not in (None, "pass"):
        return "fail"
    if summary["apple_artifact_status"] not in (None, "pass"):
        return "fail"
    return "pass"


def attach_payload_details(
    artifacts: dict,
    release_payload: dict | None,
    contract_payload: dict | None,
    soak_payload: dict | None,
    smoke_payload: dict | None,
    dataset_payload: dict | None,
    audit_payload: dict | None,
    pilot_shadow_payload: dict | None,
    pilot_regression_payload: dict | None,
    temporal_shadow_payload: dict | None,
    temporal_independent_review_payload: dict | None,
    temporal_study_attestation_verification_payload: dict | None,
    temporal_shadow_telemetry_validation_payload: dict | None,
    pilot_gate_payload: dict | None,
    kids_preprod_dry_run_payload: dict | None,
    community_surface_payload: dict | None,
    world_lifecycle_payload: dict | None,
    world_performance_payload: dict | None,
    refactor_diff_payload: dict | None,
    apple_artifact_payload: dict | None,
) -> None:
    if release_payload is not None:
        artifacts["release_report"]["observed_status"] = release_payload.get("overall_status")
        artifacts["release_report"]["schema_version"] = release_payload.get("schema_version")
        artifacts["release_report"]["operator_summary"] = release_operator_summary(
            release_payload
        )
        inference = social_context_inference_snapshot(release_payload)
        if inference is not None:
            artifacts["release_report"]["social_context_inference"] = {
                "passed": inference.get("passed"),
                "total_expectations": inference.get("total_expectations"),
                "passed_expectations": inference.get("passed_expectations"),
                "failed_expectations": inference.get("failed_expectations"),
            }
    if contract_payload is not None:
        artifacts["contract_evidence"]["runtime_release_version"] = contract_payload.get(
            "runtime_release_version"
        )
        artifacts["contract_evidence"]["wire_package"] = contract_payload.get("wire", {}).get(
            "proto_package"
        )
    if soak_payload is not None:
        artifacts["ffi_soak"]["observed_status"] = soak_payload.get("status")
        artifacts["ffi_soak"]["failure_policy_version"] = soak_payload.get(
            "failure_policy_version"
        )
        artifacts["ffi_soak"]["failure_highlights"] = soak_payload.get(
            "failure_highlights", []
        )
    if smoke_payload is not None and "ffi_smoke" in artifacts:
        artifacts["ffi_smoke"]["observed_status"] = smoke_payload.get("status")
        artifacts["ffi_smoke"]["mode"] = smoke_payload.get("mode")
        artifacts["ffi_smoke"]["compiler"] = smoke_payload.get("compiler")
        artifacts["ffi_smoke"]["note"] = smoke_payload.get("note")
    if dataset_payload is not None:
        artifacts["dataset_evidence"]["observed_status"] = dataset_payload.get("status")
        artifacts["dataset_evidence"]["dataset_count"] = len(dataset_payload.get("datasets", []))
    if audit_payload is not None:
        artifacts["audit_evidence"]["observed_status"] = audit_payload.get("status")
        artifacts["audit_evidence"]["audit_schema_version"] = audit_payload.get(
            "audit_schema_version"
        )
        artifacts["audit_evidence"]["forbidden_fields_absent"] = audit_payload.get(
            "forbidden_fields_absent"
        )
    if pilot_shadow_payload is not None:
        artifacts["pilot_shadow_bundle"]["observed_status"] = pilot_shadow_status(
            pilot_shadow_payload
        )
        artifacts["pilot_shadow_bundle"]["schema_version"] = pilot_shadow_payload.get(
            "schema_version"
        )
        artifacts["pilot_shadow_bundle"]["source_kind"] = pilot_shadow_payload.get(
            "source_kind"
        )
        artifacts["pilot_shadow_bundle"]["finding_count"] = pilot_shadow_payload.get(
            "summary", {}
        ).get("finding_count")
        artifacts["pilot_shadow_bundle"]["total_events"] = pilot_shadow_payload.get(
            "summary", {}
        ).get("total_events")
        artifacts["pilot_shadow_bundle"]["raw_text_present"] = pilot_shadow_payload.get(
            "privacy", {}
        ).get("raw_text_present")
        artifacts["pilot_shadow_bundle"][
            "raw_identifier_fields_present"
        ] = pilot_shadow_payload.get("privacy", {}).get("raw_identifier_fields_present")
    if pilot_regression_payload is not None:
        artifacts["pilot_regression_report"]["observed_status"] = pilot_regression_status(
            pilot_regression_payload
        )
        artifacts["pilot_regression_report"]["schema_version"] = pilot_regression_payload.get(
            "schema_version"
        )
        artifacts["pilot_regression_report"]["suite_id"] = pilot_regression_payload.get(
            "manifest", {}
        ).get("suite_id")
        artifacts["pilot_regression_report"]["scenario_count"] = len(
            pilot_regression_payload.get("scenarios", [])
        )
    if temporal_shadow_payload is not None:
        artifacts["temporal_shadow_report"]["observed_status"] = temporal_shadow_status(
            temporal_shadow_payload
        )
        artifacts["temporal_shadow_report"]["schema_version"] = temporal_shadow_payload.get(
            "schema_version"
        )
        metrics = temporal_shadow_payload.get("metrics", {})
        artifacts["temporal_shadow_report"]["case_count"] = metrics.get("total_cases")
        artifacts["temporal_shadow_report"]["event_count"] = metrics.get("total_events")
        artifacts["temporal_shadow_report"]["adversarial_variant_count"] = metrics.get(
            "adversarial_variants"
        )
        artifacts["temporal_shadow_report"]["adversarial_mismatch_count"] = metrics.get(
            "adversarial_mismatch_variants"
        )
        artifacts["temporal_shadow_report"]["runtime_policy_enabled"] = (
            temporal_shadow_payload.get("runtime_policy_enabled")
        )
    if temporal_independent_review_payload is not None:
        artifacts["temporal_independent_review_report"][
            "observed_status"
        ] = temporal_independent_review_status(temporal_independent_review_payload)
        artifacts["temporal_independent_review_report"][
            "schema_version"
        ] = temporal_independent_review_payload.get("schema_version")
        artifacts["temporal_independent_review_report"][
            "blinding_assurance"
        ] = temporal_independent_review_payload.get("blinding_assurance")
        artifacts["temporal_independent_review_report"][
            "preregistration_assurance"
        ] = temporal_independent_review_payload.get("preregistration_assurance")
        artifacts["temporal_independent_review_report"][
            "study_corpus_class"
        ] = temporal_independent_review_payload.get("study_corpus_class")
        artifacts["temporal_independent_review_report"][
            "study_commitment_canonical_sha256"
        ] = temporal_independent_review_payload.get(
            "study_commitment_canonical_sha256"
        )
        review_metrics = temporal_independent_review_payload.get("metrics", {})
        artifacts["temporal_independent_review_report"]["corpus_cases"] = review_metrics.get(
            "corpus_cases"
        )
        artifacts["temporal_independent_review_report"][
            "independently_reviewed_cases"
        ] = review_metrics.get("cases_with_two_independent_reviews")
        artifacts["temporal_independent_review_report"][
            "exact_set_pair_agreement_rate"
        ] = review_metrics.get("exact_set_pair_agreement_rate")
        artifacts["temporal_independent_review_report"][
            "krippendorff_alpha_nominal"
        ] = review_metrics.get("krippendorff_alpha_nominal")
    if temporal_study_attestation_verification_payload is not None:
        artifact = artifacts["temporal_study_attestation_verification"]
        artifact["observed_status"] = temporal_study_attestation_verification_status(
            temporal_study_attestation_verification_payload,
            temporal_independent_review_payload,
        )
        for field in (
            "schema_version",
            "signature_algorithm",
            "key_id",
            "study_id",
            "corpus_class",
            "commitment_canonical_sha256",
            "public_key_spki_sha256",
            "trusted_timestamp_assurance",
        ):
            artifact[field] = temporal_study_attestation_verification_payload.get(field)
    if temporal_shadow_telemetry_validation_payload is not None:
        artifacts["temporal_shadow_telemetry_validation"][
            "observed_status"
        ] = temporal_shadow_telemetry_validation_status(
            temporal_shadow_telemetry_validation_payload
        )
        artifacts["temporal_shadow_telemetry_validation"][
            "schema_version"
        ] = temporal_shadow_telemetry_validation_payload.get("schema_version")
        artifacts["temporal_shadow_telemetry_validation"]["deployments"] = {
            deployment: {
                "evaluated_inputs": temporal_shadow_telemetry_validation_payload.get(
                    deployment, {}
                )
                .get("metrics", {})
                .get("evaluated_inputs"),
                "runtime_policy_enabled": temporal_shadow_telemetry_validation_payload.get(
                    deployment, {}
                ).get("runtime_policy_enabled"),
                "action_execution_enabled": temporal_shadow_telemetry_validation_payload.get(
                    deployment, {}
                ).get("action_execution_enabled"),
            }
            for deployment in ("on_prem", "adk")
        }
    if pilot_gate_payload is not None:
        artifacts["pilot_gate_report"]["observed_status"] = pilot_gate_status(
            pilot_gate_payload
        )
        artifacts["pilot_gate_report"]["schema_version"] = pilot_gate_payload.get(
            "schema_version"
        )
        artifacts["pilot_gate_report"]["shadow_run_count"] = len(
            pilot_gate_payload.get("shadow_runs", [])
        )
        artifacts["pilot_gate_report"]["check_count"] = len(
            pilot_gate_payload.get("checks", [])
        )
    if kids_preprod_dry_run_payload is not None:
        artifacts["kids_preprod_dry_run_report"][
            "observed_status"
        ] = kids_preprod_dry_run_status(kids_preprod_dry_run_payload)
        artifacts["kids_preprod_dry_run_report"][
            "schema_version"
        ] = kids_preprod_dry_run_payload.get("schema_version")
        checks = kids_preprod_dry_run_payload.get("checks", {})
        if isinstance(checks, dict):
            artifacts["kids_preprod_dry_run_report"]["checks_failed"] = len(
                [value for value in checks.values() if value is False]
            )
            artifacts["kids_preprod_dry_run_report"]["checks_passed"] = len(
                [value for value in checks.values() if value is True]
            )
        else:
            artifacts["kids_preprod_dry_run_report"]["checks_failed"] = None
            artifacts["kids_preprod_dry_run_report"]["checks_passed"] = None
    if community_surface_payload is not None:
        artifacts["community_surface_report"]["observed_status"] = community_surface_status(
            community_surface_payload
        )
        artifacts["community_surface_report"]["schema_version"] = community_surface_payload.get(
            "schema_version"
        )
        artifacts["community_surface_report"]["total_events"] = community_surface_payload.get(
            "total_events"
        )
        artifacts["community_surface_report"]["finding_count"] = len(
            community_surface_payload.get("findings", [])
        )
        artifacts["community_surface_report"]["gates_passed"] = (
            community_surface_payload.get("gates", {}).get("passed")
        )
    if world_lifecycle_payload is not None:
        artifacts["world_lifecycle_report"]["observed_status"] = world_lifecycle_status(
            world_lifecycle_payload
        )
        artifacts["world_lifecycle_report"]["schema_version"] = world_lifecycle_payload.get(
            "schema_version"
        )
        artifacts["world_lifecycle_report"]["total_worlds"] = world_lifecycle_payload.get(
            "total_worlds"
        )
        artifacts["world_lifecycle_report"]["total_events"] = world_lifecycle_payload.get(
            "total_events"
        )
        artifacts["world_lifecycle_report"]["threat_events"] = world_lifecycle_payload.get(
            "threat_events"
        )
        artifacts["world_lifecycle_report"]["finding_count"] = world_lifecycle_payload.get(
            "total_findings"
        )
    if world_performance_payload is not None:
        artifacts["world_performance_report"][
            "observed_status"
        ] = world_performance_status(world_performance_payload)
        artifacts["world_performance_report"][
            "schema_version"
        ] = world_performance_payload.get("schema_version")
        artifacts["world_performance_report"]["tier_count"] = len(
            world_performance_payload.get("tiers", [])
        )
        artifacts["world_performance_report"]["tiers"] = [
            {
                "tier": tier.get("tier"),
                "status": tier.get("status"),
                "total_events": tier.get("total_events"),
                "elapsed_seconds": tier.get("timing", {}).get("elapsed_seconds"),
                "max_rss_mb": tier.get("timing", {}).get("max_rss_mb"),
            }
            for tier in world_performance_payload.get("tiers", [])
            if isinstance(tier, dict)
        ]
    if refactor_diff_payload is not None:
        artifacts["refactor_diff_report"][
            "observed_status"
        ] = refactor_diff_status(refactor_diff_payload)
        artifacts["refactor_diff_report"][
            "schema_version"
        ] = refactor_diff_payload.get("schema_version")
        diff_summary = refactor_diff_payload.get("summary", {})
        artifacts["refactor_diff_report"]["change_count"] = diff_summary.get(
            "change_count"
        )
        artifacts["refactor_diff_report"]["regression_count"] = diff_summary.get(
            "regression"
        )
        artifacts["refactor_diff_report"][
            "approved_safety_improvement_count"
        ] = diff_summary.get("approved_safety_improvement")
        artifacts["refactor_diff_report"][
            "structural_only_count"
        ] = diff_summary.get("structural_only")
    if apple_artifact_payload is not None:
        artifacts["apple_artifact_verification"][
            "observed_status"
        ] = apple_artifact_status(apple_artifact_payload)
        artifacts["apple_artifact_verification"][
            "schema_version"
        ] = apple_artifact_payload.get("schema_version")
        artifacts["apple_artifact_verification"]["shippable"] = (
            apple_artifact_payload.get("shippable")
        )
        artifacts["apple_artifact_verification"]["source_revision"] = (
            apple_artifact_payload.get("source_revision")
        )
        artifacts["apple_artifact_verification"]["source_tree_sha256"] = (
            apple_artifact_payload.get("source_tree_sha256")
        )
        artifacts["apple_artifact_verification"]["slice_count"] = len(
            apple_artifact_payload.get("slices", [])
        )


def main() -> int:
    args = parse_args()

    release_payload, release_artifact = load_json_artifact(args.release_report, required=True)
    contract_payload, contract_artifact = load_json_artifact(args.contract_evidence, required=True)
    soak_payload, soak_artifact = load_json_artifact(args.ffi_soak, required=True)
    dataset_payload, dataset_artifact = load_json_artifact(args.dataset_evidence, required=True)
    audit_payload, audit_artifact = load_json_artifact(args.audit_evidence, required=True)
    pilot_shadow_payload, pilot_shadow_artifact = load_json_artifact(
        args.pilot_shadow_bundle, required=args.pilot_shadow_bundle is not None
    ) if args.pilot_shadow_bundle else (None, None)
    pilot_regression_payload, pilot_regression_artifact = load_json_artifact(
        args.pilot_regression_report, required=args.pilot_regression_report is not None
    ) if args.pilot_regression_report else (None, None)
    temporal_shadow_payload, temporal_shadow_artifact = load_json_artifact(
        args.temporal_shadow_report, required=args.temporal_shadow_report is not None
    ) if args.temporal_shadow_report else (None, None)
    temporal_independent_review_payload, temporal_independent_review_artifact = (
        load_json_artifact(
            args.temporal_independent_review_report,
            required=args.temporal_independent_review_report is not None,
        )
        if args.temporal_independent_review_report
        else (None, None)
    )
    (
        temporal_study_attestation_verification_payload,
        temporal_study_attestation_verification_artifact,
    ) = (
        load_json_artifact(
            args.temporal_study_attestation_verification,
            required=args.temporal_study_attestation_verification is not None,
        )
        if args.temporal_study_attestation_verification
        else (None, None)
    )
    (
        temporal_shadow_telemetry_validation_payload,
        temporal_shadow_telemetry_validation_artifact,
    ) = (
        load_json_artifact(
            args.temporal_shadow_telemetry_validation,
            required=args.temporal_shadow_telemetry_validation is not None,
        )
        if args.temporal_shadow_telemetry_validation
        else (None, None)
    )
    pilot_gate_payload, pilot_gate_artifact = load_json_artifact(
        args.pilot_gate_report, required=args.pilot_gate_report is not None
    ) if args.pilot_gate_report else (None, None)
    kids_preprod_dry_run_payload, kids_preprod_dry_run_artifact = load_json_artifact(
        args.kids_preprod_dry_run_report,
        required=args.kids_preprod_dry_run_report is not None,
    ) if args.kids_preprod_dry_run_report else (None, None)
    community_surface_payload, community_surface_artifact = load_json_artifact(
        args.community_surface_report,
        required=args.community_surface_report is not None,
    ) if args.community_surface_report else (None, None)
    world_lifecycle_payload, world_lifecycle_artifact = load_json_artifact(
        args.world_lifecycle_report,
        required=args.world_lifecycle_report is not None,
    ) if args.world_lifecycle_report else (None, None)
    world_performance_payload, world_performance_artifact = load_json_artifact(
        args.world_performance_report,
        required=args.world_performance_report is not None,
    ) if args.world_performance_report else (None, None)
    refactor_diff_payload, refactor_diff_artifact = load_json_artifact(
        args.refactor_diff_report,
        required=args.refactor_diff_report is not None,
    ) if args.refactor_diff_report else (None, None)
    apple_artifact_payload, apple_artifact_artifact = load_json_artifact(
        args.apple_artifact_verification,
        required=args.apple_artifact_verification is not None,
    ) if args.apple_artifact_verification else (None, None)
    smoke_payload, smoke_artifact = load_json_artifact(
        args.ffi_smoke, required=args.ffi_smoke is not None
    ) if args.ffi_smoke else (None, None)

    artifacts = {
        "release_report": release_artifact,
        "contract_evidence": contract_artifact,
        "ffi_soak": soak_artifact,
        "dataset_evidence": dataset_artifact,
        "audit_evidence": audit_artifact,
    }
    if pilot_shadow_artifact is not None:
        artifacts["pilot_shadow_bundle"] = pilot_shadow_artifact
    if pilot_regression_artifact is not None:
        artifacts["pilot_regression_report"] = pilot_regression_artifact
    if temporal_shadow_artifact is not None:
        artifacts["temporal_shadow_report"] = temporal_shadow_artifact
    if temporal_independent_review_artifact is not None:
        artifacts[
            "temporal_independent_review_report"
        ] = temporal_independent_review_artifact
    if temporal_study_attestation_verification_artifact is not None:
        artifacts[
            "temporal_study_attestation_verification"
        ] = temporal_study_attestation_verification_artifact
    if temporal_shadow_telemetry_validation_artifact is not None:
        artifacts[
            "temporal_shadow_telemetry_validation"
        ] = temporal_shadow_telemetry_validation_artifact
    if pilot_gate_artifact is not None:
        artifacts["pilot_gate_report"] = pilot_gate_artifact
    if kids_preprod_dry_run_artifact is not None:
        artifacts["kids_preprod_dry_run_report"] = kids_preprod_dry_run_artifact
    if community_surface_artifact is not None:
        artifacts["community_surface_report"] = community_surface_artifact
    if world_lifecycle_artifact is not None:
        artifacts["world_lifecycle_report"] = world_lifecycle_artifact
    if world_performance_artifact is not None:
        artifacts["world_performance_report"] = world_performance_artifact
    if refactor_diff_artifact is not None:
        artifacts["refactor_diff_report"] = refactor_diff_artifact
    if apple_artifact_artifact is not None:
        artifacts["apple_artifact_verification"] = apple_artifact_artifact
    if smoke_artifact is not None:
        artifacts["ffi_smoke"] = smoke_artifact

    attach_payload_details(
        artifacts,
        release_payload=release_payload,
        contract_payload=contract_payload,
        soak_payload=soak_payload,
        smoke_payload=smoke_payload,
        dataset_payload=dataset_payload,
        audit_payload=audit_payload,
        pilot_shadow_payload=pilot_shadow_payload,
        pilot_regression_payload=pilot_regression_payload,
        temporal_shadow_payload=temporal_shadow_payload,
        temporal_independent_review_payload=temporal_independent_review_payload,
        temporal_study_attestation_verification_payload=(
            temporal_study_attestation_verification_payload
        ),
        temporal_shadow_telemetry_validation_payload=(
            temporal_shadow_telemetry_validation_payload
        ),
        pilot_gate_payload=pilot_gate_payload,
        kids_preprod_dry_run_payload=kids_preprod_dry_run_payload,
        community_surface_payload=community_surface_payload,
        world_lifecycle_payload=world_lifecycle_payload,
        world_performance_payload=world_performance_payload,
        refactor_diff_payload=refactor_diff_payload,
        apple_artifact_payload=apple_artifact_payload,
    )

    request_limits = (
        contract_payload.get("abi", {}).get("request_limits_bytes", [])
        if contract_payload is not None
        else []
    )
    release_inference = social_context_inference_snapshot(release_payload)
    summary = {
        "runtime_release_version": (
            contract_payload.get("runtime_release_version") if contract_payload else None
        ),
        "wire_package": (
            contract_payload.get("wire", {}).get("proto_package") if contract_payload else None
        ),
        "wire_major_version": (
            contract_payload.get("wire", {}).get("wire_major_version") if contract_payload else None
        ),
        "state_schema_version": (
            contract_payload.get("persisted_state", {}).get("schema_version")
            if contract_payload
            else None
        ),
        "release_report_status": release_status(release_payload),
        "release_report_schema_version": (
            release_payload.get("schema_version") if release_payload else None
        ),
        "release_operator_summary": release_operator_summary(release_payload),
        "release_social_context_inference_passed": (
            release_inference.get("passed") if release_inference else None
        ),
        "release_social_context_inference_total_expectations": (
            release_inference.get("total_expectations") if release_inference else None
        ),
        "release_social_context_inference_failed_expectations": (
            release_inference.get("failed_expectations") if release_inference else None
        ),
        "ffi_request_limit_count": len(request_limits),
        "ffi_import_context_max_bytes": next(
            (
                item.get("max_bytes")
                for item in request_limits
                if item.get("constant_name") == "MAX_IMPORT_CONTEXT_REQUEST_BYTES"
            ),
            None,
        ),
        "ffi_soak_status": soak_status(soak_payload),
        "ffi_soak_iterations": soak_payload.get("iterations") if soak_payload else None,
        "ffi_soak_attempts_run": soak_payload.get("attempts_run") if soak_payload else None,
        "ffi_soak_failure_category": (
            soak_payload.get("failure_category") if soak_payload else None
        ),
        "ffi_soak_failure_summary": (
            soak_payload.get("failure_summary") if soak_payload else None
        ),
        "ffi_smoke_status": smoke_status(smoke_payload),
        "ffi_smoke_mode": smoke_payload.get("mode") if smoke_payload else None,
        "ffi_smoke_compiler": smoke_payload.get("compiler") if smoke_payload else None,
        "ffi_smoke_note": smoke_payload.get("note") if smoke_payload else None,
        "dataset_evidence_status": dataset_status(dataset_payload),
        "dataset_count": len(dataset_payload.get("datasets", [])) if dataset_payload else None,
        "audit_evidence_status": audit_status(audit_payload),
        "audit_schema_version": (
            audit_payload.get("audit_schema_version") if audit_payload else None
        ),
        "audit_forbidden_fields_absent": (
            audit_payload.get("forbidden_fields_absent") if audit_payload else None
        ),
        "pilot_shadow_status": pilot_shadow_status(pilot_shadow_payload),
        "pilot_shadow_schema_version": (
            pilot_shadow_payload.get("schema_version") if pilot_shadow_payload else None
        ),
        "pilot_shadow_source_kind": (
            pilot_shadow_payload.get("source_kind") if pilot_shadow_payload else None
        ),
        "pilot_shadow_total_events": (
            pilot_shadow_payload.get("summary", {}).get("total_events")
            if pilot_shadow_payload
            else None
        ),
        "pilot_shadow_finding_count": (
            pilot_shadow_payload.get("summary", {}).get("finding_count")
            if pilot_shadow_payload
            else None
        ),
        "pilot_shadow_raw_text_present": (
            pilot_shadow_payload.get("privacy", {}).get("raw_text_present")
            if pilot_shadow_payload
            else None
        ),
        "pilot_shadow_raw_identifier_fields_present": (
            pilot_shadow_payload.get("privacy", {}).get("raw_identifier_fields_present")
            if pilot_shadow_payload
            else None
        ),
        "pilot_regression_status": pilot_regression_status(pilot_regression_payload),
        "pilot_regression_schema_version": (
            pilot_regression_payload.get("schema_version") if pilot_regression_payload else None
        ),
        "pilot_regression_suite_id": (
            pilot_regression_payload.get("manifest", {}).get("suite_id")
            if pilot_regression_payload
            else None
        ),
        "pilot_regression_scenario_count": (
            len(pilot_regression_payload.get("scenarios", []))
            if pilot_regression_payload
            else None
        ),
        "temporal_shadow_status": temporal_shadow_status(temporal_shadow_payload),
        "temporal_shadow_schema_version": (
            temporal_shadow_payload.get("schema_version")
            if temporal_shadow_payload
            else None
        ),
        "temporal_shadow_case_count": (
            temporal_shadow_payload.get("metrics", {}).get("total_cases")
            if temporal_shadow_payload
            else None
        ),
        "temporal_shadow_event_count": (
            temporal_shadow_payload.get("metrics", {}).get("total_events")
            if temporal_shadow_payload
            else None
        ),
        "temporal_shadow_adversarial_variant_count": (
            temporal_shadow_payload.get("metrics", {}).get("adversarial_variants")
            if temporal_shadow_payload
            else None
        ),
        "temporal_shadow_adversarial_mismatch_count": (
            temporal_shadow_payload.get("metrics", {}).get(
                "adversarial_mismatch_variants"
            )
            if temporal_shadow_payload
            else None
        ),
        "temporal_shadow_runtime_policy_enabled": (
            temporal_shadow_payload.get("runtime_policy_enabled")
            if temporal_shadow_payload
            else None
        ),
        "temporal_independent_review_status": temporal_independent_review_status(
            temporal_independent_review_payload
        ),
        "temporal_independent_review_schema_version": (
            temporal_independent_review_payload.get("schema_version")
            if temporal_independent_review_payload
            else None
        ),
        "temporal_independent_review_blinding_assurance": (
            temporal_independent_review_payload.get("blinding_assurance")
            if temporal_independent_review_payload
            else None
        ),
        "temporal_independent_review_blind_packet_id": (
            temporal_independent_review_payload.get("blind_packet_id")
            if temporal_independent_review_payload
            else None
        ),
        "temporal_independent_review_blind_packet_sha256": (
            temporal_independent_review_payload.get("blind_packet_canonical_sha256")
            if temporal_independent_review_payload
            else None
        ),
        "temporal_independent_review_preregistration_assurance": (
            temporal_independent_review_payload.get("preregistration_assurance")
            if temporal_independent_review_payload
            else None
        ),
        "temporal_independent_review_study_id": (
            temporal_independent_review_payload.get("study_id")
            if temporal_independent_review_payload
            else None
        ),
        "temporal_independent_review_study_corpus_class": (
            temporal_independent_review_payload.get("study_corpus_class")
            if temporal_independent_review_payload
            else None
        ),
        "temporal_independent_review_preregistration_sha256": (
            temporal_independent_review_payload.get("preregistration_canonical_sha256")
            if temporal_independent_review_payload
            else None
        ),
        "temporal_independent_review_study_commitment_sha256": (
            temporal_independent_review_payload.get(
                "study_commitment_canonical_sha256"
            )
            if temporal_independent_review_payload
            else None
        ),
        "temporal_independent_review_exact_set_pair_agreement_rate": (
            temporal_independent_review_payload.get("metrics", {}).get(
                "exact_set_pair_agreement_rate"
            )
            if temporal_independent_review_payload
            else None
        ),
        "temporal_independent_review_krippendorff_alpha_nominal": (
            temporal_independent_review_payload.get("metrics", {}).get(
                "krippendorff_alpha_nominal"
            )
            if temporal_independent_review_payload
            else None
        ),
        "temporal_independent_review_case_count": (
            temporal_independent_review_payload.get("metrics", {}).get("corpus_cases")
            if temporal_independent_review_payload
            else None
        ),
        "temporal_independently_reviewed_case_count": (
            temporal_independent_review_payload.get("metrics", {}).get(
                "cases_with_two_independent_reviews"
            )
            if temporal_independent_review_payload
            else None
        ),
        "temporal_study_attestation_verification_status": (
            temporal_study_attestation_verification_status(
                temporal_study_attestation_verification_payload,
                temporal_independent_review_payload,
            )
        ),
        "temporal_study_attestation_key_id": (
            temporal_study_attestation_verification_payload.get("key_id")
            if temporal_study_attestation_verification_payload
            else None
        ),
        "temporal_study_attestation_public_key_spki_sha256": (
            temporal_study_attestation_verification_payload.get(
                "public_key_spki_sha256"
            )
            if temporal_study_attestation_verification_payload
            else None
        ),
        "temporal_study_attestation_trusted_timestamp_assurance": (
            temporal_study_attestation_verification_payload.get(
                "trusted_timestamp_assurance"
            )
            if temporal_study_attestation_verification_payload
            else None
        ),
        "temporal_shadow_telemetry_validation_status": (
            temporal_shadow_telemetry_validation_status(
                temporal_shadow_telemetry_validation_payload
            )
        ),
        "temporal_policy_activation_readiness": temporal_policy_activation_readiness(
            temporal_shadow_payload,
            temporal_independent_review_payload,
            temporal_shadow_telemetry_validation_payload,
            temporal_study_attestation_verification_payload,
        ),
        "temporal_shadow_telemetry_on_prem_inputs": (
            temporal_shadow_telemetry_validation_payload.get("on_prem", {})
            .get("metrics", {})
            .get("evaluated_inputs")
            if temporal_shadow_telemetry_validation_payload
            else None
        ),
        "temporal_shadow_telemetry_adk_inputs": (
            temporal_shadow_telemetry_validation_payload.get("adk", {})
            .get("metrics", {})
            .get("evaluated_inputs")
            if temporal_shadow_telemetry_validation_payload
            else None
        ),
        "pilot_gate_status": pilot_gate_status(pilot_gate_payload),
        "pilot_gate_schema_version": (
            pilot_gate_payload.get("schema_version") if pilot_gate_payload else None
        ),
        "pilot_gate_shadow_run_count": (
            len(pilot_gate_payload.get("shadow_runs", []))
            if pilot_gate_payload
            else None
        ),
        "pilot_gate_check_count": (
            len(pilot_gate_payload.get("checks", []))
            if pilot_gate_payload
            else None
        ),
        "kids_preprod_dry_run_status": kids_preprod_dry_run_status(
            kids_preprod_dry_run_payload
        ),
        "kids_preprod_dry_run_schema_version": (
            kids_preprod_dry_run_payload.get("schema_version")
            if kids_preprod_dry_run_payload
            else None
        ),
        "kids_preprod_dry_run_checks_failed": (
            len(
                [
                    value
                    for value in kids_preprod_dry_run_payload.get("checks", {}).values()
                    if value is False
                ]
            )
            if kids_preprod_dry_run_payload
            and isinstance(kids_preprod_dry_run_payload.get("checks"), dict)
            else None
        ),
        "community_surface_status": community_surface_status(community_surface_payload),
        "community_surface_schema_version": (
            community_surface_payload.get("schema_version")
            if community_surface_payload
            else None
        ),
        "community_surface_total_events": (
            community_surface_payload.get("total_events")
            if community_surface_payload
            else None
        ),
        "community_surface_detect_rate": (
            community_surface_payload.get("total", {}).get("detect_rate")
            if community_surface_payload
            else None
        ),
        "community_surface_fp_rate": (
            community_surface_payload.get("total", {}).get("fp_rate")
            if community_surface_payload
            else None
        ),
        "community_surface_finding_count": (
            len(community_surface_payload.get("findings", []))
            if community_surface_payload
            else None
        ),
        "community_surface_scenario_count": (
            len(community_surface_payload.get("by_scenario", []))
            if community_surface_payload
            else None
        ),
        "community_surface_text_variant_count": (
            len(community_surface_payload.get("by_text_variant", []))
            if community_surface_payload
            else None
        ),
        "world_lifecycle_status": world_lifecycle_status(world_lifecycle_payload),
        "world_lifecycle_schema_version": (
            world_lifecycle_payload.get("schema_version") if world_lifecycle_payload else None
        ),
        "world_lifecycle_total_worlds": (
            world_lifecycle_payload.get("total_worlds") if world_lifecycle_payload else None
        ),
        "world_lifecycle_total_events": (
            world_lifecycle_payload.get("total_events") if world_lifecycle_payload else None
        ),
        "world_lifecycle_threat_events": (
            world_lifecycle_payload.get("threat_events") if world_lifecycle_payload else None
        ),
        "world_lifecycle_finding_count": (
            world_lifecycle_payload.get("total_findings") if world_lifecycle_payload else None
        ),
        "world_performance_status": world_performance_status(
            world_performance_payload
        ),
        "world_performance_schema_version": (
            world_performance_payload.get("schema_version")
            if world_performance_payload
            else None
        ),
        "world_performance_tier_count": (
            len(world_performance_payload.get("tiers", []))
            if world_performance_payload
            else None
        ),
        "refactor_diff_status": refactor_diff_status(refactor_diff_payload),
        "refactor_diff_schema_version": (
            refactor_diff_payload.get("schema_version")
            if refactor_diff_payload
            else None
        ),
        "refactor_diff_change_count": (
            refactor_diff_payload.get("summary", {}).get("change_count")
            if refactor_diff_payload
            else None
        ),
        "refactor_diff_regression_count": (
            refactor_diff_payload.get("summary", {}).get("regression")
            if refactor_diff_payload
            else None
        ),
        "refactor_diff_structural_only_count": (
            refactor_diff_payload.get("summary", {}).get("structural_only")
            if refactor_diff_payload
            else None
        ),
        "refactor_diff_approved_safety_improvement_count": (
            refactor_diff_payload.get("summary", {}).get(
                "approved_safety_improvement"
            )
            if refactor_diff_payload
            else None
        ),
        "apple_artifact_status": apple_artifact_status(apple_artifact_payload),
        "apple_artifact_schema_version": (
            apple_artifact_payload.get("schema_version")
            if apple_artifact_payload
            else None
        ),
        "apple_artifact_shippable": (
            apple_artifact_payload.get("shippable")
            if apple_artifact_payload
            else None
        ),
        "apple_artifact_source_revision": (
            apple_artifact_payload.get("source_revision")
            if apple_artifact_payload
            else None
        ),
        "apple_artifact_source_tree_sha256": (
            apple_artifact_payload.get("source_tree_sha256")
            if apple_artifact_payload
            else None
        ),
        "apple_artifact_slice_count": (
            len(apple_artifact_payload.get("slices", []))
            if apple_artifact_payload
            else None
        ),
        "ffi_export_count": (
            len(contract_payload.get("abi", {}).get("exported_functions", []))
            if contract_payload
            else None
        ),
    }

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": now_utc(),
        "label": args.label,
        "evidence_status": None,
        "summary": summary,
        "artifacts": artifacts,
    }
    manifest["evidence_status"] = evidence_status(artifacts, summary)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0 if manifest["evidence_status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
