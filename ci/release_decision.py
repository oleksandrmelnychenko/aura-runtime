#!/usr/bin/env python3

import argparse
import base64
import binascii
import hmac
import json
import math
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

try:
    from ci import evidence_attestation as crypto_support
    from ci import pilot_signoff_verification as pilot_signoff_support
except ModuleNotFoundError:  # Direct execution from the ci/ directory.
    import evidence_attestation as crypto_support
    import pilot_signoff_verification as pilot_signoff_support


DECISION_SCHEMA_VERSION = "aura.release_decision.v3"
PRODUCT_ACCEPTANCE_SCHEMA_VERSION = "aura.product_integration_acceptance.v2"
ATTESTATION_SCHEMA_VERSION = "aura.release_decision_attestation.v3"
VERIFICATION_SCHEMA_VERSION = "aura.release_decision_attestation_verification.v3"
APPLE_REPRODUCIBILITY_SCHEMA_VERSION = "aura.apple_artifact_reproducibility.v1"
PROFILE = "agent-kids-rules-context"
SIGNATURE_ALGORITHM = "Ed25519"
SIGNED_PAYLOAD_DOMAIN = b"aura.release-decision.attestation.v3\x00"
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_ATTESTATION_BYTES = 64 * 1024

LOWERCASE_SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_REVISION = re.compile(r"[0-9a-f]{40}")
RUNTIME_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")

DECISION_FIELDS = {
    "schema_version",
    "generated_at_utc",
    "candidate",
    "profile",
    "source_revision",
    "artifact_revision",
    "release_revision",
    "source_tree_sha256",
    "evidence_attestation_sha256",
    "evidence_signer_signature_algorithm",
    "evidence_signer_key_id",
    "evidence_signer_spki_sha256",
    "evidence_signer_manifest_sha256",
    "pilot_signoff_trust_policy_sha256",
    "pilot_signoff_policy_id",
    "pilot_signoff_policy_epoch",
    "pilot_signoff_signer_spki_sha256",
    "pilot_signoff_signer_spki_set_sha256",
    "artifact_integrity",
    "runtime_safety",
    "contract_compatibility",
    "product_integration",
    "privacy_security",
    "operational_readiness",
    "model_readiness",
    "relay_readiness",
    "human_signoffs",
    "profile_scope",
    "decision",
    "blocking_reasons",
    "artifacts",
}
ARTIFACT_FIELDS = {
    "required",
    "present",
    "bytes",
    "sha256",
    "schema_version",
    "observed_status",
}
PRODUCT_ACCEPTANCE_FIELDS = {
    "schema_version",
    "status",
    "profile",
    "candidate_revision",
    "source_revision",
    "source_tree_sha256",
    "evidence_manifest_sha256",
    "evidence_attestation_sha256",
    "evidence_attestation_verification_sha256",
    "evidence_signer_spki_sha256",
    "apple_artifact_verification_sha256",
    "apple_artifact_reproducibility_sha256",
    "apple_release_manifest_sha256",
    "pilot_gate_report_sha256",
    "runtime_artifact_descriptor_sha256",
    "runtime_capabilities_sha256",
    "local_decision_contract",
    "terminal_checkpoint_contract",
    "restart_replay_contract",
    "exact_artifact_pin",
    "artifact_revision",
    "release_revision",
    "model_enabled",
    "relay_enabled",
    "military_enabled",
}
ATTESTATION_FIELDS = {
    "schema_version",
    "signature_algorithm",
    "key_id",
    "decision_sha256",
    "candidate",
    "profile",
    "source_revision",
    "artifact_revision",
    "release_revision",
    "evidence_signer_key_id",
    "evidence_signer_spki_sha256",
    "pilot_signoff_trust_policy_sha256",
    "pilot_signoff_policy_id",
    "pilot_signoff_policy_epoch",
    "pilot_signoff_signer_spki_sha256",
    "pilot_signoff_signer_spki_set_sha256",
    "public_key_spki_sha256",
    "signature_base64",
}
REQUIRED_PILOT_CHECKS = {
    "candidate_release_revision",
    "release_gate",
    "release_social_context_inference",
    "pilot_regression",
    "kids_memory_health",
    "kids_preprod_dry_run",
    "shadow_run_count",
    "shadow_event_volume",
    "shadow_privacy_and_findings",
    "shadow_contract_stability",
    "review_signoff_set",
    "review_signoff.false_positive_hotspots",
    "review_signoff.self_harm_boundary_cases",
    "review_signoff.trusted_adult_scenarios",
    "review_signoff.reputation_image_abuse",
}
PILOT_GATE_FIELDS = {
    "schema_version",
    "release_revision",
    "overall_status",
    "config",
    "release",
    "pilot_regression",
    "shadow_runs",
    "kids_memory_health",
    "kids_preprod_dry_run",
    "signoffs",
    "checks",
    "rollback_triggers",
    "operator_review_cadence",
}
PILOT_CONFIG_FIELDS = {
    "min_shadow_runs",
    "min_shadow_total_events",
    "require_release_pass",
    "require_pilot_regression_pass",
    "require_kids_memory_pass",
    "require_kids_preprod_dry_run_pass",
    "required_review_areas",
}
PILOT_RELEASE_FIELDS = {
    "schema_version",
    "overall_status",
    "social_context_inference",
}
PILOT_SOCIAL_CONTEXT_FIELDS = {
    "passed",
    "total_expectations",
    "failed_expectations",
}
PILOT_REGRESSION_FIELDS = {
    "schema_version",
    "overall_status",
    "suite_id",
    "scenario_count",
}
PILOT_SHADOW_FIELDS = {
    "schema_version",
    "source_kind",
    "source_label",
    "wire_package",
    "protection_level",
    "total_events",
    "threat_events",
    "finding_count",
    "raw_text_present",
    "raw_identifier_fields_present",
}
PILOT_KIDS_MEMORY_FIELDS = {
    "schema_version",
    "overall_status",
    "total_memory_hits",
    "missing_mandatory_reason_codes",
}
PILOT_KIDS_PREPROD_FIELDS = {
    "schema_version",
    "overall_status",
    "checks_failed",
}
PILOT_SIGNOFF_FIELDS = {
    "area",
    "reviewer",
    "status",
    "reviewed_at_utc",
    "notes",
    "release_revision",
}
PILOT_CHECK_FIELDS = {"check_id", "status", "summary"}
PILOT_ROLLBACK_TRIGGER_FIELDS = {
    "trigger_id",
    "severity",
    "condition",
    "operator_action",
}
PILOT_REQUIRED_REVIEW_AREAS = (
    "false_positive_hotspots",
    "self_harm_boundary_cases",
    "trusted_adult_scenarios",
    "reputation_image_abuse",
)
PILOT_OPERATOR_REVIEW_CADENCE = (
    "daily for the first 7 pilot days, then every 3 days while stable"
)
PILOT_ROLLBACK_TRIGGERS = (
    {
        "trigger_id": "privacy_shadow_plaintext",
        "severity": "urgent",
        "condition": "any pilot shadow bundle contains raw text or raw identifiers",
        "operator_action": "disable pilot capture and revert to offline replay only",
    },
    {
        "trigger_id": "self_harm_boundary_disagreement",
        "severity": "urgent",
        "condition": (
            "human review finds self-harm boundary cases where supportive replies "
            "are escalated or crisis content is suppressed"
        ),
        "operator_action": "pause live guardian-enabled pilot and return to shadow mode",
    },
    {
        "trigger_id": "trusted_adult_false_positive_hotspot",
        "severity": "high",
        "condition": (
            "trusted-adult educational or supportive traffic accumulates repeated "
            "high-severity interventions"
        ),
        "operator_action": (
            "disable child-facing enforcement for the affected slice and review "
            "recent bundles"
        ),
    },
    {
        "trigger_id": "pilot_slice_regression",
        "severity": "high",
        "condition": (
            "pilot regression corpus or repeated shadow runs regress below the "
            "approved baseline"
        ),
        "operator_action": (
            "block further rollout promotion until the slice is re-approved"
        ),
    },
)
PILOT_USIZE_MAX = (1 << 64) - 1
EXPECTED_APPLE_SLICES = {
    "ios-arm64": ["arm64"],
    "ios-arm64_x86_64-simulator": ["arm64", "x86_64"],
    "ios-arm64_x86_64-maccatalyst": ["arm64", "x86_64"],
}
EXPECTED_APPLE_VERIFICATION_FIELDS = {
    "schema_version",
    "status",
    "shippable",
    "source_revision",
    "source_tree_dirty",
    "source_tree_sha256",
    "runtime_release_version",
    "wire_package",
    "state_schema_version",
    "ffi_contract_version",
    "cargo_features",
    "slices",
}
EXPECTED_APPLE_RELEASE_MANIFEST_FIELDS = {
    "schema_version",
    "source_revision",
    "source_tree_dirty",
    "source_tree_sha256",
    "shippable",
    "cargo_profile",
    "cargo_locked",
    "cargo_features",
    "runtime_release_version",
    "wire_package",
    "wire_major_version",
    "state_schema_version",
    "ffi_contract_version",
    "minimum_ios_version",
    "target_triples",
    "aura_ffi_header_sha256",
    "runtime_capabilities_sha256",
    "runtime_artifact_descriptor_sha256",
    "runtime_artifact_identities_env_sha256",
    "model_manifest_sha256",
    "execution_policy_trust_keyring_sha256",
    "xcframework_info_plist_sha256",
    "binary_sha256",
    "model_bundle_included",
}
EXPECTED_APPLE_TARGET_TRIPLES = [
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "x86_64-apple-ios",
    "aarch64-apple-ios-macabi",
    "x86_64-apple-ios-macabi",
]
EXPECTED_APPLE_ARTIFACT_PATHS = (
    "AuraAgentFFI.xcframework/Info.plist",
    "AuraAgentFFI.xcframework/ios-arm64/Headers/aura_ffi.h",
    "AuraAgentFFI.xcframework/ios-arm64/libaura_agent_ffi.a",
    "AuraAgentFFI.xcframework/ios-arm64_x86_64-maccatalyst/Headers/aura_ffi.h",
    "AuraAgentFFI.xcframework/ios-arm64_x86_64-maccatalyst/libaura_agent_ffi_maccatalyst.a",
    "AuraAgentFFI.xcframework/ios-arm64_x86_64-simulator/Headers/aura_ffi.h",
    "AuraAgentFFI.xcframework/ios-arm64_x86_64-simulator/libaura_agent_ffi_ios_sim.a",
    "execution-policy-trust-keyring.json",
    "release-manifest.json",
    "runtime-artifact-descriptor.json",
    "runtime-artifact-identities.env",
)
EXPECTED_APPLE_ARCHIVE_PATHS = {
    "ios-arm64": "AuraAgentFFI.xcframework/ios-arm64/libaura_agent_ffi.a",
    "ios-arm64_x86_64-simulator": (
        "AuraAgentFFI.xcframework/ios-arm64_x86_64-simulator/"
        "libaura_agent_ffi_ios_sim.a"
    ),
    "ios-arm64_x86_64-maccatalyst": (
        "AuraAgentFFI.xcframework/ios-arm64_x86_64-maccatalyst/"
        "libaura_agent_ffi_maccatalyst.a"
    ),
}
APPLE_REPRODUCIBILITY_FIELDS = {
    "schema_version",
    "status",
    "claim",
    "independent_reproduction_proven",
    "compiler_trust_proven",
    "candidate_blind_build_proven",
    "hermetic_build_proven",
    "trusted_source_and_build_scripts_assumed",
    "release_revision",
    "artifact_revision",
    "source_revision",
    "source_tree_sha256",
    "artifact_commit_policy",
    "committed_artifact_verification",
    "committed_archive_lfs",
    "artifact_inventory",
    "build_count",
    "source_identities",
    "all_three_inventories_equal",
    "verified_dist_output",
    "disk_preflight",
    "toolchain",
}

ReleaseDecisionError = crypto_support.AttestationError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create, sign, or verify the fail-closed AURA release decision."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="Create a GO/NO-GO decision.")
    create.add_argument("--candidate-revision", required=True)
    create.add_argument("--runtime-version", required=True)
    create.add_argument("--profile", default=PROFILE, choices=[PROFILE])
    create.add_argument("--evidence-manifest", default=None)
    create.add_argument("--evidence-attestation", default=None)
    create.add_argument("--evidence-public-key", default=None)
    create.add_argument("--expected-evidence-key-id", default=None)
    create.add_argument("--evidence-attestation-verification", default=None)
    create.add_argument("--apple-artifact-verification", default=None)
    create.add_argument("--apple-artifact-reproducibility", default=None)
    create.add_argument("--apple-release-manifest", default=None)
    create.add_argument("--pilot-gate-report", default=None)
    create.add_argument("--pilot-signoff-verification", default=None)
    create.add_argument("--pilot-signoff-trust-policy", default=None)
    create.add_argument(
        "--expected-pilot-signoff-trust-policy-sha256",
        default=None,
    )
    create.add_argument("--product-integration-acceptance", default=None)
    create.add_argument("--output", required=True)
    create.add_argument("--require-go", action="store_true")

    sign = subparsers.add_parser("sign", help="Sign a GO decision.")
    sign.add_argument("--decision", required=True)
    sign.add_argument("--private-key", required=True)
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--evidence-manifest", required=True)
    sign.add_argument("--evidence-attestation", required=True)
    sign.add_argument("--evidence-public-key", required=True)
    sign.add_argument("--expected-evidence-key-id", required=True)
    sign.add_argument("--evidence-attestation-verification", required=True)
    sign.add_argument("--apple-artifact-verification", required=True)
    sign.add_argument("--apple-artifact-reproducibility", required=True)
    sign.add_argument("--apple-release-manifest", required=True)
    sign.add_argument("--pilot-gate-report", required=True)
    sign.add_argument("--pilot-signoff-verification", required=True)
    sign.add_argument("--pilot-signoff-trust-policy", required=True)
    sign.add_argument(
        "--expected-pilot-signoff-trust-policy-sha256",
        required=True,
    )
    sign.add_argument("--product-integration-acceptance", required=True)
    sign.add_argument("--output", required=True)

    verify = subparsers.add_parser("verify", help="Verify a signed GO decision.")
    verify.add_argument("--decision", required=True)
    verify.add_argument("--attestation", required=True)
    verify.add_argument("--public-key", required=True)
    verify.add_argument("--expected-key-id", default=None)
    verify.add_argument("--output", default=None)
    verify.add_argument("--require-pass", action="store_true")
    return parser.parse_args()


def lowercase_sha256(value: object) -> bool:
    return isinstance(value, str) and LOWERCASE_SHA256.fullmatch(value) is not None


def git_revision(value: object) -> bool:
    return isinstance(value, str) and GIT_REVISION.fullmatch(value) is not None


def runtime_version(value: object) -> bool:
    return isinstance(value, str) and RUNTIME_VERSION.fullmatch(value) is not None


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_stable_regular_file_with_mode(
    path: Path, maximum: int, label: str
) -> tuple[bytes, int]:
    flags = os.O_RDONLY
    for name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, name, 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReleaseDecisionError(f"{label} is inaccessible or a symlink") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum:
            raise ReleaseDecisionError(
                f"{label} must be a nonempty regular file no larger than {maximum} bytes"
            )
        chunks = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - observed + 1))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum:
                raise ReleaseDecisionError(f"{label} exceeds its size limit")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if observed != before.st_size or identity_before != identity_after:
            raise ReleaseDecisionError(f"{label} changed while being read")
        return b"".join(chunks), before.st_mode
    finally:
        os.close(descriptor)


def read_stable_regular_file(path: Path, maximum: int, label: str) -> bytes:
    raw, _mode = read_stable_regular_file_with_mode(path, maximum, label)
    return raw


def observed_status(payload: object) -> str | None:
    if not isinstance(payload, dict):
        return None
    for field in ("decision", "evidence_status", "overall_status", "status"):
        value = payload.get(field)
        if isinstance(value, str):
            return value
    return None


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def _strict_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON value is forbidden: {value}")
    return parsed


def strict_json_loads(raw: bytes) -> object:
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_strict_json_object,
        parse_constant=_reject_json_constant,
        parse_float=_strict_json_float,
    )


def load_child(
    path_value: str | None,
    label: str,
    maximum: int = MAX_ARTIFACT_BYTES,
) -> tuple[bytes | None, dict | None, dict]:
    if path_value is None:
        return None, None, {
            "required": True,
            "present": False,
            "bytes": None,
            "sha256": None,
            "schema_version": None,
            "observed_status": "missing",
        }
    path = Path(path_value)
    try:
        raw = read_stable_regular_file(path, maximum, label)
    except ReleaseDecisionError:
        return None, None, {
            "required": True,
            "present": False,
            "bytes": None,
            "sha256": None,
            "schema_version": None,
            "observed_status": "inaccessible",
        }
    try:
        payload = strict_json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        payload = None
    return raw, payload if isinstance(payload, dict) else None, {
        "required": True,
        "present": True,
        "bytes": len(raw),
        "sha256": sha256(raw).hexdigest(),
        "schema_version": payload.get("schema_version")
        if isinstance(payload, dict)
        else None,
        "observed_status": (
            observed_status(payload) or "loaded"
            if isinstance(payload, dict)
            else "invalid_json"
        ),
    }


def load_raw_child(
    path_value: str | None,
    label: str,
    maximum: int = MAX_ARTIFACT_BYTES,
) -> tuple[bytes | None, dict]:
    if path_value is None:
        return None, {
            "required": True,
            "present": False,
            "bytes": None,
            "sha256": None,
            "schema_version": None,
            "observed_status": "missing",
        }
    try:
        raw = read_stable_regular_file(Path(path_value), maximum, label)
    except ReleaseDecisionError:
        return None, {
            "required": True,
            "present": False,
            "bytes": None,
            "sha256": None,
            "schema_version": None,
            "observed_status": "inaccessible",
        }
    return raw, {
        "required": True,
        "present": True,
        "bytes": len(raw),
        "sha256": sha256(raw).hexdigest(),
        "schema_version": None,
        "observed_status": "loaded",
    }


def child_input_status(metadata: dict) -> str:
    if metadata["present"] is not True:
        return (
            "blocked"
            if metadata.get("observed_status") == "missing"
            else "fail"
        )
    if metadata["observed_status"] == "invalid_json":
        return "fail"
    return "pass"


def combine_status(*statuses: str) -> str:
    if "fail" in statuses:
        return "fail"
    if "blocked" in statuses:
        return "blocked"
    return "pass"


def evaluate_evidence_manifest(
    payload: dict | None,
    metadata: dict,
    runtime_release_version: str,
) -> tuple[str, str, str]:
    base = child_input_status(metadata)
    if base != "pass" or payload is None:
        return base, base, base
    if (
        payload.get("schema_version") != "aura.evidence_manifest.v1"
        or payload.get("evidence_status") != "pass"
    ):
        return "fail", "fail", "fail"
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        return "fail", "fail", "fail"
    runtime_fields = (
        "release_report_status",
        "pilot_regression_status",
        "world_lifecycle_status",
        "world_performance_status",
        "refactor_diff_status",
    )
    contract_fields = (
        "ffi_smoke_status",
        "ffi_soak_status",
        "refactor_diff_status",
    )
    privacy_fields = ("dataset_evidence_status", "audit_evidence_status")
    runtime_status = (
        "pass"
        if all(summary.get(field) == "pass" for field in runtime_fields)
        else "fail"
    )
    contract_status = (
        "pass"
        if all(summary.get(field) == "pass" for field in contract_fields)
        and summary.get("wire_package") == "aura.messenger.v1"
        and summary.get("wire_major_version") == 1
        and summary.get("state_schema_version") == 3
        else "fail"
    )
    privacy_status = (
        "pass"
        if all(summary.get(field) == "pass" for field in privacy_fields)
        and summary.get("audit_forbidden_fields_absent") is True
        else "fail"
    )
    if summary.get("runtime_release_version") != runtime_release_version:
        runtime_status = "fail"
        contract_status = "fail"
    return runtime_status, contract_status, privacy_status


def evidence_manifest_binds_apple_identity(
    payload: dict | None,
    identity: dict[str, str] | None,
    reproduction_sha256: object,
    verification_sha256: object,
) -> bool:
    if not isinstance(payload, dict) or identity is None:
        return False
    summary = payload.get("summary")
    artifacts = payload.get("artifacts")
    if not isinstance(summary, dict) or not isinstance(artifacts, dict):
        return False
    verification = artifacts.get("apple_artifact_verification")
    reproduction = artifacts.get("apple_artifact_reproducibility")
    return (
        isinstance(verification, dict)
        and isinstance(reproduction, dict)
        and verification.get("sha256") == verification_sha256
        and reproduction.get("sha256") == reproduction_sha256
        and summary.get("apple_artifact_status") == "pass"
        and summary.get("apple_artifact_source_revision")
        == identity["source_revision"]
        and summary.get("apple_artifact_source_tree_sha256")
        == identity["source_tree_sha256"]
        and summary.get("apple_reproducibility_status") == "pass"
        and summary.get("apple_reproducibility_source_revision")
        == identity["source_revision"]
        and summary.get("apple_reproducibility_artifact_revision")
        == identity["artifact_revision"]
        and summary.get("apple_reproducibility_release_revision")
        == identity["release_revision"]
        and summary.get("apple_reproducibility_source_tree_sha256")
        == identity["source_tree_sha256"]
    )


def evidence_manifest_binds_pilot_gate(
    manifest: dict | None,
    pilot: dict | None,
    pilot_sha256: object,
    pilot_signoff_verification: dict | None,
    pilot_signoff_verification_sha256: object,
    candidate_revision: str,
) -> bool:
    if (
        not isinstance(manifest, dict)
        or not isinstance(pilot, dict)
        or not isinstance(pilot_signoff_verification, dict)
    ):
        return False
    summary = manifest.get("summary")
    artifacts = manifest.get("artifacts")
    if not isinstance(summary, dict) or not isinstance(artifacts, dict):
        return False
    bound = artifacts.get("pilot_gate_report")
    signoff_bound = artifacts.get("pilot_signoff_verification")
    return (
        isinstance(bound, dict)
        and bound.get("sha256") == pilot_sha256
        and bound.get("observed_status") == "pass"
        and bound.get("schema_version") == "aura.pilot_gate_report.v2"
        and bound.get("release_revision") == candidate_revision
        and summary.get("pilot_gate_status") == "pass"
        and summary.get("pilot_gate_schema_version")
        == "aura.pilot_gate_report.v2"
        and summary.get("pilot_gate_release_revision") == candidate_revision
        and summary.get("pilot_gate_shadow_run_count")
        == len(pilot.get("shadow_runs", []))
        and summary.get("pilot_gate_check_count") == len(pilot.get("checks", []))
        and isinstance(signoff_bound, dict)
        and signoff_bound.get("sha256") == pilot_signoff_verification_sha256
        and signoff_bound.get("observed_status") == "pass"
        and signoff_bound.get("schema_version")
        == pilot_signoff_verification.get("schema_version")
        and signoff_bound.get("release_revision") == candidate_revision
        and signoff_bound.get("trust_policy_sha256")
        == pilot_signoff_verification.get("trust_policy_sha256")
        and signoff_bound.get("policy_id")
        == pilot_signoff_verification.get("policy_id")
        and signoff_bound.get("policy_epoch")
        == pilot_signoff_verification.get("policy_epoch")
        and signoff_bound.get("signoff_set_sha256")
        == pilot_signoff_verification.get("signoff_set_sha256")
        and signoff_bound.get("signer_spki_set_sha256")
        == pilot_signoff_verification.get("signer_spki_set_sha256")
        and signoff_bound.get("signer_spki_sha256")
        == pilot_signoff_verification.get("signer_spki_sha256")
        and summary.get("pilot_signoff_verification_status") == "pass"
        and summary.get("pilot_signoff_verification_schema_version")
        == pilot_signoff_verification.get("schema_version")
        and summary.get("pilot_signoff_verification_release_revision")
        == candidate_revision
        and summary.get("pilot_signoff_verification_trust_policy_sha256")
        == pilot_signoff_verification.get("trust_policy_sha256")
        and summary.get("pilot_signoff_verification_policy_id")
        == pilot_signoff_verification.get("policy_id")
        and summary.get("pilot_signoff_verification_policy_epoch")
        == pilot_signoff_verification.get("policy_epoch")
        and summary.get("pilot_signoff_verification_signature_algorithm")
        == pilot_signoff_verification.get("signature_algorithm")
        and summary.get("pilot_signoff_verification_required_review_areas")
        == pilot_signoff_verification.get("required_review_areas")
        and summary.get("pilot_signoff_verification_verified_signoff_count")
        == pilot_signoff_verification.get("verified_signoff_count")
        and summary.get("pilot_signoff_verification_distinct_signer_count")
        == pilot_signoff_verification.get("distinct_signer_count")
        and summary.get("pilot_signoff_verification_signer_spki_sha256")
        == pilot_signoff_verification.get("signer_spki_sha256")
        and summary.get("pilot_signoff_verification_signoff_set_sha256")
        == pilot_signoff_verification.get("signoff_set_sha256")
        and summary.get("pilot_signoff_verification_signer_spki_set_sha256")
        == pilot_signoff_verification.get("signer_spki_set_sha256")
    )


def evaluate_evidence_attestation(
    manifest_raw: bytes | None,
    attestation_raw: bytes | None,
    public_key_raw: bytes | None,
    expected_key_id: str | None,
    derived_verification: dict | None,
    derived_metadata: dict,
    trio_supplied: tuple[bool, bool, bool],
) -> tuple[str, dict[str, str] | None]:
    """Verify the raw trust root and require the supplied report to be exact."""

    if not any(trio_supplied):
        return "blocked", None
    if not all(trio_supplied):
        return "fail", None
    if (
        manifest_raw is None
        or attestation_raw is None
        or public_key_raw is None
    ):
        return "fail", None
    if (
        not isinstance(expected_key_id, str)
        or not crypto_support.safe_key_id(expected_key_id)
    ):
        return "fail", None
    derived_base = child_input_status(derived_metadata)
    if derived_base != "pass" or derived_verification is None:
        return (
            "blocked"
            if derived_metadata.get("observed_status") == "missing"
            else "fail"
        ), None
    try:
        with tempfile.TemporaryDirectory() as directory:
            snapshots = {
                "manifest": ("manifest.json", manifest_raw),
                "attestation": ("attestation.json", attestation_raw),
                "public_key": ("public-key.pem", public_key_raw),
            }
            snapshot_paths = {}
            for name, (filename, raw) in snapshots.items():
                path = Path(directory) / filename
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                snapshot_paths[name] = path
            verified = crypto_support.verify_manifest(
                snapshot_paths["manifest"],
                snapshot_paths["attestation"],
                snapshot_paths["public_key"],
                expected_key_id,
            )
    except (ReleaseDecisionError, OSError, ValueError, TypeError):
        return "fail", None
    if not _json_exactly_equal(verified, derived_verification):
        return "fail", None
    identity = {
        "signature_algorithm": verified["signature_algorithm"],
        "key_id": verified["key_id"],
        "public_key_spki_sha256": verified["public_key_spki_sha256"],
        "manifest_sha256": verified["manifest_sha256"],
    }
    if (
        set(identity)
        != {
            "signature_algorithm",
            "key_id",
            "public_key_spki_sha256",
            "manifest_sha256",
        }
        or identity["signature_algorithm"] != SIGNATURE_ALGORITHM
        or not crypto_support.safe_key_id(identity["key_id"])
        or not lowercase_sha256(identity["public_key_spki_sha256"])
        or not lowercase_sha256(identity["manifest_sha256"])
        or identity["manifest_sha256"] != sha256(manifest_raw).hexdigest()
    ):
        return "fail", None
    return "pass", identity


def evaluate_apple_artifact(
    verification: dict | None,
    verification_metadata: dict,
    release_manifest: dict | None,
    release_manifest_metadata: dict,
    source_revision: str | None,
    expected_runtime_version: str,
) -> tuple[str, str | None]:
    base = combine_status(
        child_input_status(verification_metadata),
        child_input_status(release_manifest_metadata),
    )
    if base != "pass" or verification is None or release_manifest is None:
        return base, None
    source_tree_sha256 = verification.get("source_tree_sha256")
    binary_hashes = release_manifest.get("binary_sha256")
    slices = verification.get("slices")
    slice_map = {}
    if isinstance(slices, list):
        for item in slices:
            slice_id = item.get("slice_id") if isinstance(item, dict) else None
            if isinstance(slice_id, str) and slice_id not in slice_map:
                slice_map[slice_id] = item
    if (
        set(verification) != EXPECTED_APPLE_VERIFICATION_FIELDS
        or verification.get("schema_version")
        != "aura.apple_artifact_verification.v1"
        or verification.get("status") != "pass"
        or verification.get("shippable") is not True
        or verification.get("source_tree_dirty") is not False
        or not git_revision(verification.get("source_revision"))
        or source_revision is not None
        and verification.get("source_revision") != source_revision
        or not lowercase_sha256(source_tree_sha256)
        or verification.get("runtime_release_version") != expected_runtime_version
        or verification.get("ffi_contract_version") != 1
        or verification.get("state_schema_version") != 3
        or verification.get("wire_package") != "aura.messenger.v1"
        or verification.get("cargo_features") != []
        or not isinstance(slices, list)
        or len(slices) != len(EXPECTED_APPLE_SLICES)
        or set(slice_map) != set(EXPECTED_APPLE_SLICES)
        or set(release_manifest) != EXPECTED_APPLE_RELEASE_MANIFEST_FIELDS
        or release_manifest.get("schema_version") != 5
        or release_manifest.get("source_revision") != verification.get("source_revision")
        or release_manifest.get("source_tree_sha256") != source_tree_sha256
        or release_manifest.get("source_tree_dirty") is not False
        or release_manifest.get("shippable") is not True
        or release_manifest.get("cargo_profile") != "release"
        or release_manifest.get("cargo_locked") is not True
        or release_manifest.get("cargo_features") != []
        or release_manifest.get("model_bundle_included") is not False
        or release_manifest.get("runtime_release_version") != expected_runtime_version
        or release_manifest.get("ffi_contract_version") != 1
        or release_manifest.get("state_schema_version") != 3
        or release_manifest.get("minimum_ios_version") != "18.0"
        or release_manifest.get("wire_package") != "aura.messenger.v1"
        or release_manifest.get("wire_major_version") != 1
        or release_manifest.get("target_triples") != EXPECTED_APPLE_TARGET_TRIPLES
        or not isinstance(binary_hashes, dict)
        or set(binary_hashes) != set(EXPECTED_APPLE_SLICES)
        or any(not lowercase_sha256(value) for value in binary_hashes.values())
        or any(
            slice_map[slice_id].get("architectures") != architectures
            or slice_map[slice_id].get("binary_sha256") != binary_hashes[slice_id]
            for slice_id, architectures in EXPECTED_APPLE_SLICES.items()
        )
        or not lowercase_sha256(
            release_manifest.get("runtime_artifact_descriptor_sha256")
        )
        or not lowercase_sha256(release_manifest.get("runtime_capabilities_sha256"))
        or not lowercase_sha256(release_manifest.get("model_manifest_sha256"))
    ):
        return "fail", None
    return "pass", source_tree_sha256


def _bounded_positive_integer(value: object, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= maximum
    )


def _json_exactly_equal(left: object, right: object) -> bool:
    try:
        return json.dumps(
            left, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ) == json.dumps(
            right, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
    except (TypeError, ValueError):
        return False


def validate_apple_reproducibility_report(
    report: object,
    apple_verification: object,
) -> dict[str, str]:
    """Validate the complete v1 reproducibility claim against its verified snapshot."""

    if not isinstance(report, dict) or set(report) != APPLE_REPRODUCIBILITY_FIELDS:
        raise ReleaseDecisionError("Apple reproducibility report fields are not exact")
    if not isinstance(apple_verification, dict):
        raise ReleaseDecisionError("Apple artifact verification is unavailable")

    source_revision = report.get("source_revision")
    artifact_revision = report.get("artifact_revision")
    release_revision = report.get("release_revision")
    source_tree_sha256 = report.get("source_tree_sha256")
    if (
        report.get("schema_version") != APPLE_REPRODUCIBILITY_SCHEMA_VERSION
        or report.get("status") != "pass"
        or report.get("claim") != "same_environment_deterministic_rebuild"
        or report.get("independent_reproduction_proven") is not False
        or report.get("compiler_trust_proven") is not False
        or report.get("candidate_blind_build_proven") is not False
        or report.get("hermetic_build_proven") is not False
        or report.get("trusted_source_and_build_scripts_assumed") is not True
        or report.get("build_count") != 2
        or isinstance(report.get("build_count"), bool)
        or report.get("all_three_inventories_equal") is not True
        or not git_revision(source_revision)
        or not git_revision(artifact_revision)
        or not git_revision(release_revision)
        or source_revision == artifact_revision
        or source_revision == release_revision
        or not lowercase_sha256(source_tree_sha256)
    ):
        raise ReleaseDecisionError("Apple reproducibility claims are invalid")

    policy = report.get("artifact_commit_policy")
    if not isinstance(policy, dict) or policy != {
        "direct_single_parent": True,
        "generated_only_diff": True,
        "governance_only_release_suffix": True,
    }:
        raise ReleaseDecisionError("Apple artifact commit policy is invalid")

    if not _json_exactly_equal(
        report.get("committed_artifact_verification"), apple_verification
    ):
        raise ReleaseDecisionError(
            "Apple reproducibility report does not bind the supplied verification"
        )
    slices = apple_verification.get("slices")
    if (
        set(apple_verification) != EXPECTED_APPLE_VERIFICATION_FIELDS
        or apple_verification.get("schema_version")
        != "aura.apple_artifact_verification.v1"
        or apple_verification.get("status") != "pass"
        or apple_verification.get("source_revision") != source_revision
        or apple_verification.get("source_tree_sha256") != source_tree_sha256
        or not isinstance(slices, list)
        or len(slices) != len(EXPECTED_APPLE_SLICES)
    ):
        raise ReleaseDecisionError(
            "Apple reproducibility source identity is inconsistent"
        )
    slice_map: dict[str, dict] = {}
    for item in slices:
        slice_id = item.get("slice_id") if isinstance(item, dict) else None
        if (
            not isinstance(item, dict)
            or set(item) != {"slice_id", "architectures", "binary_sha256"}
            or not isinstance(slice_id, str)
            or slice_id in slice_map
            or slice_id not in EXPECTED_APPLE_SLICES
            or item.get("architectures")
            != EXPECTED_APPLE_SLICES.get(slice_id)
            or not lowercase_sha256(item.get("binary_sha256"))
        ):
            raise ReleaseDecisionError("Apple verification slice identity is invalid")
        slice_map[slice_id] = item
    if set(slice_map) != set(EXPECTED_APPLE_SLICES):
        raise ReleaseDecisionError("Apple verification slice set is invalid")

    inventory = report.get("artifact_inventory")
    if not isinstance(inventory, list) or len(inventory) != len(
        EXPECTED_APPLE_ARTIFACT_PATHS
    ):
        raise ReleaseDecisionError("Apple reproducibility inventory count is invalid")
    inventory_map: dict[str, dict] = {}
    total_bytes = 0
    for item in inventory:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "size", "sha256", "executable"}
            or not isinstance(item.get("path"), str)
            or item.get("path") in inventory_map
            or not _bounded_positive_integer(item.get("size"), 512 * 1024 * 1024)
            or not lowercase_sha256(item.get("sha256"))
            or item.get("executable") is not False
        ):
            raise ReleaseDecisionError("Apple reproducibility inventory entry is invalid")
        inventory_map[item["path"]] = item
        total_bytes += item["size"]
    if (
        tuple(item.get("path") for item in inventory)
        != EXPECTED_APPLE_ARTIFACT_PATHS
        or set(inventory_map) != set(EXPECTED_APPLE_ARTIFACT_PATHS)
        or total_bytes > 2 * 1024 * 1024 * 1024
    ):
        raise ReleaseDecisionError("Apple reproducibility inventory shape is invalid")

    lfs = report.get("committed_archive_lfs")
    expected_lfs_paths = {
        f"dist/apple/{path}" for path in EXPECTED_APPLE_ARCHIVE_PATHS.values()
    }
    if not isinstance(lfs, dict) or set(lfs) != expected_lfs_paths:
        raise ReleaseDecisionError("Apple reproducibility LFS archive set is invalid")
    for slice_id, relative_path in EXPECTED_APPLE_ARCHIVE_PATHS.items():
        binding = lfs[f"dist/apple/{relative_path}"]
        inventory_entry = inventory_map[relative_path]
        if (
            not isinstance(binding, dict)
            or set(binding) != {"size", "sha256"}
            or binding.get("size") != inventory_entry["size"]
            or binding.get("sha256") != inventory_entry["sha256"]
            or inventory_entry["sha256"] != slice_map[slice_id]["binary_sha256"]
        ):
            raise ReleaseDecisionError(
                "Apple reproducibility LFS archive binding is invalid"
            )

    source_identities = report.get("source_identities")
    if not isinstance(source_identities, list) or len(source_identities) != 2:
        raise ReleaseDecisionError("Apple reproducibility source identities are invalid")
    for identity in source_identities:
        if (
            not isinstance(identity, dict)
            or set(identity)
            != {"source_tree_sha256", "entry_count", "content_bytes"}
            or identity.get("source_tree_sha256") != source_tree_sha256
            or not _bounded_positive_integer(identity.get("entry_count"), 1_000_000)
            or not _bounded_positive_integer(
                identity.get("content_bytes"), 64 * 1024 * 1024 * 1024
            )
        ):
            raise ReleaseDecisionError(
                "Apple reproducibility source identity is malformed"
            )
    if not _json_exactly_equal(source_identities[0], source_identities[1]):
        raise ReleaseDecisionError("Apple rebuilds used different source identities")

    disk = report.get("disk_preflight")
    if not isinstance(disk, dict) or set(disk) != {
        "materialized_source_lfs_object_count",
        "materialized_source_lfs_bytes",
        "required_free_bytes",
        "observed_free_bytes",
    }:
        raise ReleaseDecisionError("Apple reproducibility disk preflight is invalid")
    required_free_bytes = disk.get("materialized_source_lfs_bytes", 0) + 16 * 1024**3
    if any(
        not _bounded_positive_integer(value, 1 << 60) for value in disk.values()
    ) or (
        disk["required_free_bytes"] != required_free_bytes
        or disk["observed_free_bytes"] < disk["required_free_bytes"]
    ):
        raise ReleaseDecisionError("Apple reproducibility disk preflight failed")

    toolchain = report.get("toolchain")
    if not isinstance(toolchain, dict) or set(toolchain) != {
        "xcode",
        "iphoneos_sdk",
        "iphoneos_sdk_build",
        "effective_developer_dir",
        "resolved_xcodebuild",
        "global_xcode_select",
        "rustc_verbose",
        "cargo",
        "git",
        "git_lfs",
        "python",
        "runner",
    }:
        raise ReleaseDecisionError("Apple reproducibility toolchain identity is invalid")
    if (
        toolchain.get("xcode") != ["Xcode 26.2", "Build version 17C52"]
        or toolchain.get("iphoneos_sdk") != "26.2"
        or toolchain.get("iphoneos_sdk_build") != "23C53"
        or not isinstance(toolchain.get("effective_developer_dir"), str)
        or not isinstance(toolchain.get("resolved_xcodebuild"), str)
        or not toolchain["resolved_xcodebuild"].startswith(
            toolchain["effective_developer_dir"].rstrip("/") + "/"
        )
        or not isinstance(toolchain.get("rustc_verbose"), list)
        or not toolchain["rustc_verbose"]
        or any(not isinstance(value, str) for value in toolchain["rustc_verbose"])
        or not {
            "release: 1.96.1",
            "commit-hash: 31fca3adb283cc9dfd56b49cdee9a96eb9c96ffd",
            "LLVM version: 22.1.2",
        }.issubset(toolchain["rustc_verbose"])
        or not isinstance(toolchain.get("cargo"), str)
        or not toolchain["cargo"].startswith("cargo 1.96.1 ")
        or any(
            not isinstance(toolchain.get(field), str) or not toolchain[field]
            for field in (
                "iphoneos_sdk",
                "iphoneos_sdk_build",
                "effective_developer_dir",
                "resolved_xcodebuild",
                "global_xcode_select",
                "git",
                "git_lfs",
                "python",
            )
        )
        or not isinstance(toolchain.get("runner"), dict)
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in toolchain["runner"].items()
        )
    ):
        raise ReleaseDecisionError("Apple reproducibility toolchain fields are invalid")
    verified_output = report.get("verified_dist_output")
    if (
        not isinstance(verified_output, str)
        or not verified_output
        or len(verified_output.encode("utf-8")) > 4096
        or "\x00" in verified_output
    ):
        raise ReleaseDecisionError("Apple retained artifact path claim is invalid")

    return {
        "source_revision": source_revision,
        "artifact_revision": artifact_revision,
        "release_revision": release_revision,
        "source_tree_sha256": source_tree_sha256,
    }


def evaluate_apple_reproducibility(
    report: dict | None,
    report_metadata: dict,
    apple_verification: dict | None,
    release_manifest: dict | None,
    release_manifest_metadata: dict,
    candidate_release_revision: str,
) -> tuple[str, dict[str, str] | None]:
    base = child_input_status(report_metadata)
    if base != "pass" or report is None:
        return base, None
    try:
        identity = validate_apple_reproducibility_report(report, apple_verification)
    except ReleaseDecisionError:
        return "fail", None
    binary_hashes = (
        release_manifest.get("binary_sha256")
        if isinstance(release_manifest, dict)
        else None
    )
    if not isinstance(binary_hashes, dict):
        return "fail", None
    inventory_map = {
        item["path"]: item
        for item in report["artifact_inventory"]
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    expected_nonbinary_hashes = {
        "AuraAgentFFI.xcframework/Info.plist": "xcframework_info_plist_sha256",
        "execution-policy-trust-keyring.json": (
            "execution_policy_trust_keyring_sha256"
        ),
        "runtime-artifact-descriptor.json": "runtime_artifact_descriptor_sha256",
        "runtime-artifact-identities.env": "runtime_artifact_identities_env_sha256",
    }
    header_paths = (
        path for path in EXPECTED_APPLE_ARTIFACT_PATHS if path.endswith("/aura_ffi.h")
    )
    if (
        release_manifest is None
        or identity["release_revision"] != candidate_release_revision
        or release_manifest.get("source_revision") != identity["source_revision"]
        or release_manifest.get("source_tree_sha256")
        != identity["source_tree_sha256"]
        or inventory_map["release-manifest.json"].get("sha256")
        != release_manifest_metadata.get("sha256")
        or any(
            report["artifact_inventory"][
                EXPECTED_APPLE_ARTIFACT_PATHS.index(relative_path)
            ].get("sha256")
            != binary_hashes.get(slice_id)
            for slice_id, relative_path in EXPECTED_APPLE_ARCHIVE_PATHS.items()
        )
        or any(
            inventory_map[path].get("sha256")
            != release_manifest.get(manifest_field)
            for path, manifest_field in expected_nonbinary_hashes.items()
        )
        or any(
            inventory_map[path].get("sha256")
            != release_manifest.get("aura_ffi_header_sha256")
            for path in header_paths
        )
    ):
        return "fail", None
    return "pass", identity


def _pilot_usize(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= PILOT_USIZE_MAX
    )


def _pilot_policy_epoch(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= pilot_signoff_support.MAX_POLICY_EPOCH
    )


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return (
        parsed.tzinfo is not None
        and parsed.utcoffset() == timezone.utc.utcoffset(parsed)
    )


def _pilot_check(check_id: str, summary: str) -> dict[str, str]:
    return {"check_id": check_id, "status": "pass", "summary": summary}


def evaluate_pilot_gate(
    payload: dict | None,
    metadata: dict,
    candidate_revision: str,
) -> tuple[str, str]:
    """Validate the exact strict-profile report emitted by the Rust producer.

    Reviewer values are opaque producer-supplied labels. This validates recorded
    approvals and their report consistency; it does not authenticate identities.
    """

    base = child_input_status(metadata)
    if base != "pass" or payload is None:
        return base, base
    if not isinstance(payload, dict):
        return "fail", "fail"
    if (
        set(payload) != PILOT_GATE_FIELDS
        or payload.get("schema_version") != "aura.pilot_gate_report.v2"
        or payload.get("overall_status") != "pass"
        or not git_revision(payload.get("release_revision"))
        or payload.get("release_revision") != candidate_revision
    ):
        return "fail", "fail"
    release_revision = payload["release_revision"]

    config = payload.get("config")
    if (
        not isinstance(config, dict)
        or set(config) != PILOT_CONFIG_FIELDS
        or not _pilot_usize(config.get("min_shadow_runs"))
        or config["min_shadow_runs"] < 2
        or not _pilot_usize(config.get("min_shadow_total_events"))
        or config["min_shadow_total_events"] < 500
        or config.get("require_release_pass") is not True
        or config.get("require_pilot_regression_pass") is not True
        or config.get("require_kids_memory_pass") is not True
        or config.get("require_kids_preprod_dry_run_pass") is not True
        or config.get("required_review_areas")
        != list(PILOT_REQUIRED_REVIEW_AREAS)
    ):
        return "fail", "fail"

    release = payload.get("release")
    inference = (
        release.get("social_context_inference")
        if isinstance(release, dict)
        else None
    )
    if (
        not isinstance(release, dict)
        or set(release) != PILOT_RELEASE_FIELDS
        or release.get("schema_version") != "aura.release_report.v3"
        or release.get("overall_status") != "pass"
        or not isinstance(inference, dict)
        or set(inference) != PILOT_SOCIAL_CONTEXT_FIELDS
        or inference.get("passed") is not True
        or not _pilot_usize(inference.get("total_expectations"))
        or inference["total_expectations"] == 0
        or inference.get("failed_expectations") != 0
    ):
        return "fail", "fail"

    regression = payload.get("pilot_regression")
    if (
        not isinstance(regression, dict)
        or set(regression) != PILOT_REGRESSION_FIELDS
        or regression.get("schema_version")
        != "aura.pilot_simulation_regression_report.v1"
        or regression.get("overall_status") != "pass"
        or not _nonempty_string(regression.get("suite_id"))
        or not _pilot_usize(regression.get("scenario_count"))
        or regression["scenario_count"] == 0
    ):
        return "fail", "fail"

    shadow_runs = payload.get("shadow_runs")
    if (
        not isinstance(shadow_runs, list)
        or len(shadow_runs) < config["min_shadow_runs"]
    ):
        return "fail", "fail"
    total_shadow_events = 0
    for run in shadow_runs:
        if (
            not isinstance(run, dict)
            or set(run) != PILOT_SHADOW_FIELDS
            or run.get("schema_version") != "aura.shadow_mode_bundle.v1"
            or run.get("source_kind") != "world_sim"
            or not _nonempty_string(run.get("source_label"))
            or run.get("wire_package") != "aura.messenger.v1"
            or run.get("protection_level") != "high"
            or not _pilot_usize(run.get("total_events"))
            or run["total_events"] == 0
            or not _pilot_usize(run.get("threat_events"))
            or run["threat_events"] > run["total_events"]
            or run.get("finding_count") != 0
            or run.get("raw_text_present") is not False
            or run.get("raw_identifier_fields_present") is not False
        ):
            return "fail", "fail"
        total_shadow_events += run["total_events"]
        if total_shadow_events > PILOT_USIZE_MAX:
            return "fail", "fail"
    if total_shadow_events < config["min_shadow_total_events"]:
        return "fail", "fail"

    kids_memory = payload.get("kids_memory_health")
    if (
        not isinstance(kids_memory, dict)
        or set(kids_memory) != PILOT_KIDS_MEMORY_FIELDS
        or kids_memory.get("schema_version")
        != "aura.kids_memory_health_snapshot.v1"
        or kids_memory.get("overall_status") != "pass"
        or not _pilot_usize(kids_memory.get("total_memory_hits"))
        or kids_memory["total_memory_hits"] == 0
        or kids_memory.get("missing_mandatory_reason_codes") != []
    ):
        return "fail", "fail"

    kids_preprod = payload.get("kids_preprod_dry_run")
    if (
        not isinstance(kids_preprod, dict)
        or set(kids_preprod) != PILOT_KIDS_PREPROD_FIELDS
        or kids_preprod.get("schema_version")
        != "aura.kids_preprod_dry_run_matrix.v1"
        or kids_preprod.get("overall_status") != "pass"
        or kids_preprod.get("checks_failed") != 0
        or isinstance(kids_preprod.get("checks_failed"), bool)
    ):
        return "fail", "fail"

    signoffs = payload.get("signoffs")
    if not isinstance(signoffs, list) or len(signoffs) != len(
        PILOT_REQUIRED_REVIEW_AREAS
    ):
        return "fail", "fail"
    latest_signoffs: dict[str, dict] = {}
    for signoff in signoffs:
        if (
            not isinstance(signoff, dict)
            or set(signoff) != PILOT_SIGNOFF_FIELDS
            or signoff.get("area") not in PILOT_REQUIRED_REVIEW_AREAS
            or not _nonempty_string(signoff.get("reviewer"))
            or signoff.get("status")
            not in {"approved", "pending", "needs_changes"}
            or not _utc_timestamp(signoff.get("reviewed_at_utc"))
            or (
                signoff.get("notes") is not None
                and not isinstance(signoff.get("notes"), str)
            )
            or signoff.get("release_revision") != release_revision
        ):
            return "fail", "fail"
        latest_signoffs[signoff["area"]] = signoff
    if (
        set(latest_signoffs) != set(PILOT_REQUIRED_REVIEW_AREAS)
        or any(
            latest_signoffs[area].get("status") != "approved"
            for area in PILOT_REQUIRED_REVIEW_AREAS
        )
    ):
        return "fail", "fail"

    expected_checks = [
        _pilot_check(
            "candidate_release_revision",
            f"pilot candidate is bound to release {release_revision}",
        ),
        _pilot_check("release_gate", "Phase 2 release gate passed"),
        _pilot_check(
            "release_social_context_inference",
            "social-context inference expectations passed "
            f"({inference['total_expectations']}/{inference['total_expectations']})",
        ),
        _pilot_check("pilot_regression", "pilot regression corpus passed"),
        _pilot_check(
            "kids_memory_health",
            "kids memory health passed "
            f"(total_hits={kids_memory['total_memory_hits']})",
        ),
        _pilot_check(
            "kids_preprod_dry_run",
            "kids preprod dry-run matrix passed with no failed checks",
        ),
        _pilot_check(
            "shadow_run_count",
            f"observed {len(shadow_runs)} shadow runs "
            f"(required {config['min_shadow_runs']})",
        ),
        _pilot_check(
            "shadow_event_volume",
            f"shadow runs cover {total_shadow_events} total events "
            f"(required >= {config['min_shadow_total_events']})",
        ),
        _pilot_check(
            "shadow_privacy_and_findings",
            "all shadow runs are clean and privacy-safe",
        ),
        _pilot_check(
            "shadow_contract_stability",
            "shadow runs share stable schema, wire package, and protection level",
        ),
        _pilot_check(
            "review_signoff_set",
            "all required review signoffs bind the exact release revision",
        ),
    ]
    expected_checks.extend(
        _pilot_check(
            f"review_signoff.{area}",
            f"{area} approved by {latest_signoffs[area]['reviewer']}",
        )
        for area in PILOT_REQUIRED_REVIEW_AREAS
    )
    checks = payload.get("checks")
    if (
        not isinstance(checks, list)
        or any(
            not isinstance(check, dict) or set(check) != PILOT_CHECK_FIELDS
            for check in checks
        )
        or checks != expected_checks
        or {check["check_id"] for check in checks} != REQUIRED_PILOT_CHECKS
    ):
        return "fail", "fail"

    rollback_triggers = payload.get("rollback_triggers")
    if (
        not isinstance(rollback_triggers, list)
        or any(
            not isinstance(trigger, dict)
            or set(trigger) != PILOT_ROLLBACK_TRIGGER_FIELDS
            for trigger in rollback_triggers
        )
        or rollback_triggers != list(PILOT_ROLLBACK_TRIGGERS)
        or payload.get("operator_review_cadence")
        != PILOT_OPERATOR_REVIEW_CADENCE
    ):
        return "fail", "fail"
    return "pass", "pass"


def evaluate_pilot_signoff_verification(
    report: dict | None,
    report_metadata: dict,
    trust_policy: dict | None,
    trust_policy_metadata: dict,
    expected_trust_policy_sha256: str | None,
    candidate_revision: str,
    pilot_gate: dict | None,
    evidence_signer: dict[str, str] | None,
    supplied: tuple[bool, bool, bool],
) -> tuple[str, dict | None]:
    """Reverify every pilot signature and bind the exact pilot-gate projection."""

    if not any(supplied):
        return "blocked", None
    if not all(supplied):
        return "fail", None
    report_base = child_input_status(report_metadata)
    policy_base = child_input_status(trust_policy_metadata)
    if report_base != "pass" or policy_base != "pass":
        return "fail", None
    if report is None or trust_policy is None:
        return "fail", None
    if not lowercase_sha256(expected_trust_policy_sha256):
        return "fail", None
    try:
        pilot_signoff_support.validate_trust_policy(trust_policy)
        validated_projection = pilot_signoff_support.validate_verification_report(
            report,
            trust_policy,
            expected_trust_policy_sha256,
            candidate_revision,
        )
        projection = pilot_signoff_support.review_signoffs_projection(report)
    except (pilot_signoff_support.PilotSignoffError, OSError, TypeError, ValueError):
        return "fail", None

    verified = report

    expected_projection = {
        "schema_version": pilot_signoff_support.SIGNOFFS_SCHEMA_VERSION,
        "release_revision": candidate_revision,
        "signoffs": (
            pilot_gate.get("signoffs") if isinstance(pilot_gate, dict) else None
        ),
    }
    signer_spki_sha256 = verified.get("signer_spki_sha256")
    if (
        report.get("status") != "pass"
        or verified.get("status") != "pass"
        or not _json_exactly_equal(validated_projection, projection)
        or not _json_exactly_equal(projection, expected_projection)
        or verified.get("release_revision") != candidate_revision
        or verified.get("trust_policy_sha256") != expected_trust_policy_sha256
        or not isinstance(verified.get("policy_id"), str)
        or not crypto_support.safe_key_id(verified["policy_id"])
        or not _pilot_policy_epoch(verified.get("policy_epoch"))
        or verified.get("signature_algorithm") != SIGNATURE_ALGORITHM
        or verified.get("required_review_areas")
        != list(pilot_signoff_support.REQUIRED_REVIEW_AREAS)
        or verified.get("verified_signoff_count")
        != len(PILOT_REQUIRED_REVIEW_AREAS)
        or verified.get("distinct_signer_count")
        != len(PILOT_REQUIRED_REVIEW_AREAS)
        or not isinstance(signer_spki_sha256, list)
        or len(signer_spki_sha256) != len(PILOT_REQUIRED_REVIEW_AREAS)
        or any(not lowercase_sha256(value) for value in signer_spki_sha256)
        or len(set(signer_spki_sha256)) != len(signer_spki_sha256)
        or not lowercase_sha256(verified.get("signoff_set_sha256"))
        or verified.get("signoff_set_sha256")
        != pilot_signoff_support.signoff_set_sha256(projection)
        or not lowercase_sha256(verified.get("signer_spki_set_sha256"))
        or verified.get("signer_spki_set_sha256")
        != pilot_signoff_support.signer_spki_set_sha256(signer_spki_sha256)
    ):
        return "fail", None
    evidence_spki = (
        evidence_signer.get("public_key_spki_sha256")
        if isinstance(evidence_signer, dict)
        else None
    )
    if evidence_spki is not None and any(
        hmac.compare_digest(evidence_spki, signer)
        for signer in signer_spki_sha256
    ):
        return "fail", None
    return "pass", {
        "trust_policy_sha256": verified["trust_policy_sha256"],
        "policy_id": verified["policy_id"],
        "policy_epoch": verified["policy_epoch"],
        "signer_spki_sha256": list(signer_spki_sha256),
        "signer_spki_set_sha256": verified["signer_spki_set_sha256"],
    }


def evaluate_product_acceptance(
    payload: dict | None,
    metadata: dict,
    candidate_revision: str,
    source_tree_sha256: str | None,
    apple_identity: dict[str, str] | None,
    child_metadata: dict[str, dict],
    apple_release_manifest: dict | None,
    evidence_attestation_status: str,
    evidence_signer: dict[str, str] | None,
) -> str:
    base = child_input_status(metadata)
    if base != "pass" or payload is None:
        return base
    if evidence_attestation_status != "pass":
        return evidence_attestation_status
    reproduction_base = child_input_status(
        child_metadata["apple_artifact_reproducibility"]
    )
    if reproduction_base != "pass":
        return reproduction_base
    if set(payload) != PRODUCT_ACCEPTANCE_FIELDS:
        return "fail"
    expected_digests = {
        "evidence_manifest_sha256": child_metadata["evidence_manifest"]["sha256"],
        "evidence_attestation_sha256": child_metadata["evidence_attestation"][
            "sha256"
        ],
        "evidence_attestation_verification_sha256": child_metadata[
            "evidence_attestation_verification"
        ]["sha256"],
        "apple_artifact_verification_sha256": child_metadata[
            "apple_artifact_verification"
        ]["sha256"],
        "apple_artifact_reproducibility_sha256": child_metadata[
            "apple_artifact_reproducibility"
        ]["sha256"],
        "apple_release_manifest_sha256": child_metadata["apple_release_manifest"][
            "sha256"
        ],
        "pilot_gate_report_sha256": child_metadata["pilot_gate_report"]["sha256"],
    }
    if (
        payload.get("schema_version") != PRODUCT_ACCEPTANCE_SCHEMA_VERSION
        or payload.get("status") != "pass"
        or payload.get("profile") != PROFILE
        or payload.get("candidate_revision") != candidate_revision
        or apple_identity is None
        or payload.get("source_revision") != apple_identity["source_revision"]
        or payload.get("artifact_revision") != apple_identity["artifact_revision"]
        or payload.get("release_revision") != apple_identity["release_revision"]
        or payload.get("source_tree_sha256") != source_tree_sha256
        or evidence_signer is None
        or payload.get("evidence_signer_spki_sha256")
        != evidence_signer["public_key_spki_sha256"]
        or any(
            expected is None
            or not hmac.compare_digest(str(payload.get(field)), str(expected))
            for field, expected in expected_digests.items()
        )
        or apple_release_manifest is None
        or payload.get("runtime_artifact_descriptor_sha256")
        != apple_release_manifest.get("runtime_artifact_descriptor_sha256")
        or payload.get("runtime_capabilities_sha256")
        != apple_release_manifest.get("runtime_capabilities_sha256")
        or any(
            payload.get(field) != "pass"
            for field in (
                "local_decision_contract",
                "terminal_checkpoint_contract",
                "restart_replay_contract",
            )
        )
        or payload.get("exact_artifact_pin") is not True
        or payload.get("model_enabled") is not False
        or payload.get("relay_enabled") is not False
        or payload.get("military_enabled") is not False
    ):
        return "fail"
    return "pass"


def create_decision(
    candidate_revision: str,
    expected_runtime_version: str,
    profile: str,
    paths: dict[str, str | None],
) -> dict:
    if not git_revision(candidate_revision):
        raise ReleaseDecisionError("candidate revision must be 40 lowercase hex characters")
    if not runtime_version(expected_runtime_version):
        raise ReleaseDecisionError("runtime version must be a fixed semantic version")
    if profile != PROFILE:
        raise ReleaseDecisionError("release profile is unsupported")

    raws = {}
    payloads = {}
    artifacts = {}
    for key, label in (
        ("evidence_manifest", "evidence manifest"),
        ("evidence_attestation", "evidence attestation"),
        ("evidence_attestation_verification", "evidence attestation verification"),
        ("apple_artifact_verification", "Apple artifact verification"),
        ("apple_artifact_reproducibility", "Apple artifact reproducibility"),
        ("apple_release_manifest", "Apple release manifest"),
        ("pilot_gate_report", "pilot gate report"),
        ("pilot_signoff_verification", "pilot signoff verification"),
        ("pilot_signoff_trust_policy", "pilot signoff trust policy"),
        ("product_integration_acceptance", "product integration acceptance"),
    ):
        maximum = (
            MAX_ATTESTATION_BYTES if key == "evidence_attestation" else MAX_ARTIFACT_BYTES
        )
        raw, payload, metadata = load_child(paths.get(key), label, maximum)
        raws[key] = raw
        payloads[key] = payload
        artifacts[key] = metadata
    evidence_public_key_raw, evidence_public_key_metadata = load_raw_child(
        paths.get("evidence_public_key"),
        "evidence public key",
        MAX_ATTESTATION_BYTES,
    )
    raws["evidence_public_key"] = evidence_public_key_raw
    artifacts["evidence_public_key"] = evidence_public_key_metadata

    runtime_status, contract_status, privacy_status = evaluate_evidence_manifest(
        payloads["evidence_manifest"],
        artifacts["evidence_manifest"],
        expected_runtime_version,
    )
    trio_supplied = (
        paths.get("evidence_attestation") is not None,
        paths.get("evidence_public_key") is not None,
        paths.get("expected_evidence_key_id") is not None,
    )
    attestation_status, evidence_signer = evaluate_evidence_attestation(
        raws["evidence_manifest"],
        raws["evidence_attestation"],
        raws["evidence_public_key"],
        paths.get("expected_evidence_key_id"),
        payloads["evidence_attestation_verification"],
        artifacts["evidence_attestation_verification"],
        trio_supplied,
    )
    runtime_status = combine_status(runtime_status, attestation_status)
    contract_status = combine_status(contract_status, attestation_status)
    privacy_status = combine_status(privacy_status, attestation_status)

    reproduction_status, apple_identity = evaluate_apple_reproducibility(
        payloads["apple_artifact_reproducibility"],
        artifacts["apple_artifact_reproducibility"],
        payloads["apple_artifact_verification"],
        payloads["apple_release_manifest"],
        artifacts["apple_release_manifest"],
        candidate_revision,
    )
    if reproduction_status == "pass":
        manifest_base = child_input_status(artifacts["evidence_manifest"])
        if manifest_base != "pass":
            reproduction_status = manifest_base
            apple_identity = None
        elif not evidence_manifest_binds_apple_identity(
            payloads["evidence_manifest"],
            apple_identity,
            artifacts["apple_artifact_reproducibility"].get("sha256"),
            artifacts["apple_artifact_verification"].get("sha256"),
        ):
            reproduction_status = "fail"
            apple_identity = None
    expected_source_revision = (
        apple_identity["source_revision"] if apple_identity is not None else None
    )
    artifact_status, source_tree_sha256 = evaluate_apple_artifact(
        payloads["apple_artifact_verification"],
        artifacts["apple_artifact_verification"],
        payloads["apple_release_manifest"],
        artifacts["apple_release_manifest"],
        expected_source_revision,
        expected_runtime_version,
    )
    artifact_status = combine_status(artifact_status, reproduction_status)
    operational_status, human_status = evaluate_pilot_gate(
        payloads["pilot_gate_report"],
        artifacts["pilot_gate_report"],
        candidate_revision,
    )
    pilot_signoff_status, pilot_signoff_identity = (
        evaluate_pilot_signoff_verification(
            payloads["pilot_signoff_verification"],
            artifacts["pilot_signoff_verification"],
            payloads["pilot_signoff_trust_policy"],
            artifacts["pilot_signoff_trust_policy"],
            paths.get("expected_pilot_signoff_trust_policy_sha256"),
            candidate_revision,
            payloads["pilot_gate_report"],
            evidence_signer,
            (
                paths.get("pilot_signoff_verification") is not None,
                paths.get("pilot_signoff_trust_policy") is not None,
                paths.get("expected_pilot_signoff_trust_policy_sha256") is not None,
            ),
        )
    )
    if (
        operational_status == "pass"
        and human_status == "pass"
        and pilot_signoff_status == "pass"
        and not (
            evidence_manifest_binds_pilot_gate(
                payloads["evidence_manifest"],
                payloads["pilot_gate_report"],
                artifacts["pilot_gate_report"].get("sha256"),
                payloads["pilot_signoff_verification"],
                artifacts["pilot_signoff_verification"].get("sha256"),
                candidate_revision,
            )
        )
    ):
        pilot_signoff_status = "fail"
        pilot_signoff_identity = None
    operational_status = combine_status(operational_status, pilot_signoff_status)
    human_status = combine_status(human_status, pilot_signoff_status)
    product_status = evaluate_product_acceptance(
        payloads["product_integration_acceptance"],
        artifacts["product_integration_acceptance"],
        candidate_revision,
        source_tree_sha256,
        apple_identity,
        artifacts,
        payloads["apple_release_manifest"],
        attestation_status,
        evidence_signer,
    )
    operational_status = combine_status(operational_status, product_status)
    human_status = combine_status(human_status, product_status)

    apple_manifest = payloads["apple_release_manifest"]
    model_disabled = (
        artifact_status == "pass"
        and product_status == "pass"
        and apple_manifest is not None
        and apple_manifest.get("cargo_features") == []
        and apple_manifest.get("model_bundle_included") is False
    )
    relay_disabled = product_status == "pass"
    product_acceptance = payloads["product_integration_acceptance"]
    profile_scope = {
        field: product_acceptance.get(field)
        if isinstance(product_acceptance, dict)
        and isinstance(product_acceptance.get(field), bool)
        else None
        for field in ("model_enabled", "relay_enabled", "military_enabled")
    }
    model_status = (
        "not_in_scope"
        if model_disabled
        else ("blocked" if product_status == "blocked" else "fail")
    )
    relay_status = (
        "not_in_scope"
        if relay_disabled
        else ("blocked" if product_status == "blocked" else "fail")
    )

    categories = {
        "artifact_integrity": artifact_status,
        "runtime_safety": runtime_status,
        "contract_compatibility": contract_status,
        "product_integration": product_status,
        "privacy_security": privacy_status,
        "operational_readiness": operational_status,
        "model_readiness": model_status,
        "relay_readiness": relay_status,
        "human_signoffs": human_status,
    }
    blocking_reasons = sorted(
        key
        for key, value in categories.items()
        if value not in ("pass", "not_in_scope")
    )
    for field, value in profile_scope.items():
        if value is not False:
            blocking_reasons.append(f"profile_scope.{field}")
    decision = "go" if not blocking_reasons else "no-go"
    payload = {
        "schema_version": DECISION_SCHEMA_VERSION,
        "generated_at_utc": now_utc(),
        "candidate": f"{expected_runtime_version}+{candidate_revision}",
        "profile": profile,
        "source_revision": (
            apple_identity["source_revision"] if apple_identity is not None else None
        ),
        "artifact_revision": (
            apple_identity["artifact_revision"] if apple_identity is not None else None
        ),
        "release_revision": candidate_revision,
        "source_tree_sha256": source_tree_sha256,
        "evidence_attestation_sha256": (
            artifacts["evidence_attestation"]["sha256"]
            if evidence_signer is not None
            else None
        ),
        "evidence_signer_signature_algorithm": (
            evidence_signer["signature_algorithm"]
            if evidence_signer is not None
            else None
        ),
        "evidence_signer_key_id": (
            evidence_signer["key_id"] if evidence_signer is not None else None
        ),
        "evidence_signer_spki_sha256": (
            evidence_signer["public_key_spki_sha256"]
            if evidence_signer is not None
            else None
        ),
        "evidence_signer_manifest_sha256": (
            evidence_signer["manifest_sha256"]
            if evidence_signer is not None
            else None
        ),
        "pilot_signoff_trust_policy_sha256": (
            pilot_signoff_identity["trust_policy_sha256"]
            if pilot_signoff_identity is not None
            else None
        ),
        "pilot_signoff_policy_id": (
            pilot_signoff_identity["policy_id"]
            if pilot_signoff_identity is not None
            else None
        ),
        "pilot_signoff_policy_epoch": (
            pilot_signoff_identity["policy_epoch"]
            if pilot_signoff_identity is not None
            else None
        ),
        "pilot_signoff_signer_spki_sha256": (
            pilot_signoff_identity["signer_spki_sha256"]
            if pilot_signoff_identity is not None
            else None
        ),
        "pilot_signoff_signer_spki_set_sha256": (
            pilot_signoff_identity["signer_spki_set_sha256"]
            if pilot_signoff_identity is not None
            else None
        ),
        **categories,
        "profile_scope": profile_scope,
        "decision": decision,
        "blocking_reasons": sorted(blocking_reasons),
        "artifacts": artifacts,
    }
    validate_decision(payload)
    return payload


def validate_artifact_metadata(metadata: object) -> None:
    if not isinstance(metadata, dict) or set(metadata) != ARTIFACT_FIELDS:
        raise ReleaseDecisionError("release decision artifact metadata is invalid")
    if metadata.get("required") is not True or not isinstance(
        metadata.get("present"), bool
    ):
        raise ReleaseDecisionError("release decision artifact presence is invalid")
    if metadata["present"]:
        if (
            not isinstance(metadata.get("bytes"), int)
            or isinstance(metadata.get("bytes"), bool)
            or not 1 <= metadata["bytes"] <= MAX_ARTIFACT_BYTES
            or not lowercase_sha256(metadata.get("sha256"))
        ):
            raise ReleaseDecisionError("release decision artifact identity is invalid")
    elif metadata.get("bytes") is not None or metadata.get("sha256") is not None:
        raise ReleaseDecisionError("missing release artifact cannot carry an identity")


def validate_decision(payload: dict) -> None:
    if set(payload) != DECISION_FIELDS:
        raise ReleaseDecisionError("release decision fields do not match v3")
    candidate = payload.get("candidate")
    source_revision = payload.get("source_revision")
    artifact_revision = payload.get("artifact_revision")
    release_revision = payload.get("release_revision")
    evidence_attestation_sha256 = payload.get("evidence_attestation_sha256")
    evidence_signer_signature_algorithm = payload.get(
        "evidence_signer_signature_algorithm"
    )
    evidence_signer_key_id = payload.get("evidence_signer_key_id")
    evidence_signer_spki_sha256 = payload.get("evidence_signer_spki_sha256")
    evidence_signer_manifest_sha256 = payload.get(
        "evidence_signer_manifest_sha256"
    )
    pilot_signoff_trust_policy_sha256 = payload.get(
        "pilot_signoff_trust_policy_sha256"
    )
    pilot_signoff_policy_id = payload.get("pilot_signoff_policy_id")
    pilot_signoff_policy_epoch = payload.get("pilot_signoff_policy_epoch")
    pilot_signoff_signer_spki_sha256 = payload.get(
        "pilot_signoff_signer_spki_sha256"
    )
    pilot_signoff_signer_spki_set_sha256 = payload.get(
        "pilot_signoff_signer_spki_set_sha256"
    )
    pilot_signoff_identity = (
        pilot_signoff_trust_policy_sha256,
        pilot_signoff_policy_id,
        pilot_signoff_policy_epoch,
        pilot_signoff_signer_spki_sha256,
        pilot_signoff_signer_spki_set_sha256,
    )
    if (
        payload.get("schema_version") != DECISION_SCHEMA_VERSION
        or payload.get("profile") != PROFILE
        or not git_revision(release_revision)
        or source_revision is not None and not git_revision(source_revision)
        or artifact_revision is not None and not git_revision(artifact_revision)
        or (source_revision is None) != (artifact_revision is None)
        or source_revision is not None and source_revision == artifact_revision
        or source_revision is not None and source_revision == release_revision
        or not isinstance(payload.get("generated_at_utc"), str)
        or not isinstance(candidate, str)
        or "+" not in candidate
        or candidate != f"{candidate.split('+', 1)[0]}+{release_revision}"
        or (evidence_attestation_sha256 is None)
        != (evidence_signer_signature_algorithm is None)
        or (evidence_signer_signature_algorithm is None)
        != (evidence_signer_key_id is None)
        or (evidence_signer_key_id is None)
        != (evidence_signer_spki_sha256 is None)
        or (evidence_signer_spki_sha256 is None)
        != (evidence_signer_manifest_sha256 is None)
        or evidence_attestation_sha256 is not None
        and not lowercase_sha256(evidence_attestation_sha256)
        or evidence_signer_signature_algorithm is not None
        and evidence_signer_signature_algorithm != SIGNATURE_ALGORITHM
        or evidence_signer_key_id is not None
        and (
            not isinstance(evidence_signer_key_id, str)
            or not crypto_support.safe_key_id(evidence_signer_key_id)
        )
        or evidence_signer_spki_sha256 is not None
        and not lowercase_sha256(evidence_signer_spki_sha256)
        or evidence_signer_manifest_sha256 is not None
        and not lowercase_sha256(evidence_signer_manifest_sha256)
        or any(value is None for value in pilot_signoff_identity)
        and not all(value is None for value in pilot_signoff_identity)
        or pilot_signoff_trust_policy_sha256 is not None
        and not lowercase_sha256(pilot_signoff_trust_policy_sha256)
        or pilot_signoff_policy_id is not None
        and (
            not isinstance(pilot_signoff_policy_id, str)
            or not crypto_support.safe_key_id(pilot_signoff_policy_id)
        )
        or pilot_signoff_policy_epoch is not None
        and not _pilot_policy_epoch(pilot_signoff_policy_epoch)
        or pilot_signoff_signer_spki_sha256 is not None
        and (
            not isinstance(pilot_signoff_signer_spki_sha256, list)
            or len(pilot_signoff_signer_spki_sha256)
            != len(PILOT_REQUIRED_REVIEW_AREAS)
            or any(
                not lowercase_sha256(value)
                for value in pilot_signoff_signer_spki_sha256
            )
            or len(set(pilot_signoff_signer_spki_sha256))
            != len(pilot_signoff_signer_spki_sha256)
        )
        or pilot_signoff_signer_spki_set_sha256 is not None
        and not lowercase_sha256(pilot_signoff_signer_spki_set_sha256)
        or pilot_signoff_signer_spki_sha256 is not None
        and not hmac.compare_digest(
            pilot_signoff_signer_spki_set_sha256,
            pilot_signoff_support.signer_spki_set_sha256(
                pilot_signoff_signer_spki_sha256
            ),
        )
        or evidence_signer_spki_sha256 is not None
        and pilot_signoff_signer_spki_sha256 is not None
        and evidence_signer_spki_sha256 in pilot_signoff_signer_spki_sha256
    ):
        raise ReleaseDecisionError("release decision identity is invalid")
    try:
        generated_at = datetime.fromisoformat(payload["generated_at_utc"])
    except ValueError as error:
        raise ReleaseDecisionError("release decision timestamp is invalid") from error
    if generated_at.tzinfo is None or generated_at.utcoffset() != timezone.utc.utcoffset(
        generated_at
    ):
        raise ReleaseDecisionError("release decision timestamp must be UTC")
    runtime = candidate.split("+", 1)[0]
    if not runtime_version(runtime):
        raise ReleaseDecisionError("release decision runtime version is invalid")
    source_tree_sha256 = payload.get("source_tree_sha256")
    if source_tree_sha256 is not None and not lowercase_sha256(source_tree_sha256):
        raise ReleaseDecisionError("release decision source tree identity is invalid")
    categories = (
        "artifact_integrity",
        "runtime_safety",
        "contract_compatibility",
        "product_integration",
        "privacy_security",
        "operational_readiness",
        "human_signoffs",
    )
    if any(payload.get(field) not in ("pass", "blocked", "fail") for field in categories):
        raise ReleaseDecisionError("release decision category status is invalid")
    if payload.get("model_readiness") not in ("not_in_scope", "blocked", "fail"):
        raise ReleaseDecisionError("release decision model status is invalid")
    if payload.get("relay_readiness") not in ("not_in_scope", "blocked", "fail"):
        raise ReleaseDecisionError("release decision relay status is invalid")
    scope = payload.get("profile_scope")
    if not isinstance(scope, dict) or set(scope) != {
        "model_enabled",
        "relay_enabled",
        "military_enabled",
    }:
        raise ReleaseDecisionError("release decision profile scope is invalid")
    if any(
        value is not True and value is not False and value is not None
        for value in scope.values()
    ):
        raise ReleaseDecisionError("release decision profile scope values are invalid")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "evidence_manifest",
        "evidence_attestation",
        "evidence_public_key",
        "evidence_attestation_verification",
        "apple_artifact_verification",
        "apple_artifact_reproducibility",
        "apple_release_manifest",
        "pilot_gate_report",
        "pilot_signoff_verification",
        "pilot_signoff_trust_policy",
        "product_integration_acceptance",
    }:
        raise ReleaseDecisionError("release decision artifact set is invalid")
    for metadata in artifacts.values():
        validate_artifact_metadata(metadata)
    reasons = payload.get("blocking_reasons")
    if (
        not isinstance(reasons, list)
        or reasons != sorted(set(reasons))
        or any(not isinstance(reason, str) or not reason for reason in reasons)
    ):
        raise ReleaseDecisionError("release decision blocking reasons are invalid")
    expected_reasons = sorted(
        [
            field
            for field in (*categories, "model_readiness", "relay_readiness")
            if payload[field] not in ("pass", "not_in_scope")
        ]
        + [
            f"profile_scope.{field}"
            for field, value in scope.items()
            if value is not False
        ]
    )
    if reasons != expected_reasons:
        raise ReleaseDecisionError("release decision blocking reasons are inconsistent")
    go_ready = (
        all(payload[field] == "pass" for field in categories)
        and payload["model_readiness"] == "not_in_scope"
        and payload["relay_readiness"] == "not_in_scope"
        and scope == {
            "model_enabled": False,
            "relay_enabled": False,
            "military_enabled": False,
        }
        and not reasons
        and lowercase_sha256(source_tree_sha256)
        and git_revision(source_revision)
        and git_revision(artifact_revision)
        and lowercase_sha256(evidence_attestation_sha256)
        and evidence_signer_signature_algorithm == SIGNATURE_ALGORITHM
        and isinstance(evidence_signer_key_id, str)
        and crypto_support.safe_key_id(evidence_signer_key_id)
        and lowercase_sha256(evidence_signer_spki_sha256)
        and lowercase_sha256(evidence_signer_manifest_sha256)
        and lowercase_sha256(pilot_signoff_trust_policy_sha256)
        and isinstance(pilot_signoff_policy_id, str)
        and crypto_support.safe_key_id(pilot_signoff_policy_id)
        and _pilot_policy_epoch(pilot_signoff_policy_epoch)
        and isinstance(pilot_signoff_signer_spki_sha256, list)
        and len(pilot_signoff_signer_spki_sha256)
        == len(PILOT_REQUIRED_REVIEW_AREAS)
        and all(
            lowercase_sha256(value)
            for value in pilot_signoff_signer_spki_sha256
        )
        and len(set(pilot_signoff_signer_spki_sha256))
        == len(pilot_signoff_signer_spki_sha256)
        and evidence_signer_spki_sha256 not in pilot_signoff_signer_spki_sha256
        and lowercase_sha256(pilot_signoff_signer_spki_set_sha256)
        and evidence_signer_manifest_sha256
        == artifacts["evidence_manifest"]["sha256"]
        and evidence_attestation_sha256
        == artifacts["evidence_attestation"]["sha256"]
        and all(
            metadata["present"] is True
            and isinstance(metadata["bytes"], int)
            and lowercase_sha256(metadata["sha256"])
            for metadata in artifacts.values()
        )
    )
    if payload.get("decision") not in ("go", "no-go"):
        raise ReleaseDecisionError("release decision outcome is invalid")
    if (payload["decision"] == "go") != go_ready:
        raise ReleaseDecisionError("release decision outcome contradicts its evidence")


def load_decision(path: Path) -> tuple[bytes, dict]:
    raw = read_stable_regular_file(path, MAX_ARTIFACT_BYTES, "release decision")
    try:
        payload = strict_json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ReleaseDecisionError("release decision is invalid JSON") from error
    if not isinstance(payload, dict):
        raise ReleaseDecisionError("release decision must be a JSON object")
    validate_decision(payload)
    return raw, payload


def verify_decision_evidence(decision: dict, paths: dict[str, str | None]) -> None:
    runtime = decision["candidate"].split("+", 1)[0]
    recomputed = create_decision(
        decision["release_revision"],
        runtime,
        decision["profile"],
        paths,
    )
    comparable_fields = DECISION_FIELDS - {"generated_at_utc"}
    if any(recomputed[field] != decision[field] for field in comparable_fields):
        raise ReleaseDecisionError(
            "release decision does not match the supplied source evidence"
        )


def canonical_attestation_claims(attestation: dict) -> bytes:
    claims = {
        field: attestation[field]
        for field in sorted(ATTESTATION_FIELDS - {"signature_base64"})
    }
    return SIGNED_PAYLOAD_DOMAIN + json.dumps(
        claims,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sign_decision(
    decision_path: Path,
    private_key_path: Path,
    key_id: str,
    evidence_paths: dict[str, str | None],
) -> dict:
    if not crypto_support.safe_key_id(key_id):
        raise ReleaseDecisionError("release decision key_id is invalid")
    decision_raw, decision = load_decision(decision_path)
    if decision["decision"] != "go":
        raise ReleaseDecisionError("only a GO release decision may be signed")
    verify_decision_evidence(decision, evidence_paths)
    private_key_raw, private_key_mode = read_stable_regular_file_with_mode(
        private_key_path, MAX_ATTESTATION_BYTES, "private key"
    )
    if os.name != "nt" and (private_key_mode & 0o077) != 0:
        raise ReleaseDecisionError("Ed25519 private key permissions are too broad")
    with tempfile.NamedTemporaryFile() as stable_private_key:
        if os.name != "nt":
            os.fchmod(stable_private_key.fileno(), 0o600)
        stable_private_key.write(private_key_raw)
        stable_private_key.flush()
        stable_private_key_path = Path(stable_private_key.name)
        public_key_der = crypto_support.public_key_der_from_private(
            stable_private_key_path
        )
        operator_spki_sha256 = sha256(public_key_der).hexdigest()
        if hmac.compare_digest(
            operator_spki_sha256, decision["evidence_signer_spki_sha256"]
        ):
            raise ReleaseDecisionError(
                "release operator key must differ from evidence signer key"
            )
        if any(
            hmac.compare_digest(operator_spki_sha256, signer)
            for signer in decision["pilot_signoff_signer_spki_sha256"]
        ):
            raise ReleaseDecisionError(
                "release operator key must differ from pilot signoff keys"
            )
        attestation = {
            "schema_version": ATTESTATION_SCHEMA_VERSION,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "key_id": key_id,
            "decision_sha256": sha256(decision_raw).hexdigest(),
            "candidate": decision["candidate"],
            "profile": decision["profile"],
            "source_revision": decision["source_revision"],
            "artifact_revision": decision["artifact_revision"],
            "release_revision": decision["release_revision"],
            "evidence_signer_key_id": decision["evidence_signer_key_id"],
            "evidence_signer_spki_sha256": decision[
                "evidence_signer_spki_sha256"
            ],
            "pilot_signoff_trust_policy_sha256": decision[
                "pilot_signoff_trust_policy_sha256"
            ],
            "pilot_signoff_policy_id": decision["pilot_signoff_policy_id"],
            "pilot_signoff_policy_epoch": decision["pilot_signoff_policy_epoch"],
            "pilot_signoff_signer_spki_sha256": decision[
                "pilot_signoff_signer_spki_sha256"
            ],
            "pilot_signoff_signer_spki_set_sha256": decision[
                "pilot_signoff_signer_spki_set_sha256"
            ],
            "public_key_spki_sha256": operator_spki_sha256,
        }
        with tempfile.NamedTemporaryFile() as claims_file:
            claims_file.write(canonical_attestation_claims(attestation))
            claims_file.flush()
            signature = crypto_support.run_openssl(
                [
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    stable_private_key.name,
                    "-in",
                    claims_file.name,
                ]
            )
    if len(signature) != 64:
        raise ReleaseDecisionError("OpenSSL returned a malformed Ed25519 signature")
    attestation["signature_base64"] = base64.b64encode(signature).decode("ascii")
    return attestation


def load_attestation(path: Path) -> dict:
    raw = read_stable_regular_file(path, MAX_ATTESTATION_BYTES, "release attestation")
    try:
        payload = strict_json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ReleaseDecisionError("release attestation is invalid JSON") from error
    if not isinstance(payload, dict) or set(payload) != ATTESTATION_FIELDS:
        raise ReleaseDecisionError("release attestation fields do not match v3")
    if (
        payload.get("schema_version") != ATTESTATION_SCHEMA_VERSION
        or payload.get("signature_algorithm") != SIGNATURE_ALGORITHM
        or not isinstance(payload.get("key_id"), str)
        or not crypto_support.safe_key_id(payload["key_id"])
        or not lowercase_sha256(payload.get("decision_sha256"))
        or not lowercase_sha256(payload.get("public_key_spki_sha256"))
        or payload.get("profile") != PROFILE
        or not git_revision(payload.get("source_revision"))
        or not git_revision(payload.get("artifact_revision"))
        or not git_revision(payload.get("release_revision"))
        or payload.get("source_revision") == payload.get("artifact_revision")
        or payload.get("source_revision") == payload.get("release_revision")
        or not isinstance(payload.get("evidence_signer_key_id"), str)
        or not crypto_support.safe_key_id(payload["evidence_signer_key_id"])
        or not lowercase_sha256(payload.get("evidence_signer_spki_sha256"))
        or not lowercase_sha256(
            payload.get("pilot_signoff_trust_policy_sha256")
        )
        or not isinstance(payload.get("pilot_signoff_policy_id"), str)
        or not crypto_support.safe_key_id(payload["pilot_signoff_policy_id"])
        or not _pilot_policy_epoch(payload.get("pilot_signoff_policy_epoch"))
        or not isinstance(payload.get("pilot_signoff_signer_spki_sha256"), list)
        or len(payload["pilot_signoff_signer_spki_sha256"])
        != len(PILOT_REQUIRED_REVIEW_AREAS)
        or any(
            not lowercase_sha256(value)
            for value in payload["pilot_signoff_signer_spki_sha256"]
        )
        or len(set(payload["pilot_signoff_signer_spki_sha256"]))
        != len(payload["pilot_signoff_signer_spki_sha256"])
        or payload["evidence_signer_spki_sha256"]
        in payload["pilot_signoff_signer_spki_sha256"]
        or not lowercase_sha256(
            payload.get("pilot_signoff_signer_spki_set_sha256")
        )
        or not hmac.compare_digest(
            payload["pilot_signoff_signer_spki_set_sha256"],
            pilot_signoff_support.signer_spki_set_sha256(
                payload["pilot_signoff_signer_spki_sha256"]
            ),
        )
    ):
        raise ReleaseDecisionError("release attestation claims are invalid")
    try:
        signature = base64.b64decode(payload["signature_base64"], validate=True)
    except (binascii.Error, TypeError, ValueError) as error:
        raise ReleaseDecisionError("release attestation signature is malformed") from error
    if len(signature) != 64:
        raise ReleaseDecisionError("release attestation signature is malformed")
    return payload


def verify_decision(
    decision_path: Path,
    attestation_path: Path,
    public_key_path: Path,
    expected_key_id: str | None = None,
) -> dict:
    decision_raw, decision = load_decision(decision_path)
    if decision["decision"] != "go":
        raise ReleaseDecisionError("signed release decision is not GO")
    attestation = load_attestation(attestation_path)
    public_key_raw = read_stable_regular_file(
        public_key_path, MAX_ATTESTATION_BYTES, "public key"
    )
    if expected_key_id is not None and not hmac.compare_digest(
        attestation["key_id"], expected_key_id
    ):
        raise ReleaseDecisionError("release attestation key_id is not trusted")
    expected_bindings = {
        "decision_sha256": sha256(decision_raw).hexdigest(),
        "candidate": decision["candidate"],
        "profile": decision["profile"],
        "source_revision": decision["source_revision"],
        "artifact_revision": decision["artifact_revision"],
        "release_revision": decision["release_revision"],
        "evidence_signer_key_id": decision["evidence_signer_key_id"],
        "evidence_signer_spki_sha256": decision["evidence_signer_spki_sha256"],
        "pilot_signoff_trust_policy_sha256": decision[
            "pilot_signoff_trust_policy_sha256"
        ],
        "pilot_signoff_policy_id": decision["pilot_signoff_policy_id"],
        "pilot_signoff_policy_epoch": decision["pilot_signoff_policy_epoch"],
        "pilot_signoff_signer_spki_sha256": decision[
            "pilot_signoff_signer_spki_sha256"
        ],
        "pilot_signoff_signer_spki_set_sha256": decision[
            "pilot_signoff_signer_spki_set_sha256"
        ],
    }
    if any(
        not hmac.compare_digest(str(attestation[field]), str(value))
        for field, value in expected_bindings.items()
    ):
        raise ReleaseDecisionError("release attestation does not bind this decision")
    with (
        tempfile.NamedTemporaryFile() as stable_public_key,
        tempfile.NamedTemporaryFile() as signature_file,
        tempfile.NamedTemporaryFile() as claims_file,
    ):
        stable_public_key.write(public_key_raw)
        stable_public_key.flush()
        public_key_digest = sha256(
            crypto_support.public_key_der_from_public(Path(stable_public_key.name))
        ).hexdigest()
        if not hmac.compare_digest(
            attestation["public_key_spki_sha256"], public_key_digest
        ):
            raise ReleaseDecisionError(
                "trusted public key does not match release attestation"
            )
        if hmac.compare_digest(
            public_key_digest, decision["evidence_signer_spki_sha256"]
        ):
            raise ReleaseDecisionError(
                "release operator key must differ from evidence signer key"
            )
        if any(
            hmac.compare_digest(public_key_digest, signer)
            for signer in decision["pilot_signoff_signer_spki_sha256"]
        ):
            raise ReleaseDecisionError(
                "release operator key must differ from pilot signoff keys"
            )
        signature = base64.b64decode(
            attestation["signature_base64"], validate=True
        )
        signature_file.write(signature)
        signature_file.flush()
        claims_file.write(canonical_attestation_claims(attestation))
        claims_file.flush()
        crypto_support.run_openssl(
            [
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                stable_public_key.name,
                "-sigfile",
                signature_file.name,
                "-in",
                claims_file.name,
            ]
        )
    return {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "status": "pass",
        "decision": "go",
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "key_id": attestation["key_id"],
        "candidate": decision["candidate"],
        "profile": decision["profile"],
        "source_revision": decision["source_revision"],
        "artifact_revision": decision["artifact_revision"],
        "release_revision": decision["release_revision"],
        "evidence_signer_key_id": decision["evidence_signer_key_id"],
        "evidence_signer_spki_sha256": decision["evidence_signer_spki_sha256"],
        "pilot_signoff_trust_policy_sha256": decision[
            "pilot_signoff_trust_policy_sha256"
        ],
        "pilot_signoff_policy_id": decision["pilot_signoff_policy_id"],
        "pilot_signoff_policy_epoch": decision["pilot_signoff_policy_epoch"],
        "pilot_signoff_signer_spki_sha256": decision[
            "pilot_signoff_signer_spki_sha256"
        ],
        "pilot_signoff_signer_spki_set_sha256": decision[
            "pilot_signoff_signer_spki_set_sha256"
        ],
        "source_tree_sha256": decision["source_tree_sha256"],
        "decision_sha256": expected_bindings["decision_sha256"],
        "public_key_spki_sha256": public_key_digest,
    }


def protected_input_paths(args: argparse.Namespace) -> list[Path]:
    result = []
    for field in (
        "evidence_manifest",
        "evidence_attestation",
        "evidence_public_key",
        "evidence_attestation_verification",
        "apple_artifact_verification",
        "apple_artifact_reproducibility",
        "apple_release_manifest",
        "pilot_gate_report",
        "pilot_signoff_verification",
        "pilot_signoff_trust_policy",
        "product_integration_acceptance",
        "decision",
        "attestation",
        "private_key",
        "public_key",
    ):
        value = getattr(args, field, None)
        if value:
            result.append(Path(value))
    return result


def ensure_distinct_release_output(output: Path, protected_paths: list[Path]) -> None:
    crypto_support.ensure_distinct_output(output, protected_paths)
    try:
        output_metadata = os.stat(output, follow_symlinks=False)
    except FileNotFoundError:
        return
    output_identity = (output_metadata.st_dev, output_metadata.st_ino)
    for protected in protected_paths:
        try:
            protected_metadata = os.stat(protected, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if output_identity == (protected_metadata.st_dev, protected_metadata.st_ino):
            raise ReleaseDecisionError(
                "release output must not overwrite or alias an input"
            )


def main() -> int:
    args = parse_args()
    try:
        if args.command == "create":
            output = Path(args.output)
            ensure_distinct_release_output(output, protected_input_paths(args))
            decision = create_decision(
                args.candidate_revision,
                args.runtime_version,
                args.profile,
                {
                    "evidence_manifest": args.evidence_manifest,
                    "evidence_attestation": args.evidence_attestation,
                    "evidence_public_key": args.evidence_public_key,
                    "expected_evidence_key_id": args.expected_evidence_key_id,
                    "evidence_attestation_verification": (
                        args.evidence_attestation_verification
                    ),
                    "apple_artifact_verification": args.apple_artifact_verification,
                    "apple_artifact_reproducibility": (
                        args.apple_artifact_reproducibility
                    ),
                    "apple_release_manifest": args.apple_release_manifest,
                    "pilot_gate_report": args.pilot_gate_report,
                    "pilot_signoff_verification": (
                        args.pilot_signoff_verification
                    ),
                    "pilot_signoff_trust_policy": (
                        args.pilot_signoff_trust_policy
                    ),
                    "expected_pilot_signoff_trust_policy_sha256": (
                        args.expected_pilot_signoff_trust_policy_sha256
                    ),
                    "product_integration_acceptance": (
                        args.product_integration_acceptance
                    ),
                },
            )
            crypto_support.write_json_atomic(output, decision)
            print(f"release decision written to {output} (decision={decision['decision']})")
            return 0 if decision["decision"] == "go" or not args.require_go else 1

        if args.command == "sign":
            output = Path(args.output)
            ensure_distinct_release_output(output, protected_input_paths(args))
            attestation = sign_decision(
                Path(args.decision),
                Path(args.private_key),
                args.key_id,
                {
                    "evidence_manifest": args.evidence_manifest,
                    "evidence_attestation": args.evidence_attestation,
                    "evidence_public_key": args.evidence_public_key,
                    "expected_evidence_key_id": args.expected_evidence_key_id,
                    "evidence_attestation_verification": (
                        args.evidence_attestation_verification
                    ),
                    "apple_artifact_verification": (
                        args.apple_artifact_verification
                    ),
                    "apple_artifact_reproducibility": (
                        args.apple_artifact_reproducibility
                    ),
                    "apple_release_manifest": args.apple_release_manifest,
                    "pilot_gate_report": args.pilot_gate_report,
                    "pilot_signoff_verification": (
                        args.pilot_signoff_verification
                    ),
                    "pilot_signoff_trust_policy": (
                        args.pilot_signoff_trust_policy
                    ),
                    "expected_pilot_signoff_trust_policy_sha256": (
                        args.expected_pilot_signoff_trust_policy_sha256
                    ),
                    "product_integration_acceptance": (
                        args.product_integration_acceptance
                    ),
                },
            )
            crypto_support.write_json_atomic(output, attestation)
            print(f"release decision attestation written to {output}")
            return 0

        output = Path(args.output) if args.output else None
        if output is not None:
            ensure_distinct_release_output(output, protected_input_paths(args))
        report = verify_decision(
            Path(args.decision),
            Path(args.attestation),
            Path(args.public_key),
            args.expected_key_id,
        )
        if output is not None:
            crypto_support.write_json_atomic(output, report)
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["status"] == "pass" or not args.require_pass else 1
    except (ReleaseDecisionError, OSError, ValueError) as error:
        print(f"release decision error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
