#!/usr/bin/env python3

import argparse
import json
import math
import os
import stat
import sys
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path


SCHEMA_VERSION = "aura.evidence_manifest.v1"
PILOT_SHADOW_SCHEMA_VERSION = "aura.shadow_mode_bundle.v1"
TEMPORAL_SHADOW_SCHEMA_VERSION = "aura.military.temporal_shadow_report.v1"
TEMPORAL_REVIEW_SCHEMA_VERSION = "aura.military.temporal_review_report.v5"
TEMPORAL_STUDY_ATTESTATION_VERIFICATION_SCHEMA_VERSION = (
    "aura.military.temporal_study_attestation_verification.v1"
)
TEMPORAL_STUDY_TIMESTAMP_VERIFICATION_SCHEMA_VERSION = (
    "aura.military.temporal_study_timestamp_verification.v3"
)
TEMPORAL_REVIEW_RECEIPT_CHAIN_VERIFICATION_SCHEMA_VERSION = (
    "aura.military.temporal_review_receipt_chain_verification.v4"
)
TEMPORAL_TELEMETRY_VALIDATION_SCHEMA_VERSION = (
    "aura.military.temporal_shadow_telemetry_validation.v1"
)
TEMPORAL_TELEMETRY_SCHEMA_VERSION = "aura.military.temporal_shadow_telemetry.v1"
MAX_JSON_ARTIFACT_BYTES = 256 * 1024 * 1024


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
        "--temporal-study-timestamp-verification",
        default=None,
        help="Optional path to RFC 3161 verification of the temporal study commitment.",
    )
    parser.add_argument(
        "--temporal-review-receipt-chain-verification",
        default=None,
        help=(
            "Optional path to aggregate verification of individually signed and "
            "RFC 3161 timestamped temporal-review receipts."
        ),
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
    parser.add_argument(
        "--apple-artifact-reproducibility",
        default=None,
        help="Optional path to Apple deterministic-rebuild verification JSON.",
    )
    return parser.parse_args()


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def strict_json_loads(raw: bytes) -> object:
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_strict_json_object,
        parse_constant=_reject_json_constant,
    )


def read_json_artifact_snapshot(path: Path) -> bytes:
    flags = os.O_RDONLY
    for name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, name, 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("artifact is not a regular file")
        if not 1 <= metadata.st_size <= MAX_JSON_ARTIFACT_BYTES:
            raise ValueError(
                "artifact size must be within "
                f"1..={MAX_JSON_ARTIFACT_BYTES} bytes"
            )
        chunks = []
        remaining = MAX_JSON_ARTIFACT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        final_metadata = os.fstat(descriptor)
        identity_before = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        identity_after = (
            final_metadata.st_dev,
            final_metadata.st_ino,
            final_metadata.st_mode,
            final_metadata.st_nlink,
            final_metadata.st_size,
            final_metadata.st_mtime_ns,
            final_metadata.st_ctime_ns,
        )
        if (
            not raw
            or len(raw) > MAX_JSON_ARTIFACT_BYTES
            or len(raw) != metadata.st_size
            or identity_before != identity_after
        ):
            raise ValueError("artifact changed while it was being read")
        return raw
    finally:
        os.close(descriptor)


def load_json_artifact(path_str: str, required: bool) -> tuple[dict | None, dict]:
    path = Path(path_str)
    artifact = {
        "required": required,
        "path": path.as_posix(),
    }
    try:
        raw = read_json_artifact_snapshot(path)
    except FileNotFoundError:
        artifact["exists"] = False
        artifact["status"] = "missing"
        return None, artifact
    except (OSError, ValueError) as error:
        artifact["exists"] = True
        artifact["status"] = "invalid_file"
        artifact["error"] = str(error)
        return None, artifact

    artifact.update(
        {
            "exists": True,
            "bytes": len(raw),
            "sha256": sha256(raw).hexdigest(),
        }
    )
    try:
        payload = strict_json_loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("top-level JSON value must be an object")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
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
        review_bundle_digest = payload.get("review_bundle_canonical_sha256")
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
        if not lowercase_sha256(review_bundle_digest):
            return "invalid_review_bundle_identity"
        if payload.get("study_corpus_class") != "embargoed_external":
            return "insufficient_external_validity"
        chronology = payload.get("chronology")
        if (
            not isinstance(chronology, dict)
            or chronology.get("decision_time_assurance") != "bundle_declared"
        ):
            return "invalid_review_chronology"
        chronology_fields = (
            "declared_preregistration_at_ms",
            "earliest_annotation_completed_at_ms",
            "latest_annotation_completed_at_ms",
            "earliest_adjudication_completed_at_ms",
            "latest_adjudication_completed_at_ms",
        )
        chronology_values = [chronology.get(field) for field in chronology_fields]
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in chronology_values
        ):
            return "invalid_review_chronology"
        (
            registered_at_ms,
            earliest_annotation_ms,
            latest_annotation_ms,
            earliest_adjudication_ms,
            latest_adjudication_ms,
        ) = chronology_values
        if (
            registered_at_ms >= earliest_annotation_ms
            or earliest_annotation_ms > latest_annotation_ms
            or registered_at_ms >= earliest_adjudication_ms
            or earliest_adjudication_ms > latest_adjudication_ms
            or latest_annotation_ms >= earliest_adjudication_ms
        ):
            return "invalid_review_chronology"
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


def valid_oid(value: object) -> bool:
    if not isinstance(value, str) or not 3 <= len(value) <= 128:
        return False
    components = value.split(".")
    if len(components) < 3 or any(
        not component.isascii()
        or not component.isdigit()
        or (len(component) > 1 and component.startswith("0"))
        for component in components
    ):
        return False
    first = int(components[0])
    second = int(components[1])
    return first in (0, 1, 2) and (first == 2 or second <= 39)


def lowercase_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def historical_crl_claims_valid(payload: dict) -> bool:
    if (
        payload.get("revocation_assurance") != "full_chain_crl_at_gen_time"
        or payload.get("revocation_evidence_kind") != "offline_complete_crl"
        or payload.get("revocation_validation_time_basis") != "tsa_gen_time"
        or payload.get("revocation_scope") != "full_non_anchor_chain"
        or payload.get("revocation_network_fetch_used") is not False
        or payload.get("revocation_delta_crls_used") is not False
        or payload.get("revocation_indirect_crls_used") is not False
    ):
        return False
    gen_time = payload.get("gen_time_unix_ms")
    submillisecond_micros = payload.get("gen_time_submillisecond_micros")
    checked_count = payload.get("revocation_checked_certificate_count")
    crl_count = payload.get("revocation_crl_count")
    crls = payload.get("revocation_crls")
    digests = payload.get("revocation_crl_der_sha256s")
    if (
        isinstance(gen_time, bool)
        or not isinstance(gen_time, int)
        or gen_time <= 0
        or isinstance(submillisecond_micros, bool)
        or not isinstance(submillisecond_micros, int)
        or not 0 <= submillisecond_micros <= 999
        or isinstance(checked_count, bool)
        or not isinstance(checked_count, int)
        or checked_count <= 0
        or isinstance(crl_count, bool)
        or not isinstance(crl_count, int)
        or crl_count > 6
        or crl_count != checked_count
        or not isinstance(crls, list)
        or len(crls) != crl_count
        or not isinstance(digests, list)
        or len(digests) != crl_count
        or digests != sorted(set(digests))
        or any(not lowercase_sha256(digest) for digest in digests)
    ):
        return False
    expected_fields = {
        "issuer_name_sha256",
        "this_update_unix_ms",
        "next_update_unix_ms",
        "crl_number_hex",
        "der_sha256",
    }
    issuer_digests = set()
    observed_digests = []
    exact_gen_time_micros = gen_time * 1_000 + submillisecond_micros
    for crl in crls:
        if not isinstance(crl, dict) or set(crl) != expected_fields:
            return False
        issuer_digest = crl.get("issuer_name_sha256")
        der_digest = crl.get("der_sha256")
        this_update = crl.get("this_update_unix_ms")
        next_update = crl.get("next_update_unix_ms")
        number = crl.get("crl_number_hex")
        if (
            not lowercase_sha256(issuer_digest)
            or issuer_digest in issuer_digests
            or not lowercase_sha256(der_digest)
            or isinstance(this_update, bool)
            or not isinstance(this_update, int)
            or isinstance(next_update, bool)
            or not isinstance(next_update, int)
            or not this_update * 1_000
            <= exact_gen_time_micros
            <= next_update * 1_000
            or next_update <= this_update
            or not isinstance(number, str)
            or not number.startswith("0x")
            or not 1 <= len(number[2:]) <= 40
            or any(character not in "0123456789abcdef" for character in number[2:])
        ):
            return False
        issuer_digests.add(issuer_digest)
        observed_digests.append(der_digest)
    revocation_evidence_digest = payload.get("revocation_evidence_sha256")
    if not lowercase_sha256(revocation_evidence_digest):
        return False
    framed_revocation = bytearray(
        b"aura.domain.rfc3161-revocation-evidence.v1\0"
    )
    framed_revocation.extend(len(digests).to_bytes(4, byteorder="big"))
    for digest in digests:
        framed_revocation.extend(bytes.fromhex(digest))
    return (
        observed_digests == digests
        and lowercase_sha256(payload.get("revocation_crl_set_sha256"))
        and payload["revocation_crl_set_sha256"]
        == sha256("\n".join(digests).encode("ascii")).hexdigest()
        and revocation_evidence_digest == sha256(framed_revocation).hexdigest()
    )


def selected_certificate_chain_claims_valid(payload: dict) -> bool:
    digests = payload.get("certificate_chain_der_sha256s")
    if (
        payload.get("certificate_chain_order") != "tsa_signer_to_trust_anchor"
        or not isinstance(digests, list)
        or not 2 <= len(digests) <= 7
        or len(set(digests)) != len(digests)
        or any(not lowercase_sha256(digest) for digest in digests)
        or not lowercase_sha256(payload.get("tsa_signer_certificate_sha256"))
        or digests[0] != payload.get("tsa_signer_certificate_sha256")
        or payload.get("revocation_checked_certificate_count") != len(digests) - 1
    ):
        return False
    framed = bytearray(b"aura.domain.rfc3161-certificate-chain.v1\0")
    framed.extend(len(digests).to_bytes(4, byteorder="big"))
    for digest in digests:
        framed.extend(bytes.fromhex(digest))
    return payload.get("certificate_chain_sha256") == sha256(framed).hexdigest()


def temporal_study_timestamp_verification_status(
    payload: dict | None,
    temporal_independent_review_payload: dict | None,
    temporal_study_attestation_verification_payload: dict | None,
) -> str | None:
    if payload is None:
        return None
    if (
        payload.get("schema_version")
        != TEMPORAL_STUDY_TIMESTAMP_VERIFICATION_SCHEMA_VERSION
    ):
        return "invalid_schema"
    if payload.get("status") != "pass":
        return "fail"
    if (
        payload.get("timestamp_protocol") != "RFC3161"
        or payload.get("trusted_timestamp_assurance")
        != "rfc3161_trusted_chain"
        or payload.get("message_imprint_algorithm") != "sha256"
        or payload.get("certificate_validation_time_basis") != "tsa_gen_time"
        or payload.get("revocation_assurance") != "full_chain_crl_at_gen_time"
        or payload.get("request_nonce_present") is not True
    ):
        return "invalid_timestamp_assurance"
    if not historical_crl_claims_valid(payload):
        return "invalid_timestamp_revocation_evidence"
    if not selected_certificate_chain_claims_valid(payload):
        return "invalid_timestamp_identity"
    if not valid_oid(payload.get("policy_oid")):
        return "invalid_timestamp_identity"
    serial = payload.get("serial_hex")
    if (
        not isinstance(serial, str)
        or not serial.startswith("0x")
        or not 1 <= len(serial[2:]) <= 40
        or any(character not in "0123456789abcdef" for character in serial[2:])
    ):
        return "invalid_timestamp_identity"
    ordering = payload.get("ordering")
    submillisecond_micros = payload.get("gen_time_submillisecond_micros")
    accuracy_micros = payload.get("accuracy_micros")
    earliest_trusted_time_ms = payload.get("earliest_trusted_time_unix_ms")
    latest_trusted_time_ms = payload.get("latest_trusted_time_unix_ms")
    if (
        not isinstance(ordering, bool)
        or isinstance(submillisecond_micros, bool)
        or not isinstance(submillisecond_micros, int)
        or not 0 <= submillisecond_micros <= 999
        or isinstance(accuracy_micros, bool)
        or not isinstance(accuracy_micros, int)
        or not 0 < accuracy_micros <= 5 * 60 * 1_000_000
    ):
        return "invalid_timestamp_identity"
    for field in (
        "commitment_file_sha256",
        "commitment_canonical_sha256",
        "preregistration_canonical_sha256",
        "corpus_sha256",
        "packet_canonical_sha256",
        "request_sha256",
        "response_sha256",
        "tsa_signer_certificate_sha256",
        "tsa_signer_spki_sha256",
        "trust_anchor_bundle_sha256",
    ):
        digest = payload.get(field)
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            return "invalid_timestamp_identity"
    untrusted_chain_digest = payload.get("untrusted_chain_sha256")
    if untrusted_chain_digest is not None and (
        not isinstance(untrusted_chain_digest, str)
        or len(untrusted_chain_digest) != 64
        or any(
            character not in "0123456789abcdef"
            for character in untrusted_chain_digest
        )
    ):
        return "invalid_timestamp_identity"
    for field in (
        "registered_at_ms",
        "gen_time_unix_ms",
        "verification_time_unix_ms",
    ):
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            return "invalid_timestamp_chronology"
    registered_at_ms = payload["registered_at_ms"]
    gen_time_ms = payload["gen_time_unix_ms"]
    verification_time_ms = payload["verification_time_unix_ms"]
    exact_time_micros = gen_time_ms * 1_000 + submillisecond_micros
    if exact_time_micros < accuracy_micros:
        return "invalid_timestamp_chronology"
    expected_earliest_trusted_time_ms = (
        exact_time_micros - accuracy_micros
    ) // 1_000
    expected_latest_trusted_time_ms = (
        exact_time_micros + accuracy_micros + 999
    ) // 1_000
    if (
        gen_time_ms + 5 * 60 * 1000 < registered_at_ms
        or gen_time_ms > verification_time_ms + 5 * 60 * 1000
        or earliest_trusted_time_ms != expected_earliest_trusted_time_ms
        or latest_trusted_time_ms != expected_latest_trusted_time_ms
    ):
        return "invalid_timestamp_chronology"
    if temporal_independent_review_payload is None:
        return "missing_review_binding"
    if temporal_study_attestation_verification_payload is None:
        return "missing_attestation_binding"
    attestation_bindings = (
        "study_id",
        "registered_at_ms",
        "corpus_class",
        "commitment_file_sha256",
        "commitment_canonical_sha256",
        "preregistration_canonical_sha256",
        "corpus_sha256",
        "packet_canonical_sha256",
    )
    if any(
        payload.get(field)
        != temporal_study_attestation_verification_payload.get(field)
        for field in attestation_bindings
    ):
        return "attestation_binding_mismatch"
    review_bindings = (
        ("study_id", "study_id"),
        ("corpus_class", "study_corpus_class"),
        ("commitment_canonical_sha256", "study_commitment_canonical_sha256"),
        ("preregistration_canonical_sha256", "preregistration_canonical_sha256"),
        ("corpus_sha256", "corpus_sha256"),
        ("packet_canonical_sha256", "blind_packet_canonical_sha256"),
    )
    if any(
        payload.get(timestamp_field)
        != temporal_independent_review_payload.get(review_field)
        for timestamp_field, review_field in review_bindings
    ):
        return "review_binding_mismatch"
    chronology = temporal_independent_review_payload.get("chronology")
    if not isinstance(chronology, dict):
        return "missing_review_chronology"
    if chronology.get("declared_preregistration_at_ms") != registered_at_ms:
        return "review_chronology_mismatch"
    earliest_annotation_ms = chronology.get("earliest_annotation_completed_at_ms")
    if (
        isinstance(earliest_annotation_ms, bool)
        or not isinstance(earliest_annotation_ms, int)
        or latest_trusted_time_ms >= earliest_annotation_ms
    ):
        return "timestamp_not_before_review"
    return "pass"


def temporal_review_receipt_chain_verification_status(
    payload: dict | None,
    temporal_independent_review_payload: dict | None,
    temporal_study_timestamp_verification_payload: dict | None,
) -> str | None:
    if payload is None:
        return None
    if (
        payload.get("schema_version")
        != TEMPORAL_REVIEW_RECEIPT_CHAIN_VERIFICATION_SCHEMA_VERSION
    ):
        return "invalid_schema"
    if payload.get("status") != "pass":
        return "fail"
    if (
        payload.get("chronology_assurance")
        != "individual_signed_rfc3161_receipts"
        or payload.get("roster_assurance") != "signed_rfc3161_precommitted"
        or payload.get("signature_algorithm") != "Ed25519"
        or payload.get("timestamp_protocol") != "RFC3161"
        or payload.get("message_imprint_algorithm") != "sha256"
        or payload.get("certificate_validation_time_basis") != "tsa_gen_time"
        or payload.get("revocation_assurance") != "full_chain_crl_at_gen_time"
        or payload.get("revocation_evidence_kind") != "offline_complete_crl"
        or payload.get("revocation_validation_time_basis") != "tsa_gen_time"
        or payload.get("revocation_scope") != "full_non_anchor_chain"
        or payload.get("revocation_network_fetch_used") is not False
        or payload.get("revocation_delta_crls_used") is not False
        or payload.get("revocation_indirect_crls_used") is not False
    ):
        return "invalid_receipt_assurance"
    for field in (
        "preregistration_canonical_sha256",
        "study_commitment_canonical_sha256",
        "packet_canonical_sha256",
        "review_bundle_file_sha256",
        "review_bundle_canonical_sha256",
        "receipt_index_sha256",
        "study_timestamp_response_sha256",
        "study_timestamp_revocation_crl_set_sha256",
        "revocation_crl_evidence_set_sha256",
        "receipt_signer_spki_set_sha256",
        "participant_signer_spki_set_sha256",
        "roster_canonical_sha256",
        "roster_attestation_sha256",
        "roster_timestamp_response_sha256",
        "roster_coordinator_public_key_spki_sha256",
        "governance_record_set_sha256",
    ):
        if not lowercase_sha256(payload.get(field)):
            return "invalid_receipt_identity"
    for field in (
        "reviewer_receipt_count",
        "distinct_reviewer_signer_count",
        "distinct_receipt_signer_count",
        "distinct_reviewer_affiliation_count",
        "distinct_participant_affiliation_count",
        "adjudicator_receipt_count",
        "reviewed_case_count",
        "reviewer_decision_count",
        "adjudication_decision_count",
        "receipt_timestamp_authority_count",
        "governance_record_count",
        "revocation_checked_timestamp_count",
        "revocation_unique_crl_count",
    ):
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            return "invalid_receipt_summary"
    reviewer_count = payload["reviewer_receipt_count"]
    participant_count = reviewer_count + payload["adjudicator_receipt_count"]
    case_count = payload["reviewed_case_count"]
    if (
        reviewer_count < 2
        or payload["adjudicator_receipt_count"] != 1
        or payload["distinct_reviewer_signer_count"] != reviewer_count
        or payload["distinct_receipt_signer_count"] != participant_count
        or payload["distinct_reviewer_affiliation_count"] != reviewer_count
        or payload["distinct_participant_affiliation_count"] != participant_count
        or not 1
        <= payload["receipt_timestamp_authority_count"]
        <= participant_count + 1
        or not 2 * case_count
        <= payload["reviewer_decision_count"]
        <= reviewer_count * case_count
        or payload["adjudication_decision_count"] != case_count
        or payload["governance_record_count"] != 4 * participant_count
        or payload["participant_signer_spki_set_sha256"]
        != payload["receipt_signer_spki_set_sha256"]
        or payload["revocation_checked_timestamp_count"] != participant_count + 2
        or payload["revocation_unique_crl_count"]
        > payload["revocation_checked_timestamp_count"] * 6
    ):
        return "invalid_receipt_summary"
    proof_fields = (
        "commitment_before_review_receipts",
        "commitment_before_roster",
        "roster_before_review_decisions",
        "roster_changes_after_timestamp_forbidden",
        "review_receipts_before_adjudication",
        "adjudicator_binds_exact_reviewer_receipts",
        "review_decisions_after_commitment",
        "review_decisions_before_receipts",
        "adjudication_after_review_receipts",
        "adjudication_before_receipt",
    )
    if any(payload.get(field) is not True for field in proof_fields):
        return "invalid_receipt_chronology"
    time_fields = (
        "commitment_latest_trusted_time_unix_ms",
        "roster_earliest_trusted_time_unix_ms",
        "roster_latest_trusted_time_unix_ms",
        "reviewer_earliest_trusted_time_unix_ms",
        "reviewer_latest_trusted_time_unix_ms",
        "adjudicator_earliest_trusted_time_unix_ms",
        "adjudicator_latest_trusted_time_unix_ms",
    )
    times = [payload.get(field) for field in time_fields]
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in times
    ):
        return "invalid_receipt_chronology"
    (
        commitment_upper,
        roster_lower,
        roster_upper,
        reviewer_lower,
        reviewer_upper,
        adjudicator_lower,
        adjudicator_upper,
    ) = times
    if not (
        commitment_upper
        < roster_lower
        <= roster_upper
        < reviewer_lower
        <= reviewer_upper
        < adjudicator_lower
        <= adjudicator_upper
    ):
        return "invalid_receipt_chronology"
    privacy = payload.get("privacy")
    if not isinstance(privacy, dict) or any(
        privacy.get(field) is not False
        for field in (
            "participant_tokens_exported",
            "affiliation_tokens_exported",
            "individual_participant_key_digests_exported",
            "governance_record_digests_exported",
            "case_tokens_exported",
            "decision_labels_exported",
            "raw_text_present",
        )
    ):
        return "privacy_fail"
    if temporal_independent_review_payload is None:
        return "missing_review_binding"
    if temporal_study_timestamp_verification_payload is None:
        return "missing_timestamp_binding"
    review_bindings = (
        ("study_id", "study_id"),
        ("preregistration_canonical_sha256", "preregistration_canonical_sha256"),
        ("study_commitment_canonical_sha256", "study_commitment_canonical_sha256"),
        ("packet_id", "blind_packet_id"),
        ("packet_canonical_sha256", "blind_packet_canonical_sha256"),
        ("review_bundle_canonical_sha256", "review_bundle_canonical_sha256"),
    )
    if any(
        payload.get(receipt_field) != temporal_independent_review_payload.get(review_field)
        for receipt_field, review_field in review_bindings
    ):
        return "review_binding_mismatch"
    metrics = temporal_independent_review_payload.get("metrics")
    if not isinstance(metrics, dict) or metrics.get("corpus_cases") != case_count:
        return "review_binding_mismatch"
    timestamp_bindings = (
        ("study_id", "study_id"),
        ("preregistration_canonical_sha256", "preregistration_canonical_sha256"),
        ("study_commitment_canonical_sha256", "commitment_canonical_sha256"),
        ("packet_canonical_sha256", "packet_canonical_sha256"),
        ("study_timestamp_response_sha256", "response_sha256"),
        (
            "commitment_latest_trusted_time_unix_ms",
            "latest_trusted_time_unix_ms",
        ),
        (
            "study_timestamp_revocation_crl_set_sha256",
            "revocation_crl_set_sha256",
        ),
    )
    if any(
        payload.get(receipt_field)
        != temporal_study_timestamp_verification_payload.get(timestamp_field)
        for receipt_field, timestamp_field in timestamp_bindings
    ):
        return "timestamp_binding_mismatch"
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
    temporal_study_timestamp_verification_payload: dict | None,
    temporal_review_receipt_chain_verification_payload: dict | None,
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
    timestamp_status = temporal_study_timestamp_verification_status(
        temporal_study_timestamp_verification_payload,
        temporal_independent_review_payload,
        temporal_study_attestation_verification_payload,
    )
    receipt_chain_status = temporal_review_receipt_chain_verification_status(
        temporal_review_receipt_chain_verification_payload,
        temporal_independent_review_payload,
        temporal_study_timestamp_verification_payload,
    )
    if (
        shadow_status is None
        and review_status is None
        and telemetry_status is None
        and attestation_status is None
        and timestamp_status is None
        and receipt_chain_status is None
    ):
        return None
    if shadow_status != "pass" or telemetry_status != "pass":
        return "fail"
    if attestation_status not in (None, "pass"):
        return "fail"
    if timestamp_status not in (None, "pass"):
        return "fail"
    if receipt_chain_status not in (None, "pass"):
        return "fail"
    if review_status == "pass":
        if (
            attestation_status == "pass"
            and timestamp_status == "pass"
            and receipt_chain_status == "pass"
        ):
            return "pass"
        if (
            attestation_status is None
            or timestamp_status is None
            or receipt_chain_status is None
        ):
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


def apple_reproducibility_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    if payload.get("schema_version") != "aura.apple_artifact_reproducibility.v1":
        return "invalid_schema"
    if (
        payload.get("status") != "pass"
        or payload.get("claim") != "same_environment_deterministic_rebuild"
        or payload.get("build_count") != 2
        or isinstance(payload.get("build_count"), bool)
        or payload.get("all_three_inventories_equal") is not True
        or payload.get("independent_reproduction_proven") is not False
        or payload.get("compiler_trust_proven") is not False
        or payload.get("candidate_blind_build_proven") is not False
        or payload.get("hermetic_build_proven") is not False
        or payload.get("trusted_source_and_build_scripts_assumed") is not True
    ):
        return "fail"
    return "pass"


def evidence_status(artifacts: dict, summary: dict) -> str:
    if any(
        meta["required"] and meta.get("status") != "loaded"
        for meta in artifacts.values()
    ):
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
    if summary["temporal_study_timestamp_verification_status"] not in (
        None,
        "pass",
    ):
        return "fail"
    if summary["temporal_review_receipt_chain_verification_status"] not in (
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
    if summary["apple_reproducibility_status"] not in (None, "pass"):
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
    temporal_study_timestamp_verification_payload: dict | None,
    temporal_review_receipt_chain_verification_payload: dict | None,
    temporal_shadow_telemetry_validation_payload: dict | None,
    pilot_gate_payload: dict | None,
    kids_preprod_dry_run_payload: dict | None,
    community_surface_payload: dict | None,
    world_lifecycle_payload: dict | None,
    world_performance_payload: dict | None,
    refactor_diff_payload: dict | None,
    apple_artifact_payload: dict | None,
    apple_reproducibility_payload: dict | None,
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
        artifacts["temporal_independent_review_report"][
            "review_bundle_canonical_sha256"
        ] = temporal_independent_review_payload.get(
            "review_bundle_canonical_sha256"
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
        review_chronology = temporal_independent_review_payload.get("chronology", {})
        artifacts["temporal_independent_review_report"]["chronology"] = {
            "decision_time_assurance": review_chronology.get(
                "decision_time_assurance"
            ),
            "declared_preregistration_at_ms": review_chronology.get(
                "declared_preregistration_at_ms"
            ),
            "earliest_annotation_completed_at_ms": review_chronology.get(
                "earliest_annotation_completed_at_ms"
            ),
            "latest_annotation_completed_at_ms": review_chronology.get(
                "latest_annotation_completed_at_ms"
            ),
            "earliest_adjudication_completed_at_ms": review_chronology.get(
                "earliest_adjudication_completed_at_ms"
            ),
            "latest_adjudication_completed_at_ms": review_chronology.get(
                "latest_adjudication_completed_at_ms"
            ),
        }
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
    if temporal_study_timestamp_verification_payload is not None:
        artifact = artifacts["temporal_study_timestamp_verification"]
        artifact["observed_status"] = temporal_study_timestamp_verification_status(
            temporal_study_timestamp_verification_payload,
            temporal_independent_review_payload,
            temporal_study_attestation_verification_payload,
        )
        for field in (
            "schema_version",
            "timestamp_protocol",
            "trusted_timestamp_assurance",
            "policy_oid",
            "serial_hex",
            "gen_time_unix_ms",
            "gen_time_submillisecond_micros",
            "accuracy_micros",
            "latest_trusted_time_unix_ms",
            "tsa_signer_spki_sha256",
            "trust_anchor_bundle_sha256",
            "revocation_assurance",
            "revocation_evidence_kind",
            "revocation_checked_certificate_count",
            "revocation_crl_count",
            "revocation_crl_set_sha256",
        ):
            artifact[field] = temporal_study_timestamp_verification_payload.get(field)
    if temporal_review_receipt_chain_verification_payload is not None:
        artifact = artifacts["temporal_review_receipt_chain_verification"]
        artifact["observed_status"] = (
            temporal_review_receipt_chain_verification_status(
                temporal_review_receipt_chain_verification_payload,
                temporal_independent_review_payload,
                temporal_study_timestamp_verification_payload,
            )
        )
        for field in (
            "schema_version",
            "chronology_assurance",
            "roster_assurance",
            "signature_algorithm",
            "timestamp_protocol",
            "review_bundle_canonical_sha256",
            "roster_canonical_sha256",
            "governance_record_count",
            "reviewer_receipt_count",
            "adjudicator_receipt_count",
            "reviewed_case_count",
            "commitment_latest_trusted_time_unix_ms",
            "roster_earliest_trusted_time_unix_ms",
            "roster_latest_trusted_time_unix_ms",
            "reviewer_earliest_trusted_time_unix_ms",
            "reviewer_latest_trusted_time_unix_ms",
            "adjudicator_earliest_trusted_time_unix_ms",
            "adjudicator_latest_trusted_time_unix_ms",
            "revocation_assurance",
            "revocation_evidence_kind",
            "revocation_checked_timestamp_count",
            "revocation_unique_crl_count",
            "revocation_crl_evidence_set_sha256",
        ):
            artifact[field] = temporal_review_receipt_chain_verification_payload.get(
                field
            )
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
    if apple_reproducibility_payload is not None:
        artifact = artifacts["apple_artifact_reproducibility"]
        artifact["observed_status"] = apple_reproducibility_status(
            apple_reproducibility_payload
        )
        for field in (
            "schema_version",
            "claim",
            "source_revision",
            "artifact_revision",
            "release_revision",
            "source_tree_sha256",
            "build_count",
            "all_three_inventories_equal",
            "independent_reproduction_proven",
            "compiler_trust_proven",
            "candidate_blind_build_proven",
            "hermetic_build_proven",
            "trusted_source_and_build_scripts_assumed",
        ):
            artifact[field] = apple_reproducibility_payload.get(field)
        inventory = apple_reproducibility_payload.get("artifact_inventory")
        artifact["inventory_count"] = len(inventory) if isinstance(inventory, list) else None


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
        temporal_study_timestamp_verification_payload,
        temporal_study_timestamp_verification_artifact,
    ) = (
        load_json_artifact(
            args.temporal_study_timestamp_verification,
            required=args.temporal_study_timestamp_verification is not None,
        )
        if args.temporal_study_timestamp_verification
        else (None, None)
    )
    (
        temporal_review_receipt_chain_verification_payload,
        temporal_review_receipt_chain_verification_artifact,
    ) = (
        load_json_artifact(
            args.temporal_review_receipt_chain_verification,
            required=args.temporal_review_receipt_chain_verification is not None,
        )
        if args.temporal_review_receipt_chain_verification
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
    apple_reproducibility_payload, apple_reproducibility_artifact = load_json_artifact(
        args.apple_artifact_reproducibility,
        required=args.apple_artifact_reproducibility is not None,
    ) if args.apple_artifact_reproducibility else (None, None)
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
    if temporal_study_timestamp_verification_artifact is not None:
        artifacts[
            "temporal_study_timestamp_verification"
        ] = temporal_study_timestamp_verification_artifact
    if temporal_review_receipt_chain_verification_artifact is not None:
        artifacts[
            "temporal_review_receipt_chain_verification"
        ] = temporal_review_receipt_chain_verification_artifact
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
    if apple_reproducibility_artifact is not None:
        artifacts["apple_artifact_reproducibility"] = apple_reproducibility_artifact
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
        temporal_study_timestamp_verification_payload=(
            temporal_study_timestamp_verification_payload
        ),
        temporal_review_receipt_chain_verification_payload=(
            temporal_review_receipt_chain_verification_payload
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
        apple_reproducibility_payload=apple_reproducibility_payload,
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
        "temporal_review_decision_time_assurance": (
            temporal_independent_review_payload.get("chronology", {}).get(
                "decision_time_assurance"
            )
            if temporal_independent_review_payload
            else None
        ),
        "temporal_review_earliest_annotation_completed_at_ms": (
            temporal_independent_review_payload.get("chronology", {}).get(
                "earliest_annotation_completed_at_ms"
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
        "temporal_study_timestamp_verification_status": (
            temporal_study_timestamp_verification_status(
                temporal_study_timestamp_verification_payload,
                temporal_independent_review_payload,
                temporal_study_attestation_verification_payload,
            )
        ),
        "temporal_study_timestamp_assurance": (
            temporal_study_timestamp_verification_payload.get(
                "trusted_timestamp_assurance"
            )
            if temporal_study_timestamp_verification_payload
            else None
        ),
        "temporal_study_timestamp_gen_time_unix_ms": (
            temporal_study_timestamp_verification_payload.get("gen_time_unix_ms")
            if temporal_study_timestamp_verification_payload
            else None
        ),
        "temporal_study_timestamp_latest_trusted_time_unix_ms": (
            temporal_study_timestamp_verification_payload.get(
                "latest_trusted_time_unix_ms"
            )
            if temporal_study_timestamp_verification_payload
            else None
        ),
        "temporal_study_timestamp_tsa_spki_sha256": (
            temporal_study_timestamp_verification_payload.get(
                "tsa_signer_spki_sha256"
            )
            if temporal_study_timestamp_verification_payload
            else None
        ),
        "temporal_study_timestamp_revocation_assurance": (
            temporal_study_timestamp_verification_payload.get(
                "revocation_assurance"
            )
            if temporal_study_timestamp_verification_payload
            else None
        ),
        "temporal_study_timestamp_revocation_crl_set_sha256": (
            temporal_study_timestamp_verification_payload.get(
                "revocation_crl_set_sha256"
            )
            if temporal_study_timestamp_verification_payload
            else None
        ),
        "temporal_review_receipt_chain_verification_status": (
            temporal_review_receipt_chain_verification_status(
                temporal_review_receipt_chain_verification_payload,
                temporal_independent_review_payload,
                temporal_study_timestamp_verification_payload,
            )
        ),
        "temporal_review_receipt_chronology_assurance": (
            temporal_review_receipt_chain_verification_payload.get(
                "chronology_assurance"
            )
            if temporal_review_receipt_chain_verification_payload
            else None
        ),
        "temporal_review_roster_assurance": (
            temporal_review_receipt_chain_verification_payload.get(
                "roster_assurance"
            )
            if temporal_review_receipt_chain_verification_payload
            else None
        ),
        "temporal_review_receipt_revocation_assurance": (
            temporal_review_receipt_chain_verification_payload.get(
                "revocation_assurance"
            )
            if temporal_review_receipt_chain_verification_payload
            else None
        ),
        "temporal_review_receipt_revocation_checked_timestamp_count": (
            temporal_review_receipt_chain_verification_payload.get(
                "revocation_checked_timestamp_count"
            )
            if temporal_review_receipt_chain_verification_payload
            else None
        ),
        "temporal_review_roster_latest_trusted_time_unix_ms": (
            temporal_review_receipt_chain_verification_payload.get(
                "roster_latest_trusted_time_unix_ms"
            )
            if temporal_review_receipt_chain_verification_payload
            else None
        ),
        "temporal_review_receipt_reviewer_count": (
            temporal_review_receipt_chain_verification_payload.get(
                "reviewer_receipt_count"
            )
            if temporal_review_receipt_chain_verification_payload
            else None
        ),
        "temporal_review_receipt_reviewer_earliest_trusted_time_unix_ms": (
            temporal_review_receipt_chain_verification_payload.get(
                "reviewer_earliest_trusted_time_unix_ms"
            )
            if temporal_review_receipt_chain_verification_payload
            else None
        ),
        "temporal_review_receipt_adjudicator_latest_trusted_time_unix_ms": (
            temporal_review_receipt_chain_verification_payload.get(
                "adjudicator_latest_trusted_time_unix_ms"
            )
            if temporal_review_receipt_chain_verification_payload
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
            temporal_study_timestamp_verification_payload,
            temporal_review_receipt_chain_verification_payload,
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
        "apple_reproducibility_status": apple_reproducibility_status(
            apple_reproducibility_payload
        ),
        "apple_reproducibility_schema_version": (
            apple_reproducibility_payload.get("schema_version")
            if apple_reproducibility_payload
            else None
        ),
        "apple_reproducibility_source_revision": (
            apple_reproducibility_payload.get("source_revision")
            if apple_reproducibility_payload
            else None
        ),
        "apple_reproducibility_artifact_revision": (
            apple_reproducibility_payload.get("artifact_revision")
            if apple_reproducibility_payload
            else None
        ),
        "apple_reproducibility_release_revision": (
            apple_reproducibility_payload.get("release_revision")
            if apple_reproducibility_payload
            else None
        ),
        "apple_reproducibility_source_tree_sha256": (
            apple_reproducibility_payload.get("source_tree_sha256")
            if apple_reproducibility_payload
            else None
        ),
        "apple_reproducibility_build_count": (
            apple_reproducibility_payload.get("build_count")
            if apple_reproducibility_payload
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
