import json
import sys
import tempfile
import unittest
from hashlib import sha256
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
        "schema_version": "aura.military.temporal_review_report.v5",
        "overall_status": "pass",
        "blinding_assurance": "packet_bound",
        "blind_packet_id": "blind_round_alpha",
        "blind_packet_canonical_sha256": "a" * 64,
        "preregistration_assurance": "packet_bound",
        "study_id": "external_temporal_study_2026",
        "study_corpus_class": "embargoed_external",
        "preregistration_canonical_sha256": "b" * 64,
        "study_commitment_canonical_sha256": "c" * 64,
        "review_bundle_canonical_sha256": "f" * 64,
        "corpus_sha256": "d" * 64,
        "chronology": {
            "decision_time_assurance": "bundle_declared",
            "declared_preregistration_at_ms": 1780000000000,
            "earliest_annotation_completed_at_ms": 1780000060000,
            "latest_annotation_completed_at_ms": 1780000120000,
            "earliest_adjudication_completed_at_ms": 1780000180000,
            "latest_adjudication_completed_at_ms": 1780000240000,
        },
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
            "reviewer_pair_comparisons": 37,
            "exact_set_pair_agreement_rate": 0.9,
            "krippendorff_alpha_nominal": 0.85,
        },
    }
    payload.update(overrides)
    return payload


def temporal_study_attestation_verification_payload(**overrides):
    payload = {
        "schema_version": "aura.military.temporal_study_attestation_verification.v1",
        "status": "pass",
        "signature_algorithm": "Ed25519",
        "key_id": "study-review-key-2026",
        "study_id": "external_temporal_study_2026",
        "registered_at_ms": 1780000000000,
        "corpus_class": "embargoed_external",
        "commitment_file_sha256": "e" * 64,
        "commitment_canonical_sha256": "c" * 64,
        "preregistration_canonical_sha256": "b" * 64,
        "corpus_sha256": "d" * 64,
        "packet_canonical_sha256": "a" * 64,
        "public_key_spki_sha256": "f" * 64,
        "trusted_timestamp_assurance": "absent",
    }
    payload.update(overrides)
    return payload


def temporal_study_timestamp_verification_payload(**overrides):
    crl_digest = "7" * 64
    payload = {
        "schema_version": "aura.military.temporal_study_timestamp_verification.v2",
        "status": "pass",
        "timestamp_protocol": "RFC3161",
        "trusted_timestamp_assurance": "rfc3161_trusted_chain",
        "message_imprint_algorithm": "sha256",
        "policy_oid": "1.2.3.4.1",
        "serial_hex": "0x01",
        "gen_time_unix_ms": 1780000001000,
        "accuracy_micros": 1000000,
        "earliest_trusted_time_unix_ms": 1780000000000,
        "latest_trusted_time_unix_ms": 1780000002000,
        "ordering": True,
        "request_nonce_present": True,
        "study_id": "external_temporal_study_2026",
        "registered_at_ms": 1780000000000,
        "corpus_class": "embargoed_external",
        "commitment_file_sha256": "e" * 64,
        "commitment_canonical_sha256": "c" * 64,
        "preregistration_canonical_sha256": "b" * 64,
        "corpus_sha256": "d" * 64,
        "packet_canonical_sha256": "a" * 64,
        "request_sha256": "1" * 64,
        "response_sha256": "2" * 64,
        "tsa_signer_certificate_sha256": "3" * 64,
        "tsa_signer_spki_sha256": "4" * 64,
        "trust_anchor_bundle_sha256": "5" * 64,
        "untrusted_chain_sha256": "6" * 64,
        "certificate_validation_time_basis": "tsa_gen_time",
        "revocation_assurance": "full_chain_crl_at_gen_time",
        "revocation_evidence_kind": "offline_complete_crl",
        "revocation_validation_time_basis": "tsa_gen_time",
        "revocation_scope": "full_non_anchor_chain",
        "revocation_network_fetch_used": False,
        "revocation_delta_crls_used": False,
        "revocation_indirect_crls_used": False,
        "revocation_checked_certificate_count": 1,
        "revocation_crl_count": 1,
        "revocation_crl_der_sha256s": [crl_digest],
        "revocation_crl_set_sha256": sha256(crl_digest.encode("ascii")).hexdigest(),
        "revocation_crls": [
            {
                "issuer_name_sha256": "9" * 64,
                "this_update_unix_ms": 1780000000000,
                "next_update_unix_ms": 1780003600000,
                "crl_number_hex": "0x1000",
                "der_sha256": crl_digest,
            }
        ],
        "verification_time_unix_ms": 1780000002000,
        "verification_tool": "OpenSSL test",
    }
    payload.update(overrides)
    return payload


def temporal_review_receipt_chain_verification_payload(**overrides):
    crl_digest = "7" * 64
    crl_set_digest = sha256(crl_digest.encode("ascii")).hexdigest()
    payload = {
        "schema_version": "aura.military.temporal_review_receipt_chain_verification.v3",
        "status": "pass",
        "chronology_assurance": "individual_signed_rfc3161_receipts",
        "roster_assurance": "signed_rfc3161_precommitted",
        "signature_algorithm": "Ed25519",
        "timestamp_protocol": "RFC3161",
        "message_imprint_algorithm": "sha256",
        "certificate_validation_time_basis": "tsa_gen_time",
        "revocation_assurance": "full_chain_crl_at_gen_time",
        "revocation_evidence_kind": "offline_complete_crl",
        "revocation_validation_time_basis": "tsa_gen_time",
        "revocation_scope": "full_non_anchor_chain",
        "revocation_network_fetch_used": False,
        "revocation_delta_crls_used": False,
        "revocation_indirect_crls_used": False,
        "revocation_checked_timestamp_count": 5,
        "revocation_unique_crl_count": 1,
        "revocation_crl_evidence_set_sha256": crl_set_digest,
        "study_id": "external_temporal_study_2026",
        "preregistration_canonical_sha256": "b" * 64,
        "study_commitment_canonical_sha256": "c" * 64,
        "packet_id": "blind_round_alpha",
        "packet_canonical_sha256": "a" * 64,
        "review_bundle_file_sha256": "e" * 64,
        "review_bundle_canonical_sha256": "f" * 64,
        "receipt_index_sha256": "7" * 64,
        "study_timestamp_response_sha256": "2" * 64,
        "study_timestamp_revocation_crl_set_sha256": crl_set_digest,
        "reviewer_receipt_count": 2,
        "distinct_reviewer_signer_count": 2,
        "distinct_receipt_signer_count": 3,
        "distinct_reviewer_affiliation_count": 2,
        "distinct_participant_affiliation_count": 3,
        "adjudicator_receipt_count": 1,
        "reviewed_case_count": 37,
        "reviewer_decision_count": 74,
        "adjudication_decision_count": 37,
        "receipt_signer_spki_set_sha256": "8" * 64,
        "participant_signer_spki_set_sha256": "8" * 64,
        "roster_canonical_sha256": "9" * 64,
        "roster_attestation_sha256": "a" * 64,
        "roster_timestamp_response_sha256": "b" * 64,
        "roster_coordinator_public_key_spki_sha256": "c" * 64,
        "governance_record_count": 12,
        "governance_record_set_sha256": "d" * 64,
        "receipt_timestamp_authority_count": 1,
        "commitment_latest_trusted_time_unix_ms": 1780000002000,
        "roster_earliest_trusted_time_unix_ms": 1780000030000,
        "roster_latest_trusted_time_unix_ms": 1780000040000,
        "reviewer_earliest_trusted_time_unix_ms": 1780000130000,
        "reviewer_latest_trusted_time_unix_ms": 1780000170000,
        "adjudicator_earliest_trusted_time_unix_ms": 1780000250000,
        "adjudicator_latest_trusted_time_unix_ms": 1780000260000,
        "commitment_before_review_receipts": True,
        "commitment_before_roster": True,
        "roster_before_review_decisions": True,
        "roster_changes_after_timestamp_forbidden": True,
        "review_receipts_before_adjudication": True,
        "adjudicator_binds_exact_reviewer_receipts": True,
        "review_decisions_after_commitment": True,
        "review_decisions_before_receipts": True,
        "adjudication_after_review_receipts": True,
        "adjudication_before_receipt": True,
        "privacy": {
            "participant_tokens_exported": False,
            "affiliation_tokens_exported": False,
            "individual_participant_key_digests_exported": False,
            "governance_record_digests_exported": False,
            "case_tokens_exported": False,
            "decision_labels_exported": False,
            "raw_text_present": False,
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

    def test_temporal_review_rejects_public_seed_as_activation_evidence(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_independent_review_status(
                temporal_review_payload(study_corpus_class="public_seed")
            ),
            "insufficient_external_validity",
        )

    def test_temporal_review_rejects_missing_preregistration_binding(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_independent_review_status(
                temporal_review_payload(preregistration_assurance="absent")
            ),
            "insufficient_preregistration",
        )

    def test_temporal_review_rejects_undefined_agreement(self):
        payload = temporal_review_payload()
        payload["metrics"]["krippendorff_alpha_nominal"] = None

        self.assertEqual(
            generate_evidence_manifest.temporal_independent_review_status(payload),
            "invalid_agreement_summary",
        )

    def test_temporal_review_rejects_missing_study_commitment(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_independent_review_status(
                temporal_review_payload(study_commitment_canonical_sha256=None)
            ),
            "invalid_study_commitment",
        )

    def test_temporal_review_rejects_insufficient_interreviewer_agreement(self):
        payload = temporal_review_payload()
        payload["metrics"]["krippendorff_alpha_nominal"] = 0.79

        self.assertEqual(
            generate_evidence_manifest.temporal_independent_review_status(payload),
            "insufficient_interreviewer_agreement",
        )

    def test_temporal_review_rejects_adjudication_before_all_reviews_freeze(self):
        payload = temporal_review_payload()
        payload["chronology"]["earliest_adjudication_completed_at_ms"] = (
            payload["chronology"]["latest_annotation_completed_at_ms"]
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_independent_review_status(payload),
            "invalid_review_chronology",
        )

    def test_temporal_activation_stays_pending_without_independent_review(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_policy_activation_readiness(
                temporal_shadow_payload(),
                None,
                temporal_telemetry_validation_payload(),
                None,
                None,
                None,
            ),
            "pending",
        )

    def test_temporal_activation_remains_pending_without_study_attestation(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_policy_activation_readiness(
                temporal_shadow_payload(),
                temporal_review_payload(),
                temporal_telemetry_validation_payload(),
                None,
                None,
                None,
            ),
            "pending",
        )

    def test_temporal_activation_remains_pending_without_trusted_timestamp(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_policy_activation_readiness(
                temporal_shadow_payload(),
                temporal_review_payload(),
                temporal_telemetry_validation_payload(),
                temporal_study_attestation_verification_payload(),
                None,
                None,
            ),
            "pending",
        )

    def test_temporal_activation_remains_pending_without_review_receipts(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_policy_activation_readiness(
                temporal_shadow_payload(),
                temporal_review_payload(),
                temporal_telemetry_validation_payload(),
                temporal_study_attestation_verification_payload(),
                temporal_study_timestamp_verification_payload(),
                None,
            ),
            "pending",
        )

    def test_temporal_activation_passes_with_verified_receipt_chain(self):
        self.assertEqual(
            generate_evidence_manifest.temporal_policy_activation_readiness(
                temporal_shadow_payload(),
                temporal_review_payload(),
                temporal_telemetry_validation_payload(),
                temporal_study_attestation_verification_payload(),
                temporal_study_timestamp_verification_payload(),
                temporal_review_receipt_chain_verification_payload(),
            ),
            "pass",
        )

    def test_temporal_timestamp_must_precede_first_declared_review(self):
        payload = temporal_study_timestamp_verification_payload(
            gen_time_unix_ms=1780000059000,
            earliest_trusted_time_unix_ms=1780000058000,
            latest_trusted_time_unix_ms=1780000060000,
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_study_timestamp_verification_status(
                payload,
                temporal_review_payload(),
                temporal_study_attestation_verification_payload(),
            ),
            "timestamp_not_before_review",
        )

    def test_temporal_receipt_chain_rejects_review_bundle_substitution(self):
        payload = temporal_review_receipt_chain_verification_payload(
            review_bundle_canonical_sha256="0" * 64
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_review_receipt_chain_verification_status(
                payload,
                temporal_review_payload(),
                temporal_study_timestamp_verification_payload(),
            ),
            "review_binding_mismatch",
        )

    def test_temporal_receipt_chain_rejects_overlapping_intervals(self):
        payload = temporal_review_receipt_chain_verification_payload(
            adjudicator_earliest_trusted_time_unix_ms=1780000170000
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_review_receipt_chain_verification_status(
                payload,
                temporal_review_payload(),
                temporal_study_timestamp_verification_payload(),
            ),
            "invalid_receipt_chronology",
        )

    def test_temporal_receipt_chain_rejects_roster_review_overlap(self):
        payload = temporal_review_receipt_chain_verification_payload(
            roster_latest_trusted_time_unix_ms=1780000130000
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_review_receipt_chain_verification_status(
                payload,
                temporal_review_payload(),
                temporal_study_timestamp_verification_payload(),
            ),
            "invalid_receipt_chronology",
        )

    def test_temporal_receipt_chain_requires_precommitted_roster(self):
        payload = temporal_review_receipt_chain_verification_payload(
            roster_assurance="absent"
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_review_receipt_chain_verification_status(
                payload,
                temporal_review_payload(),
                temporal_study_timestamp_verification_payload(),
            ),
            "invalid_receipt_assurance",
        )

    def test_temporal_receipt_chain_requires_every_timestamp_revocation_check(self):
        payload = temporal_review_receipt_chain_verification_payload(
            revocation_checked_timestamp_count=4
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_review_receipt_chain_verification_status(
                payload,
                temporal_review_payload(),
                temporal_study_timestamp_verification_payload(),
            ),
            "invalid_receipt_summary",
        )

    def test_temporal_receipt_chain_binds_study_crl_set(self):
        payload = temporal_review_receipt_chain_verification_payload(
            study_timestamp_revocation_crl_set_sha256="0" * 64
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_review_receipt_chain_verification_status(
                payload,
                temporal_review_payload(),
                temporal_study_timestamp_verification_payload(),
            ),
            "timestamp_binding_mismatch",
        )

    def test_temporal_receipt_chain_rejects_identifier_export(self):
        payload = temporal_review_receipt_chain_verification_payload()
        payload["privacy"]["participant_tokens_exported"] = True

        self.assertEqual(
            generate_evidence_manifest.temporal_review_receipt_chain_verification_status(
                payload,
                temporal_review_payload(),
                temporal_study_timestamp_verification_payload(),
            ),
            "privacy_fail",
        )

    def test_temporal_timestamp_requires_bounded_declared_accuracy(self):
        payload = temporal_study_timestamp_verification_payload(
            accuracy_micros=None,
            latest_trusted_time_unix_ms=1780000001000,
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_study_timestamp_verification_status(
                payload,
                temporal_review_payload(),
                temporal_study_attestation_verification_payload(),
            ),
            "invalid_timestamp_identity",
        )

    def test_temporal_timestamp_rejects_unverified_revocation_claim(self):
        payload = temporal_study_timestamp_verification_payload(
            revocation_assurance="checked"
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_study_timestamp_verification_status(
                payload,
                temporal_review_payload(),
                temporal_study_attestation_verification_payload(),
            ),
            "invalid_timestamp_assurance",
        )

    def test_temporal_timestamp_rejects_inconsistent_crl_set(self):
        payload = temporal_study_timestamp_verification_payload(
            revocation_crl_set_sha256="0" * 64
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_study_timestamp_verification_status(
                payload,
                temporal_review_payload(),
                temporal_study_attestation_verification_payload(),
            ),
            "invalid_timestamp_revocation_evidence",
        )

    def test_temporal_timestamp_rejects_attestation_binding_mismatch(self):
        payload = temporal_study_timestamp_verification_payload(
            commitment_file_sha256="0" * 64
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_study_timestamp_verification_status(
                payload,
                temporal_review_payload(),
                temporal_study_attestation_verification_payload(),
            ),
            "attestation_binding_mismatch",
        )

    def test_temporal_attestation_rejects_review_binding_mismatch(self):
        payload = temporal_study_attestation_verification_payload(
            commitment_canonical_sha256="0" * 64
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_study_attestation_verification_status(
                payload,
                temporal_review_payload(),
            ),
            "review_binding_mismatch",
        )

    def test_temporal_attestation_rejects_unearned_timestamp_claim(self):
        payload = temporal_study_attestation_verification_payload(
            trusted_timestamp_assurance="rfc3161"
        )

        self.assertEqual(
            generate_evidence_manifest.temporal_study_attestation_verification_status(
                payload,
                temporal_review_payload(),
            ),
            "unsupported_timestamp_claim",
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
                "temporal_review": root / "temporal-review.json",
                "temporal_attestation": root / "temporal-attestation-verification.json",
                "temporal_timestamp": root / "temporal-timestamp-verification.json",
                "temporal_receipts": root / "temporal-review-receipts-verification.json",
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
            write_json(paths["temporal_review"], temporal_review_payload())
            write_json(
                paths["temporal_attestation"],
                temporal_study_attestation_verification_payload(),
            )
            write_json(
                paths["temporal_timestamp"],
                temporal_study_timestamp_verification_payload(),
            )
            write_json(
                paths["temporal_receipts"],
                temporal_review_receipt_chain_verification_payload(),
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
                "--temporal-independent-review-report",
                paths["temporal_review"].as_posix(),
                "--temporal-study-attestation-verification",
                paths["temporal_attestation"].as_posix(),
                "--temporal-study-timestamp-verification",
                paths["temporal_timestamp"].as_posix(),
                "--temporal-review-receipt-chain-verification",
                paths["temporal_receipts"].as_posix(),
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
                manifest["summary"][
                    "temporal_study_timestamp_verification_status"
                ],
                "pass",
            )
            self.assertEqual(
                manifest["summary"][
                    "temporal_review_receipt_chain_verification_status"
                ],
                "pass",
            )
            self.assertEqual(
                manifest["summary"]["temporal_policy_activation_readiness"],
                "pass",
            )
            self.assertEqual(
                manifest["summary"][
                    "temporal_study_attestation_verification_status"
                ],
                "pass",
            )
            self.assertEqual(
                manifest["artifacts"]["temporal_study_attestation_verification"][
                    "key_id"
                ],
                "study-review-key-2026",
            )
            self.assertEqual(
                manifest["artifacts"]["world_lifecycle_report"]["observed_status"],
                "pass",
            )


def write_json(path: Path, payload: dict):
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
