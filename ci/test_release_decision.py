import json
import os
import shutil
import subprocess
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from ci import release_decision


class ReleaseDecisionFixture(unittest.TestCase):
    revision = "a" * 40
    source_tree_sha256 = "b" * 64
    runtime_version = "0.2.0"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.evidence_manifest = self.root / "evidence-manifest.json"
        self.evidence_verification = self.root / "evidence-verification.json"
        self.apple_verification = self.root / "apple-verification.json"
        self.apple_manifest = self.root / "apple-release-manifest.json"
        self.pilot_gate = self.root / "pilot-gate.json"
        self.product_acceptance = self.root / "product-acceptance.json"
        self.write_all_valid_inputs()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def digest(path: Path) -> str:
        return sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def write(path: Path, payload: dict) -> None:
        release_decision.crypto_support.write_json_atomic(path, payload)

    def evidence_payload(self, **summary_overrides) -> dict:
        summary = {
            "runtime_release_version": self.runtime_version,
            "wire_package": "aura.messenger.v1",
            "wire_major_version": 1,
            "state_schema_version": 3,
            "release_report_status": "pass",
            "pilot_regression_status": "pass",
            "world_lifecycle_status": "pass",
            "world_performance_status": "pass",
            "refactor_diff_status": "pass",
            "ffi_smoke_status": "pass",
            "ffi_soak_status": "pass",
            "dataset_evidence_status": "pass",
            "audit_evidence_status": "pass",
            "audit_forbidden_fields_absent": True,
        }
        summary.update(summary_overrides)
        return {
            "schema_version": "aura.evidence_manifest.v1",
            "evidence_status": "pass",
            "summary": summary,
            "artifacts": {},
        }

    def apple_manifest_payload(self, **overrides) -> dict:
        payload = {
            "schema_version": 5,
            "source_revision": self.revision,
            "source_tree_dirty": False,
            "source_tree_sha256": self.source_tree_sha256,
            "shippable": True,
            "cargo_profile": "release",
            "cargo_locked": True,
            "cargo_features": [],
            "runtime_release_version": self.runtime_version,
            "runtime_artifact_descriptor_sha256": "c" * 64,
            "runtime_capabilities_sha256": "d" * 64,
            "model_bundle_included": False,
            "binary_sha256": {
                "ios-arm64": "1" * 64,
                "ios-arm64_x86_64-simulator": "2" * 64,
                "ios-arm64_x86_64-maccatalyst": "3" * 64,
            },
            "ffi_contract_version": 1,
            "state_schema_version": 3,
            "wire_package": "aura.messenger.v1",
            "wire_major_version": 1,
            "target_triples": release_decision.EXPECTED_APPLE_TARGET_TRIPLES,
        }
        payload.update(overrides)
        return payload

    def apple_verification_payload(self, **overrides) -> dict:
        payload = {
            "schema_version": "aura.apple_artifact_verification.v1",
            "status": "pass",
            "shippable": True,
            "source_tree_dirty": False,
            "source_revision": self.revision,
            "source_tree_sha256": self.source_tree_sha256,
            "runtime_release_version": self.runtime_version,
            "ffi_contract_version": 1,
            "state_schema_version": 3,
            "wire_package": "aura.messenger.v1",
            "cargo_features": [],
            "slices": [
                {
                    "slice_id": "ios-arm64",
                    "architectures": ["arm64"],
                    "binary_sha256": "1" * 64,
                },
                {
                    "slice_id": "ios-arm64_x86_64-simulator",
                    "architectures": ["arm64", "x86_64"],
                    "binary_sha256": "2" * 64,
                },
                {
                    "slice_id": "ios-arm64_x86_64-maccatalyst",
                    "architectures": ["arm64", "x86_64"],
                    "binary_sha256": "3" * 64,
                },
            ],
        }
        payload.update(overrides)
        return payload

    def pilot_payload(self, **overrides) -> dict:
        checks = [
            {"check_id": check_id, "status": "pass", "summary": "pass"}
            for check_id in sorted(release_decision.REQUIRED_PILOT_CHECKS)
        ]
        payload = {
            "schema_version": "aura.pilot_gate_report.v1",
            "overall_status": "pass",
            "checks": checks,
            "rollback_triggers": [
                {
                    "trigger_id": f"trigger-{index}",
                    "severity": "high",
                    "condition": "defined stop condition",
                    "operator_action": "pause rollout",
                }
                for index in range(4)
            ],
            "operator_review_cadence": "daily for the first seven days",
        }
        payload.update(overrides)
        return payload

    def product_payload(self, **overrides) -> dict:
        payload = {
            "schema_version": release_decision.PRODUCT_ACCEPTANCE_SCHEMA_VERSION,
            "status": "pass",
            "profile": release_decision.PROFILE,
            "candidate_revision": self.revision,
            "source_tree_sha256": self.source_tree_sha256,
            "evidence_manifest_sha256": self.digest(self.evidence_manifest),
            "evidence_attestation_verification_sha256": self.digest(
                self.evidence_verification
            ),
            "apple_artifact_verification_sha256": self.digest(
                self.apple_verification
            ),
            "apple_release_manifest_sha256": self.digest(self.apple_manifest),
            "pilot_gate_report_sha256": self.digest(self.pilot_gate),
            "runtime_artifact_descriptor_sha256": "c" * 64,
            "runtime_capabilities_sha256": "d" * 64,
            "local_decision_contract": "pass",
            "terminal_checkpoint_contract": "pass",
            "restart_replay_contract": "pass",
            "exact_artifact_pin": True,
            "model_enabled": False,
            "relay_enabled": False,
            "military_enabled": False,
        }
        payload.update(overrides)
        return payload

    def write_all_valid_inputs(self):
        self.write(self.evidence_manifest, self.evidence_payload())
        self.write(
            self.evidence_verification,
            {
                "schema_version": (
                    "aura.evidence_manifest_attestation_verification.v1"
                ),
                "status": "pass",
                "signature_algorithm": "Ed25519",
                "key_id": "evidence-key",
                "manifest_sha256": self.digest(self.evidence_manifest),
                "manifest_evidence_status": "pass",
                "public_key_spki_sha256": "e" * 64,
            },
        )
        self.write(self.apple_verification, self.apple_verification_payload())
        self.write(self.apple_manifest, self.apple_manifest_payload())
        self.write(self.pilot_gate, self.pilot_payload())
        self.write(self.product_acceptance, self.product_payload())

    def input_paths(self) -> dict[str, str | None]:
        return {
            "evidence_manifest": self.evidence_manifest.as_posix(),
            "evidence_attestation_verification": (
                self.evidence_verification.as_posix()
            ),
            "apple_artifact_verification": self.apple_verification.as_posix(),
            "apple_release_manifest": self.apple_manifest.as_posix(),
            "pilot_gate_report": self.pilot_gate.as_posix(),
            "product_integration_acceptance": self.product_acceptance.as_posix(),
        }

    def create(self, paths: dict[str, str | None] | None = None) -> dict:
        return release_decision.create_decision(
            self.revision,
            self.runtime_version,
            release_decision.PROFILE,
            self.input_paths() if paths is None else paths,
        )


class ReleaseDecisionTests(ReleaseDecisionFixture):
    def test_complete_rules_only_candidate_is_go(self):
        decision = self.create()

        self.assertEqual(decision["decision"], "go")
        self.assertEqual(decision["blocking_reasons"], [])
        self.assertEqual(decision["artifact_integrity"], "pass")
        self.assertEqual(decision["runtime_safety"], "pass")
        self.assertEqual(decision["contract_compatibility"], "pass")
        self.assertEqual(decision["product_integration"], "pass")
        self.assertEqual(decision["privacy_security"], "pass")
        self.assertEqual(decision["operational_readiness"], "pass")
        self.assertEqual(decision["human_signoffs"], "pass")
        self.assertEqual(decision["model_readiness"], "not_in_scope")
        self.assertEqual(decision["relay_readiness"], "not_in_scope")
        self.assertEqual(
            decision["profile_scope"],
            {
                "model_enabled": False,
                "relay_enabled": False,
                "military_enabled": False,
            },
        )

    def test_missing_external_evidence_is_no_go_not_an_exception(self):
        paths = {key: None for key in self.input_paths()}
        decision = self.create(paths)

        self.assertEqual(decision["decision"], "no-go")
        self.assertIn("artifact_integrity", decision["blocking_reasons"])
        self.assertIn("product_integration", decision["blocking_reasons"])
        self.assertIn("human_signoffs", decision["blocking_reasons"])
        self.assertIsNone(decision["source_tree_sha256"])

    def test_evidence_manifest_failure_blocks_runtime_and_privacy(self):
        self.write(
            self.evidence_manifest,
            self.evidence_payload(audit_evidence_status="fail"),
        )
        decision = self.create()

        self.assertEqual(decision["decision"], "no-go")
        self.assertEqual(decision["privacy_security"], "fail")
        self.assertEqual(decision["product_integration"], "fail")

    def test_product_acceptance_must_bind_exact_candidate_and_all_children(self):
        self.write(
            self.product_acceptance,
            self.product_payload(candidate_revision="f" * 40),
        )
        decision = self.create()

        self.assertEqual(decision["product_integration"], "fail")
        self.assertEqual(decision["decision"], "no-go")

    def test_apple_slice_hash_must_match_release_manifest(self):
        verification = self.apple_verification_payload()
        verification["slices"][0]["binary_sha256"] = "f" * 64
        self.write(self.apple_verification, verification)
        self.write(self.product_acceptance, self.product_payload())

        decision = self.create()

        self.assertEqual(decision["artifact_integrity"], "fail")
        self.assertEqual(decision["decision"], "no-go")

    def test_model_relay_or_military_enablement_is_rejected_for_profile(self):
        self.write(
            self.product_acceptance,
            self.product_payload(model_enabled=True, relay_enabled=True),
        )
        decision = self.create()

        self.assertEqual(decision["product_integration"], "fail")
        self.assertNotEqual(decision["model_readiness"], "not_in_scope")
        self.assertNotEqual(decision["relay_readiness"], "not_in_scope")
        self.assertEqual(decision["decision"], "no-go")

    def test_missing_pilot_signoff_cannot_be_hidden_by_overall_pass(self):
        pilot = self.pilot_payload()
        pilot["checks"] = [
            check
            for check in pilot["checks"]
            if check["check_id"]
            != "review_signoff.self_harm_boundary_cases"
        ]
        self.write(self.pilot_gate, pilot)
        self.write(self.product_acceptance, self.product_payload())
        decision = self.create()

        self.assertEqual(decision["human_signoffs"], "fail")
        self.assertEqual(decision["decision"], "no-go")

    def test_artifact_metadata_exports_hashes_but_not_local_paths(self):
        decision = self.create()

        encoded = json.dumps(decision, sort_keys=True)
        self.assertNotIn(self.root.as_posix(), encoded)
        for metadata in decision["artifacts"].values():
            self.assertRegex(metadata["sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("path", metadata)

    @unittest.skipIf(os.name == "nt", "symbolic-link semantics differ on Windows")
    def test_symbolic_link_input_is_not_followed(self):
        link = self.root / "product-link.json"
        link.symlink_to(self.product_acceptance)
        paths = self.input_paths()
        paths["product_integration_acceptance"] = link.as_posix()

        decision = self.create(paths)

        self.assertEqual(decision["product_integration"], "blocked")
        self.assertEqual(
            decision["artifacts"]["product_integration_acceptance"][
                "observed_status"
            ],
            "inaccessible",
        )

    def test_validator_rejects_handcrafted_go_with_blocked_category(self):
        decision = self.create()
        decision["runtime_safety"] = "blocked"

        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "inconsistent"
        ):
            release_decision.validate_decision(decision)

    def test_invalid_candidate_revision_is_rejected(self):
        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "40 lowercase hex"
        ):
            release_decision.create_decision(
                "main",
                self.runtime_version,
                release_decision.PROFILE,
                self.input_paths(),
            )


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class ReleaseDecisionAttestationTests(ReleaseDecisionFixture):
    def setUp(self):
        super().setUp()
        self.decision_path = self.root / "release-decision.json"
        self.attestation_path = self.root / "release-decision.attestation.json"
        self.private_key = self.root / "private.pem"
        self.public_key = self.root / "public.pem"
        self.write(self.decision_path, self.create())
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "Ed25519",
                "-out",
                self.private_key.as_posix(),
            ],
            check=True,
            capture_output=True,
        )
        os.chmod(self.private_key, 0o600)
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                self.private_key.as_posix(),
                "-pubout",
                "-out",
                self.public_key.as_posix(),
            ],
            check=True,
            capture_output=True,
        )

    def sign(self):
        attestation = release_decision.sign_decision(
            self.decision_path,
            self.private_key,
            "release-operator-2026",
            self.input_paths(),
        )
        self.write(self.attestation_path, attestation)
        return attestation

    def test_signed_go_decision_verifies(self):
        self.sign()

        report = release_decision.verify_decision(
            self.decision_path,
            self.attestation_path,
            self.public_key,
            "release-operator-2026",
        )

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["decision"], "go")
        self.assertEqual(report["source_revision"], self.revision)

    def test_decision_tampering_is_rejected(self):
        self.sign()
        decision = json.loads(self.decision_path.read_text(encoding="utf-8"))
        decision["generated_at_utc"] = "2099-01-01T00:00:00+00:00"
        self.write(self.decision_path, decision)

        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "does not bind"
        ):
            release_decision.verify_decision(
                self.decision_path, self.attestation_path, self.public_key
            )

    def test_no_go_decision_cannot_be_signed(self):
        paths = {key: None for key in self.input_paths()}
        self.write(self.decision_path, self.create(paths))

        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "only a GO"
        ):
            release_decision.sign_decision(
                self.decision_path,
                self.private_key,
                "release-operator-2026",
                self.input_paths(),
            )

    def test_go_cannot_be_signed_after_source_evidence_changes(self):
        self.write(
            self.evidence_manifest,
            self.evidence_payload(world_performance_status="fail"),
        )

        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "does not match"
        ):
            release_decision.sign_decision(
                self.decision_path,
                self.private_key,
                "release-operator-2026",
                self.input_paths(),
            )

    def test_untrusted_operator_key_id_is_rejected(self):
        self.sign()

        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "not trusted"
        ):
            release_decision.verify_decision(
                self.decision_path,
                self.attestation_path,
                self.public_key,
                "different-release-operator",
            )


if __name__ == "__main__":
    unittest.main()
