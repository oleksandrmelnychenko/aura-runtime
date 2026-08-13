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
    source_revision = "a" * 40
    artifact_revision = "c" * 40
    release_revision = "f" * 40
    revision = release_revision
    source_tree_sha256 = "b" * 64
    runtime_version = "0.2.0"

    def setUp(self):
        if shutil.which("openssl") is None:
            self.skipTest("OpenSSL is required")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.evidence_manifest = self.root / "evidence-manifest.json"
        self.evidence_attestation = self.root / "evidence-attestation.json"
        self.evidence_private_key = self.root / "evidence-private.pem"
        self.evidence_public_key = self.root / "evidence-public.pem"
        self.expected_evidence_key_id = "evidence-key"
        self.evidence_verification = self.root / "evidence-verification.json"
        self.apple_verification = self.root / "apple-verification.json"
        self.apple_reproducibility = self.root / "apple-reproducibility.json"
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
            "artifacts": {
                "apple_artifact_verification": {
                    "sha256": self.digest(self.apple_verification)
                },
                "apple_artifact_reproducibility": {
                    "sha256": self.digest(self.apple_reproducibility)
                },
            },
        }

    def apple_manifest_payload(self, **overrides) -> dict:
        payload = {
            "schema_version": 5,
            "source_revision": self.source_revision,
            "source_tree_dirty": False,
            "source_tree_sha256": self.source_tree_sha256,
            "shippable": True,
            "cargo_profile": "release",
            "cargo_locked": True,
            "cargo_features": [],
            "runtime_release_version": self.runtime_version,
            "runtime_artifact_descriptor_sha256": "c" * 64,
            "runtime_capabilities_sha256": "d" * 64,
            "aura_ffi_header_sha256": "4" * 64,
            "execution_policy_trust_keyring_sha256": "5" * 64,
            "xcframework_info_plist_sha256": "6" * 64,
            "runtime_artifact_identities_env_sha256": "7" * 64,
            "model_bundle_included": False,
            "binary_sha256": {
                "ios-arm64": "1" * 64,
                "ios-arm64_x86_64-simulator": "2" * 64,
                "ios-arm64_x86_64-maccatalyst": "3" * 64,
            },
            "ffi_contract_version": 1,
            "minimum_ios_version": "18.0",
            "model_manifest_sha256": "8" * 64,
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
            "source_revision": self.source_revision,
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

    def apple_reproducibility_payload(self, **overrides) -> dict:
        hashes = {
            "AuraAgentFFI.xcframework/Info.plist": "6" * 64,
            "AuraAgentFFI.xcframework/ios-arm64/Headers/aura_ffi.h": "4" * 64,
            "AuraAgentFFI.xcframework/ios-arm64/libaura_agent_ffi.a": "1" * 64,
            "AuraAgentFFI.xcframework/ios-arm64_x86_64-maccatalyst/Headers/aura_ffi.h": "4" * 64,
            "AuraAgentFFI.xcframework/ios-arm64_x86_64-maccatalyst/libaura_agent_ffi_maccatalyst.a": "3" * 64,
            "AuraAgentFFI.xcframework/ios-arm64_x86_64-simulator/Headers/aura_ffi.h": "4" * 64,
            "AuraAgentFFI.xcframework/ios-arm64_x86_64-simulator/libaura_agent_ffi_ios_sim.a": "2" * 64,
            "execution-policy-trust-keyring.json": "5" * 64,
            "release-manifest.json": self.digest(self.apple_manifest),
            "runtime-artifact-descriptor.json": "c" * 64,
            "runtime-artifact-identities.env": "7" * 64,
        }
        inventory = [
            {
                "path": path,
                "size": index + 1,
                "sha256": hashes[path],
                "executable": False,
            }
            for index, path in enumerate(release_decision.EXPECTED_APPLE_ARTIFACT_PATHS)
        ]
        inventory_map = {item["path"]: item for item in inventory}
        lfs = {
            f"dist/apple/{path}": {
                "size": inventory_map[path]["size"],
                "sha256": inventory_map[path]["sha256"],
            }
            for path in release_decision.EXPECTED_APPLE_ARCHIVE_PATHS.values()
        }
        source_identity = {
            "source_tree_sha256": self.source_tree_sha256,
            "entry_count": 100,
            "content_bytes": 1000,
        }
        payload = {
            "schema_version": release_decision.APPLE_REPRODUCIBILITY_SCHEMA_VERSION,
            "status": "pass",
            "claim": "same_environment_deterministic_rebuild",
            "independent_reproduction_proven": False,
            "compiler_trust_proven": False,
            "candidate_blind_build_proven": False,
            "hermetic_build_proven": False,
            "trusted_source_and_build_scripts_assumed": True,
            "release_revision": self.release_revision,
            "artifact_revision": self.artifact_revision,
            "source_revision": self.source_revision,
            "source_tree_sha256": self.source_tree_sha256,
            "artifact_commit_policy": {
                "direct_single_parent": True,
                "generated_only_diff": True,
                "governance_only_release_suffix": True,
            },
            "committed_artifact_verification": self.apple_verification_payload(),
            "committed_archive_lfs": lfs,
            "artifact_inventory": inventory,
            "build_count": 2,
            "source_identities": [source_identity, dict(source_identity)],
            "all_three_inventories_equal": True,
            "verified_dist_output": "artifacts/apple-verified-dist",
            "disk_preflight": {
                "materialized_source_lfs_object_count": 3,
                "materialized_source_lfs_bytes": 100,
                "required_free_bytes": 100 + 16 * 1024**3,
                "observed_free_bytes": 100 + 17 * 1024**3,
            },
            "toolchain": {
                "xcode": ["Xcode 26.2", "Build version 17C52"],
                "iphoneos_sdk": "26.2",
                "iphoneos_sdk_build": "23C53",
                "effective_developer_dir": "/Applications/Xcode.app/Developer",
                "resolved_xcodebuild": "/Applications/Xcode.app/Developer/usr/bin/xcodebuild",
                "global_xcode_select": "/Applications/Xcode.app/Developer",
                "rustc_verbose": [
                    "release: 1.96.1",
                    "commit-hash: 31fca3adb283cc9dfd56b49cdee9a96eb9c96ffd",
                    "LLVM version: 22.1.2",
                ],
                "cargo": "cargo 1.96.1 (fixture)",
                "git": "git version 2.50.0",
                "git_lfs": "git-lfs/3.7.1",
                "python": "Python 3.14.0",
                "runner": {"RUNNER_OS": "macOS"},
            },
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
        verification = json.loads(
            self.evidence_verification.read_text(encoding="utf-8")
        )
        payload = {
            "schema_version": release_decision.PRODUCT_ACCEPTANCE_SCHEMA_VERSION,
            "status": "pass",
            "profile": release_decision.PROFILE,
            "candidate_revision": self.revision,
            "source_revision": self.source_revision,
            "artifact_revision": self.artifact_revision,
            "release_revision": self.release_revision,
            "source_tree_sha256": self.source_tree_sha256,
            "evidence_manifest_sha256": self.digest(self.evidence_manifest),
            "evidence_attestation_sha256": self.digest(self.evidence_attestation),
            "evidence_attestation_verification_sha256": self.digest(
                self.evidence_verification
            ),
            "evidence_signer_spki_sha256": verification[
                "public_key_spki_sha256"
            ],
            "apple_artifact_verification_sha256": self.digest(
                self.apple_verification
            ),
            "apple_artifact_reproducibility_sha256": self.digest(
                self.apple_reproducibility
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
        self.write(self.apple_verification, self.apple_verification_payload())
        self.write(self.apple_manifest, self.apple_manifest_payload())
        self.write(
            self.apple_reproducibility,
            self.apple_reproducibility_payload(),
        )
        self.write(self.evidence_manifest, self.evidence_payload(
            apple_artifact_status="pass",
            apple_artifact_source_revision=self.source_revision,
            apple_artifact_source_tree_sha256=self.source_tree_sha256,
            apple_reproducibility_status="pass",
            apple_reproducibility_source_revision=self.source_revision,
            apple_reproducibility_artifact_revision=self.artifact_revision,
            apple_reproducibility_release_revision=self.release_revision,
            apple_reproducibility_source_tree_sha256=self.source_tree_sha256,
        ))
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "Ed25519",
                "-out",
                self.evidence_private_key.as_posix(),
            ],
            check=True,
            capture_output=True,
        )
        os.chmod(self.evidence_private_key, 0o600)
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                self.evidence_private_key.as_posix(),
                "-pubout",
                "-out",
                self.evidence_public_key.as_posix(),
            ],
            check=True,
            capture_output=True,
        )
        attestation = release_decision.crypto_support.sign_manifest(
            self.evidence_manifest,
            self.evidence_private_key,
            self.expected_evidence_key_id,
        )
        self.write(self.evidence_attestation, attestation)
        self.write(
            self.evidence_verification,
            self.evidence_verification_payload(),
        )
        self.write(self.pilot_gate, self.pilot_payload())
        self.write(self.product_acceptance, self.product_payload())

    def input_paths(self) -> dict[str, str | None]:
        return {
            "evidence_manifest": self.evidence_manifest.as_posix(),
            "evidence_attestation": self.evidence_attestation.as_posix(),
            "evidence_public_key": self.evidence_public_key.as_posix(),
            "expected_evidence_key_id": self.expected_evidence_key_id,
            "evidence_attestation_verification": (
                self.evidence_verification.as_posix()
            ),
            "apple_artifact_verification": self.apple_verification.as_posix(),
            "apple_artifact_reproducibility": (
                self.apple_reproducibility.as_posix()
            ),
            "apple_release_manifest": self.apple_manifest.as_posix(),
            "pilot_gate_report": self.pilot_gate.as_posix(),
            "product_integration_acceptance": self.product_acceptance.as_posix(),
        }

    def evidence_verification_payload(self) -> dict:
        return release_decision.crypto_support.verify_manifest(
            self.evidence_manifest,
            self.evidence_attestation,
            self.evidence_public_key,
            self.expected_evidence_key_id,
        )

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
        self.assertEqual(decision["runtime_safety"], "blocked")
        self.assertIsNone(decision["evidence_signer_spki_sha256"])

    def test_absent_raw_trust_trio_is_blocked(self):
        paths = self.input_paths()
        for field in (
            "evidence_attestation",
            "evidence_public_key",
            "expected_evidence_key_id",
        ):
            paths[field] = None

        decision = self.create(paths)

        self.assertEqual(decision["runtime_safety"], "blocked")
        self.assertEqual(decision["privacy_security"], "blocked")
        self.assertEqual(decision["decision"], "no-go")

    def test_every_partial_raw_trust_trio_is_fail(self):
        fields = (
            "evidence_attestation",
            "evidence_public_key",
            "expected_evidence_key_id",
        )
        for supplied_mask in range(1, 7):
            with self.subTest(supplied_mask=supplied_mask):
                paths = self.input_paths()
                for index, field in enumerate(fields):
                    if supplied_mask & (1 << index) == 0:
                        paths[field] = None

                decision = self.create(paths)

                self.assertEqual(decision["runtime_safety"], "fail")
                self.assertEqual(decision["privacy_security"], "fail")
                self.assertEqual(decision["decision"], "no-go")

    def test_forged_derived_verification_cannot_substitute_for_raw_trust(self):
        forged = self.evidence_verification_payload()
        forged["key_id"] = "attacker-key"
        forged["public_key_spki_sha256"] = "e" * 64
        self.write(self.evidence_verification, forged)
        self.write(self.product_acceptance, self.product_payload())

        decision = self.create()

        self.assertEqual(decision["runtime_safety"], "fail")
        self.assertEqual(decision["privacy_security"], "fail")
        self.assertEqual(decision["decision"], "no-go")

    def test_wrong_evidence_key_and_expected_id_fail(self):
        replacement_private = self.root / "replacement-evidence-private.pem"
        replacement_public = self.root / "replacement-evidence-public.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "Ed25519",
                "-out",
                replacement_private.as_posix(),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                replacement_private.as_posix(),
                "-pubout",
                "-out",
                replacement_public.as_posix(),
            ],
            check=True,
            capture_output=True,
        )
        paths = self.input_paths()
        paths["evidence_public_key"] = replacement_public.as_posix()
        self.assertEqual(self.create(paths)["runtime_safety"], "fail")

        paths = self.input_paths()
        paths["expected_evidence_key_id"] = "wrong-evidence-key"
        self.assertEqual(self.create(paths)["runtime_safety"], "fail")

    def test_raw_evidence_attestation_or_manifest_mutation_fails(self):
        attestation = json.loads(
            self.evidence_attestation.read_text(encoding="utf-8")
        )
        attestation["signature_base64"] = "A" * 88
        self.write(self.evidence_attestation, attestation)
        self.write(self.product_acceptance, self.product_payload())
        self.assertEqual(self.create()["runtime_safety"], "fail")

        self.write_all_valid_inputs()
        manifest = self.evidence_payload(
            apple_artifact_status="pass",
            apple_artifact_source_revision=self.source_revision,
            apple_artifact_source_tree_sha256=self.source_tree_sha256,
            apple_reproducibility_status="pass",
            apple_reproducibility_source_revision=self.source_revision,
            apple_reproducibility_artifact_revision=self.artifact_revision,
            apple_reproducibility_release_revision=self.release_revision,
            apple_reproducibility_source_tree_sha256=self.source_tree_sha256,
        )
        manifest["tampered_after_attestation"] = True
        self.write(self.evidence_manifest, manifest)
        self.write(self.product_acceptance, self.product_payload())
        self.assertEqual(self.create()["runtime_safety"], "fail")

    def test_malformed_raw_attestation_fails_closed(self):
        self.evidence_attestation.write_text('{"key_id":[]}', encoding="utf-8")
        self.write(self.product_acceptance, self.product_payload())

        decision = self.create()

        self.assertEqual(decision["runtime_safety"], "fail")

    def test_product_acceptance_binds_raw_attestation_and_signer_spki(self):
        self.write(
            self.product_acceptance,
            self.product_payload(
                evidence_attestation_sha256="0" * 64,
                evidence_signer_spki_sha256="1" * 64,
            ),
        )

        self.assertEqual(self.create()["product_integration"], "fail")

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
            self.product_payload(candidate_revision="e" * 40),
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

    def test_apple_release_manifest_extra_field_fails_closed(self):
        self.write(
            self.apple_manifest,
            self.apple_manifest_payload(unexpected="mirrored"),
        )
        self.write(
            self.apple_reproducibility,
            self.apple_reproducibility_payload(),
        )

        self.assertEqual(self.create()["artifact_integrity"], "fail")

    def test_apple_release_manifest_requires_exact_ios_floor(self):
        self.write(
            self.apple_manifest,
            self.apple_manifest_payload(minimum_ios_version="17.0"),
        )
        self.write(
            self.apple_reproducibility,
            self.apple_reproducibility_payload(),
        )

        self.assertEqual(self.create()["artifact_integrity"], "fail")

    def test_apple_release_manifest_requires_model_manifest_digest(self):
        self.write(
            self.apple_manifest,
            self.apple_manifest_payload(model_manifest_sha256=None),
        )
        self.write(
            self.apple_reproducibility,
            self.apple_reproducibility_payload(),
        )

        self.assertEqual(self.create()["artifact_integrity"], "fail")

    def test_missing_reproducibility_proof_blocks_go(self):
        paths = self.input_paths()
        paths["apple_artifact_reproducibility"] = None

        decision = self.create(paths)

        self.assertEqual(decision["artifact_integrity"], "blocked")
        self.assertEqual(decision["decision"], "no-go")

    def test_reproducibility_claim_upgrade_is_rejected(self):
        self.write(
            self.apple_reproducibility,
            self.apple_reproducibility_payload(
                independent_reproduction_proven=True
            ),
        )

        decision = self.create()

        self.assertEqual(decision["artifact_integrity"], "fail")
        self.assertEqual(decision["decision"], "no-go")

    def test_reproducibility_must_bind_exact_apple_verification(self):
        proof = self.apple_reproducibility_payload()
        proof["committed_artifact_verification"]["cargo_features"] = ["onnx"]
        self.write(self.apple_reproducibility, proof)

        decision = self.create()

        self.assertEqual(decision["artifact_integrity"], "fail")

    def test_reproducibility_malformed_slice_identifier_fails_closed(self):
        verification = self.apple_verification_payload()
        verification["slices"][0]["slice_id"] = []
        proof = self.apple_reproducibility_payload()
        proof["committed_artifact_verification"] = verification
        self.write(self.apple_verification, verification)
        self.write(self.apple_reproducibility, proof)

        decision = self.create()

        self.assertEqual(decision["artifact_integrity"], "fail")

    def test_reproducibility_malformed_toolchain_fails_closed(self):
        proof = self.apple_reproducibility_payload()
        proof["toolchain"]["rustc_verbose"] = [[]]
        self.write(self.apple_reproducibility, proof)

        decision = self.create()

        self.assertEqual(decision["artifact_integrity"], "fail")

    def test_apple_verification_extra_field_fails_closed(self):
        verification = self.apple_verification_payload(unexpected="mirrored")
        proof = self.apple_reproducibility_payload()
        proof["committed_artifact_verification"] = verification
        self.write(self.apple_verification, verification)
        self.write(self.apple_reproducibility, proof)

        self.assertEqual(self.create()["artifact_integrity"], "fail")

    def test_reproducibility_disk_and_xcode_path_claims_are_exact(self):
        proof = self.apple_reproducibility_payload()
        proof["disk_preflight"]["required_free_bytes"] += 1
        self.write(self.apple_reproducibility, proof)
        self.assertEqual(self.create()["artifact_integrity"], "fail")

        proof = self.apple_reproducibility_payload()
        proof["toolchain"]["resolved_xcodebuild"] = "/tmp/xcodebuild"
        self.write(self.apple_reproducibility, proof)
        self.assertEqual(self.create()["artifact_integrity"], "fail")

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

    @unittest.skipIf(os.name == "nt", "FIFO semantics differ on Windows")
    def test_fifo_input_is_rejected_without_blocking(self):
        fifo = self.root / "product.fifo"
        os.mkfifo(fifo)
        paths = self.input_paths()
        paths["product_integration_acceptance"] = fifo.as_posix()

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

    def test_validator_rejects_go_with_missing_bound_artifact(self):
        decision = self.create()
        decision["artifacts"]["evidence_public_key"] = {
            "required": True,
            "present": False,
            "bytes": None,
            "sha256": None,
            "schema_version": None,
            "observed_status": "missing",
        }

        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "contradicts"
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
        self.assertEqual(report["source_revision"], self.source_revision)
        self.assertEqual(report["artifact_revision"], self.artifact_revision)
        self.assertEqual(report["release_revision"], self.release_revision)

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

    def test_sign_reverifies_raw_attestation_not_only_derived_report(self):
        attestation = json.loads(
            self.evidence_attestation.read_text(encoding="utf-8")
        )
        attestation["signature_base64"] = "A" * 88
        self.write(self.evidence_attestation, attestation)

        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "does not match"
        ):
            release_decision.sign_decision(
                self.decision_path,
                self.private_key,
                "release-operator-2026",
                self.input_paths(),
            )

    def test_evidence_signer_cannot_also_be_release_operator(self):
        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "must differ"
        ):
            release_decision.sign_decision(
                self.decision_path,
                self.evidence_private_key,
                "release-operator-2026",
                self.input_paths(),
            )

    def test_verifier_enforces_evidence_and_release_role_separation(self):
        decision = json.loads(self.decision_path.read_text(encoding="utf-8"))
        operator_spki = sha256(
            release_decision.crypto_support.public_key_der_from_public(
                self.public_key
            )
        ).hexdigest()
        decision["evidence_signer_spki_sha256"] = operator_spki
        self.write(self.decision_path, decision)
        raw = self.decision_path.read_bytes()
        attestation = {
            "schema_version": release_decision.ATTESTATION_SCHEMA_VERSION,
            "signature_algorithm": "Ed25519",
            "key_id": "release-operator-2026",
            "decision_sha256": sha256(raw).hexdigest(),
            "candidate": decision["candidate"],
            "profile": decision["profile"],
            "source_revision": decision["source_revision"],
            "artifact_revision": decision["artifact_revision"],
            "release_revision": decision["release_revision"],
            "evidence_signer_key_id": decision["evidence_signer_key_id"],
            "evidence_signer_spki_sha256": operator_spki,
            "public_key_spki_sha256": operator_spki,
        }
        with tempfile.NamedTemporaryFile() as claims:
            claims.write(release_decision.canonical_attestation_claims(attestation))
            claims.flush()
            signature = release_decision.crypto_support.run_openssl(
                [
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    self.private_key.as_posix(),
                    "-in",
                    claims.name,
                ]
            )
        import base64

        attestation["signature_base64"] = base64.b64encode(signature).decode("ascii")
        self.write(self.attestation_path, attestation)

        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "must differ"
        ):
            release_decision.verify_decision(
                self.decision_path, self.attestation_path, self.public_key
            )

    def test_cli_protects_raw_trust_inputs_from_output_alias(self):
        result = subprocess.run(
            [
                "python3",
                "ci/release_decision.py",
                "create",
                "--candidate-revision",
                self.revision,
                "--runtime-version",
                self.runtime_version,
                "--evidence-manifest",
                self.evidence_manifest.as_posix(),
                "--evidence-attestation",
                self.evidence_attestation.as_posix(),
                "--evidence-public-key",
                self.evidence_public_key.as_posix(),
                "--expected-evidence-key-id",
                self.expected_evidence_key_id,
                "--output",
                self.evidence_attestation.as_posix(),
            ],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("must not overwrite", result.stderr)

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

    def test_malformed_attestation_types_fail_closed(self):
        attestation = self.sign()
        attestation["key_id"] = []
        attestation["signature_base64"] = []
        self.write(self.attestation_path, attestation)

        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "claims are invalid"
        ):
            release_decision.verify_decision(
                self.decision_path, self.attestation_path, self.public_key
            )


if __name__ == "__main__":
    unittest.main()
