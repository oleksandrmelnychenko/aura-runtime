import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from unittest import mock

from ci import release_decision
from ci import pilot_signoff_verification


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
        self.pilot_signoff_verification = (
            self.root / "pilot-signoff-verification.json"
        )
        self.pilot_signoff_trust_policy = self.root / "pilot-signoff-policy.json"
        self.pilot_signoff_private_keys = [
            self.root / f"pilot-signoff-{index}.pem" for index in range(4)
        ]
        self.product_acceptance = self.root / "product-acceptance.json"
        self.write_all_valid_inputs()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def digest(path: Path) -> str:
        return sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def write(path: Path, payload: object) -> None:
        release_decision.crypto_support.write_json_atomic(path, payload)

    def evidence_payload(self, **summary_overrides) -> dict:
        pilot_signoff = json.loads(
            self.pilot_signoff_verification.read_text(encoding="utf-8")
        )
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
            "pilot_gate_status": "pass",
            "pilot_gate_schema_version": "aura.pilot_gate_report.v2",
            "pilot_gate_release_revision": self.release_revision,
            "pilot_gate_shadow_run_count": 2,
            "pilot_gate_check_count": 15,
            "pilot_signoff_verification_status": "pass",
            "pilot_signoff_verification_schema_version": pilot_signoff[
                "schema_version"
            ],
            "pilot_signoff_verification_release_revision": pilot_signoff[
                "release_revision"
            ],
            "pilot_signoff_verification_trust_policy_sha256": pilot_signoff[
                "trust_policy_sha256"
            ],
            "pilot_signoff_verification_policy_id": pilot_signoff["policy_id"],
            "pilot_signoff_verification_policy_epoch": pilot_signoff[
                "policy_epoch"
            ],
            "pilot_signoff_verification_signature_algorithm": pilot_signoff[
                "signature_algorithm"
            ],
            "pilot_signoff_verification_required_review_areas": pilot_signoff[
                "required_review_areas"
            ],
            "pilot_signoff_verification_verified_signoff_count": pilot_signoff[
                "verified_signoff_count"
            ],
            "pilot_signoff_verification_distinct_signer_count": pilot_signoff[
                "distinct_signer_count"
            ],
            "pilot_signoff_verification_signer_spki_sha256": pilot_signoff[
                "signer_spki_sha256"
            ],
            "pilot_signoff_verification_signoff_set_sha256": pilot_signoff[
                "signoff_set_sha256"
            ],
            "pilot_signoff_verification_signer_spki_set_sha256": pilot_signoff[
                "signer_spki_set_sha256"
            ],
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
                "pilot_gate_report": {
                    "sha256": self.digest(self.pilot_gate),
                    "observed_status": "pass",
                    "schema_version": "aura.pilot_gate_report.v2",
                    "release_revision": self.release_revision,
                },
                "pilot_signoff_verification": {
                    "sha256": self.digest(self.pilot_signoff_verification),
                    "observed_status": "pass",
                    "schema_version": pilot_signoff["schema_version"],
                    "release_revision": pilot_signoff["release_revision"],
                    "trust_policy_sha256": pilot_signoff[
                        "trust_policy_sha256"
                    ],
                    "policy_id": pilot_signoff["policy_id"],
                    "policy_epoch": pilot_signoff["policy_epoch"],
                    "signer_spki_sha256": pilot_signoff[
                        "signer_spki_sha256"
                    ],
                    "signoff_set_sha256": pilot_signoff["signoff_set_sha256"],
                    "signer_spki_set_sha256": pilot_signoff[
                        "signer_spki_set_sha256"
                    ],
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
        review_areas = list(release_decision.PILOT_REQUIRED_REVIEW_AREAS)
        config = {
            "min_shadow_runs": 2,
            "min_shadow_total_events": 500,
            "require_release_pass": True,
            "require_pilot_regression_pass": True,
            "require_kids_memory_pass": True,
            "require_kids_preprod_dry_run_pass": True,
            "required_review_areas": review_areas,
        }
        release = {
            "schema_version": "aura.release_report.v3",
            "overall_status": "pass",
            "social_context_inference": {
                "passed": True,
                "total_expectations": 8,
                "failed_expectations": 0,
            },
        }
        pilot_regression = {
            "schema_version": "aura.pilot_simulation_regression_report.v1",
            "overall_status": "pass",
            "suite_id": "unit-test-pilot-suite",
            "scenario_count": 12,
        }
        shadow_runs = [
            {
                "schema_version": "aura.shadow_mode_bundle.v1",
                "source_kind": "world_sim",
                "source_label": f"unit-test-shadow-{index}",
                "wire_package": "aura.messenger.v1",
                "protection_level": "high",
                "total_events": 300,
                "threat_events": 40,
                "finding_count": 0,
                "raw_text_present": False,
                "raw_identifier_fields_present": False,
            }
            for index in range(2)
        ]
        kids_memory = {
            "schema_version": "aura.kids_memory_health_snapshot.v1",
            "overall_status": "pass",
            "total_memory_hits": 6,
            "missing_mandatory_reason_codes": [],
        }
        kids_preprod = {
            "schema_version": "aura.kids_preprod_dry_run_matrix.v1",
            "overall_status": "pass",
            "checks_failed": 0,
        }
        signoffs = [
            {
                "area": area,
                "reviewer": f"unit-test-reviewer-{index}",
                "status": "approved",
                "reviewed_at_utc": f"2026-03-16T10:{index:02d}:00Z",
                "notes": "unit-test fixture only; not an authenticated identity",
                "release_revision": self.release_revision,
            }
            for index, area in enumerate(review_areas)
        ]
        checks = [
            {
                "check_id": "candidate_release_revision",
                "status": "pass",
                "summary": (
                    "pilot candidate is bound to release "
                    f"{self.release_revision}"
                ),
            },
            {
                "check_id": "release_gate",
                "status": "pass",
                "summary": "Phase 2 release gate passed",
            },
            {
                "check_id": "release_social_context_inference",
                "status": "pass",
                "summary": "social-context inference expectations passed (8/8)",
            },
            {
                "check_id": "pilot_regression",
                "status": "pass",
                "summary": "pilot regression corpus passed",
            },
            {
                "check_id": "kids_memory_health",
                "status": "pass",
                "summary": "kids memory health passed (total_hits=6)",
            },
            {
                "check_id": "kids_preprod_dry_run",
                "status": "pass",
                "summary": (
                    "kids preprod dry-run matrix passed with no failed checks"
                ),
            },
            {
                "check_id": "shadow_run_count",
                "status": "pass",
                "summary": "observed 2 shadow runs (required 2)",
            },
            {
                "check_id": "shadow_event_volume",
                "status": "pass",
                "summary": "shadow runs cover 600 total events (required >= 500)",
            },
            {
                "check_id": "shadow_privacy_and_findings",
                "status": "pass",
                "summary": "all shadow runs are clean and privacy-safe",
            },
            {
                "check_id": "shadow_contract_stability",
                "status": "pass",
                "summary": (
                    "shadow runs share stable schema, wire package, and "
                    "protection level"
                ),
            },
            {
                "check_id": "review_signoff_set",
                "status": "pass",
                "summary": (
                    "all required review signoffs bind the exact release revision"
                ),
            },
        ]
        checks.extend(
            {
                "check_id": f"review_signoff.{signoff['area']}",
                "status": "pass",
                "summary": (
                    f"{signoff['area']} approved by {signoff['reviewer']}"
                ),
            }
            for signoff in signoffs
        )
        payload = {
            "schema_version": "aura.pilot_gate_report.v2",
            "release_revision": self.release_revision,
            "overall_status": "pass",
            "config": config,
            "release": release,
            "pilot_regression": pilot_regression,
            "shadow_runs": shadow_runs,
            "kids_memory_health": kids_memory,
            "kids_preprod_dry_run": kids_preprod,
            "signoffs": signoffs,
            "checks": checks,
            "rollback_triggers": json.loads(
                json.dumps(release_decision.PILOT_ROLLBACK_TRIGGERS)
            ),
            "operator_review_cadence": (
                release_decision.PILOT_OPERATOR_REVIEW_CADENCE
            ),
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

    def sign_pilot_attestation(
        self,
        attestation: dict,
        private_key: Path,
        label: str,
    ) -> str:
        claims_path = self.root / f"pilot-signoff-claims-{label}.bin"
        claims_path.write_bytes(
            pilot_signoff_verification.canonical_attestation_claims(attestation)
        )
        signature = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                private_key.as_posix(),
                "-in",
                claims_path.as_posix(),
            ],
            check=True,
            capture_output=True,
        ).stdout
        return base64.b64encode(signature).decode("ascii")

    def write_pilot_signoff_inputs(self) -> None:
        signoffs = self.pilot_payload()["signoffs"]
        roles = []
        attestations = []
        public_key_der = []
        for index, (signoff, private_key) in enumerate(
            zip(signoffs, self.pilot_signoff_private_keys, strict=True)
        ):
            subprocess.run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "Ed25519",
                    "-out",
                    private_key.as_posix(),
                ],
                check=True,
                capture_output=True,
            )
            os.chmod(private_key, 0o600)
            der = subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    private_key.as_posix(),
                    "-pubout",
                    "-outform",
                    "DER",
                ],
                check=True,
                capture_output=True,
            ).stdout
            public_key_der.append(der)
            roles.append(
                {
                    "area": signoff["area"],
                    "reviewer": signoff["reviewer"],
                    "key_id": f"pilot-signoff-key-{index}",
                    "public_key_hex": der[-32:].hex(),
                }
            )
        policy = {
            "schema_version": (
                pilot_signoff_verification.TRUST_POLICY_SCHEMA_VERSION
            ),
            "policy_id": "unit-test-pilot-signoff-policy",
            "policy_epoch": 1,
            "roles": roles,
        }
        self.expected_pilot_signoff_trust_policy_sha256 = (
            pilot_signoff_verification.trust_policy_sha256(policy)
        )
        for index, (signoff, private_key, der) in enumerate(
            zip(
                signoffs,
                self.pilot_signoff_private_keys,
                public_key_der,
                strict=True,
            )
        ):
            claims = {
                "schema_version": pilot_signoff_verification.CLAIM_SCHEMA_VERSION,
                "policy_id": policy["policy_id"],
                "policy_epoch": policy["policy_epoch"],
                "trust_policy_sha256": (
                    self.expected_pilot_signoff_trust_policy_sha256
                ),
                **signoff,
            }
            attestation = {
                "schema_version": (
                    pilot_signoff_verification.ATTESTATION_SCHEMA_VERSION
                ),
                "signature_algorithm": "Ed25519",
                "key_id": roles[index]["key_id"],
                "public_key_spki_sha256": sha256(der).hexdigest(),
                "claims": claims,
                "signature_base64": "",
            }
            attestation["signature_base64"] = self.sign_pilot_attestation(
                attestation,
                private_key,
                str(index),
            )
            attestations.append(attestation)
        bundle = {
            "schema_version": pilot_signoff_verification.BUNDLE_SCHEMA_VERSION,
            "release_revision": self.release_revision,
            "attestations": attestations,
        }
        report = pilot_signoff_verification.verify_bundle(
            bundle,
            policy,
            self.expected_pilot_signoff_trust_policy_sha256,
            self.release_revision,
        )
        self.write(self.pilot_signoff_trust_policy, policy)
        self.write(self.pilot_signoff_verification, report)

    def write_all_valid_inputs(self):
        self.write(self.apple_verification, self.apple_verification_payload())
        self.write(self.apple_manifest, self.apple_manifest_payload())
        self.write(
            self.apple_reproducibility,
            self.apple_reproducibility_payload(),
        )
        self.write(self.pilot_gate, self.pilot_payload())
        self.write_pilot_signoff_inputs()
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
            "pilot_signoff_verification": (
                self.pilot_signoff_verification.as_posix()
            ),
            "pilot_signoff_trust_policy": (
                self.pilot_signoff_trust_policy.as_posix()
            ),
            "expected_pilot_signoff_trust_policy_sha256": (
                self.expected_pilot_signoff_trust_policy_sha256
            ),
            "product_integration_acceptance": self.product_acceptance.as_posix(),
        }

    def evidence_verification_payload(self) -> dict:
        return release_decision.crypto_support.verify_manifest(
            self.evidence_manifest,
            self.evidence_attestation,
            self.evidence_public_key,
            self.expected_evidence_key_id,
        )

    def write_signed_evidence(self, manifest: dict) -> None:
        self.write(self.evidence_manifest, manifest)
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
        self.write(self.product_acceptance, self.product_payload())

    def create(self, paths: dict[str, str | None] | None = None) -> dict:
        return release_decision.create_decision(
            self.revision,
            self.runtime_version,
            release_decision.PROFILE,
            self.input_paths() if paths is None else paths,
        )

    def assert_pilot_fails_closed(self, payload: object) -> None:
        self.write(self.pilot_gate, payload)
        self.write(self.product_acceptance, self.product_payload())

        decision = self.create()

        self.assertEqual(decision["operational_readiness"], "fail")
        self.assertEqual(decision["human_signoffs"], "fail")
        self.assertEqual(decision["decision"], "no-go")


class ReleaseDecisionTests(ReleaseDecisionFixture):
    def test_complete_rules_only_candidate_is_go(self):
        decision = self.create()

        self.assertEqual(decision["schema_version"], "aura.release_decision.v3")
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
            decision["pilot_signoff_trust_policy_sha256"],
            self.expected_pilot_signoff_trust_policy_sha256,
        )
        self.assertEqual(decision["pilot_signoff_policy_epoch"], 1)
        self.assertEqual(len(decision["pilot_signoff_signer_spki_sha256"]), 4)
        self.assertEqual(
            decision["pilot_signoff_signer_spki_set_sha256"],
            pilot_signoff_verification.signer_spki_set_sha256(
                decision["pilot_signoff_signer_spki_sha256"]
            ),
        )
        self.assertEqual(
            decision["profile_scope"],
            {
                "model_enabled": False,
                "relay_enabled": False,
                "military_enabled": False,
            },
        )

    def test_integer_profile_scope_values_are_rejected(self):
        for value in (0, 1):
            with self.subTest(value=value):
                decision = self.create()
                decision["profile_scope"]["model_enabled"] = value
                with self.assertRaisesRegex(
                    release_decision.ReleaseDecisionError,
                    "profile scope values",
                ):
                    release_decision.validate_decision(decision)

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

    def test_pilot_gate_rejects_unknown_or_incomplete_top_level_contract(self):
        mutations = {
            "extra field": lambda payload: payload.__setitem__(
                "unexpected", "mirrored"
            ),
            "missing config": lambda payload: payload.pop("config"),
            "wrong schema": lambda payload: payload.__setitem__(
                "schema_version", "aura.pilot_gate_report.v1"
            ),
            "non-pass overall": lambda payload: payload.__setitem__(
                "overall_status", "blocked"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                pilot = self.pilot_payload()
                mutate(pilot)
                self.assert_pilot_fails_closed(pilot)

    def test_pilot_gate_rejects_v1_array_without_crashing(self):
        self.assert_pilot_fails_closed(
            [
                {
                    "area": "false_positive_hotspots",
                    "reviewer": "stale-reviewer",
                    "status": "approved",
                }
            ]
        )

    def test_pilot_gate_rejects_weakened_or_malformed_config(self):
        mutations = {
            "extra field": lambda payload: payload["config"].__setitem__(
                "unexpected", True
            ),
            "too few shadow runs": lambda payload: payload["config"].__setitem__(
                "min_shadow_runs", 1
            ),
            "boolean shadow runs": lambda payload: payload["config"].__setitem__(
                "min_shadow_runs", True
            ),
            "too few shadow events": lambda payload: payload["config"].__setitem__(
                "min_shadow_total_events", 499
            ),
            "release disabled": lambda payload: payload["config"].__setitem__(
                "require_release_pass", False
            ),
            "regression disabled": lambda payload: payload["config"].__setitem__(
                "require_pilot_regression_pass", False
            ),
            "kids memory disabled": lambda payload: payload["config"].__setitem__(
                "require_kids_memory_pass", False
            ),
            "kids preprod disabled": lambda payload: payload["config"].__setitem__(
                "require_kids_preprod_dry_run_pass", False
            ),
            "review area missing": lambda payload: payload["config"][
                "required_review_areas"
            ].pop(),
            "review areas reordered": lambda payload: payload["config"].__setitem__(
                "required_review_areas",
                list(reversed(payload["config"]["required_review_areas"])),
            ),
            "unknown review area": lambda payload: payload["config"][
                "required_review_areas"
            ].append("unknown"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                pilot = self.pilot_payload()
                mutate(pilot)
                self.assert_pilot_fails_closed(pilot)

    def test_pilot_gate_rejects_malformed_release_or_regression_snapshots(self):
        mutations = {
            "release extra": lambda payload: payload["release"].__setitem__(
                "unexpected", True
            ),
            "release schema": lambda payload: payload["release"].__setitem__(
                "schema_version", "aura.release_report.v2"
            ),
            "release inference absent": lambda payload: payload["release"].__setitem__(
                "social_context_inference", None
            ),
            "release inference failed": lambda payload: payload["release"][
                "social_context_inference"
            ].__setitem__("passed", False),
            "release inference empty": lambda payload: payload["release"][
                "social_context_inference"
            ].__setitem__("total_expectations", 0),
            "release inference failures": lambda payload: payload["release"][
                "social_context_inference"
            ].__setitem__("failed_expectations", 1),
            "regression extra": lambda payload: payload[
                "pilot_regression"
            ].__setitem__("unexpected", True),
            "regression schema": lambda payload: payload[
                "pilot_regression"
            ].__setitem__("schema_version", "aura.pilot_regression.v0"),
            "regression empty suite": lambda payload: payload[
                "pilot_regression"
            ].__setitem__("suite_id", ""),
            "regression empty scenarios": lambda payload: payload[
                "pilot_regression"
            ].__setitem__("scenario_count", 0),
            "regression boolean scenarios": lambda payload: payload[
                "pilot_regression"
            ].__setitem__("scenario_count", True),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                pilot = self.pilot_payload()
                mutate(pilot)
                self.assert_pilot_fails_closed(pilot)

    def test_pilot_gate_rejects_unsafe_or_malformed_shadow_snapshots(self):
        mutations = {
            "no runs": lambda payload: payload.__setitem__("shadow_runs", []),
            "too few runs": lambda payload: payload["shadow_runs"].pop(),
            "extra field": lambda payload: payload["shadow_runs"][0].__setitem__(
                "unexpected", True
            ),
            "wrong schema": lambda payload: payload["shadow_runs"][0].__setitem__(
                "schema_version", "aura.shadow_mode_bundle.v0"
            ),
            "wrong source": lambda payload: payload["shadow_runs"][0].__setitem__(
                "source_kind", "uploaded"
            ),
            "empty label": lambda payload: payload["shadow_runs"][0].__setitem__(
                "source_label", " "
            ),
            "wrong wire": lambda payload: payload["shadow_runs"][0].__setitem__(
                "wire_package", "aura.messenger.v2"
            ),
            "weaker protection": lambda payload: payload["shadow_runs"][
                0
            ].__setitem__("protection_level", "medium"),
            "empty events": lambda payload: payload["shadow_runs"][0].__setitem__(
                "total_events", 0
            ),
            "boolean events": lambda payload: payload["shadow_runs"][0].__setitem__(
                "total_events", True
            ),
            "threats exceed total": lambda payload: payload["shadow_runs"][
                0
            ].__setitem__("threat_events", 301),
            "findings": lambda payload: payload["shadow_runs"][0].__setitem__(
                "finding_count", 1
            ),
            "raw text": lambda payload: payload["shadow_runs"][0].__setitem__(
                "raw_text_present", True
            ),
            "raw identifiers": lambda payload: payload["shadow_runs"][
                0
            ].__setitem__("raw_identifier_fields_present", True),
            "insufficient volume": lambda payload: [
                run.__setitem__("total_events", 200)
                for run in payload["shadow_runs"]
            ],
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                pilot = self.pilot_payload()
                mutate(pilot)
                self.assert_pilot_fails_closed(pilot)

    def test_pilot_gate_rejects_malformed_kids_or_signoff_content(self):
        mutations = {
            "kids memory absent": lambda payload: payload.__setitem__(
                "kids_memory_health", None
            ),
            "kids memory extra": lambda payload: payload[
                "kids_memory_health"
            ].__setitem__("unexpected", True),
            "kids memory schema": lambda payload: payload[
                "kids_memory_health"
            ].__setitem__("schema_version", "aura.kids_memory_health_snapshot.v0"),
            "kids memory no hits": lambda payload: payload[
                "kids_memory_health"
            ].__setitem__("total_memory_hits", 0),
            "kids memory missing reasons": lambda payload: payload[
                "kids_memory_health"
            ].__setitem__("missing_mandatory_reason_codes", ["kids.memory.missing"]),
            "kids preprod absent": lambda payload: payload.__setitem__(
                "kids_preprod_dry_run", None
            ),
            "kids preprod extra": lambda payload: payload[
                "kids_preprod_dry_run"
            ].__setitem__("unexpected", True),
            "kids preprod schema": lambda payload: payload[
                "kids_preprod_dry_run"
            ].__setitem__("schema_version", "aura.kids_preprod_dry_run_matrix.v0"),
            "kids preprod failure": lambda payload: payload[
                "kids_preprod_dry_run"
            ].__setitem__("checks_failed", 1),
            "kids preprod boolean": lambda payload: payload[
                "kids_preprod_dry_run"
            ].__setitem__("checks_failed", False),
            "signoff missing": lambda payload: payload["signoffs"].pop(),
            "signoff extra": lambda payload: payload["signoffs"][0].__setitem__(
                "unexpected", True
            ),
            "signoff unknown area": lambda payload: payload["signoffs"][
                0
            ].__setitem__("area", "unknown"),
            "signoff empty reviewer": lambda payload: payload["signoffs"][
                0
            ].__setitem__("reviewer", ""),
            "signoff pending": lambda payload: payload["signoffs"][0].__setitem__(
                "status", "pending"
            ),
            "signoff malformed time": lambda payload: payload["signoffs"][
                0
            ].__setitem__("reviewed_at_utc", "yesterday"),
            "signoff non-utc time": lambda payload: payload["signoffs"][
                0
            ].__setitem__("reviewed_at_utc", "2026-03-16T10:00:00+02:00"),
            "signoff malformed notes": lambda payload: payload["signoffs"][
                0
            ].__setitem__("notes", {}),
            "signoff missing release": lambda payload: payload["signoffs"][
                0
            ].pop("release_revision"),
            "signoff stale release": lambda payload: payload["signoffs"][
                0
            ].__setitem__("release_revision", "e" * 40),
            "signoff duplicate area": lambda payload: payload["signoffs"][
                1
            ].__setitem__("area", payload["signoffs"][0]["area"]),
            "signoff fifth entry": lambda payload: payload["signoffs"].append(
                dict(payload["signoffs"][0])
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                pilot = self.pilot_payload()
                mutate(pilot)
                self.assert_pilot_fails_closed(pilot)

    def test_pilot_gate_rejects_stale_or_malformed_candidate_revision(self):
        mutations = {
            "stale report release": lambda payload: payload.__setitem__(
                "release_revision", "e" * 40
            ),
            "uppercase report release": lambda payload: payload.__setitem__(
                "release_revision", "F" * 40
            ),
            "short report release": lambda payload: payload.__setitem__(
                "release_revision", "f" * 39
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                pilot = self.pilot_payload()
                mutate(pilot)
                self.assert_pilot_fails_closed(pilot)

    def test_signed_manifest_must_bind_the_exact_pilot_gate(self):
        mutations = {
            "pilot leaf omitted": lambda manifest: manifest["artifacts"].pop(
                "pilot_gate_report"
            ),
            "pilot digest substituted": lambda manifest: manifest["artifacts"][
                "pilot_gate_report"
            ].__setitem__("sha256", "0" * 64),
            "pilot artifact release stale": lambda manifest: manifest["artifacts"][
                "pilot_gate_report"
            ].__setitem__("release_revision", "e" * 40),
            "pilot summary release stale": lambda manifest: manifest["summary"].__setitem__(
                "pilot_gate_release_revision", "e" * 40
            ),
            "pilot summary count forged": lambda manifest: manifest["summary"].__setitem__(
                "pilot_gate_check_count", 16
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self.write_all_valid_inputs()
                manifest = json.loads(
                    self.evidence_manifest.read_text(encoding="utf-8")
                )
                mutate(manifest)
                self.write_signed_evidence(manifest)

                decision = self.create()

                self.assertEqual(decision["operational_readiness"], "fail")
                self.assertEqual(decision["human_signoffs"], "fail")
                self.assertEqual(decision["decision"], "no-go")

    def test_absent_pilot_signoff_trio_is_blocked(self):
        paths = self.input_paths()
        for field in (
            "pilot_signoff_verification",
            "pilot_signoff_trust_policy",
            "expected_pilot_signoff_trust_policy_sha256",
        ):
            paths[field] = None

        decision = self.create(paths)

        self.assertEqual(decision["operational_readiness"], "blocked")
        self.assertEqual(decision["human_signoffs"], "blocked")
        self.assertEqual(decision["decision"], "no-go")

    def test_every_partial_pilot_signoff_trio_fails(self):
        fields = (
            "pilot_signoff_verification",
            "pilot_signoff_trust_policy",
            "expected_pilot_signoff_trust_policy_sha256",
        )
        for supplied_mask in range(1, 7):
            with self.subTest(supplied_mask=supplied_mask):
                paths = self.input_paths()
                for index, field in enumerate(fields):
                    if supplied_mask & (1 << index) == 0:
                        paths[field] = None

                decision = self.create(paths)

                self.assertEqual(decision["operational_readiness"], "fail")
                self.assertEqual(decision["human_signoffs"], "fail")
                self.assertEqual(decision["decision"], "no-go")

    def test_supplied_nonexistent_pilot_report_or_policy_fails(self):
        for field in (
            "pilot_signoff_verification",
            "pilot_signoff_trust_policy",
        ):
            with self.subTest(field=field):
                paths = self.input_paths()
                paths[field] = (self.root / f"missing-{field}.json").as_posix()

                decision = self.create(paths)

                self.assertEqual(decision["operational_readiness"], "fail")
                self.assertEqual(decision["human_signoffs"], "fail")
                self.assertEqual(decision["decision"], "no-go")

    def test_invalid_or_stale_pilot_signoff_report_fails(self):
        mutations = {
            "malformed": lambda report: report.clear(),
            "stale release": lambda report: report.__setitem__(
                "release_revision", "e" * 40
            ),
            "nonpass": lambda report: report.__setitem__("status", "fail"),
            "swapped signers": lambda report: report[
                "signer_spki_sha256"
            ].reverse(),
            "forged distinct count": lambda report: report.__setitem__(
                "distinct_signer_count", 3
            ),
            "bad signature": lambda report: report["attestations"][0].__setitem__(
                "signature_base64", "A" * 88
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self.write_all_valid_inputs()
                report = json.loads(
                    self.pilot_signoff_verification.read_text(encoding="utf-8")
                )
                mutate(report)
                self.write(self.pilot_signoff_verification, report)

                decision = self.create()

                self.assertEqual(decision["operational_readiness"], "fail")
                self.assertEqual(decision["human_signoffs"], "fail")
                self.assertEqual(decision["decision"], "no-go")

    def test_cryptographically_valid_nonpass_pilot_report_fails_release(self):
        for claim_status, report_status in (
            ("pending", "blocked"),
            ("needs_changes", "fail"),
        ):
            with self.subTest(claim_status=claim_status):
                self.write_all_valid_inputs()
                report = json.loads(
                    self.pilot_signoff_verification.read_text(encoding="utf-8")
                )
                report["attestations"][0]["claims"]["status"] = claim_status
                report["attestations"][0][
                    "signature_base64"
                ] = self.sign_pilot_attestation(
                    report["attestations"][0],
                    self.pilot_signoff_private_keys[0],
                    claim_status,
                )
                policy = json.loads(
                    self.pilot_signoff_trust_policy.read_text(encoding="utf-8")
                )
                report = pilot_signoff_verification.verify_bundle(
                    {
                        "schema_version": (
                            pilot_signoff_verification.BUNDLE_SCHEMA_VERSION
                        ),
                        "release_revision": self.release_revision,
                        "attestations": report["attestations"],
                    },
                    policy,
                    self.expected_pilot_signoff_trust_policy_sha256,
                    self.release_revision,
                )
                self.assertEqual(report["status"], report_status)
                self.write(self.pilot_signoff_verification, report)

                decision = self.create()

                self.assertEqual(decision["operational_readiness"], "fail")
                self.assertEqual(decision["human_signoffs"], "fail")
                self.assertEqual(decision["decision"], "no-go")

    def test_wrong_pilot_policy_or_expected_digest_fails(self):
        paths = self.input_paths()
        paths["expected_pilot_signoff_trust_policy_sha256"] = "0" * 64
        decision = self.create(paths)
        self.assertEqual(decision["human_signoffs"], "fail")

        policy = json.loads(
            self.pilot_signoff_trust_policy.read_text(encoding="utf-8")
        )
        policy["roles"][0]["public_key_hex"] = "0" * 64
        self.write(self.pilot_signoff_trust_policy, policy)
        decision = self.create()
        self.assertEqual(decision["operational_readiness"], "fail")
        self.assertEqual(decision["human_signoffs"], "fail")

    def test_authenticated_projection_must_match_pilot_gate_exactly(self):
        pilot = self.pilot_payload()
        pilot["signoffs"][0]["notes"] = "different signed claim projection"
        self.assert_pilot_fails_closed(pilot)

    def test_evidence_signer_must_differ_from_every_pilot_signer(self):
        pilot_private_key = self.pilot_signoff_private_keys[0]
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                pilot_private_key.as_posix(),
                "-pubout",
                "-out",
                self.evidence_public_key.as_posix(),
            ],
            check=True,
            capture_output=True,
        )
        attestation = release_decision.crypto_support.sign_manifest(
            self.evidence_manifest,
            pilot_private_key,
            self.expected_evidence_key_id,
        )
        self.write(self.evidence_attestation, attestation)
        self.write(self.evidence_verification, self.evidence_verification_payload())
        self.write(self.product_acceptance, self.product_payload())

        decision = self.create()

        self.assertEqual(decision["operational_readiness"], "fail")
        self.assertEqual(decision["human_signoffs"], "fail")
        self.assertIsNone(decision["pilot_signoff_signer_spki_sha256"])
        self.assertEqual(decision["decision"], "no-go")

    def test_signed_manifest_must_bind_authenticated_signoff_leaf(self):
        mutations = {
            "leaf omitted": lambda manifest: manifest["artifacts"].pop(
                "pilot_signoff_verification"
            ),
            "digest substituted": lambda manifest: manifest["artifacts"][
                "pilot_signoff_verification"
            ].__setitem__("sha256", "0" * 64),
            "policy substituted": lambda manifest: manifest["summary"].__setitem__(
                "pilot_signoff_verification_trust_policy_sha256", "0" * 64
            ),
            "signoff set substituted": lambda manifest: manifest["summary"].__setitem__(
                "pilot_signoff_verification_signoff_set_sha256", "0" * 64
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self.write_all_valid_inputs()
                manifest = json.loads(
                    self.evidence_manifest.read_text(encoding="utf-8")
                )
                mutate(manifest)
                self.write_signed_evidence(manifest)

                decision = self.create()

                self.assertEqual(decision["operational_readiness"], "fail")
                self.assertEqual(decision["human_signoffs"], "fail")
                self.assertEqual(decision["decision"], "no-go")

    def test_pilot_gate_rejects_forged_checks_rollbacks_or_cadence(self):
        mutations = {
            "check missing": lambda payload: payload["checks"].pop(),
            "check reordered": lambda payload: payload["checks"].reverse(),
            "check unknown": lambda payload: payload["checks"].append(
                {"check_id": "unknown", "status": "pass", "summary": "pass"}
            ),
            "check duplicate": lambda payload: payload["checks"].append(
                dict(payload["checks"][0])
            ),
            "check extra field": lambda payload: payload["checks"][0].__setitem__(
                "unexpected", True
            ),
            "check forged status": lambda payload: payload["checks"][0].__setitem__(
                "status", "approved"
            ),
            "check forged summary": lambda payload: payload["checks"][
                0
            ].__setitem__("summary", "trust me"),
            "rollback missing": lambda payload: payload["rollback_triggers"].pop(),
            "rollback extra": lambda payload: payload["rollback_triggers"].append(
                dict(payload["rollback_triggers"][0])
            ),
            "rollback unknown": lambda payload: payload["rollback_triggers"][
                0
            ].__setitem__("trigger_id", "unknown"),
            "rollback severity": lambda payload: payload["rollback_triggers"][
                0
            ].__setitem__("severity", "low"),
            "rollback condition": lambda payload: payload["rollback_triggers"][
                0
            ].__setitem__("condition", "anything"),
            "cadence empty": lambda payload: payload.__setitem__(
                "operator_review_cadence", ""
            ),
            "cadence changed": lambda payload: payload.__setitem__(
                "operator_review_cadence", "weekly"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                pilot = self.pilot_payload()
                mutate(pilot)
                self.assert_pilot_fails_closed(pilot)

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

        self.assertEqual(decision["product_integration"], "fail")
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

        self.assertEqual(decision["product_integration"], "fail")
        self.assertEqual(
            decision["artifacts"]["product_integration_acceptance"][
                "observed_status"
            ],
            "inaccessible",
        )

    def test_only_genuinely_omitted_children_have_blocked_input_status(self):
        file_fields = (
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
        )
        for field in file_fields:
            with self.subTest(field=field):
                paths = self.input_paths()
                paths[field] = None

                decision = self.create(paths)
                metadata = decision["artifacts"][field]

                self.assertEqual(metadata["observed_status"], "missing")
                self.assertEqual(
                    release_decision.child_input_status(metadata), "blocked"
                )

    def test_every_supplied_inaccessible_child_has_fail_input_status(self):
        file_fields = (
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
        )
        for field in file_fields:
            with self.subTest(field=field):
                paths = self.input_paths()
                paths[field] = (self.root / f"absent-{field}").as_posix()

                decision = self.create(paths)
                metadata = decision["artifacts"][field]

                self.assertEqual(metadata["observed_status"], "inaccessible")
                self.assertEqual(release_decision.child_input_status(metadata), "fail")
                self.assertEqual(decision["decision"], "no-go")

    def test_every_supplied_malformed_json_child_has_fail_input_status(self):
        malformed = self.root / "malformed.json"
        malformed.write_bytes(b'{"schema_version":')
        json_fields = (
            "evidence_manifest",
            "evidence_attestation",
            "evidence_attestation_verification",
            "apple_artifact_verification",
            "apple_artifact_reproducibility",
            "apple_release_manifest",
            "pilot_gate_report",
            "pilot_signoff_verification",
            "pilot_signoff_trust_policy",
            "product_integration_acceptance",
        )
        for field in json_fields:
            with self.subTest(field=field):
                paths = self.input_paths()
                paths[field] = malformed.as_posix()

                decision = self.create(paths)
                metadata = decision["artifacts"][field]

                self.assertEqual(metadata["observed_status"], "invalid_json")
                self.assertEqual(release_decision.child_input_status(metadata), "fail")
                self.assertEqual(decision["decision"], "no-go")

    def test_overflowing_json_float_is_invalid_json_and_fails_closed(self):
        malformed = self.root / "overflowing-float.json"
        malformed.write_bytes(b'{"schema_version":"invalid","value":1e999}')
        paths = self.input_paths()
        paths["pilot_gate_report"] = malformed.as_posix()

        decision = self.create(paths)

        self.assertEqual(
            decision["artifacts"]["pilot_gate_report"]["observed_status"],
            "invalid_json",
        )
        self.assertEqual(decision["decision"], "no-go")

    def test_supplied_empty_directory_and_oversize_children_fail(self):
        empty = self.root / "empty.json"
        empty.touch()
        directory = self.root / "directory-input"
        directory.mkdir()
        oversize = self.root / "oversize.json"
        with oversize.open("wb") as handle:
            handle.truncate(release_decision.MAX_ARTIFACT_BYTES + 1)

        for name, path in {
            "empty": empty,
            "directory": directory,
            "oversize": oversize,
        }.items():
            with self.subTest(name=name):
                paths = self.input_paths()
                paths["product_integration_acceptance"] = path.as_posix()

                decision = self.create(paths)
                metadata = decision["artifacts"][
                    "product_integration_acceptance"
                ]

                self.assertEqual(metadata["observed_status"], "inaccessible")
                self.assertEqual(decision["product_integration"], "fail")

    def test_supplied_unstable_child_fails(self):
        original_reader = release_decision.read_stable_regular_file

        def unstable_reader(path: Path, maximum: int, label: str) -> bytes:
            if path == self.product_acceptance:
                raise release_decision.ReleaseDecisionError(
                    "product integration acceptance changed while being read"
                )
            return original_reader(path, maximum, label)

        with mock.patch.object(
            release_decision,
            "read_stable_regular_file",
            side_effect=unstable_reader,
        ):
            decision = self.create()

        metadata = decision["artifacts"]["product_integration_acceptance"]
        self.assertEqual(metadata["observed_status"], "inaccessible")
        self.assertEqual(release_decision.child_input_status(metadata), "fail")
        self.assertEqual(decision["product_integration"], "fail")

    def test_unstable_pilot_signoff_report_or_policy_fails(self):
        original_reader = release_decision.read_stable_regular_file
        for field, target in (
            ("pilot_signoff_verification", self.pilot_signoff_verification),
            ("pilot_signoff_trust_policy", self.pilot_signoff_trust_policy),
        ):
            with self.subTest(field=field):
                def unstable_reader(path: Path, maximum: int, label: str) -> bytes:
                    if path == target:
                        raise release_decision.ReleaseDecisionError(
                            f"{label} changed while being read"
                        )
                    return original_reader(path, maximum, label)

                with mock.patch.object(
                    release_decision,
                    "read_stable_regular_file",
                    side_effect=unstable_reader,
                ):
                    decision = self.create()

                metadata = decision["artifacts"][field]
                self.assertEqual(metadata["observed_status"], "inaccessible")
                self.assertEqual(decision["operational_readiness"], "fail")
                self.assertEqual(decision["human_signoffs"], "fail")

    def test_supplied_malformed_raw_public_key_fails_attestation(self):
        malformed_key = self.root / "malformed-public.pem"
        malformed_key.write_text("not a public key\n", encoding="utf-8")
        paths = self.input_paths()
        paths["evidence_public_key"] = malformed_key.as_posix()

        decision = self.create(paths)

        self.assertEqual(decision["runtime_safety"], "fail")
        self.assertEqual(decision["privacy_security"], "fail")
        self.assertEqual(decision["decision"], "no-go")

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

    def test_validator_rejects_forged_or_nondistinct_pilot_signer_set(self):
        mutations = {
            "set digest": lambda decision: decision.__setitem__(
                "pilot_signoff_signer_spki_set_sha256", "0" * 64
            ),
            "duplicate signer": lambda decision: decision[
                "pilot_signoff_signer_spki_sha256"
            ].__setitem__(
                1, decision["pilot_signoff_signer_spki_sha256"][0]
            ),
            "evidence signer reused": lambda decision: decision[
                "pilot_signoff_signer_spki_sha256"
            ].__setitem__(0, decision["evidence_signer_spki_sha256"]),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                decision = self.create()
                mutate(decision)
                with self.assertRaisesRegex(
                    release_decision.ReleaseDecisionError, "identity"
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
        self.assertEqual(
            report["schema_version"],
            "aura.release_decision_attestation_verification.v3",
        )
        self.assertEqual(report["decision"], "go")
        self.assertEqual(report["source_revision"], self.source_revision)
        self.assertEqual(report["artifact_revision"], self.artifact_revision)
        self.assertEqual(report["release_revision"], self.release_revision)
        self.assertEqual(
            report["pilot_signoff_signer_spki_sha256"],
            json.loads(self.decision_path.read_text(encoding="utf-8"))[
                "pilot_signoff_signer_spki_sha256"
            ],
        )

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

    def test_sign_reverifies_pilot_signatures_and_exact_report(self):
        report = json.loads(
            self.pilot_signoff_verification.read_text(encoding="utf-8")
        )
        report["attestations"][0]["signature_base64"] = "A" * 88
        self.write(self.pilot_signoff_verification, report)

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

    def test_pilot_signer_cannot_also_be_release_operator(self):
        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "pilot signoff keys"
        ):
            release_decision.sign_decision(
                self.decision_path,
                self.pilot_signoff_private_keys[0],
                "release-operator-2026",
                self.input_paths(),
            )

    def test_standalone_verifier_rejects_pilot_signer_as_operator(self):
        pilot_public = self.root / "pilot-release-operator-public.pem"
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                self.pilot_signoff_private_keys[0].as_posix(),
                "-pubout",
                "-out",
                pilot_public.as_posix(),
            ],
            check=True,
            capture_output=True,
        )
        decision = json.loads(self.decision_path.read_text(encoding="utf-8"))
        pilot_spki = sha256(
            release_decision.crypto_support.public_key_der_from_public(pilot_public)
        ).hexdigest()
        self.assertIn(pilot_spki, decision["pilot_signoff_signer_spki_sha256"])
        attestation = {
            "schema_version": release_decision.ATTESTATION_SCHEMA_VERSION,
            "signature_algorithm": "Ed25519",
            "key_id": "release-operator-2026",
            "decision_sha256": sha256(self.decision_path.read_bytes()).hexdigest(),
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
            "public_key_spki_sha256": pilot_spki,
            "signature_base64": base64.b64encode(b"\x00" * 64).decode("ascii"),
        }
        self.write(self.attestation_path, attestation)

        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "pilot signoff keys"
        ):
            release_decision.verify_decision(
                self.decision_path, self.attestation_path, pilot_public
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

    def test_cli_protects_pilot_signoff_inputs_from_output_alias(self):
        for argument, path in (
            ("--pilot-signoff-verification", self.pilot_signoff_verification),
            ("--pilot-signoff-trust-policy", self.pilot_signoff_trust_policy),
        ):
            with self.subTest(argument=argument):
                result = subprocess.run(
                    [
                        "python3",
                        "ci/release_decision.py",
                        "create",
                        "--candidate-revision",
                        self.revision,
                        "--runtime-version",
                        self.runtime_version,
                        argument,
                        path.as_posix(),
                        "--output",
                        path.as_posix(),
                    ],
                    cwd=Path(__file__).resolve().parents[1],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("must not overwrite", result.stderr)

    @unittest.skipIf(os.name == "nt", "hard-link semantics differ on Windows")
    def test_cli_rejects_hard_link_aliases_of_pilot_signoff_inputs(self):
        for index, (argument, path) in enumerate(
            (
                ("--pilot-signoff-verification", self.pilot_signoff_verification),
                ("--pilot-signoff-trust-policy", self.pilot_signoff_trust_policy),
            )
        ):
            with self.subTest(argument=argument):
                output = self.root / f"pilot-signoff-hardlink-{index}.json"
                os.link(path, output)
                result = subprocess.run(
                    [
                        "python3",
                        "ci/release_decision.py",
                        "create",
                        "--candidate-revision",
                        self.revision,
                        "--runtime-version",
                        self.runtime_version,
                        argument,
                        path.as_posix(),
                        "--output",
                        output.as_posix(),
                    ],
                    cwd=Path(__file__).resolve().parents[1],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("alias an input", result.stderr)

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
