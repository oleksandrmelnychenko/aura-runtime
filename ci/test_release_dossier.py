import base64
import json
import os
import shutil
import subprocess
import unittest
from hashlib import sha256
from pathlib import Path
from unittest import mock

from ci import release_decision, release_dossier
from ci.test_release_decision import ReleaseDecisionFixture


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class ReleaseDossierTests(ReleaseDecisionFixture):
    release_key_id = "release-operator-key"

    def setUp(self):
        super().setUp()
        self.source_root = self.root / "release-input"
        self.preliminary = self.root / "preliminary-dossier"
        self.final = self.root / "final-dossier"
        self.release_private_key = self.root / "release-private.pem"
        self.release_public_key = self.root / "release-public.pem"
        self.release_attestation = self.root / "release-attestation.json"
        self._copy_fixed_source_layout()
        self._generate_release_key()

    def _copy_fixed_source_layout(self) -> None:
        sources = {
            release_dossier.SOURCE_PATHS["evidence_manifest"]: self.evidence_manifest,
            release_dossier.SOURCE_PATHS[
                "evidence_attestation"
            ]: self.evidence_attestation,
            release_dossier.SOURCE_PATHS[
                "evidence_attestation_verification"
            ]: self.evidence_verification,
            release_dossier.SOURCE_PATHS[
                "apple_artifact_verification"
            ]: self.apple_verification,
            release_dossier.SOURCE_PATHS[
                "apple_artifact_reproducibility"
            ]: self.apple_reproducibility,
            release_dossier.SOURCE_PATHS[
                "apple_release_manifest"
            ]: self.apple_manifest,
            release_dossier.SOURCE_PATHS["pilot_gate_report"]: self.pilot_gate,
            release_dossier.SOURCE_PATHS[
                "pilot_signoff_verification"
            ]: self.pilot_signoff_verification,
            release_dossier.SOURCE_PATHS[
                "product_integration_acceptance"
            ]: self.product_acceptance,
        }
        for relative, source in sources.items():
            target = self.source_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

    def _generate_release_key(self) -> None:
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "Ed25519",
                "-out",
                self.release_private_key.as_posix(),
            ],
            check=True,
            capture_output=True,
        )
        os.chmod(self.release_private_key, 0o600)
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                self.release_private_key.as_posix(),
                "-pubout",
                "-out",
                self.release_public_key.as_posix(),
            ],
            check=True,
            capture_output=True,
        )

    def _assemble(self) -> dict:
        return release_dossier.assemble_dossier(
            self.source_root,
            self.preliminary,
            self.revision,
            self.runtime_version,
            self.evidence_public_key,
            self.expected_evidence_key_id,
            self.pilot_signoff_trust_policy,
            self.expected_pilot_signoff_trust_policy_sha256,
        )

    def _bundle_evidence_paths(self) -> dict[str, str | None]:
        return {
            field: (self.preliminary / relative).as_posix()
            for field, relative in release_dossier.SOURCE_PATHS.items()
        } | {
            "evidence_public_key": self.evidence_public_key.as_posix(),
            "expected_evidence_key_id": self.expected_evidence_key_id,
            "pilot_signoff_trust_policy": (
                self.pilot_signoff_trust_policy.as_posix()
            ),
            "expected_pilot_signoff_trust_policy_sha256": (
                self.expected_pilot_signoff_trust_policy_sha256
            ),
        }

    def _sign_preliminary_decision(self) -> dict:
        attestation = release_decision.sign_decision(
            self.preliminary / release_dossier.DECISION_PATH,
            self.release_private_key,
            self.release_key_id,
            self._bundle_evidence_paths(),
        )
        release_decision.crypto_support.write_json_atomic(
            self.release_attestation, attestation
        )
        return attestation

    def _finalize(self) -> dict:
        return release_dossier.finalize_dossier(
            self.preliminary,
            self.final,
            self.release_attestation,
            self.evidence_public_key,
            self.expected_evidence_key_id,
            self.release_public_key,
            self.release_key_id,
            self.pilot_signoff_trust_policy,
            self.expected_pilot_signoff_trust_policy_sha256,
        )

    def _write_same_key_release_attestation(self) -> dict:
        decision_path = self.preliminary / release_dossier.DECISION_PATH
        decision_raw, decision = release_decision.load_decision(decision_path)
        public_der = release_decision.crypto_support.public_key_der_from_public(
            self.evidence_public_key
        )
        attestation = {
            "schema_version": release_decision.ATTESTATION_SCHEMA_VERSION,
            "signature_algorithm": release_decision.SIGNATURE_ALGORITHM,
            "key_id": "same-role-key",
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
            "public_key_spki_sha256": sha256(public_der).hexdigest(),
        }
        claims = self.root / "same-key-claims.bin"
        signature = self.root / "same-key-signature.bin"
        claims.write_bytes(release_decision.canonical_attestation_claims(attestation))
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                self.evidence_private_key.as_posix(),
                "-in",
                claims.as_posix(),
                "-out",
                signature.as_posix(),
            ],
            check=True,
            capture_output=True,
        )
        attestation["signature_base64"] = base64.b64encode(
            signature.read_bytes()
        ).decode("ascii")
        release_decision.crypto_support.write_json_atomic(
            self.release_attestation, attestation
        )
        return attestation

    def test_missing_source_is_a_valid_blocked_no_go_dossier(self):
        shutil.rmtree(self.source_root)
        self.source_root.mkdir()

        dossier = release_dossier.assemble_dossier(
            self.source_root,
            self.preliminary,
            self.revision,
            self.runtime_version,
            None,
            None,
        )

        self.assertEqual(dossier["status"], "blocked")
        self.assertEqual(dossier["authorization"], "blocked")
        self.assertEqual(dossier["release_decision"], "no-go")
        entry = next(
            item
            for item in dossier["inventory"]
            if item["path"] == release_dossier.SOURCE_PATHS["pilot_gate_report"]
        )
        self.assertEqual(
            entry,
            {
                "path": release_dossier.SOURCE_PATHS["pilot_gate_report"],
                "required": True,
                "present": False,
                "bytes": None,
                "sha256": None,
            },
        )
        report = release_dossier.verify_dossier(
            self.preliminary,
            None,
            None,
        )
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["release_decision"], "no-go")

    def test_complete_go_can_be_signed_externally_and_finalized(self):
        preliminary = self._assemble()
        self.assertEqual(preliminary["release_decision"], "go")
        self.assertEqual(preliminary["status"], "blocked")
        self._sign_preliminary_decision()

        dossier = self._finalize()
        report = release_dossier.verify_dossier(
            self.final,
            self.evidence_public_key,
            self.expected_evidence_key_id,
            self.release_public_key,
            self.release_key_id,
            self.pilot_signoff_trust_policy,
            self.expected_pilot_signoff_trust_policy_sha256,
        )

        self.assertEqual(dossier["status"], "pass")
        self.assertEqual(dossier["authorization"], "go")
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["authorization"], "go")
        self.assertTrue(report["release_operator_attestation_verified"])
        self.assertTrue(report["pilot_signoff_trust_policy_verified"])
        self.assertEqual(len(release_dossier.FINAL_FILES), 13)
        self.assertEqual(
            {
                path.relative_to(self.final).as_posix()
                for path in self.final.rglob("*")
                if path.is_file()
            },
            set(release_dossier.FINAL_FILES),
        )
        self.assertTrue(
            (
                self.final
                / release_dossier.SOURCE_PATHS["pilot_signoff_verification"]
            ).is_file()
        )
        self.assertEqual(len(dossier["inventory"]), 12)
        self.assertFalse(any("key" in path.name for path in self.final.rglob("*")))
        self.assertFalse(
            any(
                "trust-policy" in path.relative_to(self.final).as_posix()
                for path in self.final.rglob("*")
            )
        )
        pilot_trust = dossier["pilot_signoff_trust"]
        self.assertTrue(pilot_trust["external_trust_policy_required"])
        self.assertFalse(pilot_trust["trust_policy_embedded"])
        self.assertTrue(pilot_trust["trust_policy_supplied"])
        self.assertEqual(
            pilot_trust["expected_trust_policy_sha256"],
            self.expected_pilot_signoff_trust_policy_sha256,
        )
        self.assertEqual(
            pilot_trust["verification_report_trust_policy_sha256"],
            self.expected_pilot_signoff_trust_policy_sha256,
        )
        self.assertEqual(
            len(pilot_trust["verification_report_signer_spki_sha256"]), 4
        )
        self.assertRegex(
            pilot_trust["verification_report_signer_spki_set_sha256"],
            r"^[0-9a-f]{64}$",
        )
        assurance = dossier["assurance"]
        self.assertTrue(assurance["terminal_unsigned_index"])
        self.assertFalse(assurance["index_self_hash_included"])
        self.assertFalse(assurance["public_keys_embedded"])
        self.assertFalse(assurance["independent_reproduction_proven_by_dossier"])
        self.assertFalse(assurance["compiler_trust_proven_by_dossier"])
        self.assertFalse(assurance["candidate_blind_build_proven_by_dossier"])
        self.assertFalse(assurance["hermetic_build_proven_by_dossier"])
        self.assertFalse(assurance["pilot_signoffs_generated"])
        self.assertFalse(assurance["product_acceptance_generated"])
        decision = json.loads(
            (self.final / release_dossier.DECISION_PATH).read_text(encoding="utf-8")
        )
        self.assertEqual(dossier["generated_at_utc"], decision["generated_at_utc"])
        self.assertEqual(
            preliminary["generated_at_utc"], decision["generated_at_utc"]
        )

    def test_malformed_supplied_artifact_produces_fail_not_blocked(self):
        pilot = self.source_root / release_dossier.SOURCE_PATHS["pilot_gate_report"]
        pilot.write_text('{"schema_version":NaN}\n', encoding="utf-8")

        dossier = self._assemble()

        self.assertEqual(dossier["status"], "fail")
        self.assertEqual(dossier["authorization"], "blocked")
        self.assertEqual(dossier["release_decision"], "no-go")
        report = release_dossier.verify_dossier(
            self.preliminary,
            self.evidence_public_key,
            self.expected_evidence_key_id,
            pilot_signoff_trust_policy_path=self.pilot_signoff_trust_policy,
            expected_pilot_signoff_trust_policy_sha256=(
                self.expected_pilot_signoff_trust_policy_sha256
            ),
        )
        self.assertEqual(report["status"], "fail")

    def test_supplied_invalid_dominates_a_different_missing_input(self):
        pilot = self.source_root / release_dossier.SOURCE_PATHS["pilot_gate_report"]
        pilot.write_text(
            json.dumps({"schema_version": "unsupported", "overall_status": "pass"})
            + "\n",
            encoding="utf-8",
        )
        missing = self.source_root / release_dossier.SOURCE_PATHS[
            "apple_artifact_verification"
        ]
        missing.unlink()

        dossier = self._assemble()

        self.assertEqual(dossier["status"], "fail")
        self.assertEqual(dossier["authorization"], "blocked")

    def test_supplied_missing_public_key_is_fail_not_absent(self):
        missing_key = self.root / "provided-but-missing.pem"

        with self.assertRaisesRegex(
            release_dossier.DossierError, "supplied.*missing"
        ):
            release_dossier.assemble_dossier(
                self.source_root,
                self.preliminary,
                self.revision,
                self.runtime_version,
                missing_key,
                self.expected_evidence_key_id,
            )

        self.assertFalse(self.preliminary.exists())

    def test_preliminary_verify_reads_a_supplied_key_even_when_recorded_absent(self):
        release_dossier.assemble_dossier(
            self.source_root,
            self.preliminary,
            self.revision,
            self.runtime_version,
            None,
            None,
        )

        with self.assertRaisesRegex(
            release_dossier.DossierError, "supplied.*missing"
        ):
            release_dossier.verify_dossier(
                self.preliminary,
                self.root / "provided-but-missing.pem",
                None,
            )

        malformed = self.root / "provided-malformed.pem"
        malformed.write_text("not a public key\n", encoding="utf-8")
        with self.assertRaises(
            (release_dossier.DossierError, release_decision.ReleaseDecisionError)
        ):
            release_dossier.verify_dossier(
                self.preliminary,
                malformed,
                None,
            )

    def test_final_child_mutation_is_rejected(self):
        self._assemble()
        self._sign_preliminary_decision()
        self._finalize()
        pilot = self.final / release_dossier.SOURCE_PATHS["pilot_gate_report"]
        payload = json.loads(pilot.read_text(encoding="utf-8"))
        payload["overall_status"] = "fail"
        pilot.write_text(json.dumps(payload) + "\n", encoding="utf-8")

        with self.assertRaises(
            (release_dossier.DossierError, release_decision.ReleaseDecisionError)
        ):
            release_dossier.verify_dossier(
                self.final,
                self.evidence_public_key,
                self.expected_evidence_key_id,
                self.release_public_key,
                self.release_key_id,
                self.pilot_signoff_trust_policy,
                self.expected_pilot_signoff_trust_policy_sha256,
            )

    def test_index_mutation_is_rejected(self):
        self._assemble()
        index = self.preliminary / release_dossier.INDEX_PATH
        payload = json.loads(index.read_text(encoding="utf-8"))
        payload["assurance"]["pilot_signoffs_generated"] = True
        index.write_text(json.dumps(payload) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(
            release_dossier.DossierError, "assurance boundaries|does not exactly match"
        ):
            release_dossier.verify_dossier(
                self.preliminary,
                self.evidence_public_key,
                self.expected_evidence_key_id,
            )

    def test_boolean_to_integer_index_mutation_is_rejected(self):
        self._assemble()
        index = self.preliminary / release_dossier.INDEX_PATH
        payload = json.loads(index.read_text(encoding="utf-8"))
        payload["assurance"]["terminal_unsigned_index"] = 1
        index.write_text(json.dumps(payload) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(release_dossier.DossierError, "assurance"):
            release_dossier.verify_dossier(
                self.preliminary,
                self.evidence_public_key,
                self.expected_evidence_key_id,
            )

    def test_overflowing_float_in_index_is_rejected(self):
        self._assemble()
        index = self.preliminary / release_dossier.INDEX_PATH
        serialized = index.read_text(encoding="utf-8").rstrip()
        index.write_text(
            serialized[:-1] + ',"overflow":1e999}\n', encoding="utf-8"
        )

        with self.assertRaisesRegex(release_dossier.DossierError, "invalid JSON"):
            release_dossier.verify_dossier(
                self.preliminary,
                self.evidence_public_key,
                self.expected_evidence_key_id,
            )

    def test_inventory_cannot_include_the_index_itself(self):
        self._assemble()
        index = self.preliminary / release_dossier.INDEX_PATH
        payload = json.loads(index.read_text(encoding="utf-8"))
        payload["inventory"].append(
            {
                "path": release_dossier.INDEX_PATH,
                "required": True,
                "present": True,
                "bytes": 1,
                "sha256": "0" * 64,
            }
        )
        index.write_text(json.dumps(payload) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(release_dossier.DossierError, "cyclic"):
            release_dossier.verify_dossier(
                self.preliminary,
                self.evidence_public_key,
                self.expected_evidence_key_id,
            )

    def test_extra_file_is_rejected(self):
        (self.source_root / "latest.json").write_text("{}\n", encoding="utf-8")

        with self.assertRaisesRegex(release_dossier.DossierError, "extra path"):
            self._assemble()

    def test_extra_file_added_during_snapshot_is_rejected(self):
        original = release_dossier._read_descriptor
        injected = False

        def inject_after_read(descriptor, maximum, label):
            nonlocal injected
            raw = original(descriptor, maximum, label)
            if not injected:
                injected = True
                (self.source_root / "late-extra.json").write_text(
                    "{}\n", encoding="utf-8"
                )
            return raw

        with mock.patch.object(
            release_dossier, "_read_descriptor", side_effect=inject_after_read
        ):
            with self.assertRaisesRegex(release_dossier.DossierError, "changed"):
                self._assemble()

    @unittest.skipIf(os.name == "nt", "POSIX symbolic-link policy")
    def test_symlink_input_is_rejected(self):
        pilot = self.source_root / release_dossier.SOURCE_PATHS["pilot_gate_report"]
        pilot.unlink()
        pilot.symlink_to(self.pilot_gate)

        with self.assertRaisesRegex(release_dossier.DossierError, "regular file"):
            self._assemble()

    @unittest.skipIf(os.name == "nt", "POSIX FIFO policy")
    def test_fifo_input_is_rejected_without_blocking(self):
        pilot = self.source_root / release_dossier.SOURCE_PATHS["pilot_gate_report"]
        pilot.unlink()
        os.mkfifo(pilot)

        with self.assertRaisesRegex(release_dossier.DossierError, "regular file"):
            self._assemble()

    @unittest.skipIf(os.name == "nt", "POSIX hard-link policy")
    def test_hard_link_input_is_rejected(self):
        pilot = self.source_root / release_dossier.SOURCE_PATHS["pilot_gate_report"]
        pilot.unlink()
        os.link(self.pilot_gate, pilot)

        with self.assertRaisesRegex(release_dossier.DossierError, "hard link"):
            self._assemble()

    def test_output_cannot_alias_or_contain_an_input(self):
        with self.assertRaisesRegex(release_dossier.DossierError, "alias"):
            release_dossier.assemble_dossier(
                self.source_root,
                self.source_root,
                self.revision,
                self.runtime_version,
                self.evidence_public_key,
                self.expected_evidence_key_id,
            )
        nested_output = self.source_root / "new-dossier"
        with self.assertRaisesRegex(release_dossier.DossierError, "alias"):
            release_dossier.assemble_dossier(
                self.source_root,
                nested_output,
                self.revision,
                self.runtime_version,
                self.evidence_public_key,
                self.expected_evidence_key_id,
            )

    @unittest.skipIf(os.name == "nt", "POSIX symlink-parent policy")
    def test_symlink_output_parent_is_rejected(self):
        real_parent = self.root / "real-output-parent"
        real_parent.mkdir()
        symbolic_parent = self.root / "output-parent-link"
        symbolic_parent.symlink_to(real_parent, target_is_directory=True)

        with self.assertRaisesRegex(release_dossier.DossierError, "non-symlink"):
            release_dossier.assemble_dossier(
                self.source_root,
                symbolic_parent / "dossier",
                self.revision,
                self.runtime_version,
                self.evidence_public_key,
                self.expected_evidence_key_id,
            )

        self.assertFalse((real_parent / "dossier").exists())

    @unittest.skipIf(os.name == "nt", "POSIX directory-descriptor policy")
    def test_output_parent_swap_is_detected_without_redirecting_publication(self):
        output_parent = self.root / "output-parent"
        moved_parent = self.root / "moved-output-parent"
        output_parent.mkdir()
        original = release_dossier._write_private_file_at
        swapped = False

        def swap_parent_after_write(descriptor, relative, raw):
            nonlocal swapped
            original(descriptor, relative, raw)
            if not swapped:
                swapped = True
                output_parent.rename(moved_parent)
                output_parent.mkdir()

        with mock.patch.object(
            release_dossier,
            "_write_private_file_at",
            side_effect=swap_parent_after_write,
        ):
            with self.assertRaisesRegex(release_dossier.DossierError, "parent changed"):
                release_dossier.assemble_dossier(
                    self.source_root,
                    output_parent / "dossier",
                    self.revision,
                    self.runtime_version,
                    self.evidence_public_key,
                    self.expected_evidence_key_id,
                )

        self.assertFalse((output_parent / "dossier").exists())
        self.assertFalse((moved_parent / "dossier").exists())

    def test_post_publish_error_never_deletes_a_swapped_bundle_target(self):
        output = self.root / "published-dossier"
        escaped = self.root / "escaped-dossier"
        original = release_dossier._assert_parent_still_bound
        checks = 0

        def swap_after_publish(descriptor, parent_path):
            nonlocal checks
            checks += 1
            if checks == 2:
                output.rename(escaped)
                output.mkdir()
                (output / "attacker-marker").write_text(
                    "do not delete\n", encoding="utf-8"
                )
                raise release_dossier.DossierError("fixture post-publish failure")
            return original(descriptor, parent_path)

        with mock.patch.object(
            release_dossier,
            "_assert_parent_still_bound",
            side_effect=swap_after_publish,
        ):
            with self.assertRaisesRegex(
                release_dossier.DossierError, "post-publish"
            ):
                release_dossier.publish_bundle(
                    output,
                    {"evidence/item.json": b"{}\n"},
                    [],
                )

        self.assertEqual(
            (output / "attacker-marker").read_text(encoding="utf-8"),
            "do not delete\n",
        )
        self.assertEqual((escaped / "evidence/item.json").read_bytes(), b"{}\n")

    def test_bundle_publish_rejects_a_swapped_staging_inode(self):
        output = self.root / "published-dossier"
        escaped = self.root / "verified-staging-dossier"
        original = release_dossier._rename_noreplace_at

        def swap_staging(parent_descriptor, source_name, target_name):
            os.rename(
                source_name,
                escaped.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            os.mkdir(source_name, mode=0o700, dir_fd=parent_descriptor)
            replacement = os.open(
                source_name,
                release_dossier._open_flags(directory=True),
                dir_fd=parent_descriptor,
            )
            try:
                marker = os.open(
                    "attacker-marker",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=replacement,
                )
                os.write(marker, b"do not delete\n")
                os.close(marker)
            finally:
                os.close(replacement)
            original(parent_descriptor, source_name, target_name)

        with mock.patch.object(
            release_dossier,
            "_rename_noreplace_at",
            side_effect=swap_staging,
        ):
            with self.assertRaisesRegex(
                release_dossier.DossierError,
                "replaced during publication",
            ):
                release_dossier.publish_bundle(
                    output,
                    {"evidence/item.json": b"verified\n"},
                    [],
                )

        self.assertEqual(
            (output / "attacker-marker").read_bytes(), b"do not delete\n"
        )
        self.assertEqual(
            (escaped / "evidence/item.json").read_bytes(), b"verified\n"
        )

    def test_prepublication_error_never_deletes_swapped_staging_entries(self):
        output = self.root / "failed-dossier"
        parked = self.root / "parked-item.json"
        original = release_dossier._write_private_file_at

        def swap_staging_entry(descriptor, relative, raw):
            original(descriptor, relative, raw)
            if relative == "evidence/item.json":
                staging = next(self.root.glob(".failed-dossier.*"))
                item = staging / relative
                item.rename(parked)
                item.write_bytes(b"attacker replacement\n")
                raise release_dossier.DossierError("fixture staging failure")

        with mock.patch.object(
            release_dossier,
            "_write_private_file_at",
            side_effect=swap_staging_entry,
        ):
            with self.assertRaisesRegex(
                release_dossier.DossierError, "staging failure"
            ):
                release_dossier.publish_bundle(
                    output,
                    {"evidence/item.json": b"verified\n"},
                    [],
                )

        staging = next(self.root.glob(".failed-dossier.*"))
        self.assertEqual(
            (staging / "evidence/item.json").read_bytes(),
            b"attacker replacement\n",
        )
        self.assertEqual(parked.read_bytes(), b"verified\n")
        self.assertFalse(output.exists())

    def test_existing_output_is_never_overwritten(self):
        self.preliminary.mkdir()
        marker = self.preliminary / "keep"
        marker.write_text("owned by caller\n", encoding="utf-8")

        with self.assertRaisesRegex(release_dossier.DossierError, "fresh"):
            self._assemble()

        self.assertEqual(marker.read_text(encoding="utf-8"), "owned by caller\n")

    def test_finalization_requires_external_keys_and_attestation(self):
        self._assemble()

        with self.assertRaises(release_dossier.DossierBlocked):
            release_dossier.finalize_dossier(
                self.preliminary,
                self.final,
                None,
                self.evidence_public_key,
                self.expected_evidence_key_id,
                self.release_public_key,
                self.release_key_id,
            )

    def test_finalization_and_final_verification_require_external_pilot_trust(self):
        self._assemble()
        self._sign_preliminary_decision()

        with self.assertRaisesRegex(
            release_dossier.DossierBlocked, "pilot signoff trust-policy pin"
        ):
            release_dossier.finalize_dossier(
                self.preliminary,
                self.final,
                self.release_attestation,
                self.evidence_public_key,
                self.expected_evidence_key_id,
                self.release_public_key,
                self.release_key_id,
            )

        self._finalize()
        with self.assertRaisesRegex(
            release_dossier.DossierBlocked, "pilot signoff trust-policy pin"
        ):
            release_dossier.verify_dossier(
                self.final,
                self.evidence_public_key,
                self.expected_evidence_key_id,
                self.release_public_key,
                self.release_key_id,
            )

    def test_supplied_missing_or_wrong_pilot_trust_policy_fails(self):
        self._assemble()
        self._sign_preliminary_decision()

        with self.assertRaisesRegex(release_dossier.DossierError, "supplied.*missing"):
            release_dossier.finalize_dossier(
                self.preliminary,
                self.final,
                self.release_attestation,
                self.evidence_public_key,
                self.expected_evidence_key_id,
                self.release_public_key,
                self.release_key_id,
                self.root / "provided-but-missing-policy.json",
                self.expected_pilot_signoff_trust_policy_sha256,
            )
        with self.assertRaises(release_dossier.DossierError):
            release_dossier.finalize_dossier(
                self.preliminary,
                self.final,
                self.release_attestation,
                self.evidence_public_key,
                self.expected_evidence_key_id,
                self.release_public_key,
                self.release_key_id,
                self.pilot_signoff_trust_policy,
                "0" * 64,
            )
        self.assertFalse(self.final.exists())

    def test_pilot_verification_leaf_mutation_is_rejected(self):
        self._assemble()
        self._sign_preliminary_decision()
        self._finalize()
        verification_path = (
            self.final
            / release_dossier.SOURCE_PATHS["pilot_signoff_verification"]
        )
        report = json.loads(verification_path.read_text(encoding="utf-8"))
        report["attestations"][0]["signature_base64"] = "AA=="
        verification_path.write_text(json.dumps(report) + "\n", encoding="utf-8")

        with self.assertRaises(
            (release_dossier.DossierError, release_decision.ReleaseDecisionError)
        ):
            release_dossier.verify_dossier(
                self.final,
                self.evidence_public_key,
                self.expected_evidence_key_id,
                self.release_public_key,
                self.release_key_id,
                self.pilot_signoff_trust_policy,
                self.expected_pilot_signoff_trust_policy_sha256,
            )

    def test_report_output_cannot_alias_external_pilot_trust_policy(self):
        with self.assertRaisesRegex(release_dossier.DossierError, "alias"):
            release_dossier._publish_report(
                self.pilot_signoff_trust_policy,
                b"{}\n",
                [self.pilot_signoff_trust_policy],
            )

    def test_supplied_missing_release_key_fails_finalization(self):
        self._assemble()
        self._sign_preliminary_decision()
        supplied_missing_key = self.root / "missing-release-public.pem"

        with self.assertRaisesRegex(
            release_dossier.DossierError, "supplied.*missing"
        ):
            release_dossier.finalize_dossier(
                self.preliminary,
                self.final,
                self.release_attestation,
                self.evidence_public_key,
                self.expected_evidence_key_id,
                supplied_missing_key,
                self.release_key_id,
                self.pilot_signoff_trust_policy,
                self.expected_pilot_signoff_trust_policy_sha256,
            )

        self.assertFalse(self.final.exists())

    def test_same_evidence_and_release_key_is_rejected_by_authority(self):
        self._assemble()

        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "must differ"
        ):
            release_decision.sign_decision(
                self.preliminary / release_dossier.DECISION_PATH,
                self.evidence_private_key,
                "same-role-key",
                self._bundle_evidence_paths(),
            )

    def test_finalize_rejects_a_direct_same_spki_attestation(self):
        self._assemble()
        self._write_same_key_release_attestation()

        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "must differ"
        ):
            release_dossier.finalize_dossier(
                self.preliminary,
                self.final,
                self.release_attestation,
                self.evidence_public_key,
                self.expected_evidence_key_id,
                self.evidence_public_key,
                "same-role-key",
                self.pilot_signoff_trust_policy,
                self.expected_pilot_signoff_trust_policy_sha256,
            )

    def test_verify_rejects_a_direct_same_spki_attestation(self):
        self._assemble()
        self._sign_preliminary_decision()
        self._finalize()
        same_key_attestation = self._write_same_key_release_attestation()
        release_decision.crypto_support.write_json_atomic(
            self.final / release_dossier.RELEASE_ATTESTATION_PATH,
            same_key_attestation,
        )

        with self.assertRaisesRegex(
            release_decision.ReleaseDecisionError, "must differ"
        ):
            release_dossier.verify_dossier(
                self.final,
                self.evidence_public_key,
                self.expected_evidence_key_id,
                self.evidence_public_key,
                "same-role-key",
                self.pilot_signoff_trust_policy,
                self.expected_pilot_signoff_trust_policy_sha256,
            )

    def test_verify_report_cannot_be_written_inside_bundle(self):
        self._assemble()
        report = release_dossier.verify_dossier(
            self.preliminary,
            self.evidence_public_key,
            self.expected_evidence_key_id,
            pilot_signoff_trust_policy_path=self.pilot_signoff_trust_policy,
            expected_pilot_signoff_trust_policy_sha256=(
                self.expected_pilot_signoff_trust_policy_sha256
            ),
        )
        with self.assertRaisesRegex(release_dossier.DossierError, "alias"):
            release_dossier._publish_report(
                self.preliminary / "verification.json",
                release_dossier._json_bytes(report),
                [self.preliminary],
            )

    def test_verify_report_is_atomically_written_to_a_fresh_file(self):
        self._assemble()
        report = release_dossier.verify_dossier(
            self.preliminary,
            self.evidence_public_key,
            self.expected_evidence_key_id,
            pilot_signoff_trust_policy_path=self.pilot_signoff_trust_policy,
            expected_pilot_signoff_trust_policy_sha256=(
                self.expected_pilot_signoff_trust_policy_sha256
            ),
        )
        output = self.root / "verification.json"

        release_dossier._publish_report(
            output,
            release_dossier._json_bytes(report),
            [self.preliminary],
        )

        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)
        self.assertEqual(output.stat().st_nlink, 1)

    @unittest.skipIf(os.name == "nt", "POSIX directory-descriptor policy")
    def test_report_parent_swap_is_detected_without_redirecting_publication(self):
        output_parent = self.root / "report-output-parent"
        moved_parent = self.root / "moved-report-output-parent"
        output_parent.mkdir()
        original = release_dossier._assert_parent_still_bound
        swapped = False

        def swap_before_binding_check(descriptor, parent_path):
            nonlocal swapped
            if not swapped:
                swapped = True
                output_parent.rename(moved_parent)
                output_parent.mkdir()
            return original(descriptor, parent_path)

        with mock.patch.object(
            release_dossier,
            "_assert_parent_still_bound",
            side_effect=swap_before_binding_check,
        ):
            with self.assertRaisesRegex(release_dossier.DossierError, "parent changed"):
                release_dossier._publish_report(
                    output_parent / "verification.json",
                    b"{}\n",
                    [],
                )

        self.assertFalse((output_parent / "verification.json").exists())
        self.assertFalse((moved_parent / "verification.json").exists())

    def test_post_publish_error_never_deletes_a_swapped_report_target(self):
        output = self.root / "verification.json"
        escaped = self.root / "escaped-verification.json"
        original = release_dossier._assert_parent_still_bound
        checks = 0

        def swap_after_publish(descriptor, parent_path):
            nonlocal checks
            checks += 1
            if checks == 2:
                output.rename(escaped)
                output.write_bytes(b"attacker-owned\n")
                raise release_dossier.DossierError("fixture post-publish failure")
            return original(descriptor, parent_path)

        with mock.patch.object(
            release_dossier,
            "_assert_parent_still_bound",
            side_effect=swap_after_publish,
        ):
            with self.assertRaisesRegex(
                release_dossier.DossierError, "post-publish"
            ):
                release_dossier._publish_report(output, b"verified\n", [])

        self.assertEqual(output.read_bytes(), b"attacker-owned\n")
        self.assertEqual(escaped.read_bytes(), b"verified\n")

    def test_report_publish_rejects_a_swapped_staging_inode(self):
        output = self.root / "verification.json"
        escaped = self.root / "verified-staging.json"
        original = release_dossier._rename_noreplace_at

        def swap_staging(parent_descriptor, source_name, target_name):
            os.rename(
                source_name,
                escaped.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            replacement = os.open(
                source_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_descriptor,
            )
            os.write(replacement, b"attacker replacement\n")
            os.close(replacement)
            original(parent_descriptor, source_name, target_name)

        with mock.patch.object(
            release_dossier,
            "_rename_noreplace_at",
            side_effect=swap_staging,
        ):
            with self.assertRaisesRegex(
                release_dossier.DossierError,
                "replaced during publication",
            ):
                release_dossier._publish_report(output, b"verified\n", [])

        self.assertEqual(output.read_bytes(), b"attacker replacement\n")
        self.assertEqual(escaped.read_bytes(), b"verified\n")


if __name__ == "__main__":
    unittest.main()
