import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from ci import evidence_attestation, temporal_study_attestation


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class TemporalStudyAttestationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private_key = self.root / "private.pem"
        self.public_key = self.root / "public.pem"
        self.other_private_key = self.root / "other-private.pem"
        self.other_public_key = self.root / "other-public.pem"
        self.commitment = self.root / "temporal-study-commitment.json"
        self.attestation = self.root / "temporal-study-attestation.json"
        for private_key, public_key in (
            (self.private_key, self.public_key),
            (self.other_private_key, self.other_public_key),
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
            subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    private_key.as_posix(),
                    "-pubout",
                    "-out",
                    public_key.as_posix(),
                ],
                check=True,
                capture_output=True,
            )
        self.commitment_payload = {
            "schema_version": "aura.military.temporal_study_commitment.v1",
            "study_id": "external_temporal_study_2026",
            "registered_at_ms": 1780000000000,
            "corpus_class": "embargoed_external",
            "preregistration_canonical_sha256": "a" * 64,
            "dataset_id": "external_temporal_holdout_2026",
            "corpus_sha256": "b" * 64,
            "packet_id": "temporal_round_2026_01",
            "packet_canonical_sha256": "c" * 64,
            "case_count": 37,
            "minimum_reviewers_per_case": 2,
            "minimum_acceptable_exact_set_pair_agreement_rate": 0.8,
            "minimum_acceptable_krippendorff_alpha": 0.8,
        }
        self.write_commitment()

    def tearDown(self):
        self.temporary.cleanup()

    def write_commitment(self):
        self.commitment.write_text(
            json.dumps(self.commitment_payload, indent=2) + "\n", encoding="utf-8"
        )

    def sign(self):
        payload = temporal_study_attestation.sign_commitment(
            self.commitment, self.private_key, "study-review-key-2026"
        )
        evidence_attestation.write_json_atomic(self.attestation, payload)
        return payload

    def test_signed_commitment_verifies_with_trusted_public_key(self):
        self.sign()

        report = temporal_study_attestation.verify_commitment(
            self.commitment,
            self.attestation,
            self.public_key,
            "study-review-key-2026",
        )

        self.assertEqual(report["status"], "pass")

    def test_public_key_path_swap_cannot_change_verified_key(self):
        self.sign()
        original_snapshot = evidence_attestation.private_key_snapshot

        def swap_path_after_read(payload):
            self.public_key.write_bytes(self.other_public_key.read_bytes())
            return original_snapshot(payload)

        with mock.patch.object(
            evidence_attestation,
            "private_key_snapshot",
            side_effect=swap_path_after_read,
        ):
            report = temporal_study_attestation.verify_commitment(
                self.commitment,
                self.attestation,
                self.public_key,
                "study-review-key-2026",
            )

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["study_id"], self.commitment_payload["study_id"])
        self.assertEqual(report["trusted_timestamp_assurance"], "absent")

    def test_cli_sign_and_verify_round_trip(self):
        script = Path(__file__).with_name("temporal_study_attestation.py")
        verification = self.root / "verification.json"
        subprocess.run(
            [
                sys.executable,
                script.as_posix(),
                "sign",
                "--commitment",
                self.commitment.as_posix(),
                "--private-key",
                self.private_key.as_posix(),
                "--key-id",
                "study-review-key-2026",
                "--output",
                self.attestation.as_posix(),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                sys.executable,
                script.as_posix(),
                "verify",
                "--commitment",
                self.commitment.as_posix(),
                "--attestation",
                self.attestation.as_posix(),
                "--public-key",
                self.public_key.as_posix(),
                "--expected-key-id",
                "study-review-key-2026",
                "--output",
                verification.as_posix(),
                "--require-pass",
            ],
            check=True,
            capture_output=True,
        )

        report = json.loads(verification.read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "pass")

    def test_commitment_tampering_is_rejected(self):
        self.sign()
        self.commitment_payload["case_count"] += 1
        self.write_commitment()

        with self.assertRaisesRegex(
            temporal_study_attestation.AttestationError, "does not match attested field"
        ):
            temporal_study_attestation.verify_commitment(
                self.commitment,
                self.attestation,
                self.public_key,
                "study-review-key-2026",
            )

    def test_semantically_equivalent_byte_change_is_detected(self):
        self.sign()
        self.commitment.write_text(
            json.dumps(self.commitment_payload, separators=(",", ":")), encoding="utf-8"
        )

        with self.assertRaisesRegex(
            temporal_study_attestation.AttestationError,
            "commitment_file_sha256",
        ):
            temporal_study_attestation.verify_commitment(
                self.commitment,
                self.attestation,
                self.public_key,
                "study-review-key-2026",
            )

    def test_untrusted_key_id_is_rejected(self):
        self.sign()

        with self.assertRaisesRegex(
            temporal_study_attestation.AttestationError, "key_id is not trusted"
        ):
            temporal_study_attestation.verify_commitment(
                self.commitment,
                self.attestation,
                self.public_key,
                "another-study-key",
            )

    def test_different_public_key_is_rejected(self):
        self.sign()

        with self.assertRaisesRegex(
            temporal_study_attestation.AttestationError,
            "public_key_spki_sha256",
        ):
            temporal_study_attestation.verify_commitment(
                self.commitment,
                self.attestation,
                self.other_public_key,
                "study-review-key-2026",
            )

    def test_attestation_claim_tampering_is_rejected(self):
        payload = self.sign()
        payload["study_id"] = "attacker_study_identity"
        evidence_attestation.write_json_atomic(self.attestation, payload)

        with self.assertRaisesRegex(
            temporal_study_attestation.AttestationError, "attested field study_id"
        ):
            temporal_study_attestation.verify_commitment(
                self.commitment,
                self.attestation,
                self.public_key,
                "study-review-key-2026",
            )

    def test_duplicate_commitment_field_is_rejected(self):
        raw = self.commitment.read_text(encoding="utf-8")
        self.commitment.write_text(
            raw.replace(
                '"study_id": "external_temporal_study_2026",',
                '"study_id": "external_temporal_study_2026",\n  '
                '"study_id": "external_temporal_study_2026",',
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            temporal_study_attestation.AttestationError, "duplicate JSON field"
        ):
            temporal_study_attestation.sign_commitment(
                self.commitment, self.private_key, "study-review-key-2026"
            )

    def test_weak_agreement_threshold_is_rejected(self):
        self.commitment_payload[
            "minimum_acceptable_krippendorff_alpha"
        ] = 0.79
        self.write_commitment()

        with self.assertRaisesRegex(
            temporal_study_attestation.AttestationError,
            "minimum_acceptable_krippendorff_alpha",
        ):
            temporal_study_attestation.sign_commitment(
                self.commitment, self.private_key, "study-review-key-2026"
            )

    def test_canonical_commitment_normalizes_integer_f64_fields(self):
        self.commitment_payload[
            "minimum_acceptable_exact_set_pair_agreement_rate"
        ] = 1

        canonical = temporal_study_attestation.canonical_commitment(
            self.commitment_payload
        )

        self.assertIn(
            b'"minimum_acceptable_exact_set_pair_agreement_rate":1.0', canonical
        )

    @unittest.skipIf(os.name == "nt", "POSIX permission check")
    def test_group_readable_private_key_is_rejected(self):
        os.chmod(self.private_key, 0o640)

        with self.assertRaisesRegex(
            temporal_study_attestation.AttestationError, "permissions"
        ):
            temporal_study_attestation.sign_commitment(
                self.commitment, self.private_key, "study-review-key-2026"
            )

    @unittest.skipIf(os.name == "nt", "POSIX symlink check")
    def test_private_key_symlink_is_rejected(self):
        symlink = self.root / "private-link.pem"
        symlink.symlink_to(self.private_key)

        with self.assertRaisesRegex(
            temporal_study_attestation.AttestationError, "symbolic link"
        ):
            temporal_study_attestation.sign_commitment(
                self.commitment, symlink, "study-review-key-2026"
            )


if __name__ == "__main__":
    unittest.main()
