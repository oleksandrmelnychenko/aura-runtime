import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from ci import domain_recomputation_timestamp_adapter as adapter
from ci import domain_result_timestamp_adapter as result_adapter
from ci import temporal_study_timestamp
from ci.test_domain_result_timestamp_adapter import FIXED_ED25519_PRIVATE_KEY
from ci import test_temporal_study_timestamp as timestamp_fixture_support


FIXED_RECOMPUTATION_TIMESTAMP_SIGNATURE_HEX = (
    "00648b44618edf65aebfdf1126c09889381837ed67e46a1b9ebd2ad103daaa681"
    "cd1dd7a7437e635e27328c36f2974e9bc0935f87011a790fbb6b7f867af9708"
)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class DomainRecomputationTimestampAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = timestamp_fixture_support.TemporalStudyTimestampTests(
            "test_nonce_bearing_sha256_request_is_created"
        )
        cls.fixture.setUp()
        cls.root = cls.fixture.root
        cls.subject = cls.root / "recomputation-execution-attestation.json"
        cls.subject_bytes = (
            b'{"claims":{"schema_version":'
            b'"aura.domain.recomputation_execution_attestation.v1",'
            b'"recomputation_id":"recomputation_2026_01"},'
            b'"signature":{"key_id":"recomputation_executor",'
            b'"signature_hex":"' + b"0" * 128 + b'"}}'
        )
        temporal_study_timestamp.write_bytes_atomic(cls.subject, cls.subject_bytes)
        cls.request = cls.root / "recomputation-subject-request.tsq"
        cls.response = cls.root / "recomputation-subject-response.tsr"
        temporal_study_timestamp.write_bytes_atomic(
            cls.request,
            temporal_study_timestamp.create_request_for_document(
                cls.subject_bytes, cls.fixture.policy_oid
            ),
        )
        cls.fixture.issue_response(
            cls.request,
            cls.response,
            cls.fixture.tsa_certificate,
            cls.fixture.tsa_key,
        )
        cls.verifier_private_key = cls.root / "recomputation-timestamp-verifier.pem"
        cls.verifier_public_key = cls.root / "recomputation-timestamp-verifier.pub.pem"
        temporal_study_timestamp.run_openssl(
            [
                "genpkey",
                "-algorithm",
                "Ed25519",
                "-out",
                cls.verifier_private_key.as_posix(),
            ]
        )
        os.chmod(cls.verifier_private_key, 0o600)
        public_key = temporal_study_timestamp.run_openssl(
            [
                "pkey",
                "-in",
                cls.verifier_private_key.as_posix(),
                "-pubout",
            ]
        )
        temporal_study_timestamp.write_bytes_atomic(
            cls.verifier_public_key, public_key
        )

    @classmethod
    def tearDownClass(cls):
        cls.fixture.tearDown()

    def create_receipt(self, kind="execution_attestation"):
        return adapter.create_trusted_timestamp_receipt(
            subject_path=self.subject,
            subject_kind=kind,
            request_path=self.request,
            response_path=self.response,
            ca_file_path=self.fixture.ca_certificate,
            untrusted_chain_path=self.fixture.tsa_certificate,
            revocation_crl_paths=[self.fixture.revocation_crl],
            expected_policy_oid=self.fixture.policy_oid,
            expected_tsa_spki_sha256=self.fixture.expected_spki_sha256,
            private_key_path=self.verifier_private_key,
            key_id="recomputation_timestamp_verifier_2026",
        )

    def verify_signature(self, receipt):
        payload = adapter.signing_payload(
            receipt["claims"], receipt["signature"]["key_id"]
        )
        with (
            tempfile.NamedTemporaryFile() as payload_file,
            tempfile.NamedTemporaryFile() as signature_file,
        ):
            payload_file.write(payload)
            payload_file.flush()
            signature_file.write(bytes.fromhex(receipt["signature"]["signature_hex"]))
            signature_file.flush()
            temporal_study_timestamp.run_openssl(
                [
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    self.verifier_public_key.as_posix(),
                    "-sigfile",
                    signature_file.name,
                    "-in",
                    payload_file.name,
                ]
            )

    def test_profile_is_separate_and_default_result_profile_is_unchanged(self):
        self.assertEqual(
            adapter.TRUSTED_TIMESTAMP_SCHEMA_VERSION,
            "aura.domain.independent_recomputation_timestamp_verification.v1",
        )
        self.assertEqual(
            adapter.SIGNED_PAYLOAD_DOMAIN,
            b"aura.domain.independent-recomputation-trusted-timestamp.v1\x00",
        )
        self.assertEqual(len(adapter.SUBJECT_KINDS), 7)
        self.assertTrue(set(adapter.SUBJECT_KINDS).isdisjoint(result_adapter.SUBJECT_KINDS))
        self.assertEqual(
            result_adapter.RESULT_TIMESTAMP_PROFILE.schema_version,
            "aura.domain.trusted_timestamp_verification.v2",
        )
        self.assertEqual(
            result_adapter.RESULT_TIMESTAMP_PROFILE.signed_payload_domain,
            b"aura.domain.trusted-timestamp.v1\x00",
        )

    def test_receipt_uses_exact_recomputation_schema_domain_and_verifies(self):
        receipt = self.create_receipt()

        self.assertEqual(
            receipt["claims"]["schema_version"],
            adapter.TRUSTED_TIMESTAMP_SCHEMA_VERSION,
        )
        self.assertEqual(receipt["claims"]["subject_kind"], "execution_attestation")
        self.assertEqual(
            receipt["claims"]["subject_canonical_sha256"],
            sha256(self.subject_bytes).hexdigest(),
        )
        self.assertTrue(
            adapter.signing_payload(
                receipt["claims"], receipt["signature"]["key_id"]
            ).startswith(adapter.SIGNED_PAYLOAD_DOMAIN)
        )
        self.assertNotEqual(
            adapter.signing_payload(
                receipt["claims"], receipt["signature"]["key_id"]
            ),
            result_adapter.signing_payload(
                receipt["claims"], receipt["signature"]["key_id"]
            ),
        )
        self.verify_signature(receipt)

    def test_fixed_cross_language_payload_and_signature_vector(self):
        claims = {
            "schema_version": adapter.TRUSTED_TIMESTAMP_SCHEMA_VERSION,
            "subject_kind": "recomputation_final_manifest",
            "subject_canonical_sha256": "a" * 64,
            "protocol": adapter.TRUSTED_TIMESTAMP_PROTOCOL,
            "issued_at_ms": 1780000000000,
            "gen_time_submillisecond_micros": 999,
            "accuracy_micros": 1000,
            "request_sha256": "b" * 64,
            "response_sha256": "c" * 64,
            "certificate_chain_sha256": "d" * 64,
            "revocation_evidence_sha256": "a" * 64,
            "tsa_spki_sha256": "b" * 64,
            "tsa_policy_oid": "1.3.6.1.4.1.57264.1",
        }
        expected_json = (
            '{"key_id":"recomputation_timestamp_verifier","claims":{'
            '"schema_version":"aura.domain.independent_recomputation_timestamp_verification.v1",'
            '"subject_kind":"recomputation_final_manifest",'
            f'"subject_canonical_sha256":"{"a" * 64}",'
            '"protocol":"rfc3161_trusted_chain","issued_at_ms":1780000000000,'
            '"gen_time_submillisecond_micros":999,"accuracy_micros":1000,'
            f'"request_sha256":"{"b" * 64}",'
            f'"response_sha256":"{"c" * 64}",'
            f'"certificate_chain_sha256":"{"d" * 64}",'
            f'"revocation_evidence_sha256":"{"a" * 64}",'
            f'"tsa_spki_sha256":"{"b" * 64}",'
            '"tsa_policy_oid":"1.3.6.1.4.1.57264.1"}}'
        ).encode("utf-8")
        self.assertEqual(
            adapter.signing_payload(claims, "recomputation_timestamp_verifier"),
            adapter.SIGNED_PAYLOAD_DOMAIN + expected_json,
        )

        fixed_key = self.root / "fixed-recomputation-timestamp-private.pem"
        temporal_study_timestamp.write_bytes_atomic(
            fixed_key, FIXED_ED25519_PRIVATE_KEY
        )
        os.chmod(fixed_key, 0o600)
        signature = adapter.sign_claims(
            claims,
            fixed_key,
            "recomputation_timestamp_verifier",
        )
        self.assertEqual(
            signature["signature_hex"],
            FIXED_RECOMPUTATION_TIMESTAMP_SIGNATURE_HEX,
        )

    def test_every_recomputation_subject_kind_uses_the_full_verification_flow(self):
        for kind in adapter.SUBJECT_KINDS:
            with self.subTest(kind=kind):
                receipt = self.create_receipt(kind)
                self.assertEqual(receipt["claims"]["subject_kind"], kind)
                self.assertEqual(
                    receipt["claims"]["schema_version"],
                    adapter.TRUSTED_TIMESTAMP_SCHEMA_VERSION,
                )

    def test_result_subject_kind_is_rejected_before_signing(self):
        with self.assertRaisesRegex(adapter.AdapterError, "unsupported"):
            self.create_receipt("final_evidence_manifest")

    def test_request_and_verify_sign_cli_round_trip(self):
        script = Path(__file__).with_name("domain_recomputation_timestamp_adapter.py")
        request = self.root / "recomputation-cli-request.tsq"
        response = self.root / "recomputation-cli-response.tsr"
        receipt_path = self.root / "recomputation-cli-receipt.json"
        subprocess.run(
            [
                sys.executable,
                script.as_posix(),
                "request",
                "--subject",
                self.subject.as_posix(),
                "--policy-oid",
                self.fixture.policy_oid,
                "--output",
                request.as_posix(),
            ],
            check=True,
            capture_output=True,
        )
        self.fixture.issue_response(
            request,
            response,
            self.fixture.tsa_certificate,
            self.fixture.tsa_key,
        )
        subprocess.run(
            [
                sys.executable,
                script.as_posix(),
                "verify-sign",
                "--subject",
                self.subject.as_posix(),
                "--subject-kind",
                "comparison_receipt",
                "--request",
                request.as_posix(),
                "--response",
                response.as_posix(),
                "--ca-file",
                self.fixture.ca_certificate.as_posix(),
                "--untrusted-chain",
                self.fixture.tsa_certificate.as_posix(),
                "--revocation-crl",
                self.fixture.revocation_crl.as_posix(),
                "--expected-policy-oid",
                self.fixture.policy_oid,
                "--expected-tsa-spki-sha256",
                self.fixture.expected_spki_sha256,
                "--private-key",
                self.verifier_private_key.as_posix(),
                "--key-id",
                "recomputation_timestamp_verifier_2026",
                "--output",
                receipt_path.as_posix(),
                "--require-pass",
            ],
            check=True,
            capture_output=True,
        )
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["claims"]["subject_kind"], "comparison_receipt")
        self.assertEqual(
            receipt["claims"]["schema_version"],
            adapter.TRUSTED_TIMESTAMP_SCHEMA_VERSION,
        )


if __name__ == "__main__":
    unittest.main()
