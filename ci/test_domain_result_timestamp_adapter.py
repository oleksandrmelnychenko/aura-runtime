import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from ci import domain_result_timestamp_adapter as adapter
from ci import temporal_study_timestamp
from ci import test_temporal_study_timestamp as timestamp_fixture_support


FIXED_ED25519_PRIVATE_KEY = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g
-----END PRIVATE KEY-----
"""
FIXED_ED25519_PUBLIC_KEY_HEX = (
    "d75a980182b10ab7d54bfed3c964073a"
    "0ee172f3daa62325af021a68f707511a"
)
FIXED_ED25519_SIGNATURE_HEX = (
    "a09b19f78bceb5a0ab643bf1eeb339ad9efe9fecc2fdda98ecdc25c279a60141"
    "35868bb7ac18ea249f029613bdcf7ab878e690ab77cbe6170ed53d33fd19800e"
)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class DomainResultTimestampAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = timestamp_fixture_support.TemporalStudyTimestampTests(
            "test_nonce_bearing_sha256_request_is_created"
        )
        cls.fixture.setUp()
        cls.root = cls.fixture.root
        cls.subject = cls.root / "preregistration-attestation.json"
        cls.subject_bytes = (
            b'{"claims":{"schema_version":"aura.domain.preregistration_attestation.v1",'
            b'"study_id":"external_study_2026",'
            b'"preregistration_canonical_sha256":"' + b"a" * 64 + b'",'
            b'"attested_at_ms":1780000000000},'
            b'"signature":{"key_id":"institution_2026",'
            b'"signature_hex":"' + b"0" * 128 + b'"}}'
        )
        temporal_study_timestamp.write_bytes_atomic(cls.subject, cls.subject_bytes)
        cls.request = cls.root / "domain-subject-request.tsq"
        cls.response = cls.root / "domain-subject-response.tsr"
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
        cls.verifier_private_key = cls.root / "timestamp-verifier-private.pem"
        cls.verifier_public_key = cls.root / "timestamp-verifier-public.pem"
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

    def create_receipt(self):
        return adapter.create_trusted_timestamp_receipt(
            subject_path=self.subject,
            subject_kind="preregistration_attestation",
            request_path=self.request,
            response_path=self.response,
            ca_file_path=self.fixture.ca_certificate,
            untrusted_chain_path=self.fixture.tsa_certificate,
            revocation_crl_paths=[self.fixture.revocation_crl],
            expected_policy_oid=self.fixture.policy_oid,
            expected_tsa_spki_sha256=self.fixture.expected_spki_sha256,
            private_key_path=self.verifier_private_key,
            key_id="timestamp_verifier_2026",
        )

    def test_receipt_claim_order_matches_rust_and_signature_verifies(self):
        receipt = self.create_receipt()
        claims = receipt["claims"]

        self.assertEqual(
            list(claims),
            [
                "schema_version",
                "subject_kind",
                "subject_canonical_sha256",
                "protocol",
                "issued_at_ms",
                "gen_time_submillisecond_micros",
                "accuracy_micros",
                "request_sha256",
                "response_sha256",
                "certificate_chain_sha256",
                "revocation_evidence_sha256",
                "tsa_spki_sha256",
                "tsa_policy_oid",
            ],
        )
        self.assertEqual(
            claims["subject_canonical_sha256"],
            __import__("hashlib").sha256(self.subject_bytes).hexdigest(),
        )
        self.assertEqual(len(receipt["signature"]["signature_hex"]), 128)
        payload = adapter.signing_payload(
            claims, receipt["signature"]["key_id"]
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

    def test_signing_payload_has_exact_rust_serde_order(self):
        claims = {
            "schema_version": adapter.TRUSTED_TIMESTAMP_SCHEMA_VERSION,
            "subject_kind": "final_evidence_manifest",
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
            '{"key_id":"timestamp_verifier","claims":{'
            '"schema_version":"aura.domain.trusted_timestamp_verification.v2",'
            '"subject_kind":"final_evidence_manifest",'
            f'"subject_canonical_sha256":"{"a" * 64}",'
            '"protocol":"rfc3161_trusted_chain",'
            '"issued_at_ms":1780000000000,'
            '"gen_time_submillisecond_micros":999,"accuracy_micros":1000,'
            f'"request_sha256":"{"b" * 64}",'
            f'"response_sha256":"{"c" * 64}",'
            f'"certificate_chain_sha256":"{"d" * 64}",'
            f'"revocation_evidence_sha256":"{"a" * 64}",'
            f'"tsa_spki_sha256":"{"b" * 64}",'
            '"tsa_policy_oid":"1.3.6.1.4.1.57264.1"}}'
        ).encode("utf-8")

        self.assertEqual(
            adapter.signing_payload(claims, "timestamp_verifier"),
            adapter.SIGNED_PAYLOAD_DOMAIN + expected_json,
        )
        self.assertEqual(
            adapter.signing_payload(
                dict(reversed(list(claims.items()))), "timestamp_verifier"
            ),
            adapter.SIGNED_PAYLOAD_DOMAIN + expected_json,
        )

        fixed_key = self.root / "fixed-cross-language-private.pem"
        temporal_study_timestamp.write_bytes_atomic(
            fixed_key, FIXED_ED25519_PRIVATE_KEY
        )
        os.chmod(fixed_key, 0o600)
        signature = adapter.sign_claims(
            claims,
            fixed_key,
            "timestamp_verifier",
        )
        self.assertEqual(
            signature["signature_hex"], FIXED_ED25519_SIGNATURE_HEX
        )
        public_der = temporal_study_timestamp.run_openssl(
            ["pkey", "-in", fixed_key.as_posix(), "-pubout", "-outform", "DER"]
        )
        self.assertEqual(public_der[-32:].hex(), FIXED_ED25519_PUBLIC_KEY_HEX)

    def test_signing_payload_rejects_missing_or_extra_claims(self):
        receipt = self.create_receipt()
        missing = dict(receipt["claims"])
        missing.pop("request_sha256")
        extra = {**receipt["claims"], "unexpected": True}

        with self.assertRaisesRegex(adapter.AdapterError, "exact field set"):
            adapter.signing_payload(missing, receipt["signature"]["key_id"])
        with self.assertRaisesRegex(adapter.AdapterError, "exact field set"):
            adapter.signing_payload(extra, receipt["signature"]["key_id"])

    def test_all_subject_kinds_are_issued_by_the_full_verification_flow(self):
        for subject_kind in adapter.SUBJECT_KINDS:
            with self.subTest(subject_kind=subject_kind):
                receipt = adapter.create_trusted_timestamp_receipt(
                    subject_path=self.subject,
                    subject_kind=subject_kind,
                    request_path=self.request,
                    response_path=self.response,
                    ca_file_path=self.fixture.ca_certificate,
                    untrusted_chain_path=self.fixture.tsa_certificate,
                    revocation_crl_paths=[self.fixture.revocation_crl],
                    expected_policy_oid=self.fixture.policy_oid,
                    expected_tsa_spki_sha256=self.fixture.expected_spki_sha256,
                    private_key_path=self.verifier_private_key,
                    key_id="timestamp_verifier_2026",
                )
                self.assertEqual(receipt["claims"]["subject_kind"], subject_kind)

    def test_key_id_limit_matches_rust_contract(self):
        receipt = self.create_receipt()
        claims = receipt["claims"]
        self.assertTrue(adapter.safe_key_id("k" * 128))
        self.assertFalse(adapter.safe_key_id("k" * 129))
        signature = adapter.sign_claims(
            claims,
            self.verifier_private_key,
            "k" * 128,
        )
        self.assertEqual(signature["key_id"], "k" * 128)

    def test_request_and_verify_sign_cli_round_trip(self):
        script = Path(__file__).with_name("domain_result_timestamp_adapter.py")
        request = self.root / "cli-domain-request.tsq"
        response = self.root / "cli-domain-response.tsr"
        receipt_path = self.root / "cli-domain-receipt.json"
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
                "preregistration_attestation",
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
                "timestamp_verifier_2026",
                "--output",
                receipt_path.as_posix(),
                "--require-pass",
            ],
            check=True,
            capture_output=True,
        )

        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        request_details = temporal_study_timestamp.inspect_request(request)
        self.assertEqual(request_details["certificate_required"], "yes")
        self.assertTrue(request_details["nonce"].startswith("0x"))
        self.assertEqual(
            receipt["claims"]["subject_kind"], "preregistration_attestation"
        )
        self.assertEqual(list(receipt["claims"]), sorted(adapter.CLAIM_FIELDS))
        reloaded_payload = adapter.signing_payload(
            receipt["claims"], receipt["signature"]["key_id"]
        )
        with (
            tempfile.NamedTemporaryFile() as payload_file,
            tempfile.NamedTemporaryFile() as signature_file,
        ):
            payload_file.write(reloaded_payload)
            payload_file.flush()
            signature_file.write(
                bytes.fromhex(receipt["signature"]["signature_hex"])
            )
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

    def test_noncompact_or_duplicate_subject_is_rejected(self):
        noncompact = self.root / "noncompact-subject.json"
        duplicate = self.root / "duplicate-subject.json"
        temporal_study_timestamp.write_bytes_atomic(noncompact, b'{"value":1}\n')
        temporal_study_timestamp.write_bytes_atomic(
            duplicate, b'{"value":1,"value":2}'
        )

        with self.assertRaisesRegex(adapter.AdapterError, "compact Rust serde JSON"):
            adapter.read_compact_subject(noncompact)
        with self.assertRaisesRegex(adapter.AdapterError, "duplicate JSON field"):
            adapter.read_compact_subject(duplicate)

    def test_nonfinite_or_nonobject_subject_is_rejected(self):
        nonfinite = self.root / "nonfinite-subject.json"
        nonobject = self.root / "nonobject-subject.json"
        temporal_study_timestamp.write_bytes_atomic(nonfinite, b'{"value":NaN}')
        temporal_study_timestamp.write_bytes_atomic(nonobject, b"[]")

        with self.assertRaisesRegex(adapter.AdapterError, "non-finite JSON number"):
            adapter.read_compact_subject(nonfinite)
        with self.assertRaisesRegex(adapter.AdapterError, "must be a JSON object"):
            adapter.read_compact_subject(nonobject)

    def test_request_output_cannot_overwrite_subject(self):
        script = Path(__file__).with_name("domain_result_timestamp_adapter.py")
        original = self.subject.read_bytes()

        result = subprocess.run(
            [
                sys.executable,
                script.as_posix(),
                "request",
                "--subject",
                self.subject.as_posix(),
                "--policy-oid",
                self.fixture.policy_oid,
                "--output",
                self.subject.as_posix(),
            ],
            check=False,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.subject.read_bytes(), original)

    @unittest.skipIf(os.name == "nt", "POSIX directory-descriptor semantics")
    def test_same_path_is_rejected_before_parent_swap_window(self):
        live_parent = self.root / "same-output-live"
        frozen_parent = self.root / "same-output-frozen"
        replacement_parent = self.root / "same-output-replacement"
        live_parent.mkdir()
        replacement_parent.mkdir()
        protected = live_parent / "same.json"
        temporal_study_timestamp.write_bytes_atomic(protected, b"ORIGINAL")

        with (
            mock.patch.object(
                adapter.os,
                "open",
                side_effect=AssertionError("same path must fail before opening files"),
            ),
            self.assertRaisesRegex(adapter.AdapterError, "must not overwrite"),
        ):
            adapter.FrozenAtomicOutput(protected, [protected])

        self.assertEqual(protected.read_bytes(), b"ORIGINAL")
        self.assertFalse(frozen_parent.exists())
        self.assertTrue(replacement_parent.is_dir())

    @unittest.skipIf(os.name == "nt", "POSIX directory-descriptor semantics")
    def test_request_parent_swap_cannot_redirect_output_over_subject(self):
        live_parent = self.root / "request-output-live"
        frozen_parent = self.root / "request-output-frozen"
        replacement_parent = self.root / "request-output-replacement"
        live_parent.mkdir()
        replacement_parent.mkdir()
        protected_subject = replacement_parent / "request.tsq"
        temporal_study_timestamp.write_bytes_atomic(
            protected_subject, self.subject_bytes
        )
        original_subject = protected_subject.read_bytes()
        output = live_parent / protected_subject.name
        original_reader = adapter.read_compact_subject_with_identity

        def swap_parent_then_read(path):
            live_parent.rename(frozen_parent)
            live_parent.symlink_to(replacement_parent, target_is_directory=True)
            return original_reader(path)

        arguments = [
            "domain_result_timestamp_adapter.py",
            "request",
            "--subject",
            protected_subject.as_posix(),
            "--policy-oid",
            self.fixture.policy_oid,
            "--output",
            output.as_posix(),
        ]
        with (
            mock.patch.object(sys, "argv", arguments),
            mock.patch.object(
                adapter,
                "read_compact_subject_with_identity",
                side_effect=swap_parent_then_read,
            ),
        ):
            self.assertEqual(adapter.main(), 0)

        self.assertEqual(protected_subject.read_bytes(), original_subject)
        frozen_output = frozen_parent / protected_subject.name
        self.assertNotEqual(frozen_output.read_bytes(), original_subject)
        request_details = temporal_study_timestamp.inspect_request(frozen_output)
        self.assertEqual(request_details["certificate_required"], "yes")

    @unittest.skipIf(os.name == "nt", "POSIX directory-descriptor semantics")
    def test_verify_sign_parent_swap_cannot_redirect_output_over_private_key(self):
        live_parent = self.root / "receipt-output-live"
        frozen_parent = self.root / "receipt-output-frozen"
        replacement_parent = self.root / "receipt-output-replacement"
        live_parent.mkdir()
        replacement_parent.mkdir()
        protected_private_key = replacement_parent / "receipt.json"
        shutil.copyfile(self.verifier_private_key, protected_private_key)
        os.chmod(protected_private_key, 0o600)
        original_private_key = protected_private_key.read_bytes()
        output = live_parent / protected_private_key.name
        expected_receipt = {"claims": {"test": "frozen-output"}}

        def swap_parent_then_return_receipt(**_):
            live_parent.rename(frozen_parent)
            live_parent.symlink_to(replacement_parent, target_is_directory=True)
            return expected_receipt

        arguments = [
            "domain_result_timestamp_adapter.py",
            "verify-sign",
            "--subject",
            self.subject.as_posix(),
            "--subject-kind",
            "preregistration_attestation",
            "--request",
            self.request.as_posix(),
            "--response",
            self.response.as_posix(),
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
            protected_private_key.as_posix(),
            "--key-id",
            "timestamp_verifier_2026",
            "--output",
            output.as_posix(),
        ]
        with (
            mock.patch.object(sys, "argv", arguments),
            mock.patch.object(
                adapter,
                "create_trusted_timestamp_receipt",
                side_effect=swap_parent_then_return_receipt,
            ),
        ):
            self.assertEqual(adapter.main(), 0)

        self.assertEqual(protected_private_key.read_bytes(), original_private_key)
        written_receipt = json.loads(
            (frozen_parent / protected_private_key.name).read_text(encoding="utf-8")
        )
        self.assertEqual(written_receipt, expected_receipt)

    def test_inconsistent_verifier_interval_is_not_signed(self):
        original_verifier = temporal_study_timestamp.verify_document_timestamp

        def verifier_with_inconsistent_interval(*args, **kwargs):
            report = original_verifier(*args, **kwargs)
            report["latest_trusted_time_unix_ms"] += 1
            return report

        with (
            mock.patch.object(
                temporal_study_timestamp,
                "verify_document_timestamp",
                side_effect=verifier_with_inconsistent_interval,
            ),
            self.assertRaisesRegex(adapter.AdapterError, "interval is inconsistent"),
        ):
            self.create_receipt()

    @unittest.skipIf(os.name == "nt", "POSIX symlink key policy")
    def test_symbolic_link_private_key_is_rejected(self):
        symbolic_link = self.root / "timestamp-verifier-link.pem"
        symbolic_link.symlink_to(self.verifier_private_key)

        with self.assertRaisesRegex(adapter.AdapterError, "symbolic link"):
            adapter.sign_claims({}, symbolic_link, "timestamp_verifier_2026")


if __name__ == "__main__":
    unittest.main()
