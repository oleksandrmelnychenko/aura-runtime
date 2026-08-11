import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from hashlib import sha256
from pathlib import Path

from ci import temporal_review_receipt
from ci import temporal_study_timestamp


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class TemporalReviewReceiptTests(unittest.TestCase):
    policy_oid = "1.2.3.4.1"
    study_id = "external_temporal_study_2026"
    packet_id = "temporal_round_2026_01"
    preregistration_sha256 = "a" * 64
    commitment_sha256 = "b" * 64
    packet_sha256 = "c" * 64
    case_tokens = (
        "blind_0123456789abcdef0123456789abcdef",
        "blind_fedcba9876543210fedcba9876543210",
    )

    @classmethod
    def setUpClass(cls):
        cls.fixture_temporary = tempfile.TemporaryDirectory()
        cls.fixture = Path(cls.fixture_temporary.name)
        cls.ca_key = cls.fixture / "ca-key.pem"
        cls.ca_certificate = cls.fixture / "ca-certificate.pem"
        cls.tsa_key = cls.fixture / "tsa-key.pem"
        cls.tsa_request = cls.fixture / "tsa-request.pem"
        cls.tsa_certificate = cls.fixture / "tsa-certificate.pem"
        cls.generate_ca()
        cls.generate_tsa()
        cls.expected_tsa_spki = cls.spki_sha256(cls.tsa_certificate)
        cls.participant_spki = {}
        cls.write_base_material()
        reviewer_completed_at = int(time.time() * 1000) - 5_000
        cls.write_participant_material(
            "reviewer_a_8f2c10", "reviewer", reviewer_completed_at
        )
        cls.write_participant_material(
            "reviewer_b_41ad22", "reviewer", reviewer_completed_at
        )

        reviewer_reports = [
            cls.verify_participant("reviewer_a_8f2c10"),
            cls.verify_participant("reviewer_b_41ad22"),
        ]
        links = sorted(
            [
                {
                    "participant_token": report["participant_token"],
                    "submission_attestation_sha256": report[
                        "submission_attestation_sha256"
                    ],
                    "timestamp_response_sha256": report["response_sha256"],
                }
                for report in reviewer_reports
            ],
            key=lambda link: link["participant_token"],
        )
        time.sleep(7.0)
        cls.write_participant_material(
            "adjudicator_c_77b901",
            "adjudicator",
            int(time.time() * 1000) - 3_000,
            links=links,
        )
        cls.write_bundle_and_index()
        report = temporal_review_receipt.verify_chain(cls.fixture / "receipt-index.json")
        if report["status"] != "pass":
            raise AssertionError("class receipt fixture did not verify")

    @classmethod
    def tearDownClass(cls):
        cls.fixture_temporary.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "fixture"
        shutil.copytree(self.fixture, self.root)

    def tearDown(self):
        self.temporary.cleanup()

    @classmethod
    def run_openssl(cls, arguments, *, input_bytes=None):
        return subprocess.run(
            ["openssl", *arguments],
            input=input_bytes,
            check=True,
            capture_output=True,
        ).stdout

    @classmethod
    def generate_ca(cls):
        cls.run_openssl(
            [
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                cls.ca_key.as_posix(),
                "-out",
                cls.ca_certificate.as_posix(),
                "-subj",
                "/CN=AURA Receipt Test Root",
                "-days",
                "2",
                "-sha256",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-addext",
                "subjectKeyIdentifier=hash",
            ]
        )

    @classmethod
    def generate_tsa(cls):
        cls.run_openssl(
            [
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                cls.tsa_key.as_posix(),
                "-out",
                cls.tsa_request.as_posix(),
                "-subj",
                "/CN=AURA Receipt Test TSA",
                "-sha256",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=critical,timeStamping",
                "-addext",
                "subjectKeyIdentifier=hash",
            ]
        )
        cls.run_openssl(
            [
                "x509",
                "-req",
                "-in",
                cls.tsa_request.as_posix(),
                "-CA",
                cls.ca_certificate.as_posix(),
                "-CAkey",
                cls.ca_key.as_posix(),
                "-CAcreateserial",
                "-out",
                cls.tsa_certificate.as_posix(),
                "-days",
                "2",
                "-sha256",
                "-copy_extensions",
                "copy",
            ]
        )

    @classmethod
    def spki_sha256(cls, certificate):
        public_key = cls.run_openssl(
            ["x509", "-in", certificate.as_posix(), "-pubkey", "-noout"]
        )
        public_key_der = cls.run_openssl(
            ["pkey", "-pubin", "-outform", "DER"], input_bytes=public_key
        )
        return sha256(public_key_der).hexdigest()

    @classmethod
    def write_json(cls, path, payload):
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    @classmethod
    def write_base_material(cls):
        template = {
            "schema_version": "aura.military.temporal_independent_review.v3",
            "study_id": cls.study_id,
            "preregistration_canonical_sha256": cls.preregistration_sha256,
            "review_bundle_id": cls.packet_id,
            "packet_id": cls.packet_id,
            "packet_canonical_sha256": cls.packet_sha256,
            "protocol": {
                "label_blinding": True,
                "minimum_reviewers_per_case": 2,
                "distinct_reviewer_affiliations": True,
                "independent_adjudicator": True,
            },
            "reviewers": [],
            "cases": [
                {
                    "blind_case_token": token,
                    "annotations": [],
                    "adjudication": None,
                }
                for token in cls.case_tokens
            ],
        }
        cls.write_json(cls.fixture / "review-template.json", template)
        study_gen_time = int(time.time() * 1000) - 5_400_000
        study_accuracy_micros = 1_500_100
        study_accuracy_ms = (study_accuracy_micros + 999) // 1000
        cls.write_json(
            cls.fixture / "study-timestamp.json",
            {
                "schema_version": "aura.military.temporal_study_timestamp_verification.v1",
                "status": "pass",
                "timestamp_protocol": "RFC3161",
                "trusted_timestamp_assurance": "rfc3161_trusted_chain",
                "message_imprint_algorithm": "sha256",
                "certificate_validation_time_basis": "tsa_gen_time",
                "revocation_assurance": "not_checked",
                "request_nonce_present": True,
                "study_id": cls.study_id,
                "preregistration_canonical_sha256": cls.preregistration_sha256,
                "commitment_canonical_sha256": cls.commitment_sha256,
                "packet_canonical_sha256": cls.packet_sha256,
                "response_sha256": "d" * 64,
                "gen_time_unix_ms": study_gen_time,
                "accuracy_micros": study_accuracy_micros,
                "earliest_trusted_time_unix_ms": study_gen_time
                - study_accuracy_ms,
                "latest_trusted_time_unix_ms": study_gen_time
                + study_accuracy_ms,
            },
        )

    @classmethod
    def submission(cls, participant, role, completed_at, links=None):
        return {
            "schema_version": "aura.military.temporal_review_submission.v1",
            "study_id": cls.study_id,
            "preregistration_canonical_sha256": cls.preregistration_sha256,
            "study_commitment_canonical_sha256": cls.commitment_sha256,
            "packet_id": cls.packet_id,
            "packet_canonical_sha256": cls.packet_sha256,
            "participant_token": participant,
            "affiliation_token": participant.replace(
                "reviewer", "affiliation"
            ).replace("adjudicator", "affiliation"),
            "role": role,
            "decisions": [
                {
                    "blind_case_token": token,
                    "expected_reason_codes": (
                        []
                        if index == 0
                        else ["military.temporal.influence_pressure"]
                    ),
                    "completed_at_ms": completed_at,
                }
                for index, token in enumerate(cls.case_tokens)
            ],
            "reviewer_receipt_links": links or [],
        }

    @classmethod
    def participant_paths(cls, participant, root=None):
        root = root or cls.fixture
        return {
            "submission": root / f"{participant}.submission.json",
            "private_key": root / f"{participant}.private.pem",
            "public_key": root / f"{participant}.public.pem",
            "attestation": root / f"{participant}.attestation.json",
            "request": root / f"{participant}.tsq",
            "response": root / f"{participant}.tsr",
        }

    @classmethod
    def write_participant_material(cls, participant, role, completed_at, links=None):
        paths = cls.participant_paths(participant)
        cls.write_json(paths["submission"], cls.submission(participant, role, completed_at, links))
        cls.run_openssl(
            [
                "genpkey",
                "-algorithm",
                "Ed25519",
                "-out",
                paths["private_key"].as_posix(),
            ]
        )
        paths["private_key"].chmod(0o600)
        cls.run_openssl(
            [
                "pkey",
                "-in",
                paths["private_key"].as_posix(),
                "-pubout",
                "-out",
                paths["public_key"].as_posix(),
            ]
        )
        cls.participant_spki[participant] = sha256(
            temporal_study_timestamp.crypto_support.public_key_der_from_public(
                paths["public_key"]
            )
        ).hexdigest()
        key_id = f"{participant}.key"
        attestation = temporal_review_receipt.sign_submission(
            paths["submission"], paths["private_key"], key_id
        )
        temporal_study_timestamp.crypto_support.write_json_atomic(
            paths["attestation"], attestation
        )
        request = temporal_study_timestamp.create_request_for_document(
            paths["attestation"].read_bytes(), cls.policy_oid
        )
        temporal_study_timestamp.write_bytes_atomic(paths["request"], request)
        cls.issue_response(paths["request"], paths["response"])

    @classmethod
    def issue_response(cls, request, response):
        cls.run_openssl(
            [
                "ts",
                "-reply",
                "-queryfile",
                request.as_posix(),
                "-signer",
                cls.tsa_certificate.as_posix(),
                "-inkey",
                cls.tsa_key.as_posix(),
                "-chain",
                cls.ca_certificate.as_posix(),
                "-tspolicy",
                cls.policy_oid,
                "-out",
                response.as_posix(),
            ]
        )

    @classmethod
    def verify_participant(cls, participant, root=None):
        root = root or cls.fixture
        paths = cls.participant_paths(participant, root)
        return temporal_review_receipt.verify_receipt(
            paths["submission"],
            paths["attestation"],
            paths["public_key"],
            f"{participant}.key",
            cls.participant_spki[participant],
            paths["request"],
            paths["response"],
            root / "ca-certificate.pem",
            root / "tsa-certificate.pem",
            cls.policy_oid,
            cls.expected_tsa_spki,
        )

    @classmethod
    def receipt_package(cls, participant):
        return {
            "submission": f"{participant}.submission.json",
            "attestation": f"{participant}.attestation.json",
            "public_key": f"{participant}.public.pem",
            "expected_key_id": f"{participant}.key",
            "expected_signer_spki_sha256": cls.participant_spki[participant],
            "timestamp_request": f"{participant}.tsq",
            "timestamp_response": f"{participant}.tsr",
            "ca_file": "ca-certificate.pem",
            "untrusted_chain": "tsa-certificate.pem",
            "expected_policy_oid": cls.policy_oid,
            "expected_tsa_spki_sha256": cls.expected_tsa_spki,
        }

    @classmethod
    def write_bundle_and_index(cls):
        _, template = temporal_review_receipt.read_json(
            cls.fixture / "review-template.json",
            temporal_review_receipt.MAX_REVIEW_BUNDLE_BYTES,
            "review template",
        )
        reviewers = [
            temporal_review_receipt.read_json(
                cls.fixture / f"{participant}.submission.json",
                temporal_review_receipt.MAX_SUBMISSION_BYTES,
                "review submission",
            )[1]
            for participant in ("reviewer_a_8f2c10", "reviewer_b_41ad22")
        ]
        adjudicator = temporal_review_receipt.read_json(
            cls.fixture / "adjudicator_c_77b901.submission.json",
            temporal_review_receipt.MAX_SUBMISSION_BYTES,
            "adjudicator submission",
        )[1]
        bundle = temporal_review_receipt.assemble_bundle(
            template, cls.commitment_sha256, reviewers, adjudicator
        )
        cls.write_json(cls.fixture / "review-bundle.json", bundle)
        cls.write_json(
            cls.fixture / "receipt-index.json",
            {
                "schema_version": "aura.military.temporal_review_receipt_index.v1",
                "review_bundle": "review-bundle.json",
                "study_timestamp_verification": "study-timestamp.json",
                "reviewer_receipts": [
                    cls.receipt_package("reviewer_a_8f2c10"),
                    cls.receipt_package("reviewer_b_41ad22"),
                ],
                "adjudicator_receipt": cls.receipt_package(
                    "adjudicator_c_77b901"
                ),
            },
        )

    def load_json(self, name):
        return json.loads((self.root / name).read_text(encoding="utf-8"))

    def save_json(self, name, payload):
        self.write_json(self.root / name, payload)

    def test_valid_chain_verifies_without_exporting_participant_identity(self):
        report = temporal_review_receipt.verify_chain(self.root / "receipt-index.json")

        self.assertEqual(report["status"], "pass")
        self.assertEqual(
            report["chronology_assurance"],
            "individual_signed_rfc3161_receipts",
        )
        self.assertEqual(report["reviewer_receipt_count"], 2)
        self.assertTrue(report["commitment_before_review_receipts"])
        self.assertTrue(report["review_receipts_before_adjudication"])
        self.assertFalse(report["privacy"]["participant_tokens_exported"])
        serialized = json.dumps(report)
        self.assertNotIn("reviewer_a_8f2c10", serialized)
        self.assertNotIn("affiliation_a_8f2c10", serialized)

    def test_tampered_reviewer_submission_is_rejected(self):
        submission = self.load_json("reviewer_a_8f2c10.submission.json")
        submission["decisions"][0]["expected_reason_codes"] = [
            "military.temporal.influence_pressure"
        ]
        self.save_json("reviewer_a_8f2c10.submission.json", submission)

        with self.assertRaisesRegex(
            temporal_review_receipt.ReceiptError, "attested field"
        ):
            temporal_review_receipt.verify_chain(self.root / "receipt-index.json")

    def test_swapped_timestamp_response_is_rejected(self):
        index = self.load_json("receipt-index.json")
        index["reviewer_receipts"][0]["timestamp_response"] = (
            "reviewer_b_41ad22.tsr"
        )
        self.save_json("receipt-index.json", index)

        with self.assertRaises(temporal_review_receipt.ReceiptError):
            temporal_review_receipt.verify_chain(self.root / "receipt-index.json")

    def test_untrusted_reviewer_signing_key_is_rejected(self):
        index = self.load_json("receipt-index.json")
        index["reviewer_receipts"][0]["expected_signer_spki_sha256"] = "0" * 64
        self.save_json("receipt-index.json", index)

        with self.assertRaisesRegex(
            temporal_review_receipt.ReceiptError, "expected SPKI"
        ):
            temporal_review_receipt.verify_chain(self.root / "receipt-index.json")

    def test_review_bundle_label_substitution_is_rejected(self):
        bundle = self.load_json("review-bundle.json")
        bundle["cases"][0]["annotations"][0]["expected_reason_codes"] = [
            "military.temporal.influence_pressure"
        ]
        self.save_json("review-bundle.json", bundle)

        with self.assertRaisesRegex(
            temporal_review_receipt.ReceiptError, "does not exactly match"
        ):
            temporal_review_receipt.verify_chain(self.root / "receipt-index.json")

    def test_commitment_interval_must_precede_reviewer_receipts(self):
        study_timestamp = self.load_json("study-timestamp.json")
        reviewer = self.verify_participant("reviewer_a_8f2c10", self.root)
        reviewer_earliest = reviewer["earliest_trusted_time_unix_ms"]
        study_timestamp["gen_time_unix_ms"] = reviewer_earliest
        study_timestamp["accuracy_micros"] = 0
        study_timestamp["earliest_trusted_time_unix_ms"] = reviewer_earliest
        study_timestamp["latest_trusted_time_unix_ms"] = reviewer_earliest
        self.save_json("study-timestamp.json", study_timestamp)

        with self.assertRaisesRegex(
            temporal_review_receipt.ReceiptError, "overlaps reviewer receipts"
        ):
            temporal_review_receipt.verify_chain(self.root / "receipt-index.json")

    def test_adjudicator_must_bind_exact_reviewer_receipts(self):
        submission = self.load_json("adjudicator_c_77b901.submission.json")
        submission["reviewer_receipt_links"][0]["timestamp_response_sha256"] = "0" * 64
        self.save_json("adjudicator_c_77b901.submission.json", submission)

        with self.assertRaises(temporal_review_receipt.ReceiptError):
            temporal_review_receipt.verify_chain(self.root / "receipt-index.json")

    def test_private_signing_key_permissions_are_enforced(self):
        key = self.root / "reviewer_a_8f2c10.private.pem"
        key.chmod(0o644)

        with self.assertRaisesRegex(
            temporal_review_receipt.ReceiptError, "permissions"
        ):
            temporal_review_receipt.sign_submission(
                self.root / "reviewer_a_8f2c10.submission.json",
                key,
                "reviewer_a_8f2c10.key",
            )

    def test_chain_output_cannot_overwrite_nested_input(self):
        with self.assertRaisesRegex(
            temporal_review_receipt.ReceiptError, "must not overwrite"
        ):
            temporal_review_receipt.verify_chain(
                self.root / "receipt-index.json",
                self.root / "reviewer_a_8f2c10.submission.json",
            )

    def test_inconsistent_study_timestamp_interval_is_rejected(self):
        study_timestamp = self.load_json("study-timestamp.json")
        study_timestamp["latest_trusted_time_unix_ms"] += 1
        self.save_json("study-timestamp.json", study_timestamp)

        with self.assertRaisesRegex(
            temporal_review_receipt.ReceiptError, "interval is inconsistent"
        ):
            temporal_review_receipt.verify_chain(self.root / "receipt-index.json")

    def test_assembly_is_deterministic_and_matches_verified_bundle(self):
        template = self.load_json("review-template.json")
        reviewers = [
            self.load_json("reviewer_a_8f2c10.submission.json"),
            self.load_json("reviewer_b_41ad22.submission.json"),
        ]
        adjudicator = self.load_json("adjudicator_c_77b901.submission.json")

        assembled = temporal_review_receipt.assemble_bundle(
            template, self.commitment_sha256, reviewers, adjudicator
        )

        self.assertEqual(assembled, self.load_json("review-bundle.json"))

    def test_cli_chain_verification_round_trip(self):
        output = self.root / "chain-verification.json"
        script = Path(__file__).with_name("temporal_review_receipt.py")
        subprocess.run(
            [
                sys.executable,
                script.as_posix(),
                "verify-chain",
                "--index",
                (self.root / "receipt-index.json").as_posix(),
                "--output",
                output.as_posix(),
                "--require-pass",
            ],
            check=True,
            capture_output=True,
        )

        self.assertEqual(self.load_json("chain-verification.json")["status"], "pass")


if __name__ == "__main__":
    unittest.main()
