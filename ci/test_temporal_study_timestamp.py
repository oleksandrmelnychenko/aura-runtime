import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ci import temporal_study_timestamp


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class TemporalStudyTimestampTests(unittest.TestCase):
    policy_oid = "1.2.3.4.1"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.commitment = self.root / "temporal-study-commitment.json"
        self.request = self.root / "temporal-study-request.tsq"
        self.response = self.root / "temporal-study-response.tsr"
        self.ca_key = self.root / "ca-key.pem"
        self.ca_certificate = self.root / "ca-certificate.pem"
        self.tsa_key = self.root / "tsa-key.pem"
        self.tsa_request = self.root / "tsa-request.pem"
        self.tsa_certificate = self.root / "tsa-certificate.pem"
        self.ca_database = self.root / "ca-database"
        self.ca_config = self.root / "ca.cnf"
        self.revocation_crl = self.root / "ca-revocation.crl.pem"
        self.commitment_payload = {
            "schema_version": "aura.military.temporal_study_commitment.v1",
            "study_id": "external_temporal_study_2026",
            "registered_at_ms": int(time.time() * 1000) - 60_000,
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
        self.generate_ca()
        self.generate_tsa(
            self.tsa_key,
            self.tsa_request,
            self.tsa_certificate,
            "AURA Test TSA",
        )
        self.prepare_ca_database()
        self.generate_crl(self.revocation_crl)
        self.expected_spki_sha256 = self.spki_sha256(self.tsa_certificate)
        temporal_study_timestamp.write_bytes_atomic(
            self.request,
            temporal_study_timestamp.create_request(
                self.commitment, self.policy_oid
            ),
        )
        self.issue_response(
            self.request,
            self.response,
            self.tsa_certificate,
            self.tsa_key,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def run_openssl(self, arguments, *, input_bytes=None):
        return subprocess.run(
            ["openssl", *arguments],
            input=input_bytes,
            check=True,
            capture_output=True,
        ).stdout

    def write_commitment(self):
        self.commitment.write_text(
            json.dumps(self.commitment_payload, indent=2) + "\n", encoding="utf-8"
        )

    def generate_ca(self):
        self.run_openssl(
            [
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                self.ca_key.as_posix(),
                "-out",
                self.ca_certificate.as_posix(),
                "-subj",
                "/CN=AURA Test Timestamp Root",
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

    def generate_tsa(self, key, request, certificate, common_name):
        self.run_openssl(
            [
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                key.as_posix(),
                "-out",
                request.as_posix(),
                "-subj",
                f"/CN={common_name}",
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
        self.run_openssl(
            [
                "x509",
                "-req",
                "-in",
                request.as_posix(),
                "-CA",
                self.ca_certificate.as_posix(),
                "-CAkey",
                self.ca_key.as_posix(),
                "-CAcreateserial",
                "-out",
                certificate.as_posix(),
                "-days",
                "2",
                "-sha256",
                "-copy_extensions",
                "copy",
            ]
        )

    def prepare_ca_database(self):
        self.ca_database.mkdir()
        (self.ca_database / "newcerts").mkdir()
        (self.ca_database / "index.txt").write_text("", encoding="ascii")
        (self.ca_database / "crlnumber").write_text("1000\n", encoding="ascii")
        self.ca_config.write_text(
            "\n".join(
                [
                    "[ ca ]",
                    "default_ca = local_ca",
                    "[ local_ca ]",
                    f"database = {self.ca_database / 'index.txt'}",
                    f"new_certs_dir = {self.ca_database / 'newcerts'}",
                    f"certificate = {self.ca_certificate}",
                    f"private_key = {self.ca_key}",
                    f"crlnumber = {self.ca_database / 'crlnumber'}",
                    "default_md = sha256",
                    "default_crl_days = 1",
                    "policy = policy_any",
                    "[ policy_any ]",
                    "commonName = supplied",
                    "",
                ]
            ),
            encoding="ascii",
        )

    def generate_crl(self, output, *, this_update=None, next_update=None):
        arguments = [
            "ca",
            "-gencrl",
            "-batch",
            "-config",
            self.ca_config.as_posix(),
            "-out",
            output.as_posix(),
        ]
        if this_update is not None:
            arguments.extend(
                ["-crl_lastupdate", this_update.strftime("%Y%m%d%H%M%SZ")]
            )
        if next_update is not None:
            arguments.extend(
                ["-crl_nextupdate", next_update.strftime("%Y%m%d%H%M%SZ")]
            )
        self.run_openssl(arguments)

    def issue_response(self, request, response, certificate, key):
        self.run_openssl(
            [
                "ts",
                "-reply",
                "-queryfile",
                request.as_posix(),
                "-signer",
                certificate.as_posix(),
                "-inkey",
                key.as_posix(),
                "-chain",
                self.ca_certificate.as_posix(),
                "-tspolicy",
                self.policy_oid,
                "-out",
                response.as_posix(),
            ]
        )

    def spki_sha256(self, certificate):
        public_key = self.run_openssl(
            ["x509", "-in", certificate.as_posix(), "-pubkey", "-noout"]
        )
        public_key_der = self.run_openssl(
            ["pkey", "-pubin", "-outform", "DER"], input_bytes=public_key
        )
        import hashlib

        return hashlib.sha256(public_key_der).hexdigest()

    def verify(self, **overrides):
        arguments = {
            "commitment_path": self.commitment,
            "request_path": self.request,
            "response_path": self.response,
            "ca_file_path": self.ca_certificate,
            "untrusted_chain_path": self.tsa_certificate,
            "expected_policy_oid": self.policy_oid,
            "expected_tsa_spki_sha256": self.expected_spki_sha256,
            "revocation_crl_paths": [self.revocation_crl],
        }
        arguments.update(overrides)
        return temporal_study_timestamp.verify_timestamp(**arguments)

    def test_nonce_bearing_sha256_request_is_created(self):
        request = temporal_study_timestamp.inspect_request(self.request)

        self.assertEqual(request["policy_oid"], self.policy_oid)
        self.assertEqual(request["hash_algorithm"], "sha256")
        self.assertEqual(request["certificate_required"], "yes")
        self.assertTrue(request["nonce"].startswith("0x"))

    def test_trusted_timestamp_verifies_against_request_and_commitment(self):
        report = self.verify()

        self.assertEqual(report["status"], "pass")
        self.assertEqual(
            report["trusted_timestamp_assurance"], "rfc3161_trusted_chain"
        )
        self.assertEqual(report["tsa_signer_spki_sha256"], self.expected_spki_sha256)
        self.assertEqual(report["study_id"], self.commitment_payload["study_id"])
        self.assertEqual(
            report["revocation_assurance"], "full_chain_crl_at_gen_time"
        )
        self.assertEqual(report["revocation_checked_certificate_count"], 1)
        self.assertEqual(report["revocation_crl_count"], 1)
        self.assertFalse(report["revocation_network_fetch_used"])
        self.assertEqual(
            report["latest_trusted_time_unix_ms"],
            report["gen_time_unix_ms"] + (report["accuracy_micros"] + 999) // 1000,
        )

    def test_commitment_tampering_is_rejected(self):
        self.commitment_payload["case_count"] += 1
        self.write_commitment()

        with self.assertRaisesRegex(
            temporal_study_timestamp.TimestampError, "OpenSSL command failed"
        ):
            self.verify()

    def test_swapped_nonce_request_is_rejected(self):
        other_request = self.root / "other-request.tsq"
        temporal_study_timestamp.write_bytes_atomic(
            other_request,
            temporal_study_timestamp.create_request(
                self.commitment, self.policy_oid
            ),
        )

        with self.assertRaisesRegex(
            temporal_study_timestamp.TimestampError, "nonce"
        ):
            self.verify(request_path=other_request)

    def test_request_without_nonce_is_rejected(self):
        no_nonce_request = self.root / "no-nonce-request.tsq"
        self.run_openssl(
            [
                "ts",
                "-query",
                "-data",
                self.commitment.as_posix(),
                "-sha256",
                "-tspolicy",
                self.policy_oid,
                "-no_nonce",
                "-cert",
                "-out",
                no_nonce_request.as_posix(),
            ]
        )

        with self.assertRaisesRegex(
            temporal_study_timestamp.TimestampError, "nonce"
        ):
            temporal_study_timestamp.inspect_request(no_nonce_request)

    def test_response_byte_tampering_is_rejected(self):
        tampered = bytearray(self.response.read_bytes())
        tampered[-1] ^= 1
        self.response.write_bytes(tampered)

        with self.assertRaises(temporal_study_timestamp.TimestampError):
            self.verify()

    def test_missing_revocation_evidence_is_rejected(self):
        with self.assertRaisesRegex(
            temporal_study_timestamp.TimestampError, "requires 1"
        ):
            self.verify(revocation_crl_paths=[])

    def test_malformed_revocation_report_digest_is_rejected_cleanly(self):
        report = self.verify()
        report["revocation_crl_set_sha256"] = 7

        with self.assertRaisesRegex(
            temporal_study_timestamp.TimestampError, "set digest"
        ):
            temporal_study_timestamp.validate_revocation_claims(report)

    def test_duplicate_revocation_crl_path_is_rejected(self):
        with self.assertRaisesRegex(
            temporal_study_timestamp.TimestampError, "repeats a CRL path"
        ):
            self.verify(
                revocation_crl_paths=[self.revocation_crl, self.revocation_crl]
            )

    def test_tampered_revocation_crl_is_rejected(self):
        tampered = bytearray(self.revocation_crl.read_bytes())
        tampered[len(tampered) // 2] ^= 1
        self.revocation_crl.write_bytes(tampered)

        with self.assertRaises(temporal_study_timestamp.TimestampError):
            self.verify()

    def test_crl_issued_after_timestamp_does_not_prove_historical_status(self):
        future_crl = self.root / "future.crl.pem"
        now = datetime.now(tz=timezone.utc)
        self.generate_crl(
            future_crl,
            this_update=now + timedelta(hours=1),
            next_update=now + timedelta(hours=2),
        )

        with self.assertRaisesRegex(
            temporal_study_timestamp.TimestampError, "does not cover"
        ):
            self.verify(revocation_crl_paths=[future_crl])

    def test_expired_crl_does_not_prove_historical_status(self):
        expired_crl = self.root / "expired.crl.pem"
        now = datetime.now(tz=timezone.utc)
        self.generate_crl(
            expired_crl,
            this_update=now - timedelta(hours=2),
            next_update=now - timedelta(hours=1),
        )

        with self.assertRaisesRegex(
            temporal_study_timestamp.TimestampError, "does not cover"
        ):
            self.verify(revocation_crl_paths=[expired_crl])

    def test_revoked_tsa_certificate_is_rejected(self):
        self.run_openssl(
            [
                "ca",
                "-batch",
                "-config",
                self.ca_config.as_posix(),
                "-revoke",
                self.tsa_certificate.as_posix(),
                "-crl_reason",
                "keyCompromise",
            ]
        )
        revoked_crl = self.root / "revoked.crl.pem"
        self.generate_crl(revoked_crl)
        time.sleep(1.1)
        revoked_response = self.root / "revoked-response.tsr"
        self.issue_response(
            self.request,
            revoked_response,
            self.tsa_certificate,
            self.tsa_key,
        )

        with self.assertRaisesRegex(
            temporal_study_timestamp.TimestampError, "certificate revoked"
        ):
            self.verify(
                response_path=revoked_response,
                revocation_crl_paths=[revoked_crl],
            )

    def test_full_intermediate_chain_requires_every_issuer_crl(self):
        intermediate_key = self.root / "intermediate-key.pem"
        intermediate_request = self.root / "intermediate-request.pem"
        intermediate_certificate = self.root / "intermediate-certificate.pem"
        self.run_openssl(
            [
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                intermediate_key.as_posix(),
                "-out",
                intermediate_request.as_posix(),
                "-subj",
                "/CN=AURA Test Timestamp Intermediate",
                "-sha256",
                "-addext",
                "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-addext",
                "subjectKeyIdentifier=hash",
            ]
        )
        self.run_openssl(
            [
                "x509",
                "-req",
                "-in",
                intermediate_request.as_posix(),
                "-CA",
                self.ca_certificate.as_posix(),
                "-CAkey",
                self.ca_key.as_posix(),
                "-CAcreateserial",
                "-out",
                intermediate_certificate.as_posix(),
                "-days",
                "2",
                "-sha256",
                "-copy_extensions",
                "copy",
            ]
        )

        intermediate_database = self.root / "intermediate-database"
        intermediate_database.mkdir()
        (intermediate_database / "newcerts").mkdir()
        (intermediate_database / "index.txt").write_text("", encoding="ascii")
        (intermediate_database / "crlnumber").write_text("2000\n", encoding="ascii")
        intermediate_config = self.root / "intermediate-ca.cnf"
        intermediate_config.write_text(
            "\n".join(
                [
                    "[ ca ]",
                    "default_ca = local_ca",
                    "[ local_ca ]",
                    f"database = {intermediate_database / 'index.txt'}",
                    f"new_certs_dir = {intermediate_database / 'newcerts'}",
                    f"certificate = {intermediate_certificate}",
                    f"private_key = {intermediate_key}",
                    f"crlnumber = {intermediate_database / 'crlnumber'}",
                    "default_md = sha256",
                    "default_crl_days = 1",
                    "policy = policy_any",
                    "[ policy_any ]",
                    "commonName = supplied",
                    "",
                ]
            ),
            encoding="ascii",
        )
        intermediate_crl = self.root / "intermediate.crl.pem"
        self.run_openssl(
            [
                "ca",
                "-gencrl",
                "-batch",
                "-config",
                intermediate_config.as_posix(),
                "-out",
                intermediate_crl.as_posix(),
            ]
        )

        nested_tsa_key = self.root / "nested-tsa-key.pem"
        nested_tsa_request = self.root / "nested-tsa-request.pem"
        nested_tsa_certificate = self.root / "nested-tsa-certificate.pem"
        self.run_openssl(
            [
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                nested_tsa_key.as_posix(),
                "-out",
                nested_tsa_request.as_posix(),
                "-subj",
                "/CN=AURA Nested Test TSA",
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
        self.run_openssl(
            [
                "x509",
                "-req",
                "-in",
                nested_tsa_request.as_posix(),
                "-CA",
                intermediate_certificate.as_posix(),
                "-CAkey",
                intermediate_key.as_posix(),
                "-CAcreateserial",
                "-out",
                nested_tsa_certificate.as_posix(),
                "-days",
                "2",
                "-sha256",
                "-copy_extensions",
                "copy",
            ]
        )
        response_chain = self.root / "nested-response-chain.pem"
        response_chain.write_bytes(
            intermediate_certificate.read_bytes() + self.ca_certificate.read_bytes()
        )
        nested_response = self.root / "nested-response.tsr"
        self.run_openssl(
            [
                "ts",
                "-reply",
                "-queryfile",
                self.request.as_posix(),
                "-signer",
                nested_tsa_certificate.as_posix(),
                "-inkey",
                nested_tsa_key.as_posix(),
                "-chain",
                response_chain.as_posix(),
                "-tspolicy",
                self.policy_oid,
                "-out",
                nested_response.as_posix(),
            ]
        )
        expected_spki = self.spki_sha256(nested_tsa_certificate)

        report = self.verify(
            response_path=nested_response,
            untrusted_chain_path=intermediate_certificate,
            expected_tsa_spki_sha256=expected_spki,
            revocation_crl_paths=[self.revocation_crl, intermediate_crl],
        )
        self.assertEqual(report["revocation_checked_certificate_count"], 2)
        self.assertEqual(report["revocation_crl_count"], 2)

        with self.assertRaisesRegex(
            temporal_study_timestamp.TimestampError, "exactly every"
        ):
            self.verify(
                response_path=nested_response,
                untrusted_chain_path=intermediate_certificate,
                expected_tsa_spki_sha256=expected_spki,
                revocation_crl_paths=[intermediate_crl],
            )

    def test_unexpected_policy_is_rejected(self):
        with self.assertRaisesRegex(
            temporal_study_timestamp.TimestampError, "request policy"
        ):
            self.verify(expected_policy_oid="1.2.3.4.99")

    def test_unexpected_tsa_signer_is_rejected_even_under_same_root(self):
        other_key = self.root / "other-tsa-key.pem"
        other_request = self.root / "other-tsa-request.pem"
        other_certificate = self.root / "other-tsa-certificate.pem"
        other_response = self.root / "other-tsa-response.tsr"
        self.generate_tsa(
            other_key,
            other_request,
            other_certificate,
            "AURA Other Test TSA",
        )
        self.issue_response(self.request, other_response, other_certificate, other_key)

        with self.assertRaisesRegex(
            temporal_study_timestamp.TimestampError, "expected TSA SPKI"
        ):
            self.verify(
                response_path=other_response,
                untrusted_chain_path=other_certificate,
            )

    def test_declared_registration_cannot_postdate_timestamp_beyond_skew(self):
        self.commitment_payload["registered_at_ms"] += 60 * 60 * 1000
        self.write_commitment()
        temporal_study_timestamp.write_bytes_atomic(
            self.request,
            temporal_study_timestamp.create_request(
                self.commitment, self.policy_oid
            ),
        )
        self.issue_response(
            self.request,
            self.response,
            self.tsa_certificate,
            self.tsa_key,
        )

        with self.assertRaisesRegex(
            temporal_study_timestamp.TimestampError, "declared registration time"
        ):
            self.verify()

    def test_cli_request_and_verify_round_trip(self):
        script = Path(__file__).with_name("temporal_study_timestamp.py")
        cli_request = self.root / "cli-request.tsq"
        cli_response = self.root / "cli-response.tsr"
        verification = self.root / "verification.json"
        subprocess.run(
            [
                sys.executable,
                script.as_posix(),
                "request",
                "--commitment",
                self.commitment.as_posix(),
                "--policy-oid",
                self.policy_oid,
                "--output",
                cli_request.as_posix(),
            ],
            check=True,
            capture_output=True,
        )
        self.issue_response(
            cli_request,
            cli_response,
            self.tsa_certificate,
            self.tsa_key,
        )
        subprocess.run(
            [
                sys.executable,
                script.as_posix(),
                "verify",
                "--commitment",
                self.commitment.as_posix(),
                "--request",
                cli_request.as_posix(),
                "--response",
                cli_response.as_posix(),
                "--ca-file",
                self.ca_certificate.as_posix(),
                "--untrusted-chain",
                self.tsa_certificate.as_posix(),
                "--revocation-crl",
                self.revocation_crl.as_posix(),
                "--expected-policy-oid",
                self.policy_oid,
                "--expected-tsa-spki-sha256",
                self.expected_spki_sha256,
                "--output",
                verification.as_posix(),
                "--require-pass",
            ],
            check=True,
            capture_output=True,
        )

        report = json.loads(verification.read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "pass")


if __name__ == "__main__":
    unittest.main()
