import json
import shutil
import time
import unittest
from pathlib import Path

from ci import temporal_evidence_renewal
from ci import temporal_study_timestamp
from ci import test_temporal_study_timestamp as timestamp_fixture_support


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class TemporalEvidenceRenewalTests(unittest.TestCase):
    renewal_id = "aura_research_archive_2026"

    def setUp(self):
        self.fixture = timestamp_fixture_support.TemporalStudyTimestampTests(
            "test_nonce_bearing_sha256_request_is_created"
        )
        self.fixture.setUp()
        self.root = self.fixture.root
        self.evidence_manifest = self.root / "evidence-manifest.json"
        self.evidence_attestation = self.root / "evidence-attestation.json"
        self.evidence_manifest.write_text(
            json.dumps(
                {
                    "schema_version": "aura.evidence_manifest.v1",
                    "evidence_status": "pass",
                    "source_revision": "a" * 40,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.evidence_attestation.write_text(
            json.dumps(
                {
                    "schema_version": "aura.evidence_manifest_attestation.v1",
                    "manifest_sha256": "b" * 64,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.evidence = [
            ("evidence_manifest", self.evidence_manifest),
            ("evidence_manifest_attestation", self.evidence_attestation),
        ]
        self.commitment_one = self.root / "renewal-01.json"
        self.request_one = self.root / "renewal-01.tsq"
        self.response_one = self.root / "renewal-01.tsr"
        self.write_commitment(
            self.commitment_one,
            temporal_evidence_renewal.create_commitment(
                self.renewal_id,
                1,
                int(time.time() * 1000) - 1000,
                self.evidence,
            ),
        )
        self.issue_timestamp(
            self.commitment_one, self.request_one, self.response_one
        )

    def tearDown(self):
        self.fixture.tearDown()

    def write_commitment(self, path: Path, payload: dict):
        temporal_evidence_renewal.crypto_support.write_json_atomic(path, payload)

    def issue_timestamp(self, commitment: Path, request: Path, response: Path):
        temporal_study_timestamp.write_bytes_atomic(
            request,
            temporal_study_timestamp.create_request_for_document(
                commitment.read_bytes(), self.fixture.policy_oid
            ),
        )
        self.fixture.issue_response(
            request,
            response,
            self.fixture.tsa_certificate,
            self.fixture.tsa_key,
        )

    def verify(self, **overrides):
        arguments = {
            "commitment_path": self.commitment_one,
            "evidence_specifications": self.evidence,
            "request_path": self.request_one,
            "response_path": self.response_one,
            "ca_file_path": self.fixture.ca_certificate,
            "untrusted_chain_path": self.fixture.tsa_certificate,
            "revocation_crl_paths": [self.fixture.revocation_crl],
            "expected_policy_oid": self.fixture.policy_oid,
            "expected_tsa_spki_sha256": self.fixture.expected_spki_sha256,
        }
        arguments.update(overrides)
        return temporal_evidence_renewal.verify_renewal(**arguments)

    def create_second_link(self):
        time.sleep(4.1)
        commitment = self.root / "renewal-02.json"
        request = self.root / "renewal-02.tsq"
        response = self.root / "renewal-02.tsr"
        self.write_commitment(
            commitment,
            temporal_evidence_renewal.create_commitment(
                self.renewal_id,
                2,
                int(time.time() * 1000) - 1000,
                self.evidence,
                self.resolved_package(
                    self.commitment_one, self.request_one, self.response_one
                ),
            ),
        )
        self.issue_timestamp(commitment, request, response)
        return commitment, request, response

    def package(self, commitment: Path, request: Path, response: Path) -> dict:
        return {
            "commitment": commitment.as_posix(),
            "timestamp_request": request.as_posix(),
            "timestamp_response": response.as_posix(),
            "ca_file": self.fixture.ca_certificate.as_posix(),
            "untrusted_chain": self.fixture.tsa_certificate.as_posix(),
            "revocation_crls": [self.fixture.revocation_crl.as_posix()],
            "expected_policy_oid": self.fixture.policy_oid,
            "expected_tsa_spki_sha256": self.fixture.expected_spki_sha256,
        }

    def resolved_package(
        self, commitment: Path, request: Path, response: Path
    ) -> dict:
        package = self.package(commitment, request, response)
        for field in (
            "commitment",
            "timestamp_request",
            "timestamp_response",
            "ca_file",
            "untrusted_chain",
        ):
            package[field] = Path(package[field]) if package[field] is not None else None
        package["revocation_crls"] = [
            Path(path) for path in package["revocation_crls"]
        ]
        return package

    def write_index(self, renewals: list[dict]) -> Path:
        path = self.root / "renewal-index.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": temporal_evidence_renewal.INDEX_SCHEMA_VERSION,
                    "evidence_items": [
                        {"label": label, "path": item_path.as_posix()}
                        for label, item_path in self.evidence
                    ],
                    "renewals": renewals,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def test_initial_renewal_verifies_with_exact_non_ers_claim(self):
        report = self.verify()

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["sequence_number"], 1)
        self.assertEqual(report["evidence_item_count"], 2)
        self.assertEqual(
            report["renewal_profile"],
            "aura_rfc3161_renewal_envelope_not_rfc4998_ers",
        )
        self.assertFalse(report["rfc4998_ers_conformance"])
        self.assertTrue(report["all_preserved_evidence_bytes_rehashed"])
        self.assertEqual(
            report["revocation_assurance"], "full_chain_crl_at_gen_time"
        )

    def test_changed_preserved_evidence_is_rejected(self):
        self.evidence_manifest.write_text("tampered\n", encoding="utf-8")

        with self.assertRaisesRegex(
            temporal_evidence_renewal.RenewalError, "does not match"
        ):
            self.verify()

    def test_direct_api_rejects_duplicate_evidence_paths(self):
        with self.assertRaisesRegex(
            temporal_evidence_renewal.RenewalError, "valid and unique"
        ):
            temporal_evidence_renewal.create_commitment(
                self.renewal_id,
                1,
                int(time.time() * 1000),
                [
                    ("first_copy", self.evidence_manifest),
                    ("second_copy", self.evidence_manifest),
                ],
            )

    def test_non_initial_commitment_requires_predecessor_files(self):
        with self.assertRaisesRegex(
            temporal_evidence_renewal.RenewalError, "requires a predecessor"
        ):
            temporal_evidence_renewal.create_commitment(
                self.renewal_id,
                2,
                int(time.time() * 1000),
                self.evidence,
            )

    def test_timestamp_renewal_cannot_replace_the_evidence_set(self):
        replacement = self.root / "replacement.json"
        replacement.write_text("{}\n", encoding="utf-8")

        with self.assertRaisesRegex(
            temporal_evidence_renewal.RenewalError, "evidence set changed"
        ):
            temporal_evidence_renewal.create_commitment(
                self.renewal_id,
                2,
                int(time.time() * 1000),
                [("replacement", replacement)],
                self.resolved_package(
                    self.commitment_one, self.request_one, self.response_one
                ),
            )

    def test_second_renewal_link_verifies_predecessor_binding(self):
        commitment, request, response = self.create_second_link()

        report = self.verify(
            commitment_path=commitment,
            request_path=request,
            response_path=response,
            previous_package=self.resolved_package(
                self.commitment_one, self.request_one, self.response_one
            ),
        )

        self.assertEqual(report["sequence_number"], 2)
        self.assertTrue(report["renewal_follows_previous_timestamp"])
        self.assertLess(
            report["previous_latest_trusted_time_unix_ms"],
            report["earliest_trusted_time_unix_ms"],
        )

    def test_tampered_predecessor_response_is_rejected(self):
        commitment, request, response = self.create_second_link()
        original = self.response_one.read_bytes()
        tampered = bytearray(original)
        tampered[-1] ^= 1
        self.response_one.write_bytes(tampered)

        with self.assertRaisesRegex(
            temporal_evidence_renewal.RenewalError, "predecessor package"
        ):
            self.verify(
                commitment_path=commitment,
                request_path=request,
                response_path=response,
                previous_package=self.resolved_package(
                    self.commitment_one, self.request_one, self.response_one
                ),
            )

        self.response_one.write_bytes(original)
        changed_trust_package = self.resolved_package(
            self.commitment_one, self.request_one, self.response_one
        )
        changed_trust_package["expected_policy_oid"] = "1.2.3.4.999"
        with self.assertRaisesRegex(
            temporal_evidence_renewal.RenewalError, "predecessor package"
        ):
            self.verify(
                commitment_path=commitment,
                request_path=request,
                response_path=response,
                previous_package=changed_trust_package,
            )

    def test_two_link_index_reverifies_every_raw_timestamp(self):
        commitment, request, response = self.create_second_link()
        index = self.write_index(
            [
                self.package(self.commitment_one, self.request_one, self.response_one),
                self.package(commitment, request, response),
            ]
        )

        report = temporal_evidence_renewal.verify_chain(index)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["renewal_link_count"], 2)
        self.assertTrue(report["all_links_reverified_from_raw_inputs"])
        self.assertEqual(report["revocation_checked_timestamp_count"], 2)
        self.assertFalse(report["rfc4998_ers_conformance"])

    def test_chain_rejects_missing_crl(self):
        package = self.package(
            self.commitment_one, self.request_one, self.response_one
        )
        package["revocation_crls"] = []
        index = self.write_index([package])

        with self.assertRaisesRegex(
            temporal_evidence_renewal.RenewalError, "CRL list"
        ):
            temporal_evidence_renewal.verify_chain(index)

    def test_chain_output_cannot_overwrite_preserved_evidence(self):
        index = self.write_index(
            [self.package(self.commitment_one, self.request_one, self.response_one)]
        )

        with self.assertRaisesRegex(
            temporal_evidence_renewal.RenewalError, "must not overwrite"
        ):
            temporal_evidence_renewal.verify_chain(index, self.evidence_manifest)


if __name__ == "__main__":
    unittest.main()
