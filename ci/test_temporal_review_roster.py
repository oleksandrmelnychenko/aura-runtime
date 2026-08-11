import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ci import temporal_review_roster


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class TemporalReviewRosterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.roster_path = self.root / "roster.json"
        self.private_key = self.root / "coordinator.private.pem"
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
        self.private_key.chmod(0o600)
        self.roster = self.valid_roster()
        self.write_roster()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def valid_roster():
        participants = []
        for token, affiliation, role, seed in (
            ("adjudicator_c_77b901", "affiliation_c_77b901", "adjudicator", 1),
            ("reviewer_a_8f2c10", "affiliation_a_8f2c10", "reviewer", 2),
            ("reviewer_b_41ad22", "affiliation_b_41ad22", "reviewer", 3),
        ):
            participants.append(
                {
                    "participant_token": token,
                    "affiliation_token": affiliation,
                    "role": role,
                    "signing_key_id": f"{token}.key",
                    "signing_key_spki_sha256": f"{seed:x}" * 64,
                    "eligibility_record_sha256": f"{seed + 3:x}" * 64,
                    "affiliation_evidence_sha256": f"{seed + 6:x}" * 64,
                    "conflict_declaration_sha256": f"{seed + 9:x}" * 64,
                    "blinding_acknowledgement_sha256": f"{seed + 12:x}" * 64,
                }
            )
        return {
            "schema_version": "aura.military.temporal_review_roster.v1",
            "roster_id": "temporal_roster_2026_01",
            "study_id": "external_temporal_study_2026",
            "preregistration_canonical_sha256": "a" * 64,
            "study_commitment_canonical_sha256": "b" * 64,
            "packet_id": "temporal_round_2026_01",
            "packet_canonical_sha256": "c" * 64,
            "protocol": {
                "distinct_reviewer_affiliations": True,
                "independent_adjudicator": True,
                "conflict_screening_records": True,
                "blinding_acknowledgements": True,
                "post_timestamp_changes_forbidden": True,
            },
            "participants": participants,
        }

    def write_roster(self):
        self.roster_path.write_text(
            json.dumps(self.roster, indent=2) + "\n", encoding="utf-8"
        )

    def test_valid_roster_signs_without_exporting_governance_records(self):
        attestation = temporal_review_roster.sign_roster(
            self.roster_path, self.private_key, "study_coordinator_roster_2026"
        )

        self.assertEqual(attestation["signature_algorithm"], "Ed25519")
        self.assertNotIn("participants", attestation)
        self.assertNotIn("conflict_declaration_sha256", attestation)

    def test_duplicate_affiliation_is_rejected(self):
        self.roster["participants"][2]["affiliation_token"] = self.roster[
            "participants"
        ][1]["affiliation_token"]
        self.write_roster()

        with self.assertRaisesRegex(
            temporal_review_roster.RosterError, "identities must be distinct"
        ):
            temporal_review_roster.load_roster(self.roster_path)

    def test_post_timestamp_change_permission_cannot_be_disabled(self):
        self.roster["protocol"]["post_timestamp_changes_forbidden"] = False
        self.write_roster()

        with self.assertRaisesRegex(
            temporal_review_roster.RosterError, "not high assurance"
        ):
            temporal_review_roster.load_roster(self.roster_path)

    def test_personal_identifier_field_is_rejected(self):
        roster = copy.deepcopy(self.roster)
        roster["participants"][0]["email"] = "not-allowed@example.test"
        self.roster = roster
        self.write_roster()

        with self.assertRaisesRegex(
            temporal_review_roster.RosterError, "participant fields"
        ):
            temporal_review_roster.load_roster(self.roster_path)

    def test_private_key_permissions_are_enforced(self):
        self.private_key.chmod(0o644)

        with self.assertRaisesRegex(
            temporal_review_roster.RosterError, "permissions"
        ):
            temporal_review_roster.sign_roster(
                self.roster_path,
                self.private_key,
                "study_coordinator_roster_2026",
            )


if __name__ == "__main__":
    unittest.main()
