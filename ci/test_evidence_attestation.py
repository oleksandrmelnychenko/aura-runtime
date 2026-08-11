import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ci import evidence_attestation


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class EvidenceAttestationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private_key = self.root / "private.pem"
        self.public_key = self.root / "public.pem"
        self.manifest = self.root / "evidence-manifest.json"
        self.attestation = self.root / "evidence-manifest.attestation.json"
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
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": "aura.evidence_manifest.v1",
                    "evidence_status": "pass",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def sign(self):
        payload = evidence_attestation.sign_manifest(
            self.manifest, self.private_key, "release-test-key"
        )
        evidence_attestation.write_json_atomic(self.attestation, payload)
        return payload

    def test_signed_manifest_verifies_with_trusted_public_key(self):
        self.sign()

        report = evidence_attestation.verify_manifest(
            self.manifest,
            self.attestation,
            self.public_key,
            "release-test-key",
        )

        self.assertEqual(report["status"], "pass")

    def test_manifest_tampering_is_rejected(self):
        self.sign()
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": "aura.evidence_manifest.v1",
                    "evidence_status": "pass",
                    "tampered": True,
                }
            )
            + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "digest does not match"
        ):
            evidence_attestation.verify_manifest(
                self.manifest, self.attestation, self.public_key
            )

    def test_untrusted_key_id_is_rejected(self):
        self.sign()

        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "key_id is not trusted"
        ):
            evidence_attestation.verify_manifest(
                self.manifest,
                self.attestation,
                self.public_key,
                "another-key",
            )

    def test_attestation_claim_tampering_is_rejected(self):
        payload = self.sign()
        payload["key_id"] = "attacker-key"
        evidence_attestation.write_json_atomic(self.attestation, payload)

        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "OpenSSL command failed"
        ):
            evidence_attestation.verify_manifest(
                self.manifest, self.attestation, self.public_key
            )

    def test_invalid_key_id_is_rejected_before_signing(self):
        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "key_id must be"
        ):
            evidence_attestation.sign_manifest(
                self.manifest, self.private_key, "contains spaces"
            )

    def test_output_cannot_overwrite_an_input(self):
        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "must not overwrite"
        ):
            evidence_attestation.ensure_distinct_output(
                self.manifest,
                [self.manifest, self.private_key],
            )

    def test_nonpassing_manifest_is_rejected(self):
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": "aura.evidence_manifest.v1",
                    "evidence_status": "fail",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "only a passing"
        ):
            evidence_attestation.sign_manifest(
                self.manifest, self.private_key, "release-test-key"
            )

    @unittest.skipIf(os.name == "nt", "POSIX permission check")
    def test_group_readable_private_key_is_rejected(self):
        os.chmod(self.private_key, 0o640)

        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "permissions"
        ):
            evidence_attestation.sign_manifest(
                self.manifest, self.private_key, "release-test-key"
            )


if __name__ == "__main__":
    unittest.main()
