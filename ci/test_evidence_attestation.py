import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
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

    def test_malformed_attestation_types_fail_closed(self):
        payload = self.sign()
        payload["key_id"] = []
        payload["signature_base64"] = []
        evidence_attestation.write_json_atomic(self.attestation, payload)

        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "key_id is invalid"
        ):
            evidence_attestation.verify_manifest(
                self.manifest, self.attestation, self.public_key
            )

        payload["key_id"] = "release-test-key"
        evidence_attestation.write_json_atomic(self.attestation, payload)
        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "signature is malformed"
        ):
            evidence_attestation.verify_manifest(
                self.manifest, self.attestation, self.public_key
            )

    def test_duplicate_and_nonfinite_attestation_json_is_rejected(self):
        payload = self.sign()
        serialized = json.dumps(payload)
        self.attestation.write_text(
            serialized[:-1] + ',"key_id":"duplicate"}', encoding="utf-8"
        )
        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "invalid JSON"
        ):
            evidence_attestation.verify_manifest(
                self.manifest, self.attestation, self.public_key
            )

        self.attestation.write_text(
            serialized[:-1] + ',"unexpected":1e999}', encoding="utf-8"
        )
        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "invalid JSON"
        ):
            evidence_attestation.verify_manifest(
                self.manifest, self.attestation, self.public_key
            )

        self.attestation.write_text(
            serialized[:-1] + ',"unexpected":NaN}', encoding="utf-8"
        )
        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "invalid JSON"
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

    def test_atomic_writer_rejects_a_swapped_staging_inode(self):
        output = self.root / "report.json"
        escaped = self.root / "verified-staging.json"
        original = evidence_attestation.os.replace

        def swap_staging(source, target, *, src_dir_fd, dst_dir_fd):
            os.rename(
                source,
                escaped.name,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=src_dir_fd,
            )
            replacement = os.open(
                source,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=src_dir_fd,
            )
            os.write(replacement, b'{"attacker":true}\n')
            os.close(replacement)
            original(
                source,
                target,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )

        with mock.patch.object(
            evidence_attestation.os,
            "replace",
            side_effect=swap_staging,
        ):
            with self.assertRaisesRegex(
                evidence_attestation.AttestationError,
                "replaced during publication",
            ):
                evidence_attestation.write_json_atomic(output, {"status": "pass"})

        self.assertEqual(output.read_bytes(), b'{"attacker":true}\n')
        self.assertEqual(
            json.loads(escaped.read_text(encoding="utf-8")),
            {"status": "pass"},
        )

    def test_atomic_writer_never_deletes_a_swapped_staging_name_on_error(self):
        output = self.root / "report.json"
        escaped = self.root / "verified-staging.json"
        replacement_name = None

        def fail_after_swap(source, _target, *, src_dir_fd, dst_dir_fd):
            nonlocal replacement_name
            self.assertEqual(src_dir_fd, dst_dir_fd)
            replacement_name = source
            os.rename(
                source,
                escaped.name,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=src_dir_fd,
            )
            replacement = os.open(
                source,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=src_dir_fd,
            )
            os.write(replacement, b"do not delete\n")
            os.close(replacement)
            raise OSError("fixture replace failure")

        with mock.patch.object(
            evidence_attestation.os,
            "replace",
            side_effect=fail_after_swap,
        ):
            with self.assertRaisesRegex(
                evidence_attestation.AttestationError,
                "could not be published",
            ):
                evidence_attestation.write_json_atomic(output, {"status": "pass"})

        self.assertIsNotNone(replacement_name)
        self.assertEqual((self.root / replacement_name).read_bytes(), b"do not delete\n")
        self.assertEqual(
            json.loads(escaped.read_text(encoding="utf-8")),
            {"status": "pass"},
        )
        self.assertFalse(output.exists())

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

    def test_bounded_reader_rejects_oversized_input(self):
        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "size must be within"
        ):
            evidence_attestation.read_bounded(
                self.manifest,
                self.manifest.stat().st_size - 1,
                "test manifest",
            )

    @unittest.skipIf(os.name == "nt", "POSIX symbolic-link policy")
    def test_bounded_reader_rejects_symbolic_link(self):
        symbolic_link = self.root / "manifest-link.json"
        symbolic_link.symlink_to(self.manifest)

        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "symbolic"
        ):
            evidence_attestation.read_bounded(
                symbolic_link,
                evidence_attestation.MAX_MANIFEST_BYTES,
                "test manifest",
            )

    @unittest.skipIf(os.name == "nt", "POSIX regular-file policy")
    def test_bounded_reader_rejects_fifo_without_opening_it(self):
        fifo = self.root / "manifest.fifo"
        os.mkfifo(fifo)

        with self.assertRaisesRegex(
            evidence_attestation.AttestationError, "not a regular file"
        ):
            evidence_attestation.read_bounded(
                fifo,
                evidence_attestation.MAX_MANIFEST_BYTES,
                "test manifest",
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

    def test_public_key_path_swap_cannot_change_verified_key(self):
        self.sign()
        original_public_key = self.public_key.read_bytes()
        replacement_private = self.root / "replacement-private.pem"
        replacement_public = self.root / "replacement-public.pem"
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
        original_snapshot = evidence_attestation.private_key_snapshot

        def swap_path_after_read(payload):
            self.public_key.write_bytes(replacement_public.read_bytes())
            return original_snapshot(payload)

        with mock.patch.object(
            evidence_attestation,
            "private_key_snapshot",
            side_effect=swap_path_after_read,
        ):
            report = evidence_attestation.verify_manifest(
                self.manifest,
                self.attestation,
                self.public_key,
                "release-test-key",
            )

        self.assertEqual(report["status"], "pass")
        self.assertNotEqual(self.public_key.read_bytes(), original_public_key)


if __name__ == "__main__":
    unittest.main()
