import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from ci import domain_reproduction_manifest as materializer


class DomainReproductionManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.files = {
            "corpus.bin": b"private corpus",
            "request.tsq": b"DER request",
            "response.tsr": b"DER response",
            "leaf.der": b"leaf certificate",
            "root.der": b"root certificate",
            "issuer.crl.der": b"issuer CRL",
        }
        for name, payload in self.files.items():
            (self.root / name).write_bytes(payload)
        self.descriptor = {
            "schema_version": materializer.DESCRIPTOR_SCHEMA_VERSION,
            "study_id": "external_study_2026",
            "result_id": "result_2026",
            "preregistration_canonical_sha256": "a" * 64,
            "result_bundle_sha256": "b" * 64,
            "final_manifest_sha256": "c" * 64,
            "evidence_bundle_canonical_sha256": "d" * 64,
            "primary_artifacts": [
                {"role": "corpus", "ordinal": 0, "path": "corpus.bin"}
            ],
            "timestamp_materials": [
                {
                    "subject_kind": "preregistration_attestation",
                    "reviewer_index": None,
                    "request_path": "request.tsq",
                    "response_path": "response.tsr",
                    "certificate_chain_der_paths": ["leaf.der", "root.der"],
                    "revocation_crl_der_paths": ["issuer.crl.der"],
                }
            ],
            "public_distribution_permitted": False,
            "independent_recomputation_completed": False,
        }
        self.descriptor_path = self.root / "descriptor.json"
        self.output_path = self.root / "manifest.json"
        self.write_descriptor()

    def tearDown(self):
        self.temporary.cleanup()

    def write_descriptor(self):
        self.descriptor_path.write_text(
            json.dumps(self.descriptor), encoding="utf-8"
        )

    def test_materializes_exact_path_free_file_identities(self):
        manifest = materializer.materialize(self.descriptor_path, self.output_path)

        persisted = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(persisted, manifest)
        self.assertNotIn(str(self.root), self.output_path.read_text(encoding="utf-8"))
        self.assertNotIn("corpus.bin", self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["file_count"], 6)
        self.assertEqual(
            manifest["primary_artifacts"][0]["digest_kind"],
            "raw_file_sha256",
        )
        self.assertEqual(manifest["primary_artifacts"][0]["covered_file_count"], 1)
        self.assertEqual(
            manifest["primary_artifacts"][0]["sha256"],
            __import__("hashlib").sha256(self.files["corpus.bin"]).hexdigest(),
        )
        self.assertFalse(manifest["independent_recomputation_completed"])

    def test_rejects_duplicate_descriptor_fields(self):
        self.descriptor_path.write_text(
            '{"schema_version":"one","schema_version":"two"}',
            encoding="utf-8",
        )

        with self.assertRaisesRegex(materializer.MaterializationError, "duplicate JSON field"):
            materializer.materialize(self.descriptor_path, self.output_path)

    def test_rejects_symbolic_artifact(self):
        (self.root / "corpus.bin").unlink()
        (self.root / "corpus.bin").symlink_to(self.root / "request.tsq")

        with self.assertRaisesRegex(materializer.MaterializationError, "symbolic|unsafe"):
            materializer.materialize(self.descriptor_path, self.output_path)

    def test_rejects_completed_recomputation_claim(self):
        self.descriptor["independent_recomputation_completed"] = True
        self.write_descriptor()

        with self.assertRaisesRegex(materializer.MaterializationError, "completed rerun"):
            materializer.materialize(self.descriptor_path, self.output_path)

    def test_rejects_duplicate_timestamp_certificate_bytes(self):
        self.descriptor["timestamp_materials"][0]["certificate_chain_der_paths"] = [
            "leaf.der",
            "leaf.der",
        ]
        self.write_descriptor()

        with self.assertRaisesRegex(materializer.MaterializationError, "duplicate DER"):
            materializer.materialize(self.descriptor_path, self.output_path)

    def test_source_tree_uses_release_digest_contract(self):
        source_root = self.root / "source"
        source_root.mkdir()
        subprocess.run(["git", "init", "--quiet"], cwd=source_root, check=True)
        (source_root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        subprocess.run(["git", "add", "Cargo.toml"], cwd=source_root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=AURA Test",
                "-c",
                "user.email=aura-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
            cwd=source_root,
            check=True,
        )
        self.descriptor["primary_artifacts"] = [
            {"role": "source_tree", "ordinal": 0, "path": "source"}
        ]
        self.write_descriptor()

        manifest = materializer.materialize(self.descriptor_path, self.output_path)

        artifact = manifest["primary_artifacts"][0]
        expected, count, byte_length, _ = materializer.source_tree_support.source_tree_identity(
            source_root
        )
        self.assertEqual(artifact["digest_kind"], "build_source_tree_v2")
        self.assertEqual(artifact["sha256"], expected)
        self.assertEqual(artifact["covered_file_count"], count)
        self.assertEqual(artifact["byte_length"], byte_length)

    def test_rejects_output_inside_source_tree(self):
        source_root = self.root / "source"
        source_root.mkdir()
        subprocess.run(["git", "init", "--quiet"], cwd=source_root, check=True)
        (source_root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        subprocess.run(["git", "add", "Cargo.toml"], cwd=source_root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=AURA Test",
                "-c",
                "user.email=aura-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
            cwd=source_root,
            check=True,
        )
        self.descriptor["primary_artifacts"] = [
            {"role": "source_tree", "ordinal": 0, "path": "source"}
        ]
        self.write_descriptor()

        with self.assertRaisesRegex(materializer.MaterializationError, "outside source_tree"):
            materializer.materialize(
                self.descriptor_path, source_root / "reproduction-manifest.json"
            )

    def test_rejects_dirty_source_tree(self):
        source_root = self.root / "source"
        source_root.mkdir()
        subprocess.run(["git", "init", "--quiet"], cwd=source_root, check=True)
        (source_root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        self.descriptor["primary_artifacts"] = [
            {"role": "source_tree", "ordinal": 0, "path": "source"}
        ]
        self.write_descriptor()

        with self.assertRaisesRegex(materializer.MaterializationError, "must be clean"):
            materializer.materialize(self.descriptor_path, self.output_path)


if __name__ == "__main__":
    unittest.main()
