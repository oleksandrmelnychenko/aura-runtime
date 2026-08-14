import os
import stat
import tempfile
import unittest
import warnings
import zipfile
from hashlib import sha256
from pathlib import Path
from unittest import mock

from ci import release_artifact_ingest as ingest


EXPECTED_PROMOTION_FILES = frozenset(
    {
        "audit-evidence.json",
        "community-surface-report.json",
        "contract-evidence.json",
        "dataset-evidence.json",
        "evidence-manifest.json",
        "ffi-header-smoke.json",
        "ffi-state-sync-soak.json",
        "kids-memory-health.json",
        "kids-preprod-dry-run-matrix.json",
        "performance/world-performance-summary.json",
        "pilot-gate-report.json",
        "pilot-regression-report.json",
        "pilot-review-signoff-bundle.json",
        "pilot-review-signoffs.json",
        "pilot-shadow-bundle.json",
        "pilot-signoff-verification.json",
        "refactor-candidate.json",
        "refactor-diff-report.json",
        "release-report.json",
        "temporal-shadow-report.json",
        "temporal-shadow-telemetry-validation.json",
        "world-lifecycle-suite-report.json",
    }
)

EXPECTED_APPLE_FILES = frozenset(
    {
        "apple-release-verification.json",
        "apple-reproducibility.json",
        "apple-verified-dist/AuraAgentFFI.xcframework/Info.plist",
        "apple-verified-dist/AuraAgentFFI.xcframework/ios-arm64/Headers/aura_ffi.h",
        "apple-verified-dist/AuraAgentFFI.xcframework/ios-arm64/libaura_agent_ffi.a",
        "apple-verified-dist/AuraAgentFFI.xcframework/ios-arm64_x86_64-maccatalyst/Headers/aura_ffi.h",
        "apple-verified-dist/AuraAgentFFI.xcframework/ios-arm64_x86_64-maccatalyst/libaura_agent_ffi_maccatalyst.a",
        "apple-verified-dist/AuraAgentFFI.xcframework/ios-arm64_x86_64-simulator/Headers/aura_ffi.h",
        "apple-verified-dist/AuraAgentFFI.xcframework/ios-arm64_x86_64-simulator/libaura_agent_ffi_ios_sim.a",
        "apple-verified-dist/execution-policy-trust-keyring.json",
        "apple-verified-dist/release-manifest.json",
        "apple-verified-dist/runtime-artifact-descriptor.json",
        "apple-verified-dist/runtime-artifact-identities.env",
    }
)

EXPECTED_PILOT_SIGNOFF_FILES = frozenset(
    {
        "pilot-review-signoff-bundle.json",
        "pilot-review-signoffs.json",
        "pilot-signoff-verification.json",
    }
)


class ReleaseArtifactIngestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.archive_index = 0

    def tearDown(self):
        self.temporary.cleanup()

    def archive(
        self,
        *,
        profile: str = "promotion",
        omitted: str | None = None,
        extra: str | None = None,
        symlink: str | None = None,
        duplicate: str | None = None,
    ) -> Path:
        self.archive_index += 1
        path = self.root / f"{profile}-{self.archive_index}.zip"
        expected = {
            "promotion": EXPECTED_PROMOTION_FILES,
            "apple": EXPECTED_APPLE_FILES,
            "pilot_signoff": EXPECTED_PILOT_SIGNOFF_FILES,
        }[profile]
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for relative in sorted(expected):
                if relative == omitted:
                    continue
                if relative == symlink:
                    info = zipfile.ZipInfo(relative)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(info, "target")
                else:
                    archive.writestr(relative, b"{}\n")
            if extra is not None:
                archive.writestr(extra, b"extra\n")
            if duplicate is not None:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr(duplicate, b"duplicate\n")
        return path

    @staticmethod
    def identity(path: Path) -> tuple[str, int]:
        raw = path.read_bytes()
        return sha256(raw).hexdigest(), len(raw)

    def extract(self, archive: Path, profile: str = "promotion") -> Path:
        digest, size = self.identity(archive)
        output = self.root / "output"
        ingest.extract_artifact(archive, digest, size, profile, output)
        return output

    def test_exact_profile_is_extracted_with_private_regular_files(self):
        archive = self.archive()
        output = self.extract(archive)
        actual = {
            path.relative_to(output).as_posix()
            for path in output.rglob("*")
            if path.is_file()
        }
        self.assertEqual(actual, EXPECTED_PROMOTION_FILES)
        for path in output.rglob("*"):
            if path.is_file():
                self.assertTrue(stat.S_ISREG(path.lstat().st_mode))
                self.assertEqual(path.stat().st_nlink, 1)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_profile_contracts_and_apple_happy_path_are_independent(self):
        self.assertEqual(ingest.PROMOTION_FILES, EXPECTED_PROMOTION_FILES)
        self.assertEqual(ingest.APPLE_FILES, EXPECTED_APPLE_FILES)
        self.assertEqual(
            ingest.PILOT_SIGNOFF_FILES, EXPECTED_PILOT_SIGNOFF_FILES
        )
        archive = self.archive(profile="apple")
        output = self.extract(archive, profile="apple")
        actual = {
            path.relative_to(output).as_posix()
            for path in output.rglob("*")
            if path.is_file()
        }
        self.assertEqual(actual, EXPECTED_APPLE_FILES)

        pilot_archive = self.archive(profile="pilot_signoff")
        pilot_output = self.root / "pilot-output"
        digest, size = self.identity(pilot_archive)
        ingest.extract_artifact(
            pilot_archive,
            digest,
            size,
            "pilot_signoff",
            pilot_output,
        )
        self.assertEqual(
            {
                path.relative_to(pilot_output).as_posix()
                for path in pilot_output.rglob("*")
                if path.is_file()
            },
            EXPECTED_PILOT_SIGNOFF_FILES,
        )

    def test_pilot_signoff_profile_has_narrow_transport_and_expansion_limits(self):
        self.assertEqual(ingest.PROFILE_ARCHIVE_LIMITS["pilot_signoff"], 1024 * 1024)
        self.assertEqual(ingest.PROFILE_EXTRACTED_LIMITS["pilot_signoff"], 512 * 1024)
        self.assertEqual(ingest.PROFILE_FILE_LIMITS["pilot_signoff"], 256 * 1024)
        archive = self.root / "oversized-pilot-signoff.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for relative in sorted(EXPECTED_PILOT_SIGNOFF_FILES):
                raw = b"x" * (256 * 1024 + 1) if relative.endswith("bundle.json") else b"{}\n"
                output.writestr(relative, raw)
        digest, size = self.identity(archive)
        with self.assertRaises(ingest.ArtifactIngestError):
            ingest.extract_artifact(
                archive,
                digest,
                size,
                "pilot_signoff",
                self.root / "oversized-pilot-output",
            )

    def test_wrong_digest_and_byte_length_fail_closed(self):
        archive = self.archive()
        digest, size = self.identity(archive)
        with self.assertRaises(ingest.ArtifactIngestError):
            ingest.extract_artifact(
                archive, "0" * 64, size, "promotion", self.root / "wrong-digest"
            )
        with self.assertRaises(ingest.ArtifactIngestError):
            ingest.extract_artifact(
                archive, digest, size + 1, "promotion", self.root / "wrong-size"
            )

    def test_missing_extra_duplicate_and_symlink_members_are_rejected(self):
        first = sorted(ingest.PROMOTION_FILES)[0]
        cases = (
            self.archive(omitted=first),
            self.archive(extra="unexpected.json"),
            self.archive(duplicate=first),
            self.archive(symlink=first),
        )
        for index, archive in enumerate(cases):
            digest, size = self.identity(archive)
            with self.subTest(index=index):
                with self.assertRaises(ingest.ArtifactIngestError):
                    ingest.extract_artifact(
                        archive,
                        digest,
                        size,
                        "promotion",
                        self.root / f"rejected-{index}",
                    )

    def test_fresh_output_and_non_hardlinked_archive_are_required(self):
        archive = self.archive()
        digest, size = self.identity(archive)
        existing = self.root / "existing"
        existing.mkdir()
        with self.assertRaises(ingest.ArtifactIngestError):
            ingest.extract_artifact(
                archive, digest, size, "promotion", existing
            )

        alias = self.root / "archive-alias.zip"
        os.link(archive, alias)
        with self.assertRaises(ingest.ArtifactIngestError):
            ingest.extract_artifact(
                archive,
                digest,
                size,
                "promotion",
                self.root / "hardlink-rejected",
            )

    def test_unsafe_parent_and_archive_symlink_are_rejected(self):
        archive = self.archive()
        digest, size = self.identity(archive)
        archive_link = self.root / "archive-link.zip"
        archive_link.symlink_to(archive)
        with self.assertRaises(ingest.ArtifactIngestError):
            ingest.extract_artifact(
                archive_link,
                digest,
                size,
                "promotion",
                self.root / "archive-link-output",
            )

        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        parent_link = self.root / "parent-link"
        parent_link.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaises(ingest.ArtifactIngestError):
            ingest.extract_artifact(
                archive,
                digest,
                size,
                "promotion",
                parent_link / "output",
            )

    def test_published_output_must_match_the_verified_staging_inode(self):
        archive = self.archive()
        digest, size = self.identity(archive)
        output = self.root / "published"
        escaped = self.root / "verified-escaped"
        original = ingest._rename_noreplace_at

        def swap_staging(parent_descriptor, source_name, target_name):
            os.rename(
                source_name,
                escaped.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            os.mkdir(source_name, mode=0o700, dir_fd=parent_descriptor)
            replacement = os.open(
                source_name,
                ingest._open_flags(directory=True),
                dir_fd=parent_descriptor,
            )
            try:
                marker = os.open(
                    "attacker-marker",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=replacement,
                )
                os.write(marker, b"do not delete\n")
                os.close(marker)
            finally:
                os.close(replacement)
            original(parent_descriptor, source_name, target_name)

        with mock.patch.object(
            ingest, "_rename_noreplace_at", side_effect=swap_staging
        ):
            with self.assertRaisesRegex(
                ingest.ArtifactIngestError, "replaced during publication"
            ):
                ingest.extract_artifact(
                    archive,
                    digest,
                    size,
                    "promotion",
                    output,
                )

        self.assertEqual(
            (output / "attacker-marker").read_bytes(), b"do not delete\n"
        )
        self.assertTrue((escaped / "evidence-manifest.json").is_file())

    def test_final_name_is_rechecked_after_the_published_tree_snapshot(self):
        archive = self.archive()
        digest, size = self.identity(archive)
        output = self.root / "published-final"
        escaped = self.root / "verified-final-escaped"
        original = ingest._snapshot_extracted_tree
        calls = 0

        def swap_after_final_snapshot(descriptor, prefix=()):
            nonlocal calls
            result = original(descriptor, prefix)
            if not prefix:
                calls += 1
                if calls == 2:
                    output.rename(escaped)
                    output.mkdir(mode=0o700)
                    (output / "attacker-marker").write_bytes(b"replacement\n")
            return result

        with mock.patch.object(
            ingest,
            "_snapshot_extracted_tree",
            side_effect=swap_after_final_snapshot,
        ):
            with self.assertRaisesRegex(
                ingest.ArtifactIngestError,
                "replaced after final verification",
            ):
                ingest.extract_artifact(
                    archive,
                    digest,
                    size,
                    "promotion",
                    output,
                )

        self.assertEqual(
            (output / "attacker-marker").read_bytes(), b"replacement\n"
        )
        self.assertTrue((escaped / "evidence-manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
