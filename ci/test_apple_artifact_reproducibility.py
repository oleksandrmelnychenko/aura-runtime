import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ci.apple_artifact import APPLE_ARTIFACT_FILE_LIMITS
from ci.apple_artifact_reproducibility import (
    ALLOWED_ARTIFACT_COMMIT_PATHS,
    ARCHIVE_PATHS,
    REQUIRED_ARTIFACT_COMMIT_PATHS,
    ReproducibilityError,
    MAX_RELEASE_LINEAGE_COMMITS,
    _command_environment,
    _artifact_commit_pair,
    _bind_committed_archive_lfs,
    _copy_verified_snapshot,
    _require_equal_inventories,
    _toolchain_report,
)


class GitFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        (self.root / "src").mkdir()
        (self.root / "src/lib.rs").write_text("pub fn source() {}\n")
        for governance_path in (
            "docs/refactor-diff-approvals.json",
            "crates/aura-core/data/refactor_baseline_v1.json",
        ):
            target = self.root / governance_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('{"status":"initial"}\n')
        for path in REQUIRED_ARTIFACT_COMMIT_PATHS:
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("source artifact\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        self.source_revision = self.commit("source")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def commit(self, message: str) -> str:
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Aura Test",
                "-c",
                "user.email=aura-test@example.invalid",
                "commit",
                "-qam",
                message,
            ],
            cwd=self.root,
            check=True,
        )
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def update_required_documents(self) -> None:
        for path in REQUIRED_ARTIFACT_COMMIT_PATHS:
            (self.root / path).write_text("generated candidate\n")


class ArtifactCommitPolicyTests(GitFixture):
    def test_accepts_direct_generated_only_artifact_child(self) -> None:
        self.update_required_documents()
        artifact_revision = self.commit("artifact")

        _artifact_commit_pair(self.root, artifact_revision, self.source_revision)

    def test_rejects_source_change_in_artifact_child(self) -> None:
        self.update_required_documents()
        (self.root / "src/lib.rs").write_text("pub fn changed_in_artifact() {}\n")
        artifact_revision = self.commit("artifact plus source")

        with self.assertRaisesRegex(ReproducibilityError, "non-generated path"):
            _artifact_commit_pair(self.root, artifact_revision, self.source_revision)

    def test_rejects_non_parent_manifest_source(self) -> None:
        self.update_required_documents()
        artifact_revision = self.commit("artifact")

        with self.assertRaisesRegex(ReproducibilityError, "must differ"):
            _artifact_commit_pair(self.root, artifact_revision, artifact_revision)

    def test_allowed_paths_exclude_governed_trust_keyring(self) -> None:
        self.assertNotIn(
            "dist/apple/execution-policy-trust-keyring.json",
            ALLOWED_ARTIFACT_COMMIT_PATHS,
        )

    def test_accepts_governance_only_release_suffix(self) -> None:
        self.update_required_documents()
        artifact_revision = self.commit("artifact")
        (self.root / "docs/refactor-diff-approvals.json").write_text(
            '{"status":"approved"}\n'
        )
        release_revision = self.commit("approve artifact")

        self.assertEqual(
            _artifact_commit_pair(
                self.root, release_revision, self.source_revision
            ),
            artifact_revision,
        )

    def test_rejects_non_governance_release_suffix(self) -> None:
        self.update_required_documents()
        self.commit("artifact")
        (self.root / "src/lib.rs").write_text("pub fn changed_after_artifact() {}\n")
        release_revision = self.commit("invalid release suffix")

        with self.assertRaisesRegex(ReproducibilityError, "non-governance path"):
            _artifact_commit_pair(self.root, release_revision, self.source_revision)

    def test_git_replace_objects_are_disabled(self) -> None:
        environment = _command_environment(
            {
                "GIT_NO_REPLACE_OBJECTS": "0",
                "GIT_REPLACE_REF_BASE": "refs/custom-replace/",
            }
        )

        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertNotIn("GIT_REPLACE_REF_BASE", environment)

    def test_rejects_git_graft_metadata(self) -> None:
        self.update_required_documents()
        artifact_revision = self.commit("artifact")
        grafts = Path(
            subprocess.run(
                ["git", "rev-parse", "--git-path", "info/grafts"],
                cwd=self.root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )
        if not grafts.is_absolute():
            grafts = self.root / grafts
        grafts.parent.mkdir(parents=True, exist_ok=True)
        grafts.write_text(f"{artifact_revision} {self.source_revision}\n")

        with self.assertRaisesRegex(ReproducibilityError, "graft metadata"):
            from ci.apple_artifact_reproducibility import _full_clean_checkout

            _full_clean_checkout(self.root, artifact_revision)

    def test_release_lineage_commit_bound_is_exact(self) -> None:
        self.update_required_documents()
        artifact_revision = self.commit("artifact")
        release_revision = artifact_revision
        for sequence in range(1, MAX_RELEASE_LINEAGE_COMMITS):
            (self.root / "docs/refactor-diff-approvals.json").write_text(
                f'{{"sequence":{sequence}}}\n'
            )
            release_revision = self.commit(f"governance {sequence}")

        self.assertEqual(
            _artifact_commit_pair(
                self.root, release_revision, self.source_revision
            ),
            artifact_revision,
        )

        (self.root / "docs/refactor-diff-approvals.json").write_text(
            f'{{"sequence":{MAX_RELEASE_LINEAGE_COMMITS}}}\n'
        )
        release_revision = self.commit("governance beyond bound")
        with self.assertRaisesRegex(ReproducibilityError, "does not descend linearly"):
            _artifact_commit_pair(
                self.root, release_revision, self.source_revision
            )


class ArtifactInventoryTests(unittest.TestCase):
    def inventory(self) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "path": path,
                "size": len(path),
                "sha256": hashlib.sha256(path.encode()).hexdigest(),
                "executable": False,
            }
            for path in sorted(APPLE_ARTIFACT_FILE_LIMITS)
        )

    def test_exact_inventory_is_equal(self) -> None:
        inventory = self.inventory()
        _require_equal_inventories(inventory, inventory, "fixture")

    def test_one_byte_identity_change_is_rejected(self) -> None:
        expected = self.inventory()
        observed = list(expected)
        observed[0] = {**observed[0], "size": int(observed[0]["size"]) + 1}

        with self.assertRaisesRegex(ReproducibilityError, "differs byte-for-byte"):
            _require_equal_inventories(expected, tuple(observed), "fixture")

    def test_verified_snapshot_copy_is_exact_and_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "snapshot"
            output = root / "retained"
            for relative_path in APPLE_ARTIFACT_FILE_LIMITS:
                path = source / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative_path.encode())

            _copy_verified_snapshot(source, output)
            for relative_path in APPLE_ARTIFACT_FILE_LIMITS:
                self.assertEqual(
                    (source / relative_path).read_bytes(),
                    (output / relative_path).read_bytes(),
                )
            with self.assertRaisesRegex(ReproducibilityError, "already exists"):
                _copy_verified_snapshot(source, output)


class ToolchainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.developer_dir = self.root / "Xcode.app" / "Contents" / "Developer"
        self.xcodebuild = self.developer_dir / "usr" / "bin" / "xcodebuild"
        self.xcodebuild.parent.mkdir(parents=True)
        self.xcodebuild.write_bytes(b"")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def observed(self, arguments: list[str], *, cwd: Path) -> str:
        del cwd
        values = {
            ("xcodebuild", "-version"): "Xcode 26.2\nBuild version 17C52",
            ("xcrun", "--sdk", "iphoneos", "--show-sdk-version"): "26.2",
            (
                "xcrun",
                "--sdk",
                "iphoneos",
                "--show-sdk-build-version",
            ): "23C53",
            ("rustc", "-vV"): (
                "rustc 1.96.1\n"
                "release: 1.96.1\n"
                "commit-hash: 31fca3adb283cc9dfd56b49cdee9a96eb9c96ffd\n"
                "LLVM version: 22.1.2"
            ),
            ("cargo", "--version"): "cargo 1.96.1 (fixture)",
            ("git", "--version"): "git version fixture",
            ("git", "lfs", "version"): "git-lfs/fixture",
            ("python", "--version"): "Python fixture",
            ("xcrun", "--find", "xcodebuild"): str(self.xcodebuild),
            ("xcode-select", "-p"): str(self.developer_dir),
        }
        key = tuple(arguments)
        if arguments[0].endswith("python") or "python" in Path(arguments[0]).name:
            key = ("python", *arguments[1:])
        return values[key]

    def test_report_binds_sdk_build_and_effective_developer_directory(self) -> None:
        with mock.patch(
            "ci.apple_artifact_reproducibility._run_text",
            side_effect=self.observed,
        ), mock.patch.dict(
            os.environ, {"DEVELOPER_DIR": str(self.developer_dir)}, clear=False
        ):
            report = _toolchain_report(self.root)

        self.assertEqual(report["iphoneos_sdk_build"], "23C53")
        self.assertEqual(
            report["effective_developer_dir"], str(self.developer_dir.resolve())
        )
        self.assertEqual(report["resolved_xcodebuild"], str(self.xcodebuild.resolve()))

    def test_wrong_sdk_build_is_rejected(self) -> None:
        def wrong_sdk_build(arguments: list[str], *, cwd: Path) -> str:
            value = self.observed(arguments, cwd=cwd)
            if arguments[-1] == "--show-sdk-build-version":
                return "unexpected"
            return value

        with mock.patch(
            "ci.apple_artifact_reproducibility._run_text",
            side_effect=wrong_sdk_build,
        ):
            with self.assertRaisesRegex(ReproducibilityError, "SDK build"):
                _toolchain_report(self.root)


class ArtifactLfsBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        (self.root / ".gitattributes").write_text(
            "*.a filter=lfs diff=lfs merge=lfs -text\n"
        )
        subprocess.run(["git", "add", ".gitattributes"], cwd=self.root, check=True)
        self.inventory = []
        for relative_path in sorted(APPLE_ARTIFACT_FILE_LIMITS):
            content = f"artifact:{relative_path}".encode()
            digest = hashlib.sha256(content).hexdigest()
            if f"dist/apple/{relative_path}" in ARCHIVE_PATHS:
                pointer = (
                    "version https://git-lfs.github.com/spec/v1\n"
                    f"oid sha256:{digest}\n"
                    f"size {len(content)}\n"
                ).encode()
                object_id = subprocess.run(
                    ["git", "hash-object", "-w", "--stdin"],
                    cwd=self.root,
                    input=pointer,
                    check=True,
                    capture_output=True,
                ).stdout.decode().strip()
                repository_path = f"dist/apple/{relative_path}"
                target = self.root / repository_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                subprocess.run(
                    [
                        "git",
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        f"100644,{object_id},{repository_path}",
                    ],
                    cwd=self.root,
                    check=True,
                )
            self.inventory.append(
                {
                    "path": relative_path,
                    "size": len(content),
                    "sha256": digest,
                    "executable": False,
                }
            )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_committed_archive_matches_every_index_pointer(self) -> None:
        bindings = _bind_committed_archive_lfs(self.root, tuple(self.inventory))
        self.assertEqual(set(bindings), set(ARCHIVE_PATHS))

    def test_wrong_archive_digest_is_rejected(self) -> None:
        inventory = list(self.inventory)
        archive_index = next(
            index for index, item in enumerate(inventory) if str(item["path"]).endswith(".a")
        )
        inventory[archive_index] = {**inventory[archive_index], "sha256": "f" * 64}

        with self.assertRaisesRegex(ReproducibilityError, "LFS pointer"):
            _bind_committed_archive_lfs(self.root, tuple(inventory))


if __name__ == "__main__":
    unittest.main()
