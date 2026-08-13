import hashlib
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ci.apple_artifact import (
    APPLE_ARTIFACT_FILE_LIMITS,
    ArtifactError,
    SOURCE_TREE_DIGEST_DOMAIN,
    _frame,
    _git_environment,
    _load_json,
    _archive_platform_versions,
    _verify_architecture_platform,
    _source_paths,
    _source_revision_is_ancestor,
    source_tree_digest,
    source_tree_dirty,
    snapshot_apple_artifact,
)


class SourceTreeIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        (self.root / "src").mkdir()
        (self.root / "src" / "lib.rs").write_text("pub fn value() -> u8 { 1 }\n")
        (self.root / "dist" / "apple").mkdir(parents=True)
        (self.root / "dist" / "apple" / "release-manifest.json").write_text(
            '{"schema_version": 4}\n'
        )
        (self.root / "crates" / "aura-core" / "data").mkdir(parents=True)
        (self.root / "crates" / "aura-core" / "data" / "refactor_baseline_v1.json").write_text(
            '{"baseline_id": "fixture"}\n'
        )
        (self.root / "docs").mkdir()
        (self.root / "docs" / "refactor-diff-approvals.json").write_text(
            '{"approvals": []}\n'
        )
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Aura Test",
                "-c",
                "user.email=aura-test@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
            cwd=self.root,
            check=True,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def install_lfs_fixture(self, content: bytes) -> tuple[Path, bytes]:
        attributes = self.root / ".gitattributes"
        attributes.write_text("*.bin filter=lfs diff=lfs merge=lfs -text\n")
        subprocess.run(["git", "add", ".gitattributes"], cwd=self.root, check=True)

        relative_path = "assets/model.bin"
        path = self.root / relative_path
        path.parent.mkdir()
        content_digest = hashlib.sha256(content).hexdigest()
        pointer = (
            "version https://git-lfs.github.com/spec/v1\n"
            f"oid sha256:{content_digest}\n"
            f"size {len(content)}\n"
        ).encode("ascii")
        pointer_object = subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],
            cwd=self.root,
            check=True,
            input=pointer,
            capture_output=True,
        ).stdout.decode("ascii").strip()
        subprocess.run(
            [
                "git",
                "update-index",
                "--add",
                "--cacheinfo",
                f"100644,{pointer_object},{relative_path}",
            ],
            cwd=self.root,
            check=True,
        )
        path.write_bytes(content)
        return path, pointer

    def test_digest_ignores_generated_apple_outputs(self) -> None:
        baseline = source_tree_digest(self.root)

        (self.root / "dist" / "apple" / "release-manifest.json").write_text(
            '{"schema_version": 5}\n'
        )

        self.assertEqual(source_tree_digest(self.root), baseline)
        self.assertFalse(source_tree_dirty(self.root))

    def test_digest_and_dirty_flag_track_reviewable_source_changes(self) -> None:
        baseline = source_tree_digest(self.root)

        (self.root / "src" / "lib.rs").write_text("pub fn value() -> u8 { 2 }\n")

        self.assertNotEqual(source_tree_digest(self.root), baseline)
        self.assertTrue(source_tree_dirty(self.root))

    def test_digest_ignores_self_referential_refactor_evidence(self) -> None:
        baseline = source_tree_digest(self.root)

        (self.root / "crates" / "aura-core" / "data" / "refactor_baseline_v1.json").write_text(
            '{"baseline_id": "accepted"}\n'
        )
        (self.root / "docs" / "refactor-diff-approvals.json").write_text(
            '{"approvals": [{"path": "/artifact/hash"}]}\n'
        )

        self.assertEqual(source_tree_digest(self.root), baseline)
        self.assertFalse(source_tree_dirty(self.root))

    def test_digest_still_tracks_neighboring_governed_data(self) -> None:
        baseline = source_tree_digest(self.root)
        governed = self.root / "crates" / "aura-core" / "data" / "governed.json"

        governed.write_text('{"rule": "new"}\n')

        self.assertNotEqual(source_tree_digest(self.root), baseline)
        self.assertTrue(source_tree_dirty(self.root))

    def test_digest_tracks_untracked_reviewable_source(self) -> None:
        baseline = source_tree_digest(self.root)

        (self.root / "src" / "new.rs").write_text("pub const NEW: bool = true;\n")

        self.assertNotEqual(source_tree_digest(self.root), baseline)
        self.assertTrue(source_tree_dirty(self.root))

    def test_streamed_digest_preserves_v2_wire_algorithm(self) -> None:
        hasher = hashlib.sha256()
        hasher.update(SOURCE_TREE_DIGEST_DOMAIN)
        for relative_path in _source_paths(self.root):
            path = self.root / relative_path
            _frame(hasher, relative_path.encode("utf-8", errors="surrogateescape"))
            if path.is_symlink():
                hasher.update(b"L")
                _frame(
                    hasher,
                    os.readlink(path).encode("utf-8", errors="surrogateescape"),
                )
            elif path.is_file():
                hasher.update(b"F")
                hasher.update(b"X" if path.stat().st_mode & stat.S_IXUSR else b"-")
                _frame(hasher, path.read_bytes())
            elif not path.exists():
                hasher.update(b"D")
            else:
                self.fail(f"unsupported fixture path: {relative_path}")

        self.assertEqual(source_tree_digest(self.root), hasher.hexdigest())

    def test_digest_accepts_exact_materialized_lfs_object(self) -> None:
        path, _ = self.install_lfs_fixture(b"governed model bytes\x00\x01")

        first = source_tree_digest(self.root)
        self.assertEqual(path.read_bytes(), b"governed model bytes\x00\x01")
        self.assertEqual(source_tree_digest(self.root), first)

    def test_digest_rejects_unmaterialized_lfs_pointer(self) -> None:
        path, pointer = self.install_lfs_fixture(b"governed model bytes")
        path.write_bytes(pointer)

        with self.assertRaisesRegex(ArtifactError, "not materialized"):
            source_tree_digest(self.root)

    def test_digest_rejects_wrong_lfs_object_with_declared_size(self) -> None:
        path, _ = self.install_lfs_fixture(b"governed model bytes")
        path.write_bytes(b"x" * len(b"governed model bytes"))

        with self.assertRaisesRegex(ArtifactError, "digest does not match"):
            source_tree_digest(self.root)

    def test_digest_rejects_git_info_attribute_override(self) -> None:
        self.install_lfs_fixture(b"governed model bytes")
        info_attributes = self.root / ".git" / "info" / "attributes"
        info_attributes.write_text("*.bin -filter\n")

        with self.assertRaisesRegex(ArtifactError, "info/attributes"):
            source_tree_digest(self.root)

    def test_digest_rejects_unsupported_content_filter(self) -> None:
        custom = self.root / "assets" / "custom.dat"
        custom.parent.mkdir()
        custom.write_bytes(b"custom-filtered")
        (self.root / ".gitattributes").write_text("*.dat filter=custom\n")
        subprocess.run(["git", "add", ".gitattributes", str(custom)], cwd=self.root, check=True)

        with self.assertRaisesRegex(ArtifactError, "unsupported Git content filter"):
            source_tree_digest(self.root)

    def test_digest_rejects_assume_unchanged_source(self) -> None:
        subprocess.run(
            ["git", "update-index", "--assume-unchanged", "src/lib.rs"],
            cwd=self.root,
            check=True,
        )
        (self.root / "src" / "lib.rs").write_text("hidden source mutation\n")

        with self.assertRaisesRegex(ArtifactError, "hidden, sparse, or exceptional"):
            source_tree_digest(self.root)

    def test_digest_rejects_deleted_skip_worktree_source(self) -> None:
        subprocess.run(
            ["git", "update-index", "--skip-worktree", "src/lib.rs"],
            cwd=self.root,
            check=True,
        )
        (self.root / "src" / "lib.rs").unlink()

        with self.assertRaisesRegex(ArtifactError, "hidden, sparse, or exceptional"):
            source_tree_digest(self.root)

    def test_digest_rejects_external_hard_link_alias(self) -> None:
        external = Path(self.temporary_directory.name).parent / (
            f"aura-source-hardlink-{os.getpid()}-{id(self)}.rs"
        )
        try:
            os.link(self.root / "src" / "lib.rs", external)
            with self.assertRaisesRegex(ArtifactError, "must not be hard-linked"):
                source_tree_digest(self.root)
        finally:
            external.unlink(missing_ok=True)

    def test_git_replace_objects_are_disabled(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "GIT_DIR": "/tmp/untrusted-git-dir",
                "GIT_WORK_TREE": "/tmp/untrusted-worktree",
                "GIT_INDEX_FILE": "/tmp/untrusted-index",
                "GIT_CONFIG_COUNT": "1",
                "GIT_NO_REPLACE_OBJECTS": "0",
                "GIT_REPLACE_REF_BASE": "refs/custom-replace/",
            },
        ):
            environment = _git_environment()

        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertNotIn("GIT_REPLACE_REF_BASE", environment)
        for name in (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_CONFIG_COUNT",
        ):
            self.assertNotIn(name, environment)
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")

    def test_digest_rejects_git_graft_metadata(self) -> None:
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
        grafts.write_text("a" * 40 + " " + "b" * 40 + "\n")

        with self.assertRaisesRegex(ArtifactError, "graft metadata"):
            source_tree_digest(self.root)

    def test_json_loader_rejects_duplicate_fields(self) -> None:
        payload = self.root / "duplicate.json"
        payload.write_text('{"schema_version": 5, "schema_version": 6}\n')

        with self.assertRaisesRegex(ArtifactError, "duplicate JSON field"):
            _load_json(payload)

    def test_json_loader_rejects_symlink(self) -> None:
        target = self.root / "target.json"
        target.write_text('{"schema_version": 5}\n')
        payload = self.root / "linked.json"
        payload.symlink_to(target)

        with self.assertRaisesRegex(ArtifactError, "regular non-symlink"):
            _load_json(payload)

    def test_artifact_only_commit_can_follow_source_revision(self) -> None:
        source_revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        baseline = source_tree_digest(self.root)

        (self.root / "dist" / "apple" / "release-manifest.json").write_text(
            '{"schema_version": 5}\n'
        )
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Aura Test",
                "-c",
                "user.email=aura-test@example.invalid",
                "commit",
                "-qm",
                "artifact",
            ],
            cwd=self.root,
            check=True,
        )
        artifact_revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        self.assertTrue(
            _source_revision_is_ancestor(
                self.root,
                source_revision,
                artifact_revision,
            )
        )
        self.assertEqual(source_tree_digest(self.root), baseline)
        self.assertFalse(source_tree_dirty(self.root))


class AppleArtifactSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.dist = Path(self.temporary_directory.name) / "dist" / "apple"
        for relative_path in APPLE_ARTIFACT_FILE_LIMITS:
            path = self.dist / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"fixture:{relative_path}\n".encode())

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_snapshot_accepts_only_exact_inventory(self) -> None:
        with snapshot_apple_artifact(self.dist) as (snapshot, inventory):
            self.assertEqual(
                [item["path"] for item in inventory],
                sorted(APPLE_ARTIFACT_FILE_LIMITS),
            )
            for item in inventory:
                self.assertEqual(
                    (snapshot / item["path"]).read_bytes(),
                    (self.dist / item["path"]).read_bytes(),
                )

    def test_snapshot_rejects_extra_file(self) -> None:
        (self.dist / "unexpected.txt").write_text("not governed\n")

        with self.assertRaisesRegex(ArtifactError, "inventory differs"):
            with snapshot_apple_artifact(self.dist):
                pass

    def test_snapshot_rejects_symlink(self) -> None:
        target = self.dist / "runtime-artifact-identities.env"
        target.unlink()
        target.symlink_to(self.dist / "release-manifest.json")

        with self.assertRaisesRegex(ArtifactError, "must be regular"):
            with snapshot_apple_artifact(self.dist):
                pass

    def test_snapshot_rejects_hard_link(self) -> None:
        target = self.dist / "runtime-artifact-identities.env"
        target.unlink()
        os.link(self.dist / "release-manifest.json", target)

        with self.assertRaisesRegex(ArtifactError, "must not be hard-linked"):
            with snapshot_apple_artifact(self.dist):
                pass


class AppleArchivePlatformTests(unittest.TestCase):
    def test_accepts_modern_build_version_for_every_member(self) -> None:
        output = """Archive : fixture.a
fixture.a(one.o):
Load command 0
      cmd LC_BUILD_VERSION
 platform 7
    minos 18.0
fixture.a(two.o):
Load command 0
      cmd LC_BUILD_VERSION
 platform 7
    minos 18.0
"""
        with mock.patch("ci.apple_artifact._run", return_value=output):
            self.assertEqual(
                _archive_platform_versions(Path("."), Path("fixture.a")),
                ((7, "18.0"), (7, "18.0")),
            )

    def test_parses_legacy_iphoneos_platform_command(self) -> None:
        output = """Archive : fixture.a
fixture.a(one.o):
Load command 0
      cmd LC_VERSION_MIN_IPHONEOS
  version 10.0
"""
        with mock.patch("ci.apple_artifact._run", return_value=output):
            self.assertEqual(
                _archive_platform_versions(Path("."), Path("fixture.a")),
                ((None, "10.0"),),
            )

    def test_rejects_member_without_build_version(self) -> None:
        output = """Archive : fixture.a
fixture.a(one.o):
Load command 0
      cmd LC_SEGMENT_64
"""
        with mock.patch("ci.apple_artifact._run", return_value=output):
            with self.assertRaisesRegex(ArtifactError, "lacks one platform"):
                _archive_platform_versions(Path("."), Path("fixture.a"))

    def test_rejects_wrong_platform_in_one_member(self) -> None:
        output = """Archive : fixture.a
fixture.a(one.o):
Load command 0
      cmd LC_BUILD_VERSION
 platform 7
    minos 18.0
fixture.a(two.o):
Load command 0
      cmd LC_BUILD_VERSION
 platform 1
    minos 14.0
"""
        with mock.patch("ci.apple_artifact._run", return_value=output):
            with self.assertRaisesRegex(ArtifactError, "wrong Mach-O platform"):
                _verify_architecture_platform(
                    Path("."),
                    Path("fixture.a"),
                    expected_platform=7,
                    allow_legacy_iphoneos=False,
                )

    def test_accepts_compatible_legacy_members_when_modern_floor_is_bound(self) -> None:
        output = """Archive : fixture.a
fixture.a(primary.o):
Load command 0
      cmd LC_BUILD_VERSION
 platform 2
    minos 18.0
fixture.a(runtime.o):
Load command 0
      cmd LC_VERSION_MIN_IPHONEOS
  version 10.0
"""
        with mock.patch("ci.apple_artifact._run", return_value=output):
            _verify_architecture_platform(
                Path("."),
                Path("fixture.a"),
                expected_platform=2,
                allow_legacy_iphoneos=True,
            )

    def test_rejects_archive_without_exact_modern_floor_binding(self) -> None:
        output = """Archive : fixture.a
fixture.a(runtime.o):
Load command 0
      cmd LC_VERSION_MIN_IPHONEOS
  version 10.0
"""
        with mock.patch("ci.apple_artifact._run", return_value=output):
            with self.assertRaisesRegex(ArtifactError, "lacks an exact modern"):
                _verify_architecture_platform(
                    Path("."),
                    Path("fixture.a"),
                    expected_platform=2,
                    allow_legacy_iphoneos=True,
                )

    def test_legacy_minimum_is_not_overwritten_by_later_source_version(self) -> None:
        output = """Archive : fixture.a
fixture.a(runtime.o):
Load command 0
      cmd LC_VERSION_MIN_IPHONEOS
  version 99.0
Load command 1
      cmd LC_SOURCE_VERSION
  version 1.0
"""
        with mock.patch("ci.apple_artifact._run", return_value=output):
            self.assertEqual(
                _archive_platform_versions(Path("."), Path("fixture.a")),
                ((None, "99.0"),),
            )

    def test_rejects_modern_command_without_platform(self) -> None:
        output = """Archive : fixture.a
fixture.a(primary.o):
Load command 0
      cmd LC_BUILD_VERSION
    minos 18.0
"""
        with mock.patch("ci.apple_artifact._run", return_value=output):
            with self.assertRaisesRegex(ArtifactError, "lacks platform"):
                _archive_platform_versions(Path("."), Path("fixture.a"))


if __name__ == "__main__":
    unittest.main()
