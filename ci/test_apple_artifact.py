import subprocess
import tempfile
import unittest
from pathlib import Path

from ci.apple_artifact import (
    _source_revision_is_ancestor,
    source_tree_digest,
    source_tree_dirty,
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


if __name__ == "__main__":
    unittest.main()
