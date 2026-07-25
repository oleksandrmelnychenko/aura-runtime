import subprocess
import tempfile
import unittest
from pathlib import Path

from ci.apple_artifact import source_tree_digest, source_tree_dirty


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

    def test_digest_tracks_untracked_reviewable_source(self) -> None:
        baseline = source_tree_digest(self.root)

        (self.root / "src" / "new.rs").write_text("pub const NEW: bool = true;\n")

        self.assertNotEqual(source_tree_digest(self.root), baseline)
        self.assertTrue(source_tree_dirty(self.root))


if __name__ == "__main__":
    unittest.main()
