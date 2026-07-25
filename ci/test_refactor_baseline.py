import unittest

from ci import refactor_baseline


def snapshot_with(value, timing=None):
    return {
        "schema_version": refactor_baseline.SNAPSHOT_SCHEMA_VERSION,
        "baseline_id": "test",
        "source": {"revision": "abc", "tree_dirty": False},
        "workspace": {"value": value},
        "contracts": {},
        "fixture_inputs": [],
        "behavior": {},
        "performance": (
            {
                "schema_version": "performance.v1",
                "input": "fixture.json",
                "status": "pass",
                "failures": [],
                "tiers": [
                    {
                        "tier": "10k",
                        "status": "pass",
                        "timing": timing,
                    }
                ],
            }
            if timing is not None
            else None
        ),
    }


class RefactorDiffTests(unittest.TestCase):
    def test_identical_snapshots_pass(self):
        baseline = snapshot_with("same")
        candidate = snapshot_with("same")

        report = refactor_baseline.build_diff(baseline, candidate, [])

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["summary"]["change_count"], 0)

    def test_unapproved_change_is_regression(self):
        baseline = snapshot_with("before")
        candidate = snapshot_with("after")

        report = refactor_baseline.build_diff(baseline, candidate, [])

        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["summary"]["regression"], 1)
        self.assertEqual(report["changes"][0]["path"], "/workspace/value")

    def test_fixture_addition_is_keyed_by_path_without_index_churn(self):
        baseline = snapshot_with("same")
        baseline["fixture_inputs"] = [
            {"path": "fixtures/a.json", "bytes": 10, "sha256": "a"},
            {"path": "fixtures/b.json", "bytes": 20, "sha256": "b"},
        ]
        candidate = snapshot_with("same")
        candidate["fixture_inputs"] = [
            {"path": "fixtures/0-new.json", "bytes": 5, "sha256": "new"},
            {"path": "fixtures/a.json", "bytes": 10, "sha256": "a"},
            {"path": "fixtures/b.json", "bytes": 20, "sha256": "b"},
        ]

        report = refactor_baseline.build_diff(baseline, candidate, [])

        self.assertEqual(report["summary"]["change_count"], 1)
        self.assertEqual(
            report["changes"][0]["path"],
            "/fixture_inputs/fixtures~10-new.json",
        )

    def test_exact_safety_approval_passes(self):
        baseline = snapshot_with("before")
        candidate = snapshot_with("after")
        approvals = [
            {
                "path": "/workspace/value",
                "classification": "approved_safety_improvement",
                "baseline": "before",
                "candidate": "after",
                "reason": "Reviewed safety improvement.",
            }
        ]

        report = refactor_baseline.build_diff(baseline, candidate, approvals)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["summary"]["approved_safety_improvement"], 1)

    def test_stale_approval_fails(self):
        baseline = snapshot_with("same")
        candidate = snapshot_with("same")
        approvals = [
            {
                "path": "/workspace/value",
                "classification": "structural_only",
                "baseline": "before",
                "candidate": "after",
                "reason": "No longer applicable.",
            }
        ]

        report = refactor_baseline.build_diff(baseline, candidate, approvals)

        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["summary"]["invalid_approval_count"], 1)

    def test_performance_inside_envelope_passes(self):
        baseline = snapshot_with(
            "same",
            timing={"elapsed_seconds": 10.0, "max_rss_mb": 100.0},
        )
        candidate = snapshot_with(
            "same",
            timing={"elapsed_seconds": 11.0, "max_rss_mb": 110.0},
        )

        report = refactor_baseline.build_diff(baseline, candidate, [])

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["performance_observations"][0]["status"], "pass")

    def test_performance_outside_envelope_is_regression(self):
        baseline = snapshot_with(
            "same",
            timing={"elapsed_seconds": 100.0, "max_rss_mb": 1000.0},
        )
        candidate = snapshot_with(
            "same",
            timing={"elapsed_seconds": 130.0, "max_rss_mb": 1200.0},
        )

        report = refactor_baseline.build_diff(baseline, candidate, [])

        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["summary"]["regression"], 2)


class WorkspacePathTests(unittest.TestCase):
    def test_resolves_relative_path_from_workspace(self):
        root = refactor_baseline.Path("/repo")

        result = refactor_baseline.workspace_path("artifacts/report.json", root)

        self.assertEqual(result, root / "artifacts/report.json")


if __name__ == "__main__":
    unittest.main()
