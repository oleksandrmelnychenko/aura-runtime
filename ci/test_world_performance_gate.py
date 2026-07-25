import tempfile
import unittest
from pathlib import Path

from ci import world_performance_gate


class ParseTimeReportTests(unittest.TestCase):
    def test_parses_gnu_time_report(self):
        text = """
User time (seconds): 3.50
System time (seconds): 0.25
Elapsed (wall clock) time (h:mm:ss or m:ss): 0:04.00
Maximum resident set size (kbytes): 131072
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "time.txt"
            path.write_text(text, encoding="utf-8")

            report = world_performance_gate.parse_time_report(path, system="Linux")

        self.assertEqual(
            report,
            {
                "elapsed_seconds": 4.0,
                "user_seconds": 3.5,
                "system_seconds": 0.25,
                "max_rss_mb": 128.0,
            },
        )

    def test_parses_darwin_time_report(self):
        text = """
real 4.00
user 3.50
sys 0.25
        134217728  maximum resident set size
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "time.txt"
            path.write_text(text, encoding="utf-8")

            report = world_performance_gate.parse_time_report(path, system="Darwin")

        self.assertEqual(
            report,
            {
                "elapsed_seconds": 4.0,
                "user_seconds": 3.5,
                "system_seconds": 0.25,
                "max_rss_mb": 128.0,
            },
        )


class DisplayPathTests(unittest.TestCase):
    def test_keeps_external_artifact_path_absolute(self):
        path = Path("/tmp/aura-performance/summary.json")

        displayed = world_performance_gate.display_path(path, Path("/repo"))

        self.assertEqual(displayed, path.as_posix())


if __name__ == "__main__":
    unittest.main()
