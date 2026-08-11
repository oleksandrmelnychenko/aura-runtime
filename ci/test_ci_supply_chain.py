import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
FULL_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
CARGO_LOCKED_COMMAND = re.compile(r"\bcargo\s+(?:build|clippy|install|run|test)\b")
JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")


def workflows() -> list[Path]:
    return sorted(
        [*WORKFLOW_DIRECTORY.glob("*.yml"), *WORKFLOW_DIRECTORY.glob("*.yaml")]
    )


class CiSupplyChainTests(unittest.TestCase):
    def test_external_actions_are_pinned_to_full_commit_sha(self):
        for workflow in workflows():
            for line_number, line in enumerate(
                workflow.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "uses:" not in line:
                    continue
                target = line.split("uses:", 1)[1].split("#", 1)[0].strip()
                if target.startswith("./"):
                    continue
                self.assertIn("@", target, f"{workflow}:{line_number} lacks an action ref")
                action, reference = target.rsplit("@", 1)
                self.assertTrue(action, f"{workflow}:{line_number} has an empty action name")
                self.assertRegex(
                    reference,
                    rf"^{FULL_COMMIT_SHA.pattern}$",
                    f"{workflow}:{line_number} must pin a full commit SHA",
                )

    def test_checkout_never_persists_credentials(self):
        for workflow in workflows():
            lines = workflow.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if "uses: actions/checkout@" not in line:
                    continue
                nearby_configuration = "\n".join(lines[index + 1 : index + 5])
                self.assertIn(
                    "persist-credentials: false",
                    nearby_configuration,
                    f"{workflow}:{index + 1} must not retain the GitHub token",
                )

    def test_every_job_limits_token_to_read_only_contents(self):
        for workflow in workflows():
            lines = workflow.read_text(encoding="utf-8").splitlines()
            jobs_index = lines.index("jobs:")
            job_starts = [
                index
                for index in range(jobs_index + 1, len(lines))
                if JOB_HEADER.match(lines[index])
            ]
            self.assertTrue(job_starts, f"{workflow} has no jobs")
            for position, start in enumerate(job_starts):
                end = job_starts[position + 1] if position + 1 < len(job_starts) else len(lines)
                block = "\n".join(lines[start:end])
                job_name = JOB_HEADER.match(lines[start]).group(1)
                self.assertRegex(
                    block,
                    r"(?m)^    permissions:\s*\n      contents: read\s*$",
                    f"{workflow} job {job_name} must use read-only contents permission",
                )

    def test_all_ci_cargo_resolution_uses_lockfile(self):
        for workflow in workflows():
            for line_number, line in enumerate(
                workflow.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if CARGO_LOCKED_COMMAND.search(line):
                    self.assertIn(
                        "--locked",
                        line,
                        f"{workflow}:{line_number} may resolve outside Cargo.lock",
                    )

    def test_helper_gate_discovers_every_python_test(self):
        discovery = "python3 -m unittest discover -s ci -p 'test_*.py'"
        for name in ("rust.yml", "promotion-gate.yml"):
            text = (WORKFLOW_DIRECTORY / name).read_text(encoding="utf-8")
            self.assertIn(discovery, text)

    def test_rust_and_audit_tool_versions_are_fixed(self):
        toolchain = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
        match = re.search(r'^channel = "([0-9]+\.[0-9]+\.[0-9]+)"$', toolchain, re.MULTILINE)
        self.assertIsNotNone(match, "Rust channel must be an exact stable version")
        rust_version = match.group(1)

        apple_workflow = (WORKFLOW_DIRECTORY / "apple-artifact.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"toolchain: {rust_version}", apple_workflow)

        rust_workflow = (WORKFLOW_DIRECTORY / "rust.yml").read_text(encoding="utf-8")
        self.assertRegex(rust_workflow, r"cargo install cargo-audit --version [0-9]+\.[0-9]+\.[0-9]+ --locked")
        audit_step = rust_workflow.split("- name: Audit Dependencies", 1)[1].split(
            "- name:", 1
        )[0]
        self.assertNotIn("|| true", audit_step)


if __name__ == "__main__":
    unittest.main()
