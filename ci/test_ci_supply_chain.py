import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
APPLE_WORKFLOW = WORKFLOW_DIRECTORY / "apple-artifact.yml"
FULL_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
CARGO_LOCKED_COMMAND = re.compile(r"\bcargo\s+(?:build|clippy|install|run|test)\b")
JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")


def workflows() -> list[Path]:
    return sorted(
        [*WORKFLOW_DIRECTORY.glob("*.yml"), *WORKFLOW_DIRECTORY.glob("*.yaml")]
    )


class CiSupplyChainTests(unittest.TestCase):
    @staticmethod
    def apple_workflow() -> str:
        return APPLE_WORKFLOW.read_text(encoding="utf-8")

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

    def test_apple_workflow_materializes_exact_head_with_full_history(self):
        workflow = self.apple_workflow()
        checkout = workflow.split("uses: actions/checkout@", 1)[1].split(
            "- uses:", 1
        )[0]
        self.assertIn("persist-credentials: false", checkout)
        self.assertIn("fetch-depth: 0", checkout)
        self.assertIn("lfs: true", checkout)
        self.assertIn(
            "ref: ${{ github.event.pull_request.head.sha || github.sha }}", checkout
        )

    def test_apple_workflow_covers_all_artifact_provenance_paths(self):
        workflow = self.apple_workflow()
        for path in (
            '"**"',
            '"dist/apple/**"',
            '"ci/apple_artifact.py"',
            '"ci/test_apple_artifact.py"',
            '"ci/apple_artifact_reproducibility.py"',
            '"ci/test_apple_artifact_reproducibility.py"',
        ):
            self.assertIn(path, workflow)

    def test_apple_workflow_pins_release_build_environment(self):
        workflow = self.apple_workflow()
        for setting in (
            "timeout-minutes: 120",
            "DEVELOPER_DIR: /Applications/Xcode_26.2.app/Contents/Developer",
            'CARGO_BUILD_JOBS: "10"',
            'CARGO_NET_OFFLINE: "true"',
            "PROFILE: release",
            'AURA_AGENT_ONNX: "0"',
            'MINIMUM_IOS_VERSION: "18.0"',
            "EXPECTED_XCODE=$'Xcode 26.2\\nBuild version 17C52'",
            '"commit-hash: 31fca3adb283cc9dfd56b49cdee9a96eb9c96ffd"',
            '"LLVM version: 22.1.2"',
            '"23C53"',
            "minimum_free_bytes = 35 * 1024**3",
        ):
            self.assertIn(setting, workflow)
        self.assertLess(
            workflow.index("minimum_free_bytes = 35 * 1024**3"),
            workflow.index("uses: actions/checkout@"),
        )

    def test_apple_workflow_verifies_committed_bytes_before_reproduction(self):
        workflow = self.apple_workflow()
        helper_tests = "python3 -m unittest discover -s ci -p 'test_apple_artifact*.py'"
        committed_verify = "python3 ci/apple_artifact.py verify"
        reproducibility_verify = (
            "python3 ci/apple_artifact_reproducibility.py verify --root . "
            '--output artifacts/apple-reproducibility.json --temporary-parent "$RUNNER_TEMP"'
        )
        self.assertIn(helper_tests, workflow)
        self.assertIn(committed_verify, workflow)
        self.assertIn(reproducibility_verify, workflow)
        self.assertLess(workflow.index(committed_verify), workflow.index(reproducibility_verify))
        self.assertNotIn("bash scripts/release/build-apple-xcframework.sh", workflow)
        locked_fetch = "cargo fetch --locked"
        self.assertIn(locked_fetch, workflow)
        self.assertLess(workflow.index(locked_fetch), workflow.index(reproducibility_verify))
        fetch_step = workflow.split(
            "- name: Fetch locked Rust dependencies for offline rebuilds", 1
        )[1].split("- name:", 1)[0]
        self.assertIn("if: ${{ github.event_name != 'pull_request' }}", fetch_step)
        self.assertIn('CARGO_NET_OFFLINE: "false"', fetch_step)

    def test_apple_release_proof_and_upload_are_not_issued_for_pull_requests(self):
        workflow = self.apple_workflow()
        reproduce = workflow.split(
            "- name: Reproduce checked-in Apple artifact twice", 1
        )[1].split("- name:", 1)[0]
        upload = workflow.split("- name: Upload verified Apple release artifact", 1)[1]
        self.assertIn("if: ${{ github.event_name != 'pull_request' }}", reproduce)
        self.assertIn(
            "if: ${{ github.event_name != 'pull_request' && success() }}", upload
        )
        expected_paths = (
            "artifacts/apple-verified-dist",
            "artifacts/apple-release-verification.json",
            "artifacts/apple-reproducibility.json",
        )
        for path in expected_paths:
            self.assertIn(path, upload)
        self.assertNotRegex(upload, r"(?m)^\s+dist/apple(?:/|\s*$)")
        upload_paths = upload.split("path: |", 1)[1].split(
            "if-no-files-found:", 1
        )[0]
        self.assertEqual(
            tuple(line.strip() for line in upload_paths.splitlines() if line.strip()),
            expected_paths,
        )

    def test_rust_and_audit_tool_versions_are_fixed(self):
        toolchain = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
        match = re.search(r'^channel = "([0-9]+\.[0-9]+\.[0-9]+)"$', toolchain, re.MULTILINE)
        self.assertIsNotNone(match, "Rust channel must be an exact stable version")
        rust_version = match.group(1)

        apple_workflow = self.apple_workflow()
        self.assertIn(f"toolchain: {rust_version}", apple_workflow)

        rust_workflow = (WORKFLOW_DIRECTORY / "rust.yml").read_text(encoding="utf-8")
        self.assertRegex(rust_workflow, r"cargo install cargo-audit --version [0-9]+\.[0-9]+\.[0-9]+ --locked")
        audit_step = rust_workflow.split("- name: Audit Dependencies", 1)[1].split(
            "- name:", 1
        )[0]
        self.assertNotIn("|| true", audit_step)


if __name__ == "__main__":
    unittest.main()
